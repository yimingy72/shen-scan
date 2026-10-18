package control

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/webevidence"
)

const webScreenshotSchema = `
CREATE TABLE IF NOT EXISTS http_screenshots (
 id text PRIMARY KEY,
 run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 parent_observation_id text NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 attempt_no integer NOT NULL,
 png bytea NOT NULL CHECK(octet_length(png)>0 AND octet_length(png)<=786432),
 thumbnail bytea NOT NULL,
 width integer NOT NULL CHECK(width BETWEEN 1 AND 1920),
 height integer NOT NULL CHECK(height BETWEEN 1 AND 1080),
 sha256 text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(task_id,attempt_no,parent_observation_id)
);`

func validateScreenshotPNG(s *webevidence.BrowserScreenshot) (image.Image, error) {
	if len(s.PNG) == 0 || len(s.PNG) > webevidence.MaxScreenshot {
		return nil, errors.New("screenshot PNG exceeds size bound or is empty")
	}
	if !bytes.HasPrefix(s.PNG, []byte("\x89PNG\r\n\x1a\n")) || !bytes.HasSuffix(s.PNG, []byte{0, 0, 0, 0, 'I', 'E', 'N', 'D', 174, 66, 96, 130}) {
		return nil, errors.New("screenshot must be a complete PNG")
	}
	config, err := png.DecodeConfig(bytes.NewReader(s.PNG))
	if err != nil {
		return nil, errors.New("invalid screenshot PNG header")
	}
	if config.Width < 1 || config.Width > 1920 || config.Height < 1 || config.Height > 1080 {
		return nil, errors.New("screenshot dimensions exceed 1920x1080")
	}
	if s.Width != 0 && s.Width != config.Width || s.Height != 0 && s.Height != config.Height {
		return nil, errors.New("screenshot declared dimensions mismatch")
	}
	digest := webevidence.SHA256(s.PNG)
	if s.SHA256 != "" && s.SHA256 != digest {
		return nil, errors.New("screenshot SHA256 mismatch")
	}
	decoded, err := png.Decode(bytes.NewReader(s.PNG))
	if err != nil {
		return nil, errors.New("invalid screenshot PNG pixels")
	}
	s.Width, s.Height, s.SHA256 = config.Width, config.Height, digest
	return decoded, nil
}

func screenshotThumbnail(source image.Image) ([]byte, error) {
	b := source.Bounds()
	w := min(240, b.Dx())
	h := max(1, b.Dy()*w/b.Dx())
	thumbnail := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			thumbnail.Set(x, y, source.At(b.Min.X+x*b.Dx()/w, b.Min.Y+y*b.Dy()/h))
		}
	}
	var out bytes.Buffer
	err := png.Encode(&out, thumbnail)
	return out.Bytes(), err
}

// Caller holds the ordinary live run/task/attempt fence and immutable parent
// binding. Invalid worker images become screenshot-only partial outcomes.
func storeBrowserScreenshot(ctx context.Context, tx pgx.Tx, taskID string, attempt int, p webevidence.BrowserAssignment, s *webevidence.BrowserScreenshot) (*webevidence.ScreenshotMetadata, error) {
	metadata := &webevidence.ScreenshotMetadata{WebStage: webevidence.WebStage{State: "partial", StopReason: "screenshot-missing"}}
	if s == nil {
		return metadata, nil
	}
	metadata.WebStage = s.WebStage
	if len(s.PNG) == 0 {
		metadata.State = "partial"
		if metadata.StopReason == "" {
			metadata.StopReason = "screenshot-missing"
		}
		s.State, s.StopReason = metadata.State, metadata.StopReason
		return metadata, nil
	}
	if s.State != "complete" || s.Error != "" {
		metadata.State = "partial"
		s.State = "partial"
		if metadata.StopReason == "" {
			metadata.StopReason = "screenshot-partial"
		}
		s.StopReason = metadata.StopReason
	}
	decoded, err := validateScreenshotPNG(s)
	if err != nil {
		s.PNG = nil
		s.State = "partial"
		s.Error = err.Error()
		s.StopReason = "invalid-screenshot"
		metadata.WebStage = s.WebStage
		return metadata, nil
	}
	thumbnail, err := screenshotThumbnail(decoded)
	if err != nil {
		return nil, err
	}
	var runID string
	if err = tx.QueryRow(ctx, `SELECT run_id FROM tasks WHERE id=$1`, taskID).Scan(&runID); err != nil {
		return nil, err
	}
	id := newID()
	err = tx.QueryRow(ctx, `INSERT INTO http_screenshots(id,run_id,parent_observation_id,task_id,attempt_no,png,thumbnail,width,height,sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(task_id,attempt_no,parent_observation_id) DO UPDATE SET sha256=http_screenshots.sha256 RETURNING id`, id, runID, p.BrowserParent.ObservationID, taskID, attempt, s.PNG, thumbnail, s.Width, s.Height, s.SHA256).Scan(&id)
	if err != nil {
		return nil, err
	}
	metadata.ID, metadata.Width, metadata.Height, metadata.SHA256, metadata.Bytes = id, s.Width, s.Height, s.SHA256, len(s.PNG)
	s.PNG = nil
	return metadata, nil
}

func (s *Server) getObservationScreenshot(w http.ResponseWriter, r *http.Request) {
	var data []byte
	var digest string
	err := s.db.QueryRow(r.Context(), `SELECT CASE WHEN $2 THEN ss.thumbnail ELSE ss.png END,ss.sha256 FROM assets a JOIN tasks t ON t.id=a.task_id JOIN http_screenshots ss ON ss.task_id=t.id AND ss.attempt_no=a.attempt_no JOIN tasks p ON p.id=t.payload->>'source_task_id' WHERE a.id=$1 AND t.state='completed' AND t.accepted_attempt_no=a.attempt_no AND p.state='completed' AND p.accepted_attempt_no=(t.payload->>'source_attempt_no')::int AND p.completion_id=t.payload->>'source_completion_id' AND ss.parent_observation_id=t.payload->'browser_parent'->>'observation_id'`, r.PathValue("id"), r.URL.Query().Get("thumbnail") == "true").Scan(&data, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "截图不存在或尚未完成")
		return
	}
	if err != nil {
		writeError(w, 500, "读取截图失败")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
