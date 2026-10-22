package control

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

const exportPageSize = 200

// Export uses exactly the list API queries, within one read-only snapshot. A
// private temporary file prevents a failed later page becoming a successful,
// apparently complete download. Memory is bounded by one result page.
func (s *Server) exportRun(w http.ResponseWriter, r *http.Request) {
	format, kind := r.URL.Query().Get("format"), r.URL.Query().Get("kind")
	if !contains([]string{"csv", "json"}, format) || !contains([]string{"targets", "ports", "http", "findings"}, kind) {
		writeError(w, http.StatusBadRequest, "请选择 csv/json 格式及 targets/ports/http/findings 类型")
		return
	}
	file, err := os.CreateTemp("", "scan-export-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法准备导出文件")
		return
	}
	defer os.Remove(file.Name())
	defer file.Close()
	run, snapshotAt, err := s.prepareRunExport(r.Context(), file, r.PathValue("id"), format, kind)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "任务不存在")
		return
	}
	if err != nil {
		slog.Error("prepare run export", "run_id", r.PathValue("id"), "error", err)
		writeError(w, http.StatusInternalServerError, "导出失败，未生成完整文件")
		return
	}
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取导出文件失败")
		return
	}
	filename := exportFilename(run.ID, kind, format, snapshotAt)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Export-Snapshot-At", snapshotAt.Format(time.RFC3339Nano))
	w.Header().Set("Content-Type", map[string]string{"csv": "text/csv; charset=utf-8", "json": "application/json; charset=utf-8"}[format])
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	http.ServeContent(w, r, filename, time.Time{}, file)
}

func exportFilename(id, kind, format string, at time.Time) string {
	var safe strings.Builder
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			safe.WriteRune(c)
		}
		if safe.Len() >= 64 {
			break
		}
	}
	return "scan-" + safe.String() + "-" + kind + "-" + at.UTC().Format("20060102T150405Z") + "." + format
}

func (s *Server) prepareRunExport(ctx context.Context, file io.Writer, id, format, kind string) (Run, time.Time, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Run{}, time.Time{}, err
	}
	defer tx.Rollback(ctx)
	// Target quality is paginated below; do not materialize the full input array.
	run, err := scanRun(tx.QueryRow(ctx, runSelect(`'[]'::jsonb`, `runs`)+` WHERE r.id=$1`, id))
	if err != nil {
		return run, time.Time{}, err
	}
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
		return run, at, err
	}
	out := newRunExportWriter(file, format, kind, run, at.UTC())
	if err = out.start(); err != nil {
		return run, at, err
	}
	err = eachExportPage(ctx, tx, "targets", id, "", func(item map[string]any) error {
		return out.writeItem("target_quality", item)
	})
	if err == nil {
		err = out.startItems()
	}
	if err == nil && kind == "ports" {
		// Ports are grouped per source target by the existing list endpoint.
		err = eachExportPage(ctx, tx, "targets", id, "", func(target map[string]any) error {
			key, _ := target["target"].(string)
			return eachExportPage(ctx, tx, kind, id, key, func(item map[string]any) error {
				item["source_target"] = key
				return out.writeItem("result", item)
			})
		})
	} else if err == nil && kind != "targets" {
		err = eachExportPage(ctx, tx, kind, id, "", func(item map[string]any) error { return out.writeItem("result", item) })
	}
	if err == nil {
		err = out.finish()
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	return run, at.UTC(), err
}

func eachExportPage(ctx context.Context, tx pgx.Tx, kind, id, target string, write func(map[string]any) error) error {
	for offset := 0; ; offset += exportPageSize {
		var total int64
		var raw json.RawMessage
		var err error
		var counts [8]int64
		switch kind {
		case "targets":
			err = tx.QueryRow(ctx, targetResultPageQuery, id, "", "", exportPageSize, offset).Scan(&total, &counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &raw)
		case "ports":
			err = tx.QueryRow(ctx, portResultPageQuery, id, target, exportPageSize, offset).Scan(&total, &raw)
		case "http":
			err = tx.QueryRow(ctx, httpResultPageQuery, id, "", "", "all", exportPageSize, offset).Scan(&total, &raw)
		case "findings":
			err = tx.QueryRow(ctx, findingResultPageQuery, id, "all", "", "", "", exportPageSize, offset).Scan(&total, &counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5], &counts[6], &raw)
		default:
			return errors.New("unknown export kind")
		}
		if err != nil {
			return err
		}
		var page []map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err = decoder.Decode(&page); err != nil {
			return err
		}
		if len(page) == 0 && int64(offset) < total {
			return errors.New("export pagination ended before total")
		}
		for _, item := range page {
			if err = write(item); err != nil {
				return err
			}
		}
		if int64(offset+len(page)) >= total {
			return nil
		}
	}
}

var exportCSVColumns = strings.Fields("target source_target observed_at updated_at port url status_code finding_status severity coverage port_coverage state port_state error")

type runExportWriter struct {
	out     io.Writer
	csv     *csv.Writer
	kind    string
	run     Run
	at      time.Time
	first   bool
	runJSON []byte
}

func newRunExportWriter(out io.Writer, format, kind string, run Run, at time.Time) *runExportWriter {
	w := &runExportWriter{out: out, kind: kind, run: run, at: at, first: true}
	if format == "csv" {
		w.csv = csv.NewWriter(out)
	}
	return w
}

func (w *runExportWriter) start() error {
	raw, err := json.Marshal(w.run)
	if err != nil {
		return err
	}
	var metadata map[string]json.RawMessage
	if err = json.Unmarshal(raw, &metadata); err != nil {
		return err
	}
	// Original input targets are deliberately not loaded; target_quality holds
	// the complete paginated effective target list, so do not imply empty input.
	delete(metadata, "targets")
	w.runJSON, err = json.Marshal(metadata)
	if err != nil {
		return err
	}
	if w.csv != nil {
		columns := append([]string{"run_id", "run_name", "run_status", "run_modes", "snapshot_at", "export_complete", "export_kind", "record_type"}, exportCSVColumns...)
		return w.csv.Write(append(columns, "details_json", "run_json"))
	}
	_, err = fmt.Fprintf(w.out, `{"snapshot_at":%q,"complete":true,"kind":%q,"run":%s,"target_quality":[`, w.at.Format(time.RFC3339Nano), w.kind, w.runJSON)
	return err
}

func (w *runExportWriter) startItems() error {
	w.first = true
	if w.csv != nil {
		return nil
	}
	_, err := io.WriteString(w.out, `],"items":[`)
	return err
}

func (w *runExportWriter) writeItem(recordType string, item map[string]any) error {
	cleanExportValue(item)
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if w.csv != nil {
		row := []string{w.run.ID, w.run.Name, w.run.Status, exportCell(w.run.Modes), w.at.Format(time.RFC3339Nano), "true", w.kind, recordType}
		for _, key := range exportCSVColumns {
			row = append(row, exportCell(item[key]))
		}
		row = append(row, string(raw), string(w.runJSON))
		for i := range row {
			row[i] = safeExportCSVCell(row[i])
		}
		return w.csv.Write(row)
	}
	if !w.first {
		if _, err = io.WriteString(w.out, ","); err != nil {
			return err
		}
	}
	w.first = false
	_, err = w.out.Write(raw)
	return err
}

func (w *runExportWriter) finish() error {
	if w.csv != nil {
		w.csv.Flush()
		return w.csv.Error()
	}
	_, err := io.WriteString(w.out, "]}\n")
	return err
}

func exportCell(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func safeExportCSVCell(value string) string {
	trimmed := strings.TrimLeftFunc(value, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) || c == '\ufeff' })
	if len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

// Exports are result summaries, never raw evidence, binary screenshots, worker
// credentials, or request headers. Apply recursively to nested check evidence.
func cleanExportValue(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			lower := strings.ToLower(key)
			if contains([]string{"request_raw", "response_raw", "body_excerpt", "headers", "evidence", "checks", "banner", "png", "http_progress"}, lower) || exportSecretKey(lower) {
				delete(v, key)
				continue
			}
			if text, ok := item.(string); ok {
				if u, err := url.Parse(text); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
					u.User = nil
					q := u.Query()
					for name := range q {
						if exportSecretKey(strings.ToLower(name)) {
							q.Set(name, "[REDACTED]")
						}
					}
					u.RawQuery = q.Encode()
					v[key] = u.String()
				}
			}
			cleanExportValue(item)
		}
	case []any:
		for _, item := range v {
			cleanExportValue(item)
		}
	}
}

func exportSecretKey(key string) bool {
	key = strings.ReplaceAll(key, "-", "_")
	return strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "password") || strings.Contains(key, "api_key") || strings.Contains(key, "apikey") || strings.Contains(key, "access_key") || key == "authorization" || key == "cookie" || key == "set-cookie"
}
