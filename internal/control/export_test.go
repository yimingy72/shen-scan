package control

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunExportEncoding(t *testing.T) {
	at := time.Date(2026, 10, 22, 1, 2, 3, 0, time.UTC)
	run := Run{ID: "run", Name: " \t=HYPERLINK(\"bad\")", Status: "running", Modes: []string{"http"}}
	for _, format := range []string{"csv", "json"} {
		var out bytes.Buffer
		w := newRunExportWriter(&out, format, "http", run, at)
		if err := w.start(); err != nil {
			t.Fatal(err)
		}
		if err := w.writeItem("target_quality", map[string]any{"target": "example.com", "port_coverage": "partial", "task_failed": 1}); err != nil {
			t.Fatal(err)
		}
		if err := w.startItems(); err != nil {
			t.Fatal(err)
		}
		item := map[string]any{"url": "https://user:password@example.com/a?token=raw-secret&ok=1", "title": "=SUM(1,2)\nquoted,\"title\"", "coverage": "partial", "response_raw": "raw-secret", "checks": []any{map[string]any{"request_raw": "raw-secret"}}, "screenshot": map[string]any{"png": "raw-secret", "state": "complete"}, "access_token": "raw-secret"}
		if err := w.writeItem("result", item); err != nil {
			t.Fatal(err)
		}
		if err := w.finish(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "raw-secret") || strings.Contains(out.String(), "user:password") {
			t.Fatalf("%s leaked raw evidence or credential", format)
		}
		if format == "csv" {
			rows, err := csv.NewReader(&out).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 3 || rows[1][1] != "'"+run.Name {
				t.Fatalf("CSV quoting/record count: %v", rows)
			}
			if !strings.Contains(rows[2][len(rows[2])-2], "quoted,\\\"title\\\"") {
				t.Fatal("CSV lost full nested fields")
			}
		} else if !json.Valid(out.Bytes()) {
			t.Fatal("invalid JSON export")
		}
	}
	for _, cell := range []string{"=x", " +x", "\t-x", "\r@x", "\ufeff=x"} {
		if !strings.HasPrefix(safeExportCSVCell(cell), "'") {
			t.Fatalf("unsafe CSV cell %q", cell)
		}
	}
	for _, format := range []string{"json", "csv"} {
		w := newRunExportWriter(exportFailWriter{}, format, "http", run, at)
		err := w.start()
		if err == nil {
			err = w.finish()
		}
		if err == nil {
			t.Fatalf("%s hid a failed output write", format)
		}
	}
	if name := exportFilename("../../a\r\nb", "http", "json", at); name != "scan-ab-http-20261022T010203Z.json" {
		t.Fatalf("unsafe filename %q", name)
	}
}

type exportFailWriter struct{}

func (exportFailWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

type exportMutatingWriter struct {
	bytes.Buffer
	mutate func()
}

func (w *exportMutatingWriter) Write(p []byte) (int, error) {
	if w.mutate != nil && bytes.Contains(p, []byte(`"status_code"`)) {
		mutate := w.mutate
		w.mutate = nil
		mutate()
	}
	return w.Buffer.Write(p)
}

func TestRunExportPostgresSnapshotAndPagination(t *testing.T) {
	s, handler := newPolicyTestServer(t, "export_test")
	ctx := context.Background()
	targets := make([]string, exportPageSize+5)
	for i := range targets {
		targets[i] = fmt.Sprintf("target-%03d.example.com", i)
	}
	var run Run
	callAPI(t, handler, "POST", "/api/runs", "admin-policy", map[string]any{"name": "=export", "targets": targets, "modes": []string{"http"}}, 201, &run)
	var task, receiptTask string
	if err := s.db.QueryRow(ctx, `SELECT id FROM tasks WHERE run_id=$1 AND target_key=$2 LIMIT 1`, run.ID, targets[0]).Scan(&task); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(ctx, `SELECT id FROM tasks WHERE run_id=$1 AND target_key=$2 LIMIT 1`, run.ID, targets[1]).Scan(&receiptTask); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE tasks SET state='completed',attempt_no=2,accepted_attempt_no=2,coverage='complete' WHERE run_id=$1`, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE tasks SET type='port',state='failed',coverage='partial' WHERE id=$1`, receiptTask); err != nil {
		t.Fatal(err)
	}
	insert := func(taskID, target string, attempt, index int, o map[string]any) string {
		t.Helper()
		id := newID()
		raw, _ := json.Marshal(o)
		if _, err := s.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation) VALUES($1,$2,$3,$4,0,$5,$6,$7)`, id, run.ID, taskID, attempt, index, target, raw); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for i := 0; i < exportPageSize+1; i++ {
		insert(task, targets[0], 2, i*3, map[string]any{"kind": "http", "target": targets[0], "url": fmt.Sprintf("https://%s/%03d", targets[0], i), "status_code": 200, "response_raw": "private-raw"})
		insert(task, targets[0], 2, i*3+1, map[string]any{"kind": "port", "target": targets[0], "ip": targets[0], "port": i + 1})
		insert(task, targets[0], 2, i*3+2, map[string]any{"kind": "poc", "target": targets[0], "rule_id": fmt.Sprintf("rule-%d", i), "finding_status": []string{"matched", "not_matched", "error", "incomplete"}[i%4], "coverage": "partial"})
	}
	insert(task, targets[0], 1, 9999, map[string]any{"kind": "http", "target": targets[0], "url": "https://stale.example/", "status_code": 200})
	portID := insert(receiptTask, targets[1], 1, 0, map[string]any{"kind": "port", "target": targets[1], "port": 443})
	pocID := insert(receiptTask, targets[1], 1, 1, map[string]any{"kind": "poc", "target": targets[1], "rule_id": "independent", "finding_status": "incomplete", "coverage": "partial"})
	if _, err := s.db.Exec(ctx, `INSERT INTO port_positive_receipts(id,run_id,target_key,port,source_task_id,source_attempt_no,batch_seq,batch_digest,observation_id) VALUES($1,$2,$3,443,$4,1,0,'digest',$5)`, newID(), run.ID, targets[1], receiptTask, portID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO poc_template_receipts(task_id,rule_id,rule_revision,template_id,content_sha256,source_attempt_no,batch_seq,batch_digest,observation_id,completion_id) VALUES($1,'independent',1,'template','hash',1,0,'digest',$2,$3)`, receiptTask, pocID, newID()); err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[string]int{"targets": 0, "http": 201, "ports": 202, "findings": 202} {
		req := httptest.NewRequest("GET", "/api/runs/"+run.ID+"/export?format=json&kind="+kind, nil)
		req.Header.Set("Authorization", "Bearer admin-policy")
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != 200 || rr.Header().Get("Content-Encoding") != "" {
			t.Fatalf("%s export: %d %s", kind, rr.Code, rr.Body.String())
		}
		var got struct {
			Complete      bool
			SnapshotAt    string           `json:"snapshot_at"`
			TargetQuality []map[string]any `json:"target_quality"`
			Items         []map[string]any
			Run           Run
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Complete || got.SnapshotAt == "" || len(got.TargetQuality) != len(targets) || len(got.Items) != want || got.Run.Status != "pending" {
			t.Fatalf("%s missing page/quality/run state: quality=%d items=%d run=%s", kind, len(got.TargetQuality), len(got.Items), got.Run.Status)
		}
		if strings.Contains(rr.Body.String(), "stale.example") || strings.Contains(rr.Body.String(), "private-raw") {
			t.Fatal("export includes stale/raw observations")
		}
		if kind == "ports" && !strings.Contains(rr.Body.String(), portID) {
			t.Fatal("independent positive receipt lost")
		}
		if kind == "findings" && !strings.Contains(rr.Body.String(), pocID) {
			t.Fatal("independent template receipt lost")
		}
	}
	out := &exportMutatingWriter{mutate: func() {
		if _, err := s.db.Exec(ctx, `UPDATE tasks SET state='failed' WHERE id=$1`, task); err != nil {
			t.Fatal(err)
		}
	}}
	if _, _, err := s.prepareRunExport(ctx, out, run.ID, "json", "http"); err != nil {
		t.Fatal(err)
	}
	var snapshot struct{ Items []map[string]any }
	if err := json.Unmarshal(out.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Items) != 201 {
		t.Fatalf("concurrent change tore export snapshot: %d", len(snapshot.Items))
	}
	if _, _, err := s.prepareRunExport(ctx, exportFailWriter{}, run.ID, "json", "http"); err == nil {
		t.Fatal("preparation accepted failed output")
	}
	for _, test := range []struct {
		path, token string
		status      int
	}{
		{"/api/runs/" + run.ID + "/export?format=json&kind=http", "", 401},
		{"/api/runs/" + run.ID + "/export?format=bad&kind=http", "admin-policy", 400},
		{"/api/runs/missing/export?format=csv&kind=targets", "admin-policy", 404},
	} {
		callAPI(t, handler, http.MethodGet, test.path, test.token, nil, test.status, nil)
	}
	var csvOut bytes.Buffer
	if _, _, err := s.prepareRunExport(ctx, &csvOut, run.ID, "csv", "findings"); err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(&csvOut)
	rows := 0
	for {
		_, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rows++
	}
	// After the mutation, only the independent finding is effective; every
	// target quality row is retained regardless of whether it has a finding.
	if rows != len(targets)+2 {
		t.Fatalf("CSV quality/result rows: %d", rows)
	}
	before, err := filepath.Glob(filepath.Join(os.TempDir(), "scan-export-*"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(ctx, `ALTER TABLE assets RENAME TO export_unavailable_assets`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/runs/"+run.ID+"/export?format=json&kind=http", nil)
	req.Header.Set("Authorization", "Bearer admin-policy")
	handler.ServeHTTP(rr, req)
	if rr.Code != 500 || rr.Header().Get("Content-Disposition") != "" || strings.Contains(rr.Body.String(), `"complete":true`) {
		t.Fatalf("failed preparation served attachment: %d %s", rr.Code, rr.Body.String())
	}
	after, err := filepath.Glob(filepath.Join(os.TempDir(), "scan-export-*"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatal("export leaked temporary file")
	}
}
