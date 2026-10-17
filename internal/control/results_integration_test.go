package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestResultGroupingAndAttemptFence(t *testing.T) {
	databaseURL := os.Getenv("CONTROL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schemaName := "results_test_" + strings.ReplaceAll(newID(), "-", "")
	if _, err = db.Exec(ctx, `CREATE SCHEMA `+schemaName); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(databaseURL)
	q := u.Query()
	q.Set("search_path", schemaName)
	u.RawQuery = q.Encode()
	s, err := New(ctx, u.String(), "admin-results", "join-results")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); _, _ = db.Exec(ctx, `DROP SCHEMA `+schemaName+` CASCADE`) })
	var run Run
	callAPI(t, s.Handler(), http.MethodPost, "/api/runs", "admin-results", map[string]any{"name": "grouping", "targets": []string{"192.0.2.10", "192.0.2.11", "example.com"}, "modes": []string{"port", "http"}}, 201, &run)
	var portID, httpID string
	if err = s.db.QueryRow(ctx, `SELECT id FROM tasks WHERE run_id=$1 AND target_key='192.0.2.10'`, run.ID).Scan(&portID); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(ctx, `SELECT id FROM tasks WHERE run_id=$1 AND target_key='example.com'`, run.ID).Scan(&httpID); err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(ctx, `UPDATE tasks SET state='completed',attempt_no=2 WHERE run_id=$1`, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(taskID string, attempt, index int, o Observation) string {
		t.Helper()
		id := newID()
		raw, _ := json.Marshal(o)
		_, err := s.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,observation,target_key) VALUES($1,$2,$3,$4,0,$5,$6,$7)`, id, run.ID, taskID, attempt, index, raw, canonicalTarget(o.Target))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	insert(portID, 1, 0, Observation{Kind: "port", Target: "192.0.2.10", IP: "192.0.2.10", Port: 9999})
	insert(portID, 2, 0, Observation{Kind: "port", Target: "192.0.2.10", IP: "192.0.2.10", Port: 80})
	insert(portID, 2, 1, Observation{Kind: "port", Target: "192.0.2.10", IP: "192.0.2.10", Port: 80})
	insert(portID, 2, 2, Observation{Kind: "service", Target: "192.0.2.10", IP: "192.0.2.10", Port: 80, Service: "http", Product: "nginx"})
	httpObservation := insert(httpID, 2, 0, Observation{Kind: "http", Target: "http://example.com", URL: "https://redirect.example.net/", IP: "192.0.2.10", Port: 443, StatusCode: 200, Title: "Example", Technologies: []Technology{{Name: "WordPress"}}, ResponseRaw: "HTTP/1.1 200 OK\r\n\r\nfull body"})
	insert(httpID, 2, 1, Observation{Kind: "http", Target: "https://example.com", URL: "https://example.com/", Port: 443, Error: "timeout"})
	var result struct {
		Items []struct {
			Target, PortState string
			Ports             []int
			OpenPortCount     int    `json:"open_port_count"`
			HTTPCount         int    `json:"http_count"`
			PortStatus        string `json:"port_state"`
		}
		Total int
	}
	// Surface SQL diagnostics directly in this single focused database check.
	var count int
	if err = s.db.QueryRow(ctx, targetResults+` SELECT count(*) FROM filtered`, run.ID, "", "").Scan(&count); err != nil {
		t.Fatal(err)
	}
	callAPI(t, s.Handler(), "GET", "/api/runs/"+run.ID+"/results", "admin-results", nil, 200, &result)
	if result.Total != 3 {
		t.Fatalf("target total=%d", result.Total)
	}
	for _, row := range result.Items {
		switch row.Target {
		case "192.0.2.10":
			if row.OpenPortCount != 1 || len(row.Ports) != 1 || row.Ports[0] != 80 || row.HTTPCount != 0 {
				t.Fatalf("IP merged incorrectly: %+v", row)
			}
		case "192.0.2.11":
			if row.OpenPortCount != 0 || row.PortStatus != "completed" {
				t.Fatalf("empty target missing completion: %+v", row)
			}
		case "example.com":
			if row.PortStatus != "not_scanned" || row.HTTPCount != 1 || row.OpenPortCount != 0 {
				t.Fatalf("domain merged with resolved IP: %+v", row)
			}
		}
	}
	var ports struct {
		Items []struct {
			Port    int
			Product string
		}
		Total int
	}
	callAPI(t, s.Handler(), "GET", "/api/runs/"+run.ID+"/ports?target=192.0.2.10", "admin-results", nil, 200, &ports)
	if ports.Total != 1 || ports.Items[0].Product != "nginx" {
		t.Fatalf("ports=%+v", ports)
	}
	var httpResults struct {
		Items []map[string]any
		Total int
	}
	callAPI(t, s.Handler(), "GET", "/api/runs/"+run.ID+"/http", "admin-results", nil, 200, &httpResults)
	if httpResults.Total != 2 {
		t.Fatalf("http total=%d", httpResults.Total)
	}
	for _, row := range httpResults.Items {
		if row["source_target"] != "example.com" || row["response_raw"] != nil {
			t.Fatal("HTTP source or lazy evidence is wrong")
		}
	}
	callAPI(t, s.Handler(), "GET", "/api/runs/"+run.ID+"/http?status=responded", "admin-results", nil, 200, &httpResults)
	if httpResults.Total != 1 {
		t.Fatal("successful HTTP endpoints include failed probes")
	}
	callAPI(t, s.Handler(), "GET", "/api/runs/"+run.ID+"/results?filter=errors", "admin-results", nil, 200, &result)
	if result.Total != 0 {
		t.Fatal("expected HTTP non-response was classified as a task failure")
	}
	var evidence Asset
	callAPI(t, s.Handler(), "GET", "/api/observations/"+httpObservation, "admin-results", nil, 200, &evidence)
	if !strings.HasSuffix(evidence.ResponseRaw, "full body") {
		t.Fatal("evidence was lost")
	}
	callAPI(t, s.Handler(), "GET", "/api/runs/"+run.ID, "admin-results", nil, 200, &run)
	if run.TargetCount != 3 || run.InputCount != 3 || run.OpenPortCount != 1 || run.HTTPCount != 1 {
		t.Fatalf("run counts=%+v", run)
	}
	var runs struct{ Items []Run }
	callAPI(t, s.Handler(), "GET", "/api/runs", "admin-results", nil, 200, &runs)
	if len(runs.Items) != 1 || len(runs.Items[0].Targets) != 3 {
		t.Fatalf("full run list=%+v", runs.Items)
	}
	callAPI(t, s.Handler(), "GET", "/api/runs?summary=true", "admin-results", nil, 200, &runs)
	if len(runs.Items) != 1 || runs.Items[0].InputCount != 3 || len(runs.Items[0].Targets) != 2 {
		t.Fatalf("run summary=%+v", runs.Items)
	}
}

func TestPayloadTargetPreservesSource(t *testing.T) {
	for raw, want := range map[string]string{`{"targets":["192.0.2.1"]}`: "192.0.2.1", `{"endpoints":[{"url":"https://EXAMPLE.com:8443/a"}]}`: "example.com", `{"endpoints":[{"url":"https://[2001:db8::1]/"}]}`: "2001:db8::1"} {
		if got := payloadTarget([]byte(raw)); got != want {
			t.Fatalf("%s: got %q, want %q", raw, got, want)
		}
	}
}
