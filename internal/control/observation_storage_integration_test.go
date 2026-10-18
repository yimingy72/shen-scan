package control

import (
	"context"
	"encoding/json"
	"net/http"
	"scanplatform/internal/webevidence"
	"strings"
	"testing"
)

func TestBinaryObservationBatchRoundTrip(t *testing.T) {
	server, handler := newPolicyTestServer(t, "binary_observation")
	ctx := context.Background()
	if _, err := server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, http.MethodPost, "/api/workers/register", "join-policy", map[string]any{
		"instance_id": "local-binary-fixture", "hostname": "local", "session_id": "binary-session",
	}, http.StatusOK, &worker)
	var run Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-policy", map[string]any{
		"name": "binary observations", "targets": []string{"192.0.2.20"}, "modes": []string{"port", "http"},
	}, http.StatusCreated, &run)
	claim := func(kind string) Task {
		t.Helper()
		var out struct {
			Task *Task `json:"task"`
		}
		callAPI(t, handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, map[string]any{
			"worker_id": worker.WorkerID, "session_id": "binary-session", "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile, "web_enrichment_profile": webevidence.EnrichmentProfile, "fingerprint_bundle": webevidence.FingerprintBundle, "supports_confirmed_stop": true, "supports_http_request_budget": true, "request_id": kind, "types": []string{kind},
		}, http.StatusOK, &out)
		if out.Task == nil {
			t.Fatalf("no %s task", kind)
		}
		return *out.Task
	}
	batch := func(task Task, items []Observation, status int) {
		t.Helper()
		callAPI(t, handler, http.MethodPost, "/api/tasks/"+task.ID+"/batches", worker.WorkerToken, map[string]any{
			"worker_id": worker.WorkerID, "session_id": "binary-session", "attempt_no": task.AttemptNo, "batch_seq": 0, "items": items,
		}, status, nil)
	}
	complete := func(task Task) {
		t.Helper()
		callAPI(t, handler, http.MethodPost, "/api/tasks/"+task.ID+"/complete", worker.WorkerToken, map[string]any{
			"worker_id": worker.WorkerID, "session_id": "binary-session", "attempt_no": task.AttemptNo, "last_batch_seq": 0,
		}, http.StatusOK, nil)
	}
	port := claim("port")
	batch(port, []Observation{{Kind: "port", Target: "192.0.2.20", IP: "192.0.2.20", Port: 3306, Protocol: "tcp"}}, http.StatusOK)
	complete(port)
	for _, kind := range []string{"service", "http"} {
		task := claim(kind)
		var payload struct {
			Endpoints []taskEndpoint `json:"endpoints"`
		}
		if err := json.Unmarshal(task.Payload, &payload); err != nil || len(payload.Endpoints) != 1 {
			t.Fatalf("invalid assigned entry: %s %v", task.Payload, err)
		}
		item := Observation{Kind: kind, Target: "192.0.2.20", IP: "192.0.2.20", Port: 3306, Protocol: "tcp", WorkKey: payload.Endpoints[0].WorkKey}
		if kind == "service" {
			item.Banner = "J\x00\x00\x00\x0a8.4.11\x00 literal \\u0000 and ␀"
			item.Service, item.Product, item.Version = "mysql", "MySQL", "8.4.11"
		} else {
			item.URL, item.Protocol, item.StatusCode = "http://192.0.2.20:3306/", "http", 200
			item.BodyExcerpt, item.ResponseRaw = "body\x00tail", "HTTP/1.1 200 OK\r\n\r\nbody\x00tail"
			item.Headers = map[string][]string{"X-Fixture": {"literal \\u0000", "zero\x00end"}}
			item = controlHTTPFixture(item)
		}
		items := []Observation{item}
		batch(task, items, http.StatusOK)
		batch(task, items, http.StatusOK)
		var id string
		var count int
		if err := server.db.QueryRow(ctx, `SELECT min(id),count(*) FROM assets WHERE task_id=$1`, task.ID).Scan(&id, &count); err != nil || count != 1 {
			t.Fatalf("rows=%d err=%v", count, err)
		}
		var detail Asset
		callAPI(t, handler, http.MethodGet, "/api/observations/"+id, "admin-policy", nil, http.StatusOK, &detail)
		got, _ := json.Marshal(detail.Observation)
		want, _ := json.Marshal(item)
		if string(got) != string(want) {
			t.Fatalf("original observation changed: %s != %s", got, want)
		}
		complete(task)
		batch(task, items, http.StatusOK) // lost response after completion remains idempotent
		items[0].Banner = strings.ReplaceAll(item.Banner, "\x00", "␀")
		items[0].BodyExcerpt = strings.ReplaceAll(item.BodyExcerpt, "\x00", "␀")
		batch(task, items, http.StatusConflict) // equal display text must not mean equal content
	}
	callAPI(t, handler, http.MethodGet, "/api/runs/"+run.ID, "admin-policy", nil, http.StatusOK, &run)
	if run.Status != "completed" {
		t.Fatalf("run status=%s", run.Status)
	}
}
