package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"scanplatform/internal/rulesource"
)

func TestLiveRuleSourcesAndClaimCapacity(t *testing.T) {
	if os.Getenv("RULESOURCE_LIVE_TEST") != "1" {
		t.Skip("RULESOURCE_LIVE_TEST is not set")
	}
	server, handler := newPolicyTestServer(t, "source_live_test")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	wappalyzer, err := rulesource.Fetch(ctx, rulesource.WappalyzerID)
	if err != nil {
		t.Fatal(err)
	}
	if err = server.applyRuleSourceCatalog(ctx, rulesource.WappalyzerID, wappalyzer); err != nil {
		t.Fatal(err)
	}
	nuclei := rulesource.Catalog{Skipped: map[string]int{}}
	if os.Getenv("RULESOURCE_SKIP_NUCLEI") != "1" {
		nuclei, err = rulesource.Fetch(ctx, rulesource.NucleiID)
		if err != nil {
			t.Fatal(err)
		}
		if err = server.applyRuleSourceCatalog(ctx, rulesource.NucleiID, nuclei); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, http.MethodPost, "/api/workers/register", "join-policy", map[string]any{
		"instance_id": "capacity-worker", "hostname": "local", "agent_version": "test", "session_id": "capacity-session", "spec": map[string]any{},
	}, http.StatusOK, &worker)
	var run Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-policy", map[string]any{
		"name": "claim capacity", "targets": []string{"https://capacity.example"}, "modes": []string{"http"}, "poc_enabled": true,
	}, http.StatusCreated, &run)
	claimBody := map[string]any{"worker_id": worker.WorkerID, "session_id": "capacity-session", "request_id": "capacity-claim", "types": []string{"http"}, "supports_httpx_cff": true}
	uncompressed := recordAPI(handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, claimBody)
	if uncompressed.Code != http.StatusOK || uncompressed.Body.Len() >= 4<<20 {
		t.Fatalf("uncompressed claim status/bytes=%d/%d", uncompressed.Code, uncompressed.Body.Len())
	}
	encoded, _ := json.Marshal(claimBody)
	request := httptest.NewRequest(http.MethodPost, "/api/tasks/claim", bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer "+worker.WorkerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Encoding", "gzip")
	compressed := httptest.NewRecorder()
	handler.ServeHTTP(compressed, request)
	if compressed.Code != http.StatusOK || compressed.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip claim status/encoding=%d/%q", compressed.Code, compressed.Header().Get("Content-Encoding"))
	}
	compressedBytes := compressed.Body.Len()
	reader, err := gzip.NewReader(compressed.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil || len(decoded) != uncompressed.Body.Len() {
		t.Fatalf("decoded claim bytes=%d want=%d err=%v", len(decoded), uncompressed.Body.Len(), err)
	}
	t.Logf("wappalyzer total=%d accepted=%d skipped=%d; nuclei total=%d accepted=%d skipped=%d; claim_json=%d claim_gzip=%d",
		wappalyzer.Total, len(wappalyzer.Rules), skippedCount(wappalyzer.Skipped), nuclei.Total, len(nuclei.Rules), skippedCount(nuclei.Skipped),
		uncompressed.Body.Len(), compressedBytes)
	var refRun Run
	callAPI(t, handler, http.MethodPost, "/api/runs", "admin-policy", map[string]any{
		"name": "claim reference capacity", "targets": []string{"https://capacity-ref.example"}, "modes": []string{"http"}, "poc_enabled": true,
	}, http.StatusCreated, &refRun)
	refBody := map[string]any{"worker_id": worker.WorkerID, "session_id": "capacity-session", "request_id": "capacity-ref-claim", "types": []string{"http"}, "use_rule_sets": true, "supports_httpx_cff": true}
	reference := recordAPI(handler, http.MethodPost, "/api/tasks/claim", worker.WorkerToken, refBody)
	if reference.Code != http.StatusOK || reference.Body.Len() >= 2048 {
		t.Fatalf("reference claim status/bytes=%d/%d", reference.Code, reference.Body.Len())
	}
	t.Logf("reference_claim_json=%d", reference.Body.Len())
}

func skippedCount(items map[string]int) int {
	total := 0
	for _, count := range items {
		total += count
	}
	return total
}
