package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHTTPPermitEndpointIdentity(t *testing.T) {
	payload := []byte(`{"endpoints":[{"ip":"192.0.2.1","url":"https://one.example.test:8443/"},{"url":"http://192.0.2.2/"}]}`)
	for _, tc := range []struct {
		host, ip string
		port     int
		allowed  bool
	}{
		{"one.example.test", "192.0.2.1", 8443, true},
		{"other.example.test", "192.0.2.1", 8443, false},
		{"one.example.test", "192.0.2.3", 8443, false},
		{"one.example.test", "192.0.2.1", 443, false},
		{"192.0.2.2", "192.0.2.2", 80, true},
		{"192.0.2.2", "192.0.2.1", 80, false},
	} {
		req := httpPermitRequest{Host: tc.host, Port: tc.port}
		if got := httpPermitEndpoint(payload, req, netip.MustParseAddr(tc.ip)); got != tc.allowed {
			t.Fatalf("%+v got %v", tc, got)
		}
	}
}

func TestPostgresHTTPBudgetSharedAdmissionAndFences(t *testing.T) {
	server, handler := newPolicyTestServer(t, "http_budget")
	ctx := context.Background()
	peerPool, err := pgxpool.New(ctx, server.db.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer peerPool.Close()
	peer := &Server{db: peerPool, adminHash: server.adminHash, joinHash: server.joinHash, ctx: ctx}
	handlers := []http.Handler{handler, peer.Handler()}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := server.db.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE worker_pool SET enabled=true`)
	exec(`INSERT INTO runs(id,name,targets,modes,status) VALUES('http-budget-run','budget','["192.0.2.1"]','{http}','running')`)
	tokens := []string{"local-budget-worker-one", "local-budget-worker-two"}
	for i, token := range tokens {
		hash := sha256.Sum256([]byte(token))
		exec(`INSERT INTO workers(id,instance_id,hostname,status,agent_version,session_id,token_hash) VALUES($1,$1,'fixture','running','test','s1',$2)`, fmt.Sprintf("w%d", i), hash[:])
	}
	for i := 0; i < 14; i++ {
		id := fmt.Sprintf("task-%02d", i)
		worker := fmt.Sprintf("w%d", i%2)
		typ := "http"
		if i%2 == 1 {
			typ = "poc"
		}
		payload := fmt.Sprintf(`{"endpoints":[{"ip":"192.0.2.1","url":"http://host%d.example.test:8080/"},{"ip":"192.0.2.1","url":"https://host%d.example.test:8443/"}]}`, i, i)
		if i == 12 {
			payload = `{"endpoints":[{"url":"http://host12.example.test:8080/"}]}`
		}
		if i == 13 {
			payload = `{"endpoints":[{"ip":"192.0.2.2","url":"http://host13.example.test:8080/"}]}`
		}
		exec(`INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,worker_id,session_id,lease_until,rate_until,derived_key,target_key) VALUES($1,'http-budget-run',$2,$3,'leased',1,$4,'s1',now()+interval '1 minute',now()+interval '1 minute',$1,'192.0.2.1')`, id, typ, []byte(payload), worker)
		exec(`INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until) VALUES($1,$1,1,$2,$2,'s1','192.0.2.1','web_jobs',1,'active',now()+interval '1 minute')`, id, worker)
	}
	var evidenceMu sync.Mutex
	var evidence bytes.Buffer
	request := func(index int, req httpPermitRequest) (int, httpPermitResponse) {
		raw, _ := json.Marshal(req)
		r := httptest.NewRequest("POST", fmt.Sprintf("http://control.test/api/tasks/task-%02d/http-permit", index), bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+tokens[index%2])
		r.Header.Set("Content-Type", "application/json")
		dump, _ := httputil.DumpRequest(r, true)
		w := httptest.NewRecorder()
		handlers[index%2].ServeHTTP(w, r)
		response := w.Result()
		responseDump, _ := httputil.DumpResponse(response, true)
		evidenceMu.Lock()
		fmt.Fprintf(&evidence, "\n```http\n%s\n%s\n```\n", dump, responseDump)
		evidenceMu.Unlock()
		var out httpPermitResponse
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if path := os.Getenv("CONTROL_HTTP_BUDGET_EVIDENCE"); path != "" {
		t.Cleanup(func() {
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(path, evidence.Bytes(), 0600); err != nil {
				t.Error(err)
			}
		})
	}
	body := func(i int, id string) httpPermitRequest {
		return httpPermitRequest{WorkerID: fmt.Sprintf("w%d", i%2), SessionID: "s1", AttemptNo: 1, RequestID: id, ConnectIP: "192.0.2.1", Host: fmt.Sprintf("host%d.example.test", i), Port: 8080}
	}
	type result struct {
		index, status int
		out           httpPermitResponse
	}
	results := make(chan result, 12)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			code, out := request(i, body(i, "1"))
			results <- result{i, code, out}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	granted := 0
	var winner result
	for v := range results {
		if v.status != 200 {
			t.Fatalf("concurrent request %d: status %d", v.index, v.status)
		}
		if v.out.Granted {
			granted++
			winner = v
		} else if v.out.RetryAfterMS <= 0 {
			t.Fatal("denial lacks retry delay")
		}
	}
	if granted != 1 {
		t.Fatalf("simultaneous shared-IP admissions=%d, want one", granted)
	}
	req := body(winner.index, "1")
	status, replay := request(winner.index, req)
	if status != 200 || !replay.Granted || !replay.ValidUntil.Equal(winner.out.ValidUntil) {
		t.Fatalf("grant replay altered receipt: %d %+v", status, replay)
	}
	req.Port = 8443
	if status, _ := request(winner.index, req); status != 409 {
		t.Fatalf("changed grant body status=%d", status)
	}
	req = body(winner.index, "2")
	time.Sleep(110 * time.Millisecond)
	status, second := request(winner.index, req)
	if status != 200 || !second.Granted || second.ServerTime.Sub(winner.out.ServerTime) < 100*time.Millisecond {
		t.Fatalf("admission pacing: %d %+v", status, second)
	}
	exec(`UPDATE workers SET maintenance=true,status='draining' WHERE id=$1`, fmt.Sprintf("w%d", winner.index%2))
	if status, out := request(winner.index, body(winner.index, "2")); status != 200 || !out.Granted || !out.ValidUntil.Equal(second.ValidUntil) {
		t.Fatalf("maintenance/draining interrupted existing execution: %d %+v", status, out)
	}
	exec(`UPDATE workers SET maintenance=false,status='running' WHERE id=$1`, fmt.Sprintf("w%d", winner.index%2))
	if status, _ := request(winner.index, body(winner.index, "1")); status != 409 {
		t.Fatalf("superseded ID status=%d", status)
	}
	exec(`UPDATE http_permit_receipts SET valid_until=now()-interval '1 second' WHERE task_id=$1`, fmt.Sprintf("task-%02d", winner.index))
	if status, _ := request(winner.index, body(winner.index, "2")); status != 409 {
		t.Fatalf("expired ID status=%d", status)
	}
	// A distinct IP is still denied by a future cluster slot.
	exec(`UPDATE http_cluster_budget SET next_at=clock_timestamp()+interval '500 milliseconds' WHERE singleton`)
	clusterReq := body(13, "1")
	clusterReq.ConnectIP = "192.0.2.2"
	if status, out := request(13, clusterReq); status != 200 || out.Granted || out.RetryAfterMS < 400 {
		t.Fatalf("cluster budget: %d %+v", status, out)
	}
	exec(`UPDATE http_cluster_budget SET next_at='epoch' WHERE singleton`)
	exec(`UPDATE http_ip_budgets SET next_at=clock_timestamp()`)
	if status, out := request(12, body(12, "1")); status != 200 || !out.Granted {
		t.Fatalf("domain first binding: %d %+v", status, out)
	}
	domainReq := body(12, "2")
	domainReq.ConnectIP = "192.0.2.3"
	if status, _ := request(12, domainReq); status != 409 {
		t.Fatalf("domain execution changed IP: %d", status)
	}
	stats, err := peer.HTTPBudgetStatus(ctx)
	if err != nil || stats["cluster_rps"] != 250 || stats["per_connect_ip_rps"] != 10 {
		t.Fatalf("budget status: %v %v", stats, err)
	}
	invalid := body(winner.index, "3")
	invalid.ConnectIP = "192.0.2.9"
	if status, _ := request(winner.index, invalid); status != 400 {
		t.Fatalf("arbitrary IP status=%d", status)
	}
	invalid = body(winner.index, "3")
	invalid.AttemptNo = 2
	if status, _ := request(winner.index, invalid); status != 409 {
		t.Fatalf("old attempt status=%d", status)
	}
	taskID := fmt.Sprintf("task-%02d", winner.index)
	for _, state := range []string{"paused", "cancelling", "cancelled", "failed"} {
		exec(`UPDATE runs SET status=$1 WHERE id='http-budget-run'`, state)
		if status, _ := request(winner.index, body(winner.index, "3")); status != 409 {
			t.Fatalf("run %s status=%d", state, status)
		}
	}
	exec(`UPDATE runs SET status='running' WHERE id='http-budget-run'`)
	exec(`UPDATE target_quotas SET state='suspect' WHERE task_id=$1`, taskID)
	if status, _ := request(winner.index, body(winner.index, "3")); status != 409 {
		t.Fatalf("unknown stop status=%d", status)
	}
	exec(`UPDATE target_quotas SET state='active' WHERE task_id=$1`, taskID)
	exec(`UPDATE tasks SET lease_until=now()-interval '1 second' WHERE id=$1`, taskID)
	if status, _ := request(winner.index, body(winner.index, "3")); status != 409 {
		t.Fatalf("expired lease status=%d", status)
	}
	exec(`UPDATE tasks SET lease_until=now()+interval '1 minute' WHERE id=$1`, taskID)
	exec(`UPDATE tasks SET state='cancelled' WHERE id=$1`, taskID)
	if status, _ := request(winner.index, body(winner.index, "3")); status != 409 {
		t.Fatalf("stopped task status=%d", status)
	}
	exec(`UPDATE tasks SET state='leased' WHERE id=$1`, taskID)
	exec(`UPDATE worker_pool SET enabled=false`)
	if status, _ := request(winner.index, body(winner.index, "3")); status != 409 {
		t.Fatalf("disabled pool status=%d", status)
	}
	exec(`UPDATE worker_pool SET enabled=true`)
	exec(`UPDATE workers SET session_id='s2' WHERE id=$1`, fmt.Sprintf("w%d", winner.index%2))
	if status, _ := request(winner.index, body(winner.index, "3")); status != 401 {
		t.Fatalf("replaced session status=%d", status)
	}
	var receiptCount, ipCount int
	if err := server.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM http_permit_receipts),(SELECT count(*) FROM http_ip_budgets)`).Scan(&receiptCount, &ipCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 2 || ipCount != 2 {
		t.Fatalf("unbounded per-request storage: receipts/IPs %d/%d", receiptCount, ipCount)
	}
	t.Logf("PASS: two independent control pools; HTTP+PoC, 12 distinct host/tasks share one connect IP, burst=1, spacing>=100ms, exact replay, altered/superseded/expired IDs, arbitrary IP, stale attempt, paused/cancelled run, unknown-stop quota, expired lease, replaced session, cluster limit, fixed first domain binding, maintenance/draining continuation, stopped task/pool rejection; receipt rows=%d IP rows=%d", receiptCount, ipCount)
}

func TestHTTPPermitMalformedIDs(t *testing.T) {
	s := &Server{}
	for _, id := range []string{"", "0", "-1", "01", "9223372036854775808", strings.Repeat("1", 100)} {
		raw, _ := json.Marshal(httpPermitRequest{WorkerID: "w", SessionID: "s", AttemptNo: 1, RequestID: id, ConnectIP: "192.0.2.1", Host: "example.test", Port: 80})
		w := httptest.NewRecorder()
		s.httpPermit(w, httptest.NewRequest("POST", "/", bytes.NewReader(raw)))
		if w.Code != 400 {
			t.Fatalf("id=%q status=%d", id, w.Code)
		}
	}
}

func TestPostgresHTTPBudgetClaimCapabilityFence(t *testing.T) {
	server, handler := newPolicyTestServer(t, "http_budget_claim")
	ctx := context.Background()
	if path := os.Getenv("CONTROL_HTTP_BUDGET_EVIDENCE"); path != "" {
		var evidence bytes.Buffer
		baseHandler := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dump, _ := httputil.DumpRequest(r, true)
			recorder := httptest.NewRecorder()
			baseHandler.ServeHTTP(recorder, r)
			responseDump, _ := httputil.DumpResponse(recorder.Result(), true)
			fmt.Fprintf(&evidence, "\n```http\n%s\n%s\n```\n", dump, responseDump)
			for name, values := range recorder.Header() {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
		})
		t.Cleanup(func() {
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(path+".capability.md", evidence.Bytes(), 0600); err != nil {
				t.Error(err)
			}
		})
	}
	if _, err := server.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	var worker struct {
		WorkerID    string `json:"worker_id"`
		WorkerToken string `json:"worker_token"`
	}
	callAPI(t, handler, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "budget-claim-worker", "hostname": "fixture", "agent_version": "test", "session_id": "s1", "spec": map[string]any{}}, 200, &worker)
	for index, stage := range []string{"http", "poc"} {
		runID := "claim-budget-" + stage
		ip := fmt.Sprintf("192.0.2.%d", index+10)
		if _, err := server.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status) VALUES($1,$1,$2,'{http}','pending')`, runID, []byte(fmt.Sprintf(`["%s"]`, ip))); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"endpoints": []map[string]any{{"ip": ip, "port": 80}}, "endpoint": map[string]any{"ip": ip, "port": 80}})
		if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES($1,$1,$2,$3,$1,$4)`, runID, stage, payload, ip); err != nil {
			t.Fatal(err)
		}
		claim := map[string]any{"worker_id": worker.WorkerID, "session_id": "s1", "supports_confirmed_stop": true, "types": []string{stage}, "request_id": "old-" + stage}
		var result struct {
			Task          *Task  `json:"task"`
			Expired       bool   `json:"expired"`
			BlockedReason string `json:"blocked_reason"`
		}
		callAPI(t, handler, "POST", "/api/tasks/claim", worker.WorkerToken, claim, 200, &result)
		if result.Task != nil || result.BlockedReason != "agent_upgrade_required" {
			t.Fatalf("%s missing-capability claim=%+v", stage, result)
		}
		claim["supports_http_request_budget"] = true
		claim["request_id"] = "current-" + stage
		result.Task = nil
		result.Expired = false
		callAPI(t, handler, "POST", "/api/tasks/claim", worker.WorkerToken, claim, 200, &result)
		if result.Task == nil || result.Task.Type != stage {
			t.Fatalf("%s capable claim=%+v", stage, result)
		}
		delete(claim, "supports_http_request_budget")
		result.Task = nil
		result.Expired = false
		callAPI(t, handler, "POST", "/api/tasks/claim", worker.WorkerToken, claim, 200, &result)
		if result.Task != nil || !result.Expired {
			t.Fatalf("%s replay downgrade granted=%+v", stage, result)
		}
	}
}

func TestHTTPPermitPreservesCanonicalIPv6EndpointIdentity(t *testing.T) {
	payload := []byte(`{"endpoints":[{"url":"https://[2001:db8::1]:8443/"}]}`)
	req := httpPermitRequest{Host: "2001:db8::1", Port: 8443}
	if !httpPermitEndpoint(payload, req, netip.MustParseAddr("2001:0db8:0:0:0:0:0:1")) {
		t.Fatal("canonical IPv6 HTTP endpoint was rejected")
	}
	if httpPermitEndpoint(payload, req, netip.MustParseAddr("2001:db8::2")) {
		t.Fatal("unassigned IPv6 HTTP endpoint was accepted")
	}
}
