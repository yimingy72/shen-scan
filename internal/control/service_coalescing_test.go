package control

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestEarlyQueuedServiceCoalescing(t *testing.T) {
	t.Setenv("SCAN_CALIBRATED_PORT_PROFILE", "")
	s, h := newPolicyTestServer(t, "queued_service_coalescing")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	call := earlyEvidenceCaller(t, h)
	type worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	workers := make([]worker, 2)
	for i := range workers {
		instance := "coalesce-port"
		if i == 1 {
			instance = "coalesce-service"
		}
		call("POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": instance, "hostname": "fixture", "session_id": "session"}, 200, &workers[i])
	}
	var run Run
	call("POST", "/api/runs", "admin-policy", map[string]any{"name": "queued coalescing fixture", "targets": []string{"192.0.2.63"}, "modes": []string{"port"}}, 201, &run)
	claim := func(i int, stage string) *Task {
		var out struct {
			Task *Task `json:"task"`
		}
		call("POST", "/api/tasks/claim", workers[i].Token, map[string]any{"worker_id": workers[i].ID, "session_id": "session", "request_id": stage + newID(), "types": []string{stage}, "supports_confirmed_stop": true, "supports_port_ranges": true, "service_profile": "nmap-light-v1"}, 200, &out)
		if out.Task == nil {
			t.Fatalf("no %s task", stage)
		}
		return out.Task
	}
	source := claim(0, "port")
	submit := func(seq, port int) {
		call("POST", "/api/tasks/"+source.ID+"/batches", workers[0].Token, map[string]any{"worker_id": workers[0].ID, "session_id": "session", "attempt_no": source.AttemptNo, "batch_seq": seq, "items": []Observation{{Kind: "port", IP: "192.0.2.63", Port: port}}}, 200, nil)
	}
	submit(0, 80)
	var firstID, firstReceipt string
	if err := s.db.QueryRow(ctx, `SELECT task_id FROM port_service_work WHERE run_id=$1 AND port=80`, run.ID).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(ctx, `SELECT payload->'endpoints'->0->>'positive_port_receipt_id' FROM tasks WHERE id=$1`, firstID).Scan(&firstReceipt); err != nil {
		t.Fatal(err)
	}
	call("POST", "/api/tasks/"+source.ID+"/release", workers[0].Token, map[string]any{"worker_id": workers[0].ID, "session_id": "session", "attempt_no": source.AttemptNo, "reason": "fixture source retry before service claim", "retryable": true, "stopped": true}, 200, nil)
	source = claim(0, "port")
	if source.AttemptNo != 2 {
		t.Fatal("source retry not claimed", source)
	}
	submit(0, 443)
	var queued, items int
	if err := s.db.QueryRow(ctx, `SELECT count(*),sum(jsonb_array_length(payload->'endpoints')) FROM tasks WHERE run_id=$1 AND type='service'`, run.ID).Scan(&queued, &items); err != nil || queued != 1 || items != 2 {
		t.Fatal("did not merge two early batches", queued, items, err)
	}
	var sameBindings bool
	if err := s.db.QueryRow(ctx, `SELECT bool_and(task_id=$2) FROM port_service_work WHERE run_id=$1`, run.ID, firstID).Scan(&sameBindings); err != nil || !sameBindings {
		t.Fatal(sameBindings, err)
	}
	var preservedReceipt string
	if err := s.db.QueryRow(ctx, `SELECT payload->'endpoints'->0->>'positive_port_receipt_id' FROM tasks WHERE id=$1`, firstID).Scan(&preservedReceipt); err != nil || preservedReceipt != firstReceipt {
		t.Fatal("rewrote old endpoint", preservedReceipt, firstReceipt, err)
	}
	var firstSource, sourceAttempts int
	if err := s.db.QueryRow(ctx, `SELECT (payload->>'source_attempt_no')::int,(SELECT count(DISTINCT r.source_attempt_no) FROM jsonb_array_elements(payload->'endpoints') e JOIN port_positive_receipts r ON r.id=e->>'positive_port_receipt_id') FROM tasks WHERE id=$1`, firstID).Scan(&firstSource, &sourceAttempts); err != nil || firstSource != 1 || sourceAttempts != 2 {
		t.Fatal("source provenance changed", firstSource, sourceAttempts, err)
	}
	leased := claim(1, "service")
	if leased.ID != firstID {
		t.Fatal("unexpected claimed batch", leased.ID, firstID)
	}
	var frozen []byte
	if err := s.db.QueryRow(ctx, `SELECT payload FROM tasks WHERE id=$1`, leased.ID).Scan(&frozen); err != nil {
		t.Fatal(err)
	}
	submit(1, 8080)
	call("POST", "/api/tasks/"+leased.ID+"/release", workers[1].Token, map[string]any{"worker_id": workers[1].ID, "session_id": "session", "attempt_no": leased.AttemptNo, "reason": "fixture retry", "retryable": true, "stopped": true}, 200, nil)
	submit(2, 8443)
	submit(3, 80)
	var current []byte
	if err := s.db.QueryRow(ctx, `SELECT payload FROM tasks WHERE id=$1`, leased.ID).Scan(&current); err != nil || !bytes.Equal(current, frozen) {
		t.Fatal("changed leased/retry batch", err, string(current), string(frozen))
	}
	var newTask string
	if err := s.db.QueryRow(ctx, `SELECT task_id FROM port_service_work WHERE run_id=$1 AND port=8080`, run.ID).Scan(&newTask); err != nil || newTask == firstID {
		t.Fatal("reused leased batch", newTask, err)
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*),sum(jsonb_array_length(payload->'endpoints')) FROM tasks WHERE run_id=$1 AND type='service'`, run.ID).Scan(&queued, &items); err != nil || queued != 2 || items != 4 {
		t.Fatal("new work did not merge only into unclaimed batch", queued, items, err)
	}
	var selected int
	if err := s.db.QueryRow(ctx, `SELECT fingerprint_count FROM run_target_policies WHERE run_id=$1`, run.ID).Scan(&selected); err != nil || selected != 4 {
		t.Fatal("duplicate budget charge", selected, err)
	}
}

func TestQueuedServiceCoalescingProfileAndCapacity(t *testing.T) {
	s, _ := newPolicyTestServer(t, "queued_service_isolation")
	ctx := context.Background()
	var run Run
	callAPI(t, s.Handler(), "POST", "/api/runs", "admin-policy", map[string]any{"name": "coalescing isolation fixture", "targets": []string{"192.0.2.64"}, "modes": []string{"port"}}, 201, &run)
	var parentID string
	if err := s.db.QueryRow(ctx, `SELECT id FROM tasks WHERE run_id=$1`, run.ID).Scan(&parentID); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var locked string
	if err = tx.QueryRow(ctx, `SELECT id FROM runs WHERE id=$1 FOR UPDATE`, run.ID).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	for _, batch := range []struct {
		port    int
		profile string
		http    bool
	}{{80, "a", true}, {443, "b", true}, {8080, "a", false}, {8443, "a", true}, {9000, "a", true}} {
		if err = insertPortServiceBatch(ctx, tx, run.ID, parentID, "192.0.2.64", batch.profile, 1, []int{batch.port}, batch.http, 2); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := tx.Query(ctx, `SELECT payload FROM tasks WHERE run_id=$1 AND type='service' ORDER BY created_at,id`, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var p struct {
			Profile   string         `json:"service_profile"`
			HTTP      bool           `json:"http_enabled"`
			Endpoints []taskEndpoint `json:"endpoints"`
		}
		if err = json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if len(p.Endpoints) > 2 {
			t.Fatal("capacity exceeded", p)
		}
		for _, ep := range p.Endpoints {
			if (ep.Port == 443 && p.Profile != "b") || (ep.Port == 8080 && p.HTTP) || ((ep.Port == 80 || ep.Port == 8443 || ep.Port == 9000) && (p.Profile != "a" || !p.HTTP)) {
				t.Fatal("profile/HTTP scope mixed", p)
			}
		}
		count++
	}
	rows.Close()
	if err = rows.Err(); err != nil || count != 4 {
		t.Fatal("wrong batch count", count, err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
