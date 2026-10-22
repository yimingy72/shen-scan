package control

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTerminalRunDeletionFencesAndCascades(t *testing.T) {
	s, h := newPolicyTestServer(t, "run_cleanup")
	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	create := func(id, status string) {
		t.Helper()
		exec(`INSERT INTO runs(id,name,targets,modes,status,rules_snapshot) VALUES($1,$1,'[]','{http}',$2,'{"frozen":"shared"}')`, id, status)
		exec(`INSERT INTO tasks(id,run_id,type,payload,state,derived_key,attempt_no,accepted_attempt_no,completion_id) VALUES($1,$2,'http','{}','completed',$1,1,1,$1)`, id+"-task", id)
	}
	for _, status := range []string{"pending", "running", "paused", "cancelling"} {
		create(status, status)
		callAPI(t, h, "DELETE", "/api/runs/"+status, "admin-policy", nil, 409, nil)
	}
	create("blocked", "cancelled")
	for _, condition := range []string{"state='queued'", "state='leased'", "lease_until=now()+interval '1 minute'", "rate_until=now()+interval '1 minute'", "reserved_until=now()+interval '1 minute'"} {
		exec(`UPDATE tasks SET state='completed',lease_until=NULL,rate_until=NULL,reserved_until=NULL WHERE run_id='blocked'`)
		exec(`UPDATE tasks SET ` + condition + ` WHERE run_id='blocked'`)
		callAPI(t, h, "DELETE", "/api/runs/blocked", "admin-policy", nil, 409, nil)
	}
	exec(`UPDATE tasks SET state='cancelled',lease_until=NULL,rate_until=NULL,reserved_until=NULL WHERE run_id='blocked'`)
	var worker struct {
		ID string `json:"worker_id"`
	}
	callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "cleanup", "hostname": "local", "session_id": "s1"}, 200, &worker)
	exec(`INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until) VALUES('unknown','blocked-task',1,$1,'cleanup','s1','192.0.2.1','http',1,'suspect',now()-interval '1 hour')`, worker.ID)
	callAPI(t, h, "DELETE", "/api/runs/blocked", "admin-policy", nil, 409, nil)
	exec(`UPDATE target_quotas SET state='released',stop_evidence='fixture stopped',released_at=now() WHERE epoch='unknown'`)
	exec(`UPDATE workers SET current_task_id='blocked-task' WHERE id=$1`, worker.ID)
	exec(`INSERT INTO claim_requests(worker_id,session_id,request_id,task_id,attempt_no,response) VALUES($1,'s1','r1','blocked-task',1,'{}')`, worker.ID)
	exec(`INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,observation,observation_raw) VALUES('cleanup-observation','blocked','blocked-task',1,0,0,'{}','raw-evidence')`)
	exec(`INSERT INTO http_screenshots(id,run_id,parent_observation_id,task_id,attempt_no,png,thumbnail,width,height,sha256) VALUES('cleanup-image','blocked','cleanup-observation','blocked-task',1,'png','thumb',1,1,'fixture')`)
	exec(`INSERT INTO task_batches(task_id,attempt_no,batch_seq,content_hash,items) VALUES('blocked-task',1,0,'digest','[]')`)
	exec(`INSERT INTO task_item_completions(task_id,work_key,accepted_attempt_no,completion_id,outcome,coverage,observation_id) VALUES('blocked-task','work',1,'item-completion','success','complete','cleanup-observation')`)
	exec(`INSERT INTO task_targets VALUES('blocked-task','192.0.2.1')`)
	exec(`INSERT INTO run_target_policies(run_id,target_key) VALUES('blocked','192.0.2.1')`)
	exec(`INSERT INTO port_range_manifest VALUES('blocked','192.0.2.1',1,65535,'blocked-task')`)
	exec(`INSERT INTO port_positive_receipts(id,run_id,target_key,port,source_task_id,source_attempt_no,batch_seq,batch_digest,observation_id) VALUES('receipt','blocked','192.0.2.1',80,'blocked-task',1,0,'digest','cleanup-observation')`)
	exec(`INSERT INTO port_service_work VALUES('blocked','192.0.2.1',80,'fixture','blocked-task')`)
	exec(`INSERT INTO poc_template_receipts(task_id,rule_id,rule_revision,template_id,content_sha256,source_attempt_no,batch_seq,batch_digest,observation_id,completion_id) VALUES('blocked-task','rule',1,'template','hash',1,0,'digest','cleanup-observation','poc-completion')`)
	exec(`INSERT INTO poc_batch_derived_keys VALUES('blocked','key','blocked-task')`)
	exec(`INSERT INTO http_endpoint_bindings VALUES('blocked-task','example.test',80,1,$1,'s1','192.0.2.1')`, worker.ID)
	exec(`INSERT INTO http_permit_receipts VALUES('blocked-task',1,$1,'s1',1,'192.0.2.1','example.test',80,now(),now()-interval '1 minute')`, worker.ID)
	exec(`INSERT INTO port_start_tickets VALUES($1,'s1','ticket','blocked-task','blocked-task','fixture',now(),now())`, worker.ID)
	create("other", "completed")
	exec(`INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,observation) VALUES('other-observation','other','other-task',1,0,0,'{}')`)
	digest := strings.Repeat("a", 64)
	exec(`INSERT INTO fingerprint_bundles(digest,source_revision,engine_revision,package,stats,source_notice) VALUES($1,$2,'fixture','shared-package','{}','notice')`, digest, strings.Repeat("b", 40))
	exec(`INSERT INTO fingerprint_bundle_default(singleton,digest) VALUES(true,$1)`, digest)
	s.storage.next = time.Now().Add(time.Minute)
	callAPI(t, h, "DELETE", "/api/runs/blocked", "admin-policy", nil, 200, nil)
	for _, table := range []string{"http_screenshots", "task_batches", "task_item_completions", "task_targets", "run_target_policies", "port_range_manifest", "port_positive_receipts", "port_service_work", "poc_template_receipts", "poc_batch_derived_keys", "http_endpoint_bindings", "http_permit_receipts", "port_start_tickets", "claim_requests", "target_quotas"} {
		var n int
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s retained %d rows: %v", table, n, err)
		}
	}
	var other, orphan, bundles int
	if err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM assets WHERE id='other-observation'),(SELECT count(*) FROM assets WHERE id='cleanup-observation'),(SELECT count(*) FROM fingerprint_bundles WHERE digest=$1)`, digest).Scan(&other, &orphan, &bundles); err != nil || other != 1 || orphan != 0 || bundles != 1 {
		t.Fatal("cross-run/frozen evidence changed", other, orphan, bundles, err)
	}
	var pointer *string
	if err := s.db.QueryRow(ctx, `SELECT current_task_id FROM workers WHERE id=$1`, worker.ID).Scan(&pointer); err != nil || pointer != nil {
		t.Fatal("dangling worker task", pointer, err)
	}
	if !s.storage.next.IsZero() {
		t.Fatal("storage cache was not invalidated")
	}
	for _, status := range []string{"completed", "partial", "failed"} {
		id := "terminal-" + status
		create(id, status)
		callAPI(t, h, "DELETE", "/api/runs/"+id, "admin-policy", nil, 200, nil)
	}
	callAPI(t, h, "DELETE", "/api/runs/blocked", "admin-policy", nil, 404, nil)
	callAPI(t, h, "DELETE", "/api/runs/other", "admin-policy", map[string]any{"unexpected": true}, 400, nil)
	var capacity struct {
		DatabaseBytes int64          `json:"database_bytes"`
		Free          *int64         `json:"database_free_disk_bytes"`
		Tables        []storageTable `json:"tables"`
	}
	callAPI(t, h, "GET", "/api/storage/status", "admin-policy", nil, 200, &capacity)
	if capacity.DatabaseBytes <= 0 || capacity.Free != nil || len(capacity.Tables) == 0 {
		t.Fatalf("invalid capacity: %+v", capacity)
	}
}
