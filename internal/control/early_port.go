package control

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const earlyPortSchema = `
CREATE INDEX IF NOT EXISTS tasks_adaptive_port_batch_idx ON tasks((payload->>'rate_pps'),(COALESCE(completed_at,updated_at)) DESC,id DESC)
 WHERE type='port' AND attempt_no=1 AND payload->>'ports'='1-65535';
CREATE INDEX IF NOT EXISTS tasks_adaptive_service_batch_idx ON tasks((payload->>'service_profile'),(COALESCE(completed_at,updated_at)) DESC,id DESC)
 WHERE type='service' AND attempt_no=1;
CREATE INDEX IF NOT EXISTS tasks_adaptive_worker_port_idx ON tasks(worker_id,session_id,completed_at DESC,id DESC)
 WHERE type='port' AND state='completed' AND attempt_no=1 AND accepted_attempt_no=1 AND coverage='complete' AND error='';
CREATE INDEX IF NOT EXISTS tasks_adaptive_worker_failure_idx ON tasks(worker_id,session_id,updated_at DESC)
 WHERE type='port' AND (state='failed' OR error<>'' OR (state='completed' AND coverage<>'complete'));
CREATE TABLE IF NOT EXISTS port_positive_receipts (
 id text NOT NULL UNIQUE,
 run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 target_key text NOT NULL,
 port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
 source_task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 source_attempt_no integer NOT NULL,
 batch_seq integer NOT NULL,
 batch_digest bytea NOT NULL,
 observation_id text NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 accepted_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(run_id,target_key,port)
);
CREATE INDEX IF NOT EXISTS port_positive_observation_idx ON port_positive_receipts(observation_id);
CREATE TABLE IF NOT EXISTS port_service_work (
 run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 target_key text NOT NULL,
 port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
 profile text NOT NULL,
 task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 PRIMARY KEY(run_id,target_key,port,profile)
);
`

// Initialization follows normal target-key backfill. Historical unfinished
// observations are deliberately not promoted into independently accepted evidence.
func initializeEarlyPorts(ctx context.Context, db *pgxpool.Pool) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(current_schema()),1935894902)`); err != nil {
		return err
	}
	var initialized bool
	if err = tx.QueryRow(ctx, `SELECT to_regclass('port_service_work') IS NOT NULL`).Scan(&initialized); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, earlyPortSchema); err != nil {
		return err
	}
	if !initialized {
		_, err = tx.Exec(ctx, `INSERT INTO port_service_work(run_id,target_key,port,profile,task_id)
 SELECT DISTINCT ON(t.run_id,e->>'ip',(e->>'port')::int,COALESCE(t.payload->>'service_profile',''))
 t.run_id,e->>'ip',(e->>'port')::int,COALESCE(t.payload->>'service_profile',''),t.id
 FROM tasks t CROSS JOIN LATERAL jsonb_array_elements(COALESCE(t.payload->'endpoints','[]'::jsonb)) e
 WHERE t.type='service' AND COALESCE(e->>'ip','')<>'' AND COALESCE((e->>'port')::int,0) BETWEEN 1 AND 65535
 ORDER BY t.run_id,e->>'ip',(e->>'port')::int,COALESCE(t.payload->>'service_profile',''),t.created_at,t.id
 ON CONFLICT DO NOTHING`)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Called only after current task/attempt/lease and the complete submitted scope
// have been validated. The original batch digest and observation are immutable.
// Later execution failure changes range coverage, not this positive observation.
func acceptPortPositives(ctx context.Context, tx pgx.Tx, taskID, runID string, attempt, batch int) error {
	_, err := tx.Exec(ctx, `INSERT INTO port_positive_receipts(id,run_id,target_key,port,source_task_id,source_attempt_no,batch_seq,batch_digest,observation_id)
 SELECT a.id,$2,a.target_key,(a.observation->>'port')::int,$1,$3,$4,b.content_hash,a.id
 FROM assets a JOIN task_batches b ON b.task_id=a.task_id AND b.attempt_no=a.attempt_no AND b.batch_seq=a.batch_seq
 WHERE a.task_id=$1 AND a.attempt_no=$3 AND a.batch_seq=$4 AND a.observation->>'kind'='port'
 AND COALESCE(a.observation->>'error','')='' AND (a.observation->>'port')::int BETWEEN 1 AND 65535
 ORDER BY a.item_index ON CONFLICT(run_id,target_key,port) DO NOTHING`, taskID, runID, attempt, batch)
	return err
}

// Logical endpoint work never changes. A batch that has never been claimed can
// accept additional independently proven endpoints until its current size cap.
func insertPortServiceBatch(ctx context.Context, tx pgx.Tx, runID, parentID, target, profile string, attempt int, ports []int, httpEnabled bool, maximum int) error {
	maximum = max(1, min(32, maximum))
	endpoints := make([]map[string]any, 0, len(ports))
	for _, port := range ports {
		endpoint := map[string]any{"ip": target, "port": port, "work_key": fmt.Sprintf("service:%s:%d:%s", target, port, profile)}
		var receiptID string
		err := tx.QueryRow(ctx, `SELECT id FROM port_positive_receipts WHERE run_id=$1 AND target_key=$2 AND port=$3`, runID, target, port).Scan(&receiptID)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if receiptID != "" {
			endpoint["positive_port_receipt_id"] = receiptID
		}
		endpoints = append(endpoints, endpoint)
	}
	for start := 0; start < len(ports); {
		var taskID string
		var occupied int
		err := tx.QueryRow(ctx, `SELECT id,jsonb_array_length(payload->'endpoints') FROM tasks
 WHERE run_id=$1 AND target_key=$2 AND type='service' AND state='queued' AND attempt_no=0
 AND first_started_at IS NULL AND worker_id IS NULL AND lease_until IS NULL
 AND COALESCE(payload->>'service_profile','')=$3 AND COALESCE((payload->>'http_enabled')::boolean,false)=$4
 AND payload->>'source_evidence_policy'='accepted_positive_port_batch_v1'
 AND jsonb_array_length(payload->'endpoints')<$5
 ORDER BY created_at,id LIMIT 1 FOR UPDATE`, runID, target, profile, httpEnabled, maximum).Scan(&taskID, &occupied)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		end := min(len(ports), start+maximum-occupied)
		if err == nil {
			added, marshalErr := json.Marshal(endpoints[start:end])
			if marshalErr != nil {
				return marshalErr
			}
			// Preserve every existing endpoint and the first source's trace fields.
			_, err = tx.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{endpoints}',(payload->'endpoints')||$2::jsonb),updated_at=now() WHERE id=$1`, taskID, added)
		} else {
			var payload []byte
			payload, err = json.Marshal(map[string]any{"endpoints": endpoints[start:end], "timeout_seconds": 60, "execution_timeout_seconds": 90, "source_task_id": parentID, "source_attempt_no": attempt, "source_evidence_policy": "accepted_positive_port_batch_v1", "service_profile": profile, "http_enabled": httpEnabled})
			if err != nil {
				return err
			}
			taskID = newID()
			_, err = tx.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES($1,$2,'service',$3,$4,$5)`, taskID, runID, payload, fmt.Sprintf("service:%s:%s:%d", profile, target, ports[start]), target)
			if err == nil {
				err = insertTaskTargets(ctx, tx, taskID, payload)
			}
		}
		if err != nil {
			return err
		}
		for _, port := range ports[start:end] {
			if _, err = tx.Exec(ctx, `INSERT INTO port_service_work(run_id,target_key,port,profile,task_id) VALUES($1,$2,$3,$4,$5)`, runID, target, port, profile, taskID); err != nil {
				return err
			}
		}
		start = end
	}
	return nil
}
