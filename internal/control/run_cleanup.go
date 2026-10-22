package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// Explicit whole-run deletion only. A cancelled run can still have an executor
// with an unconfirmed stop; elapsed quota validity never proves it stopped.
func (s *Server) deleteRun(w http.ResponseWriter, r *http.Request) {
	if !consumeEmptyAction(w, r) {
		return
	}
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		writeError(w, 503, "database unavailable")
		return
	}
	defer tx.Rollback(ctx)
	id := r.PathValue("id")
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM runs WHERE id=$1 FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "run not found")
		return
	}
	if err != nil {
		writeError(w, 503, "load run failed")
		return
	}
	if status != "completed" && status != "partial" && status != "failed" && status != "cancelled" {
		writeError(w, 409, "only terminal runs can be deleted")
		return
	}
	// Ingest, renewal, completion and claims lock run before task. Match that
	// order, then keep every task fenced until all evidence is deleted atomically.
	if _, err = tx.Exec(ctx, `SELECT id FROM tasks WHERE run_id=$1 ORDER BY id FOR UPDATE`, id); err != nil {
		writeError(w, 503, "lock tasks failed")
		return
	}
	var active bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE run_id=$1 AND
 (state IN('queued','leased') OR lease_until>now() OR rate_until>now() OR reserved_until>now()))
 OR EXISTS(SELECT 1 FROM target_quotas q JOIN tasks t ON t.id=q.task_id WHERE t.run_id=$1 AND q.state<>'released')`, id).Scan(&active)
	if err != nil {
		writeError(w, 503, "check active executions failed")
		return
	}
	if active {
		writeError(w, 409, "run still has work, a live lease, or an unconfirmed executor stop")
		return
	}
	// These references intentionally have no cascade. Never delete an unreleased
	// quota: orphan quotas remain the safety fence for unknown executors.
	for _, query := range []string{
		`DELETE FROM claim_requests WHERE task_id IN(SELECT id FROM tasks WHERE run_id=$1)`,
		`DELETE FROM target_quotas WHERE state='released' AND task_id IN(SELECT id FROM tasks WHERE run_id=$1)`,
		`UPDATE workers SET current_task_id=NULL WHERE current_task_id IN(SELECT id FROM tasks WHERE run_id=$1)`,
		`DELETE FROM runs WHERE id=$1`,
	} {
		if _, err = tx.Exec(ctx, query, id); err != nil {
			writeError(w, 503, "delete run failed")
			return
		}
	}
	// All task batches, accepted receipts, observations and screenshot bytes use
	// FK cascades. Shared rule libraries and immutable bundles are never touched.
	if err = tx.Commit(ctx); err != nil {
		writeError(w, 503, "commit run deletion failed")
		return
	}
	s.storage.mu.Lock()
	s.storage.next = time.Time{}
	s.storage.mu.Unlock()
	writeJSON(w, 200, map[string]any{"deleted": true, "run_id": id})
}
