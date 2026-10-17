package control

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Maintenance only fences new claims; current executors and cloud capacity keep running.
func (s *Server) setWorkerMaintenance(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled           *bool  `json:"enabled"`
		ExpectedSessionID string `json:"expected_session_id"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if request.Enabled == nil || (!*request.Enabled && request.ExpectedSessionID == "") {
		writeError(w, 400, "enabled is required; disabling maintenance requires expected_session_id")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, 503, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	id := r.PathValue("id")
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock($1,hashtext($2))`, workerClaimLockNamespace, id); err != nil {
		writeError(w, 503, "lock worker claims failed")
		return
	}
	var sessionID string
	if err = tx.QueryRow(r.Context(), `SELECT session_id FROM workers WHERE id=$1 FOR UPDATE`, id).Scan(&sessionID); errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "worker not found")
		return
	} else if err != nil {
		writeError(w, 503, "load worker failed")
		return
	}
	if request.ExpectedSessionID != "" && request.ExpectedSessionID != sessionID {
		writeError(w, 409, "worker session changed; reload before changing maintenance")
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE workers SET maintenance=$2 WHERE id=$1`, id, *request.Enabled); err != nil {
		writeError(w, 503, "update maintenance failed")
		return
	}
	var active int
	// Expired leases and unconfirmed stops are not evidence that a worker is idle.
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM (SELECT id FROM tasks WHERE worker_id=$1 AND state='leased'
	 UNION SELECT task_id FROM target_quotas WHERE worker_id=$1 AND state IN('active','suspect','revoking')) executions`, id).Scan(&active); err != nil {
		writeError(w, 503, "load active executions failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, 503, "commit maintenance failed")
		return
	}
	writeJSON(w, 200, map[string]any{"worker_id": id, "session_id": sessionID, "maintenance": *request.Enabled, "active_tasks": active})
}
