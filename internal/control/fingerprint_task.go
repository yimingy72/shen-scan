package control

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/fingerprintbundle"
)

func (s *Server) getTaskFingerprintBundle(w http.ResponseWriter, r *http.Request) {
	workerID, sessionID := r.URL.Query().Get("worker_id"), r.URL.Query().Get("session_id")
	attempt, err := strconv.Atoi(r.URL.Query().Get("attempt_no"))
	if err != nil || attempt < 1 {
		writeError(w, 400, "positive attempt_no is required")
		return
	}
	if err = s.authenticateWorker(r.Context(), workerID, sessionID); err != nil {
		writeError(w, 401, err.Error())
		return
	}
	var digest string
	err = s.db.QueryRow(r.Context(), `SELECT r.rules_snapshot->>'fingerprint_bundle'
 FROM tasks t JOIN runs r ON r.id=t.run_id
 WHERE t.id=$1 AND t.worker_id=$2 AND t.session_id=$3 AND t.attempt_no=$4
 AND t.type='http' AND t.state='leased' AND t.lease_until>now()
 AND t.payload->>'fingerprint_bundle'=r.rules_snapshot->>'fingerprint_bundle'
 AND t.payload->>'fingerprint_bundle_schema'=r.rules_snapshot->>'fingerprint_bundle_schema' AND t.payload->>'fingerprint_bundle_schema' IN($5,$6)`,
		r.PathValue("id"), workerID, sessionID, attempt, fingerprintbundle.Schema, fingerprintbundle.LegacySchema).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 409, "task execution is stale or has no external fingerprint snapshot")
		return
	}
	if err != nil {
		writeError(w, 500, "load task fingerprint snapshot failed")
		return
	}
	s.writeFingerprintBundle(w, r, digest)
}
