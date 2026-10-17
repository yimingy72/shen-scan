package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/rulelib"
)

const (
	controlLockID            int64 = 0x5343414e
	workerClaimLockNamespace int32 = 0x53434e
)

func (s *Server) registerWorker(w http.ResponseWriter, r *http.Request) {
	var request struct {
		InstanceID   string          `json:"instance_id"`
		Hostname     string          `json:"hostname"`
		AgentVersion string          `json:"agent_version"`
		SessionID    string          `json:"session_id"`
		AZ           string          `json:"az"`
		Spec         json.RawMessage `json:"spec"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.InstanceID = strings.TrimSpace(request.InstanceID)
	request.Hostname = strings.TrimSpace(request.Hostname)
	request.SessionID = strings.TrimSpace(request.SessionID)
	if request.InstanceID == "" || request.Hostname == "" || request.SessionID == "" ||
		len(request.InstanceID) > 200 || len(request.Hostname) > 255 || len(request.SessionID) > 200 {
		writeError(w, http.StatusBadRequest, "instance_id, hostname, and session_id are required and bounded")
		return
	}
	if len(request.Spec) == 0 {
		request.Spec = json.RawMessage(`{}`)
	}
	var object map[string]any
	if json.Unmarshal(request.Spec, &object) != nil {
		writeError(w, http.StatusBadRequest, "spec must be a JSON object")
		return
	}
	workerToken, proposedID := newToken(), newID()
	tokenHash := sha256.Sum256([]byte(workerToken))
	var workerID string
	err := s.db.QueryRow(r.Context(), `INSERT INTO workers
		(id,instance_id,hostname,status,agent_version,session_id,token_hash,az,spec)
		VALUES ($1,$2,$3,CASE WHEN (SELECT enabled FROM worker_pool WHERE singleton) THEN 'ready' ELSE 'draining' END,$4,$5,$6,$7,$8)
		ON CONFLICT (instance_id) DO UPDATE SET hostname=EXCLUDED.hostname,status=EXCLUDED.status,
		agent_version=EXCLUDED.agent_version,session_id=EXCLUDED.session_id,token_hash=EXCLUDED.token_hash,
		last_heartbeat=now(),current_task_id=NULL,az=EXCLUDED.az,spec=EXCLUDED.spec,metrics='{}'::jsonb
		RETURNING id`, proposedID, request.InstanceID, request.Hostname, request.AgentVersion,
		request.SessionID, tokenHash[:], request.AZ, request.Spec).Scan(&workerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "register worker failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"worker_id": workerID, "worker_token": workerToken, "heartbeat_seconds": heartbeatInterval})
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var request struct {
		WorkerID      string          `json:"worker_id"`
		SessionID     string          `json:"session_id"`
		CurrentTaskID string          `json:"current_task_id"`
		Status        string          `json:"status"`
		TerminationAt *time.Time      `json:"termination_at"`
		Metrics       json.RawMessage `json:"metrics"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authenticateWorker(r.Context(), request.WorkerID, request.SessionID); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if request.Status != "ready" && request.Status != "running" && request.Status != "draining" {
		writeError(w, http.StatusBadRequest, "status must be ready, running, or draining")
		return
	}
	metrics, err := validateWorkerMetrics(request.Metrics)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	metricsJSON, _ := json.Marshal(metrics)
	pool, err := s.loadPool(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	action, reason := "continue", ""
	status := request.Status
	var forcedReason, forcedDeadline string
	if err := s.db.QueryRow(r.Context(), `SELECT COALESCE(spec->>'drain_reason',''),COALESCE(spec->>'termination_at','')
		FROM workers WHERE id=$1 AND session_id=$2`, request.WorkerID, request.SessionID).Scan(&forcedReason, &forcedDeadline); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	if forcedReason != "" {
		action, reason, status = "drain", forcedReason, "draining"
	} else if !pool.Enabled {
		action, reason, status = "drain", "worker pool disabled", "draining"
	} else if request.TerminationAt != nil {
		action, reason, status = "drain", "instance termination scheduled", "draining"
	}
	stopTaskIDs := make([]string, 0)
	rows, err := s.db.Query(r.Context(), `SELECT t.id FROM tasks t
		WHERE t.worker_id=$1 AND t.session_id=$2
		AND (t.state='cancelled' OR (t.state='leased' AND t.lease_until <= now()))`,
		request.WorkerID, request.SessionID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	for rows.Next() {
		var taskID string
		if err := rows.Scan(&taskID); err != nil {
			rows.Close()
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		stopTaskIDs = append(stopTaskIDs, taskID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	rows.Close()
	if request.CurrentTaskID != "" {
		var isCurrent bool
		err := s.db.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM tasks WHERE id=$1 AND worker_id=$2
			AND session_id=$3 AND state='leased' AND lease_until > now())`, request.CurrentTaskID, request.WorkerID, request.SessionID).Scan(&isCurrent)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		if !isCurrent && !contains(stopTaskIDs, request.CurrentTaskID) {
			stopTaskIDs = append(stopTaskIDs, request.CurrentTaskID)
		}
	}
	result, err := s.db.Exec(r.Context(), `UPDATE workers SET status=$1,last_heartbeat=now(),current_task_id=NULLIF($2,''),metrics=$5
		WHERE id=$3 AND session_id=$4`, status, request.CurrentTaskID, request.WorkerID, request.SessionID, metricsJSON)
	if err != nil || result.RowsAffected() != 1 {
		writeError(w, http.StatusInternalServerError, "record heartbeat failed")
		return
	}
	response := map[string]any{"action": action, "control_generation": pool.Generation, "reason": reason, "stop_task_ids": stopTaskIDs}
	if request.TerminationAt != nil {
		response["stop_deadline"] = request.TerminationAt.UTC()
	} else if forcedDeadline != "" {
		if deadline, err := time.Parse(time.RFC3339, forcedDeadline); err == nil {
			response["stop_deadline"] = deadline.UTC()
		}
	}
	writeJSON(w, http.StatusOK, response)
}

var workerMetricLimits = map[string]float64{
	"active_tasks":          1000,
	"cpu_percent":           100,
	"mem_total_mib":         1_000_000_000,
	"mem_available_mib":     1_000_000_000,
	"agent_rss_mib":         1_000_000_000,
	"masscan_rss_mib":       1_000_000_000,
	"peak_cpu_percent":      100,
	"peak_agent_rss_mib":    1_000_000_000,
	"peak_masscan_rss_mib":  1_000_000_000,
	"min_mem_available_mib": 1_000_000_000,
}

func validateWorkerMetrics(raw json.RawMessage) (map[string]float64, error) {
	metrics := make(map[string]float64)
	if len(raw) == 0 || string(raw) == "null" {
		return metrics, nil
	}
	if len(raw) > 4096 {
		return nil, errors.New("metrics exceeds 4096 bytes")
	}
	if err := json.Unmarshal(raw, &metrics); err != nil {
		return nil, errors.New("metrics must be a numeric JSON object")
	}
	for name, value := range metrics {
		limit, allowed := workerMetricLimits[name]
		if !allowed {
			return nil, fmt.Errorf("unsupported metrics field %q", name)
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > limit {
			return nil, fmt.Errorf("metrics field %q is out of range", name)
		}
		if name == "active_tasks" && value != math.Trunc(value) {
			return nil, errors.New("metrics field \"active_tasks\" must be an integer")
		}
	}
	return metrics, nil
}

func (s *Server) claimTask(w http.ResponseWriter, r *http.Request) {
	var request struct {
		WorkerID  string   `json:"worker_id"`
		SessionID string   `json:"session_id"`
		RequestID string   `json:"request_id"`
		Types     []string `json:"types"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authenticateWorker(r.Context(), request.WorkerID, request.SessionID); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if request.RequestID == "" || len(request.RequestID) > 200 {
		writeError(w, http.StatusBadRequest, "request_id is required and must not exceed 200 characters")
		return
	}
	types, err := normalizeTaskTypes(request.Types)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var poolEnabled bool
	var generation int64
	if err = tx.QueryRow(r.Context(), `SELECT enabled,generation FROM worker_pool WHERE singleton FOR SHARE`).Scan(&poolEnabled, &generation); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock($1,hashtext($2))`, workerClaimLockNamespace, request.WorkerID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	var workerStatus string
	if err = tx.QueryRow(r.Context(), `SELECT status FROM workers WHERE id=$1 AND session_id=$2`,
		request.WorkerID, request.SessionID).Scan(&workerStatus); err != nil {
		writeError(w, http.StatusUnauthorized, "worker session is invalid")
		return
	}
	inserted, err := tx.Exec(r.Context(), `INSERT INTO claim_requests(worker_id,session_id,request_id,response)
		VALUES ($1,$2,$3,'null'::jsonb) ON CONFLICT DO NOTHING`, request.WorkerID, request.SessionID, request.RequestID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "claim task failed")
		return
	}
	if inserted.RowsAffected() == 1 && (!poolEnabled || workerStatus == "draining" || workerStatus == "offline") {
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"task": nil})
		return
	}
	var previousTaskID *string
	var previousAttempt *int
	var previousResponse []byte
	if inserted.RowsAffected() == 0 {
		err = tx.QueryRow(r.Context(), `SELECT task_id,attempt_no,response FROM claim_requests
			WHERE worker_id=$1 AND session_id=$2 AND request_id=$3`, request.WorkerID, request.SessionID, request.RequestID).Scan(&previousTaskID, &previousAttempt, &previousResponse)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "claim task failed")
			return
		}
		var task *Task
		expired := false
		if previousTaskID != nil {
			expired = !poolEnabled || workerStatus == "draining" || workerStatus == "offline"
			if !expired {
				valid, validErr := claimStillValid(r.Context(), tx, *previousTaskID, *previousAttempt, request.WorkerID, request.SessionID)
				if validErr != nil {
					writeError(w, http.StatusInternalServerError, "load idempotent claim failed")
					return
				}
				expired = !valid
			}
		}
		if !expired && len(previousResponse) != 0 && string(previousResponse) != "null" {
			var loaded Task
			if json.Unmarshal(previousResponse, &loaded) != nil {
				writeError(w, http.StatusInternalServerError, "load idempotent claim failed")
				return
			}
			loaded.ServerTime = utcNow()
			task = &loaded
		} else if !expired && previousTaskID != nil {
			loaded, loadErr := loadTask(r.Context(), tx, *previousTaskID, *previousAttempt)
			if loadErr != nil {
				writeError(w, http.StatusInternalServerError, "load idempotent claim failed")
				return
			}
			loaded.ServerTime = utcNow()
			task = &loaded
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		response := map[string]any{"task": task}
		if expired {
			response["expired"] = true
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	var runID, lastTargetKey string
	err = tx.QueryRow(r.Context(), `SELECT r.id,r.last_claim_target_key FROM runs r
		WHERE r.status IN ('pending','running') AND EXISTS (
			SELECT 1 FROM tasks t WHERE t.run_id=r.id AND t.type=ANY($1)
			AND (t.state='queued' OR (t.state='leased' AND t.lease_until <= now()))
			AND ((t.type='port' AND NOT EXISTS (SELECT 1 FROM tasks active_port
				WHERE active_port.worker_id=$2 AND active_port.session_id=$3 AND active_port.type='port'
				AND active_port.state='leased' AND active_port.lease_until > now()))
			OR (t.type<>'port' AND NOT EXISTS (SELECT 1 FROM tasks active_target
				WHERE active_target.worker_id=$2 AND active_target.session_id=$3
				AND active_target.type IN ('service','http','poc') AND active_target.target_key=t.target_key
				AND active_target.state='leased' AND active_target.lease_until > now()))))
		ORDER BY r.last_claim_at,r.created_at,r.id FOR UPDATE OF r SKIP LOCKED LIMIT 1`,
		types, request.WorkerID, request.SessionID).Scan(&runID, &lastTargetKey)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "record empty claim failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"task": nil})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "claim task failed")
		return
	}
	var taskID, typeName, targetKey string
	var payload json.RawMessage
	candidates := []struct {
		retry, afterCursor bool
	}{{retry: true}, {afterCursor: true}, {}}
	for _, candidate := range candidates {
		err = tx.QueryRow(r.Context(), `SELECT t.id,t.run_id,t.type,t.payload,t.target_key FROM tasks t
			WHERE t.run_id=$1 AND t.type=ANY($2)
			AND (($5 AND ((t.state='leased' AND t.lease_until<=now()) OR (t.state='queued' AND t.attempt_no>0)))
				OR (NOT $5 AND t.state='queued' AND t.attempt_no=0))
			AND (NOT $6 OR t.target_key>$7)
			AND ((t.type='port' AND NOT EXISTS (SELECT 1 FROM tasks active_port
				WHERE active_port.worker_id=$3 AND active_port.session_id=$4 AND active_port.type='port'
				AND active_port.state='leased' AND active_port.lease_until > now()))
			OR (t.type<>'port' AND NOT EXISTS (SELECT 1 FROM tasks active_target
				WHERE active_target.worker_id=$3 AND active_target.session_id=$4
				AND active_target.type IN ('service','http','poc') AND active_target.target_key=t.target_key
				AND active_target.state='leased' AND active_target.lease_until > now())))
			ORDER BY t.target_key,t.created_at,t.id FOR UPDATE OF t SKIP LOCKED LIMIT 1`,
			runID, types, request.WorkerID, request.SessionID, candidate.retry, candidate.afterCursor, lastTargetKey).Scan(
			&taskID, &runID, &typeName, &payload, &targetKey)
		if !errors.Is(err, pgx.ErrNoRows) {
			break
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"task": nil})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "claim task failed")
		return
	}
	serverTime := utcNow()
	leaseUntil, rateUntil := serverTime.Add(leaseDuration), serverTime.Add(rateDuration)
	var attempt int
	err = tx.QueryRow(r.Context(), `UPDATE tasks SET state='leased',attempt_no=attempt_no+1,worker_id=$1,session_id=$2,
		lease_until=$3,rate_until=$4,last_batch_seq=-1,updated_at=now() WHERE id=$5 RETURNING attempt_no`,
		request.WorkerID, request.SessionID, leaseUntil, rateUntil, taskID).Scan(&attempt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE runs SET status='running',last_claim_at=now(),
			last_claim_target_key=$2,updated_at=CASE WHEN status='pending' THEN now() ELSE updated_at END WHERE id=$1`, runID, targetKey)
	}
	if err == nil {
		payload, err = attachClaimRules(r.Context(), tx, runID, typeName, payload)
	}
	task := Task{ID: taskID, RunID: runID, Type: typeName, AttemptNo: attempt, Payload: payload,
		LeaseUntil: leaseUntil, RateUntil: rateUntil, ServerTime: serverTime, ControlGeneration: generation}
	if err == nil {
		response, _ := json.Marshal(task)
		_, err = tx.Exec(r.Context(), `UPDATE claim_requests SET task_id=$4,attempt_no=$5,response=$6
			WHERE worker_id=$1 AND session_id=$2 AND request_id=$3`, request.WorkerID, request.SessionID, request.RequestID, taskID, attempt, response)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		writeError(w, http.StatusInternalServerError, "claim task failed")
		return
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE workers SET status='running',current_task_id=$1
		WHERE id=$2 AND session_id=$3 AND status NOT IN ('draining','offline')`, taskID, request.WorkerID, request.SessionID)
	writeJSON(w, http.StatusOK, map[string]any{"task": task})
}

func normalizeTaskTypes(input []string) ([]string, error) {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))
	for _, value := range input {
		if value != "port" && value != "service" && value != "http" && value != "poc" {
			return nil, fmt.Errorf("unsupported task type %q", value)
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("types must contain port, service, http, or poc")
	}
	return result, nil
}

func loadTask(ctx context.Context, tx pgx.Tx, id string, attempt int) (Task, error) {
	var task Task
	var lease, rate *time.Time
	err := tx.QueryRow(ctx, `SELECT t.id,t.run_id,t.type,t.attempt_no,t.payload,t.lease_until,t.rate_until,
		now(),p.generation FROM tasks t CROSS JOIN worker_pool p WHERE t.id=$1 AND t.attempt_no=$2`, id, attempt).Scan(
		&task.ID, &task.RunID, &task.Type, &task.AttemptNo, &task.Payload, &lease, &rate, &task.ServerTime, &task.ControlGeneration)
	if lease != nil {
		task.LeaseUntil = lease.UTC()
	}
	if rate != nil {
		task.RateUntil = rate.UTC()
	}
	task.ServerTime = task.ServerTime.UTC()
	if err == nil {
		task.Payload, err = attachClaimRules(ctx, tx, task.RunID, task.Type, task.Payload)
	}
	return task, err
}

func claimStillValid(ctx context.Context, tx pgx.Tx, taskID string, attempt int, workerID, sessionID string) (bool, error) {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM tasks t JOIN runs r ON r.id=t.run_id
		WHERE t.id=$1 AND t.attempt_no=$2 AND t.worker_id=$3 AND t.session_id=$4
		AND t.state='leased' AND t.lease_until > now() AND r.status IN ('pending','running'))`,
		taskID, attempt, workerID, sessionID).Scan(&valid)
	return valid, err
}

func (s *Server) renewTask(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.decodeTaskIdentity(w, r)
	if !ok {
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var pool Pool
	if err = tx.QueryRow(r.Context(), `SELECT enabled,generation FROM worker_pool WHERE singleton FOR SHARE`).Scan(
		&pool.Enabled, &pool.Generation); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	var runID string
	if err = tx.QueryRow(r.Context(), `SELECT run_id FROM tasks WHERE id=$1 AND worker_id=$2 AND session_id=$3 AND attempt_no=$4`,
		r.PathValue("id"), identity.WorkerID, identity.SessionID, identity.AttemptNo).Scan(&runID); errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "renew task failed")
		return
	}
	var runStatus string
	if err = tx.QueryRow(r.Context(), `SELECT status FROM runs WHERE id=$1 FOR SHARE`, runID).Scan(&runStatus); err != nil {
		writeError(w, http.StatusInternalServerError, "renew task failed")
		return
	}
	var state string
	var currentLease *time.Time
	err = tx.QueryRow(r.Context(), `SELECT state,lease_until FROM tasks
		WHERE id=$1 AND run_id=$2 AND worker_id=$3 AND session_id=$4 AND attempt_no=$5 FOR UPDATE`,
		r.PathValue("id"), runID, identity.WorkerID, identity.SessionID, identity.AttemptNo).Scan(&state, &currentLease)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "renew task failed")
		return
	}
	serverTime := utcNow()
	action, reason := "continue", ""
	var leaseUntil, rateUntil time.Time
	if state != "leased" || currentLease == nil || !currentLease.After(serverTime) || runStatus == "cancelled" || runStatus == "cancelling" || !pool.Enabled {
		action, reason = "stop", "task is no longer authorized to scan"
	} else if runStatus == "paused" {
		action, reason = "drain", "run paused"
	} else {
		leaseUntil, rateUntil = serverTime.Add(leaseDuration), serverTime.Add(rateDuration)
		_, err = tx.Exec(r.Context(), `UPDATE tasks SET lease_until=$1,rate_until=$2,updated_at=now() WHERE id=$3`, leaseUntil, rateUntil, r.PathValue("id"))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		writeError(w, http.StatusInternalServerError, "renew task failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"action": action, "lease_until": leaseUntil, "rate_until": rateUntil,
		"server_time": serverTime, "control_generation": pool.Generation, "reason": reason})
}

type taskIdentity struct {
	WorkerID  string `json:"worker_id"`
	SessionID string `json:"session_id"`
	AttemptNo int    `json:"attempt_no"`
}

func (s *Server) decodeTaskIdentity(w http.ResponseWriter, r *http.Request) (taskIdentity, bool) {
	var identity taskIdentity
	if err := decodeJSON(w, r, &identity); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return identity, false
	}
	if identity.AttemptNo < 1 {
		writeError(w, http.StatusBadRequest, "attempt_no must be positive")
		return identity, false
	}
	if err := s.authenticateWorker(r.Context(), identity.WorkerID, identity.SessionID); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return identity, false
	}
	return identity, true
}

func (s *Server) submitBatch(w http.ResponseWriter, r *http.Request) {
	var request struct {
		taskIdentity
		BatchSeq int           `json:"batch_seq"`
		Items    []Observation `json:"items"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authenticateWorker(r.Context(), request.WorkerID, request.SessionID); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if request.AttemptNo < 1 || request.BatchSeq < 0 || len(request.Items) == 0 || len(request.Items) > maxBatchItems {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("attempt_no must be positive; batch_seq non-negative; items must contain 1 to %d observations", maxBatchItems))
		return
	}
	for index, item := range request.Items {
		if item.Kind != "port" && item.Kind != "service" && item.Kind != "http" && item.Kind != "poc" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("items[%d].kind is invalid", index))
			return
		}
		if item.Port < 0 || item.Port > 65535 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("items[%d].port is out of range", index))
			return
		}
	}
	itemsJSON, _ := json.Marshal(request.Items)
	hash := sha256.Sum256(itemsJSON)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var priorHash []byte
	err = tx.QueryRow(r.Context(), `SELECT b.content_hash FROM task_batches b WHERE b.task_id=$1 AND b.attempt_no=$2 AND b.batch_seq=$3
		AND EXISTS (SELECT 1 FROM claim_requests c WHERE c.task_id=b.task_id AND c.attempt_no=b.attempt_no
			AND c.worker_id=$4 AND c.session_id=$5)`, r.PathValue("id"), request.AttemptNo, request.BatchSeq,
		request.WorkerID, request.SessionID).Scan(&priorHash)
	if err == nil {
		if !bytes.Equal(priorHash, hash[:]) {
			writeError(w, http.StatusConflict, "batch_seq was already committed with different content")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "store batch failed")
		return
	}
	var runID, typeName, state, sourceTarget string
	var payload json.RawMessage
	var leaseUntil *time.Time
	err = tx.QueryRow(r.Context(), `SELECT run_id,type,state,payload,target_key,lease_until FROM tasks
		WHERE id=$1 AND worker_id=$2 AND session_id=$3 AND attempt_no=$4 FOR UPDATE`,
		r.PathValue("id"), request.WorkerID, request.SessionID, request.AttemptNo).Scan(
		&runID, &typeName, &state, &payload, &sourceTarget, &leaseUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store batch failed")
		return
	}
	err = tx.QueryRow(r.Context(), `SELECT content_hash FROM task_batches WHERE task_id=$1 AND attempt_no=$2 AND batch_seq=$3`,
		r.PathValue("id"), request.AttemptNo, request.BatchSeq).Scan(&priorHash)
	if err == nil {
		if !bytes.Equal(priorHash, hash[:]) {
			writeError(w, http.StatusConflict, "batch_seq was already committed with different content")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "store batch failed")
		return
	}
	if state != "leased" || leaseUntil == nil || !leaseUntil.After(utcNow()) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	}
	assetRows := make([][]any, len(request.Items))
	for index, item := range request.Items {
		targetKey, err := observationTarget(typeName, payload, sourceTarget, item)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("items[%d]: %v", index, err))
			return
		}
		raw, _ := json.Marshal(item)
		assetRows[index] = []any{newID(), runID, r.PathValue("id"), request.AttemptNo, request.BatchSeq, index, targetKey, raw}
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO task_batches(task_id,attempt_no,batch_seq,content_hash,items) VALUES ($1,$2,$3,$4,$5)`,
		r.PathValue("id"), request.AttemptNo, request.BatchSeq, hash[:], itemsJSON)
	if err == nil {
		var copied int64
		copied, err = tx.CopyFrom(r.Context(), pgx.Identifier{"assets"},
			[]string{"id", "run_id", "task_id", "attempt_no", "batch_seq", "item_index", "target_key", "observation"},
			pgx.CopyFromRows(assetRows))
		if err == nil && copied != int64(len(assetRows)) {
			err = fmt.Errorf("copied %d of %d assets", copied, len(assetRows))
		}
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		writeError(w, http.StatusInternalServerError, "store batch failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
}

func (s *Server) completeTask(w http.ResponseWriter, r *http.Request) {
	var request struct {
		taskIdentity
		LastBatchSeq int `json:"last_batch_seq"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authenticateWorker(r.Context(), request.WorkerID, request.SessionID); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if request.AttemptNo < 1 || request.LastBatchSeq < -1 {
		writeError(w, http.StatusBadRequest, "attempt_no must be positive and last_batch_seq must be at least -1")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var runID string
	if err = tx.QueryRow(r.Context(), `SELECT run_id FROM tasks WHERE id=$1 AND worker_id=$2 AND session_id=$3`,
		r.PathValue("id"), request.WorkerID, request.SessionID).Scan(&runID); errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "task not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "complete task failed")
		return
	}
	if err = tx.QueryRow(r.Context(), `SELECT id FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&runID); err != nil {
		writeError(w, http.StatusInternalServerError, "complete task failed")
		return
	}
	var typeName, state, sourceTarget string
	var payload json.RawMessage
	var attempt int
	var leaseUntil *time.Time
	err = tx.QueryRow(r.Context(), `SELECT type,state,attempt_no,payload,target_key,lease_until FROM tasks
		WHERE id=$1 AND run_id=$2 AND worker_id=$3 AND session_id=$4 FOR UPDATE`,
		r.PathValue("id"), runID, request.WorkerID, request.SessionID).Scan(&typeName, &state, &attempt, &payload, &sourceTarget, &leaseUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "complete task failed")
		return
	}
	if state == "completed" && attempt == request.AttemptNo {
		_ = tx.Commit(r.Context())
		writeJSON(w, http.StatusOK, map[string]bool{"completed": true})
		return
	}
	if state != "leased" || attempt != request.AttemptNo || leaseUntil == nil || !leaseUntil.After(utcNow()) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	}
	var count int
	var minSeq, maxSeq *int
	if err := tx.QueryRow(r.Context(), `SELECT count(*),min(batch_seq),max(batch_seq) FROM task_batches WHERE task_id=$1 AND attempt_no=$2`,
		r.PathValue("id"), request.AttemptNo).Scan(&count, &minSeq, &maxSeq); err != nil {
		writeError(w, http.StatusInternalServerError, "verify batches failed")
		return
	}
	if (request.LastBatchSeq == -1 && count != 0) || (request.LastBatchSeq >= 0 &&
		(count != request.LastBatchSeq+1 || minSeq == nil || *minSeq != 0 || maxSeq == nil || *maxSeq != request.LastBatchSeq)) {
		writeError(w, http.StatusConflict, "complete batch sequence is not committed")
		return
	}
	if typeName == "port" {
		if err := derivePortTasks(r.Context(), tx, r.PathValue("id"), runID, request.AttemptNo, payload); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	if typeName == "http" {
		if err := derivePOCTasks(r.Context(), tx, r.PathValue("id"), runID, request.AttemptNo, sourceTarget, payload); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	_, err = tx.Exec(r.Context(), `UPDATE tasks SET state='completed',last_batch_seq=$1,lease_until=NULL,rate_until=NULL,
		completed_at=now(),updated_at=now() WHERE id=$2`, request.LastBatchSeq, r.PathValue("id"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE workers SET status=CASE WHEN status='draining' THEN status ELSE 'ready' END,current_task_id=NULL
			WHERE id=$1 AND session_id=$2`, request.WorkerID, request.SessionID)
	}
	if err == nil {
		err = finalizeRun(r.Context(), tx, runID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		writeError(w, http.StatusInternalServerError, "complete task failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"completed": true})
}

func derivePortTasks(ctx context.Context, tx pgx.Tx, taskID, runID string, attempt int, payload json.RawMessage) error {
	var config struct {
		HTTPEnabled bool `json:"http_enabled"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		return errors.New("invalid persisted port task payload")
	}
	rows, err := tx.Query(ctx, `SELECT observation FROM assets WHERE task_id=$1 AND attempt_no=$2
		AND observation->>'kind'='port' AND COALESCE((observation->>'port')::int,0) BETWEEN 1 AND 65535 ORDER BY item_index`, taskID, attempt)
	if err != nil {
		return fmt.Errorf("load discovered ports: %w", err)
	}
	defer rows.Close()
	portsByIP := make(map[string]map[int]struct{})
	for rows.Next() {
		var raw []byte
		var observation Observation
		if err := rows.Scan(&raw); err != nil || json.Unmarshal(raw, &observation) != nil {
			return errors.New("invalid persisted port observation")
		}
		ip, err := observationTarget("port", payload, payloadTarget(payload), observation)
		if err != nil {
			return fmt.Errorf("invalid persisted port observation: %w", err)
		}
		if portsByIP[ip] == nil {
			portsByIP[ip] = make(map[int]struct{})
		}
		portsByIP[ip][observation.Port] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("load discovered ports: %w", err)
	}
	ips := make([]string, 0, len(portsByIP))
	for ip := range portsByIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		ports := make([]int, 0, len(portsByIP[ip]))
		for port := range portsByIP[ip] {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		ports, err = fingerprintPorts(ctx, tx, runID, ip, ports)
		if err != nil {
			return err
		}
		taskTypes := []struct {
			name               string
			chunkSize, timeout int
		}{{"service", 32, 5}}
		if config.HTTPEnabled {
			taskTypes = append(taskTypes, struct {
				name               string
				chunkSize, timeout int
			}{"http", 8, 12})
		}
		for _, taskType := range taskTypes {
			for start := 0; start < len(ports); start += taskType.chunkSize {
				end := min(start+taskType.chunkSize, len(ports))
				endpoints := make([]map[string]any, 0, end-start)
				for _, port := range ports[start:end] {
					endpoints = append(endpoints, map[string]any{"ip": ip, "port": port})
				}
				if err := insertDerivedTask(ctx, tx, runID, taskID, taskType.name, ip,
					start/taskType.chunkSize, taskType.timeout, endpoints); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type taskEndpoint struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
	Host string `json:"host,omitempty"`
	URL  string `json:"url,omitempty"`
}

func endpointBaseURL(endpoint taskEndpoint) (*url.URL, error) {
	if endpoint.URL != "" {
		u, err := url.Parse(endpoint.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return nil, errors.New("invalid HTTP endpoint URL")
		}
		return u, nil
	}
	host := endpoint.Host
	if host == "" {
		host = endpoint.IP
	}
	if host == "" {
		return nil, errors.New("HTTP endpoint has no host")
	}
	scheme := "http"
	if endpoint.Port == 443 || endpoint.Port == 8443 || endpoint.Port == 9443 {
		scheme = "https"
	}
	if endpoint.Port > 0 {
		host = net.JoinHostPort(host, strconv.Itoa(endpoint.Port))
	}
	return url.Parse(scheme + "://" + host + "/")
}

func origin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + strconv.Itoa(urlPortNumber(u))
}

func urlPortNumber(u *url.URL) int {
	if port, err := strconv.Atoi(u.Port()); err == nil && port > 0 {
		return port
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func sameOriginURL(base *url.URL, raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && origin(base) == origin(u)
}

func observedEndpoint(endpoint taskEndpoint, raw string) (*url.URL, bool) {
	if endpoint.URL != "" {
		base, err := endpointBaseURL(endpoint)
		if err != nil {
			return nil, false
		}
		return sameOriginURL(base, raw)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, false
	}
	host := endpoint.Host
	if host == "" {
		host = endpoint.IP
	}
	if canonicalTarget(host) != canonicalTarget(u.Hostname()) {
		return nil, false
	}
	if endpoint.Port > 0 {
		if urlPortNumber(u) != endpoint.Port {
			return nil, false
		}
	}
	return u, true
}

func derivePOCTasks(ctx context.Context, tx pgx.Tx, parentID, runID string, attempt int, sourceTarget string, payload json.RawMessage) error {
	var snapshotRaw []byte
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT poc_enabled,rules_snapshot FROM runs WHERE id=$1`, runID).Scan(&enabled, &snapshotRaw); err != nil {
		return fmt.Errorf("load PoC snapshot: %w", err)
	}
	if !enabled {
		return nil
	}
	var snapshot ruleSnapshot
	if err := json.Unmarshal(snapshotRaw, &snapshot); err != nil {
		return errors.New("invalid persisted PoC snapshot")
	}
	if len(snapshot.POC) == 0 {
		return nil
	}
	var config struct {
		Endpoints []taskEndpoint `json:"endpoints"`
	}
	if err := json.Unmarshal(payload, &config); err != nil || len(config.Endpoints) == 0 {
		return errors.New("invalid persisted HTTP task payload")
	}
	rows, err := tx.Query(ctx, `SELECT observation FROM assets WHERE task_id=$1 AND attempt_no=$2
		AND observation->>'kind'='http' AND COALESCE((observation->>'status_code')::int,0)>0 ORDER BY batch_seq,item_index`, parentID, attempt)
	if err != nil {
		return fmt.Errorf("load HTTP observations: %w", err)
	}
	defer rows.Close()
	endpoints := make(map[string]taskEndpoint)
	for rows.Next() {
		var raw []byte
		var observation Observation
		if err := rows.Scan(&raw); err != nil || json.Unmarshal(raw, &observation) != nil {
			return errors.New("invalid persisted HTTP observation")
		}
		for _, endpoint := range config.Endpoints {
			observedURL, ok := observedEndpoint(endpoint, observation.URL)
			if !ok {
				continue
			}
			endpointTarget := endpoint.URL
			if endpointTarget == "" {
				endpointTarget = endpoint.Host
			}
			if endpointTarget == "" {
				endpointTarget = endpoint.IP
			}
			if observation.Target != "" && canonicalTarget(observation.Target) != canonicalTarget(endpointTarget) {
				continue
			}
			observedURL.Path, observedURL.RawPath, observedURL.RawQuery, observedURL.Fragment = "/", "", "", ""
			derivedEndpoint := endpoint
			derivedEndpoint.URL = observedURL.String()
			endpoints[origin(observedURL)] = derivedEndpoint
			break
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("load HTTP observations: %w", err)
	}
	rows.Close()
	keys := make([]string, 0, len(endpoints))
	for key := range endpoints {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, endpointKey := range keys {
		for _, rule := range snapshot.POC {
			if err := insertPOCTask(ctx, tx, runID, parentID, attempt, endpointKey, sourceTarget, endpoints[endpointKey], rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func insertPOCTask(ctx context.Context, tx pgx.Tx, runID, parentID string, attempt int, endpointKey, targetKey string, endpoint taskEndpoint, rule rulelib.Rule) error {
	payload, _ := json.Marshal(map[string]any{"endpoint": endpoint, "rules": []rulelib.Rule{rule}, "execution_timeout_seconds": 90})
	taskID := newID()
	derivedKey := fmt.Sprintf("poc:%s:%d:%s:%s", parentID, attempt, endpointKey, rule.ID)
	result, err := tx.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES($1,$2,'poc',$3,$4,$5)
		ON CONFLICT(run_id,derived_key) DO NOTHING`, taskID, runID, payload, derivedKey, targetKey)
	if err != nil || result.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES($1,$2)`, taskID, targetKey)
	return err
}

func insertDerivedTask(ctx context.Context, tx pgx.Tx, runID, parentID, typeName, targetKey string, chunk, timeout int, endpoints []map[string]any) error {
	payload, _ := json.Marshal(map[string]any{"endpoints": endpoints, "timeout_seconds": timeout, "execution_timeout_seconds": 180})
	taskID := newID()
	result, err := tx.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (run_id,derived_key) DO NOTHING`,
		taskID, runID, typeName, payload, fmt.Sprintf("derived:%s:%s:%s:%d", parentID, typeName, targetKey, chunk), targetKey)
	if err != nil || result.RowsAffected() == 0 {
		return err
	}
	return insertTaskTargets(ctx, tx, taskID, payload)
}

func (s *Server) releaseTask(w http.ResponseWriter, r *http.Request) {
	var request struct {
		taskIdentity
		Reason       string `json:"reason"`
		Retryable    bool   `json:"retryable"`
		FailureClass string `json:"failure_class"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authenticateWorker(r.Context(), request.WorkerID, request.SessionID); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	request.FailureClass = strings.TrimSpace(request.FailureClass)
	if request.AttemptNo < 1 || len(request.Reason) > 2000 || (request.FailureClass != "" && request.FailureClass != "execution_timeout") {
		writeError(w, http.StatusBadRequest, "attempt_no must be positive; reason must not exceed 2000 characters; failure_class must be empty or execution_timeout")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	var runID string
	if err = tx.QueryRow(r.Context(), `SELECT run_id FROM tasks WHERE id=$1 AND worker_id=$2 AND session_id=$3 AND attempt_no=$4`,
		r.PathValue("id"), request.WorkerID, request.SessionID, request.AttemptNo).Scan(&runID); errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "release task failed")
		return
	}
	if err = tx.QueryRow(r.Context(), `SELECT id FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&runID); err != nil {
		writeError(w, http.StatusInternalServerError, "release task failed")
		return
	}
	var finalState string
	err = tx.QueryRow(r.Context(), `UPDATE tasks SET
		state=CASE WHEN $1 AND ($2='' OR execution_failures+1<3) THEN 'queued' ELSE 'failed' END,
		execution_failures=execution_failures+CASE WHEN $2='execution_timeout' THEN 1 ELSE 0 END,
		error=$3,worker_id=NULL,session_id=NULL,lease_until=NULL,rate_until=NULL,updated_at=now()
		WHERE id=$4 AND run_id=$5 AND worker_id=$6 AND session_id=$7 AND attempt_no=$8 AND state='leased'
		RETURNING run_id,state`, request.Retryable, request.FailureClass, request.Reason, r.PathValue("id"), runID,
		request.WorkerID, request.SessionID, request.AttemptNo).Scan(&runID, &finalState)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE workers SET status=CASE WHEN status='draining' THEN status ELSE 'ready' END,current_task_id=NULL WHERE id=$1`, request.WorkerID)
	}
	if err == nil && finalState == "failed" {
		err = finalizeRun(r.Context(), tx, runID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		writeError(w, http.StatusInternalServerError, "release task failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"released": true})
}

func finalizeRun(ctx context.Context, tx pgx.Tx, runID string) error {
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tasks WHERE run_id=$1 AND state IN ('queued','leased'))`, runID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return nil
	}
	var failed, completed int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='failed'),count(*) FILTER (WHERE state='completed') FROM tasks WHERE run_id=$1`, runID).Scan(&failed, &completed); err != nil {
		return err
	}
	status := "completed"
	if failed > 0 && completed > 0 {
		status = "partial"
	} else if failed > 0 {
		status = "failed"
	}
	_, err := tx.Exec(ctx, `UPDATE runs SET status=$1,error=COALESCE((SELECT NULLIF(error,'') FROM tasks WHERE run_id=$2 AND state='failed' ORDER BY updated_at DESC LIMIT 1),''),updated_at=now() WHERE id=$2 AND status NOT IN ('cancelled','cancelling')`, status, runID)
	return err
}
