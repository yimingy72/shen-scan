package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
		WorkerID                   string   `json:"worker_id"`
		SessionID                  string   `json:"session_id"`
		RequestID                  string   `json:"request_id"`
		Types                      []string `json:"types"`
		UseRuleSets                bool     `json:"use_rule_sets"`
		SupportsHTTPXCFF           bool     `json:"supports_httpx_cff"`
		SupportsNucleiHTTPOriginal bool     `json:"supports_nuclei_http_original"`
		SupportsNucleiHTTPBatch    bool     `json:"supports_nuclei_http_batch"`
		SupportsPortRanges         bool     `json:"supports_port_ranges"`
		SupportsConfirmedStop      bool     `json:"supports_confirmed_stop"`
		SupportsHTTPRequestBudget  bool     `json:"supports_http_request_budget"`
		PortStartReserved          bool     `json:"port_start_reserved"`
		ServiceProfile             string   `json:"service_profile"`
		WebEvidenceProfile         string   `json:"web_evidence_profile"`
		FingerprintBundleSchema    string   `json:"fingerprint_bundle_schema"`
		FingerprintBundle          string   `json:"fingerprint_bundle"`
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
	if !request.SupportsHTTPRequestBudget {
		filtered := make([]string, 0, len(types))
		for _, stage := range types {
			if stage != "http" && stage != "poc" {
				filtered = append(filtered, stage)
			}
		}
		types = filtered
	}
	if err := s.reconcileExpiredWork(r.Context()); err != nil {
		writeError(w, 503, "reconcile execution limits failed")
		return
	}
	if request.SupportsConfirmedStop && request.SupportsPortRanges && request.PortStartReserved && contains(types, "port") {
		if err := s.preparePortStart(r.Context(), request.WorkerID, request.SessionID, request.RequestID); err != nil {
			writeError(w, 503, "prepare startup reservation failed")
			return
		}
	}
	httpxCapable := request.SupportsHTTPXCFF && request.UseRuleSets
	originalNucleiCapable := request.SupportsNucleiHTTPOriginal
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
	if err = expireQuotas(r.Context(), tx); err != nil {
		writeError(w, 503, "quota reconciliation failed")
		return
	}
	var workerStatus string
	var maintenance bool
	if err = tx.QueryRow(r.Context(), `SELECT status,maintenance FROM workers WHERE id=$1 AND session_id=$2`,
		request.WorkerID, request.SessionID).Scan(&workerStatus, &maintenance); err != nil {
		writeError(w, http.StatusUnauthorized, "worker session is invalid")
		return
	}
	var sessionSuspect bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM target_quotas WHERE worker_id=$1 AND state IN('suspect','revoking'))`, request.WorkerID).Scan(&sessionSuspect); err != nil {
		writeError(w, 503, "quota reconciliation failed")
		return
	}
	inserted, err := tx.Exec(r.Context(), `INSERT INTO claim_requests(worker_id,session_id,request_id,response)
		VALUES ($1,$2,$3,'null'::jsonb) ON CONFLICT DO NOTHING`, request.WorkerID, request.SessionID, request.RequestID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "claim task failed")
		return
	}
	if inserted.RowsAffected() == 1 && (!poolEnabled || workerStatus == "draining" || workerStatus == "offline" || sessionSuspect || maintenance || !request.SupportsConfirmedStop || len(types) == 0) {
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		response := map[string]any{"task": nil}
		if !request.SupportsConfirmedStop || len(types) == 0 {
			response["blocked_reason"] = "agent_upgrade_required"
		} else if maintenance {
			response["blocked_reason"] = "worker_maintenance"
		} else if sessionSuspect {
			response["blocked_reason"] = "blocked_quota_unknown"
		}
		writeJSON(w, http.StatusOK, response)
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
			if !expired && !request.SupportsHTTPRequestBudget {
				var needsBudget bool
				if err := tx.QueryRow(r.Context(), `SELECT type IN('http','poc') FROM tasks WHERE id=$1`, *previousTaskID).Scan(&needsBudget); err != nil {
					writeError(w, 500, "load HTTP budget compatibility failed")
					return
				}
				expired = needsBudget
			}
			if !expired && !request.SupportsNucleiHTTPBatch {
				var needsBatch bool
				if err := tx.QueryRow(r.Context(), `SELECT COALESCE(payload->>'nuclei_batch_profile','')<>'' FROM tasks WHERE id=$1`, *previousTaskID).Scan(&needsBatch); err != nil {
					writeError(w, 500, "load batch compatibility failed")
					return
				}
				expired = needsBatch
			}
			if !expired && !originalNucleiCapable {
				var requiresOriginal bool
				checkErr := tx.QueryRow(r.Context(), `SELECT COALESCE(payload->'rules'->0->'nuclei'->>'execution_profile','')='http-basic-v1'
					FROM tasks WHERE id=$1`, *previousTaskID).Scan(&requiresOriginal)
				if checkErr == nil && requiresOriginal {
					expired = true
				}
			}
			if !expired {
				var incompatible bool
				checkErr := tx.QueryRow(r.Context(), `SELECT type='http' AND COALESCE(payload->>'web_profile','')<>'' AND
                    (payload->>'web_profile'<>$2 OR CASE WHEN COALESCE(payload->>'fingerprint_bundle_schema','')='' THEN payload->>'fingerprint_bundle'<>$3 ELSE payload->>'fingerprint_bundle_schema'<>$4 OR $4='' END) FROM tasks WHERE id=$1`, *previousTaskID, request.WebEvidenceProfile, request.FingerprintBundle, request.FingerprintBundleSchema).Scan(&incompatible)
				if checkErr != nil {
					writeError(w, 500, "load claim compatibility failed")
					return
				}
				expired = incompatible
			}
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
		if task != nil && task.Type == "poc" {
			task.Payload, err = remainingPOCRules(r.Context(), tx, task.ID, task.Payload)
			if err != nil {
				writeError(w, 500, "filter accepted PoC templates failed")
				return
			}
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
	var requiresHTTPXCFF bool
	// Startup-selected workers wait briefly for their reserved run lock rather
	// than losing the reserved slot to SKIP LOCKED and a polling delay.
	var reservedRunID string
	reserveErr := tx.QueryRow(r.Context(), `SELECT t.run_id FROM port_start_tickets p JOIN tasks t ON t.id=p.task_id
        WHERE p.worker_id=$1 AND p.session_id=$2 AND p.request_id=$3 AND t.state='queued' AND t.reserved_until>now()`, request.WorkerID, request.SessionID, request.RequestID).Scan(&reservedRunID)
	if reserveErr != nil && !errors.Is(reserveErr, pgx.ErrNoRows) {
		writeError(w, 503, "load startup reservation failed")
		return
	}
	if reservedRunID != "" {
		err = tx.QueryRow(r.Context(), `SELECT id,last_claim_target_key,requires_httpx_cff FROM runs WHERE id=$1 AND status IN('pending','running') FOR UPDATE`, reservedRunID).Scan(&runID, &lastTargetKey, &requiresHTTPXCFF)
	} else {
		err = tx.QueryRow(r.Context(), `SELECT r.id,r.last_claim_target_key,r.requires_httpx_cff FROM runs r
		WHERE r.status IN ('pending','running') AND EXISTS (
			SELECT 1 FROM tasks t WHERE t.run_id=r.id AND t.type=ANY($1)
			AND (t.state='queued' OR (t.state='leased' AND t.lease_until <= now()))
            AND t.attempt_no<6 AND (t.first_started_at IS NULL OR t.first_started_at>now()-interval '30 minutes')
            AND (t.type<>'port' OR $6 OR t.payload->>'ports'='1-65535')
            AND (t.state<>'queued' OR t.worker_id IS NULL OR t.reserved_until<=now() OR (t.worker_id=$2 AND t.session_id=$3))
            AND NOT EXISTS(SELECT 1 FROM port_start_tickets p WHERE p.root_task_id=t.id AND p.task_id IS NULL AND p.expires_at>now())
            AND NOT EXISTS(SELECT 1 FROM target_quotas q WHERE q.task_id=t.id AND q.attempt_no=t.attempt_no AND q.state IN('active','suspect','revoking'))
			AND (t.type<>'service' OR COALESCE(t.payload->>'service_profile','')='' OR t.payload->>'service_profile'=$9)
            AND (t.type<>'http' OR NOT r.requires_httpx_cff OR $4)
            AND (t.type<>'http' OR COALESCE(t.payload->>'web_profile','')='' OR (t.payload->>'web_profile'=$7 AND CASE WHEN COALESCE(t.payload->>'fingerprint_bundle_schema','')='' THEN t.payload->>'fingerprint_bundle'=$8 ELSE $10<>'' AND t.payload->>'fingerprint_bundle_schema'=$10 END))
			AND (t.type<>'poc' OR COALESCE(t.payload->'rules'->0->'nuclei'->>'execution_profile','') <> 'http-basic-v1' OR $5)
 AND (COALESCE(t.payload->>'nuclei_batch_profile','')='' OR $11)
			AND ((t.type='port' AND NOT EXISTS (SELECT 1 FROM tasks active_port
				WHERE active_port.worker_id=$2 AND active_port.session_id=$3 AND active_port.type='port'
				AND active_port.state='leased' AND active_port.lease_until > now()))
			OR (t.type<>'port' AND NOT EXISTS (SELECT 1 FROM tasks active_target
				WHERE active_target.worker_id=$2 AND active_target.session_id=$3
				AND active_target.type IN ('service','http','poc') AND active_target.target_key=t.target_key
                AND (t.type<>'http' OR active_target.type<>'http' OR
                    ((active_target.payload->'endpoints'->0) - 'work_key') = ((t.payload->'endpoints'->0) - 'work_key'))
				AND active_target.state='leased' AND active_target.lease_until > now()))))
		ORDER BY r.last_claim_at,r.created_at,r.id FOR UPDATE OF r SKIP LOCKED LIMIT 1`,
			types, request.WorkerID, request.SessionID, httpxCapable, originalNucleiCapable, request.SupportsPortRanges, request.WebEvidenceProfile, request.FingerprintBundle, request.ServiceProfile, request.FingerprintBundleSchema, request.SupportsNucleiHTTPBatch).Scan(&runID, &lastTargetKey, &requiresHTTPXCFF)
	}
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
            AND t.attempt_no<6 AND (t.first_started_at IS NULL OR t.first_started_at>now()-interval '30 minutes')
            AND (t.type<>'port' OR $11 OR t.payload->>'ports'='1-65535')
            AND (t.state<>'queued' OR t.worker_id IS NULL OR t.reserved_until<=now() OR (t.worker_id=$3 AND t.session_id=$4))
            AND NOT EXISTS(SELECT 1 FROM port_start_tickets p WHERE p.root_task_id=t.id AND p.task_id IS NULL AND p.expires_at>now())
            AND NOT EXISTS(SELECT 1 FROM target_quotas q WHERE q.task_id=t.id AND q.attempt_no=t.attempt_no AND q.state IN('active','suspect','revoking'))
			AND (t.type<>'service' OR COALESCE(t.payload->>'service_profile','')='' OR t.payload->>'service_profile'=$14)
            AND (t.type<>'http' OR NOT $8 OR $9)
            AND (t.type<>'http' OR COALESCE(t.payload->>'web_profile','')='' OR (t.payload->>'web_profile'=$12 AND CASE WHEN COALESCE(t.payload->>'fingerprint_bundle_schema','')='' THEN t.payload->>'fingerprint_bundle'=$13 ELSE $15<>'' AND t.payload->>'fingerprint_bundle_schema'=$15 END))
			AND (t.type<>'poc' OR COALESCE(t.payload->'rules'->0->'nuclei'->>'execution_profile','') <> 'http-basic-v1' OR $10)
 AND (COALESCE(t.payload->>'nuclei_batch_profile','')='' OR $16)
			AND ((t.type='port' AND NOT EXISTS (SELECT 1 FROM tasks active_port
				WHERE active_port.worker_id=$3 AND active_port.session_id=$4 AND active_port.type='port'
				AND active_port.state='leased' AND active_port.lease_until > now()))
			OR (t.type<>'port' AND NOT EXISTS (SELECT 1 FROM tasks active_target
				WHERE active_target.worker_id=$3 AND active_target.session_id=$4
				AND active_target.type IN ('service','http','poc') AND active_target.target_key=t.target_key
                AND (t.type<>'http' OR active_target.type<>'http' OR
                    ((active_target.payload->'endpoints'->0) - 'work_key') = ((t.payload->'endpoints'->0) - 'work_key'))
				AND active_target.state='leased' AND active_target.lease_until > now())))
			ORDER BY (t.worker_id=$3 AND t.session_id=$4 AND t.reserved_until>now()) DESC NULLS LAST,t.target_key,t.created_at,t.id FOR UPDATE OF t SKIP LOCKED LIMIT 1`,
			runID, types, request.WorkerID, request.SessionID, candidate.retry, candidate.afterCursor, lastTargetKey,
			requiresHTTPXCFF, httpxCapable, originalNucleiCapable, request.SupportsPortRanges, request.WebEvidenceProfile, request.FingerprintBundle, request.ServiceProfile, request.FingerprintBundleSchema, request.SupportsNucleiHTTPBatch).Scan(
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
	var previousAttemptNo int
	if err = tx.QueryRow(r.Context(), `SELECT attempt_no FROM tasks WHERE id=$1`, taskID).Scan(&previousAttemptNo); err != nil {
		writeError(w, 500, "load execution identity failed")
		return
	}
	allowed, quotaErr := acquireTaskQuota(r.Context(), tx, taskID, previousAttemptNo+1, request.WorkerID, request.SessionID, typeName, payload, rateUntil)
	if quotaErr != nil {
		writeError(w, 500, "reserve target quota failed")
		return
	}
	if !allowed {
		if _, err = tx.Exec(r.Context(), `UPDATE runs SET last_claim_at=now(),last_claim_target_key=$2 WHERE id=$1`, runID, targetKey); err != nil {
			writeError(w, 503, "record blocked claim failed")
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			writeError(w, 503, "record blocked claim failed")
			return
		}
		writeJSON(w, 200, map[string]any{"task": nil, "blocked_reason": "target_quota_unavailable"})
		return
	}
	var attempt int
	err = tx.QueryRow(r.Context(), `UPDATE tasks SET state='leased' ,attempt_no=attempt_no+1,worker_id=$1,session_id=$2,
		lease_until=$3,rate_until=$4,last_batch_seq=-1,first_started_at=COALESCE(first_started_at,now()),reserved_until=NULL,updated_at=now() WHERE id=$5 RETURNING attempt_no`,
		request.WorkerID, request.SessionID, leaseUntil, rateUntil, taskID).Scan(&attempt)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE runs SET status='running',last_claim_at=now(),
			last_claim_target_key=$2,updated_at=CASE WHEN status='pending' THEN now() ELSE updated_at END WHERE id=$1`, runID, targetKey)
	}
	if err == nil {
		payload, err = attachClaimRules(r.Context(), tx, runID, typeName, payload, request.UseRuleSets)
	}
	if err == nil && typeName == "poc" {
		payload, err = remainingPOCRules(r.Context(), tx, taskID, payload)
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

func (s *Server) getTaskRules(w http.ResponseWriter, r *http.Request) {
	workerID := strings.TrimSpace(r.URL.Query().Get("worker_id"))
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	attempt, err := strconv.Atoi(r.URL.Query().Get("attempt_no"))
	if err != nil || attempt < 1 {
		writeError(w, http.StatusBadRequest, "positive attempt_no is required")
		return
	}
	if err = s.authenticateWorker(r.Context(), workerID, sessionID); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var runID, typeName string
	var snapshotRaw []byte
	err = s.db.QueryRow(r.Context(), `SELECT t.run_id,t.type,r.rules_snapshot FROM tasks t JOIN runs r ON r.id=t.run_id
		WHERE t.id=$1 AND t.worker_id=$2 AND t.session_id=$3 AND t.attempt_no=$4
		AND t.state='leased' AND t.lease_until>now() AND t.type IN ('http','service')`,
		r.PathValue("id"), workerID, sessionID, attempt).Scan(&runID, &typeName, &snapshotRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "task execution is stale or has no rule set")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load task rules failed")
		return
	}
	if len(snapshotRaw) == 0 || string(snapshotRaw) == "null" {
		writeError(w, http.StatusConflict, "task has no frozen rule set")
		return
	}
	var snapshot ruleSnapshot
	if json.Unmarshal(snapshotRaw, &snapshot) != nil {
		writeError(w, http.StatusInternalServerError, "load task rules failed")
		return
	}
	kind := "http"
	rules := executionRules(snapshot.HTTP)
	if typeName == "service" {
		kind = "port"
		rules = executionRules(snapshot.Port)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ref": runID + ":" + typeName, "kind": kind, "rules": rules})
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
		task.Payload, err = attachClaimRules(ctx, tx, task.RunID, task.Type, task.Payload, false)
	}
	if err == nil && task.Type == "poc" {
		task.Payload, err = remainingPOCRules(ctx, tx, task.ID, task.Payload)
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
	var state, typeName string
	var payload []byte
	var currentLease *time.Time
	err = tx.QueryRow(r.Context(), `SELECT state,lease_until,type,payload FROM tasks
		WHERE id=$1 AND run_id=$2 AND worker_id=$3 AND session_id=$4 AND attempt_no=$5 FOR UPDATE`,
		r.PathValue("id"), runID, identity.WorkerID, identity.SessionID, identity.AttemptNo).Scan(&state, &currentLease, &typeName, &payload)
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
		var allowed bool
		allowed, err = renewTaskQuota(r.Context(), tx, r.PathValue("id"), identity.AttemptNo, identity.WorkerID, identity.SessionID, typeName, payload, rateUntil)
		if err == nil && !allowed {
			action, reason = "stop", "execution quota expired or stop is unconfirmed"
			leaseUntil, rateUntil = time.Time{}, time.Time{}
		} else if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE tasks SET lease_until=$1,rate_until=$2,updated_at=now() WHERE id=$3`, leaseUntil, rateUntil, r.PathValue("id"))
		}
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
	batchIndex, _, err := observationStorageJSON(itemsJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid observation JSON")
		return
	}
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
	// Serialize derived work with completion/cancellation, always locking run before task.
	var lockedRunID string
	if err = tx.QueryRow(r.Context(), `SELECT run_id FROM tasks WHERE id=$1`, r.PathValue("id")).Scan(&lockedRunID); err != nil {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	}
	if err = tx.QueryRow(r.Context(), `SELECT id FROM runs WHERE id=$1 FOR UPDATE`, lockedRunID).Scan(&lockedRunID); err != nil {
		writeError(w, http.StatusInternalServerError, "lock source run failed")
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
	seenPOCRules := map[string]bool{}
	for index := range request.Items {
		item := &request.Items[index]
		if typeName == "poc" {
			if seenPOCRules[item.RuleID] {
				writeError(w, 422, "duplicate PoC template outcome in one batch")
				return
			}
			seenPOCRules[item.RuleID] = true
		}
		targetKey, err := observationTarget(typeName, payload, sourceTarget, item)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("items[%d]: %v", index, err))
			return
		}
		if typeName == "poc" {
			var alreadyAccepted bool
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM poc_template_receipts WHERE task_id=$1 AND rule_id=$2)`, r.PathValue("id"), item.RuleID).Scan(&alreadyAccepted); err != nil {
				writeError(w, 500, "check accepted template failed")
				return
			}
			if alreadyAccepted {
				writeError(w, 422, "PoC template already has an immutable completion receipt")
				return
			}
		}
		raw, _ := json.Marshal(item)
		stored, original, err := observationStorageJSON(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid observation JSON")
			return
		}
		assetRows[index] = []any{newID(), runID, r.PathValue("id"), request.AttemptNo, request.BatchSeq, index, targetKey, stored, original}
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO task_batches(task_id,attempt_no,batch_seq,content_hash,items) VALUES ($1,$2,$3,$4,$5)`,
		r.PathValue("id"), request.AttemptNo, request.BatchSeq, hash[:], batchIndex)
	if err == nil {
		var copied int64
		copied, err = tx.CopyFrom(r.Context(), pgx.Identifier{"assets"},
			[]string{"id", "run_id", "task_id", "attempt_no", "batch_seq", "item_index", "target_key", "observation", "observation_raw"},
			pgx.CopyFromRows(assetRows))
		if err == nil && copied != int64(len(assetRows)) {
			err = fmt.Errorf("copied %d of %d assets", copied, len(assetRows))
		}
	}
	if err == nil && typeName == "poc" {
		err = acceptPOCTemplates(r.Context(), tx, r.PathValue("id"), request.AttemptNo, request.BatchSeq, payload)
	}
	if err == nil && typeName == "port" {
		err = acceptPortPositives(r.Context(), tx, r.PathValue("id"), runID, request.AttemptNo, request.BatchSeq)
		if err == nil {
			err = derivePortTasks(r.Context(), tx, r.PathValue("id"), runID, request.AttemptNo, payload, request.BatchSeq)
		}
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		slog.Error("store task batch failed", "task_id", r.PathValue("id"), "attempt_no", request.AttemptNo, "batch_seq", request.BatchSeq, "error", err)
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
	var attempt, committedLastSeq int
	var acceptedCompletionID *string
	var leaseUntil *time.Time
	err = tx.QueryRow(r.Context(), `SELECT type,state,attempt_no,payload,target_key,lease_until,last_batch_seq,completion_id FROM tasks
		WHERE id=$1 AND run_id=$2 AND worker_id=$3 AND session_id=$4 FOR UPDATE`,
		r.PathValue("id"), runID, request.WorkerID, request.SessionID).Scan(&typeName, &state, &attempt, &payload, &sourceTarget, &leaseUntil, &committedLastSeq, &acceptedCompletionID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "complete task failed")
		return
	}
	if state == "completed" && attempt == request.AttemptNo {
		if committedLastSeq != request.LastBatchSeq {
			writeError(w, http.StatusConflict, "completion receipt has a different final batch")
			return
		}
		_ = tx.Commit(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"completed": true, "completion_id": acceptedCompletionID})
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
	outcome, coverage, err := completeOutcome(r.Context(), tx, r.PathValue("id"), typeName, request.AttemptNo, payload)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err = finishTaskQuota(r.Context(), tx, r.PathValue("id"), request.AttemptNo, request.WorkerID, request.SessionID, true, "agent completed after process exit"); err != nil {
		writeError(w, 500, "release completion quota failed")
		return
	}
	if typeName == "port" {
		if err := derivePortTasks(r.Context(), tx, r.PathValue("id"), runID, request.AttemptNo, payload); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	if typeName == "service" {
		if err := deriveServiceWebTasks(r.Context(), tx, r.PathValue("id"), runID, request.AttemptNo, payload); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	if typeName == "http" {
		if err := derivePOCTasks(r.Context(), tx, r.PathValue("id"), runID, request.AttemptNo, typeName, sourceTarget, payload); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	completionID := newID()
	_, err = tx.Exec(r.Context(), `UPDATE tasks SET state='completed',last_batch_seq=$1,lease_until=NULL,rate_until=NULL,
		completed_at=now(),updated_at=now(),accepted_attempt_no=attempt_no,completion_id=$3,outcome=$4,coverage=$5 WHERE id=$2`, request.LastBatchSeq, r.PathValue("id"), completionID, outcome, coverage)
	if err == nil {
		err = sealCompletionEvidence(r.Context(), tx, r.PathValue("id"), typeName, request.AttemptNo, payload)
	}
	if err == nil && typeName == "poc" {
		err = sealPOCBatchReceipts(r.Context(), tx, r.PathValue("id"), payload)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE tasks SET payload=payload||jsonb_build_object('source_completion_id',$3::text)
      WHERE run_id=$1 AND payload->>'source_task_id'=$2 AND state='queued'`, runID, r.PathValue("id"), completionID)
	}
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
	writeJSON(w, http.StatusOK, map[string]any{"completed": true, "completion_id": completionID})
}

func derivePortTasks(ctx context.Context, tx pgx.Tx, taskID, runID string, attempt int, payload json.RawMessage, batches ...int) error {
	var config struct {
		HTTPEnabled bool `json:"http_enabled"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		return errors.New("invalid persisted port task payload")
	}
	var batch *int
	if len(batches) > 0 {
		batch = &batches[0]
	}
	rows, err := tx.Query(ctx, `SELECT observation FROM assets WHERE task_id=$1 AND attempt_no=$2
		AND ($3::int IS NULL OR batch_seq=$3) AND observation->>'kind'='port' AND COALESCE(observation->>'error','')='' AND COALESCE((observation->>'port')::int,0) BETWEEN 1 AND 65535 ORDER BY batch_seq,item_index`, taskID, attempt, batch)
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
		ip, err := observationTarget("port", payload, payloadTarget(payload), &observation)
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
	tuning, err := loadAdaptiveBatch(ctx, tx, "service", 32, 45)
	if err != nil {
		return err
	}
	var serviceProfile string
	if err = tx.QueryRow(ctx, `SELECT COALESCE(rules_snapshot->>'service_profile','') FROM runs WHERE id=$1`, runID).Scan(&serviceProfile); err != nil {
		return err
	}
	for _, ip := range ips {
		ports := make([]int, 0, len(portsByIP[ip]))
		for port := range portsByIP[ip] {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		selectedRows, err := tx.Query(ctx, `SELECT port FROM port_service_work WHERE run_id=$1 AND target_key=$2 AND profile=$3`, runID, ip, serviceProfile)
		if err != nil {
			return err
		}
		for selectedRows.Next() {
			var port int
			if err = selectedRows.Scan(&port); err != nil {
				selectedRows.Close()
				return err
			}
			delete(portsByIP[ip], port)
		}
		selectedRows.Close()
		if err = selectedRows.Err(); err != nil {
			return err
		}
		pending := ports[:0]
		for _, port := range ports {
			if _, exists := portsByIP[ip][port]; exists {
				pending = append(pending, port)
			}
		}
		ports = pending
		ports, err = fingerprintPorts(ctx, tx, runID, ip, ports)
		if err != nil {
			return err
		}
		if err := insertPortServiceBatch(ctx, tx, runID, taskID, ip, serviceProfile, attempt, ports, config.HTTPEnabled, tuning.Size); err != nil {
			return err
		}
	}
	return nil
}

type taskEndpoint struct {
	WorkKey string `json:"work_key,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port,omitempty"`
	Host    string `json:"host,omitempty"`
	URL     string `json:"url,omitempty"`
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

func derivePOCTasks(ctx context.Context, tx pgx.Tx, triggerTaskID, runID string, triggerAttempt int, triggerType, sourceTarget string, payload json.RawMessage) error {
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
	if snapshot.POCPolicy == "" {
		if triggerType != "http" {
			return nil
		}
		if err := deriveLegacyPOCTasks(ctx, tx, triggerTaskID, runID, triggerAttempt, sourceTarget, payload, snapshot.POC); err != nil {
			return err
		}
		return groupDerivedPOCBatches(ctx, tx, runID)
	}
	if snapshot.POCPolicy != "fingerprint" {
		return fmt.Errorf("unsupported persisted PoC policy %q", snapshot.POCPolicy)
	}
	if err := deriveFingerprintPOCTasks(ctx, tx, triggerTaskID, runID, triggerAttempt, triggerType, sourceTarget, snapshot); err != nil {
		return err
	}
	return groupDerivedPOCBatches(ctx, tx, runID)
}

func deriveLegacyPOCTasks(ctx context.Context, tx pgx.Tx, parentID, runID string, attempt int, sourceTarget string, payload json.RawMessage, rules []rulelib.Rule) error {
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
			if endpoint.URL != "" {
				if inputURL, parseErr := url.Parse(endpoint.URL); parseErr == nil {
					inputURL.Scheme, inputURL.Host = observedURL.Scheme, observedURL.Host
					inputURL.Path = strings.TrimRight(inputURL.Path, "/")
					inputURL.RawPath = strings.TrimRight(inputURL.RawPath, "/")
					inputURL.RawQuery, inputURL.Fragment, inputURL.ForceQuery = "", "", false
					derivedEndpoint.URL = inputURL.String()
				}
			}
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
		for _, rule := range rules {
			if err := insertPOCTask(ctx, tx, runID, parentID, attempt, endpointKey, sourceTarget, endpoints[endpointKey], rule, nil, "legacy_all_enabled", false); err != nil {
				return err
			}
		}
	}
	return nil
}

type pocEndpointCandidate struct {
	ParentID     string
	Attempt      int
	TargetKey    string
	Origin       string
	IP           string
	Port         int
	Endpoint     taskEndpoint
	HTTPProducts []string
}

func productEndpointKey(targetKey, ip string, port int) string {
	return targetKey + "\x00" + canonicalTarget(ip) + "\x00" + strconv.Itoa(port)
}

func deriveFingerprintPOCTasks(ctx context.Context, tx pgx.Tx, triggerTaskID, runID string, triggerAttempt int, triggerType, sourceTarget string, snapshot ruleSnapshot) error {
	serviceProducts := make(map[string][]string)
	serviceRows, err := tx.Query(ctx, `SELECT a.target_key,a.observation->>'ip',(a.observation->>'port')::int,a.observation->>'product'
		FROM assets a JOIN tasks t ON t.id=a.task_id AND t.attempt_no=a.attempt_no
		WHERE a.run_id=$1 AND a.target_key=$2 AND a.observation->>'kind'='service'
		AND COALESCE(a.observation->>'product','')<>'' AND COALESCE(a.observation->>'error','')='' AND
		(t.state='completed' OR ($3='service' AND t.id=$4 AND t.attempt_no=$5))`,
		runID, sourceTarget, triggerType, triggerTaskID, triggerAttempt)
	if err != nil {
		return fmt.Errorf("load service fingerprints: %w", err)
	}
	for serviceRows.Next() {
		var targetKey, ip, product string
		var port int
		if err = serviceRows.Scan(&targetKey, &ip, &port, &product); err != nil {
			serviceRows.Close()
			return fmt.Errorf("load service fingerprints: %w", err)
		}
		key := productEndpointKey(targetKey, ip, port)
		serviceProducts[key] = appendUniqueString(serviceProducts[key], product)
	}
	serviceRows.Close()
	if err = serviceRows.Err(); err != nil {
		return fmt.Errorf("load service fingerprints: %w", err)
	}

	httpRows, err := tx.Query(ctx, `SELECT a.task_id,a.attempt_no,a.target_key,a.observation,t.payload
		FROM assets a JOIN tasks t ON t.id=a.task_id AND t.attempt_no=a.attempt_no
		WHERE a.run_id=$1 AND a.observation->>'kind'='http' AND COALESCE((a.observation->>'status_code')::int,0)>0
        AND COALESCE(a.observation->>'error','')='' AND COALESCE(a.observation->>'coverage','') NOT IN('partial','incomplete','missing','unconfirmed')
		AND (($2='http' AND t.id=$3 AND t.attempt_no=$4) OR ($2='service' AND a.target_key=$5 AND t.state='completed'))
		ORDER BY a.task_id,a.attempt_no,a.batch_seq,a.item_index`, runID, triggerType, triggerTaskID, triggerAttempt, sourceTarget)
	if err != nil {
		return fmt.Errorf("load HTTP fingerprints: %w", err)
	}
	candidates := make(map[string]*pocEndpointCandidate)
	for httpRows.Next() {
		var parentID, targetKey string
		var attempt int
		var raw, taskPayload []byte
		if err = httpRows.Scan(&parentID, &attempt, &targetKey, &raw, &taskPayload); err != nil {
			httpRows.Close()
			return fmt.Errorf("load HTTP fingerprints: %w", err)
		}
		var observation Observation
		var config struct {
			Endpoints []taskEndpoint `json:"endpoints"`
		}
		if json.Unmarshal(raw, &observation) != nil || json.Unmarshal(taskPayload, &config) != nil {
			httpRows.Close()
			return errors.New("invalid persisted HTTP fingerprint")
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
			ip := observation.IP
			if ip == "" {
				ip = endpoint.IP
			}
			port := observation.Port
			if port == 0 {
				port = urlPortNumber(observedURL)
			}
			key := fmt.Sprintf("%s\x00%d\x00%s", parentID, attempt, origin(observedURL))
			candidate := candidates[key]
			if candidate == nil {
				candidate = &pocEndpointCandidate{ParentID: parentID, Attempt: attempt, TargetKey: targetKey,
					Origin: origin(observedURL), IP: ip, Port: port, Endpoint: derivedEndpoint}
				candidates[key] = candidate
			}
			for _, technology := range observation.Technologies {
				if strings.TrimSpace(technology.Name) != "" {
					candidate.HTTPProducts = appendUniqueString(candidate.HTTPProducts, technology.Name)
				}
			}
			break
		}
	}
	httpRows.Close()
	if err = httpRows.Err(); err != nil {
		return fmt.Errorf("load HTTP fingerprints: %w", err)
	}

	explicit := make(map[string]bool, len(snapshot.ExplicitPOCRuleIDs))
	for _, id := range snapshot.ExplicitPOCRuleIDs {
		explicit[id] = true
	}
	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		candidate := candidates[key]
		service := serviceProducts[productEndpointKey(candidate.TargetKey, candidate.IP, candidate.Port)]
		for _, rule := range snapshot.POC {
			matchedProducts := make([]string, 0)
			httpMatched, serviceMatched := false, false
			for _, product := range candidate.HTTPProducts {
				if rulelib.MatchesProducts(rule, []string{product}) {
					matchedProducts = appendUniqueString(matchedProducts, product)
					httpMatched = true
				}
			}
			for _, product := range service {
				if rulelib.MatchesProducts(rule, []string{product}) {
					matchedProducts = appendUniqueString(matchedProducts, product)
					serviceMatched = true
				}
			}
			reasons := make([]string, 0, 2)
			if httpMatched {
				reasons = append(reasons, "http_technology")
			}
			if serviceMatched {
				reasons = append(reasons, "service_product")
			}
			if len(rule.AppliesTo) == 0 {
				if !explicit[rule.ID] {
					continue
				}
				reasons = append(reasons, "explicit_unbound_rule")
			} else if len(matchedProducts) == 0 {
				continue
			}
			sort.Strings(matchedProducts)
			if err := insertPOCTask(ctx, tx, runID, candidate.ParentID, candidate.Attempt, candidate.Origin,
				candidate.TargetKey, candidate.Endpoint, rule, matchedProducts, strings.Join(reasons, "+"), true); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func insertPOCTask(ctx context.Context, tx pgx.Tx, runID, parentID string, attempt int, endpointKey, targetKey string, endpoint taskEndpoint, rule rulelib.Rule, matchedProducts []string, triggerReason string, fingerprintPolicy bool) error {
	payload, _ := json.Marshal(map[string]any{"endpoint": endpoint, "rules": []rulelib.Rule{rule}, "execution_timeout_seconds": 90,
		"matched_products": matchedProducts, "trigger_reason": triggerReason, "source_task_id": parentID, "source_attempt_no": attempt})
	taskID := newID()
	derivedKey := fmt.Sprintf("poc:%s:%d:%s:%s", parentID, attempt, endpointKey, rule.ID)
	if fingerprintPolicy {
		derivedKey = fmt.Sprintf("poc-fingerprint:%s:%s:%d", endpointKey, rule.ID, rule.Revision)
	}
	var grouped bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM poc_batch_derived_keys WHERE run_id=$1 AND derived_key=$2)`, runID, derivedKey).Scan(&grouped); err != nil {
		return err
	}
	if grouped {
		return nil
	}
	result, err := tx.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES($1,$2,'poc',$3,$4,$5)
		ON CONFLICT(run_id,derived_key) DO NOTHING`, taskID, runID, payload, derivedKey, targetKey)
	if err != nil || result.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES($1,$2)`, taskID, targetKey)
	return err
}

func insertDerivedTask(ctx context.Context, tx pgx.Tx, runID, parentID, typeName, targetKey string, chunk, timeout int, endpoints []map[string]any) error {
	profile := map[string]any{"endpoints": endpoints, "timeout_seconds": timeout, "execution_timeout_seconds": 90, "source_task_id": parentID}
	if typeName == "service" {
		var required string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(rules_snapshot->>'service_profile','') FROM runs WHERE id=$1`, runID).Scan(&required); err != nil {
			return err
		}
		if required != "" {
			profile["service_profile"] = required
		}
	}
	if typeName == "http" {
		var bundle, webProfile, bundleSchema string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(rules_snapshot->>'fingerprint_bundle',''),COALESCE(rules_snapshot->>'web_profile',''),COALESCE(rules_snapshot->>'fingerprint_bundle_schema','') FROM runs WHERE id=$1`, runID).Scan(&bundle, &webProfile, &bundleSchema); err != nil {
			return err
		}
		if bundle != "" {
			profile["fingerprint_bundle"] = bundle
			profile["fingerprint_bundle_schema"] = bundleSchema
			profile["web_profile"] = webProfile
		}
		for i := range endpoints {
			endpoints[i]["work_key"] = fmt.Sprintf("web:%s:%d", targetKey, chunk)
		}
		profile["max_requests"] = 8
		profile["max_body_bytes"] = 2 << 20
		profile["max_icons"] = 2
	}
	payload, _ := json.Marshal(profile)
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
		Stopped      bool   `json:"stopped"`
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
		state=CASE WHEN state='cancelled' THEN 'cancelled' WHEN $1 AND ($2='' OR execution_failures+1<3) AND attempt_no<6 AND COALESCE(first_started_at,now())>now()-interval '30 minutes' THEN 'queued' ELSE 'failed' END,
		execution_failures=execution_failures+CASE WHEN $2='execution_timeout' THEN 1 ELSE 0 END,
		error=$3,worker_id=NULL,session_id=NULL,lease_until=NULL,rate_until=NULL,updated_at=now()
		WHERE id=$4 AND run_id=$5 AND worker_id=$6 AND session_id=$7 AND attempt_no=$8 AND state IN('leased','cancelled')
		RETURNING run_id,state`, request.Retryable, request.FailureClass, request.Reason, r.PathValue("id"), runID,
		request.WorkerID, request.SessionID, request.AttemptNo).Scan(&runID, &finalState)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "task execution is stale")
		return
	}
	if err == nil {
		err = finishTaskQuota(r.Context(), tx, r.PathValue("id"), request.AttemptNo, request.WorkerID, request.SessionID, request.Stopped, request.Reason)
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
	var failed, completed, incomplete int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='failed'),count(*) FILTER (WHERE state='completed'),count(*) FILTER(WHERE state='completed' AND coverage='partial') FROM tasks WHERE run_id=$1`, runID).Scan(&failed, &completed, &incomplete); err != nil {
		return err
	}
	status := "completed"
	if incomplete > 0 || (failed > 0 && completed > 0) {
		status = "partial"
	} else if failed > 0 {
		status = "failed"
	}
	_, err := tx.Exec(ctx, `UPDATE runs SET status=$1,error=COALESCE((SELECT NULLIF(error,'') FROM tasks WHERE run_id=$2 AND state='failed' ORDER BY updated_at DESC LIMIT 1),''),updated_at=now() WHERE id=$2 AND status NOT IN ('cancelled','cancelling')`, status, runID)
	return err
}
