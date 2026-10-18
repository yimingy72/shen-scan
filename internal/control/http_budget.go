package control

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/webevidence"
)

const (
	httpBudgetRPS      = 10
	httpClusterRPS     = 250
	httpPermitLifetime = 500 * time.Millisecond
)

// Admission is paced at 10 grants/second/IP and 250/second/cluster, burst one. A worker must
// begin the request before its conservative local permit deadline. With the
// 500ms lifetime, request starts may bunch: this is not exact wire-arrival RPS.
// Storage is one row/IP plus one high-water receipt/task, never one row/request.
const httpBudgetSchema = `
CREATE TABLE IF NOT EXISTS http_ip_budgets (
 connect_ip inet PRIMARY KEY,
 next_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS http_ip_budgets_next_idx ON http_ip_budgets(next_at);
CREATE TABLE IF NOT EXISTS http_permit_receipts (
 task_id text PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
 attempt_no integer NOT NULL,
 worker_id text NOT NULL,
 session_id text NOT NULL,
 request_seq bigint NOT NULL CHECK(request_seq>0),
 connect_ip inet NOT NULL,
 host text NOT NULL,
 port integer NOT NULL,
 granted_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS http_cluster_budget (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 next_at timestamptz NOT NULL DEFAULT 'epoch'
);
INSERT INTO http_cluster_budget(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS http_endpoint_bindings (
 task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 host text NOT NULL,port integer NOT NULL,
 attempt_no integer NOT NULL,worker_id text NOT NULL,session_id text NOT NULL,
 connect_ip inet NOT NULL,
 PRIMARY KEY(task_id,host,port)
);` + pocReceiptSchema

type httpPermitRequest struct {
	Segment   int    `json:"segment,omitempty"`
	WorkerID  string `json:"worker_id"`
	SessionID string `json:"session_id"`
	AttemptNo int    `json:"attempt_no"`
	RequestID string `json:"request_id"`
	ConnectIP string `json:"connect_ip"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
}

type httpPermitResponse struct {
	Granted      bool      `json:"granted"`
	ServerTime   time.Time `json:"server_time"`
	ValidUntil   time.Time `json:"valid_until,omitempty"`
	RetryAfterMS int64     `json:"retry_after_ms,omitempty"`
	RateRPS      int       `json:"rate_rps"`
	ClusterRPS   int       `json:"cluster_rps"`
	Burst        int       `json:"burst"`
}

func (s *Server) httpPermit(w http.ResponseWriter, r *http.Request) {
	var req httpPermitRequest
	if err := decodeJSONLimit(w, r, &req, 4096); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	seq, err := strconv.ParseInt(req.RequestID, 10, 64)
	ip, ipErr := netip.ParseAddr(req.ConnectIP)
	if err != nil || seq < 1 || strconv.FormatInt(seq, 10) != req.RequestID || ipErr != nil || ip.Zone() != "" || req.AttemptNo < 1 || req.Port < 1 || req.Port > 65535 || len(req.Host) > 253 || req.Host == "" {
		writeError(w, 400, "positive decimal request_id, attempt_no and valid connect_ip/host/port are required")
		return
	}
	ip = ip.Unmap()
	req.ConnectIP = ip.String()
	req.Host = canonicalTarget(req.Host)
	if !allowedAddress(ip, s.allowLocal) {
		writeError(w, 400, "connect IP is not authorized")
		return
	}
	if err = s.authenticateWorker(r.Context(), req.WorkerID, req.SessionID); err != nil {
		writeError(w, 401, err.Error())
		return
	}
	// Endpoint origin and any pinned IP are checked before acquiring locks.
	// Unpinned domain IPs rely on authenticated Agents' address-policy validation;
	// the first IP binding is then fixed for this execution/origin below.
	var payload []byte
	err = s.db.QueryRow(r.Context(), `SELECT payload FROM tasks WHERE id=$1 AND type IN('http','poc') AND worker_id=$2 AND session_id=$3 AND attempt_no=$4 AND state='leased' AND lease_until>clock_timestamp()`, r.PathValue("id"), req.WorkerID, req.SessionID, req.AttemptNo).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 409, "HTTP execution is stale")
		return
	}
	if err != nil {
		writeError(w, 503, "load HTTP execution failed")
		return
	}
	if !httpPermitEndpoint(payload, req, ip) {
		writeError(w, 400, "connect IP, host and port do not match an authorized task endpoint")
		return
	}
	out, status, err := s.admitHTTP(r.Context(), r.PathValue("id"), req, seq)
	if err != nil {
		if status < 400 {
			status = http.StatusServiceUnavailable
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func httpPermitEndpoint(payload []byte, req httpPermitRequest, ip netip.Addr) bool {
	var p struct {
		Endpoints []taskEndpoint `json:"endpoints"`
		Endpoint  *taskEndpoint  `json:"endpoint"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return false
	}
	if p.Endpoint != nil {
		p.Endpoints = append(p.Endpoints, *p.Endpoint)
	}
	for _, ep := range p.Endpoints {
		base, err := endpointBaseURL(ep)
		if err != nil || canonicalTarget(base.Hostname()) != req.Host || urlPortNumber(base) != req.Port {
			continue
		}
		if ep.IP != "" {
			assigned, err := netip.ParseAddr(ep.IP)
			if err == nil && assigned.Unmap() == ip {
				return true
			}
			continue
		}
		if assigned, err := netip.ParseAddr(base.Hostname()); err == nil {
			if assigned.Unmap() == ip {
				return true
			}
			continue
		}
		// Cooperative authenticated Agent owns DNS and validates the address.
		return true
	}
	return false
}

func (s *Server) admitHTTP(ctx context.Context, taskID string, req httpPermitRequest, seq int64) (httpPermitResponse, int, error) {
	out := httpPermitResponse{RateRPS: httpBudgetRPS, ClusterRPS: httpClusterRPS, Burst: 1}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return out, 503, errors.New("HTTP admission unavailable")
	}
	defer tx.Rollback(ctx)
	// Match cancellation/renewal's run-before-task lock order. Otherwise a
	// cancellation holding the run row could deadlock a reader holding the task.
	var runID string
	err = tx.QueryRow(ctx, `SELECT r.id FROM runs r WHERE r.id=(SELECT run_id FROM tasks WHERE id=$1) FOR SHARE`, taskID).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, 409, errors.New("HTTP execution is stale")
	}
	if err != nil {
		return out, 503, errors.New("lock HTTP run failed")
	}
	var token []byte
	var lease, rate time.Time
	// Share locks serialize with task completion/cancel, run pause/cancel and worker
	// registration. Revalidate the token inside this transaction to fence rotation.
	err = tx.QueryRow(ctx, `SELECT w.token_hash,t.lease_until,t.rate_until FROM tasks t JOIN runs r ON r.id=t.run_id JOIN workers w ON w.id=t.worker_id
 WHERE t.id=$1 AND t.worker_id=$2 AND t.session_id=$3 AND w.session_id=$3 AND t.attempt_no=$4
 AND t.type IN('http','poc') AND t.state='leased' AND t.lease_until>clock_timestamp() AND t.rate_until>clock_timestamp()
 AND r.status IN('pending','running') AND w.status IN('ready','running','draining')
 AND EXISTS(SELECT 1 FROM worker_pool WHERE enabled)
 AND EXISTS(SELECT 1 FROM target_quotas q WHERE q.task_id=t.id AND q.attempt_no=t.attempt_no AND q.worker_id=w.id AND q.session_id=t.session_id AND q.dimension='web_jobs' AND q.state='active' AND q.valid_until>clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM target_quotas q WHERE q.task_id=t.id AND q.attempt_no=t.attempt_no AND q.worker_id=w.id AND q.session_id=t.session_id AND q.state IN('suspect','revoking'))
 FOR UPDATE OF t FOR SHARE OF r,w`, taskID, req.WorkerID, req.SessionID, req.AttemptNo).Scan(&token, &lease, &rate)
	hash, ok := ctx.Value(workerTokenKey{}).([32]byte)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!ok || subtle.ConstantTimeCompare(token, hash[:]) != 1) {
		return out, 409, errors.New("HTTP execution is stale or stopped")
	}
	if err != nil {
		return out, 503, errors.New("check HTTP execution failed")
	}
	// Lock the occupied allocations as well: unknown-stop freezes must fence
	// admission, and a quota may expire while awaiting the shared IP lock.
	rows, quotaErr := tx.Query(ctx, `SELECT state,valid_until FROM target_quotas WHERE task_id=$1 AND attempt_no=$2 AND worker_id=$3 AND session_id=$4 AND dimension='web_jobs' AND state<>'released' FOR SHARE`, taskID, req.AttemptNo, req.WorkerID, req.SessionID)
	if quotaErr != nil {
		return out, 503, errors.New("lock HTTP quota failed")
	}
	quotaCount := 0
	for rows.Next() {
		var state string
		var until time.Time
		if err = rows.Scan(&state, &until); err != nil {
			rows.Close()
			return out, 503, err
		}
		if state != "active" {
			rows.Close()
			return out, 409, errors.New("HTTP quota is frozen")
		}
		if until.Before(rate) {
			rate = until
		}
		quotaCount++
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return out, 503, err
	}
	if quotaCount == 0 {
		return out, 409, errors.New("HTTP quota is unavailable")
	}
	// Different IP requests within one task still share one monotonic ID stream.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1935894901,hashtext($1))`, taskID); err != nil {
		return out, 503, errors.New("lock HTTP execution failed")
	}
	// One binding per task endpoint; a changed DNS answer cannot distribute an
	// execution over arbitrarily many fresh IP buckets. A new execution may bind.
	bound, bindErr := tx.Exec(ctx, `INSERT INTO http_endpoint_bindings(task_id,host,port,attempt_no,worker_id,session_id,connect_ip) VALUES($1,$2,$3,$4,$5,$6,$7)
 ON CONFLICT(task_id,host,port) DO UPDATE SET attempt_no=EXCLUDED.attempt_no,worker_id=EXCLUDED.worker_id,session_id=EXCLUDED.session_id,connect_ip=EXCLUDED.connect_ip
 WHERE http_endpoint_bindings.attempt_no<>EXCLUDED.attempt_no OR http_endpoint_bindings.worker_id<>EXCLUDED.worker_id OR http_endpoint_bindings.session_id<>EXCLUDED.session_id OR http_endpoint_bindings.connect_ip=EXCLUDED.connect_ip`, taskID, req.Host, req.Port, req.AttemptNo, req.WorkerID, req.SessionID, req.ConnectIP)
	if bindErr != nil {
		return out, 503, errors.New("bind HTTP endpoint failed")
	}
	if bound.RowsAffected() != 1 {
		return out, 409, errors.New("HTTP endpoint connect IP changed within this execution")
	}
	var old httpPermitRequest
	var oldSeq int64
	var grantedAt, validUntil time.Time
	err = tx.QueryRow(ctx, `SELECT attempt_no,worker_id,session_id,request_seq,host(connect_ip),host,port,granted_at,valid_until FROM http_permit_receipts WHERE task_id=$1`, taskID).Scan(&old.AttemptNo, &old.WorkerID, &old.SessionID, &oldSeq, &old.ConnectIP, &old.Host, &old.Port, &grantedAt, &validUntil)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, 503, errors.New("read HTTP receipt failed")
	}
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&out.ServerTime); err != nil {
		return out, 503, err
	}
	if !lease.After(out.ServerTime) || !rate.After(out.ServerTime) {
		return out, 409, errors.New("HTTP execution expired while awaiting admission")
	}
	if old.AttemptNo == req.AttemptNo && old.WorkerID == req.WorkerID && old.SessionID == req.SessionID && seq <= oldSeq {
		if seq != oldSeq || old.ConnectIP != req.ConnectIP || old.Host != req.Host || old.Port != req.Port || !validUntil.After(out.ServerTime) || validUntil.After(lease) || validUntil.After(rate) {
			return out, 409, errors.New("HTTP request_id is superseded, changed or expired")
		}
		out.Granted = true
		out.ValidUntil = validUntil
		return out, 200, tx.Commit(ctx)
	}
	var full fullHTTPPayload
	var taskPayload []byte
	if err = tx.QueryRow(ctx, `SELECT payload FROM tasks WHERE id=$1`, taskID).Scan(&taskPayload); err != nil {
		return out, 503, err
	}
	if json.Unmarshal(taskPayload, &full) != nil {
		return out, 503, errors.New("invalid HTTP payload")
	}
	var browser webevidence.BrowserAssignment
	_ = json.Unmarshal(taskPayload, &browser)
	if browser.Phase == "browser" && (browser.BrowserRequestsUsed >= 32 || browser.BrowserDeadline.IsZero() || !browser.BrowserDeadline.After(out.ServerTime)) {
		return out, 409, errors.New("browser cumulative budget or deadline exhausted")
	}
	if full.Profile == webevidence.FullProfile {
		if full.Progress != nil && req.Segment > full.Progress.ReservedSegment {
			reserveHTTPFullSegment(full.Progress, req.Segment)
		}
		if full.Progress == nil || full.Progress.RequestsUsed >= full.Progress.MaxRequests || full.Progress.SegmentRequestLimit <= 0 || full.Progress.SegmentRequestsUsed >= full.Progress.SegmentRequestLimit || !full.Progress.Deadline.After(out.ServerTime) || req.Segment < 1 || req.Segment > full.Progress.MaxSegments || req.Segment < full.Progress.Segment {
			return out, 409, errors.New("full HTTP cumulative budget, deadline or segment exhausted")
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO http_ip_budgets(connect_ip,next_at) VALUES($1,'epoch') ON CONFLICT DO NOTHING`, req.ConnectIP); err != nil {
		return out, 503, err
	}
	var next time.Time
	if err = tx.QueryRow(ctx, `SELECT next_at FROM http_ip_budgets WHERE connect_ip=$1 FOR UPDATE`, req.ConnectIP).Scan(&next); err != nil {
		return out, 503, err
	}
	var clusterNext time.Time
	if err = tx.QueryRow(ctx, `SELECT next_at FROM http_cluster_budget WHERE singleton FOR UPDATE`).Scan(&clusterNext); err != nil {
		return out, 503, err
	}
	if clusterNext.After(next) {
		next = clusterNext
	}
	// Refresh DB time after a potentially contended lock. Never sleep in a tx.
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&out.ServerTime); err != nil {
		return out, 503, err
	}
	if next.After(out.ServerTime) {
		out.RetryAfterMS = max(int64(1), (next.Sub(out.ServerTime).Microseconds()+999)/1000)
		return out, 200, tx.Commit(ctx)
	}
	if !lease.After(out.ServerTime) || !rate.After(out.ServerTime) {
		return out, 409, errors.New("HTTP execution expired while awaiting admission")
	}
	if full.Profile == webevidence.FullProfile {
		full.Progress.RequestsUsed++
		full.Progress.SegmentRequestsUsed++
		full.Progress.Segment = max(full.Progress.Segment, req.Segment)
		progress, _ := json.Marshal(full.Progress)
		if _, err = tx.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{http_progress}',$2::jsonb) WHERE id=$1`, taskID, progress); err != nil {
			return out, 503, err
		}
	}
	if browser.Phase == "browser" {
		browser.BrowserRequestsUsed++
		if _, err = tx.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{browser_requests_used}',to_jsonb($2::int)) WHERE id=$1`, taskID, browser.BrowserRequestsUsed); err != nil {
			return out, 503, err
		}
	}
	out.Granted = true
	out.ValidUntil = out.ServerTime.Add(httpPermitLifetime)
	if lease.Before(out.ValidUntil) {
		out.ValidUntil = lease
	}
	if rate.Before(out.ValidUntil) {
		out.ValidUntil = rate
	}
	if _, err = tx.Exec(ctx, `UPDATE http_ip_budgets SET next_at=$2 WHERE connect_ip=$1`, req.ConnectIP, out.ServerTime.Add(time.Second/httpBudgetRPS)); err != nil {
		return out, 503, err
	}
	if _, err = tx.Exec(ctx, `UPDATE http_cluster_budget SET next_at=$1 WHERE singleton`, out.ServerTime.Add(time.Second/httpClusterRPS)); err != nil {
		return out, 503, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO http_permit_receipts(task_id,attempt_no,worker_id,session_id,request_seq,connect_ip,host,port,granted_at,valid_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
 ON CONFLICT(task_id) DO UPDATE SET attempt_no=EXCLUDED.attempt_no,worker_id=EXCLUDED.worker_id,session_id=EXCLUDED.session_id,request_seq=EXCLUDED.request_seq,connect_ip=EXCLUDED.connect_ip,host=EXCLUDED.host,port=EXCLUDED.port,granted_at=EXCLUDED.granted_at,valid_until=EXCLUDED.valid_until`, taskID, req.AttemptNo, req.WorkerID, req.SessionID, seq, req.ConnectIP, req.Host, req.Port, out.ServerTime, out.ValidUntil)
	if err != nil {
		return out, 503, err
	}
	// Bounded opportunistic pruning, at most 32 cold IPs per successful admission.
	_, err = tx.Exec(ctx, `DELETE FROM http_ip_budgets WHERE connect_ip IN(SELECT connect_ip FROM http_ip_budgets WHERE next_at<clock_timestamp()-interval '1 hour' ORDER BY next_at LIMIT 32 FOR UPDATE SKIP LOCKED)`)
	if err != nil {
		return out, 503, err
	}
	return out, 200, tx.Commit(ctx)
}

// HTTPBudgetStatus is the read-only HTTP admission section of scheduler status.
func (s *Server) HTTPBudgetStatus(ctx context.Context) (map[string]any, error) {
	var activeIPs, receipts int64
	err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM http_ip_budgets WHERE next_at>clock_timestamp()-interval '1 minute'),(SELECT count(*) FROM http_permit_receipts WHERE valid_until>clock_timestamp())`).Scan(&activeIPs, &receipts)
	return map[string]any{"per_connect_ip_rps": httpBudgetRPS, "cluster_rps": httpClusterRPS, "admission_burst": 1, "permit_lifetime_ms": httpPermitLifetime.Milliseconds(), "active_connect_ips": activeIPs, "unexpired_permit_receipts": receipts, "enforcement": "cooperative_request_admission"}, err
}
