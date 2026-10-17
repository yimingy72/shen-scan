package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// WorkerQuotaRecovery is an immutable execution identity, not a live-heartbeat claim.
// Cloud callers must verify the instance is stopped/deleted before confirming it.
type WorkerQuotaRecovery struct {
	WorkerID       string
	InstanceID     string
	SessionID      string
	TaskID         string
	AttemptNo      int
	Epoch          string
	State          string
	SuspectSince   time.Time
	RevokeDeadline time.Time
}

// expireQuotas never recycles an active allocation on time alone.
func expireQuotas(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `UPDATE target_quotas SET state='suspect',suspect_since=COALESCE(suspect_since,now()),
 revoke_deadline=COALESCE(revoke_deadline,now()+interval '90 seconds')
 WHERE state='active' AND (valid_until<=now() OR EXISTS(SELECT 1 FROM workers w WHERE w.id=worker_id AND w.session_id<>target_quotas.session_id) OR EXISTS(SELECT 1 FROM tasks t WHERE t.id=task_id AND t.state IN('cancelled','failed')));
 UPDATE target_quotas SET state='released',stop_evidence='unactivated startup reservation expired',released_at=now()
 WHERE state='reserved' AND valid_until<=now();
 UPDATE tasks t SET error='blocked_quota_unknown',updated_at=now() WHERE t.state IN('queued','leased')
 AND EXISTS(SELECT 1 FROM target_quotas q WHERE q.task_id=t.id AND q.state IN('suspect','revoking') AND q.revoke_deadline<=now())
 AND t.error<>'blocked_quota_unknown'`)
	return err
}

func (s *Server) UnknownWorkerQuotas(ctx context.Context) ([]WorkerQuotaRecovery, error) {
	if err := s.reconcileExpiredWork(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = expireQuotas(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT worker_id,instance_id,session_id,task_id,attempt_no,epoch,state,suspect_since,revoke_deadline
 FROM target_quotas WHERE state IN('suspect','revoking') ORDER BY suspect_since,epoch`)
	if err != nil {
		return nil, err
	}
	out := []WorkerQuotaRecovery{}
	for rows.Next() {
		var v WorkerQuotaRecovery
		if err = rows.Scan(&v.WorkerID, &v.InstanceID, &v.SessionID, &v.TaskID, &v.AttemptNo, &v.Epoch, &v.State, &v.SuspectSince, &v.RevokeDeadline); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *Server) MarkWorkerQuotaRevoking(ctx context.Context, instanceID, sessionID string) error {
	_, err := s.db.Exec(ctx, `UPDATE target_quotas SET state='revoking' WHERE instance_id=$1 AND session_id=$2 AND state='suspect'`, instanceID, sessionID)
	return err
}

func (s *Server) ConfirmWorkerStopped(ctx context.Context, instanceID, sessionID, reason string) error {
	if instanceID == "" || sessionID == "" || reason == "" {
		return errors.New("exact instance/session and stop evidence are required")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Only this execution session is released. A later registration cannot inherit it.
	_, err = tx.Exec(ctx, `UPDATE target_quotas SET state='released',released_at=now(),stop_evidence=$3
 WHERE instance_id=$1 AND session_id=$2 AND state<>'released'`, instanceID, sessionID, reason)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE tasks t SET lease_until=LEAST(COALESCE(lease_until,now()),now()),rate_until=now()
 FROM workers w WHERE w.id=t.worker_id AND w.instance_id=$1 AND t.session_id=$2 AND t.state='leased'`, instanceID, sessionID)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type quotaNeed struct {
	scope, dimension string
	amount, limit    int
}

func taskQuotaNeeds(typeName string, payload []byte) ([]quotaNeed, error) {
	keys := taskTargetKeys(payload)
	if len(keys) == 0 {
		return nil, errors.New("task has no quota scope")
	}
	var p struct {
		Rate int `json:"rate_pps"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	dimension, amount, limit := "service_jobs", 1, 4
	switch typeName {
	case "port":
		dimension, amount, limit = "discovery_pps", p.Rate, portTargetQuota()
		if amount <= 0 {
			return nil, errors.New("invalid discovery rate")
		}
	case "http", "poc":
		dimension, amount, limit = "web_jobs", 1, 2
	}
	out := make([]quotaNeed, 0, len(keys))
	for _, key := range keys {
		out = append(out, quotaNeed{key, dimension, amount, limit})
	}
	return out, nil
}

func acquireTaskQuota(ctx context.Context, tx pgx.Tx, taskID string, attempt int, workerID, sessionID, typeName string, payload []byte, until time.Time) (bool, error) {
	needs, err := taskQuotaNeeds(typeName, payload)
	if err != nil {
		return false, err
	}
	// Keys are canonical and sorted by taskTargetKeys; all claimers share this order.
	for _, need := range needs {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1935894900,hashtext($1))`, need.scope); err != nil {
			return false, err
		}
		var held int
		if err = tx.QueryRow(ctx, `SELECT COALESCE(sum(amount),0) FROM target_quotas WHERE scope=$1 AND dimension=$2 AND state<>'released'
   AND NOT(task_id=$3 AND attempt_no=$4 AND worker_id=$5 AND session_id=$6 AND state='reserved')`, need.scope, need.dimension, taskID, attempt, workerID, sessionID).Scan(&held); err != nil {
			return false, err
		}
		if held+need.amount > need.limit {
			return false, nil
		}
	}
	for _, need := range needs {
		result, insertErr := tx.Exec(ctx, `INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until)
  SELECT $1,$2,$3,id,instance_id,$4,$5,$6,$7,'active',$8 FROM workers WHERE id=$9 AND session_id=$4
  ON CONFLICT(task_id,attempt_no,worker_id,session_id,scope,dimension) DO UPDATE SET epoch=EXCLUDED.epoch,state='active',valid_until=EXCLUDED.valid_until,stop_evidence='',released_at=NULL
  WHERE (target_quotas.state='reserved' OR (target_quotas.state='released' AND target_quotas.stop_evidence='unactivated startup reservation expired')) AND target_quotas.worker_id=EXCLUDED.worker_id AND target_quotas.session_id=EXCLUDED.session_id`,
			newID(), taskID, attempt, sessionID, need.scope, need.dimension, need.amount, until, workerID)
		if insertErr != nil {
			return false, insertErr
		}
		if result.RowsAffected() != 1 {
			return false, errors.New("quota epoch could not be activated")
		}
	}
	return true, nil
}

// Renew only the current execution's allocations. A prior worker's expired,
// unactivated reservation may share this attempt number and is only history.
func renewTaskQuota(ctx context.Context, tx pgx.Tx, taskID string, attempt int, workerID, sessionID, typeName string, payload []byte, until time.Time) (bool, error) {
	needs, err := taskQuotaNeeds(typeName, payload)
	if err != nil {
		return false, err
	}
	for _, need := range needs {
		var valid bool
		err = tx.QueryRow(ctx, `SELECT state='active' AND valid_until>now() AND amount=$7 FROM target_quotas
            WHERE task_id=$1 AND attempt_no=$2 AND worker_id=$3 AND session_id=$4 AND scope=$5 AND dimension=$6 FOR UPDATE`,
			taskID, attempt, workerID, sessionID, need.scope, need.dimension, need.amount).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !valid) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE target_quotas SET valid_until=$5 WHERE task_id=$1 AND attempt_no=$2 AND worker_id=$3 AND session_id=$4 AND state='active'`, taskID, attempt, workerID, sessionID, until)
	return err == nil, err
}

func finishTaskQuota(ctx context.Context, tx pgx.Tx, taskID string, attempt int, workerID, sessionID string, stopped bool, reason string) error {
	if stopped {
		_, err := tx.Exec(ctx, `UPDATE target_quotas SET state='released',released_at=now(),stop_evidence=$3
  WHERE task_id=$1 AND attempt_no=$2 AND worker_id=$4 AND session_id=$5 AND state<>'released'`, taskID, attempt, reason, workerID, sessionID)
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE target_quotas SET state='suspect',suspect_since=COALESCE(suspect_since,now()),
 revoke_deadline=COALESCE(revoke_deadline,now()+interval '90 seconds'),stop_evidence=$3 WHERE task_id=$1 AND attempt_no=$2 AND worker_id=$4 AND session_id=$5 AND state IN('active','reserved')`, taskID, attempt, fmt.Sprintf("unconfirmed stop: %s", reason), workerID, sessionID)
	return err
}

// PendingStopInstances is the instance-oriented convenience API for the existing
// cloud reconciler. It contains only allocations with unknown stop state.
func (s *Server) PendingStopInstances(ctx context.Context) ([]string, error) {
	records, err := s.UnknownWorkerQuotas(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, record := range records {
		if !seen[record.InstanceID] {
			seen[record.InstanceID] = true
			ids = append(ids, record.InstanceID)
		}
	}
	return ids, nil
}

// ConfirmInstanceStopped requires actual stopped/deleted evidence, not an
// accepted cloud stop request. It snapshots old session identities first.
func (s *Server) ConfirmInstanceStopped(ctx context.Context, instanceID, evidence string) error {
	if instanceID == "" || evidence == "" {
		return errors.New("instance and stop evidence are required")
	}
	rows, err := s.db.Query(ctx, `SELECT DISTINCT session_id FROM target_quotas WHERE instance_id=$1 AND state<>'released'`, instanceID)
	if err != nil {
		return err
	}
	sessions := []string{}
	for rows.Next() {
		var session string
		if err = rows.Scan(&session); err != nil {
			rows.Close()
			return err
		}
		sessions = append(sessions, session)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, session := range sessions {
		if err = s.ConfirmWorkerStopped(ctx, instanceID, session, evidence); err != nil {
			return err
		}
	}
	return nil
}
