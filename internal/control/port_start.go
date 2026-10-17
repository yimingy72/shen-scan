package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func portTargetQuota() int {
	// A higher cluster target allowance is explicit; worker count never raises it.
	rate, _ := portScanSettings()
	if value, err := strconv.Atoi(os.Getenv("SCAN_TARGET_DISCOVERY_PPS")); err == nil && value >= 1000 && value <= 200000 {
		return value
	}
	return rate
}

func calibratedPortProfile() (string, float64) {
	profile := strings.TrimSpace(os.Getenv("SCAN_CALIBRATED_PORT_PROFILE"))
	rate, err := strconv.ParseFloat(os.Getenv("SCAN_CALIBRATED_SYN_RATE"), 64)
	configured, _ := portScanSettings()
	baselinePPS, _ := strconv.Atoi(os.Getenv("SCAN_CALIBRATED_PPS"))
	if profile == "" || err != nil || math.IsNaN(rate) || math.IsInf(rate, 0) || rate <= 0 || baselinePPS != configured {
		return "", 0
	}
	return profile, rate
}

func choosePortPartitions(ports, slots int, rate, totalRate, wait, collect float64) int {
	if ports < 1 || slots < 2 || rate <= 0 || totalRate <= 0 {
		return 1
	}
	maxK := min(slots, max(1, ports/4096))
	predict := func(k int) float64 {
		overhead := collect
		if k == 1 {
			overhead = 0
		}
		return overhead + wait + float64(ports)/min(totalRate, float64(k)*rate)
	}
	t1 := predict(1)
	threshold := max(2, .15*t1)
	best := math.Inf(1)
	for k := 2; k <= maxK; k++ {
		if tk := predict(k); t1-tk >= threshold {
			best = min(best, tk)
		}
	}
	if math.IsInf(best, 1) {
		return 1
	}
	for k := 2; k <= maxK; k++ {
		tk := predict(k)
		if t1-tk >= threshold && tk <= best+max(2, .1*best) {
			return k
		}
	}
	return 1
}

// preparePortStart uses the in-flight claim as a short local-slot reservation.
// The Agent opts in only while it holds that slot until the claim returns.
// A heartbeat is never a start reservation, and no calibration means no split.
func (s *Server) preparePortStart(ctx context.Context, workerID, sessionID, requestID string) error {
	rate, _ := portScanSettings()
	limit := portTargetQuota()
	if limit/rate < 2 {
		return nil
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1,hashtext($2))`, workerClaimLockNamespace, workerID); err != nil {
		return err
	}
	var actualProfile string
	err = tx.QueryRow(ctx, `SELECT COALESCE(spec->>'port_profile','') FROM workers WHERE id=$1 AND session_id=$2 AND status IN('ready','running') AND NOT maintenance`, workerID, sessionID).Scan(&actualProfile)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if actualProfile == "" {
		return nil
	}
	if _, trustworthy, modelErr := loadPortCost(ctx, tx, workerID, sessionID, actualProfile, rate); modelErr != nil {
		return modelErr
	} else if !trustworthy {
		return nil
	}
	if err = expireQuotas(ctx, tx); err != nil {
		return err
	}
	var occupied bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM target_quotas WHERE worker_id=$1 AND state<>'released')`, workerID).Scan(&occupied); err != nil {
		return err
	}
	if occupied {
		return nil
	}
	var taskID, runID, target string
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT t.id,t.run_id,t.target_key,t.payload FROM tasks t JOIN runs r ON r.id=t.run_id
 WHERE r.status IN('pending','running') AND t.type='port' AND t.state='queued' AND t.attempt_no=0
 AND jsonb_array_length(t.payload->'targets')=1 AND t.payload->>'ports'='1-65535'
 AND COALESCE(t.payload->>'range_planned','false')<>'true'
 ORDER BY r.last_claim_at,r.created_at,t.created_at,t.id FOR UPDATE OF r,t LIMIT 1`).Scan(&taskID, &runID, &target, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1935894900,hashtext($1))`, target); err != nil {
		return err
	}
	var held int
	if err = tx.QueryRow(ctx, `SELECT COALESCE(sum(amount),0) FROM target_quotas WHERE scope=$1 AND dimension='discovery_pps' AND state<>'released'`, target).Scan(&held); err != nil {
		return err
	}
	if held+rate > limit {
		return nil
	}
	now := utcNow()
	collectUntil := now.Add(time.Second)
	expires := now.Add(4 * time.Second)
	if err = tx.QueryRow(ctx, `SELECT COALESCE(min(collect_until),$2) FROM port_start_tickets WHERE root_task_id=$1 AND expires_at>now()`, taskID, collectUntil).Scan(&collectUntil); err != nil {
		return err
	}
	if !collectUntil.After(now) {
		return nil
	}
	expires = collectUntil.Add(3 * time.Second)
	if _, err = tx.Exec(ctx, `INSERT INTO port_start_tickets(worker_id,session_id,request_id,root_task_id,profile,collect_until,expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, workerID, sessionID, requestID, taskID, actualProfile, collectUntil, expires); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until)
 SELECT $1,$2,0,id,instance_id,$3,$4,'discovery_pps',$5,'reserved',$6 FROM workers WHERE id=$7`, newID(), taskID, sessionID, target, rate, expires, workerID); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(collectUntil))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	return s.sealPortStart(ctx, taskID, runID, rate, limit)
}

func (s *Server) sealPortStart(ctx context.Context, rootID, runID string, rate, limit int) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var runState string
	if err = tx.QueryRow(ctx, `SELECT status FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&runState); err != nil {
		return err
	}
	if runState != "pending" && runState != "running" {
		return nil
	}
	var payload []byte
	var state string
	var attempt int
	if err = tx.QueryRow(ctx, `SELECT payload,state,attempt_no FROM tasks WHERE id=$1 FOR UPDATE`, rootID).Scan(&payload, &state, &attempt); err != nil {
		return err
	}
	var p map[string]any
	if err = json.Unmarshal(payload, &p); err != nil {
		return err
	}
	if state != "queued" || attempt != 0 || p["range_planned"] == true {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT p.worker_id,p.session_id,p.request_id,p.profile FROM port_start_tickets p JOIN workers w ON w.id=p.worker_id AND w.session_id=p.session_id
 WHERE p.root_task_id=$1 AND p.profile=COALESCE(w.spec->>'port_profile','') AND p.expires_at>now() AND w.status IN('ready','running') AND NOT w.maintenance
 AND EXISTS(SELECT 1 FROM target_quotas q WHERE q.task_id=p.root_task_id AND q.worker_id=p.worker_id AND q.session_id=p.session_id AND q.state='reserved' AND q.dimension='discovery_pps' AND q.amount=$2 AND q.valid_until>now())
 ORDER BY p.worker_id FOR SHARE OF w`, rootID, rate)
	if err != nil {
		return err
	}
	type ticket struct{ worker, session, request, profile string }
	tickets := []ticket{}
	for rows.Next() {
		var v ticket
		if err = rows.Scan(&v.worker, &v.session, &v.request, &v.profile); err != nil {
			rows.Close()
			return err
		}
		tickets = append(tickets, v)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if len(tickets) == 0 {
		return nil
	}
	candidates := make([]portStartCandidate, 0, len(tickets))
	for _, ticket := range tickets {
		model, trustworthy, modelErr := loadPortCost(ctx, tx, ticket.worker, ticket.session, ticket.profile, rate)
		if modelErr != nil {
			return modelErr
		}
		if trustworthy {
			candidates = append(candidates, portStartCandidate{ticket.worker, ticket.session, ticket.request, model})
		}
	}
	slices := planPortStart(65535, candidates, rate, limit, 1)
	if len(slices) == 0 {
		return nil
	}
	k := len(slices)
	// Collection is bounded. Only tickets actually acquired participate in k.
	p["range_planned"] = true
	p["partition_count"] = k
	p["partition_reason"] = "calibrated_start_reservations"
	for _, slice := range slices {
		if slice.candidate.model.Samples > 0 {
			p["partition_reason"] = "observed_weighted_start_reservations"
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM port_range_manifest WHERE task_id=$1`, rootID); err != nil {
		return err
	}
	// Reserved PPS allocations were never execution permission. Replace them with
	// selected task allocations atomically with the complete range manifest.
	if _, err = tx.Exec(ctx, `UPDATE target_quotas SET state='released',released_at=now(),stop_evidence='unactivated reservation replaced by sealed manifest' WHERE task_id=$1 AND state='reserved'`, rootID); err != nil {
		return err
	}
	until := utcNow().Add(2 * time.Second)
	for i := 0; i < k; i++ {
		id := rootID
		if i > 0 {
			id = newID()
		}
		slice := slices[i]
		p["ports"] = fmt.Sprintf("%d-%d", slice.first, slice.last)
		p["partition_cost"] = slice.candidate.model
		t := slice.candidate
		raw, _ := json.Marshal(p)
		if i == 0 {
			_, err = tx.Exec(ctx, `UPDATE tasks SET payload=$2,worker_id=$3,session_id=$4,reserved_until=$5 WHERE id=$1`, id, raw, t.worker, t.session, until)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key,worker_id,session_id,reserved_until)
   SELECT $1,run_id,'port',$2,$3,target_key,$4,$5,$6 FROM tasks WHERE id=$7`, id, raw, fmt.Sprintf("range:%s:%d", rootID, i), t.worker, t.session, until, rootID)
			if err == nil {
				err = insertTaskTargets(ctx, tx, id, raw)
			}
		}
		if err != nil {
			return err
		}
		if err = insertPortManifest(ctx, tx, id, runID, raw); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE port_start_tickets SET task_id=$4 WHERE worker_id=$1 AND session_id=$2 AND request_id=$3`, t.worker, t.session, t.request, id); err != nil {
			return err
		}
		// attempt 1 is reserved only; claim atomically activates it after scope checks.
		if _, err = tx.Exec(ctx, `INSERT INTO target_quotas(epoch,task_id,attempt_no,worker_id,instance_id,session_id,scope,dimension,amount,state,valid_until)
   SELECT $1,$2,1,id,instance_id,$3,$4,'discovery_pps',$5,'reserved',$6 FROM workers WHERE id=$7`, newID(), id, t.session, payloadTarget(raw), rate, until, t.worker); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM port_start_tickets WHERE root_task_id=$1 AND task_id IS NULL`, rootID); err != nil {
		return err
	}
	if err = validatePortManifest(ctx, tx, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
