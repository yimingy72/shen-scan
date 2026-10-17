package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// A task is the stable work identity in P0; work is not repacked into another job.
// Web work is single-entry. Service batches require one explicit endpoint outcome
// for every item; a failed item never causes already-successful peers to retry.
func deriveServiceWebTasks(ctx context.Context, tx pgx.Tx, taskID, runID string, attempt int, payload []byte) error {
	var config struct {
		HTTPEnabled bool           `json:"http_enabled"`
		Endpoints   []taskEndpoint `json:"endpoints"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		return err
	}
	if !config.HTTPEnabled {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT observation FROM assets WHERE task_id=$1 AND attempt_no=$2 AND observation->>'kind'='service' ORDER BY batch_seq,item_index`, taskID, attempt)
	if err != nil {
		return err
	}
	var candidates []Observation
	for rows.Next() {
		var raw []byte
		var o Observation
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return err
		}
		if serviceNeedsWeb(o) {
			candidates = append(candidates, o)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, o := range candidates {
		ep := map[string]any{"ip": o.IP, "port": o.Port}
		// Preserve Nmap's protocol evidence, including TLS on nonstandard ports.
		// Unknown services retain the bounded same-port protocol confirmation.
		scheme := ""
		service, tunnel := strings.ToLower(o.Service), strings.ToLower(o.ServiceTunnel)
		if tunnel == "ssl" || tunnel == "tls" || service == "https" || service == "ssl/http" {
			scheme = "https"
		} else if service == "http" {
			scheme = "http"
		}
		if scheme != "" {
			ep["url"] = scheme + "://" + net.JoinHostPort(o.IP, strconv.Itoa(o.Port)) + "/"
		}
		if err = insertDerivedTask(ctx, tx, runID, taskID, "http", canonicalTarget(o.IP), o.Port, 8, []map[string]any{ep}); err != nil {
			return err
		}
	}
	return nil
}

func serviceNeedsWeb(o Observation) bool {
	if o.Error != "" || o.Outcome == "error" || o.Outcome == "incomplete" || o.Outcome == "skipped" || o.Outcome == "skipped_by_policy" {
		return false
	}
	// An explicit false is accepted only with strong protocol evidence; Nmap's
	// probed/conf=10 pair also occurs on soft matches and is not this evidence.
	if o.WebCandidate != nil && !*o.WebCandidate && o.ServiceConfidence == "protocol_confirmed" && o.Error == "" {
		return false
	}
	return true
}

func completeOutcome(ctx context.Context, tx pgx.Tx, taskID, typeName string, attempt int, payload []byte) (string, string, error) {
	if typeName == "port" {
		return "scanned", "complete", nil
	}
	rows, err := tx.Query(ctx, `SELECT observation FROM assets WHERE task_id=$1 AND attempt_no=$2 ORDER BY batch_seq,item_index`, taskID, attempt)
	if err != nil {
		return "", "", err
	}
	var observations []Observation
	for rows.Next() {
		var raw []byte
		var o Observation
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return "", "", err
		}
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return "", "", err
		}
		observations = append(observations, o)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return "", "", err
	}
	if len(observations) == 0 {
		return "", "", errors.New("completion requires an explicit endpoint outcome")
	}
	if typeName == "service" {
		var p struct {
			Endpoints []taskEndpoint `json:"endpoints"`
		}
		if err = json.Unmarshal(payload, &p); err != nil {
			return "", "", err
		}
		for _, ep := range p.Endpoints {
			found := false
			for _, o := range observations {
				if canonicalTarget(o.IP) == canonicalTarget(ep.IP) && o.Port == ep.Port {
					found = true
					break
				}
			}
			if !found {
				return "", "", fmt.Errorf("service endpoint %s:%d has no terminal outcome", ep.IP, ep.Port)
			}
		}
	}
	partial := false
	for _, o := range observations {
		if o.Error != "" || o.Outcome == "error" || o.Outcome == "incomplete" || o.Coverage == "partial" || o.Coverage == "unconfirmed" || o.Coverage == "incomplete" || o.Coverage == "missing" || o.FindingStatus == "incomplete" || o.FindingStatus == "unknown" {
			partial = true
		}
		if typeName == "poc" && o.FindingStatus == "not_matched" && !o.CanProveNoMatch {
			partial = true
		}
	}
	if partial {
		return "incomplete", "partial", nil
	}
	return "processed", "complete", nil
}

func parsePortInterval(raw string) (int, int, error) {
	parts := strings.Split(raw, "-")
	if len(parts) > 2 || len(parts) == 0 {
		return 0, 0, errors.New("ports must be one contiguous TCP interval")
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 1 || start > 65535 {
		return 0, 0, errors.New("invalid TCP interval start")
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.Atoi(parts[1])
		if err != nil || end < start || end > 65535 {
			return 0, 0, errors.New("invalid TCP interval end")
		}
	}
	return start, end, nil
}

func insertPortManifest(ctx context.Context, tx pgx.Tx, taskID, runID string, payload []byte) error {
	var p struct {
		Ports string `json:"ports"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	start, end, err := parsePortInterval(p.Ports)
	if err != nil {
		return err
	}
	for _, target := range taskTargetKeys(payload) {
		_, err = tx.Exec(ctx, `INSERT INTO port_range_manifest(run_id,target_key,port_start,port_end,task_id) VALUES($1,$2,$3,$4,$5)`, runID, target, start, end, taskID)
		if err != nil {
			return err
		}
	}
	return nil
}

func validatePortManifest(ctx context.Context, tx pgx.Tx, runID string) error {
	var invalid bool
	err := tx.QueryRow(ctx, `WITH ordered AS(SELECT target_key,port_start,port_end,lag(port_end) OVER(PARTITION BY target_key ORDER BY port_start) previous FROM port_range_manifest WHERE run_id=$1)
 SELECT EXISTS(SELECT 1 FROM ordered GROUP BY target_key HAVING min(port_start)<>1 OR max(port_end)<>65535 OR sum(port_end-port_start+1)<>65535 OR bool_or(previous IS NOT NULL AND previous+1<>port_start))`, runID).Scan(&invalid)
	if err != nil {
		return err
	}
	if invalid {
		return errors.New("port range manifest has gaps or overlaps")
	}
	return nil
}

// Bounds start only at the first executable lease, never while a large run is
// merely queued. Lock runs before tasks, matching completion/cancellation.
func (s *Server) reconcileExpiredWork(ctx context.Context) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT r.id FROM runs r WHERE r.status IN('pending','running','paused') AND EXISTS(
 SELECT 1 FROM tasks t WHERE t.run_id=r.id AND (t.state='queued' OR (t.state='leased' AND t.lease_until<=now()))
 AND t.first_started_at IS NOT NULL AND (t.attempt_no>=6 OR t.first_started_at<=now()-interval '30 minutes'))
 ORDER BY r.id FOR UPDATE OF r SKIP LOCKED LIMIT 100`)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		_, err = tx.Exec(ctx, `UPDATE tasks SET state='failed',coverage='partial',outcome='incomplete',error='execution recovery limit exhausted',updated_at=now()
    WHERE run_id=$1 AND (state='queued' OR(state='leased' AND lease_until<=now())) AND first_started_at IS NOT NULL
    AND (attempt_no>=6 OR first_started_at<=now()-interval '30 minutes')`, id)
		if err != nil {
			return err
		}
		if err = finalizeRun(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func sealCompletionEvidence(ctx context.Context, tx pgx.Tx, taskID, typeName string, attempt int, payload []byte) error {
	scope := sha256.Sum256(payload)
	if _, err := tx.Exec(ctx, `UPDATE tasks SET completion_scope_sha256=$2,completion_manifest=(
      SELECT COALESCE(jsonb_agg(jsonb_build_object('batch_seq',batch_seq,'sha256',encode(content_hash,'hex')) ORDER BY batch_seq),'[]'::jsonb)
      FROM task_batches WHERE task_id=$1 AND attempt_no=$3) WHERE id=$1 AND accepted_attempt_no=$3`, taskID, hex.EncodeToString(scope[:]), attempt); err != nil {
		return err
	}
	if typeName == "port" {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id,observation FROM assets WHERE task_id=$1 AND attempt_no=$2 ORDER BY batch_seq,item_index`, taskID, attempt)
	if err != nil {
		return err
	}
	type item struct {
		id          string
		observation Observation
	}
	items := map[string]item{}
	for rows.Next() {
		var id string
		var raw []byte
		var o Observation
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return err
		}
		key := o.WorkKey
		if key == "" {
			if typeName == "service" {
				key = fmt.Sprintf("service:%s:%d", canonicalTarget(o.IP), o.Port)
			} else {
				key = typeName + ":" + o.URL + ":" + o.RuleID
			}
		}
		items[key] = item{id, o}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for key, item := range items {
		o := item.observation
		outcome, coverage := o.Outcome, "complete"
		if outcome == "" {
			outcome = "processed"
			if o.Service != "" || o.StatusCode > 0 {
				outcome = "identified"
			}
			if o.FindingStatus != "" {
				outcome = o.FindingStatus
			}
		}
		if o.Error != "" || o.Coverage == "partial" || o.Coverage == "incomplete" || o.Coverage == "missing" || o.Coverage == "unconfirmed" || o.FindingStatus == "incomplete" || o.FindingStatus == "unknown" {
			coverage = "partial"
			if o.Error != "" {
				outcome = "error"
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO task_item_completions(task_id,work_key,accepted_attempt_no,completion_id,outcome,coverage,observation_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, taskID, key, attempt, newID(), outcome, coverage, item.id); err != nil {
			return err
		}
	}
	return nil
}
