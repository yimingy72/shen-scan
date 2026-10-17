package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"scanplatform/internal/rulelib"
	"strings"
)

const pocReceiptSchema = `
CREATE TABLE IF NOT EXISTS poc_template_receipts (
 task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 rule_id text NOT NULL,rule_revision integer NOT NULL,
 template_id text NOT NULL,content_sha256 text NOT NULL,
 source_attempt_no integer NOT NULL,batch_seq integer NOT NULL,batch_digest bytea NOT NULL,
 observation_id text NOT NULL UNIQUE REFERENCES assets(id) ON DELETE CASCADE,
 completion_id text NOT NULL UNIQUE,accepted_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(task_id,rule_id)
);
CREATE TABLE IF NOT EXISTS poc_batch_derived_keys (
 run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 derived_key text NOT NULL,owner_task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 PRIMARY KEY(run_id,derived_key)
);`

type pocBatchPayload struct {
	Endpoint taskEndpoint   `json:"endpoint"`
	Rules    []rulelib.Rule `json:"rules"`
	Profile  string         `json:"nuclei_batch_profile"`
}

func validPOCBatch(p pocBatchPayload) bool {
	if p.Profile != rulelib.NucleiSingleResponseBatchProfile || len(p.Rules) > rulelib.MaxNucleiBatchTemplates {
		return false
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !rulelib.NucleiBatchEligible(r) || seen[r.Nuclei.TemplateID] {
			return false
		}
		seen[r.Nuclei.TemplateID] = true
	}
	return true
}

func remainingPOCRules(ctx context.Context, tx pgx.Tx, taskID string, payload []byte) ([]byte, error) {
	var p pocBatchPayload
	if json.Unmarshal(payload, &p) != nil || p.Profile == "" {
		return payload, nil
	}
	if !validPOCBatch(p) {
		return nil, errors.New("invalid original Nuclei batch")
	}
	rows, err := tx.Query(ctx, `SELECT rule_id FROM poc_template_receipts WHERE task_id=$1`, taskID)
	if err != nil {
		return nil, err
	}
	accepted := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		accepted[id] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rules := make([]rulelib.Rule, 0, len(p.Rules))
	for _, rule := range p.Rules {
		if !accepted[rule.ID] {
			rules = append(rules, rule)
		}
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	raw["rules"], _ = json.Marshal(rules)
	return json.Marshal(raw)
}

// Called only inside submitBatch's current worker/session/attempt/lease fence,
// after exact template metadata and origin validation. Unknown/errors remain
// observations and never gain immutable acceptance or negative coverage.
func acceptPOCTemplates(ctx context.Context, tx pgx.Tx, taskID string, attempt, batch int, payload []byte) error {
	var p pocBatchPayload
	if json.Unmarshal(payload, &p) != nil || p.Profile == "" {
		return nil
	}
	if !validPOCBatch(p) {
		return errors.New("invalid original Nuclei batch")
	}
	_, err := tx.Exec(ctx, `INSERT INTO poc_template_receipts(task_id,rule_id,rule_revision,template_id,content_sha256,source_attempt_no,batch_seq,batch_digest,observation_id,completion_id)
 SELECT a.task_id,a.observation->>'rule_id',(a.observation->>'rule_revision')::int,a.observation->>'template_id',a.observation->>'content_sha256',a.attempt_no,a.batch_seq,b.content_hash,a.id,$4||':'||(a.observation->>'rule_id')
 FROM assets a JOIN task_batches b USING(task_id,attempt_no,batch_seq)
 WHERE a.task_id=$1 AND a.attempt_no=$2 AND a.batch_seq=$3
 AND a.observation->>'kind'='poc' AND a.observation->>'finding_status' IN('matched','not_matched')
 AND a.observation->>'engine_version'='3.11.1' AND a.observation->>'evidence_profile'='nuclei-3.11.1-single-http-response-v1'
 AND COALESCE(a.observation->>'error','')='' AND COALESCE((a.observation->>'truncated')::boolean,false)=false
 AND COALESCE(a.observation->>'request_raw','')<>'' AND COALESCE(a.observation->>'response_raw','')<>''
 AND (a.observation->>'finding_status'='matched' OR COALESCE((a.observation->>'can_prove_no_match')::boolean,false))
 ON CONFLICT(task_id,rule_id) DO NOTHING`, taskID, attempt, batch, newID())
	return err
}

func completePOCBatch(ctx context.Context, tx pgx.Tx, taskID string, attempt int, payload []byte) (string, string, error) {
	var p pocBatchPayload
	if json.Unmarshal(payload, &p) != nil || !validPOCBatch(p) {
		return "", "", errors.New("invalid PoC batch completion")
	}
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM jsonb_array_elements($3::jsonb->'rules') rule WHERE
 EXISTS(SELECT 1 FROM poc_template_receipts r WHERE r.task_id=$1 AND r.rule_id=rule->>'id') OR
 EXISTS(SELECT 1 FROM assets a WHERE a.task_id=$1 AND a.attempt_no=$2 AND a.observation->>'rule_id'=rule->>'id')`, taskID, attempt, payload).Scan(&count)
	if err != nil {
		return "", "", err
	}
	if count != len(p.Rules) {
		return "", "", errors.New("PoC batch requires an explicit outcome for every unaccepted template")
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM poc_template_receipts WHERE task_id=$1`, taskID).Scan(&count); err != nil {
		return "", "", err
	}
	if count == len(p.Rules) {
		return "processed", "complete", nil
	}
	return "incomplete", "partial", nil
}

// Group only tasks just derived under the current run lock. Keep each original
// task/derived key as a durable duplicate guard, mapping it to the batch owner.
func groupDerivedPOCBatches(ctx context.Context, tx pgx.Tx, runID string) error {
	rows, err := tx.Query(ctx, `SELECT id,payload,target_key FROM tasks WHERE run_id=$1 AND type='poc' AND state='queued' AND attempt_no=0 AND COALESCE(payload->>'nuclei_batch_profile','')='' ORDER BY derived_key,id FOR UPDATE`, runID)
	if err != nil {
		return err
	}
	type item struct {
		id, target string
		p          pocBatchPayload
		raw        map[string]json.RawMessage
	}
	groups := map[string][]item{}
	for rows.Next() {
		var v item
		var payload []byte
		if err = rows.Scan(&v.id, &payload, &v.target); err != nil {
			rows.Close()
			return err
		}
		if json.Unmarshal(payload, &v.p) != nil || len(v.p.Rules) != 1 || !rulelib.NucleiBatchEligible(v.p.Rules[0]) {
			continue
		}
		_ = json.Unmarshal(payload, &v.raw)
		ep, _ := json.Marshal(v.p.Endpoint)
		key := v.target + "\x00" + string(ep)
		groups[key] = append(groups[key], v)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, items := range groups {
		for len(items) > 0 {
			batch := items[:1]
			used := map[string]bool{items[0].p.Rules[0].Nuclei.TemplateID: true}
			remaining := items[1:]
			rest := make([]item, 0, len(remaining))
			for _, v := range remaining {
				if len(batch) < rulelib.MaxNucleiBatchTemplates && !used[v.p.Rules[0].Nuclei.TemplateID] {
					batch = append(batch, v)
					used[v.p.Rules[0].Nuclei.TemplateID] = true
				} else {
					rest = append(rest, v)
				}
			}
			items = rest
			if len(batch) < 2 {
				continue
			}
			owner := batch[0]
			rules := make([]rulelib.Rule, 0, len(batch))
			for _, v := range batch {
				rules = append(rules, v.p.Rules[0])
			}
			triggers := map[string]map[string]json.RawMessage{}
			for _, v := range batch {
				triggers[v.p.Rules[0].ID] = map[string]json.RawMessage{"matched_products": v.raw["matched_products"], "trigger_reason": v.raw["trigger_reason"]}
			}
			owner.raw["rule_triggers"], _ = json.Marshal(triggers)
			owner.raw["rules"], _ = json.Marshal(rules)
			owner.raw["nuclei_batch_profile"], _ = json.Marshal(rulelib.NucleiSingleResponseBatchProfile)
			payload, _ := json.Marshal(owner.raw)
			if _, err = tx.Exec(ctx, `UPDATE tasks SET payload=$2 WHERE id=$1`, owner.id, payload); err != nil {
				return err
			}
			for _, v := range batch[1:] {
				// Alias rows are not executable logical work; keep their deduplication keys
				// in a dedicated table before removing them from scheduling/counts.
				if _, err = tx.Exec(ctx, `INSERT INTO poc_batch_derived_keys(run_id,derived_key,owner_task_id) SELECT run_id,derived_key,$2 FROM tasks WHERE id=$1 ON CONFLICT DO NOTHING`, v.id, owner.id); err != nil {
					return err
				}
				if _, err = tx.Exec(ctx, `DELETE FROM tasks WHERE id=$1`, v.id); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// The single-response profile needs the complete declared HTTP body, not just
// nonempty strings or a matcher-status boolean supplied by the worker.
func completePOCBatchEvidence(endpoint taskEndpoint, rule rulelib.Rule, item *Observation) bool {
	base, err := endpointBaseURL(endpoint)
	if err != nil {
		return false
	}
	analysis, err := rulelib.AnalyzeNucleiOriginal([]byte(rule.Template))
	if err != nil {
		return false
	}
	base.Path = strings.TrimRight(base.Path, "/")
	requests, err := rulelib.ResolveNucleiOriginalRequests(analysis.Plan, base)
	if err != nil || len(requests) != 1 {
		return false
	}
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(item.RequestRaw)))
	if err != nil {
		return false
	}
	defer request.Body.Close()
	if request.Method != requests[0].Method || request.URL.EscapedPath() != requests[0].Path || request.URL.RawQuery != "" || request.URL.IsAbs() && origin(request.URL) != origin(base) {
		return false
	}
	host, err := http.NewRequest("GET", base.Scheme+"://"+request.Host, nil)
	if err != nil || origin(host.URL) != origin(base) {
		return false
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(item.ResponseRaw)), request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (192<<10)+1))
	return err == nil && len(body) < 192<<10 && response.StatusCode >= 100
}

func sealPOCBatchReceipts(ctx context.Context, tx pgx.Tx, taskID string, payload []byte) error {
	var p pocBatchPayload
	if json.Unmarshal(payload, &p) != nil || p.Profile == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO task_item_completions(task_id,work_key,accepted_attempt_no,completion_id,outcome,coverage,observation_id)
 SELECT r.task_id,COALESCE(NULLIF(a.observation->>'work_key',''),'poc:'||(a.observation->>'url')||':'||r.rule_id),r.source_attempt_no,r.completion_id,a.observation->>'finding_status','complete',r.observation_id
 FROM poc_template_receipts r JOIN assets a ON a.id=r.observation_id WHERE r.task_id=$1 ON CONFLICT(task_id,work_key) DO NOTHING`, taskID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE tasks SET completion_manifest=completion_manifest||COALESCE((SELECT jsonb_agg(jsonb_build_object('template_completion_id',r.completion_id,'rule_id',r.rule_id,'template_id',r.template_id,'content_sha256',r.content_sha256,'source_attempt_no',r.source_attempt_no,'batch_seq',r.batch_seq,'batch_sha256',encode(r.batch_digest,'hex'),'observation_id',r.observation_id) ORDER BY r.rule_id) FROM poc_template_receipts r WHERE r.task_id=tasks.id),'[]'::jsonb) WHERE id=$1`, taskID)
	return err
}
