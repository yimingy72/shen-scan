package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// payloadTarget remains the scheduling cursor; task_targets preserves every IP
// in a multi-target port shard and assets.target_key attributes each observation.
func payloadTarget(raw []byte) string {
	keys := taskTargetKeys(raw)
	if len(keys) > 0 {
		return keys[0]
	}
	return ""
}

func backfillTargetKeys(ctx context.Context, db *pgxpool.Pool) error {
	for {
		rows, err := db.Query(ctx, `SELECT id,payload FROM tasks WHERE target_key='' LIMIT 500`)
		if err != nil {
			return err
		}
		batch := &pgx.Batch{}
		for rows.Next() {
			var id string
			var raw []byte
			if err = rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return err
			}
			key := payloadTarget(raw)
			if key == "" {
				rows.Close()
				return errors.New("task has no source target")
			}
			batch.Queue(`UPDATE tasks SET target_key=$2 WHERE id=$1`, id, key)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		if batch.Len() == 0 {
			break
		}
		if err = db.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
	}
	// Historical versions created only single-target tasks. New tasks always insert
	// all target mappings in the same transaction, including every IP in a shard.
	if _, err := db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) SELECT id,target_key FROM tasks WHERE target_key<>'' ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `UPDATE assets a SET target_key=CASE WHEN a.observation->>'kind' IN('port','service') THEN COALESCE(NULLIF(a.observation->>'ip',''),NULLIF(a.observation->>'target',''),t.target_key) ELSE t.target_key END FROM tasks t WHERE t.id=a.task_id AND a.target_key=''`)
	return err
}

const currentResults = `WITH rt AS (SELECT t.id,t.type,t.state,t.attempt_no,t.updated_at,t.error,tt.target_key FROM tasks t JOIN task_targets tt ON tt.task_id=t.id WHERE t.run_id=$1),
 ob AS (SELECT a.id,a.task_id,a.observed_at,a.observation,a.target_key,t.payload task_payload FROM assets a JOIN tasks t
 ON t.id=a.task_id AND t.attempt_no=a.attempt_no WHERE a.run_id=$1)`

const targetResults = currentResults + `,
 ts AS (SELECT target_key AS target,count(*) task_total,count(*) FILTER(WHERE state='completed') task_done,
 count(*) FILTER(WHERE state='failed') task_failed,COALESCE(max(NULLIF(error,'')) FILTER(WHERE state='failed'),'') failure_reason,
 CASE WHEN bool_or(state='leased') THEN 'running' WHEN bool_or(state='queued') THEN 'pending'
 WHEN bool_or(state='failed') THEN 'failed' WHEN bool_or(state='cancelled') THEN 'cancelled' ELSE 'completed' END state,
 CASE WHEN count(*) FILTER(WHERE type='port')=0 THEN 'not_scanned'
 WHEN bool_or(state='leased' AND type='port') THEN 'running' WHEN bool_or(state='queued' AND type='port') THEN 'pending'
 WHEN bool_or(state='failed' AND type='port') THEN 'failed' WHEN bool_or(state='cancelled' AND type='port') THEN 'cancelled' ELSE 'completed' END port_state,
 max(updated_at) updated_at FROM rt GROUP BY target_key),
 os AS (SELECT target_key,
 count(DISTINCT (observation->>'port')::int) FILTER(WHERE observation->>'kind'='port' AND COALESCE(observation->>'error','')='') open_port_count,
 (array_agg(DISTINCT (observation->>'port')::int ORDER BY (observation->>'port')::int) FILTER(WHERE observation->>'kind'='port' AND COALESCE(observation->>'error','')=''))[1:32] ports,
 count(DISTINCT observation->>'url') FILTER(WHERE observation->>'kind'='http' AND COALESCE((observation->>'status_code')::int,0)>0) http_count,
 count(*) FILTER(WHERE COALESCE(observation->>'error','')<>'') error_count,
 (array_agg(DISTINCT observation->>'ip') FILTER(WHERE COALESCE(observation->>'ip','')<>''))[1:8] ips,
 (array_agg(DISTINCT COALESCE(NULLIF(observation->>'service',''),CASE WHEN COALESCE((observation->>'status_code')::int,0)>0 THEN observation->>'protocol' END)) FILTER(WHERE observation->>'kind' IN('service','http')))[1:12] services,
 (array_agg(DISTINCT COALESCE(NULLIF(observation->>'product',''),NULLIF(observation->>'server',''))) FILTER(WHERE observation->>'kind' IN('service','http')))[1:12] products,
 (array_agg(DISTINCT observation->>'title') FILTER(WHERE COALESCE(observation->>'title','')<>''))[1:3] titles
 FROM ob GROUP BY target_key),
 tech AS (SELECT target_key,(array_agg(DISTINCT t->>'name'))[1:12] technologies FROM ob
 CROSS JOIN LATERAL jsonb_array_elements(COALESCE(observation->'technologies','[]'::jsonb)) t GROUP BY target_key),
 results AS (SELECT ts.*,COALESCE(os.open_port_count,0) open_port_count,COALESCE(os.ports,'{}'::int[]) ports,
 COALESCE(os.http_count,0) http_count,COALESCE(os.error_count,0) error_count,
 COALESCE(os.ips,'{}'::text[]) ips,array_remove(COALESCE(os.services,'{}'::text[]),NULL) services,
 array_remove(COALESCE(os.products,'{}'::text[]),NULL) products,COALESCE(os.titles,'{}'::text[]) titles,COALESCE(tech.technologies,'{}'::text[]) technologies,COALESCE(pol.open_flood,false) open_flood,COALESCE(pol.fingerprint_count,0) fingerprint_count,COALESCE(pol.open_flood AND pol.fingerprint_count<pol.open_port_count,false) fingerprint_limited
 FROM ts LEFT JOIN os ON os.target_key=ts.target LEFT JOIN tech ON tech.target_key=ts.target LEFT JOIN run_target_policies pol ON pol.run_id=$1 AND pol.target_key=ts.target),
 filtered AS (SELECT * FROM results WHERE ($2='' OR target ILIKE '%'||$2||'%' OR
 array_to_string(ips||services||products||technologies||titles,' ') ILIKE '%'||$2||'%') AND
 ($3='' OR ($3='ports' AND open_port_count>0) OR ($3='http' AND http_count>0) OR
 ($3='errors' AND task_failed>0) OR ($3='limited' AND fingerprint_limited) OR ($3='empty' AND open_port_count=0 AND port_state='completed')))`

func (s *Server) requireResultRun(w http.ResponseWriter, r *http.Request) bool {
	var exists bool
	err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM runs WHERE id=$1)`, r.PathValue("id")).Scan(&exists)
	if err != nil {
		writeError(w, 503, "数据库暂不可用")
		return false
	}
	if !exists {
		writeError(w, 404, "任务不存在")
		return false
	}
	return true
}

func (s *Server) listTargetResults(w http.ResponseWriter, r *http.Request) {
	if !s.requireResultRun(w, r) {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	filter := r.URL.Query().Get("filter")
	if filter != "" && !contains([]string{"ports", "http", "errors", "empty", "limited"}, filter) {
		writeError(w, 400, "未知结果筛选条件")
		return
	}
	args := []any{r.PathValue("id"), strings.TrimSpace(r.URL.Query().Get("q")), filter, limit, offset}
	var total, targets, ports, httpCount, withErrors, limited int64
	var items json.RawMessage
	err = s.db.QueryRow(r.Context(), targetResults+`, page AS (SELECT * FROM filtered
 ORDER BY open_port_count DESC,http_count DESC,CASE WHEN target ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' THEN string_to_array(target,'.')::int[] END NULLS LAST,target LIMIT $4 OFFSET $5)
 SELECT (SELECT count(*) FROM filtered),count(*),COALESCE(sum(open_port_count),0),COALESCE(sum(http_count),0),count(*) FILTER(WHERE task_failed>0),count(*) FILTER(WHERE fingerprint_limited),
 COALESCE((SELECT jsonb_agg(to_jsonb(p) ORDER BY open_port_count DESC,http_count DESC,CASE WHEN target ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' THEN string_to_array(target,'.')::int[] END NULLS LAST,target) FROM page p),'[]'::jsonb) FROM results`, args...).Scan(&total, &targets, &ports, &httpCount, &withErrors, &limited, &items)
	if err != nil {
		writeError(w, 500, "汇总扫描结果失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "summary": map[string]int64{"targets": targets, "open_ports": ports, "http_endpoints": httpCount, "targets_with_errors": withErrors, "limited_targets": limited}})
}

func (s *Server) listPortResults(w http.ResponseWriter, r *http.Request) {
	if !s.requireResultRun(w, r) {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, 400, "请选择目标")
		return
	}
	const grouped = `WITH latest AS (SELECT DISTINCT ON(a.observation->>'kind',a.observation->>'port') a.id,a.observed_at,a.observation
	 FROM assets a JOIN tasks t ON t.id=a.task_id AND t.attempt_no=a.attempt_no
	 WHERE a.run_id=$1 AND a.target_key=$2 AND a.observation->>'kind' IN('port','service')
	 ORDER BY a.observation->>'kind',a.observation->>'port',(COALESCE(a.observation->>'error','')='') DESC,a.observed_at DESC,a.id DESC),
 ports AS (SELECT (observation->>'port')::int port,bool_or(observation->>'kind'='port') is_open,
 max(observation->>'service') service,max(observation->>'product') product,max(observation->>'version') version,
 max(observation->>'error') error,max(id) FILTER(WHERE observation->>'kind'='service') service_observation_id
 FROM latest GROUP BY (observation->>'port')::int)`
	var total int64
	var items json.RawMessage
	err = s.db.QueryRow(r.Context(), grouped+`, page AS (SELECT * FROM ports WHERE is_open ORDER BY port LIMIT $3 OFFSET $4),
	 http_latest AS (SELECT DISTINCT ON((a.observation->>'port')::int,a.observation->>'url')
	  (a.observation->>'port')::int port,a.observation->>'url' url,
	  jsonb_build_object('id',a.id,'url',a.observation->>'url','status_code',a.observation->'status_code','title',a.observation->>'title','technologies',a.observation->'technologies') item
	 FROM assets a JOIN tasks t ON t.id=a.task_id AND t.attempt_no=a.attempt_no
	 WHERE a.run_id=$1 AND a.target_key=$2 AND a.observation->>'kind'='http' AND a.observation->>'ip'=$2 AND COALESCE((a.observation->>'status_code')::int,0)>0
	 ORDER BY (a.observation->>'port')::int,a.observation->>'url',a.observed_at DESC,a.id DESC),
	 http_by_port AS (SELECT port,jsonb_agg(item ORDER BY url) http FROM (
	  SELECT *,row_number() OVER(PARTITION BY port ORDER BY url) item_no FROM http_latest) ranked WHERE item_no<=8 GROUP BY port),
	 items AS (SELECT to_jsonb(p)||jsonb_build_object('http',COALESCE(h.http,'[]'::jsonb)) item,p.port
	 FROM page p LEFT JOIN http_by_port h ON h.port=p.port)
 SELECT count(*) FILTER(WHERE is_open),COALESCE((SELECT jsonb_agg(item ORDER BY port) FROM items),'[]'::jsonb) FROM ports`, r.PathValue("id"), target, limit, offset).Scan(&total, &items)
	if err != nil {
		writeError(w, 500, "读取端口失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

func (s *Server) listHTTPResults(w http.ResponseWriter, r *http.Request) {
	if !s.requireResultRun(w, r) {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if status := r.URL.Query().Get("status"); status != "" && !contains([]string{"all", "responded", "no_response"}, status) {
		writeError(w, 400, "未知 HTTP 响应筛选条件")
		return
	}
	const httpQuery = currentResults + `, latest AS(SELECT DISTINCT ON(target_key,COALESCE(observation->>'url',observation->>'target')) * FROM ob WHERE observation->>'kind'='http' AND ($2='' OR target_key=$2)
 ORDER BY target_key,COALESCE(observation->>'url',observation->>'target'),(COALESCE((observation->>'status_code')::int,0)>0) DESC,observed_at DESC,id DESC), filtered AS(SELECT * FROM latest WHERE ($3='' OR (observation-'request_raw'-'response_raw'-'body_excerpt'-'headers')::text ILIKE '%'||$3||'%' OR target_key ILIKE '%'||$3||'%') AND ($4='' OR $4='all' OR ($4='responded' AND COALESCE((observation->>'status_code')::int,0)>0) OR ($4='no_response' AND COALESCE((observation->>'status_code')::int,0)=0)))`
	args := []any{r.PathValue("id"), r.URL.Query().Get("target"), strings.TrimSpace(r.URL.Query().Get("q")), r.URL.Query().Get("status"), limit, offset}
	var total int64
	var items json.RawMessage
	err = s.db.QueryRow(r.Context(), httpQuery+`, page AS (SELECT * FROM filtered ORDER BY target_key,observation->>'url' LIMIT $5 OFFSET $6)
 SELECT count(*),COALESCE((SELECT jsonb_agg((observation-'request_raw'-'response_raw'-'body_excerpt'-'headers') || jsonb_build_object('id',id,'source_target',target_key,'observed_at',observed_at) ORDER BY target_key,observation->>'url') FROM page),'[]'::jsonb) FROM filtered`, args...).Scan(&total, &items)
	if err != nil {
		writeError(w, 500, "读取 HTTP 结果失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	if !s.requireResultRun(w, r) {
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "all"
	}
	if !contains([]string{"matched", "not_matched", "error", "all"}, status) {
		writeError(w, http.StatusBadRequest, "unknown finding status")
		return
	}
	severity, err := libraryFilter(r.URL.Query().Get("severity"), "severity", "info", "low", "medium", "high", "critical")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	purpose, err := libraryFilter(r.URL.Query().Get("purpose"), "purpose", "discovery", "verification", "check")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	const findings = currentResults + `, findings AS (SELECT * FROM ob WHERE observation->>'kind'='poc'),
	 filtered AS (SELECT * FROM findings WHERE ($2='all' OR observation->>'finding_status'=$2)
	 AND ($3='' OR observation->>'severity'=$3) AND ($4='' OR
	 (observation-'request_raw'-'response_raw'-'body_excerpt'-'headers')::text ILIKE '%'||$4||'%' OR target_key ILIKE '%'||$4||'%')
	 AND ($5='' OR COALESCE(NULLIF(observation->>'purpose',''),'discovery')=$5))`
	var total, matched, notMatched, failed, verificationMatched, checkMatched, discoveryMatched int64
	var items json.RawMessage
	err = s.db.QueryRow(r.Context(), findings+`, page AS (SELECT * FROM filtered ORDER BY observed_at DESC,id DESC LIMIT $6 OFFSET $7)
	 SELECT (SELECT count(*) FROM filtered),count(*) FILTER(WHERE observation->>'finding_status'='matched'),
	 count(*) FILTER(WHERE observation->>'finding_status'='not_matched'),count(*) FILTER(WHERE observation->>'finding_status'='error'),
	 count(*) FILTER(WHERE observation->>'finding_status'='matched' AND COALESCE(NULLIF(observation->>'purpose',''),'discovery')='verification'),
	 count(*) FILTER(WHERE observation->>'finding_status'='matched' AND COALESCE(NULLIF(observation->>'purpose',''),'discovery')='check'),
	 count(*) FILTER(WHERE observation->>'finding_status'='matched' AND COALESCE(NULLIF(observation->>'purpose',''),'discovery')='discovery'),
	 COALESCE((SELECT jsonb_agg((observation-'request_raw'-'response_raw'-'body_excerpt'-'headers') ||
	 jsonb_build_object('id',id,'run_id',$1::text,'source_target',target_key,'observed_at',observed_at,
	 'matched_products',COALESCE(task_payload->'matched_products','[]'::jsonb),'trigger_reason',COALESCE(task_payload->>'trigger_reason',''))
	 ORDER BY observed_at DESC,id DESC) FROM page),'[]'::jsonb)
	 FROM findings`, r.PathValue("id"), status, severity, query, purpose, limit, offset).Scan(
		&total, &matched, &notMatched, &failed, &verificationMatched, &checkMatched, &discoveryMatched, &items)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load findings failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total,
		"summary": map[string]int64{"matched": matched, "not_matched": notMatched, "error": failed,
			"verification_matched": verificationMatched, "check_matched": checkMatched, "discovery_matched": discoveryMatched}})
}

func (s *Server) getObservation(w http.ResponseWriter, r *http.Request) {
	var item Asset
	var raw, taskPayload []byte
	err := s.db.QueryRow(r.Context(), `SELECT a.id,a.run_id,a.observed_at,a.observation,t.payload
		FROM assets a JOIN tasks t ON t.id=a.task_id WHERE a.id=$1`, r.PathValue("id")).Scan(&item.ID, &item.RunID, &item.ObservedAt, &raw, &taskPayload)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "结果不存在")
		return
	}
	if err != nil || json.Unmarshal(raw, &item.Observation) != nil {
		writeError(w, 500, "读取结果详情失败")
		return
	}
	var trace struct {
		MatchedProducts []string `json:"matched_products,omitempty"`
		TriggerReason   string   `json:"trigger_reason,omitempty"`
	}
	_ = json.Unmarshal(taskPayload, &trace)
	writeJSON(w, 200, struct {
		Asset
		MatchedProducts []string `json:"matched_products,omitempty"`
		TriggerReason   string   `json:"trigger_reason,omitempty"`
	}{Asset: item, MatchedProducts: trace.MatchedProducts, TriggerReason: trace.TriggerReason})
}
