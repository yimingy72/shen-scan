package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const maxExpandedTargets = 65536

type taskSeed struct {
	typeName string
	payload  any
	key      string
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name       string   `json:"name"`
		Targets    []string `json:"targets"`
		Modes      []string `json:"modes"`
		POCEnabled bool     `json:"poc_enabled"`
		POCRuleIDs []string `json:"poc_rule_ids"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 200 {
		writeError(w, http.StatusBadRequest, "name must contain 1 to 200 characters")
		return
	}
	modes, err := normalizeModes(request.Modes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.POCEnabled && !contains(modes, "http") {
		writeError(w, http.StatusBadRequest, "poc_enabled requires http mode")
		return
	}
	if !request.POCEnabled && len(request.POCRuleIDs) != 0 {
		writeError(w, http.StatusBadRequest, "poc_rule_ids requires poc_enabled")
		return
	}
	seeds, err := buildTaskSeeds(request.Targets, modes, s.allowLocal)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pool, err := s.loadPool(r.Context())
	if err != nil {
		writeError(w, 503, "无法读取调度容量")
		return
	}
	workers := pool.HealthyWorkers
	if workers < 1 {
		workers = pool.DesiredWorkers
	}
	if workers < 1 {
		workers = 1
	}
	seeds = shardPortSeeds(seeds, workers)
	runID := newID()
	targetJSON, _ := json.Marshal(request.Targets)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	snapshot, err := loadRuleSnapshot(r.Context(), tx, request.POCEnabled, request.POCRuleIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snapshotJSON, _ := json.Marshal(snapshot)
	requiresHTTPXCFF := false
	for _, rule := range snapshot.HTTP {
		if rule.Engine == "httpx-cff" && rule.Enabled {
			requiresHTTPXCFF = true
			break
		}
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO runs (id,name,targets,modes,status,poc_enabled,rules_snapshot,requires_httpx_cff)
		VALUES ($1,$2,$3,$4,'pending',$5,$6,$7)`,
		runID, request.Name, targetJSON, modes, request.POCEnabled, snapshotJSON, requiresHTTPXCFF)
	if err == nil {
		taskRows := make([][]any, 0, len(seeds))
		targetRows := make([][]any, 0, len(seeds))
		for _, seed := range seeds {
			payload, marshalErr := json.Marshal(seed.payload)
			if marshalErr != nil {
				err = marshalErr
				break
			}
			taskID := newID()
			taskRows = append(taskRows, []any{taskID, runID, seed.typeName, payload, seed.key, payloadTarget(payload)})
			for _, key := range taskTargetKeys(payload) {
				targetRows = append(targetRows, []any{taskID, key})
			}
		}
		if err == nil {
			_, err = tx.CopyFrom(r.Context(), pgx.Identifier{"tasks"}, []string{"id", "run_id", "type", "payload", "derived_key", "target_key"}, pgx.CopyFromRows(taskRows))
		}
		if err == nil {
			_, err = tx.CopyFrom(r.Context(), pgx.Identifier{"task_targets"}, []string{"task_id", "target_key"}, pgx.CopyFromRows(targetRows))
		}
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "create run failed")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	run, err := s.loadRun(r.Context(), runID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load created run failed")
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

func shardPortSeeds(seeds []taskSeed, workers int) []taskSeed {
	var rest []taskSeed
	ips := map[string]bool{}
	httpEnabled := false
	for _, seed := range seeds {
		if seed.typeName != "port" {
			rest = append(rest, seed)
			continue
		}
		raw, _ := json.Marshal(seed.payload)
		var p struct {
			Targets     []string
			HTTPEnabled bool `json:"http_enabled"`
		}
		_ = json.Unmarshal(raw, &p)
		for _, ip := range p.Targets {
			ips[ip] = true
		}
		httpEnabled = httpEnabled || p.HTTPEnabled
	}
	addresses := make([]string, 0, len(ips))
	for ip := range ips {
		addresses = append(addresses, ip)
	}
	sort.Slice(addresses, func(i, j int) bool {
		a, _ := netip.ParseAddr(addresses[i])
		b, _ := netip.ParseAddr(addresses[j])
		return a.Compare(b) < 0
	})
	rate, cap := portScanSettings()
	workers = max(workers, 1)
	shards := max(min(workers, len(addresses)), (len(addresses)+cap-1)/cap)
	for index := 0; index < shards; index++ {
		start, end := index*len(addresses)/shards, (index+1)*len(addresses)/shards
		targets := addresses[start:end]
		rest = append(rest, taskSeed{typeName: "port", key: fmt.Sprintf("ports:%d", index), payload: map[string]any{
			"targets": targets, "ports": "1-65535", "rate_pps": rate, "wait_seconds": 15, "timeout_seconds": 180, "execution_timeout_seconds": 180, "http_enabled": httpEnabled}})
	}
	return rest
}

func portScanSettings() (rate, shardMax int) {
	rate, shardMax = 5000, 4
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SCAN_PORT_RATE_PPS"))); err == nil && n >= 1000 && n <= 20000 {
		rate = n
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SCAN_PORT_SHARD_MAX"))); err == nil && n >= 1 && n <= 16 {
		shardMax = n
	}
	// Reserve 15 seconds for Masscan's wait and 30 seconds to drain results.
	// Two packets per probe covers the worst case where every port responds.
	safeMax := (180 - 15 - 30) * rate / (2 * 65535)
	return rate, min(shardMax, max(1, safeMax))
}

func normalizeModes(input []string) ([]string, error) {
	seen := make(map[string]bool)
	var modes []string
	for _, mode := range input {
		mode = strings.ToLower(strings.TrimSpace(mode))
		if mode != "port" && mode != "http" {
			return nil, fmt.Errorf("unsupported mode %q", mode)
		}
		if !seen[mode] {
			seen[mode] = true
			modes = append(modes, mode)
		}
	}
	if len(modes) == 0 {
		return nil, errors.New("at least one mode is required")
	}
	return modes, nil
}

func buildTaskSeeds(targets, modes []string, allowPrivate bool) ([]taskSeed, error) {
	if len(targets) == 0 || len(targets) > maxExpandedTargets {
		return nil, fmt.Errorf("targets must contain 1 to %d entries", maxExpandedTargets)
	}
	hasPort, hasHTTP := contains(modes, "port"), contains(modes, "http")
	var seeds []taskSeed
	expanded := 0
	for index, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" {
			return nil, fmt.Errorf("target %d is empty", index+1)
		}
		if strings.Contains(target, "://") {
			if !hasHTTP {
				return nil, fmt.Errorf("target %q is a URL and requires http mode", target)
			}
			parsed, err := url.ParseRequestURI(target)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
				return nil, fmt.Errorf("target %q must be an HTTP or HTTPS URL", target)
			}
			if address, err := netip.ParseAddr(parsed.Hostname()); err == nil && !allowedAddress(address, allowPrivate) {
				return nil, fmt.Errorf("target %q resolves directly to a protected address", target)
			}
			seeds = append(seeds, httpSeed([]map[string]any{{"url": parsed.String()}}, fmt.Sprintf("url:%d", index)))
			expanded++
			continue
		}
		if prefix, err := netip.ParsePrefix(target); err == nil {
			if !prefix.Addr().Is4() && hasPort {
				return nil, fmt.Errorf("target %q: port mode supports IPv4 only", target)
			}
			for address := prefix.Masked().Addr(); prefix.Contains(address); address = address.Next() {
				expanded++
				if expanded > maxExpandedTargets {
					return nil, fmt.Errorf("expanded targets exceed limit %d", maxExpandedTargets)
				}
				if !allowedAddress(address, allowPrivate) {
					return nil, fmt.Errorf("target %q includes protected address %s", target, address)
				}
				seeds = append(seeds, seedsForAddress(address, hasPort, hasHTTP, fmt.Sprintf("cidr:%d:%s", index, address))...)
			}
			continue
		}
		if address, err := netip.ParseAddr(target); err == nil {
			if hasPort && !address.Is4() {
				return nil, fmt.Errorf("target %q: port mode supports IPv4 only", target)
			}
			if !allowedAddress(address, allowPrivate) {
				return nil, fmt.Errorf("target %q is a protected address", target)
			}
			seeds = append(seeds, seedsForAddress(address, hasPort, hasHTTP, fmt.Sprintf("ip:%d", index))...)
			expanded++
			continue
		}
		if net.ParseIP(target) != nil || !validHostname(target) {
			return nil, fmt.Errorf("target %q is not a valid IP, CIDR, hostname, or URL", target)
		}
		if !hasHTTP {
			return nil, fmt.Errorf("domain target %q requires http mode", target)
		}
		endpoints := []map[string]any{{"host": target, "url": "http://" + target}, {"host": target, "url": "https://" + target}}
		seeds = append(seeds, httpSeed(endpoints, fmt.Sprintf("domain:%d", index)))
		expanded++
	}
	if len(seeds) == 0 {
		return nil, errors.New("targets produced no executable tasks")
	}
	return seeds, nil
}

func seedsForAddress(address netip.Addr, hasPort, hasHTTP bool, key string) []taskSeed {
	text := address.String()
	if hasPort {
		return []taskSeed{{
			typeName: "port",
			key:      key + ":port",
			payload: map[string]any{"targets": []string{text}, "ports": "1-65535", "rate_pps": 5000,
				"wait_seconds": 15, "timeout_seconds": 180, "http_enabled": hasHTTP},
		}}
	}
	if hasHTTP {
		host := text
		if address.Is6() {
			host = "[" + text + "]"
		}
		return []taskSeed{httpSeed([]map[string]any{{"ip": text, "url": "http://" + host}, {"ip": text, "url": "https://" + host}}, key+":http")}
	}
	return nil
}

func httpSeed(endpoints []map[string]any, key string) taskSeed {
	return taskSeed{typeName: "http", key: key, payload: map[string]any{"endpoints": endpoints, "timeout_seconds": 12, "execution_timeout_seconds": 180}}
}

func allowedAddress(address netip.Addr, allowPrivate bool) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLoopback() {
		return allowPrivate && (address.IsLoopback() || address.IsPrivate())
	}
	if address.IsPrivate() {
		return allowPrivate
	}
	// Cloud metadata is link-local, but keep the exact address explicit too.
	if address.String() == "169.254.169.254" {
		return false
	}
	return true
}

func validHostname(value string) bool {
	if len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func runSelect(targets, runs string) string {
	return `SELECT r.id,r.name,` + targets + `,r.modes,r.status,r.created_at,r.updated_at,
	 COALESCE(ts.task_total,0),COALESCE(ts.task_done,0),COALESCE(ts.task_failed,0),COALESCE(ac.asset_count,0),r.error,
	 COALESCE(tgs.target_count,0),COALESCE(rs.open_port_count,0),COALESCE(rs.http_count,0),COALESCE(tgs.target_done,0),jsonb_array_length(r.targets),
	 r.poc_enabled,COALESCE(pc.finding_count,0),COALESCE(pc.verification_finding_count,0),COALESCE(pc.check_match_count,0),COALESCE(pc.discovery_match_count,0),COALESCE(pc.checked_count,0)
	 FROM ` + runs + ` r
	 LEFT JOIN LATERAL (SELECT count(*) task_total,count(*) FILTER(WHERE state='completed') task_done,
	  count(*) FILTER(WHERE state='failed') task_failed FROM tasks WHERE run_id=r.id) ts ON true
	 LEFT JOIN LATERAL (SELECT count(*) target_count,count(*) FILTER(WHERE finished) target_done FROM (
	  SELECT bool_and(t.state='completed') finished FROM tasks t JOIN task_targets tt ON tt.task_id=t.id WHERE t.run_id=r.id GROUP BY tt.target_key) target_states) tgs ON true
	 LEFT JOIN LATERAL (SELECT count(*) asset_count FROM assets WHERE run_id=r.id) ac ON true
	 LEFT JOIN LATERAL (SELECT count(*) FILTER(WHERE a.observation->>'finding_status'='matched') finding_count,
	  count(*) FILTER(WHERE a.observation->>'finding_status'='matched' AND COALESCE(NULLIF(a.observation->>'purpose',''),'discovery')='verification') verification_finding_count,
	  count(*) FILTER(WHERE a.observation->>'finding_status'='matched' AND COALESCE(NULLIF(a.observation->>'purpose',''),'discovery')='check') check_match_count,
	  count(*) FILTER(WHERE a.observation->>'finding_status'='matched' AND COALESCE(NULLIF(a.observation->>'purpose',''),'discovery')='discovery') discovery_match_count,
	  count(*) checked_count
	  FROM assets a JOIN tasks t ON t.id=a.task_id AND t.attempt_no=a.attempt_no
	  WHERE a.run_id=r.id AND a.observation->>'kind'='poc') pc ON true
	 LEFT JOIN LATERAL (SELECT count(*) FILTER(WHERE kind='port') open_port_count,count(*) FILTER(WHERE kind='http') http_count FROM (
	  SELECT a.target_key,a.observation->>'kind' kind,CASE WHEN a.observation->>'kind'='port' THEN a.observation->>'port' ELSE a.observation->>'url' END result_key
	  FROM assets a JOIN tasks t ON t.id=a.task_id AND t.attempt_no=a.attempt_no
	  WHERE a.run_id=r.id AND ((a.observation->>'kind'='port' AND COALESCE(a.observation->>'error','')='')
	   OR (a.observation->>'kind'='http' AND COALESCE((a.observation->>'status_code')::int,0)>0))
	  GROUP BY a.target_key,a.observation->>'kind',CASE WHEN a.observation->>'kind'='port' THEN a.observation->>'port' ELSE a.observation->>'url' END) grouped_results) rs ON true`
}

type rowScanner interface{ Scan(...any) error }

func scanRun(row rowScanner) (Run, error) {
	var run Run
	var targets []byte
	err := row.Scan(&run.ID, &run.Name, &targets, &run.Modes, &run.Status, &run.CreatedAt, &run.UpdatedAt,
		&run.TaskTotal, &run.TaskDone, &run.TaskFailed, &run.AssetCount, &run.Error, &run.TargetCount, &run.OpenPortCount, &run.HTTPCount, &run.TargetDone, &run.InputCount,
		&run.POCEnabled, &run.FindingCount, &run.VerificationFindingCount, &run.CheckMatchCount, &run.DiscoveryMatchCount, &run.POCCheckedCount)
	if err == nil {
		err = json.Unmarshal(targets, &run.Targets)
		run.CreatedAt = run.CreatedAt.UTC()
		run.UpdatedAt = run.UpdatedAt.UTC()
	}
	return run, err
}

func (s *Server) loadRun(ctx context.Context, id string) (Run, error) {
	return scanRun(s.db.QueryRow(ctx, runSelect(`r.targets`, `runs`)+` WHERE r.id=$1`, id))
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.loadRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load run failed")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	targets := `r.targets`
	if r.URL.Query().Get("summary") == "true" {
		targets = `CASE WHEN jsonb_array_length(r.targets)>2 THEN jsonb_build_array(r.targets->0,r.targets->1) ELSE r.targets END`
	}
	rows, err := s.db.Query(r.Context(), runSelect(targets, `(SELECT * FROM runs ORDER BY created_at DESC LIMIT 500)`)+` ORDER BY r.created_at DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load runs failed")
		return
	}
	defer rows.Close()
	items := make([]Run, 0)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load runs failed")
			return
		}
		items = append(items, run)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	s.changeRunStatus(w, r, "cancel")
}
func (s *Server) pauseRun(w http.ResponseWriter, r *http.Request) {
	s.changeRunStatus(w, r, "pause")
}
func (s *Server) resumeRun(w http.ResponseWriter, r *http.Request) {
	s.changeRunStatus(w, r, "resume")
}

func (s *Server) changeRunStatus(w http.ResponseWriter, r *http.Request, action string) {
	if !consumeEmptyAction(w, r) {
		return
	}
	id := r.PathValue("id")
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock($1)`, controlLockID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	var status string
	if err := tx.QueryRow(r.Context(), `SELECT status FROM runs WHERE id=$1 FOR UPDATE`, id).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "run not found")
		} else {
			writeError(w, http.StatusInternalServerError, "update run failed")
		}
		return
	}
	switch action {
	case "cancel":
		if status != "completed" && status != "failed" && status != "cancelled" && status != "partial" {
			_, err = tx.Exec(r.Context(), `UPDATE runs SET status='cancelling',updated_at=now() WHERE id=$1`, id)
			if err == nil {
				_, err = tx.Exec(r.Context(), `UPDATE tasks SET state='cancelled',lease_until=NULL,rate_until=NULL,updated_at=now()
					WHERE run_id=$1 AND state IN ('queued','leased')`, id)
			}
			if err == nil {
				_, err = tx.Exec(r.Context(), `UPDATE runs SET status='cancelled',updated_at=now() WHERE id=$1`, id)
			}
		}
	case "pause":
		if status == "pending" || status == "running" {
			_, err = tx.Exec(r.Context(), `UPDATE runs SET status='paused',updated_at=now() WHERE id=$1`, id)
		}
	case "resume":
		if status == "paused" {
			_, err = tx.Exec(r.Context(), `UPDATE runs SET status='pending',updated_at=now() WHERE id=$1`, id)
		}
	default:
		err = errors.New("unknown action")
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		writeError(w, http.StatusInternalServerError, "update run failed")
		return
	}
	run, err := s.loadRun(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load run failed")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	runID, query := r.URL.Query().Get("run_id"), strings.TrimSpace(r.URL.Query().Get("q"))
	where := ` WHERE ($1='' OR run_id=$1) AND ($2='' OR observation::text ILIKE '%' || $2 || '%')`
	var total int64
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM assets`+where, runID, query).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "load assets failed")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT id,run_id,observed_at,observation FROM assets`+where+` ORDER BY observed_at DESC,id LIMIT $3 OFFSET $4`, runID, query, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load assets failed")
		return
	}
	defer rows.Close()
	items := make([]Asset, 0)
	for rows.Next() {
		var item Asset
		var raw []byte
		if err := rows.Scan(&item.ID, &item.RunID, &item.ObservedAt, &raw); err != nil || json.Unmarshal(raw, &item.Observation) != nil {
			writeError(w, http.StatusInternalServerError, "load assets failed")
			return
		}
		item.ObservedAt = item.ObservedAt.UTC()
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func pagination(r *http.Request) (int, int, error) {
	limit, offset := 100, 0
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 500 {
			return 0, 0, errors.New("limit must be between 1 and 500")
		}
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 || offset > 10_000_000 {
			return 0, 0, errors.New("offset must be between 0 and 10000000")
		}
	}
	return limit, offset, nil
}

func (s *Server) listWorkers(w http.ResponseWriter, r *http.Request) {
	_, _ = s.db.Exec(r.Context(), `UPDATE workers SET status='offline' WHERE last_heartbeat < now()-interval '45 seconds' AND status <> 'offline'`)
	workers, err := s.WorkerInstances(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load workers failed")
		return
	}
	items := make([]Worker, 0, len(workers))
	tasks, err := s.db.Query(r.Context(), `SELECT t.worker_id,t.id,t.type,t.target_key,r.id,r.name,
	 ARRAY(SELECT tt.target_key FROM task_targets tt WHERE tt.task_id=t.id ORDER BY tt.target_key) FROM tasks t JOIN runs r ON r.id=t.run_id
	 WHERE t.state='leased' AND t.lease_until>now() ORDER BY t.created_at`)
	if err != nil {
		writeError(w, 503, "读取节点任务失败")
		return
	}
	active := map[string][]WorkerTask{}
	for tasks.Next() {
		var workerID string
		var task WorkerTask
		if err = tasks.Scan(&workerID, &task.ID, &task.Type, &task.Target, &task.RunID, &task.RunName, &task.Targets); err != nil {
			tasks.Close()
			writeError(w, 500, "读取节点任务失败")
			return
		}
		active[workerID] = append(active[workerID], task)
	}
	tasks.Close()
	if tasks.Err() != nil {
		writeError(w, 503, "读取节点任务失败")
		return
	}
	for _, worker := range workers {
		worker.ActiveTasks = active[worker.ID]
		if len(worker.ActiveTasks) > 0 && worker.Status == "ready" {
			worker.Status = "running"
		}
		items = append(items, worker)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) loadPool(ctx context.Context) (Pool, error) {
	var pool Pool
	err := s.db.QueryRow(ctx, `SELECT desired_workers,enabled,generation,healthy_workers,starting_workers,
		draining_workers,provider,configured,error FROM worker_pool WHERE singleton`).Scan(
		&pool.DesiredWorkers, &pool.Enabled, &pool.Generation, &pool.HealthyWorkers, &pool.StartingWorkers,
		&pool.DrainingWorkers, &pool.Provider, &pool.Configured, &pool.Error)
	return pool, err
}

func (s *Server) getPool(w http.ResponseWriter, r *http.Request) {
	pool, err := s.loadPool(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load worker pool failed")
		return
	}
	writeJSON(w, http.StatusOK, pool)
}

func (s *Server) patchPool(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DesiredWorkers     int   `json:"desired_workers"`
		Enabled            bool  `json:"enabled"`
		ExpectedGeneration int64 `json:"expected_generation"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.DesiredWorkers < 0 || request.DesiredWorkers > 1000 || request.ExpectedGeneration < 1 {
		writeError(w, http.StatusBadRequest, "desired_workers must be 0..1000 and expected_generation must be positive")
		return
	}
	s.providerMu.RLock()
	provider, configuredFn := s.provider, s.configured
	s.providerMu.RUnlock()
	configured := configuredFn != nil && configuredFn()
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock($1)`, controlLockID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	var storedConfigured bool
	if err = tx.QueryRow(r.Context(), `SELECT configured FROM worker_pool WHERE singleton FOR UPDATE`).Scan(&storedConfigured); err != nil {
		writeError(w, 503, "无法读取 Worker 池配置")
		return
	}
	if request.Enabled && (!configured || !storedConfigured) {
		writeError(w, 409, "请先配置阿里云账号并准备云网络")
		return
	}
	var pool Pool
	err = tx.QueryRow(r.Context(), `UPDATE worker_pool SET desired_workers=$1,enabled=$2,generation=generation+1,
		provider=$3,configured=$4,error='',updated_at=now() WHERE singleton AND generation=$5
		RETURNING desired_workers,enabled,generation,healthy_workers,starting_workers,draining_workers,provider,configured,error`,
		request.DesiredWorkers, request.Enabled, provider, configured, request.ExpectedGeneration).Scan(
		&pool.DesiredWorkers, &pool.Enabled, &pool.Generation, &pool.HealthyWorkers, &pool.StartingWorkers,
		&pool.DrainingWorkers, &pool.Provider, &pool.Configured, &pool.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "worker pool generation changed; reload and retry")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update worker pool failed")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	s.triggerReconcile(pool)
	writeJSON(w, http.StatusOK, pool)
}

func (s *Server) setupCloud(w http.ResponseWriter, r *http.Request) {
	if !consumeEmptyAction(w, r) {
		return
	}
	s.providerMu.RLock()
	setup := s.cloudSetup
	s.providerMu.RUnlock()
	if setup == nil {
		writeError(w, http.StatusConflict, "cloud setup is not available for the selected provider")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	result, err := setup(ctx)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Avoid an accidental zero time in API output when task endpoints are tested
// with a database value rounded below Go's monotonic clock.
func utcNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
