package control

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// BatchTuning describes only future work. Existing task scopes and receipts are immutable.
type BatchTuning struct {
	Size           int     `json:"size"`
	Samples        int     `json:"samples"`
	SecondsPerItem float64 `json:"seconds_per_item,omitempty"`
	Reason         string  `json:"reason"`
}

type batchCostSample struct {
	items     int
	seconds   float64
	unhealthy bool
}

func tuneBatch(samples []batchCostSample, maximum int, target float64) BatchTuning {
	tuning := BatchTuning{Size: maximum, Reason: "cold"}
	if maximum < 1 || !finitePositive(target) {
		tuning.Size = 1
		return tuning
	}
	size := float64(maximum)
	unhealthy := false
	for _, sample := range samples {
		if sample.items < 1 || !finitePositive(sample.seconds) {
			continue
		}
		cost := sample.seconds / float64(sample.items)
		if tuning.Samples == 0 {
			tuning.SecondsPerItem = cost
		} else {
			tuning.SecondsPerItem = .75*tuning.SecondsPerItem + .25*cost
		}
		tuning.Samples++
		candidate := target / tuning.SecondsPerItem
		if sample.unhealthy || sample.seconds >= target*1.5 {
			unhealthy = true
			candidate = min(candidate, float64(sample.items)/2, size/2)
		}
		// Sparse or degraded histories can tighten admission, never enlarge it.
		if tuning.Samples < 3 || unhealthy {
			candidate = min(candidate, size)
		}
		candidate = max(size/2, min(candidate, size*1.25))
		size = max(1, min(float64(maximum), .5*size+.5*candidate))
	}
	if tuning.Samples > 0 {
		tuning.Size = max(1, min(maximum, int(math.Floor(size))))
		tuning.Reason = "observed"
		if unhealthy {
			tuning.Reason = "degraded"
		}
	}
	return tuning
}

func finitePositive(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

// Bounded recent first-attempt samples avoid counting recovery/queue time as clean execution.
// Failed attempts only tighten; incomplete results never become successful calibration.
func loadAdaptiveBatch(ctx context.Context, tx pgx.Tx, stage string, maximum int, target float64) (BatchTuning, error) {
	query := `SELECT payload,extract(epoch FROM COALESCE(completed_at,updated_at)-first_started_at)::float8,
 state<>'completed' OR coverage<>'complete' OR error<>'' FROM tasks
 WHERE type=$1 AND first_started_at>now()-interval '24 hours' AND attempt_no=1
 AND COALESCE(completed_at,updated_at)>now()-interval '24 hours'
 AND (state IN('completed','failed') OR (state='queued' AND error<>''))`
	var profile string
	switch stage {
	case "port":
		rate, _ := portScanSettings()
		profile = fmt.Sprint(min(rate, portTargetQuota()))
		query += ` AND payload->>'ports'='1-65535' AND payload->>'rate_pps'=$2 AND payload->>'wait_seconds'='15'`
	case "service":
		profile = "nmap-light-v1"
		query += ` AND payload->>'service_profile'=$2`
	default:
		return BatchTuning{}, fmt.Errorf("unsupported adaptive stage %q", stage)
	}
	query += ` ORDER BY COALESCE(completed_at,updated_at) DESC,id DESC LIMIT 32`
	rows, err := tx.Query(ctx, query, stage, profile)
	if err != nil {
		return BatchTuning{}, err
	}
	defer rows.Close()
	samples := []batchCostSample{}
	for rows.Next() {
		var raw []byte
		var sample batchCostSample
		if err = rows.Scan(&raw, &sample.seconds, &sample.unhealthy); err != nil {
			return BatchTuning{}, err
		}
		var payload struct {
			Endpoints []json.RawMessage `json:"endpoints"`
			Targets   []string          `json:"targets"`
		}
		if err = json.Unmarshal(raw, &payload); err != nil {
			return BatchTuning{}, err
		}
		sample.items = len(payload.Endpoints)
		if stage == "port" {
			sample.items = len(payload.Targets)
		}
		samples = append(samples, sample)
	}
	if err = rows.Err(); err != nil {
		return BatchTuning{}, err
	}
	// Smooth chronologically, with the newest costs having the greatest influence.
	for i, j := 0, len(samples)-1; i < j; i, j = i+1, j-1 {
		samples[i], samples[j] = samples[j], samples[i]
	}
	return tuneBatch(samples, maximum, target), nil
}

func (s *Server) adaptivePortSeeds(ctx context.Context, seeds []taskSeed, width int) ([]taskSeed, error) {
	_, maximum := portScanSettings()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tuning, err := loadAdaptiveBatch(ctx, tx, "port", maximum, 90)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	// shardPortSeeds already deduplicates addresses and enforces hard execution bounds.
	addresses := map[string]bool{}
	for _, seed := range seeds {
		if seed.typeName != "port" {
			continue
		}
		raw, err := json.Marshal(seed.payload)
		if err != nil {
			return nil, err
		}
		var p struct {
			Targets []string `json:"targets"`
		}
		if err = json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		for _, ip := range p.Targets {
			addresses[ip] = true
		}
	}
	return shardPortSeeds(seeds, max(width, (len(addresses)+tuning.Size-1)/tuning.Size)), nil
}

type portCostModel struct {
	Rate     float64 `json:"effective_ports_per_second"`
	Overhead float64 `json:"overhead_seconds"`
	Samples  int     `json:"samples"`
	Source   string  `json:"source"`
}

type portCostSample struct{ work, seconds float64 }

// A linear cost requires variation in observed work; identical full-range timings
// cannot distinguish startup/wait overhead from throughput and are not calibration.
func fitPortCost(samples []portCostSample, pps int) (portCostModel, bool) {
	if len(samples) < 4 || pps < 1 {
		return portCostModel{}, false
	}
	var sx, sy float64
	lo, hi := math.Inf(1), 0.0
	for _, s := range samples {
		if !finitePositive(s.work) || !finitePositive(s.seconds) {
			return portCostModel{}, false
		}
		sx += s.work
		sy += s.seconds
		lo = min(lo, s.work)
		hi = max(hi, s.work)
	}
	if hi < 2*lo {
		return portCostModel{}, false
	}
	n := float64(len(samples))
	mx, my := sx/n, sy/n
	var xx, xy float64
	for _, s := range samples {
		xx += (s.work - mx) * (s.work - mx)
		xy += (s.work - mx) * (s.seconds - my)
	}
	slope := xy / xx
	if !finitePositive(slope) {
		return portCostModel{}, false
	}
	intercept := my - slope*mx
	var residual float64
	for _, s := range samples {
		d := s.seconds - (intercept + slope*s.work)
		residual += d * d
	}
	deviation := math.Sqrt(residual / (n - 2))
	// Upper cost confidence bounds keep noisy/short histories conservative.
	slope += 2 * deviation / math.Sqrt(xx)
	model := portCostModel{Rate: min(float64(pps), 1/slope), Overhead: max(15, intercept+2*deviation), Samples: len(samples), Source: "observed_linear_cost"}
	return model, finitePositive(model.Rate) && finitePositive(model.Overhead)
}

func loadPortCost(ctx context.Context, tx pgx.Tx, worker, session, profile string, pps int) (portCostModel, bool, error) {
	var lastUnhealthy *time.Time
	if err := tx.QueryRow(ctx, `SELECT max(updated_at) FROM tasks WHERE worker_id=$1 AND session_id=$2 AND type='port'
 AND updated_at>now()-interval '24 hours' AND first_started_at>now()-interval '24 hours' AND (state='failed' OR error<>'' OR (state='completed' AND coverage<>'complete'))`, worker, session).Scan(&lastUnhealthy); err != nil {
		return portCostModel{}, false, err
	}
	rows, err := tx.Query(ctx, `SELECT payload,extract(epoch FROM completed_at-first_started_at)::float8
 FROM tasks WHERE worker_id=$1 AND session_id=$2 AND type='port' AND state='completed'
 AND attempt_no=1 AND accepted_attempt_no=1 AND coverage='complete' AND error=''
 AND completed_at>now()-interval '24 hours' AND first_started_at>now()-interval '24 hours' AND ($3::timestamptz IS NULL OR first_started_at>$3) ORDER BY completed_at DESC,id DESC LIMIT 32`, worker, session, lastUnhealthy)
	if err != nil {
		return portCostModel{}, false, err
	}
	var samples []portCostSample
	for rows.Next() {
		var raw []byte
		var seconds float64
		if err = rows.Scan(&raw, &seconds); err != nil {
			rows.Close()
			return portCostModel{}, false, err
		}
		var p struct {
			Targets []string `json:"targets"`
			Ports   string   `json:"ports"`
			PPS     int      `json:"rate_pps"`
			Wait    int      `json:"wait_seconds"`
		}
		if json.Unmarshal(raw, &p) != nil || p.PPS != pps || p.Wait != 15 {
			continue
		}
		first, last, rangeErr := parsePortInterval(p.Ports)
		if rangeErr != nil {
			continue
		}
		samples = append(samples, portCostSample{float64(len(p.Targets) * (last - first + 1)), seconds})
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return portCostModel{}, false, err
	}
	if model, ok := fitPortCost(samples, pps); ok {
		return model, true, nil
	}
	baseline, effective := calibratedPortProfile()
	if lastUnhealthy == nil && baseline != "" && profile == baseline {
		return portCostModel{Rate: effective, Overhead: 15, Source: "configured_calibration"}, true, nil
	}
	return portCostModel{}, false, nil
}

type portStartCandidate struct {
	worker, session, request string
	model                    portCostModel
}
type portStartSlice struct {
	candidate   portStartCandidate
	first, last int
}

// Only candidates backed by live start reservations enter this planner. Every
// selected process keeps its own PPS allocation; adding workers never raises Q.
func planPortStart(ports int, candidates []portStartCandidate, pps, quota int, collection float64) []portStartSlice {
	if ports < 1 || pps < 1 || quota < pps || len(candidates) == 0 || math.IsNaN(collection) || math.IsInf(collection, 0) || collection < 0 {
		return nil
	}
	candidates = append([]portStartCandidate(nil), candidates...)
	valid := candidates[:0]
	for _, c := range candidates {
		if finitePositive(c.model.Rate) && finitePositive(c.model.Overhead) && finitePositive(c.model.Overhead+float64(ports)/c.model.Rate) {
			valid = append(valid, c)
		}
	}
	candidates = valid
	if len(candidates) == 0 {
		return nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].model.Overhead+float64(ports)/candidates[i].model.Rate < candidates[j].model.Overhead+float64(ports)/candidates[j].model.Rate
	})
	maxK := min(len(candidates), quota/pps, max(1, ports/4096))
	baseline := candidates[0].model.Overhead + float64(ports)/candidates[0].model.Rate
	predictions := make([]float64, maxK+1)
	best := math.Inf(1)
	for k := 2; k <= maxK; k++ {
		duration, counts := weightedPortCounts(ports, candidates[:k])
		if counts == nil {
			continue
		}
		duration += collection
		if baseline-duration >= max(2, .15*baseline) {
			predictions[k] = duration
			best = min(best, duration)
		}
	}
	k := 1
	for n := 2; n <= maxK; n++ {
		if predictions[n] > 0 && predictions[n] <= best+max(2, .1*best) {
			k = n
			break
		}
	}
	_, counts := weightedPortCounts(ports, candidates[:k])
	result := make([]portStartSlice, k)
	first := 1
	for i, count := range counts {
		result[i] = portStartSlice{candidates[i], first, first + count - 1}
		first += count
	}
	return result
}

func weightedPortCounts(ports int, candidates []portStartCandidate) (float64, []int) {
	lo, hi := 0.0, 0.0
	for _, c := range candidates {
		hi = max(hi, c.model.Overhead+float64(ports)/c.model.Rate)
	}
	for step := 0; step < 60; step++ {
		mid := (lo + hi) / 2
		capacity := 0.0
		for _, c := range candidates {
			capacity += max(0, mid-c.model.Overhead) * c.model.Rate
		}
		if capacity < float64(ports) {
			lo = mid
		} else {
			hi = mid
		}
	}
	counts := make([]int, len(candidates))
	assigned := 0
	sum := 0.0
	for i, c := range candidates {
		sum += max(0, hi-c.model.Overhead) * c.model.Rate
		end := min(ports, int(math.Floor(sum)))
		if i == len(candidates)-1 {
			end = ports
		}
		counts[i] = end - assigned
		assigned = end
		if len(candidates) > 1 && counts[i] < 4096 {
			return 0, nil
		}
	}
	actual := 0.0
	for i, c := range candidates {
		actual = max(actual, c.model.Overhead+float64(counts[i])/c.model.Rate)
	}
	return actual, counts
}
