package control

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	servicePressureSampleLimit = 1024
	servicePressureCacheTTL    = 5 * time.Second
	servicePreferenceTTL       = 20
	servicePressureTimeout     = 500 * time.Millisecond
)

const servicePressureSchema = `
CREATE INDEX IF NOT EXISTS tasks_service_pressure_idx ON tasks(created_at,id) INCLUDE(run_id)
 WHERE type='service' AND state='queued';
`

// This is a bounded oldest-first window, never a total queue size or an ETA.
type servicePressure struct {
	Available                   bool      `json:"available"`
	PreferService               bool      `json:"prefer_service"`
	ObservedAt                  time.Time `json:"observed_at"`
	SampleLimit                 int       `json:"sample_limit"`
	CandidateTasks              int       `json:"candidate_tasks"`
	SampledTasks                int       `json:"sampled_tasks"`
	SampledEndpoints            int       `json:"sampled_endpoints"`
	Truncated                   bool      `json:"truncated"`
	WorkIsLowerBound            bool      `json:"work_is_lower_bound"`
	OldestWaitSeconds           float64   `json:"oldest_wait_seconds"`
	CostSamples                 int       `json:"cost_samples"`
	SecondsPerEndpoint          float64   `json:"seconds_per_endpoint,omitempty"`
	SampledEstimatedWorkSeconds float64   `json:"sampled_estimated_work_seconds,omitempty"`
	Reason                      string    `json:"reason"`
}

func decideServicePressure(p servicePressure, tuning BatchTuning, previous bool) servicePressure {
	p.CostSamples = tuning.Samples
	// Sparse histories still expose their sample count without invented throughput.
	if tuning.Samples >= 3 && finitePositive(tuning.SecondsPerItem) {
		p.SecondsPerEndpoint = tuning.SecondsPerItem
		if work := float64(p.SampledEndpoints) * tuning.SecondsPerItem; finitePositive(work) {
			p.SampledEstimatedWorkSeconds = work
		}
	}
	if previous {
		p.PreferService = p.OldestWaitSeconds >= 10 && (p.SampledEndpoints >= 4 || p.SampledEstimatedWorkSeconds >= 45)
	} else {
		p.PreferService = p.OldestWaitSeconds >= 30 && (p.SampledEndpoints >= 8 || p.SampledEstimatedWorkSeconds >= 90)
	}
	p.Reason = "below_threshold"
	if p.PreferService {
		p.Reason = "service_backlog"
	}
	return p
}

type servicePressureCache struct {
	mu         sync.Mutex
	value      servicePressure
	next       time.Time
	refreshing bool
}

func (c *servicePressureCache) get(ctx context.Context, now time.Time, load func(context.Context, bool) (servicePressure, error)) servicePressure {
	c.mu.Lock()
	if now.Before(c.next) {
		p := c.value
		c.mu.Unlock()
		return p
	}
	// Synchronized heartbeats may arrive together after the shorter cache TTL.
	// Reuse a successful snapshot during refresh, without extending its age.
	reusable := c.value.Available && !c.value.ObservedAt.IsZero() &&
		!now.Before(c.value.ObservedAt) && now.Sub(c.value.ObservedAt) <= servicePreferenceTTL*time.Second
	if c.refreshing {
		p := servicePressure{SampleLimit: servicePressureSampleLimit, Reason: "refreshing"}
		if reusable {
			p = c.value
		}
		c.mu.Unlock()
		return p
	}
	c.refreshing = true
	previous := reusable && c.value.PreferService
	c.mu.Unlock()
	queryCtx, cancel := context.WithTimeout(ctx, servicePressureTimeout)
	p, err := load(queryCtx, previous)
	cancel()
	if err != nil {
		p = servicePressure{SampleLimit: servicePressureSampleLimit, Reason: "unavailable"}
	}
	c.mu.Lock()
	c.value, c.next, c.refreshing = p, now.Add(servicePressureCacheTTL), false
	c.mu.Unlock()
	return p
}

func (s *Server) servicePressureSnapshot(ctx context.Context) servicePressure {
	return s.servicePressure.get(ctx, time.Now(), s.loadServicePressure)
}

func (s *Server) loadServicePressure(ctx context.Context, previous bool) (servicePressure, error) {
	p := servicePressure{SampleLimit: servicePressureSampleLimit}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	// Bound candidates BEFORE run/profile filtering. Paused or incompatible work
	// can hide a newer backlog; that conservative false negative never blocks work.
	rows, err := tx.Query(ctx, `WITH candidates AS MATERIALIZED (
 SELECT id,run_id,created_at,payload FROM tasks WHERE type='service' AND state='queued'
 ORDER BY created_at,id LIMIT $1
 ) SELECT t.created_at,
 CASE WHEN r.status IN('pending','running') AND COALESCE(t.payload->>'service_profile','') IN('','nmap-light-v1')
 THEN jsonb_array_length(COALESCE(t.payload->'endpoints','[]'::jsonb)) ELSE 0 END,
 r.status IN('pending','running') AND COALESCE(t.payload->>'service_profile','') IN('','nmap-light-v1')
 FROM candidates t JOIN runs r ON r.id=t.run_id ORDER BY t.created_at,t.id`, servicePressureSampleLimit+1)
	if err != nil {
		return p, err
	}
	var oldest time.Time
	for rows.Next() {
		var created time.Time
		var endpoints int
		var eligible bool
		if err = rows.Scan(&created, &endpoints, &eligible); err != nil {
			break
		}
		if p.CandidateTasks == servicePressureSampleLimit {
			p.Truncated = true
			break
		}
		p.CandidateTasks++
		if !eligible {
			continue
		}
		if oldest.IsZero() {
			oldest = created
		}
		p.SampledTasks++
		p.SampledEndpoints += endpoints
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return p, err
	}
	tuning, err := loadAdaptiveBatch(ctx, tx, "service", 32, 45)
	if err != nil {
		return p, err
	}
	if err = tx.Commit(ctx); err != nil {
		return p, err
	}
	p.Available, p.ObservedAt, p.WorkIsLowerBound = true, time.Now().UTC(), p.Truncated
	if !oldest.IsZero() {
		p.OldestWaitSeconds = max(0, p.ObservedAt.Sub(oldest).Seconds())
	}
	return decideServicePressure(p, tuning, previous), nil
}
