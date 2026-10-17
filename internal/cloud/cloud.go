package cloud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/cms"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/jackc/pgx/v5/pgxpool"

	"scanplatform/internal/control"
)

const cloudSchema = `
CREATE TABLE IF NOT EXISTS cloud_instances (
  instance_id text PRIMARY KEY,
  provider text NOT NULL,
  pool_id text NOT NULL DEFAULT '',
  state text NOT NULL,
  generation bigint NOT NULL,
  operation_key text NOT NULL DEFAULT '',
  drain_started timestamptz,
  missing_confirmations integer NOT NULL DEFAULT 0,
  release_confirmed boolean NOT NULL DEFAULT false,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cloud_operations (
  idempotency_key text PRIMARY KEY,
  provider text NOT NULL,
  pool_id text NOT NULL DEFAULT '',
  operation text NOT NULL,
  state text NOT NULL,
  generation bigint NOT NULL DEFAULT 0,
  amount integer NOT NULL DEFAULT 0,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cloud_provider_settings (
  provider text PRIMARY KEY,
  settings jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cloud_account_settings (
  provider text PRIMARY KEY,
  settings jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE cloud_instances ADD COLUMN IF NOT EXISTS pool_id text NOT NULL DEFAULT '';
ALTER TABLE cloud_instances ADD COLUMN IF NOT EXISTS operation_key text NOT NULL DEFAULT '';
ALTER TABLE cloud_instances ADD COLUMN IF NOT EXISTS drain_started timestamptz;
ALTER TABLE cloud_instances ADD COLUMN IF NOT EXISTS missing_confirmations integer NOT NULL DEFAULT 0;
ALTER TABLE cloud_instances ADD COLUMN IF NOT EXISTS release_confirmed boolean NOT NULL DEFAULT false;
ALTER TABLE cloud_instances ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE cloud_operations ADD COLUMN IF NOT EXISTS pool_id text NOT NULL DEFAULT '';
ALTER TABLE cloud_operations ADD COLUMN IF NOT EXISTS generation bigint NOT NULL DEFAULT 0;
ALTER TABLE cloud_operations ADD COLUMN IF NOT EXISTS amount integer NOT NULL DEFAULT 0;
ALTER TABLE cloud_operations ADD COLUMN IF NOT EXISTS error text NOT NULL DEFAULT '';
ALTER TABLE cloud_operations ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS cloud_instances_pool_idx ON cloud_instances(provider,pool_id,state);
CREATE INDEX IF NOT EXISTS cloud_operations_active_idx ON cloud_operations(provider,pool_id,operation,state,updated_at);
`

type controller struct {
	ctx       context.Context
	cancel    context.CancelFunc
	db        *pgxpool.Pool
	server    *control.Server
	cfg       config
	configErr error
	ecs       *ecs.Client
	cms       *cms.Client
	vpc       *vpc.Client
	cfgMu     sync.RWMutex
	reconcile sync.Mutex
	wg        sync.WaitGroup
	account   accountSettings
}

// Start installs the selected provider and starts periodic pool reconciliation.
// SCAN_CLOUD_PROVIDER defaults to manual, which never calls a cloud API.
func Start(ctx context.Context, databaseURL string, server *control.Server) (close func(), err error) {
	if server == nil {
		return nil, errors.New("control server is required")
	}
	cfg, cfgErr := configFromEnv()
	if cfg.provider != "manual" && cfg.provider != "aliyun" {
		return nil, cfgErr
	}
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open cloud database: %w", err)
	}
	if err = db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping cloud database: %w", err)
	}
	if _, err = db.Exec(ctx, cloudSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate cloud database: %w", err)
	}
	var account accountSettings
	if cfg.provider == "aliyun" {
		var saved bool
		account, saved, err = loadAccount(ctx, db, &cfg)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("load cloud account: %w", err)
		}
		if saved {
			cfgErr = cfg.validate()
		}
		if err := loadStoredSettings(ctx, db, &cfg); err != nil {
			db.Close()
			return nil, fmt.Errorf("load cloud settings: %w", err)
		}
	}
	cloudCtx, cancel := context.WithCancel(ctx)
	c := &controller{ctx: cloudCtx, cancel: cancel, db: db, server: server, cfg: cfg, configErr: cfgErr, account: account}
	if cfg.provider == "aliyun" && cfgErr == nil {
		c.ecs, c.cms, c.vpc, c.configErr = newAliyunClients(cfg)
	}
	server.SetPoolProvider(cfg.provider, c.configured, c.Reconcile)
	server.SetCloudSetup(c.Setup)
	server.SetCloudAdmin(c.adminSettings)
	c.wg.Add(1)
	go c.loop()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			c.wg.Wait()
			db.Close()
		})
	}, nil
}

func (c *controller) configured() bool {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.cfg.provider == "manual" || (c.configErr == nil && c.cfg.readyError() == nil)
}

func (c *controller) loop() {
	defer c.wg.Done()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		pool, err := c.loadPool(c.ctx)
		if err != nil {
			slog.Error("load worker pool for cloud reconcile", "error", err)
		} else {
			ctx, cancel := context.WithTimeout(c.ctx, 90*time.Second)
			_ = c.Reconcile(ctx, pool)
			cancel()
		}
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *controller) loadPool(ctx context.Context) (control.Pool, error) {
	var pool control.Pool
	err := c.db.QueryRow(ctx, `SELECT desired_workers,enabled,generation,healthy_workers,starting_workers,
		draining_workers,provider,configured,error FROM worker_pool WHERE singleton`).Scan(
		&pool.DesiredWorkers, &pool.Enabled, &pool.Generation, &pool.HealthyWorkers, &pool.StartingWorkers,
		&pool.DrainingWorkers, &pool.Provider, &pool.Configured, &pool.Error)
	return pool, err
}

// Reconcile is safe to call from both the API-triggered path and the periodic loop.
func (c *controller) Reconcile(ctx context.Context, pool control.Pool) error {
	if !c.reconcile.TryLock() {
		return nil
	}
	defer c.reconcile.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	// API-triggered callbacks are snapshots. Re-read after taking the lock so a
	// delayed reconcile cannot create against an older enabled/generation value.
	fresh, err := c.loadPool(ctx)
	if err != nil {
		return err
	}
	pool = fresh
	if c.configErr != nil {
		return c.server.UpdatePoolRuntime(ctx, c.cfg.provider, false, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, c.configErr.Error())
	}
	if c.cfg.provider == "manual" {
		return c.reconcileManual(ctx, pool)
	}
	if err := c.cfg.readyError(); err != nil {
		return c.server.UpdatePoolRuntime(ctx, "aliyun", false, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, err.Error())
	}
	return c.reconcileAliyun(ctx, pool)
}

func (c *controller) reconcileManual(ctx context.Context, pool control.Pool) error {
	workers, err := c.server.WorkerInstances(ctx)
	if err != nil {
		_ = c.server.UpdatePoolRuntime(ctx, "manual", true, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, err.Error())
		return err
	}
	if !pool.Enabled {
		for id, worker := range workers {
			if worker.Status != "draining" {
				if err := c.server.MarkInstanceDraining(ctx, id, "worker pool disabled", nil); err == nil {
					worker.Status = "draining"
					workers[id] = worker
				}
			}
		}
	}
	healthy, draining := 0, 0
	for _, worker := range workers {
		switch worker.Status {
		case "ready", "running":
			healthy++
		case "draining":
			draining++
		}
	}
	quotaError := ""
	allocations, err := c.server.UnknownWorkerQuotas(ctx)
	if err != nil {
		quotaError = "load unknown worker allocations: " + err.Error()
	} else {
		for _, allocation := range allocations {
			if !allocation.RevokeDeadline.IsZero() && time.Now().After(allocation.RevokeDeadline) {
				quotaError = "blocked_quota_unknown: manual worker stop requires confirmation; target allocations remain reserved"
				break
			}
		}
	}
	return c.server.UpdatePoolRuntime(ctx, "manual", true, healthy, 0, draining, quotaError)
}

func joinErrors(errs ...error) string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	return strings.Join(parts, "; ")
}
