package control

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxJSONBody       = 8 << 20
	maxBatchItems     = 2000
	leaseDuration     = 120 * time.Second
	rateDuration      = 60 * time.Second
	heartbeatInterval = 10
)

type Server struct {
	db         *pgxpool.Pool
	adminHash  [32]byte
	joinHash   [32]byte
	allowLocal bool
	ctx        context.Context
	cancel     context.CancelFunc

	providerMu sync.RWMutex
	provider   string
	configured func() bool
	reconcile  PoolReconciler
	cloudSetup func(context.Context) (map[string]any, error)
	cloudAdmin http.HandlerFunc

	sourceMu        sync.Mutex
	sourceRunning   map[string]bool
	servicePressure servicePressureCache
}

func New(ctx context.Context, databaseURL, adminToken, joinToken string) (*Server, error) {
	if databaseURL == "" || adminToken == "" || joinToken == "" {
		return nil, errors.New("DATABASE_URL, SCAN_ADMIN_TOKEN and SCAN_JOIN_TOKEN are required")
	}
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err = db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if _, err = db.Exec(ctx, schema+httpBudgetSchema+servicePressureSchema+webScreenshotSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	if err = seedRuleLibrary(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed rule library: %w", err)
	}
	if err = backfillTargetKeys(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("index result targets: %w", err)
	}
	if err = initializeRuleSources(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize rule sources: %w", err)
	}
	if err = initializeFingerprintBundles(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize fingerprint bundles: %w", err)
	}
	serverCtx, cancel := context.WithCancel(ctx)
	return &Server{
		db:            db,
		adminHash:     sha256.Sum256([]byte(adminToken)),
		joinHash:      sha256.Sum256([]byte(joinToken)),
		allowLocal:    strings.EqualFold(os.Getenv("SCAN_ALLOW_PRIVATE_TARGETS"), "true"),
		ctx:           serverCtx,
		cancel:        cancel,
		sourceRunning: make(map[string]bool),
	}, nil
}

func (s *Server) Close() {
	s.cancel()
	s.db.Close()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/scheduler/status", s.admin(s.schedulerStatus))
	mux.HandleFunc("GET /api/library/fingerprint-bundles", s.admin(s.getFingerprintBundleStatus))
	mux.HandleFunc("GET /api/library/http-fingerprints", s.admin(s.listHTTPFingerprints))
	mux.HandleFunc("GET /api/library/http-fingerprints/{id}", s.admin(s.getHTTPFingerprint))
	mux.HandleFunc("POST /api/library/fingerprint-bundles/import", s.admin(s.importHTTPBundle))
	mux.HandleFunc("GET /api/library/fingerprint-bundles/{digest}", s.admin(s.getFingerprintBundle))
	mux.HandleFunc("GET /api/library", s.admin(s.listLibrary))
	mux.HandleFunc("POST /api/library", s.admin(s.createLibraryRule))
	mux.HandleFunc("GET /api/library/export", s.admin(s.exportLibrary))
	mux.HandleFunc("GET /api/library/products", s.admin(s.listLibraryProducts))
	mux.HandleFunc("POST /api/library/import", s.admin(s.importLibrary))
	mux.HandleFunc("POST /api/library/delete", s.admin(s.deleteLibraryRules))
	mux.HandleFunc("GET /api/library/sources", s.admin(s.listRuleSources))
	mux.HandleFunc("GET /api/library/sources/{id}/license", s.admin(s.getRuleSourceLicense))
	mux.HandleFunc("GET /api/library/sources/{id}/files", s.admin(s.listRuleSourceFiles))
	mux.HandleFunc("GET /api/library/sources/{id}/files/raw", s.admin(s.getRuleSourceFile))
	mux.HandleFunc("GET /api/library/sources/{id}/catalog", s.admin(s.listRuleSourceCatalog))
	mux.HandleFunc("GET /api/library/sources/{id}/catalog/{ruleID}", s.admin(s.getRuleSourceCatalogRule))
	mux.HandleFunc("GET /api/library/sources/{id}/export", s.admin(s.exportRuleSource))
	mux.HandleFunc("POST /api/library/sources/{id}/update", s.admin(s.updateRuleSource))
	mux.HandleFunc("GET /api/library/{id}", s.admin(s.getLibraryRule))
	mux.HandleFunc("PUT /api/library/{id}", s.admin(s.updateLibraryRule))
	mux.HandleFunc("PATCH /api/library/{id}", s.admin(s.patchLibraryRule))
	mux.HandleFunc("DELETE /api/library/{id}", s.admin(s.deleteLibraryRule))
	mux.HandleFunc("POST /api/runs", s.admin(s.createRun))
	mux.HandleFunc("GET /api/runs", s.admin(s.listRuns))
	mux.HandleFunc("GET /api/runs/{id}", s.admin(s.getRun))
	mux.HandleFunc("POST /api/runs/{id}/cancel", s.admin(s.cancelRun))
	mux.HandleFunc("POST /api/runs/{id}/pause", s.admin(s.pauseRun))
	mux.HandleFunc("POST /api/runs/{id}/resume", s.admin(s.resumeRun))
	mux.HandleFunc("GET /api/observations/{id}/screenshot", s.admin(s.getObservationScreenshot))
	mux.HandleFunc("GET /api/assets", s.admin(s.listAssets))
	mux.HandleFunc("GET /api/runs/{id}/results", s.admin(s.listTargetResults))
	mux.HandleFunc("GET /api/runs/{id}/ports", s.admin(s.listPortResults))
	mux.HandleFunc("GET /api/runs/{id}/http", s.admin(s.listHTTPResults))
	mux.HandleFunc("GET /api/runs/{id}/findings", s.admin(s.listFindings))
	mux.HandleFunc("GET /api/observations/{id}", s.admin(s.getObservation))
	mux.HandleFunc("GET /api/cloud/aliyun", s.admin(s.handleCloudAdmin))
	mux.HandleFunc("PUT /api/cloud/aliyun", s.admin(s.handleCloudAdmin))
	mux.HandleFunc("POST /api/cloud/aliyun/verify", s.admin(s.handleCloudAdmin))
	mux.HandleFunc("GET /api/cloud/aliyun/instances", s.admin(s.handleCloudAdmin))
	mux.HandleFunc("GET /api/workers", s.admin(s.listWorkers))
	mux.HandleFunc("POST /api/workers/{id}/maintenance", s.admin(s.setWorkerMaintenance))
	mux.HandleFunc("GET /api/worker-pool", s.admin(s.getPool))
	mux.HandleFunc("PATCH /api/worker-pool", s.admin(s.patchPool))
	mux.HandleFunc("POST /api/worker-pool/setup-cloud", s.admin(s.setupCloud))
	mux.HandleFunc("POST /api/workers/register", s.join(s.registerWorker))
	mux.HandleFunc("POST /api/workers/heartbeat", s.worker(s.heartbeat))
	mux.HandleFunc("POST /api/tasks/claim", s.worker(s.claimTask))
	mux.HandleFunc("GET /api/tasks/{id}/fingerprint-bundle", s.worker(s.getTaskFingerprintBundle))
	mux.HandleFunc("GET /api/tasks/{id}/rules", s.worker(s.getTaskRules))
	mux.HandleFunc("POST /api/tasks/{id}/renew", s.worker(s.renewTask))
	mux.HandleFunc("POST /api/tasks/{id}/http-permit", s.worker(s.httpPermit))
	mux.HandleFunc("POST /api/tasks/{id}/batches", s.worker(s.submitBatch))
	mux.HandleFunc("POST /api/tasks/{id}/complete", s.worker(s.completeTask))
	mux.HandleFunc("POST /api/tasks/{id}/release", s.worker(s.releaseTask))
	handler := gzipJSON(recoverer(mux))
	if os.Getenv("SCAN_HTTP_TIMING") != "true" {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		out := &responseStats{ResponseWriter: w}
		handler.ServeHTTP(out, r)
		slog.Info("http_timing", "route", r.Pattern, "status", out.status, "duration_us", time.Since(start).Microseconds(), "request_bytes", r.ContentLength, "response_bytes", out.bytes)
	})
}

func gzipJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if binaryResponsePath(r.URL.Path) || !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")
		writer := gzip.NewWriter(w)
		defer writer.Close()
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, writer: writer}, r)
	})
}

func binaryResponsePath(value string) bool {
	if strings.HasPrefix(value, "/api/observations/") && strings.HasSuffix(value, "/screenshot") {
		return true
	}
	return (strings.HasPrefix(value, "/api/library/sources/") &&
		(strings.HasSuffix(value, "/files/raw") || strings.HasSuffix(value, "/export")))
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w *gzipResponseWriter) Write(data []byte) (int, error) { return w.writer.Write(data) }

func acceptsGzip(value string) bool {
	explicit, explicitQuality := false, float64(0)
	wildcardQuality := float64(0)
	for _, part := range strings.Split(value, ",") {
		segments := strings.Split(part, ";")
		coding := strings.ToLower(strings.TrimSpace(segments[0]))
		if coding != "gzip" && coding != "*" {
			continue
		}
		quality := float64(1)
		for _, parameter := range segments[1:] {
			name, raw, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				quality = 0
			} else {
				quality = parsed
			}
		}
		if coding == "gzip" {
			explicit = true
			if quality > explicitQuality {
				explicitQuality = quality
			}
		} else if quality > wildcardQuality {
			wildcardQuality = quality
		}
	}
	if explicit {
		return explicitQuality > 0
	}
	return wildcardQuality > 0
}

type responseStats struct {
	http.ResponseWriter
	status, bytes int
}

func (w *responseStats) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *responseStats) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += n
	return n, err
}

func (s *Server) SetCloudAdmin(handler http.HandlerFunc) {
	s.providerMu.Lock()
	s.cloudAdmin = handler
	s.providerMu.Unlock()
}

func (s *Server) handleCloudAdmin(w http.ResponseWriter, r *http.Request) {
	s.providerMu.RLock()
	handler := s.cloudAdmin
	s.providerMu.RUnlock()
	if handler == nil {
		writeError(w, http.StatusServiceUnavailable, "云配置暂不可用")
		return
	}
	handler(w, r)
}

func (s *Server) SetCloudSetup(setup func(context.Context) (map[string]any, error)) {
	s.providerMu.Lock()
	s.cloudSetup = setup
	s.providerMu.Unlock()
}

func (s *Server) SetPoolProvider(name string, configured func() bool, reconcile PoolReconciler) {
	s.providerMu.Lock()
	s.provider, s.configured, s.reconcile = name, configured, reconcile
	s.providerMu.Unlock()
	isConfigured := configured != nil && configured()
	_, err := s.db.Exec(s.ctx, `UPDATE worker_pool SET provider=$1, configured=$2, updated_at=now() WHERE singleton`, name, isConfigured)
	if err != nil {
		slog.Error("update pool provider", "error", err)
	}
}

func (s *Server) triggerReconcile(pool Pool) {
	s.providerMu.RLock()
	reconcile := s.reconcile
	s.providerMu.RUnlock()
	if reconcile == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
		defer cancel()
		if err := reconcile(ctx, pool); err != nil {
			slog.Error("reconcile worker pool", "generation", pool.Generation, "error", err)
			_ = s.UpdatePoolRuntime(context.Background(), pool.Provider, pool.Configured, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, err.Error())
		}
	}()
}

func (s *Server) UpdatePoolRuntime(ctx context.Context, provider string, configured bool, healthy, starting, draining int, errorText string) error {
	_, err := s.db.Exec(ctx, `UPDATE worker_pool SET provider=$1, configured=$2, healthy_workers=$3,
		starting_workers=$4, draining_workers=$5, error=$6, updated_at=now() WHERE singleton`,
		provider, configured, healthy, starting, draining, errorText)
	return err
}

func (s *Server) WorkerInstances(ctx context.Context) (map[string]Worker, error) {
	_, _ = s.db.Exec(ctx, `UPDATE workers SET status='offline'
		WHERE last_heartbeat < now()-interval '45 seconds' AND status <> 'offline'`)
	rows, err := s.db.Query(ctx, `SELECT id,instance_id,hostname,status,agent_version,last_heartbeat,
		COALESCE(current_task_id,''),az,spec,metrics,maintenance,session_id FROM workers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]Worker)
	for rows.Next() {
		var w Worker
		var metrics []byte
		if err := rows.Scan(&w.ID, &w.InstanceID, &w.Hostname, &w.Status, &w.AgentVersion, &w.LastHeartbeat, &w.CurrentTaskID, &w.AZ, &w.Spec, &metrics, &w.Maintenance, &w.SessionID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(metrics, &w.Metrics); err != nil {
			return nil, fmt.Errorf("decode worker metrics: %w", err)
		}
		w.LastHeartbeat = w.LastHeartbeat.UTC()
		out[w.InstanceID] = w
	}
	return out, rows.Err()
}

func (s *Server) ActiveTasksForInstance(ctx context.Context, instanceID string) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM tasks t JOIN workers w ON w.id=t.worker_id
		WHERE w.instance_id=$1 AND t.state='leased' AND t.lease_until > now()`, instanceID).Scan(&count)
	return count, err
}

func (s *Server) MarkInstanceDraining(ctx context.Context, instanceID, reason string, terminationAt *time.Time) error {
	result, err := s.db.Exec(ctx, `UPDATE workers SET status='draining', spec=spec || jsonb_build_object(
		'drain_reason',$2::text,'termination_at',$3::text) WHERE instance_id=$1`, instanceID, reason, timeText(terminationAt))
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatches(r, s.adminHash) {
			writeError(w, http.StatusUnauthorized, "invalid administrator token")
			return
		}
		next(w, r)
	}
}

func (s *Server) join(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatches(r, s.joinHash) {
			writeError(w, http.StatusUnauthorized, "invalid worker join token")
			return
		}
		next(w, r)
	}
}

func (s *Server) worker(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "worker token required")
			return
		}
		ctx := context.WithValue(r.Context(), workerTokenKey{}, sha256.Sum256([]byte(token)))
		next(w, r.WithContext(ctx))
	}
}

type workerTokenKey struct{}

func tokenMatches(r *http.Request, expected [32]byte) bool {
	got := sha256.Sum256([]byte(bearer(r)))
	return subtle.ConstantTimeCompare(got[:], expected[:]) == 1
}

func bearer(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[7:])
}

func (s *Server) authenticateWorker(ctx context.Context, workerID, sessionID string) error {
	hash, ok := ctx.Value(workerTokenKey{}).([32]byte)
	if !ok || workerID == "" || sessionID == "" {
		return errors.New("worker_id and session_id are required")
	}
	var stored []byte
	if err := s.db.QueryRow(ctx, `SELECT token_hash FROM workers WHERE id=$1 AND session_id=$2`, workerID, sessionID).Scan(&stored); err != nil {
		return errors.New("invalid worker credentials")
	}
	if subtle.ConstantTimeCompare(hash[:], stored) != 1 {
		return errors.New("invalid worker credentials")
	}
	return nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return decodeJSONLimit(w, r, dst, maxJSONBody)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func consumeEmptyAction(w http.ResponseWriter, r *http.Request) bool {
	// An unread body on Connection: close can reset TLS during a large response.
	if r.Body != nil && r.Body != http.NoBody {
		var body struct{}
		if err := decodeJSON(w, r, &body); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, err.Error())
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func newID() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func newToken() string {
	var value [32]byte
	_, _ = rand.Read(value[:])
	return hex.EncodeToString(value[:])
}

func timeText(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("request panic", "error", recovered)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
