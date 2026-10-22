package control

import (
	"context"
	"net/http"
	"sync"
	"time"
)

type storageTable struct {
	Name                    string     `json:"name"`
	EstimatedRows           int64      `json:"estimated_rows"`
	EstimatedDeadRows       int64      `json:"estimated_dead_rows"`
	EstimatedAllocatedBytes int64      `json:"estimated_allocated_bytes"`
	LastAnalyze             *time.Time `json:"last_analyze"`
}
type storageSnapshot struct {
	ObservedAt    time.Time      `json:"observed_at"`
	DatabaseBytes int64          `json:"database_bytes"`
	Tables        []storageTable `json:"tables"`
}
type storageStatusCache struct {
	mu    sync.Mutex
	next  time.Time
	value storageSnapshot
	err   error
}

func (s *Server) storageStatus(w http.ResponseWriter, r *http.Request) {
	// This admin read is cached independently of the frequently polled scheduler.
	// pg_database_size visits relation files, so never run it on every poll.
	s.storage.mu.Lock()
	if time.Now().After(s.storage.next) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		snapshot, err := s.loadStorageStatus(ctx)
		s.storage.value, s.storage.err = snapshot, err
		s.storage.next = time.Now().Add(time.Minute)
	}
	snapshot, err := s.storage.value, s.storage.err
	s.storage.mu.Unlock()
	if err != nil {
		writeError(w, 503, "storage statistics unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"observed_at": snapshot.ObservedAt, "database_bytes": snapshot.DatabaseBytes,
		"tables": snapshot.Tables, "table_sizes_are_estimates": true, "cache_seconds": 60,
		"database_free_disk_bytes": nil, "disk_capacity_available": false, "service_pressure": s.servicePressureSnapshot(r.Context())})
}
func (s *Server) loadStorageStatus(ctx context.Context) (storageSnapshot, error) {
	out := storageSnapshot{Tables: make([]storageTable, 0), ObservedAt: time.Now().UTC()}
	if err := s.db.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&out.DatabaseBytes); err != nil {
		return out, err
	}
	rows, err := s.db.Query(ctx, `SELECT c.relname,COALESCE(st.n_live_tup,0),COALESCE(st.n_dead_tup,0),
 (GREATEST(c.relpages,0)::bigint+COALESCE((SELECT sum(GREATEST(i.relpages,0)) FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid WHERE x.indrelid=c.oid),0)
 +COALESCE((SELECT GREATEST(t.relpages,0)::bigint+COALESCE((SELECT sum(GREATEST(i.relpages,0)) FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid WHERE x.indrelid=t.oid),0) FROM pg_class t WHERE t.oid=c.reltoastrelid),0))*current_setting('block_size')::bigint,
 GREATEST(st.last_analyze,st.last_autoanalyze)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_stat_user_tables st ON st.relid=c.oid
 WHERE n.nspname=current_schema() AND c.relkind='r' AND c.relname=ANY($1) ORDER BY c.relname`, []string{"runs", "tasks", "assets", "task_batches", "http_screenshots", "claim_requests", "target_quotas", "task_item_completions", "port_positive_receipts", "port_range_manifest", "port_service_work", "poc_template_receipts", "fingerprint_bundles", "rule_library"})
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var table storageTable
		if err = rows.Scan(&table.Name, &table.EstimatedRows, &table.EstimatedDeadRows, &table.EstimatedAllocatedBytes, &table.LastAnalyze); err != nil {
			return out, err
		}
		out.Tables = append(out.Tables, table)
	}
	return out, rows.Err()
}
