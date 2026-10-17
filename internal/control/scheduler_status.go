package control

import "net/http"

func (s *Server) schedulerStatus(w http.ResponseWriter, r *http.Request) {
	budget, err := s.HTTPBudgetStatus(r.Context())
	if err != nil {
		writeError(w, 503, "load HTTP admission status failed")
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, 503, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	_, maximum := portScanSettings()
	port, err := loadAdaptiveBatch(r.Context(), tx, "port", maximum, 90)
	if err != nil {
		writeError(w, 503, "load port batch model failed")
		return
	}
	service, err := loadAdaptiveBatch(r.Context(), tx, "service", 32, 45)
	if err != nil {
		writeError(w, 503, "load service batch model failed")
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT t.type,count(*) FILTER(WHERE t.state='queued'),
 count(*) FILTER(WHERE t.state='leased'),COALESCE(max(extract(epoch FROM now()-t.created_at)) FILTER(WHERE t.state='queued'),0)::float8
 FROM tasks t JOIN runs r ON r.id=t.run_id WHERE r.status IN('pending','running') AND t.state IN('queued','leased') GROUP BY t.type`)
	if err != nil {
		writeError(w, 503, "load scheduler queues failed")
		return
	}
	type stageStatus struct {
		Stage         string  `json:"stage"`
		Queued        int64   `json:"queued"`
		Running       int64   `json:"running"`
		OldestSeconds float64 `json:"oldest_seconds"`
	}
	stages := make([]stageStatus, 0, 4)
	for rows.Next() {
		var stage stageStatus
		if err = rows.Scan(&stage.Stage, &stage.Queued, &stage.Running, &stage.OldestSeconds); err != nil {
			break
		}
		stages = append(stages, stage)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		writeError(w, 503, "read scheduler queues failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, 503, "database unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"http_budget": budget, "port_batch": port, "service_batch": service, "stages": stages, "port_range": "1-65535", "service_pressure": s.servicePressureSnapshot(r.Context())})
}
