package control

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStorageStatusCachesSuccessAndFailure(t *testing.T) {
	// No database is attached: a cached response must not initiate storage reads.
	s := &Server{}
	s.storage.next = time.Now().Add(time.Minute)
	s.storage.value = storageSnapshot{ObservedAt: time.Now().UTC(), DatabaseBytes: 4096, Tables: []storageTable{{Name: "assets", EstimatedRows: 100}}}
	s.servicePressure.next = time.Now().Add(time.Minute)
	s.servicePressure.value = servicePressure{Available: true, SampleLimit: 1024}
	for i := 0; i < 2; i++ {
		out := httptest.NewRecorder()
		s.storageStatus(out, httptest.NewRequest("GET", "/api/storage/status", nil))
		var response struct {
			DatabaseBytes int64  `json:"database_bytes"`
			Free          *int64 `json:"database_free_disk_bytes"`
			CacheSeconds  int    `json:"cache_seconds"`
		}
		if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil || out.Code != 200 || response.DatabaseBytes != 4096 || response.Free != nil || response.CacheSeconds != 60 {
			t.Fatalf("cached response: %d %s %v", out.Code, out.Body.String(), err)
		}
	}
	s.storage.err = errors.New("fixture database unavailable")
	out := httptest.NewRecorder()
	s.storageStatus(out, httptest.NewRequest("GET", "/api/storage/status", nil))
	if out.Code != 503 {
		t.Fatalf("cached failure returned %d", out.Code)
	}
}
