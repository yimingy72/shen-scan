package control

import (
	"encoding/json"
	"testing"
)

func TestDomainProducesOnlyHTTPTask(t *testing.T) {
	seeds, err := buildTaskSeeds([]string{"example.com"}, []string{"port", "http"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 1 || seeds[0].typeName != "http" {
		t.Fatalf("expected one HTTP task, got %#v", seeds)
	}
	payload, _ := json.Marshal(seeds[0].payload)
	if string(payload) != `{"endpoints":[{"host":"example.com","url":"http://example.com"},{"host":"example.com","url":"https://example.com"}],"execution_timeout_seconds":180,"timeout_seconds":12}` {
		t.Fatalf("unexpected payload: %s", payload)
	}
}

func TestCIDRExpansionAndPrivateBoundary(t *testing.T) {
	seeds, err := buildTaskSeeds([]string{"192.0.2.0/30"}, []string{"port"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeds) != 4 {
		t.Fatalf("expected all four CIDR addresses, got %d", len(seeds))
	}
	if _, err := buildTaskSeeds([]string{"127.0.0.1"}, []string{"http"}, false); err == nil {
		t.Fatal("expected loopback to be rejected")
	}
	if _, err := buildTaskSeeds([]string{"127.0.0.1"}, []string{"http"}, true); err != nil {
		t.Fatalf("explicit private-target mode should allow loopback: %v", err)
	}
}

func TestValidateWorkerMetrics(t *testing.T) {
	metrics, err := validateWorkerMetrics(json.RawMessage(`{"active_tasks":2,"cpu_percent":17.5,"mem_total_mib":2048}`))
	if err != nil || metrics["active_tasks"] != 2 {
		t.Fatalf("valid metrics rejected: metrics=%v err=%v", metrics, err)
	}
	if _, err := validateWorkerMetrics(json.RawMessage(`{"unknown":1}`)); err == nil {
		t.Fatal("unknown metric must be rejected")
	}
	if _, err := validateWorkerMetrics(json.RawMessage(`{"cpu_percent":101}`)); err == nil {
		t.Fatal("out-of-range metric must be rejected")
	}
}
