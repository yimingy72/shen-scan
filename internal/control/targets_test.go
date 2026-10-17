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
	if len(seeds) != 2 {
		t.Fatalf("expected independent HTTP and HTTPS tasks, got %#v", seeds)
	}
	for i, scheme := range []string{"http", "https"} {
		payload, _ := json.Marshal(seeds[i].payload)
		var p struct {
			Endpoints         []taskEndpoint
			FingerprintBundle string `json:"fingerprint_bundle"`
			WebProfile        string `json:"web_profile"`
		}
		if seeds[i].typeName != "http" || json.Unmarshal(payload, &p) != nil || len(p.Endpoints) != 1 || p.Endpoints[0].Host != "example.com" || p.Endpoints[0].URL != scheme+"://example.com" || p.FingerprintBundle == "" || p.WebProfile == "" {
			t.Fatalf("unexpected entry: %s", payload)
		}
	}
}

func TestP0WebInputSchemes(t *testing.T) {
	for _, target := range []string{"192.0.2.1", "2001:db8::1"} {
		seeds, err := buildTaskSeeds([]string{target}, []string{"http"}, false)
		if err != nil || len(seeds) != 2 {
			t.Fatalf("%s: seeds=%v error=%v", target, seeds, err)
		}
		host := target
		if target == "2001:db8::1" {
			host = "[" + target + "]"
		}
		for i, scheme := range []string{"http", "https"} {
			endpoints := seeds[i].payload.(map[string]any)["endpoints"].([]map[string]any)
			if len(endpoints) != 1 || endpoints[0]["url"] != scheme+"://"+host || endpoints[0]["ip"] != target {
				t.Fatalf("%s: unexpected endpoint %v", target, endpoints)
			}
		}
	}
	for _, target := range []string{"http://example.com/only-http?q=1", "https://example.com/only-https?q=2"} {
		seeds, err := buildTaskSeeds([]string{target}, []string{"http"}, false)
		if err != nil || len(seeds) != 1 {
			t.Fatalf("explicit URL %s: seeds=%v error=%v", target, seeds, err)
		}
		endpoints := seeds[0].payload.(map[string]any)["endpoints"].([]map[string]any)
		if len(endpoints) != 1 || endpoints[0]["url"] != target {
			t.Fatalf("explicit URL changed: %v", endpoints)
		}
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
