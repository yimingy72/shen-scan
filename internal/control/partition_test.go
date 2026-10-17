package control

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestAdaptiveShardsPreserveTargets(t *testing.T) {
	t.Setenv("SCAN_PORT_RATE_PPS", "")
	t.Setenv("SCAN_PORT_SHARD_MAX", "")
	var targets []string
	for i := 0; i < 1000; i++ {
		targets = append(targets, fmt.Sprintf("198.51.%d.%d", i/256, i%256))
	}
	targets = append(targets, targets[0])
	seeds, err := buildTaskSeeds(targets, []string{"port", "http"}, false)
	if err != nil {
		t.Fatal(err)
	}
	shards := shardPortSeeds(seeds, 5)
	if len(shards) != 250 {
		t.Fatalf("got %d shards", len(shards))
	}
	seen := map[string]bool{}
	for _, seed := range shards {
		raw, _ := json.Marshal(seed.payload)
		keys := taskTargetKeys(raw)
		if len(keys) != 4 {
			t.Fatalf("unexpected shard size %d", len(keys))
		}
		for _, key := range keys {
			if seen[key] {
				t.Fatalf("duplicate target %s", key)
			}
			seen[key] = true
		}
		var payload struct {
			Ports                   string
			RatePPS                 int `json:"rate_pps"`
			WaitSeconds             int `json:"wait_seconds"`
			TimeoutSeconds          int `json:"timeout_seconds"`
			ExecutionTimeoutSeconds int `json:"execution_timeout_seconds"`
		}
		_ = json.Unmarshal(raw, &payload)
		if payload.Ports != "1-65535" {
			t.Fatal("full port range changed")
		}
		if payload.RatePPS != 5000 || payload.WaitSeconds != 15 || payload.TimeoutSeconds != 180 || payload.ExecutionTimeoutSeconds != 180 {
			t.Fatalf("default port budget changed: %#v", payload)
		}
		if _, err = observationTarget("port", raw, keys[0], Observation{Kind: "port", IP: keys[3], Port: 65535}); err != nil {
			t.Fatal(err)
		}
		if _, err = observationTarget("port", raw, keys[0], Observation{Kind: "port", IP: "203.0.113.1", Port: 80}); err == nil {
			t.Fatal("out-of-shard result accepted")
		}
	}
	if len(seen) != 1000 {
		t.Fatal("lost targets")
	}
}

func TestPortScanSettingsBoundShardToExecutionBudget(t *testing.T) {
	tests := []struct {
		name, rate, shard string
		wantRate, wantMax int
	}{
		{name: "defaults", wantRate: 5000, wantMax: 4},
		{name: "configured test candidate", rate: "20000", shard: "8", wantRate: 20000, wantMax: 8},
		{name: "maximum", rate: "20000", shard: "16", wantRate: 20000, wantMax: 16},
		{name: "rate limits safe shard", rate: "5000", shard: "16", wantRate: 5000, wantMax: 5},
		{name: "minimum rate", rate: "1000", shard: "16", wantRate: 1000, wantMax: 1},
		{name: "invalid values use defaults", rate: "999", shard: "17", wantRate: 5000, wantMax: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SCAN_PORT_RATE_PPS", test.rate)
			t.Setenv("SCAN_PORT_SHARD_MAX", test.shard)
			rate, shardMax := portScanSettings()
			if rate != test.wantRate || shardMax != test.wantMax {
				t.Fatalf("got rate=%d shard=%d, want rate=%d shard=%d", rate, shardMax, test.wantRate, test.wantMax)
			}
		})
	}
}

func TestSmallPortRunUsesOneWavePerWorker(t *testing.T) {
	t.Setenv("SCAN_PORT_RATE_PPS", "5000")
	t.Setenv("SCAN_PORT_SHARD_MAX", "4")
	var targets []string
	for i := 1; i <= 11; i++ {
		targets = append(targets, fmt.Sprintf("198.51.100.%d", i))
	}
	seeds, err := buildTaskSeeds(targets, []string{"port"}, false)
	if err != nil {
		t.Fatal(err)
	}
	shards := shardPortSeeds(seeds, 5)
	if len(shards) != 5 {
		t.Fatalf("got %d shards, want one per worker", len(shards))
	}
	total, smallest, largest := 0, len(targets), 0
	for _, shard := range shards {
		raw, _ := json.Marshal(shard.payload)
		width := len(taskTargetKeys(raw))
		total += width
		smallest, largest = min(smallest, width), max(largest, width)
	}
	if total != len(targets) || largest-smallest > 1 || largest > 4 {
		t.Fatalf("unbalanced shards: total=%d smallest=%d largest=%d", total, smallest, largest)
	}
}

func TestDenseFingerprintPolicyRetainsPortEvidence(t *testing.T) {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	selected := sampleFingerprintPorts(ports, 1024)
	if len(ports) != 65535 || len(selected) != 1024 {
		t.Fatal("port evidence changed or sample size is wrong")
	}
	for _, wanted := range []int{1, 22, 80, 443, 8080, 8443, 65535} {
		found := false
		for _, p := range selected {
			found = found || p == wanted
		}
		if !found {
			t.Fatalf("missing required coverage sample %d", wanted)
		}
	}
}
