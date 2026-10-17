package rulesource

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"scanplatform/internal/rulelib"
)

func TestConvertWappalyzerPreservesRawApps(t *testing.T) {
	data := []byte(`{"apps":{"Header Tech": {"headers":{"server":"^HeaderTech"},"js":{"HeaderTech":""}},"Runtime Only":{"js":{"Runtime":""},"implies":["JavaScript"]}}}`)
	catalog, err := ConvertWappalyzer(data)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total != 2 || len(catalog.Rules) != 2 || len(catalog.Skipped) != 0 || len(catalog.Files) != 1 {
		t.Fatalf("unexpected catalog: %+v", catalog)
	}
	if catalog.Files[0].Path != "fingerprints_data.json" || !bytes.Equal(catalog.Files[0].Data, data) {
		t.Fatal("original Wappalyzer catalog bytes were not retained")
	}
	for _, rule := range catalog.Rules {
		if err := rulelib.Validate(rule); err != nil {
			t.Fatalf("rule %q invalid: %v", rule.ID, err)
		}
		if rule.Engine != "httpx-cff" || rule.Kind != "http" || rule.Purpose != "discovery" || !rule.Enabled ||
			len(rule.Fingerprint) == 0 || len(rule.Definition.Matchers) != 0 || rule.Upstream == nil || rule.Upstream.Path != "fingerprints_data.json" {
			t.Fatalf("invalid raw fingerprint rule: %+v", rule)
		}
		var raw map[string]any
		if json.Unmarshal(rule.Fingerprint, &raw) != nil || raw == nil {
			t.Fatalf("fingerprint is not an original app object: %s", rule.Fingerprint)
		}
	}
	first, _ := ConvertWappalyzer(data)
	second, _ := ConvertWappalyzer(data)
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if !bytes.Equal(left, right) {
		t.Fatal("Wappalyzer conversion is not deterministic")
	}
}

func TestConvertWappalyzerCorpus(t *testing.T) {
	filePath := os.Getenv("WAPPALYZER_FIXTURE")
	if filePath == "" {
		t.Skip("set WAPPALYZER_FIXTURE to run the upstream corpus check")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ConvertWappalyzer(data)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total < 7000 || len(catalog.Rules) != catalog.Total-sumSkipped(catalog.Skipped) {
		t.Fatalf("unexpected corpus accounting: total=%d rules=%d skipped=%v", catalog.Total, len(catalog.Rules), catalog.Skipped)
	}
	for _, rule := range catalog.Rules {
		if err := rulelib.Validate(rule); err != nil {
			t.Fatalf("rule %q invalid: %v", rule.ID, err)
		}
	}
	payload, _ := json.Marshal(catalog.Rules)
	t.Logf("source=%d raw_rules=%d payload_bytes=%d source_bytes=%d", catalog.Total, len(catalog.Rules), len(payload), len(data))
}

func TestConvertWappalyzerRejectsMalformedInput(t *testing.T) {
	for _, data := range [][]byte{nil, []byte(`{}`), []byte(`{"apps":`), []byte(`{"apps":{"bad":1}}`)} {
		catalog, err := ConvertWappalyzer(data)
		if err == nil && len(catalog.Rules) != 0 {
			t.Errorf("malformed input produced rules: %s", data)
		}
	}
	tooLong := strings.Repeat("x", 201)
	data, _ := json.Marshal(map[string]any{"apps": map[string]any{tooLong: map[string]any{"html": []string{"x"}}}})
	catalog, err := ConvertWappalyzer(data)
	if err != nil || catalog.Skipped["product-invalid"] != 1 {
		t.Fatalf("invalid product accounting=%+v err=%v", catalog, err)
	}
}

func sumSkipped(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}
