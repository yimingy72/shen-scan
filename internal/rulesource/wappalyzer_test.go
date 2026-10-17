package rulesource

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"scanplatform/internal/rulelib"
)

func TestConvertWappalyzerCorpus(t *testing.T) {
	path := os.Getenv("WAPPALYZER_FIXTURE")
	if path == "" {
		t.Skip("set WAPPALYZER_FIXTURE to run the upstream corpus check")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ConvertWappalyzer(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range catalog.Rules {
		if err := rulelib.Validate(rule); err != nil {
			t.Fatalf("rule %q is invalid: %v", rule.ID, err)
		}
	}
	payload, err := json.Marshal(catalog.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Rules) < 1000 {
		t.Fatalf("converted only %d of %d products", len(catalog.Rules), catalog.Total)
	}
	if skippedTotal(catalog.Skipped) != catalog.Total-len(catalog.Rules) {
		t.Fatalf("product skip sum %d != source-rules %d", skippedTotal(catalog.Skipped), catalog.Total-len(catalog.Rules))
	}
	executionRules := append([]rulelib.Rule(nil), catalog.Rules...)
	regexCount := 0
	for i := range executionRules {
		executionRules[i].Description = ""
		executionRules[i].Tags = nil
		executionRules[i].Source = ""
		executionRules[i].Builtin = false
		for _, matcher := range executionRules[i].Definition.Matchers {
			regexCount += len(matcher.Regex)
		}
	}
	executionPayload, err := json.Marshal(executionRules)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("source=%d converted=%d regex=%d payload_bytes=%d execution_payload_bytes=%d skipped=%v signal_skipped=%v", catalog.Total, len(catalog.Rules), regexCount, len(payload), len(executionPayload), catalog.Skipped, catalog.SignalSkipped)
	for i, sample := range catalog.Samples {
		if i == 10 {
			break
		}
		t.Logf("sample[%d]=%s: %s", i, sample.Path, sample.Reason)
	}
}

func skippedTotal(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func TestConvertWappalyzerPreservesSupportedPassiveSignals(t *testing.T) {
	document := wappalyzerDocument{Apps: map[string]wappalyzerApp{
		"Header Tech": {
			Headers: map[string]string{"server": `^HeaderTech/(\d+(?:\.\d+)+)$\;version:\1`},
			JS:      map[string]string{"HeaderTech": ""},
		},
		"Cookie Tech": {Cookies: map[string]string{"product_session": ""}},
		"Body Tech":   {HTML: []string{`<body[^>]+data-body-tech`}},
		"Meta Tech":   {Meta: map[string][]string{"generator": {`^MetaTech$`}}},
		"Script Tech": {ScriptSrc: []string{`^/assets/script-tech\.js$`}},
		"Anchored Tech": {
			HTML: []string{`^<!doctype anchored>$`},
		},
		"Static And Runtime": {
			HTML: []string{`static-runtime-marker`}, JS: map[string]string{"Runtime": ""},
		},
		"Low Confidence": {Headers: map[string]string{"x-low": `low\;confidence:50`}},
		"Implied":        {HTML: []string{`implied-marker`}, Implies: []string{"PHP"}},
		"Requires":       {HTML: []string{`required-marker`}, Requires: []string{"Other"}},
		"Bad Regex":      {HTML: []string{`(?=lookahead)`}},
	}}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ConvertWappalyzer(data)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Total != len(document.Apps) || len(catalog.Rules) != 7 {
		t.Fatalf("catalog totals = source %d rules %d", catalog.Total, len(catalog.Rules))
	}
	if catalog.Repository != WappalyzerRepository || catalog.License != "MIT" || !strings.Contains(catalog.LicenseText, "ProjectDiscovery") {
		t.Fatalf("source metadata missing: %#v", catalog)
	}
	if !strings.HasPrefix(catalog.Digest, "sha256:") || len(catalog.Revision) != 16 {
		t.Fatalf("invalid digest metadata: %q %q", catalog.Digest, catalog.Revision)
	}
	if catalog.Skipped["product-implies"] != 1 || catalog.Skipped["product-requires"] != 1 || catalog.SignalSkipped["signal-low-confidence"] != 1 || catalog.SignalSkipped["signal-unsupported-js"] != 2 || catalog.SignalSkipped["version-metadata-omitted"] != 1 {
		t.Fatalf("unexpected skip counts: products=%#v signals=%#v", catalog.Skipped, catalog.SignalSkipped)
	}

	byName := make(map[string]rulelib.Rule, len(catalog.Rules))
	ids := make(map[string]bool, len(catalog.Rules))
	for _, rule := range catalog.Rules {
		if err := rulelib.Validate(rule); err != nil {
			t.Fatalf("rule %q invalid: %v", rule.Name, err)
		}
		if !strings.HasPrefix(rule.ID, "wa-") || ids[rule.ID] || !rule.Enabled || rule.Builtin || rule.Source != WappalyzerRepository {
			t.Fatalf("invalid converted identity: %#v", rule)
		}
		ids[rule.ID] = true
		byName[rule.Name] = rule
	}
	positive := map[string]rulelib.Input{
		"Header Tech":        {Header: "Server: HeaderTech/1.2\r\n"},
		"Cookie Tech":        {Header: "Set-Cookie: product_session=abc; Path=/\r\n"},
		"Body Tech":          {Body: `<body data-body-tech="yes">`},
		"Meta Tech":          {Body: `<meta content="MetaTech" name="generator">`},
		"Script Tech":        {Body: `<script src="/assets/script-tech.js"></script>`},
		"Anchored Tech":      {Body: `<!doctype anchored>`},
		"Static And Runtime": {Body: `static-runtime-marker`},
	}
	for name, input := range positive {
		if _, ok := rulelib.Match(byName[name], input); !ok {
			t.Errorf("%s missed positive sample", name)
		}
		if _, ok := rulelib.Match(byName[name], rulelib.Input{Body: "generic page", Header: "Server: generic\r\n"}); ok {
			t.Errorf("%s matched generic response", name)
		}
	}
	if _, ok := rulelib.Match(byName["Anchored Tech"], rulelib.Input{Body: `prefix <!doctype anchored>`}); ok {
		t.Fatal("outer HTML anchors were dropped")
	}
}

func TestConvertWappalyzerChunksMatchersAndIsDeterministic(t *testing.T) {
	patterns := make([]string, 40)
	for i := range patterns {
		patterns[i] = `catalog-marker-` + string(rune('A'+i))
	}
	document := wappalyzerDocument{Apps: map[string]wappalyzerApp{
		"Large Product": {
			HTML: patterns, JS: map[string]string{"runtime": ""}, DOM: map[string]any{"#app": true},
			CSS: []string{".runtime"}, Scripts: []string{"runtime-script"},
		},
		"A/B Product": {Headers: map[string]string{"x-product": "present"}},
		"A B Product": {Headers: map[string]string{"x-product": "other"}},
	}}
	data, _ := json.Marshal(document)
	first, err := ConvertWappalyzer(data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ConvertWappalyzer(data)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("conversion is not deterministic")
	}
	if len(first.Rules) != 3 || first.Rules[0].ID == first.Rules[1].ID || first.Rules[1].ID == first.Rules[2].ID {
		t.Fatalf("stable IDs collided: %#v", first.Rules)
	}
	for _, rule := range first.Rules {
		if rule.Name == "Large Product" && len(rule.Definition.Matchers) != 2 {
			t.Fatalf("40 patterns were not split into bounded matchers: %#v", rule.Definition.Matchers)
		}
	}
}

func TestConvertWappalyzerRejectsMalformedInput(t *testing.T) {
	for _, data := range [][]byte{nil, []byte(`{}`), []byte(`{"apps":`)} {
		if _, err := ConvertWappalyzer(data); err == nil {
			t.Errorf("accepted malformed input %q", data)
		}
	}
}
