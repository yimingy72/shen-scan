package browserfp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	wapp "github.com/projectdiscovery/wappalyzergo"
)

func TestBrowserRules(t *testing.T) {
	fixture := []byte(`{"apps":{
 "JSOnly":{"js":{"Product.version":"^([0-9.]+)$\\;version:\\1\\;confidence:60","Product.flag":"^false$\\;confidence:20","Product.zero":"^0$\\;confidence:20","Product.null":"^false$","Product.undef":"^false$"},"implies":["Base\\;confidence:40", "C++\\;confidence:25"]},
 "DOM":{"dom":{"#app":{"exists":"","text":"Fixture","attributes":{"data-version":"^([0-9.]+)$\\;version:\\1","missing":""},"properties":{"_reactRootContainer":"","disabled":"^false$","zero":"^0$","null":"^false$","undefined":""}}}},
 "NoMissingJS":{"js":{"Absent":""}},
 "NoMissingDOM":{"dom":{"#app":{"attributes":{"missing":""},"properties":{"missing":""}}}},
 "NoEmptyText":{"dom":{"#empty":{"text":""}}},
 "OddKeys":{"js":{"strange-key.0.key with spaces":""}}
 }}`)
	matcher, err := Compile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := Compile(fixture)
	if err != nil || cached != matcher {
		t.Fatal("CFF digest cache missed")
	}
	plan := matcher.Plan()
	if len(plan.JS) != 7 || len(plan.DOM) != 2 || len(plan.Unsupported) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	plan.JS[0].Parts[0] = "mutated"
	if matcher.Plan().JS[0].Parts[0] == "mutated" {
		t.Fatal("caller mutated cached plan")
	}
	for _, path := range plan.JS {
		if path.Key == "strange-key.0.key with spaces" && len(path.Parts) != 3 {
			t.Fatal(path)
		}
	}
	value := func(typ, raw string) Value { return Value{Exists: true, Type: typ, Value: raw} }
	missing := Value{Type: "undefined"}
	observations := Observations{JS: map[string]Value{
		"Product.version": value("string", "2.7.1"), "Product.flag": value("boolean", "false"), "Product.zero": value("number", "0"), "Product.null": value("null", ""), "Product.undef": value("undefined", ""), "Absent": missing, "strange-key.0.key with spaces": value("object", ""),
	}, DOM: map[string]DOMObservation{
		"#app":   {Nodes: []Node{{Text: value("string", " Fixture "), Attributes: map[string]Value{"data-version": value("string", "3.4.5"), "missing": missing}, Properties: map[string]Value{"_reactRootContainer": value("object", ""), "disabled": value("boolean", "false"), "zero": value("number", "0"), "null": value("null", ""), "undefined": value("undefined", ""), "missing": missing}}}},
		"#empty": {Nodes: []Node{{Text: value("string", "  ")}}},
	}}
	result := matcher.Match(observations)
	if !result.Complete || result.EvaluatedRules != result.TotalRules || result.UnsupportedRules != 0 {
		t.Fatalf("coverage = %+v", result)
	}
	matches := map[string]Match{}
	for _, match := range result.Matches {
		matches[match.Name] = match
	}
	if len(matches) != 5 || matches["JSOnly"].Version != "2.7.1" || matches["JSOnly"].Confidence != 100 || matches["DOM"].Version != "3.4.5" || matches["Base"].Confidence != 40 || matches["C++"].Confidence != 25 {
		t.Fatalf("matches = %+v", matches)
	}
	for _, name := range []string{"NoMissingJS", "NoMissingDOM", "NoEmptyText"} {
		if _, ok := matches[name]; ok {
			t.Fatalf("missing value false positive: %s", name)
		}
	}
	// A positive first node must not hide an error in a later node.
	domWithError := observations.DOM["#app"]
	domWithError.Nodes = append(domWithError.Nodes, Node{Text: Value{Error: "getter failed"}, Attributes: domWithError.Nodes[0].Attributes, Properties: domWithError.Nodes[0].Properties})
	observations.DOM["#app"] = domWithError
	partial := matcher.Match(observations)
	if partial.Complete || partial.MatchedRules == 0 {
		t.Fatal("positive rule hid later field error")
	}
	for _, status := range partial.Rules {
		if status.Name == "DOM" && status.Operation == "text" && status.Status != "incomplete" {
			t.Fatalf("later error status: %+v", status)
		}
	}
	observations.DOM["#app"] = DOMObservation{Nodes: domWithError.Nodes[:1]}
	delete(observations.JS, "Product.version")
	dom := observations.DOM["#app"]
	dom.Truncated = true
	observations.DOM["#app"] = dom
	if matcher.Match(observations).Complete {
		t.Fatal("missing/truncated observations reported complete")
	}
	bad, err := Compile([]byte(`{"apps":{"Bad":{"js":{"v":"["},"dom":{"img":{"src":""},"#app":{"properties":{"invalid":123}}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	unsupported := bad.Match(Observations{})
	if unsupported.Complete || unsupported.UnsupportedRules != 3 {
		t.Fatalf("unsupported = %+v", unsupported)
	}
	full, err := Compile([]byte(wapp.GetFingerprints()))
	if err != nil {
		t.Fatal(err)
	}
	fullPlan := full.Plan()
	var library wapp.Fingerprints
	if err := json.Unmarshal([]byte(wapp.GetFingerprints()), &library); err != nil {
		t.Fatal(err)
	}
	jsApps, domApps := 0, 0
	for _, app := range library.Apps {
		if len(app.JS) > 0 {
			jsApps++
		}
		if len(app.Dom) > 0 {
			domApps++
		}
	}
	if len(library.Apps) != 7607 || jsApps != 3287 || domApps != 1461 || len(fullPlan.JS) != 5398 || len(fullPlan.Unsupported) != 2 {
		t.Fatalf("upstream inventory changed: apps=%d JS=%d DOM=%d paths=%d unsupported=%+v", len(library.Apps), jsApps, domApps, len(fullPlan.JS), fullPlan.Unsupported)
	}
	src, invalid := 0, 0
	for _, issue := range fullPlan.Unsupported {
		if issue.Name == "GetYourGuide" && issue.Operation == "src" {
			src++
		} else if strings.HasPrefix(issue.Reason, "invalid pattern: ") {
			invalid++
		} else {
			t.Fatalf("unexpected unsupported: %+v", issue)
		}
	}
	if src != 2 || invalid != 0 {
		t.Fatalf("unsupported counts: src=%d regex=%d", src, invalid)
	}

	// Exercise every actual raw rule that needs ECMAScript compatibility, with
	// positive and negative observations (not rewritten approximations).
	compatibilityCases := map[string]struct{ positive, negative, version string }{
		"Aniview Ad Server|link[href*='aniview.com']|attributes|href":                                               {"https://cdn.aniview.com/assets/a.css", "https://cdn.aniview.com/player.css", ""},
		"Drupal Multisite|figure[style*='/sites/']|attributes|style":                                                {"background:url('/sites/acme/themes/a')", "background:url('/sites/default/themes/a')", ""},
		"Drupal Multisite|img[src*='/sites/'], img[srcset*='/sites/'], source[srcset*='/sites/']|attributes|src":    {"/sites/acme/files/a.png", "/sites/default/files/a.png", ""},
		"Drupal Multisite|img[src*='/sites/'], img[srcset*='/sites/'], source[srcset*='/sites/']|attributes|srcset": {"/sites/acme/modules/a.png 1x", "/sites/all/modules/a.png 1x", ""},
		"Drupal Multisite|style|text|":                                          {".a{background:url('/sites/acme/modules/a')}", ".a{background:url('/sites/default/modules/a')}", ""},
		"PhotoShelter for Brands|a[href*='.photoshelter.com/']|attributes|href": {"https://acme.photoshelter.com/", "https://psecn.photoshelter.com/", ""},
		"PyData Sphinx Theme|p.theme-version|text|":                             {"0.16.1", "PyData Sphinx Theme", "0.16.1"},
		"Shaka Player|shaka.Player.version||":                                   {"v4.11.2", "release 4.11.2", "4.11.2"},
	}
	fallbackCount := 0
	for _, r := range full.rules {
		if r.fallback == nil {
			continue
		}
		fallbackCount++
		key := r.status.Name + "|" + r.status.Key + "|" + r.status.Operation + "|" + r.status.Field
		fixture, ok := compatibilityCases[key]
		if !ok {
			t.Fatalf("unexpected compatibility rule: %+v", r.status)
		}
		one := &Matcher{plan: Plan{Digest: "compatibility-fixture"}, rules: []rule{r}, implies: map[string][]string{}}
		for _, example := range []struct {
			target  string
			matched bool
		}{{fixture.positive, true}, {fixture.negative, false}} {
			observation := Observations{JS: map[string]Value{}, DOM: map[string]DOMObservation{}}
			v := value("string", example.target)
			if r.status.Source == "js" {
				observation.JS[r.status.Key] = v
			} else {
				observation.DOM[r.status.Key] = DOMObservation{Nodes: []Node{{Text: v, Attributes: map[string]Value{r.status.Field: v}, Properties: map[string]Value{r.status.Field: v}}}}
			}
			result := one.Match(observation)
			if !result.Complete || (len(result.Matches) > 0) != example.matched {
				t.Fatalf("compatibility %s target=%q: %+v", key, example.target, result)
			}
			if example.matched && (result.Matches[0].Version != fixture.version || result.Matches[0].Confidence != 100) {
				t.Fatalf("compatibility metadata %s: %+v", key, result.Matches)
			}
		}
	}
	if fallbackCount != 8 || fallbackCount != len(compatibilityCases) {
		t.Fatalf("fallback count = %d", fallbackCount)
	}

	shakaMeta, shakaRegex, err := compilePattern(`v([\d\.-\w]+)\;version:\1`)
	if err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct {
		target, version string
		matched         bool
	}{{"v4-rc_2", "4-rc_2", true}, {"v.%", ".", true}, {"v%", "", false}} {
		matched, version, err := (rule{pattern: shakaMeta, fallback: shakaRegex}).evaluate(context.Background(), example.target)
		if err != nil || matched != example.matched || version != example.version {
			t.Fatalf("Shaka Annex B character-set adaptation %q => %v/%q err=%v", example.target, matched, version, err)
		}
	}
	// Official metadata/version behavior must stay the same in the fallback path.
	for _, raw := range []string{
		`^([0-9]+)(?:\.([0-9]+))?\;version:\1.\2\;confidence:40`,
		`^([0-9]+)\;version:\1?yes:no\;confidence:45`,
		`^([0-9]+)\;version:\1?:fallback`,
		`^([0-9]+)\;version:literal`,
		`^([0-9]+)\;version:\1? yes : no `,
	} {
		official, err := wapp.ParsePattern(raw)
		if err != nil {
			t.Fatal(err)
		}
		metadata, fallback, err := compilePattern(`(?=.)` + raw)
		if err != nil || fallback == nil {
			t.Fatalf("fallback metadata compile: %v", err)
		}
		matched, want := official.Evaluate("2.7")
		gotMatch, got, err := (rule{pattern: metadata, fallback: fallback}).evaluate(context.Background(), "2.7")
		if err != nil || gotMatch != matched || got != want || metadata.Confidence != official.Confidence {
			t.Fatalf("metadata parity %q: got=%v/%q/%d want=%v/%q/%d err=%v", raw, gotMatch, got, metadata.Confidence, matched, want, official.Confidence, err)
		}
	}
	bounded, err := Compile([]byte(`{"apps":{"Bad":{"js":{"bad":"(?=a)(a+)+$"}},"Good":{"js":{"good":"safe"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	boundedInput := Observations{JS: map[string]Value{"bad": value("string", strings.Repeat("a", 10000)+"!"), "good": value("string", "safe")}}
	started := time.Now()
	timed := bounded.Match(boundedInput)
	if timed.Complete || timed.UnsupportedRules != 0 || len(timed.Matches) != 1 || timed.Matches[0].Name != "Good" || timed.Rules[0].Status != "incomplete" || timed.Rules[0].Reason != "compatibility regex timed out" || time.Since(started) > 2*time.Second {
		t.Fatalf("timeout did not remain bounded/isolated: %+v", timed)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := bounded.MatchContext(canceled, boundedInput); result.Complete || result.EvaluatedRules != 0 || len(result.Matches) != 0 {
		t.Fatalf("canceled match ran: %+v", result)
	}
	absent := Observations{JS: map[string]Value{}, DOM: map[string]DOMObservation{}}
	for _, path := range fullPlan.JS {
		absent.JS[path.Key] = missing
	}
	for _, sel := range fullPlan.DOM {
		absent.DOM[sel.Selector] = DOMObservation{Nodes: []Node{}}
	}
	inventory := full.Match(absent)
	if inventory.Complete || len(inventory.Matches) != 0 || inventory.EvaluatedRules+inventory.UnsupportedRules != inventory.TotalRules {
		t.Fatalf("full library coverage: evaluated=%d unsupported=%d total=%d matches=%+v", inventory.EvaluatedRules, inventory.UnsupportedRules, inventory.TotalRules, inventory.Matches)
	}
	t.Logf("ECMAScript fallbacks=%d, each actual raw rule positive+negative passed; timeout/cancellation passed", fallbackCount)
	t.Logf("v0.2.96 apps=%d JS-apps=%d DOM-apps=%d JS-paths=%d DOM-selectors=%d rules=%d evaluated=%d unsupported=%d", len(library.Apps), jsApps, domApps, len(fullPlan.JS), len(fullPlan.DOM), inventory.TotalRules, inventory.EvaluatedRules, inventory.UnsupportedRules)
}
