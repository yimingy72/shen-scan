package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"scanplatform/internal/rulelib"
	"scanplatform/internal/webevidence"
)

func enrichmentFixture() (taskEndpoint, Observation, webevidence.ProbeResult) {
	ep := taskEndpoint{IP: "192.0.2.70", URL: "http://192.0.2.70/start", WorkKey: "original-entry"}
	input := webevidence.Response{URL: ep.URL, ConnectIP: ep.IP, StatusCode: 302}
	final := webevidence.Response{URL: "http://192.0.2.70/login", ConnectIP: ep.IP, StatusCode: 200}
	probe := webevidence.ProbeResult{Protocol: webevidence.Protocol, EnrichmentProfile: webevidence.EnrichmentProfile,
		InputURL: ep.URL, Response: final, Attempts: []webevidence.Response{input, final}, Requests: 2,
		Redirects: []webevidence.RedirectStep{{FromURL: ep.URL, ToURL: final.URL, StatusCode: 302, AttemptIndex: 0, Outcome: "followed"}}}
	o := Observation{Kind: "http", Target: ep.IP, IP: ep.IP, Port: 80, URL: final.URL, WorkKey: ep.WorkKey, StatusCode: 200}
	return ep, o, probe
}

func enrichmentEvidence(probe webevidence.ProbeResult) string {
	raw, _ := json.Marshal(map[string]any{"probe": probe})
	return string(raw)
}

// Existing controller fixtures model a successful direct primary response.
func controlHTTPFixture(o Observation) Observation {
	response := webevidence.Response{URL: o.URL, ConnectIP: o.IP, StatusCode: o.StatusCode}
	o.Evidence = enrichmentEvidence(webevidence.ProbeResult{Protocol: webevidence.Protocol,
		EnrichmentProfile: webevidence.EnrichmentProfile, InputURL: o.URL, Response: response,
		Attempts: []webevidence.Response{response}, Requests: 1})
	return o
}

func TestHTTPEnrichmentScopeAndRuleProjection(t *testing.T) {
	ep, original, _ := enrichmentFixture()
	for _, tc := range []struct {
		name string
		edit func(*Observation, *webevidence.ProbeResult)
		bad  bool
	}{
		{"same origin redirect", func(*Observation, *webevidence.ProbeResult) {}, false},
		{"wrong input", func(_ *Observation, p *webevidence.ProbeResult) { p.InputURL = "http://192.0.2.70/other" }, true},
		{"wrong primary", func(_ *Observation, p *webevidence.ProbeResult) { p.Response.URL += "/other" }, true},
		{"foreign response", func(_ *Observation, p *webevidence.ProbeResult) {
			p.Icons = []webevidence.Response{{URL: "http://foreign.example/favicon.ico"}}
		}, true},
		{"wrong IP", func(_ *Observation, p *webevidence.ProbeResult) { p.Response.ConnectIP = "192.0.2.71" }, true},
		{"unbound redirect", func(_ *Observation, p *webevidence.ProbeResult) { p.Redirects[0].AttemptIndex = 99 }, true},
		{"cross origin followed", func(_ *Observation, p *webevidence.ProbeResult) { p.Redirects[0].ToURL = "https://192.0.2.70/login" }, true},
		{"missing chain", func(_ *Observation, p *webevidence.ProbeResult) { p.Redirects = nil }, true},
		{"wrong work", func(o *Observation, _ *webevidence.ProbeResult) { o.WorkKey = "other" }, true},
		{"foreign final", func(o *Observation, _ *webevidence.ProbeResult) { o.URL = "http://foreign.example/login" }, true},
		{"userinfo", func(o *Observation, _ *webevidence.ProbeResult) { o.URL = "http://user@192.0.2.70/login" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, o, proof := enrichmentFixture()
			tc.edit(&o, &proof)
			o.Evidence = enrichmentEvidence(proof)
			payload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{ep}, "web_enrichment_profile": webevidence.EnrichmentProfile})
			key, err := observationTarget("http", payload, ep.IP, &o)
			if (err != nil) != tc.bad || err == nil && (key != ep.IP || o.WorkKey != original.WorkKey) {
				t.Fatalf("key=%s observation=%+v error=%v", key, o, err)
			}
		})
	}
	for _, destination := range []string{"http://192.0.2.70/confirm", "http://foreign.example/confirm"} {
		_, observation, proof := enrichmentFixture()
		encoded, _ := json.Marshal(map[string]any{"probe": proof, "supplements": []map[string]any{{"url": destination, "response": webevidence.Response{URL: destination, ConnectIP: ep.IP}}}})
		observation.Evidence = string(encoded)
		err := validateHTTPEnrichmentEvidence(ep, &observation, webevidence.EnrichmentProfile)
		if (err == nil) != (destination == "http://192.0.2.70/confirm") {
			t.Fatalf("supplement scope %q: %v", destination, err)
		}
	}
	if err := validateHTTPEnrichmentEvidence(ep, &original, webevidence.EnrichmentProfile); err == nil {
		t.Fatal("changed final path without redirect evidence accepted")
	}
	for _, failure := range []string{"unknown protocol setup failed", "DNS lookup failed", "web helper unavailable"} {
		implicit := taskEndpoint{IP: "192.0.2.70", Port: 18080, WorkKey: "implicit-work"}
		payload, _ := json.Marshal(map[string]any{"endpoints": []taskEndpoint{implicit}, "web_enrichment_profile": webevidence.EnrichmentProfile})
		o := Observation{Kind: "http", Target: implicit.IP, IP: implicit.IP, WorkKey: implicit.WorkKey, Error: failure, Outcome: "error", Coverage: "incomplete"}
		if _, err := observationTarget("http", payload, implicit.IP, &o); err != nil {
			t.Fatalf("pre-probe failure rejected: %v", err)
		}
		o.WorkKey = "foreign-work"
		if _, err := observationTarget("http", payload, implicit.IP, &o); err == nil {
			t.Fatal("unbound pre-probe failure accepted")
		}
		o.WorkKey, o.StatusCode = implicit.WorkKey, 200
		if _, err := observationTarget("http", payload, implicit.IP, &o); err == nil {
			t.Fatal("successful empty URL bypassed evidence binding")
		}
	}
	collection := &rulelib.HTTPCollection{Path: "/confirm", Products: []string{"FixtureApp"}, SourceRuleID: "fixture-source", SourceRuleRevision: 3}
	rule := rulelib.Rule{ID: "http-fixture-confirm", Kind: "http", Collection: collection}
	execution := executionRules([]rulelib.Rule{rule})
	encoded, _ := json.Marshal(execution)
	var decoded []rulelib.Rule
	if json.Unmarshal(encoded, &decoded) != nil || len(decoded) != 1 || decoded[0].Collection == nil || decoded[0].Collection.SourceRuleRevision != 3 || summarizeRule(rule, "").Collection != collection {
		t.Fatalf("collection projection lost: %s", encoded)
	}
	before := webevidence.SHA256(encoded)
	collection.Path = "/different"
	encoded, _ = json.Marshal(executionRules([]rulelib.Rule{rule}))
	if before == webevidence.SHA256(encoded) {
		t.Fatal("collection changes must change execution rules content hash")
	}
}

func TestPostgresHTTPEnrichmentSnapshotAndCapabilities(t *testing.T) {
	s, h := newPolicyTestServer(t, "http_enrichment")
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `UPDATE worker_pool SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	call := earlyEvidenceCaller(t, h)
	freezeLegacyRun := func(runID string) {
		t.Helper()
		if _, err := s.db.Exec(ctx, `UPDATE runs SET rules_snapshot=jsonb_set(rules_snapshot-'web_execution_profile'-'fingerprint_bundle_schema','{fingerprint_bundle}',to_jsonb($2::text)) WHERE id=$1;`, runID, webevidence.LegacyFingerprintBundle); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload-'web_execution_profile'-'fingerprint_bundle_schema','{fingerprint_bundle}',to_jsonb($2::text)) WHERE run_id=$1`, runID, webevidence.LegacyFingerprintBundle); err != nil {
			t.Fatal(err)
		}
	}
	collectionRule := rulelib.Rule{ID: "http-legacy-collection-fixture", Kind: "http", Name: "Legacy Grafana collection", Engine: "native", Severity: "info", Enabled: true, Collection: &rulelib.HTTPCollection{Path: "/login", Products: []string{"Grafana"}, SourceRuleID: "legacy-grafana", SourceRuleRevision: 1}, Definition: rulelib.Definition{Product: "Grafana", Condition: "and", Matchers: []rulelib.Matcher{{Part: "body", Type: "word", Words: []string{"Grafana"}}}}}
	collectionRule.ID, collectionRule.Builtin = "http-enrichment-control-fixture", false
	call(http.MethodPost, "/api/library", "admin-policy", collectionRule, 201, &collectionRule)
	frozenPath := collectionRule.Collection.Path
	var run Run
	call(http.MethodPost, "/api/runs", "admin-policy", map[string]any{"name": "new enrichment", "targets": []string{"http://192.0.2.70/start"}, "modes": []string{"http"}}, 201, &run)
	freezeLegacyRun(run.ID)
	var snapshotProfile, payloadProfile string
	if err := s.db.QueryRow(ctx, `SELECT r.rules_snapshot->>'web_enrichment_profile',t.payload->>'web_enrichment_profile'
 FROM runs r JOIN tasks t ON t.run_id=r.id WHERE r.id=$1`, run.ID).Scan(&snapshotProfile, &payloadProfile); err != nil || snapshotProfile != webevidence.EnrichmentProfile || payloadProfile != snapshotProfile {
		t.Fatalf("new snapshot/task profiles=%q/%q err=%v", snapshotProfile, payloadProfile, err)
	}
	collectionRule.Collection.Path = "/control-changed-confirmation"
	call(http.MethodPut, "/api/library/"+collectionRule.ID, "admin-policy", struct {
		rulelib.Rule
		ExpectedRevision int `json:"expected_revision"`
	}{collectionRule, collectionRule.Revision}, 200, &collectionRule)
	var exported ruleExportPackage
	call(http.MethodGet, "/api/library/export?kind=http", "admin-policy", nil, 200, &exported)
	var found bool
	for _, rule := range exported.Items {
		if rule.ID == collectionRule.ID {
			found = rule.Collection != nil && rule.Collection.Path == collectionRule.Collection.Path && rule.Collection.SourceRuleRevision == collectionRule.Collection.SourceRuleRevision
		}
	}
	if !found {
		t.Fatal("export lost collection")
	}
	imported := collectionRule
	imported.ID = "http-enrichment-import-fixture"
	encoded, _ := json.Marshal(ruleExportPackage{Items: []rulelib.Rule{imported}})
	call(http.MethodPost, "/api/library/import", "admin-policy", map[string]any{"format": "json", "content": string(encoded)}, 201, nil)
	call(http.MethodGet, "/api/library/"+imported.ID, "admin-policy", nil, 200, &imported)
	if imported.Collection == nil || imported.Collection.Path != collectionRule.Collection.Path {
		t.Fatal("import lost collection")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,rules_snapshot) VALUES('old-enrichment','old','[]','{}','running','{}');
 INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES('old-http','old-enrichment','http',
 '{"endpoints":[{"ip":"192.0.2.71","url":"http://192.0.2.71/","work_key":"legacy-entry"}]}','old-http','192.0.2.71')`)
	if err != nil {
		t.Fatal(err)
	}
	var worker struct {
		ID    string `json:"worker_id"`
		Token string `json:"worker_token"`
	}
	callAPI(t, h, "POST", "/api/workers/register", "join-policy", map[string]any{"instance_id": "enrichment-worker", "hostname": "local", "session_id": "s1"}, 200, &worker)
	claim := func(id, profile string) *Task {
		t.Helper()
		var out struct {
			Task *Task `json:"task"`
		}
		callAPI(t, h, "POST", "/api/tasks/claim", worker.Token, map[string]any{
			"worker_id": worker.ID, "session_id": "s1", "request_id": id, "types": []string{"http"}, "supports_confirmed_stop": true,
			"supports_http_request_budget": true, "service_profile": "nmap-light-v1", "web_evidence_profile": webevidence.Profile,
			"fingerprint_bundle": webevidence.FingerprintBundle, "web_enrichment_profile": profile,
		}, 200, &out)
		return out.Task
	}
	old := claim("old-agent", "")
	if old == nil || old.ID != "old-http" {
		t.Fatalf("legacy task not available to old capability: %+v", old)
	}
	if replay := claim("old-agent", webevidence.EnrichmentProfile); replay == nil || replay.ID != old.ID {
		t.Fatalf("new agent lost compatibility with legacy task: %+v", replay)
	}
	batch := func(task *Task, observation Observation, want int) {
		t.Helper()
		callAPI(t, h, "POST", "/api/tasks/"+task.ID+"/batches", worker.Token,
			map[string]any{"worker_id": worker.ID, "session_id": "s1", "attempt_no": task.AttemptNo, "batch_seq": 0, "items": []Observation{observation}}, want, nil)
	}
	batch(old, Observation{Kind: "http", Target: "192.0.2.71", IP: "192.0.2.71", URL: "http://192.0.2.71/", StatusCode: 200}, 200)
	complete := func(task *Task, want int) {
		t.Helper()
		callAPI(t, h, "POST", "/api/tasks/"+task.ID+"/complete", worker.Token, map[string]any{
			"worker_id": worker.ID, "session_id": "s1", "attempt_no": task.AttemptNo, "last_batch_seq": 0}, want, nil)
	}
	complete(old, 200)
	for _, capability := range []string{"", "different-enrichment"} {
		if task := claim("reject-"+capability, capability); task != nil {
			t.Fatalf("incompatible capability claimed new task: %+v", task)
		}
	}
	task := claim("current-agent", webevidence.EnrichmentProfile)
	if task == nil || task.RunID != run.ID {
		t.Fatalf("current agent got no new task: %+v", task)
	}
	if replay := claim("current-agent", ""); replay != nil {
		t.Fatalf("downgraded replay bypassed enrichment fence: %+v", replay)
	}
	if replay := claim("current-agent", webevidence.EnrichmentProfile); replay == nil || replay.ID != task.ID || replay.AttemptNo != task.AttemptNo {
		t.Fatalf("compatible replay changed work: %+v", replay)
	}
	var attached struct {
		Rules []rulelib.Rule `json:"rules"`
	}
	if json.Unmarshal(task.Payload, &attached) != nil {
		t.Fatal("invalid attached rules")
	}
	found = false
	for _, rule := range attached.Rules {
		if rule.ID == collectionRule.ID {
			found = rule.Collection != nil && rule.Collection.Path == frozenPath && rule.Revision == 1
		}
	}
	if !found {
		t.Fatal("execution rules did not freeze the original collection")
	}
	var frozenRules struct {
		Rules []rulelib.Rule `json:"rules"`
	}
	callAPI(t, h, "GET", fmt.Sprintf("/api/tasks/%s/rules?worker_id=%s&session_id=s1&attempt_no=%d", task.ID, worker.ID, task.AttemptNo), worker.Token, nil, 200, &frozenRules)
	found = false
	for _, rule := range frozenRules.Rules {
		if rule.ID == collectionRule.ID {
			found = rule.Collection != nil && rule.Collection.Path == frozenPath
		}
	}
	if !found {
		t.Fatal("rules_ref download lost frozen collection")
	}
	var plan struct {
		Endpoints []taskEndpoint `json:"endpoints"`
	}
	if json.Unmarshal(task.Payload, &plan) != nil || len(plan.Endpoints) != 1 {
		t.Fatal("invalid task plan")
	}
	ep, observation, proof := enrichmentFixture()
	observation.WorkKey = plan.Endpoints[0].WorkKey
	proof.InputURL = "http://192.0.2.70/not-assigned"
	observation.Evidence = enrichmentEvidence(proof)
	batch(task, observation, 422)
	complete(task, 409) // Rejected evidence did not commit a batch.
	proof.InputURL = ep.URL
	observation.Evidence = enrichmentEvidence(proof)
	batch(task, observation, 200)
	complete(task, 200)
	var workKey, finalURL, coverage string
	if err = s.db.QueryRow(ctx, `SELECT a.observation->>'work_key',a.observation->>'url',t.coverage FROM assets a JOIN tasks t ON t.id=a.task_id WHERE t.id=$1`, task.ID).Scan(&workKey, &finalURL, &coverage); err != nil || workKey != observation.WorkKey || finalURL != proof.Response.URL || coverage != "complete" {
		t.Fatalf("logical work/final URL completion: %s/%s/%s err=%v", workKey, finalURL, coverage, err)
	}
	var extra int
	if err = s.db.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE run_id=$1 AND id<>$2`, run.ID, task.ID).Scan(&extra); err != nil || extra != 0 {
		t.Fatalf("redirect produced extra HTTP/PoC work: %d err=%v", extra, err)
	}
	pocRule := testPOCRule("poc-enrichment-explicit", []string{"FixtureApp"})
	call(http.MethodPost, "/api/library", "admin-policy", pocRule, 201, &pocRule)
	var enabledRun Run
	call(http.MethodPost, "/api/runs", "admin-policy", map[string]any{"name": "explicit PoC entry", "targets": []string{"http://192.0.2.73/original"}, "modes": []string{"http"}, "poc_enabled": true, "poc_rule_ids": []string{pocRule.ID}}, 201, &enabledRun)
	freezeLegacyRun(enabledRun.ID)
	enabledTask := claim("explicit-poc-entry", webevidence.EnrichmentProfile)
	if enabledTask == nil || enabledTask.RunID != enabledRun.ID {
		t.Fatalf("explicit PoC task claim=%+v", enabledTask)
	}
	if json.Unmarshal(enabledTask.Payload, &plan) != nil {
		t.Fatal("invalid explicit PoC plan")
	}
	entry := plan.Endpoints[0]
	primary := webevidence.Response{URL: "http://192.0.2.73/redirected/login", ConnectIP: "192.0.2.73", StatusCode: 200}
	pocProof := webevidence.ProbeResult{Protocol: webevidence.Protocol, EnrichmentProfile: webevidence.EnrichmentProfile,
		InputURL: entry.URL, Response: primary, Requests: 2,
		Attempts:  []webevidence.Response{{URL: entry.URL, ConnectIP: entry.IP, StatusCode: 302}, primary},
		Redirects: []webevidence.RedirectStep{{FromURL: entry.URL, ToURL: primary.URL, AttemptIndex: 0, StatusCode: 302, Outcome: "followed"}}}
	batch(enabledTask, Observation{Kind: "http", Target: entry.IP, IP: entry.IP, Port: 80, WorkKey: entry.WorkKey, URL: primary.URL, StatusCode: 200, Technologies: []Technology{{Name: "FixtureApp"}}, Evidence: enrichmentEvidence(pocProof)}, 200)
	complete(enabledTask, 200)
	var pocURL string
	if err = s.db.QueryRow(ctx, `SELECT payload->'endpoint'->>'url' FROM tasks WHERE run_id=$1 AND type='poc'`, enabledRun.ID).Scan(&pocURL); err != nil || pocURL != entry.URL {
		t.Fatalf("PoC must retain original enabled entry: %q err=%v", pocURL, err)
	}
	_, err = s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,rules_snapshot) VALUES('preprobe-run','preprobe','[]','{}','running','{}');
 INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES('preprobe-http','preprobe-run','http',
 '{"web_enrichment_profile":"bounded-enrichment-v1","endpoints":[{"ip":"192.0.2.74","port":18080,"work_key":"implicit-work"}]}','preprobe-http','192.0.2.74')`)
	if err != nil {
		t.Fatal(err)
	}
	preprobe := claim("preprobe-failure", webevidence.EnrichmentProfile)
	if preprobe == nil || preprobe.ID != "preprobe-http" {
		t.Fatalf("implicit task claim=%+v", preprobe)
	}
	batch(preprobe, Observation{Kind: "http", Target: "192.0.2.74", IP: "192.0.2.74", WorkKey: "implicit-work", Error: "DNS/helper setup failed", Outcome: "error", Coverage: "incomplete"}, 200)
	complete(preprobe, 200)
	if err = s.db.QueryRow(ctx, `SELECT coverage FROM tasks WHERE id='preprobe-http'`).Scan(&coverage); err != nil || coverage != "partial" {
		t.Fatalf("preprobe completion coverage=%q err=%v", coverage, err)
	}
	// Exercise the same derivation used by completed service tasks, against
	// immutable new and old run snapshots rather than a package-level default.
	for _, inherited := range []struct{ runID, profile string }{{run.ID, webevidence.EnrichmentProfile}, {"old-enrichment", ""}} {
		tx, err := s.db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		parentID := "service-" + inherited.runID
		payload, _ := json.Marshal(map[string]any{"http_enabled": true, "endpoints": []taskEndpoint{{IP: "192.0.2.72", Port: 8080}}})
		_, err = tx.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key,attempt_no) VALUES($1,$2,'service',$3,$1,'192.0.2.72',1)`, parentID, inherited.runID, payload)
		if err == nil {
			raw, _ := json.Marshal(Observation{Kind: "service", IP: "192.0.2.72", Port: 8080, Service: "http"})
			_, err = tx.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation) VALUES($1,$2,$3,1,0,0,'192.0.2.72',$4)`, "asset-"+parentID, inherited.runID, parentID, raw)
		}
		if err == nil {
			err = deriveServiceWebTasks(ctx, tx, parentID, inherited.runID, 1, payload)
		}
		if err == nil {
			var required string
			err = tx.QueryRow(ctx, `SELECT COALESCE(payload->>'web_enrichment_profile','') FROM tasks WHERE run_id=$1 AND type='http' AND payload->>'source_task_id'=$2`, inherited.runID, parentID).Scan(&required)
			if err == nil && required != inherited.profile {
				err = fmt.Errorf("derived profile %q, want %q", required, inherited.profile)
			}
		}
		if err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
