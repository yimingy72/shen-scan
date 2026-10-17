package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"scanplatform/internal/rulelib"
)

func verificationResponse(status int, text, body string) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", status, text, len(body), body)
}

func TestVerificationFindingPurposeDB(t *testing.T) {
	server, handler := newPolicyTestServer(t, "verification_results_test")
	ctx := context.Background()
	runID := newID()
	if _, err := server.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,poc_enabled)
		VALUES($1,'verification results','["example.test"]','{http}','completed',true)`, runID); err != nil {
		t.Fatal(err)
	}
	verificationRule := rulelib.ReviewedVerifications()[0]
	discoveryRule := testPOCRule("poc-test-discovery-result", []string{"Example"})
	insert := func(rule rulelib.Rule, purpose string, verification *rulelib.Verification, index int) {
		t.Helper()
		taskID := newID()
		payload, _ := json.Marshal(map[string]any{"endpoint": taskEndpoint{URL: "https://example.test/"}, "rules": []rulelib.Rule{rule}})
		if _, err := server.db.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,state,attempt_no,derived_key,target_key)
			VALUES($1,$2,'poc',$3,'completed',1,$4,'example.test')`, taskID, runID, payload, fmt.Sprintf("poc-result-%d", index)); err != nil {
			t.Fatal(err)
		}
		if _, err := server.db.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES($1,'example.test')`, taskID); err != nil {
			t.Fatal(err)
		}
		observation, _ := json.Marshal(Observation{Kind: "poc", Target: "https://example.test/", URL: "https://example.test/",
			RuleID: rule.ID, RuleName: rule.Name, RuleRevision: rule.Revision, Engine: rule.Engine, Severity: rule.Severity,
			FindingStatus: "matched", Evidence: "complete", Purpose: purpose, Verification: verification})
		if _, err := server.db.Exec(ctx, `INSERT INTO assets(id,run_id,task_id,attempt_no,batch_seq,item_index,target_key,observation)
			VALUES($1,$2,$3,1,0,0,'example.test',$4)`, newID(), runID, taskID, observation); err != nil {
			t.Fatal(err)
		}
	}
	insert(verificationRule, "verification", verificationRule.Verification, 0)
	insert(discoveryRule, "discovery", nil, 1)
	var run Run
	callAPI(t, handler, http.MethodGet, "/api/runs/"+runID, "admin-policy", nil, http.StatusOK, &run)
	if run.FindingCount != 2 || run.VerificationFindingCount != 1 || run.DiscoveryMatchCount != 1 {
		t.Fatalf("run purpose counts=%+v", run)
	}
	var findings struct {
		Items   []Observation    `json:"items"`
		Total   int64            `json:"total"`
		Summary map[string]int64 `json:"summary"`
	}
	callAPI(t, handler, http.MethodGet, "/api/runs/"+runID+"/findings?purpose=verification", "admin-policy", nil, http.StatusOK, &findings)
	if findings.Total != 1 || len(findings.Items) != 1 || findings.Items[0].Purpose != "verification" || findings.Items[0].Verification == nil ||
		findings.Summary["matched"] != 2 || findings.Summary["verification_matched"] != 1 || findings.Summary["discovery_matched"] != 1 {
		t.Fatalf("verification findings=%+v", findings)
	}
}

func TestValidateVerificationEvidenceReplaysProbeAndControl(t *testing.T) {
	rule := rulelib.Rule{Kind: "poc", Purpose: "verification", Engine: "native", Verification: &rulelib.Verification{ID: "test"},
		Definition: rulelib.Definition{Condition: "and", Requests: []rulelib.Request{
			{Method: "GET", Path: "/probe?fixed=1", Role: "probe", Condition: "and", Matchers: []rulelib.Matcher{
				{Part: "status", Type: "status", Status: []int{200}},
				{Part: "body", Type: "word", Words: []string{"vulnerable"}},
			}},
			{Method: "GET", Path: "/control", Role: "control", Condition: "and", Matchers: []rulelib.Matcher{
				{Part: "status", Type: "status", Status: []int{404}},
				{Part: "body", Type: "word", Words: []string{"vulnerable"}, Negative: true},
			}},
		}}}
	item := &Observation{FindingStatus: "matched", Evidence: "probe and control matched", RequestRaw: "complete", ResponseRaw: "complete",
		Checks: []rulelib.CheckEvidence{
			{RequestRaw: "GET /probe?fixed=1 HTTP/1.1\r\nHost: example.test\r\n\r\n", ResponseRaw: verificationResponse(200, "OK", "vulnerable marker")},
			{RequestRaw: "GET /control HTTP/1.1\r\nHost: example.test\r\n\r\n", ResponseRaw: verificationResponse(404, "Not Found", "not found")},
		}}
	if err := validateVerificationEvidence(rule, taskEndpoint{URL: "http://example.test/"}, item); err != nil {
		t.Fatal(err)
	}
	item.Checks[1].ResponseRaw = verificationResponse(200, "OK", "vulnerable marker")
	if err := validateVerificationEvidence(rule, taskEndpoint{URL: "http://example.test/"}, item); err == nil {
		t.Fatal("failed negative control was accepted as verification")
	}
	item.Truncated = true
	if err := validateVerificationEvidence(rule, taskEndpoint{URL: "http://example.test/"}, item); err == nil {
		t.Fatal("truncated verification evidence was accepted")
	}
}

func TestDiscoveryObservationCannotSpoofVerification(t *testing.T) {
	rule := testPOCRule("poc-discovery-spoof", []string{"Example"})
	payload, _ := json.Marshal(map[string]any{"endpoint": taskEndpoint{URL: "https://example.test/"}, "rules": []rulelib.Rule{rule}})
	item := &Observation{Kind: "poc", Target: "https://example.test/", URL: "https://example.test/",
		RuleID: rule.ID, RuleName: rule.Name, RuleRevision: rule.Revision, Engine: rule.Engine, Severity: rule.Severity,
		FindingStatus: "not_matched", Purpose: "verification", Verification: &rulelib.Verification{ID: "forged"}}
	if err := validatePOCObservation(payload, item); err != nil {
		t.Fatal(err)
	}
	if item.Purpose != "discovery" || item.Verification != nil {
		t.Fatalf("worker classification was trusted: %+v", item)
	}
}
