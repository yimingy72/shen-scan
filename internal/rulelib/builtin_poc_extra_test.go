package rulelib

import "testing"

func TestExpandedPoCRulesAreProductLinkedAndValid(t *testing.T) {
	rules := expandedPoCRules()
	if len(rules) < 30 {
		t.Fatalf("expanded PoC count = %d, want at least 30", len(rules))
	}
	ids, products := map[string]bool{}, map[string]bool{}
	forbiddenPaths := map[string]bool{
		"/v1/agent/self": true, "/server_info": true,
		"/api/v2.0/systeminfo": true, "/solr/admin/info/system": true,
		"/api/json": true, "/server-status": true,
	}
	for _, rule := range rules {
		if ids[rule.ID] {
			t.Fatalf("duplicate rule id %q", rule.ID)
		}
		ids[rule.ID] = true
		if len(rule.AppliesTo) == 0 {
			t.Fatalf("rule %q is not product-linked", rule.ID)
		}
		for _, product := range rule.AppliesTo {
			products[normalizeProduct(product)] = true
		}
		if err := Validate(rule); err != nil {
			t.Fatalf("rule %q is invalid: %v", rule.ID, err)
		}
		if rule.Engine != "native" || !rule.Enabled || !rule.Builtin || len(rule.Definition.Requests) != 1 {
			t.Fatalf("rule %q has unsafe execution shape: %#v", rule.ID, rule)
		}
		request := rule.Definition.Requests[0]
		if request.Method != "GET" || len(request.Matchers) < 2 || request.Matchers[0].Type != "status" {
			t.Fatalf("rule %q lacks status plus content evidence", rule.ID)
		}
		if forbiddenPaths[request.Path] {
			t.Fatalf("rule %q reads broader deployment metadata from %s", rule.ID, request.Path)
		}
	}
	if len(products) < 30 {
		t.Fatalf("expanded product coverage = %d, want at least 30", len(products))
	}
}

func TestExpandedPoCRulePositiveAndNegativeSamples(t *testing.T) {
	tests := []struct {
		id       string
		positive Input
		negative Input
	}{
		{
			id:       "poc-jenkins-whoami",
			positive: Input{Status: 200, Body: `{"_class":"hudson.security.WhoAmI","anonymous":true,"authenticated":false}`},
			negative: Input{Status: 200, Body: `<html><title>Welcome</title></html>`},
		},
		{
			id:       "poc-werkzeug-console",
			positive: Input{Status: 200, Body: `<title>Console Locked - Werkzeug Debugger</title>`},
			negative: Input{Status: 200, Body: `<title>Werkzeug application</title>`},
		},
		{
			id:       "poc-tomcat-manager-surface",
			positive: Input{Status: 401, Header: "Www-Authenticate: Basic realm=\"Tomcat Manager Application\"\r\n"},
			negative: Input{Status: 401, Header: "Www-Authenticate: Basic realm=\"Restricted\"\r\n"},
		},
		{
			id:       "poc-gitlab-health",
			positive: Input{Status: 200, Body: "GitLab OK\n"},
			negative: Input{Status: 200, Body: `{"status":"ok"}`},
		},
	}
	rules := expandedPoCRules()
	for _, test := range tests {
		var rule Rule
		for _, candidate := range rules {
			if candidate.ID == test.id {
				rule = candidate
				break
			}
		}
		if rule.ID == "" {
			t.Fatalf("missing rule %q", test.id)
		}
		if _, ok := NativePoCMatch(rule, []Input{test.positive}); !ok {
			t.Errorf("rule %q missed positive sample", test.id)
		}
		if _, ok := NativePoCMatch(rule, []Input{test.negative}); ok {
			t.Errorf("rule %q matched generic negative sample", test.id)
		}
	}
}
