package rulelib

import "testing"

func TestExpandedHTTPRulesValidateAndUseStrongSignals(t *testing.T) {
	rules := expandedHTTPRules()
	if len(rules) < 45 {
		t.Fatalf("expanded HTTP count = %d, want at least 45", len(rules))
	}
	byID := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if byID[rule.ID].ID != "" {
			t.Fatalf("duplicate expanded HTTP id %q", rule.ID)
		}
		byID[rule.ID] = rule
		if err := Validate(rule); err != nil {
			t.Fatalf("rule %q is invalid: %v", rule.ID, err)
		}
	}
	tests := []struct {
		id       string
		positive Input
		negative Input
	}{
		{"http-magento", Input{Body: `<script type="text/x-magento-init">{}</script>`}, Input{Body: "A guide to Magento stores"}},
		{"http-atlassian-confluence", Input{Header: "X-Confluence-Request-Time: 123\r\n"}, Input{Body: "Confluence documentation"}},
		{"http-varnish", Input{Header: "Via: 1.1 varnish\r\nX-Varnish: 42\r\n"}, Input{Body: "how varnish works"}},
		{"http-keycloak", Input{Body: `<form id="kc-form-login" action="/realms/x/login-actions/authenticate?session_code=x">`}, Input{Body: `<form id="kc-form-login">generic login</form>`}},
		{"http-apache-airflow", Input{Title: "Airflow", Body: `<script src="/static/dist/main.js"></script>`}, Input{Title: "Airflow", Body: "airflow consulting"}},
	}
	for _, test := range tests {
		rule := byID[test.id]
		if _, ok := Match(rule, test.positive); !ok {
			t.Errorf("rule %q missed positive sample", test.id)
		}
		if _, ok := Match(rule, test.negative); ok {
			t.Errorf("rule %q matched generic negative sample", test.id)
		}
	}
}

func TestExpandedPoCProductsHaveHTTPFingerprints(t *testing.T) {
	products := map[string]bool{}
	for _, rule := range Builtins() {
		if rule.Kind == "http" {
			products[normalizeProduct(rule.Definition.Product)] = true
		}
	}
	for _, rule := range expandedPoCRules() {
		for _, product := range rule.AppliesTo {
			if !products[normalizeProduct(product)] {
				t.Errorf("PoC %q product %q has no HTTP fingerprint", rule.ID, product)
			}
		}
	}
}
