package rulelib

import (
	"strings"
	"testing"
)

func TestBuiltinsValidateAndMatch(t *testing.T) {
	counts := map[string]int{}
	engines := map[string]int{}
	seen := map[string]bool{}
	byID := map[string]Rule{}
	var wordpress, openSSH, gitHead Rule
	for _, rule := range Builtins() {
		if seen[rule.ID] {
			t.Fatalf("duplicate builtin id %q", rule.ID)
		}
		seen[rule.ID] = true
		byID[rule.ID] = rule
		counts[rule.Kind]++
		engines[rule.Engine]++
		if err := Validate(rule); err != nil {
			t.Fatalf("builtin %s is invalid: %v", rule.ID, err)
		}
		switch rule.ID {
		case "http-wordpress":
			wordpress = rule
		case "port-openssh":
			openSSH = rule
		case "poc-exposed-git-head":
			gitHead = rule
		}
	}
	if counts["http"] < 150 || counts["port"] < 22 || counts["poc"] < 43 || engines["nuclei"] < 1 {
		t.Fatalf("builtin counts too small: kinds=%#v engines=%#v", counts, engines)
	}
	wpInput := Input{Body: `<meta name="generator" content="WordPress 6.7"><link href="/wp-content/a.css">`}
	if result, ok := Match(wordpress, wpInput); !ok || result.Product != "WordPress" || result.Version != "6.7" {
		t.Fatalf("WordPress match = %#v, %v", result, ok)
	}
	if _, ok := Match(wordpress, Input{Body: "an article about WordPress"}); ok {
		t.Fatal("plain product mention must not match WordPress")
	}
	wpGenerator := Input{Body: `<meta name = "generator" content = "WordPress 6.8">`}
	if result, ok := Match(wordpress, wpGenerator); !ok || result.Version != "6.8" {
		t.Fatalf("generator-only WordPress match = %#v, %v", result, ok)
	}
	if _, ok := Match(byID["http-drupal"], Input{Header: "X-Generator: WordPress 6.8\r\n"}); ok {
		t.Fatal("WordPress X-Generator must not match Drupal")
	}
	if _, ok := Match(byID["http-drupal"], Input{Body: `<meta content="Drupal 11" name="generator">`}); !ok {
		t.Fatal("Drupal generator metadata should match")
	}
	if _, ok := Match(byID["http-phpmyadmin"], Input{Body: "This article explains phpMyAdmin."}); ok {
		t.Fatal("plain phpMyAdmin mention must not match")
	}
	if _, ok := Match(byID["http-phpmyadmin"], Input{Body: `<input name = "pma_username">`}); !ok {
		t.Fatal("phpMyAdmin login field should match")
	}
	for id, input := range map[string]Input{
		"http-nextjs":  {Body: `<script id = "__NEXT_DATA__"></script>`},
		"http-nuxt":    {Body: `<div id = "__nuxt"></div>`},
		"http-angular": {Body: `<app-root ng-version = "19.0.0"></app-root>`},
	} {
		if _, ok := Match(byID[id], input); !ok {
			t.Errorf("spaced HTML attribute did not match %s", id)
		}
	}
	if _, ok := Match(byID["http-nextjs"], Input{Header: "X-Powered-By: Next.js\r\n"}); !ok {
		t.Fatal("Next.js X-Powered-By should match")
	}
	django := byID["http-django"]
	if _, ok := Match(django, Input{Header: "Set-Cookie: csrftoken=abc\r\n"}); ok {
		t.Fatal("Django cookie alone must not match")
	}
	if _, ok := Match(django, Input{Header: "Set-Cookie: csrftoken=abc\r\n", Body: `<input name = "csrfmiddlewaretoken">`}); !ok {
		t.Fatal("Django cookie and CSRF form field should match")
	}
	if result, ok := Match(openSSH, Input{Service: "ssh", Product: "OpenSSH", Version: "9.9"}); !ok || result.Version != "9.9" {
		t.Fatalf("OpenSSH match = %#v, %v", result, ok)
	}
	if _, ok := Match(openSSH, Input{Service: "ssh", Product: "Dropbear"}); ok {
		t.Fatal("wrong SSH product must not match OpenSSH")
	}
	if _, ok := NativePoCMatch(gitHead, []Input{{Status: 200, Body: "ref: refs/heads/main\n"}}); !ok {
		t.Fatal("expected exposed Git HEAD match")
	}
	if _, ok := NativePoCMatch(gitHead, []Input{{Status: 404, Body: "not found"}}); ok {
		t.Fatal("404 response must not match Git HEAD")
	}
}

func TestParseNucleiReadOnlySubset(t *testing.T) {
	safe := `id: safe-version
info:
  name: Safe version endpoint
  severity: info
  tags: version,read-only
http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["version"]
        case-insensitive: true
`
	rule, err := ParseNuclei(safe)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Enabled || rule.Builtin || rule.Engine != "nuclei" || rule.Definition.Requests[0].Path != "/version" || !strings.Contains(rule.Template, "{{BaseURL}}/version") {
		t.Fatalf("unexpected imported rule: %#v", rule)
	}

	unsafe := []string{
		strings.Replace(safe, "method: GET", "method: POST", 1),
		strings.Replace(safe, `{{BaseURL}}/version`, `https://other.example/version`, 1),
		strings.Replace(safe, `{{BaseURL}}/version`, `{{BaseURL}}/version?full=true`, 1),
		strings.Replace(safe, `{{BaseURL}}/version`, `{{BaseURL}}/../version`, 1),
		strings.Replace(safe, `{{BaseURL}}/version`, `{{BaseURL}}/api/delete-user`, 1),
		strings.Replace(safe, "    matchers-condition: and", "    redirects: true\n    matchers-condition: and", 1),
		strings.Replace(safe, "    matchers-condition: and", "    raw: ['GET / HTTP/1.1']\n    matchers-condition: and", 1),
		strings.Replace(safe, "    matchers-condition: and", "    payloads: {id: ['1']}\n    matchers-condition: and", 1),
	}
	for i, content := range unsafe {
		if _, err := ParseNuclei(content); err == nil {
			t.Errorf("unsafe template %d was accepted", i)
		}
	}
}

func TestProductBindingsAndNucleiMetadata(t *testing.T) {
	if !MatchesProducts(Rule{Kind: "poc", AppliesTo: []string{"Spring Boot"}}, []string{"springboot"}) {
		t.Fatal("Spring Boot alias did not match")
	}
	if !MatchesProducts(Rule{Kind: "poc", AppliesTo: []string{"Apache Tomcat"}}, []string{"tomcat"}) {
		t.Fatal("Tomcat alias did not match")
	}
	if MatchesProducts(Rule{Kind: "poc"}, []string{"WordPress"}) || MatchesProducts(Rule{Kind: "poc", AppliesTo: []string{"Grafana"}}, []string{"Prometheus"}) {
		t.Fatal("manual-only or different product binding matched")
	}

	template := `id: metadata-product
info:
  name: Metadata product binding
  severity: info
  metadata:
    product: [WordPress, Grafana]
http:
  - method: GET
    path: ['{{BaseURL}}/']
    matchers:
      - type: status
        status: [200]
`
	rule, err := ParseNuclei(template)
	if err != nil {
		t.Fatal(err)
	}
	if len(rule.AppliesTo) != 2 || !MatchesProducts(rule, []string{"wordpress"}) {
		t.Fatalf("metadata products were not imported: %#v", rule.AppliesTo)
	}
	rule.AppliesTo = []string{"Apache Tomcat"}
	if err := Validate(rule); err != nil {
		t.Fatalf("independently edited applies_to should remain valid: %v", err)
	}
	rule.AppliesTo = []string{"all"}
	if err := Validate(rule); err == nil {
		t.Fatal("wildcard applies_to was accepted")
	}
}

func TestImportedProductAliases(t *testing.T) {
	for alias, product := range map[string]string{
		"spring_boot": "Spring Boot", "apache_tomcat": "Apache Tomcat", "rabbitmq": "RabbitMQ Management",
		"apache_http_server": "Apache HTTP Server", "microsoft_iis": "Microsoft IIS", "sharepoint": "Microsoft SharePoint",
		"jetty": "Eclipse Jetty", "apache_airflow": "Apache Airflow", "solr": "Apache Solr", "flink": "Apache Flink",
		"nifi": "Apache NiFi", "apache_druid": "Apache Druid", "hadoop": "Apache Hadoop",
	} {
		rule := Rule{Kind: "poc", AppliesTo: []string{alias}}
		if !MatchesProducts(rule, []string{product}) || MatchesProducts(rule, []string{"unrelated " + product}) {
			t.Fatalf("product alias %q must match only %q", alias, product)
		}
	}
}
