package rulelib

import "regexp"

func Builtins() []Rule {
	rules := make([]Rule, 0, 80)
	rules = append(rules, builtinPortRules()...)
	poc := append(builtinPoCRules(), expandedPoCRules()...)
	rules = append(rules, poc...)
	return rules
}

func builtinPortRules() []Rule {
	specs := []struct{ id, service, product string }{
		{"port-openssh", "ssh", "OpenSSH"}, {"port-dropbear", "ssh", "Dropbear"},
		{"port-libssh", "ssh", "libssh"}, {"port-putty", "ssh", "PuTTY"},
		{"port-nginx", "http", "nginx"}, {"port-apache", "http", "Apache HTTP Server"},
		{"port-iis", "http", "Microsoft IIS"}, {"port-caddy", "http", "Caddy"},
		{"port-openresty", "http", "OpenResty"}, {"port-lighttpd", "http", "lighttpd"},
		{"port-gunicorn", "http", "Gunicorn"}, {"port-uvicorn", "http", "Uvicorn"},
		{"port-werkzeug", "http", "Werkzeug"}, {"port-vsftpd", "ftp", "vsftpd"},
		{"port-proftpd", "ftp", "ProFTPD"}, {"port-filezilla", "ftp", "FileZilla Server"},
		{"port-exim", "smtp", "Exim"}, {"port-postfix", "smtp", "Postfix"},
		{"port-mysql", "mysql", "MySQL"}, {"port-mariadb", "mysql", "MariaDB"},
		{"port-redis", "redis", "Redis"}, {"port-memcached", "memcached", "Memcached"},
	}
	rules := make([]Rule, 0, len(specs))
	for _, spec := range specs {
		rules = append(rules, Rule{
			ID: spec.id, Kind: "port", Name: spec.product + " service fingerprint",
			Description: "Matches the product identity parsed from an application protocol banner or handshake.",
			Engine:      "native", Severity: "info", Enabled: true, Builtin: true, Revision: 1,
			Tags: []string{"fingerprint", "service"}, Source: "SHEN built-in v1; protocol parser product identity",
			Definition: Definition{Service: spec.service, Product: spec.product, UseDetectedVersion: true, Condition: "and", Matchers: []Matcher{
				{Part: "service", Type: "regex", Regex: []string{"(?i)^" + regexp.QuoteMeta(spec.service) + "$"}, Condition: "or", CaseSensitive: true},
				{Part: "product", Type: "regex", Regex: []string{"(?i)^" + regexp.QuoteMeta(spec.product) + "$"}, Condition: "or", CaseSensitive: true},
			}},
		})
	}
	return rules
}

func builtinPoCRules() []Rule {
	rules := []Rule{
		pocRule("poc-exposed-git-head", "Exposed Git HEAD", "medium", "Git", "/.git/HEAD", []Matcher{
			{Part: "status", Type: "status", Status: []int{200}, Condition: "or"},
			{Part: "body", Type: "regex", Regex: []string{`(?m)^ref: refs/heads/[A-Za-z0-9._/-]+\s*$`}, Condition: "or", CaseSensitive: true},
		}),
		pocRule("poc-wordpress-readme", "WordPress public readme", "info", "WordPress", "/readme.html", []Matcher{
			{Part: "status", Type: "status", Status: []int{200}, Condition: "or"},
			{Part: "body", Type: "regex", Regex: []string{`(?is)<title>\s*WordPress[^<]*</title>|Semantic Personal Publishing Platform`}, Condition: "or", CaseSensitive: true},
		}),
		pocRule("poc-grafana-login", "Grafana login endpoint", "info", "Grafana", "/login", []Matcher{
			{Part: "status", Type: "status", Status: []int{200}, Condition: "or"},
			{Part: "body", Type: "regex", Regex: []string{`(?s)\bgrafanaBootData\b`}, Condition: "or", CaseSensitive: true},
		}),
		pocRule("poc-prometheus-ready", "Prometheus readiness endpoint", "info", "Prometheus", "/-/ready", []Matcher{
			{Part: "status", Type: "status", Status: []int{200}, Condition: "or"},
			{Part: "body", Type: "word", Words: []string{"Prometheus is Ready."}, Condition: "or", CaseSensitive: true},
		}),
		pocRule("poc-kubernetes-version", "Kubernetes version endpoint", "info", "Kubernetes API", "/version", []Matcher{
			{Part: "status", Type: "status", Status: []int{200}, Condition: "or"},
			{Part: "body", Type: "word", Words: []string{`"gitVersion":`, `"major":`}, Condition: "and", CaseSensitive: true},
		}),
		pocRule("poc-spring-health", "Spring Boot health endpoint", "info", "Spring Boot", "/actuator/health", []Matcher{
			{Part: "status", Type: "status", Status: []int{200}, Condition: "or"},
			{Part: "body", Type: "regex", Regex: []string{`(?i)"status"\s*:\s*"UP"`}, Condition: "or", CaseSensitive: true},
		}),
	}
	const securityTXT = `id: poc-security-txt
info:
  name: Published security.txt policy
  author: SHEN
  severity: info
  description: Confirms a same-origin security.txt policy using a read-only request.
  tags: discovery,read-only
http:
  - method: GET
    path:
      - '{{BaseURL}}/.well-known/security.txt'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - '(?mi)^Contact:\s*\S+'
`
	if rule, err := ParseNuclei(securityTXT); err == nil {
		rule.Enabled = true
		rule.Builtin = true
		rule.Source = "SHEN built-in v1; RFC 9116 security.txt Contact field"
		rules = append(rules, rule)
	}
	return rules
}

func pocRule(id, name, severity, product, path string, matchers []Matcher) Rule {
	appliesTo := []string{product}
	if id == "poc-exposed-git-head" || product == "" {
		appliesTo = nil
	}
	return Rule{
		ID: id, Kind: "poc", Name: name, Description: "Read-only same-origin endpoint check with bounded response matchers.",
		Engine: "native", Severity: severity, Enabled: true, Builtin: true, Revision: 1,
		Tags: []string{"poc", "read-only"}, AppliesTo: appliesTo, Source: "SHEN built-in v1; documented or product-specific read-only endpoint",
		Definition: Definition{Service: "http", Product: product, Condition: "and", Requests: []Request{{
			Method: "GET", Path: path, Condition: "and", Matchers: matchers,
		}}},
	}
}
