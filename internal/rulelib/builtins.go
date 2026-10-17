package rulelib

import "regexp"

func Builtins() []Rule {
	rules := make([]Rule, 0, 80)
	rules = append(rules, builtinHTTPRules()...)
	rules = append(rules, expandedHTTPRules()...)
	rules = append(rules, builtinPortRules()...)
	rules = append(rules, builtinPoCRules()...)
	rules = append(rules, expandedPoCRules()...)
	return rules
}

func builtinHTTPRules() []Rule {
	specs := []struct {
		id, product, part, pattern, versionRegex, versionPart string
	}{
		{"http-wordpress", "WordPress", "body", `(?is)(?:href|src)\s*=\s*["'][^"']*/wp-(?:content|includes)/`, `(?i)content\s*=\s*["']WordPress\s+([0-9][0-9A-Za-z.+_-]*)`, "body"},
		{"http-drupal", "Drupal", "header", `(?im)^X-Drupal-(?:Cache|Dynamic-Cache):`, "", ""},
		{"http-joomla", "Joomla", "body", `(?is)<meta\b[^>]*content=["']Joomla!?`, "", ""},
		{"http-ghost", "Ghost", "body", `(?is)<meta\b[^>]*content\s*=\s*["']Ghost(?:\s+([0-9][0-9A-Za-z.+_-]*))?`, `(?is)<meta\b[^>]*content\s*=\s*["']Ghost\s+([0-9][0-9A-Za-z.+_-]*)`, "body"},
		{"http-mediawiki", "MediaWiki", "body", `(?is)<meta\b[^>]*content\s*=\s*["']MediaWiki(?:\s+[^"']+)?`, `(?is)content\s*=\s*["']MediaWiki\s+([0-9][0-9A-Za-z.+_-]*)`, "body"},
		{"http-typo3", "TYPO3 CMS", "body", `(?is)<meta\b[^>]*content=["']TYPO3(?: CMS)?`, "", ""},
		{"http-hugo", "Hugo", "body", `(?is)<meta\b[^>]*content\s*=\s*["']Hugo(?:\s+([0-9][0-9A-Za-z.+_-]*))?`, `(?is)content\s*=\s*["']Hugo\s+([0-9][0-9A-Za-z.+_-]*)`, "body"},
		{"http-nextjs", "Next.js", "body", `(?is)<script\b[^>]*\bid\s*=\s*["']__NEXT_DATA__["']`, "", ""},
		{"http-nuxt", "Nuxt", "body", `(?is)<(?:div|main)\b[^>]*\bid\s*=\s*["']__nuxt["']`, "", ""},
		{"http-gatsby", "Gatsby", "body", `(?is)<div\b[^>]*\bid\s*=\s*["']___gatsby["']`, "", ""},
		{"http-angular", "Angular", "body", `(?is)<[a-z][^>]*\bng-version\s*=\s*["'][0-9][0-9A-Za-z.+_-]*["']`, `(?is)ng-version\s*=\s*["']([0-9][0-9A-Za-z.+_-]*)["']`, "body"},
		{"http-laravel", "Laravel", "header", `(?im)^Set-Cookie:[^\r\n]*\blaravel_session=`, "", ""},
		{"http-aspnet", "ASP.NET", "header", `(?im)^(?:X-AspNet-Version|X-Powered-By):[^\r\n]*ASP\.NET|^X-AspNet-Version:`, `(?im)^X-AspNet-Version:\s*([0-9][0-9A-Za-z.+_-]*)`, "header"},
		{"http-express", "Express", "header", `(?im)^X-Powered-By:\s*Express\s*$`, "", ""},
		{"http-php", "PHP", "header", `(?im)^X-Powered-By:[^\r\n]*\bPHP/[0-9]`, `(?im)\bPHP/([0-9][0-9A-Za-z.+_-]*)`, "header"},
		{"http-nginx", "nginx", "header", `(?im)^Server:\s*nginx(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*nginx/([^\s]+)`, "header"},
		{"http-apache", "Apache HTTP Server", "header", `(?im)^Server:\s*Apache(?:/[^\s(]+)?(?:\s|$)`, `(?im)^Server:\s*Apache/([^\s(]+)`, "header"},
		{"http-iis", "Microsoft IIS", "header", `(?im)^Server:\s*Microsoft-IIS(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*Microsoft-IIS/([^\s]+)`, "header"},
		{"http-caddy", "Caddy", "header", `(?im)^Server:\s*Caddy(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*Caddy/([^\s]+)`, "header"},
		{"http-openresty", "OpenResty", "header", `(?im)^Server:\s*openresty(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*openresty/([^\s]+)`, "header"},
		{"http-lighttpd", "lighttpd", "header", `(?im)^Server:\s*lighttpd(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*lighttpd/([^\s]+)`, "header"},
		{"http-gunicorn", "Gunicorn", "header", `(?im)^Server:\s*gunicorn(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*gunicorn/([^\s]+)`, "header"},
		{"http-uvicorn", "Uvicorn", "header", `(?im)^Server:\s*uvicorn(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*uvicorn/([^\s]+)`, "header"},
		{"http-werkzeug", "Werkzeug", "header", `(?im)^Server:[^\r\n]*Werkzeug(?:/[^\s]+)?`, `(?im)Werkzeug/([^\s]+)`, "header"},
		{"http-cloudflare", "Cloudflare", "header", `(?im)^Server:\s*cloudflare\s*$`, "", ""},
		{"http-envoy", "Envoy", "header", `(?im)^Server:\s*envoy\s*$`, "", ""},
		{"http-traefik", "Traefik", "header", `(?im)^Server:\s*Traefik(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*Traefik/([^\s]+)`, "header"},
		{"http-kestrel", "Kestrel", "header", `(?im)^Server:\s*Kestrel\s*$`, "", ""},
		{"http-cowboy", "Cowboy", "header", `(?im)^Server:\s*Cowboy\s*$`, "", ""},
		{"http-litespeed", "LiteSpeed", "header", `(?im)^Server:\s*(?:LiteSpeed|OpenLiteSpeed)(?:/[^\s]+)?\s*$`, "", ""},
		{"http-jenkins", "Jenkins", "header", `(?im)^X-Jenkins:\s*[0-9][^\r\n]*$`, `(?im)^X-Jenkins:\s*([^\s]+)`, "header"},
		{"http-grafana", "Grafana", "body", `(?s)\bgrafanaBootData\b`, "", ""},
		{"http-kibana", "Kibana", "body", `(?s)\bkbn-injected-metadata\b`, "", ""},
		{"http-prometheus", "Prometheus", "title", `(?i)^Prometheus Time Series Collection(?: and Processing Server)?$`, "", ""},
		{"http-rabbitmq", "RabbitMQ Management", "title", `(?i)^RabbitMQ Management$`, "", ""},
		{"http-phpmyadmin", "phpMyAdmin", "body", `(?is)(?:\bid\s*=\s*["']pma_navigation["']|\bname\s*=\s*["']pma_username["']|\bPMA_VERSION\s*[:=])`, "", ""},
		{"http-swagger-ui", "Swagger UI", "title", `(?i)^Swagger UI$`, "", ""},
		{"http-gitlab", "GitLab", "header", `(?im)^X-GitLab-Meta:`, "", ""},
		{"http-gitea", "Gitea", "body", generatorHTMLPattern(`Gitea`), "", ""},
		{"http-harbor", "Harbor", "body", `(?is)<harbor-app(?:\s|>)`, "", ""},
		{"http-sonarqube", "SonarQube", "header", `(?im)^Sonar-Version:\s*[^\r\n]+$`, `(?im)^Sonar-Version:\s*([^\s]+)`, "header"},
		{"http-minio", "MinIO", "header", `(?im)^Server:\s*MinIO(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*MinIO/([^\s]+)`, "header"},
		{"http-portainer", "Portainer", "title", `(?i)^Portainer$`, "", ""},
		{"http-elasticsearch", "Elasticsearch", "header", `(?im)^X-Elastic-Product:\s*Elasticsearch\s*$`, "", ""},
		{"http-consul", "Consul", "header", `(?im)^X-Consul-Index:\s*[0-9]+\s*$`, "", ""},
		{"http-vault", "Vault", "header", `(?im)^X-Vault-(?:Request|Cluster):`, "", ""},
		{"http-nomad", "Nomad", "header", `(?im)^X-Nomad-Index:\s*[0-9]+\s*$`, "", ""},
		{"http-spring-boot", "Spring Boot", "header", `(?im)^X-Application-Context:\s*[^\r\n]+$`, "", ""},
		{"http-kubernetes-dashboard", "Kubernetes Dashboard", "body", `(?is)<kd-root(?:\s|>)`, "", ""},
		{"http-vite", "Vite", "body", `(?is)<script\b[^>]*src\s*=\s*["']/@vite/client["']`, "", ""},
		{"http-tomcat", "Apache Tomcat", "body", `(?is)<title>Apache Tomcat(?:/[^<]+)?</title>`, `(?is)<title>Apache Tomcat/([^<]+)</title>`, "body"},
		{"http-jetty", "Eclipse Jetty", "header", `(?im)^Server:\s*Jetty(?:\([^)]*\))?`, "", ""},
		{"http-sharepoint", "Microsoft SharePoint", "header", `(?im)^MicrosoftSharePointTeamServices:\s*[^\r\n]+$`, `(?im)^MicrosoftSharePointTeamServices:\s*([^\s]+)`, "header"},
	}
	rules := make([]Rule, 0, len(specs)+1)
	for _, spec := range specs {
		definition := Definition{
			Service: "http", Product: spec.product, VersionRegex: spec.versionRegex, VersionPart: spec.versionPart,
			Condition: "and", Matchers: []Matcher{{Part: spec.part, Type: "regex", Regex: []string{spec.pattern}, Condition: "or", CaseSensitive: true}},
		}
		switch spec.id {
		case "http-wordpress":
			definition.Condition = "or"
			definition.Matchers = append(definition.Matchers,
				Matcher{Part: "body", Type: "regex", Regex: []string{generatorHTMLPattern(`WordPress`)}, Condition: "or", CaseSensitive: true},
				Matcher{Part: "header", Type: "regex", Regex: []string{generatorHeaderPattern(`WordPress`)}, Condition: "or", CaseSensitive: true})
		case "http-drupal":
			definition.Condition = "or"
			definition.Matchers = append(definition.Matchers,
				Matcher{Part: "body", Type: "regex", Regex: []string{generatorHTMLPattern(`Drupal`)}, Condition: "or", CaseSensitive: true},
				Matcher{Part: "header", Type: "regex", Regex: []string{generatorHeaderPattern(`Drupal`)}, Condition: "or", CaseSensitive: true})
		case "http-joomla", "http-ghost", "http-mediawiki", "http-typo3", "http-hugo":
			productPattern := map[string]string{
				"http-joomla": `Joomla!?`, "http-ghost": `Ghost`, "http-mediawiki": `MediaWiki`,
				"http-typo3": `TYPO3(?: CMS)?`, "http-hugo": `Hugo`,
			}[spec.id]
			definition.Condition = "or"
			definition.Matchers = []Matcher{
				{Part: "body", Type: "regex", Regex: []string{generatorHTMLPattern(productPattern)}, Condition: "or", CaseSensitive: true},
				{Part: "header", Type: "regex", Regex: []string{generatorHeaderPattern(productPattern)}, Condition: "or", CaseSensitive: true},
			}
		case "http-nextjs":
			definition.Condition = "or"
			definition.Matchers = append(definition.Matchers, Matcher{
				Part: "header", Type: "regex", Regex: []string{`(?im)^X-Powered-By:\s*Next\.js\s*$`}, Condition: "or", CaseSensitive: true,
			})
		}
		rules = append(rules, Rule{
			ID: spec.id, Kind: "http", Name: spec.product + " HTTP fingerprint",
			Description: "Passive match on a product-specific HTTP response marker.", Engine: "native", Severity: "info",
			Enabled: true, Builtin: true, Revision: 1, Tags: []string{"fingerprint", "http"},
			Source: "SHEN built-in v1; passive HTTP header or HTML marker", Definition: definition,
		})
	}
	rules = append(rules, Rule{
		ID: "http-django", Kind: "http", Name: "Django HTTP fingerprint", Description: "Requires both Django's CSRF cookie and form token markers.",
		Engine: "native", Severity: "info", Enabled: true, Builtin: true, Revision: 1, Tags: []string{"fingerprint", "http"},
		Source: "SHEN built-in v1; Django CSRF cookie and template field", Definition: Definition{Service: "http", Product: "Django", Condition: "and", Matchers: []Matcher{
			{Part: "header", Type: "regex", Regex: []string{`(?im)^Set-Cookie:[^\r\n]*\bcsrftoken=`}, Condition: "or", CaseSensitive: true},
			{Part: "body", Type: "regex", Regex: []string{`(?is)name\s*=\s*["']csrfmiddlewaretoken["']`}, Condition: "or", CaseSensitive: true},
		}},
	})
	return rules
}

func generatorHTMLPattern(product string) string {
	name := `\bname\s*=\s*["']generator["']`
	content := `\bcontent\s*=\s*["']` + product + `(?:\s+[^"']*)?["']`
	return `(?is)<meta\b(?:[^>]*` + name + `[^>]*` + content + `|[^>]*` + content + `[^>]*` + name + `)[^>]*>`
}

func generatorHeaderPattern(product string) string {
	return `(?im)^X-Generator:\s*` + product + `(?:\s|$)`
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
