package rulelib

// expandedPoCRules keeps product-linked checks inside the deliberately small
// read-only subset. These rules confirm a product-specific surface or a real
// unauthenticated exposure; none infer a CVE from a version banner.
func expandedPoCRules() []Rule {
	type spec struct {
		id, name, severity, product, path, description, part string
		statuses                                             []int
		patterns                                             []string
		tags                                                 []string
	}
	specs := []spec{
		{"poc-jenkins-whoami", "Jenkins anonymous identity endpoint discovery", "info", "Jenkins", "/whoAmI/api/json", "Confirms the Jenkins anonymous identity response without listing jobs, views, users, or controller configuration.", "body", []int{200}, []string{`(?s)"_class"\s*:\s*"hudson\.security\.WhoAmI"`, `(?s)"anonymous"\s*:\s*true`}, []string{"discovery", "api"}},
		{"poc-elasticsearch-cluster-health", "Elasticsearch cluster health exposure", "low", "Elasticsearch", "/_cluster/health", "Confirms unauthenticated access to Elasticsearch cluster identity and health data.", "body", []int{200}, []string{`(?s)"cluster_name"\s*:`, `(?s)"status"\s*:\s*"(?:green|yellow|red)"`}, []string{"exposure", "api"}},
		{"poc-kibana-status-api", "Kibana status API exposure", "low", "Kibana", "/api/status", "Confirms unauthenticated access to Kibana status and version metadata.", "body", []int{200}, []string{`(?s)"version"\s*:\s*\{`, `(?s)"number"\s*:\s*"[0-9]`}, []string{"exposure", "api"}},
		{"poc-rabbitmq-overview-api", "RabbitMQ management overview exposure", "low", "RabbitMQ Management", "/api/overview", "Confirms unauthenticated access to RabbitMQ management version metadata.", "body", []int{200}, []string{`(?s)"management_version"\s*:`, `(?s)"rabbitmq_version"\s*:`}, []string{"exposure", "api"}},
		{"poc-vault-health-discovery", "Vault health endpoint discovery", "info", "Vault", "/v1/sys/health", "Confirms the documented Vault health surface without treating health state as a vulnerability.", "body", []int{200, 429, 472, 473, 501, 503}, []string{`(?s)"initialized"\s*:`, `(?s)"sealed"\s*:`}, []string{"discovery", "health"}},
		{"poc-grafana-health-api", "Grafana health endpoint discovery", "info", "Grafana", "/api/health", "Confirms the product-specific Grafana health response without claiming a vulnerability.", "body", []int{200}, []string{`(?s)"database"\s*:\s*"ok"`, `(?s)"version"\s*:`}, []string{"discovery", "health"}},
		{"poc-prometheus-buildinfo-api", "Prometheus build metadata exposure", "low", "Prometheus", "/api/v1/status/buildinfo", "Confirms unauthenticated access to Prometheus build metadata.", "body", []int{200}, []string{`(?s)"status"\s*:\s*"success"`, `(?s)"version"\s*:`}, []string{"exposure", "api"}},
		{"poc-harbor-ping", "Harbor API health discovery", "info", "Harbor", "/api/v2.0/ping", "Confirms the product-specific Harbor API ping response without reading system configuration.", "body", []int{200}, []string{`(?i)^\s*Pong\s*$`}, []string{"discovery", "health"}},
		{"poc-sonarqube-system-status", "SonarQube system status exposure", "low", "SonarQube", "/api/system/status", "Confirms unauthenticated access to SonarQube system status and version metadata.", "body", []int{200}, []string{`(?s)"status"\s*:`, `(?s)"version"\s*:`}, []string{"exposure", "api"}},
		{"poc-portainer-status-api", "Portainer status API discovery", "info", "Portainer", "/api/status", "Confirms the product-specific Portainer status endpoint without treating it as a vulnerability.", "body", []int{200}, []string{`(?s)"Version"\s*:`, `(?s)"InstanceID"\s*:`}, []string{"discovery", "api"}},
		{"poc-airflow-health-api", "Airflow health API exposure", "low", "Apache Airflow", "/health", "Confirms unauthenticated access to Apache Airflow component health metadata.", "body", []int{200}, []string{`(?s)"metadatabase"\s*:\s*\{`, `(?s)"scheduler"\s*:\s*\{`}, []string{"exposure", "health"}},
		{"poc-solr-node-health", "Solr node health discovery", "info", "Apache Solr", "/solr/admin/info/health", "Confirms the product-specific Apache Solr node-health response without reading system properties.", "body", []int{200}, []string{`(?s)"responseHeader"\s*:\s*\{`, `(?s)"status"\s*:\s*"OK"`}, []string{"discovery", "health"}},
		{"poc-druid-self-discovery", "Druid self-discovery status", "info", "Apache Druid", "/status/selfDiscovered/status", "Confirms the product-specific Apache Druid self-discovery endpoint.", "body", []int{200}, []string{`(?s)"selfDiscovered"\s*:\s*(?:true|false)`}, []string{"discovery", "health"}},
		{"poc-flink-overview-api", "Flink overview API exposure", "low", "Apache Flink", "/overview", "Confirms unauthenticated access to Apache Flink cluster overview metadata.", "body", []int{200}, []string{`(?s)"taskmanagers"\s*:`, `(?s)"flink-version"\s*:`}, []string{"exposure", "api"}},
		{"poc-hadoop-yarn-cluster-info", "Hadoop YARN cluster information exposure", "low", "Apache Hadoop", "/ws/v1/cluster/info", "Confirms unauthenticated access to Hadoop YARN ResourceManager metadata.", "body", []int{200}, []string{`(?s)"clusterInfo"\s*:\s*\{`, `(?s)"resourceManagerVersion"\s*:`}, []string{"exposure", "api"}},
		{"poc-nifi-flow-about", "NiFi about API exposure", "low", "Apache NiFi", "/nifi-api/flow/about", "Confirms unauthenticated access to Apache NiFi product and version metadata.", "body", []int{200}, []string{`(?s)"about"\s*:\s*\{`, `(?s)"title"\s*:\s*"(?:Apache )?NiFi"`}, []string{"exposure", "api"}},
		{"poc-nacos-server-state", "Nacos server state exposure", "low", "Nacos", "/nacos/v1/console/server/state", "Confirms unauthenticated access to Nacos server state and version metadata.", "body", []int{200}, []string{`(?s)"version"\s*:`, `(?s)"standalone_mode"\s*:`}, []string{"exposure", "api"}},
		{"poc-traefik-version-api", "Traefik dashboard API exposure", "low", "Traefik", "/api/version", "Confirms unauthenticated access to the Traefik dashboard version API.", "body", []int{200}, []string{`(?s)"Version"\s*:`, `(?s)"Codename"\s*:`}, []string{"exposure", "api"}},
		{"poc-envoy-readiness", "Envoy readiness endpoint discovery", "info", "Envoy", "/ready", "Confirms the product-specific Envoy admin readiness response without reading command-line or configuration details.", "body", []int{200}, []string{`(?i)^\s*LIVE\s*$`}, []string{"discovery", "health"}},
		{"poc-nginx-status", "nginx stub status exposure", "low", "nginx", "/nginx_status", "Confirms that nginx stub status metrics are exposed without authentication.", "body", []int{200}, []string{`(?m)^Active connections:\s*\d+`, `(?m)^Reading:\s*\d+\s+Writing:\s*\d+\s+Waiting:\s*\d+`}, []string{"exposure", "metrics"}},
		{"poc-openresty-status", "OpenResty stub status exposure", "low", "OpenResty", "/nginx_status", "Confirms that OpenResty/nginx stub status metrics are exposed without authentication.", "body", []int{200}, []string{`(?m)^Active connections:\s*\d+`, `(?m)^Reading:\s*\d+\s+Writing:\s*\d+\s+Waiting:\s*\d+`}, []string{"exposure", "metrics"}},
		{"poc-werkzeug-console", "Werkzeug debugger console exposure", "medium", "Werkzeug", "/console", "Confirms that the Werkzeug debugger console surface is reachable; the check does not execute console commands.", "body", []int{200}, []string{`(?i)Werkzeug`, `(?i)(?:Console Locked|Interactive Console)`}, []string{"exposure", "debug"}},
		{"poc-iis-default-page", "Microsoft IIS default page discovery", "info", "Microsoft IIS", "/iisstart.htm", "Confirms the product-specific Microsoft IIS default start page.", "body", []int{200}, []string{`(?is)<title>\s*IIS Windows Server\s*</title>`, `(?i)IIS Windows Server`}, []string{"discovery", "default-page"}},
		{"poc-django-admin-login", "Django administration endpoint discovery", "info", "Django", "/admin/login/", "Confirms the Django administration login surface without attempting authentication.", "body", []int{200}, []string{`(?i)csrfmiddlewaretoken`, `(?i)Django administration`}, []string{"discovery", "admin"}},
		{"poc-phpmyadmin-setup", "phpMyAdmin setup interface exposure", "medium", "phpMyAdmin", "/setup/index.php", "Confirms that the phpMyAdmin setup interface is reachable without changing configuration.", "body", []int{200}, []string{`(?i)phpMyAdmin`, `(?i)(?:setup|configuration storage)`}, []string{"exposure", "setup"}},
		{"poc-swagger-ui-interface", "Swagger UI interface discovery", "info", "Swagger UI", "/swagger-ui/index.html", "Confirms a product-specific Swagger UI page without claiming that the documented API is vulnerable.", "body", []int{200}, []string{`(?is)<title>\s*Swagger UI\s*</title>`, `(?i)swagger-ui`}, []string{"discovery", "api"}},
		{"poc-gitea-version-api", "Gitea version API discovery", "info", "Gitea", "/api/v1/version", "Confirms the product-specific Gitea version endpoint.", "body", []int{200}, []string{`(?s)^\s*\{\s*"version"\s*:\s*"[0-9]`}, []string{"discovery", "api"}},
		{"poc-gitlab-health", "GitLab health endpoint discovery", "info", "GitLab", "/-/health", "Confirms the documented GitLab application-server health response without querying dependent services.", "body", []int{200}, []string{`(?i)^\s*GitLab OK\s*$`}, []string{"discovery", "health"}},
		{"poc-mediawiki-api", "MediaWiki API surface discovery", "info", "MediaWiki", "/api.php", "Confirms a MediaWiki API response without adding query parameters or accessing wiki data.", "body", []int{200}, []string{`(?is)MediaWiki API`, `(?is)(?:apihelp|missingparam|The "action" parameter)`}, []string{"discovery", "api"}},
		{"poc-joomla-version-manifest", "Joomla version manifest discovery", "info", "Joomla", "/administrator/manifests/files/joomla.xml", "Confirms the standard Joomla product manifest and its public version metadata.", "body", []int{200}, []string{`(?is)<name>\s*files_joomla\s*</name>`, `(?is)<version>\s*[0-9]`}, []string{"discovery", "metadata"}},
		{"poc-drupal-changelog", "Drupal changelog exposure", "low", "Drupal", "/core/CHANGELOG.txt", "Confirms that the Drupal core changelog and version history are publicly exposed.", "body", []int{200}, []string{`(?m)^Drupal [0-9]`, `(?m)^-+\s*$`}, []string{"exposure", "metadata"}},
		{"poc-gatsby-app-data", "Gatsby build metadata discovery", "info", "Gatsby", "/page-data/app-data.json", "Confirms the standard Gatsby app-data manifest without accessing application records.", "body", []int{200}, []string{`(?s)"webpackCompilationHash"\s*:`}, []string{"discovery", "metadata"}},
		{"poc-angular-service-worker-manifest", "Angular service worker manifest discovery", "info", "Angular", "/ngsw.json", "Confirms the Angular service-worker manifest without downloading application data.", "body", []int{200}, []string{`(?s)"configVersion"\s*:\s*[0-9]+`, `(?s)"timestamp"\s*:`}, []string{"discovery", "metadata"}},
		{"poc-aspnet-blazor-manifest", "ASP.NET Blazor boot manifest discovery", "info", "ASP.NET", "/_framework/blazor.boot.json", "Confirms the public ASP.NET Blazor boot manifest without accessing server-side configuration.", "body", []int{200}, []string{`(?s)"resources"\s*:\s*\{`, `(?s)"(?:runtime|dotnetjs|assembly)"\s*:`}, []string{"discovery", "metadata"}},
		{"poc-tomcat-manager-surface", "Tomcat Manager surface discovery", "info", "Apache Tomcat", "/manager/html", "Confirms the Tomcat Manager authentication surface without attempting credentials.", "header", []int{401}, []string{`(?im)^Www-Authenticate:\s*Basic[^\r\n]*Tomcat Manager Application`}, []string{"discovery", "admin"}},
		{"poc-sharepoint-client-service", "SharePoint client service discovery", "info", "Microsoft SharePoint", "/_vti_bin/client.svc", "Confirms the SharePoint client service response without querying site or user data.", "body", []int{200, 400, 405}, []string{`(?i)Microsoft\.SharePoint\.Client|SharePoint`}, []string{"discovery", "api"}},
	}

	rules := make([]Rule, 0, len(specs))
	for _, item := range specs {
		matchers := []Matcher{{Part: "status", Type: "status", Status: item.statuses, Condition: "or"}, {
			Part: item.part, Type: "regex", Regex: item.patterns, Condition: "and", CaseSensitive: true,
		}}
		rule := pocRule(item.id, item.name, item.severity, item.product, item.path, matchers)
		rule.Description = item.description
		rule.Tags = append(rule.Tags, item.tags...)
		rule.Source = "Safe read-only adaptation informed by projectdiscovery/nuclei-templates@e07ef215 and hanc00l/poc_map@acfdd0bf; rewritten for SHEN's static native subset"
		rules = append(rules, rule)
	}
	return rules
}
