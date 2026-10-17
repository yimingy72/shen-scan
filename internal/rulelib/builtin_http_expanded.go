package rulelib

const (
	wappalyzerSource = "Adapted from projectdiscovery/wappalyzergo v0.3.5@10c7df1 (MIT); selected passive response signal"
	shenSource       = "SHEN curated v2; product-specific passive response signal from documented/default product output"
)

// expandedHTTPRules contains one rule per product. Only passive root-response
// signals that map exactly to body/header/title matchers are included.
func expandedHTTPRules() []Rule {
	rules := []Rule{
		httpPassiveRule("http-adobe-aem", "Adobe Experience Manager", "cms", wappalyzerSource, "or",
			httpRegex("body", "or", `(?is)/etc(?:\.clientlibs|/clientlibs)/`, `(?is)\bclass\s*=\s*["'][^"']*\baem-grid\b`, `(?is)data-component-path\s*=\s*["'][^"']*jcr:`)),
		httpPassiveRule("http-craft-cms", "Craft CMS", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Powered-By:\s*Craft CMS\s*$`, `(?im)^Set-Cookie:[^\r\n]*\bCraftSessionId=`)),
		httpPassiveRule("http-dedecms", "DedeCMS", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<script\b[^>]*\bsrc\s*=\s*["'][^"']*dedeajax[^"']*["']`)),
		withHTTPVersion(httpPassiveRule("http-discuz-x", "Discuz! X", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", generatorHTMLPattern(`Discuz!\s*X?`))), "body", `(?is)\bcontent\s*=\s*["']Discuz!\s*X?\s*([0-9][0-9.]*)`),
		withHTTPVersion(httpPassiveRule("http-grav", "Grav", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", generatorHTMLPattern(`GravCMS`))), "body", `(?is)\bcontent\s*=\s*["']GravCMS\s*([0-9][0-9.]*)`),
		httpPassiveRule("http-october-cms", "October CMS", "cms", wappalyzerSource, "or",
			httpRegex("body", "or", generatorHTMLPattern(`OctoberCMS`)),
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\boctober_session=`)),
		httpPassiveRule("http-magento", "Magento", "cms", wappalyzerSource, "or",
			httpRegex("body", "or", `(?is)<script\b[^>]*\btype\s*=\s*["']text/x-magento-init["']`, `(?is)\bdata-requiremodule\s*=\s*["'](?:mage/|Magento_)`),
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\b(?:X-Magento-Vary|mage-cache-storage)=`)),
		httpPassiveRule("http-prestashop", "PrestaShop", "cms", wappalyzerSource, "or",
			httpRegex("body", "or", generatorHTMLPattern(`PrestaShop`), `(?is)/modules/ps_[a-z0-9_-]+/`),
			httpRegex("header", "or", `(?im)^(?:Powered-By|X-Powered-By):\s*PrestaShop\s*$`)),
		httpPassiveRule("http-shopware", "Shopware", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^sw-(?:context-token|invalidation-states|language-id|version-id):`),
			httpRegex("body", "or", metaNameContentPattern(`application-name`, `Shopware`))),
		httpPassiveRule("http-opencart", "OpenCart", "cms", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\bOCSESSID=`)),
		httpPassiveRule("http-sitecore", "Sitecore", "cms", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\b(?:SC_ANALYTICS_GLOBAL_COOKIE|SC_EXPVIEW|SC_OS_SESSIONID|sxa_site)=`)),
		httpPassiveRule("http-strapi", "Strapi", "cms", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^X-Powered-By:\s*Strapi(?:\s|$)`)),
		withHTTPVersion(httpPassiveRule("http-typecho", "Typecho", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", generatorHTMLPattern(`Typecho`))), "body", `(?is)\bcontent\s*=\s*["']Typecho\s+([0-9][0-9.]*)`),
		withHTTPVersion(httpPassiveRule("http-umbraco", "Umbraco", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Umbraco-Version:\s*[^\r\n]+$`),
			httpRegex("body", "or", generatorHTMLPattern(`Umbraco`))), "header", `(?im)^X-Umbraco-Version:\s*([^\s]+)`),
		httpPassiveRule("http-moodle", "Moodle", "cms", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\b(?:MoodleSession|MOODLEID_[^=]*)=`)),
		withHTTPVersion(httpPassiveRule("http-liferay", "Liferay", "cms", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Liferay-Portal:\s*[^\r\n]+$`)), "header", `(?im)^Liferay-Portal:.*?([0-9]+(?:\.[0-9]+)+)`),
		httpPassiveRule("http-atlassian-confluence", "Atlassian Confluence", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Confluence-Request-Time:`),
			httpRegex("body", "or", metaNameContentPattern(`confluence-request-time`, `[^"']+`))),
		httpPassiveRule("http-atlassian-jira", "Atlassian Jira", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", metaNameContentPattern(`application-name`, `JIRA`), `(?is)<[^>]+\bid\s*=\s*["']jira["']`)),
		httpPassiveRule("http-cakephp", "CakePHP", "framework", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\bCAKEPHP=`),
			httpRegex("body", "or", metaNameContentPattern(`application-name`, `CakePHP`))),
		httpPassiveRule("http-codeigniter", "CodeIgniter", "framework", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\b(?:ci_session|ci_csrf_token)=`)),
		httpPassiveRule("http-symfony", "Symfony", "framework", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\bsf_redirect=`),
			httpRegex("body", "or", `(?is)\bclass\s*=\s*["'][^"']*\bsf-toolbar(?:-block)?\b`)),
		httpPassiveRule("http-yii", "Yii", "framework", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\byii_csrf_token=`),
			httpRegex("body", "or", `(?is)<input\b[^>]*\bname\s*=\s*["']yii_csrf_token["']`, `(?is)/yii\.(?:validation|activeform)\.js`)),
		httpPassiveRule("http-ruby-on-rails", "Ruby on Rails", "framework", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^(?:Server|X-Powered-By):[^\r\n]*\bmod_(?:rails|rack)\b`)),
		httpPassiveRule("http-fastapi", "FastAPI", "framework", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<link\b[^>]*\bhref\s*=\s*["'][^"']*fastapi\.tiangolo\.com[^"']*["'][^>]*\brel\s*=\s*["']shortcut icon["']`, `(?is)<link\b[^>]*\brel\s*=\s*["']shortcut icon["'][^>]*\bhref\s*=\s*["'][^"']*fastapi\.tiangolo\.com`)),
		httpPassiveRule("http-sveltekit", "SvelteKit", "framework", wappalyzerSource, "or",
			httpRegex("body", "or", generatorHTMLPattern(`SvelteKit`), `(?is)\bdata-sveltekit-preload-data(?:\s*=|\s|>)`, `(?is)\bid\s*=\s*["']svelte-announcer["']`)),
		httpPassiveRule("http-remix", "Remix", "framework", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<script\b[^>]*>[^<]*\b(?:window\.)?__remixContext\b`)),
		withHTTPVersion(httpPassiveRule("http-astro", "Astro", "framework", wappalyzerSource, "or",
			httpRegex("body", "or", generatorHTMLPattern(`Astro\s*v[0-9][0-9.]*`), `(?is)(?:href|src)\s*=\s*["'][^"']*/_astro/[^"']+["']`)), "body", `(?is)\bcontent\s*=\s*["']Astro\s*v([0-9][0-9.]*)`),
		withHTTPVersion(httpPassiveRule("http-qwik", "Qwik", "framework", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)\bq:version\s*=\s*["'][0-9][0-9.-]*["']`)), "body", `(?is)\bq:version\s*=\s*["']([0-9][0-9.-]*)["']`),
		httpPassiveRule("http-blazor", "Blazor", "framework", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<script\b[^>]*\bsrc\s*=\s*["'][^"']*blazor\.(?:host\.min|server|webassembly)\.js[^"']*["']`)),
		httpPassiveRule("http-meteor", "Meteor", "framework", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<link\b[^>]+__meteor-css__`)),
		httpPassiveRule("http-varnish", "Varnish", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^(?:X-Varnish|X-Varnish-(?:Action|Age|Cache|Hostname)):\s*`, `(?im)^Via:[^\r\n]*\bvarnish(?:/|\s|$)`)),
		withHTTPVersion(httpPassiveRule("http-apache-traffic-server", "Apache Traffic Server", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Server:\s*ATS(?:/[0-9][^\s]*)?\s*$`)), "header", `(?im)^Server:\s*ATS/([^\s]+)`),
		httpPassiveRule("http-tengine", "Tengine", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Server:\s*Tengine(?:/[^\s]+)?\s*$`)),
		withHTTPVersion(httpPassiveRule("http-jboss", "JBoss Application Server", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^X-Powered-By:[^\r\n]*\bJBoss(?:-[0-9][^\s,;]*)?`)), "header", `(?im)\bJBoss-([0-9][^\s,;]*)`),
		withHTTPVersion(httpPassiveRule("http-jboss-web", "JBoss Web", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^X-Powered-By:[^\r\n]*\bJBossWeb(?:-[0-9][^\s,;]*)?`)), "header", `(?im)\bJBossWeb-([0-9][^\s,;]*)`),
		httpPassiveRule("http-websphere", "WebSphere", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\bLtpaToken2?=`)),
		withHTTPVersion(httpPassiveRule("http-glassfish", "GlassFish", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Server:\s*GlassFish(?: Server)?(?: Open Source Edition)?(?:\s*/?[^\s]+)?\s*$`)), "header", `(?im)^Server:\s*GlassFish(?: Server)?(?: Open Source Edition)?\s*/?([^\s]+)`),
		withHTTPVersion(httpPassiveRule("http-resin", "Resin", "middleware", wappalyzerSource, "and",
			httpRegex("header", "or", `(?im)^Server:\s*Resin(?:/[^\s]+)?\s*$`)), "header", `(?im)^Server:\s*Resin/([^\s]+)`),
	}
	rules = append(rules, shenProductHTTPRules()...)
	rules = append(rules, catalogHTTPRules()...)
	return rules
}

func shenProductHTTPRules() []Rule {
	return []Rule{
		httpPassiveRule("http-xwiki", "XWiki", "cms", wappalyzerSource, "and",
			httpRegex("body", "and", metaNameContentPattern(`wiki`, `xwiki`), `(?is)<html\b[^>]*\bdata-xwiki-reference\s*=`)),
		httpPassiveRule("http-keycloak", "Keycloak", "middleware", shenSource, "and",
			httpRegex("body", "and", `(?is)\bid\s*=\s*["']kc-form-login["']`, `(?is)/login-actions/authenticate(?:\?|["'])`)),
		withHTTPVersion(httpPassiveRule("http-squid", "Squid", "middleware", shenSource, "and",
			httpRegex("header", "or", `(?im)^Server:\s*squid(?:/[^\s]+)?\s*$`, `(?im)^Via:[^\r\n]*\bsquid(?:/|\s|$)`)), "header", `(?im)\bsquid/([^\s]+)`),
		withHTTPVersion(httpPassiveRule("http-wildfly", "WildFly", "middleware", shenSource, "and",
			httpRegex("header", "or", `(?im)^Server:\s*WildFly(?:/[^\s]+)?\s*$`, `(?im)^X-Powered-By:[^\r\n]*\bWildFly(?:/[0-9][^\s,;]*)?`)), "header", `(?im)\bWildFly/([^\s,;]+)`),
		httpPassiveRule("http-apache-airflow", "Apache Airflow", "middleware", shenSource, "and",
			httpRegex("title", "or", `(?i)^Airflow$`, `(?i)^Apache Airflow$`),
			httpRegex("body", "or", `(?is)/(?:static/(?:dist|appbuilder)|airflow)/[^"']+`)),
		httpPassiveRule("http-apache-solr", "Apache Solr", "middleware", shenSource, "and",
			httpRegex("title", "or", `(?i)^Solr Admin$`),
			httpRegex("body", "or", `(?s)\bsolrAdminApp\b`)),
		httpPassiveRule("http-apache-flink", "Apache Flink", "middleware", shenSource, "and",
			httpRegex("title", "or", `(?i)^Apache Flink Web Dashboard$`)),
		httpPassiveRule("http-apache-nifi", "Apache NiFi", "middleware", shenSource, "and",
			httpRegex("title", "or", `(?i)^(?:Apache )?NiFi$`),
			httpRegex("body", "or", `(?is)(?:href|src)\s*=\s*["'][^"']*/nifi/[^"']*["']`)),
		httpPassiveRule("http-nacos", "Nacos", "middleware", shenSource, "and",
			httpRegex("title", "or", `(?i)^Nacos$`),
			httpRegex("body", "or", `(?is)(?:href|src)\s*=\s*["'][^"']*/nacos/[^"']*["']`)),
		httpPassiveRule("http-apache-druid", "Apache Druid", "middleware", shenSource, "and",
			httpRegex("title", "or", `(?i)^Apache Druid$`, `(?i)^Druid Console$`)),
		httpPassiveRule("http-apache-hadoop", "Apache Hadoop", "middleware", shenSource, "and",
			httpRegex("body", "and", `(?is)\bResourceManager\b`, `(?is)(?:hadoop|yarn)`)),
		httpPassiveRule("http-kong", "Kong Gateway", "middleware", shenSource, "and",
			httpRegex("header", "or", `(?im)^X-Kong-(?:Proxy-Latency|Upstream-Latency|Request-Id):`, `(?im)^Via:[^\r\n]*\bkong/[0-9]`)),
	}
}

func httpPassiveRule(id, product, category, source, condition string, matchers ...Matcher) Rule {
	return Rule{
		ID: id, Kind: "http", Name: product + " HTTP fingerprint",
		Description: "Passive match on a product-specific HTTP response marker.",
		Engine:      "native", Severity: "info", Enabled: true, Builtin: true, Revision: 1,
		Tags: []string{"fingerprint", "http", category}, Source: source,
		Definition: Definition{Service: "http", Product: product, Condition: condition, Matchers: matchers},
	}
}

func httpRegex(part, condition string, patterns ...string) Matcher {
	return Matcher{Part: part, Type: "regex", Regex: patterns, Condition: condition, CaseSensitive: true}
}

func withHTTPVersion(rule Rule, part, pattern string) Rule {
	rule.Definition.VersionPart = part
	rule.Definition.VersionRegex = pattern
	return rule
}

func metaNameContentPattern(name, content string) string {
	namePattern := `\bname\s*=\s*["']` + name + `["']`
	contentPattern := `\bcontent\s*=\s*["']` + content + `["']`
	return `(?is)<meta\b(?:[^>]*` + namePattern + `[^>]*` + contentPattern + `|[^>]*` + contentPattern + `[^>]*` + namePattern + `)[^>]*>`
}
