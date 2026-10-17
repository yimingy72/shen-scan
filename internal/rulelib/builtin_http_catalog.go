package rulelib

// catalogHTTPRules is a curated, data-oriented subset of wappalyzergo signals.
// Runtime JavaScript, favicon/hash, active paths, and implication-only entries
// are intentionally absent because the current agent cannot preserve them.
func catalogHTTPRules() []Rule {
	type headerSpec struct {
		id, product, category, pattern, version string
	}
	headerSpecs := []headerSpec{
		{"http-thinkphp", "ThinkPHP", "framework", `(?im)^X-Powered-By:\s*ThinkPHP(?:\s|$)`, ""},
		{"http-play-framework", "Play Framework", "framework", `(?im)^Set-Cookie:[^\r\n]*\bPLAY_SESSION=`, ""},
		{"http-cherrypy", "CherryPy", "middleware", `(?im)^Server:\s*CherryPy(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*CherryPy/([^\s]+)`},
		{"http-adonisjs", "AdonisJS", "framework", `(?im)^Set-Cookie:[^\r\n]*\badonis-session(?:-values)?=`, ""},
		{"http-koa", "Koa", "framework", `(?im)^X-Powered-By:\s*Koa\s*$`, ""},
		{"http-phusion-passenger", "Phusion Passenger", "middleware", `(?im)^(?:Server|X-Powered-By):[^\r\n]*\bPhusion Passenger(?:\(R\))?(?:\s+[0-9][^\s]*)?`, `(?im)\bPhusion Passenger(?:\(R\))?\s+([0-9][^\s]*)`},
		{"http-webrick", "WEBrick", "middleware", `(?im)^Server:\s*WEBrick/[^\s]+\s*$`, `(?im)^Server:\s*WEBrick/([^\s]+)`},
		{"http-hypercorn", "Hypercorn", "middleware", `(?im)^Server:\s*Hypercorn(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*Hypercorn/([^\s]+)`},
		{"http-daphne", "Daphne", "middleware", `(?im)^Server:\s*Daphne(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*Daphne/([^\s]+)`},
		{"http-ibm-http-server", "IBM HTTP Server", "middleware", `(?im)^Server:\s*IBM_HTTP_Server(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*IBM_HTTP_Server/([^\s]+)`},
		{"http-oracle-http-server", "Oracle HTTP Server", "middleware", `(?im)^Server:\s*Oracle-HTTP-Server(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*Oracle-HTTP-Server/([^\s]+)`},
		{"http-goahead", "GoAhead", "middleware", `(?im)^Server:\s*GoAhead(?:-Webs)?(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*GoAhead(?:-Webs)?/([^\s]+)`},
		{"http-thttpd", "thttpd", "middleware", `(?im)^Server:[^\r\n]*\bthttpd(?:/[^\s]+)?`, `(?im)\bthttpd/([^\s]+)`},
		{"http-zope", "Zope", "middleware", `(?im)^Server:\s*Zope/[^\s]+`, `(?im)^Server:\s*Zope/([^\s]+)`},
		{"http-twistedweb", "TwistedWeb", "middleware", `(?im)^Server:\s*TwistedWeb(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*TwistedWeb/([^\s]+)`},
		{"http-mochiweb", "MochiWeb", "middleware", `(?im)^Server:\s*MochiWeb(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*MochiWeb/([^\s]+)`},
		{"http-warp", "Warp", "middleware", `(?im)^Server:\s*Warp/[0-9][^\s]*\s*$`, `(?im)^Server:\s*Warp/([^\s]+)`},
		{"http-apache-apisix", "Apache APISIX", "middleware", `(?im)^(?:Server:\s*APISIX(?:/[^\s]+)?\s*|X-APISIX-Upstream-Status:)`, `(?im)^Server:\s*APISIX/([^\s]+)`},
		{"http-tornadoserver", "TornadoServer", "middleware", `(?im)^Server:\s*TornadoServer(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*TornadoServer/([^\s]+)`},
		{"http-zend", "Zend", "framework", `(?im)^(?:X-Powered-By:[^\r\n]*\bZend(?: Server)?(?:[/\s][0-9][^\s,;]*)?|Set-Cookie:[^\r\n]*\bZendServerSessId=)`, `(?im)\bZend(?: Server)?[/\s]([0-9][^\s,;]*)`},
		{"http-bun", "Bun", "framework", `(?im)^X-Powered-By:\s*Bun\s*$`, ""},
		{"http-deno-deploy", "Deno Deploy", "middleware", `(?im)^Server:\s*Deno(?:/[^\s]+)?\s*$`, `(?im)^Server:\s*Deno/([^\s]+)`},
		{"http-squarespace", "Squarespace", "cms", `(?im)^Server:\s*Squarespace\s*$`, ""},
	}
	rules := make([]Rule, 0, len(headerSpecs)+30)
	for _, spec := range headerSpecs {
		rule := httpPassiveRule(spec.id, spec.product, spec.category, wappalyzerSource, "and", httpRegex("header", "or", spec.pattern))
		if spec.version != "" {
			rule = withHTTPVersion(rule, "header", spec.version)
		}
		rules = append(rules, rule)
	}

	rules = append(rules,
		httpPassiveRule("http-vaadin", "Vaadin", "framework", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<script\b[^>]*\bsrc\s*=\s*["'][^"']*vaadinbootstrap\.js(?:\?v=[0-9.]+)?[^"']*["']`)),
		httpPassiveRule("http-javaserver-faces", "JavaServer Faces", "framework", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Powered-By:[^\r\n]*\bJSF(?:/[^\s,;]+)?`),
			httpRegex("body", "or", `(?is)<input\b[^>]*\bname\s*=\s*["']javax\.faces\.ViewState["']`)),
		httpPassiveRule("http-fresh", "Fresh", "framework", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<(?:script|style)\b[^>]*\bid\s*=\s*["']__FRSH_(?:STATE|STYLE|TWIND)["']`)),
		httpPassiveRule("http-nette", "Nette Framework", "framework", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^(?:X-Powered-By:\s*Nette Framework|Set-Cookie:[^\r\n]*\bnette-browser=)`),
			httpRegex("body", "or", `(?is)<input\b[^>]*\bdata-nette-rules(?:\s*=|\s|>)`)),
		httpPassiveRule("http-shopify", "Shopify", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^(?:Powered-By:\s*Shopify\s*$|X-Shopify-(?:Stage|Shop-Api-Call-Limit):|Set-Cookie:[^\r\n]*\b_shopify_[sy]=)`),
			httpRegex("body", "or", metaNameContentPattern(`shopify-(?:checkout-api-token|digital-wallet)`, `[^"']+`))),
		httpPassiveRule("http-wix", "Wix", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Wix-(?:Renderer-Server|Request-Id|Server-Artifact-Id):`),
			httpRegex("body", "or", generatorHTMLPattern(`Wix\.com Website Builder`), `(?is)(?:href|src)\s*=\s*["'][^"']*static\.parastorage\.com`)),
		httpPassiveRule("http-webflow", "Webflow", "cms", wappalyzerSource, "or",
			httpRegex("body", "or", generatorHTMLPattern(`Webflow`), `(?is)<html\b[^>]*\bdata-wf-site\s*=`)),
		httpPassiveRule("http-bigcommerce", "BigCommerce", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)(?:href|src|data-src)\s*=\s*["'][^"']*(?:\.bigcommerce\.com/|/bigcommerce/(?:assets)?)[^"']*["']`)),
		httpPassiveRule("http-contentful", "Contentful", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Contentful-Request-Id:`),
			httpRegex("body", "or", `(?is)<[^>]+(?:assets|downloads|images|videos)\.(?:ctfassets\.net|contentful\.com)`)),
		httpPassiveRule("http-sanity", "Sanity", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Sanity-Shard:`, `(?im)^Content-Security-Policy:[^\r\n]*cdn\.sanity\.io`),
			httpRegex("body", "or", `(?is)(?:src|srcset)\s*=\s*["'][^"']*cdn\.sanity\.io/`)),
		httpPassiveRule("http-contentstack", "Contentstack", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)(?:src|srcset)\s*=\s*["'][^"']*\.contentstack\.(?:io|com)/`)),
		httpPassiveRule("http-dnn", "DNN", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^(?:DNNOutputCache:|X-Compressed-By:\s*DotNetNuke|Set-Cookie:[^\r\n]*\bDotNetNukeAnonymous=)`),
			httpRegex("body", "or", generatorHTMLPattern(`DotNetNuke`), `(?is)<!--\s*(?:by DotNetNuke Corporation|DNN Platform)`)),
		httpPassiveRule("http-orchard-core", "Orchard Core", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^(?:X-Generator:\s*Orchard\s*$|X-Powered-By:\s*OrchardCore\s*$)`),
			httpRegex("body", "or", generatorHTMLPattern(`Orchard`))),
		httpPassiveRule("http-bolt-cms", "Bolt CMS", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", generatorHTMLPattern(`Bolt`))),
		httpPassiveRule("http-silverstripe", "Silverstripe", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", generatorHTMLPattern(`Silverstripe`), `(?is)powered by\s*<a\b[^>]*href=["'][^"']*silverstripe`)),
		httpPassiveRule("http-contao", "Contao", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", generatorHTMLPattern(`Contao Open Source CMS`), `(?is)(?:href|src)\s*=\s*["'][^"']*/(?:typolight|contao)\.css`)),
		httpPassiveRule("http-plone", "Plone", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", generatorHTMLPattern(`Plone`), `(?is)(?:href|src)\s*=\s*["']/\+\+resource\+\+`)),
		httpPassiveRule("http-modx", "MODX", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^X-Powered-By:\s*MODX(?:\s|$)`),
			httpRegex("body", "or", generatorHTMLPattern(`MODX(?:\s+[0-9][0-9.]*)?`), `(?is)<!--\s*MODX process time debug info`)),
		httpPassiveRule("http-concrete-cms", "Concrete CMS", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^Set-Cookie:[^\r\n]*\bCONCRETE5=`),
			httpRegex("body", "or", generatorHTMLPattern(`Concrete5(?:\s*-\s*[0-9][0-9.]*)?`), `(?is)<script\b[^>]*\bsrc\s*=\s*["'][^"']*/concrete/js/`)),
		httpPassiveRule("http-expressionengine", "ExpressionEngine", "cms", wappalyzerSource, "and",
			httpRegex("header", "and", `(?im)^Set-Cookie:[^\r\n]*\bexp_csrf_token=`, `(?im)^Set-Cookie:[^\r\n]*\bexp_(?:last_activity|tracker)=`)),
		httpPassiveRule("http-weebly", "Weebly", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)<script\b[^>]*\bsrc\s*=\s*["'][^"']*cdn\d+\.editmysite\.com/`)),
		httpPassiveRule("http-vtex", "VTEX", "cms", wappalyzerSource, "or",
			httpRegex("header", "or", `(?im)^(?:Powered:\s*VTEX\s*$|Server:\s*VTEX IO\s*$|Set-Cookie:[^\r\n]*\b(?:vtex_session|vtexfingerprint|vtexstoreversion|vtexworkspace)=)`),
			httpRegex("body", "or", `(?is)(?:href|src|srcset)\s*=\s*["'][^"']*\.vteximg\.com\.br/`)),
		withHTTPVersion(httpPassiveRule("http-adminer", "Adminer", "cms", wappalyzerSource, "and",
			httpRegex("body", "or", `(?is)adminer</a>\s*<span\s+class=["']version["']>[0-9][^<]*</span>`, `(?is)onload=["']verifyVersion\(["'][0-9]`)), "body", `(?is)class=["']version["']>([0-9][^<]*)</span>`),
		httpPassiveRule("http-zabbix", "Zabbix", "cms", wappalyzerSource, "or",
			httpRegex("body", "or", `(?is)<body\b[^>]*\bzbxCallPostScripts`, metaNameContentPattern(`author`, `Zabbix SIA`))),
	)
	return rules
}
