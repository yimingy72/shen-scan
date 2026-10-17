package agent

import (
	"net/http"
	"regexp"
	"strings"
)

type textFingerprintRule struct {
	name         string
	pattern      *regexp.Regexp
	versionGroup int
	evidence     string
}

var (
	metaTagPattern  = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	htmlAttrPattern = regexp.MustCompile(`(?is)([a-z][a-z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)

	generatorFingerprintRules = []textFingerprintRule{
		{"WordPress", regexp.MustCompile(`(?i)^WordPress(?:\s+([0-9][0-9A-Za-z.+_-]*))?\b`), 1, "generator identifies WordPress"},
		{"Drupal", regexp.MustCompile(`(?i)^Drupal(?:\s+([0-9][0-9A-Za-z.+_-]*))?\b`), 1, "generator identifies Drupal"},
		{"Joomla", regexp.MustCompile(`(?i)^Joomla!?(?:\s+([0-9][0-9A-Za-z.+_-]*))?\b`), 1, "generator identifies Joomla"},
		{"Ghost", regexp.MustCompile(`(?i)^Ghost(?:\s+([0-9][0-9A-Za-z.+_-]*))?\b`), 1, "generator identifies Ghost"},
		{"MediaWiki", regexp.MustCompile(`(?i)^MediaWiki(?:\s+([0-9][0-9A-Za-z.+_-]*))?\b`), 1, "generator identifies MediaWiki"},
		{"TYPO3 CMS", regexp.MustCompile(`(?i)^TYPO3(?: CMS)?(?:\s+([0-9][0-9A-Za-z.+_-]*))?\b`), 1, "generator identifies TYPO3 CMS"},
		{"Hugo", regexp.MustCompile(`(?i)^Hugo(?:\s+([0-9][0-9A-Za-z.+_-]*))?\b`), 1, "generator identifies Hugo"},
	}
	bodyFingerprintRules = []textFingerprintRule{
		{"WordPress", regexp.MustCompile(`(?is)(?:href|src)\s*=\s*["'][^"']*/wp-(?:content|includes)/`), 0, "HTML resource URL uses /wp-content/ or /wp-includes/"},
		{"Next.js", regexp.MustCompile(`(?is)<script\b[^>]*\bid\s*=\s*["']__NEXT_DATA__["']`), 0, "HTML contains the __NEXT_DATA__ script element"},
		{"Nuxt", regexp.MustCompile(`(?is)<(?:div|main)\b[^>]*\bid\s*=\s*["']__nuxt["']`), 0, "HTML contains the __nuxt application root"},
		{"Gatsby", regexp.MustCompile(`(?is)<div\b[^>]*\bid\s*=\s*["']___gatsby["']`), 0, "HTML contains the ___gatsby application root"},
		{"Angular", regexp.MustCompile(`(?is)<[a-z][^>]*\bng-version\s*=\s*["']([0-9][0-9A-Za-z.+_-]*)["']`), 1, "HTML root element exposes ng-version"},
	}
	phpPoweredByPattern   = regexp.MustCompile(`(?i)(?:^|[,;\s])PHP\s*/\s*([0-9][0-9A-Za-z.+_-]*)`)
	aspNetPoweredPattern  = regexp.MustCompile(`(?i)(?:^|[,;\s])ASP\.NET(?:$|[,;\s])`)
	expressPoweredPattern = regexp.MustCompile(`(?i)(?:^|[,;\s])Express(?:$|[,;\s])`)
	nextPoweredPattern    = regexp.MustCompile(`(?i)(?:^|[,;\s])Next\.js(?:$|[,;\s])`)
	djangoCSRFPattern     = regexp.MustCompile(`(?is)<(?:input|meta)\b[^>]*(?:name\s*=\s*["']csrfmiddlewaretoken["']|content\s*=\s*["'][^"']+["'][^>]*name\s*=\s*["']csrfmiddlewaretoken["'])`)
)

func detectTechnologies(h http.Header, body []byte) []Technology {
	var out []Technology
	seen := make(map[string]int)
	if generator := htmlGenerator(body); generator != "" {
		matchTextRules(&out, seen, generator, "HTML meta ", generatorFingerprintRules)
	}
	if generator := strings.TrimSpace(h.Get("X-Generator")); generator != "" {
		matchTextRules(&out, seen, generator, "X-Generator ", generatorFingerprintRules)
	}
	for _, rule := range bodyFingerprintRules {
		if match := rule.pattern.FindSubmatch(body); match != nil {
			version := ""
			if rule.versionGroup > 0 && rule.versionGroup < len(match) {
				version = string(match[rule.versionGroup])
			}
			addTechnologyValue(&out, seen, rule.name, version, rule.evidence)
		}
	}

	poweredBy := h.Get("X-Powered-By")
	if match := phpPoweredByPattern.FindStringSubmatch(poweredBy); match != nil {
		addTechnologyValue(&out, seen, "PHP", match[1], "X-Powered-By identifies PHP")
	}
	if aspNetVersion := strings.TrimSpace(h.Get("X-AspNet-Version")); aspNetVersion != "" {
		addTechnologyValue(&out, seen, "ASP.NET", aspNetVersion, "X-AspNet-Version header")
	} else if aspNetPoweredPattern.MatchString(poweredBy) {
		addTechnologyValue(&out, seen, "ASP.NET", "", "X-Powered-By identifies ASP.NET")
	}
	if expressPoweredPattern.MatchString(poweredBy) {
		addTechnologyValue(&out, seen, "Express", "", "X-Powered-By identifies Express")
	}
	if nextPoweredPattern.MatchString(poweredBy) {
		addTechnologyValue(&out, seen, "Next.js", "", "X-Powered-By identifies Next.js")
	}

	cookies := responseCookieNames(h)
	if cookies["laravel_session"] {
		addTechnologyValue(&out, seen, "Laravel", "", "Set-Cookie contains the laravel_session cookie")
	}
	if cookies["csrftoken"] && djangoCSRFPattern.Match(body) {
		addTechnologyValue(&out, seen, "Django", "", "HTML csrfmiddlewaretoken and csrftoken cookie both match")
	}
	if h.Get("X-Drupal-Cache") != "" || h.Get("X-Drupal-Dynamic-Cache") != "" {
		addTechnologyValue(&out, seen, "Drupal", "", "Drupal cache response header")
	}
	return out
}

func htmlGenerator(body []byte) string {
	for _, tag := range metaTagPattern.FindAll(body, -1) {
		attrs := make(map[string]string)
		for _, match := range htmlAttrPattern.FindAllSubmatch(tag, -1) {
			value := match[2]
			if len(value) == 0 {
				value = match[3]
			}
			if len(value) == 0 {
				value = match[4]
			}
			attrs[strings.ToLower(string(match[1]))] = string(value)
		}
		if strings.EqualFold(strings.TrimSpace(attrs["name"]), "generator") {
			return strings.TrimSpace(attrs["content"])
		}
	}
	return ""
}

func matchTextRules(out *[]Technology, seen map[string]int, value, source string, rules []textFingerprintRule) {
	for _, rule := range rules {
		if match := rule.pattern.FindStringSubmatch(value); match != nil {
			addTechnology(out, seen, rule, match, source+rule.evidence)
			return
		}
	}
}

func addTechnology(out *[]Technology, seen map[string]int, rule textFingerprintRule, match []string, evidence string) {
	version := ""
	if rule.versionGroup > 0 && rule.versionGroup < len(match) {
		version = match[rule.versionGroup]
	}
	addTechnologyValue(out, seen, rule.name, version, evidence)
}

func addTechnologyValue(out *[]Technology, seen map[string]int, name, version, evidence string) {
	if index, ok := seen[name]; ok {
		if (*out)[index].Version == "" && version != "" {
			(*out)[index].Version = version
			(*out)[index].Evidence = evidence
		}
		return
	}
	seen[name] = len(*out)
	*out = append(*out, Technology{Name: name, Version: version, Evidence: evidence})
}

func responseCookieNames(h http.Header) map[string]bool {
	names := make(map[string]bool)
	for _, raw := range h.Values("Set-Cookie") {
		if cookie, err := http.ParseSetCookie(raw); err == nil {
			names[strings.ToLower(cookie.Name)] = true
		}
	}
	return names
}
