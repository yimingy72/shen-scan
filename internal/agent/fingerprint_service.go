package agent

import (
	"regexp"
	"strings"
)

type productRule struct {
	pattern *regexp.Regexp
	product string
	version int
}

var (
	sshProductRules = []productRule{
		{regexp.MustCompile(`(?i)^OpenSSH_([0-9][0-9A-Za-z.+_-]*)$`), "OpenSSH", 1},
		{regexp.MustCompile(`(?i)^dropbear_([0-9][0-9A-Za-z.+_-]*)$`), "Dropbear", 1},
		{regexp.MustCompile(`(?i)^libssh[_-]([0-9][0-9A-Za-z.+_-]*)$`), "libssh", 1},
		{regexp.MustCompile(`(?i)^PuTTY(?:_Release)?_([0-9][0-9A-Za-z.+_-]*)$`), "PuTTY", 1},
	}
	httpServerRules = []productRule{
		{regexp.MustCompile(`(?i)^nginx(?:/([^\s()]+))?(?:$|[\s(])`), "nginx", 1},
		{regexp.MustCompile(`(?i)^Apache(?:/([^\s()]+))?(?:$|[\s(])`), "Apache HTTP Server", 1},
		{regexp.MustCompile(`(?i)^Microsoft-IIS(?:/([^\s()]+))?(?:$|[\s(])`), "Microsoft IIS", 1},
		{regexp.MustCompile(`(?i)^Caddy(?:/([^\s()]+))?(?:$|[\s(])`), "Caddy", 1},
		{regexp.MustCompile(`(?i)^openresty(?:/([^\s()]+))?(?:$|[\s(])`), "OpenResty", 1},
		{regexp.MustCompile(`(?i)^lighttpd(?:/([^\s()]+))?(?:$|[\s(])`), "lighttpd", 1},
		{regexp.MustCompile(`(?i)^gunicorn(?:/([^\s()]+))?(?:$|[\s(])`), "Gunicorn", 1},
		{regexp.MustCompile(`(?i)^uvicorn(?:/([^\s()]+))?(?:$|[\s(])`), "Uvicorn", 1},
		{regexp.MustCompile(`(?i)^Werkzeug(?:/([^\s()]+))?(?:$|[\s(])`), "Werkzeug", 1},
	}
	vsFTPdPattern           = regexp.MustCompile(`(?i)\bvsFTPd\s+([0-9][0-9A-Za-z.+_-]*)`)
	proFTPdPattern          = regexp.MustCompile(`(?i)\bProFTPD(?:\s+([0-9][0-9A-Za-z.+_-]*))?`)
	fileZillaPattern        = regexp.MustCompile(`(?i)\bFileZilla Server(?:\s+version)?\s+([0-9][0-9A-Za-z.+_-]*)`)
	eximPattern             = regexp.MustCompile(`(?i)\bExim\s+([0-9][0-9A-Za-z.+_-]*)`)
	postfixPattern          = regexp.MustCompile(`(?i)\bPostfix\b`)
	mysqlVersionPattern     = regexp.MustCompile(`^[\x20-\x7e]{1,128}$`)
	memcachedVersionPattern = regexp.MustCompile(`(?i)^VERSION\s+([0-9][0-9A-Za-z.+_-]*)$`)
)

func identifyService(port int, banner string) (service, product, version string) {
	first := firstBannerLine(banner)
	lower := strings.ToLower(first)
	switch {
	case strings.HasPrefix(first, "SSH-"):
		return identifySSH(first)
	case strings.HasPrefix(lower, "http/"):
		product, version = matchProduct(headerServer(banner), httpServerRules)
		if product == "" {
			product = headerServer(banner)
		}
		return "http", product, version
	case isMySQLHandshake([]byte(banner)):
		product, version = mysqlHandshakeProduct([]byte(banner))
		return "mysql", product, version
	case hasReplyCode(first, "220") && (strings.Contains(lower, "esmtp") || strings.Contains(lower, " smtp")):
		return identifySMTP(first)
	case hasReplyCode(first, "220") && (strings.Contains(lower, "ftp") || strings.Contains(lower, "filezilla")):
		return identifyFTP(first)
	case strings.HasPrefix(first, "+OK"):
		return "pop3", strings.TrimSpace(first), ""
	case strings.HasPrefix(first, "* OK"):
		return "imap", strings.TrimSpace(first), ""
	case first == "+PONG" || strings.HasPrefix(first, "-NOAUTH ") || (strings.HasPrefix(first, "-NOPERM ") && strings.Contains(lower, "ping")):
		return "redis", "Redis", ""
	case strings.HasPrefix(first, "-ERR") && (port == 110 || port == 995):
		return "pop3", strings.TrimSpace(first), ""
	case memcachedVersionPattern.MatchString(first):
		return "memcached", "Memcached", memcachedVersionPattern.FindStringSubmatch(first)[1]
	}
	return "", "", ""
}

func serviceProbe(port int, host string) string {
	switch port {
	case 80, 8000, 8080, 8888:
		return "HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"
	case 6379:
		return "PING\r\n"
	case 11211:
		return "version\r\n"
	}
	return ""
}

func identifySSH(first string) (service, product, version string) {
	parts := strings.SplitN(strings.TrimSpace(first), "-", 3)
	if len(parts) != 3 || parts[2] == "" {
		return "ssh", strings.TrimSpace(first), ""
	}
	fields := strings.Fields(parts[2])
	if len(fields) == 0 {
		return "ssh", strings.TrimSpace(first), ""
	}
	software := fields[0]
	product, version = matchProduct(software, sshProductRules)
	if product == "" {
		product = software
	}
	return "ssh", product, version
}

func identifySMTP(first string) (service, product, version string) {
	if match := eximPattern.FindStringSubmatch(first); match != nil {
		return "smtp", "Exim", match[1]
	}
	if postfixPattern.MatchString(first) {
		return "smtp", "Postfix", ""
	}
	return "smtp", strings.TrimSpace(first), ""
}

func identifyFTP(first string) (service, product, version string) {
	for _, candidate := range []struct {
		pattern *regexp.Regexp
		product string
	}{{vsFTPdPattern, "vsftpd"}, {proFTPdPattern, "ProFTPD"}, {fileZillaPattern, "FileZilla Server"}} {
		if match := candidate.pattern.FindStringSubmatch(first); match != nil {
			version := ""
			if len(match) > 1 {
				version = match[1]
			}
			return "ftp", candidate.product, version
		}
	}
	return "ftp", strings.TrimSpace(first), ""
}

func matchProduct(value string, rules []productRule) (product, version string) {
	for _, rule := range rules {
		if match := rule.pattern.FindStringSubmatch(value); match != nil {
			if rule.version > 0 && rule.version < len(match) {
				version = match[rule.version]
			}
			return rule.product, version
		}
	}
	return "", ""
}

func firstBannerLine(banner string) string {
	if index := strings.IndexAny(banner, "\r\n"); index >= 0 {
		banner = banner[:index]
	}
	return strings.TrimSpace(banner)
}

func hasReplyCode(line, code string) bool {
	return len(line) > len(code) && strings.HasPrefix(line, code) && (line[len(code)] == ' ' || line[len(code)] == '-')
}

func isMySQLHandshake(banner []byte) bool {
	if len(banner) < 7 || banner[3] != 0 || banner[4] != 0x0a {
		return false
	}
	payloadLength := int(banner[0]) | int(banner[1])<<8 | int(banner[2])<<16
	return payloadLength >= 3 && payloadLength <= len(banner)-4
}

func mysqlHandshakeProduct(banner []byte) (product, version string) {
	end := 5
	for end < len(banner) && banner[end] != 0 {
		end++
	}
	if end == len(banner) || !mysqlVersionPattern.Match(banner[5:end]) {
		return "MySQL", ""
	}
	version = string(banner[5:end])
	if strings.Contains(strings.ToLower(version), "mariadb") {
		product = "MariaDB"
		version = strings.TrimPrefix(version, "5.5.5-")
	} else {
		product = "MySQL"
	}
	return product, version
}

func headerServer(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "server:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

func isTLSPort(port int) bool {
	return port == 443 || port == 465 || port == 636 || port == 993 || port == 995 || port == 8443 || port == 9443
}
