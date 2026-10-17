package agent

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPFingerprints(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		body       string
		technology string
		version    string
	}{
		{"WordPress generator", nil, `<meta content='WordPress 6.7.2' name='generator'>`, "WordPress", "6.7.2"},
		{"WordPress resource", nil, `<link href="/wp-content/themes/site.css">`, "WordPress", ""},
		{"Next data", nil, `<script type="application/json" id="__NEXT_DATA__">{}</script>`, "Next.js", ""},
		{"Drupal header", http.Header{"X-Generator": {"Drupal 11"}}, "", "Drupal", "11"},
		{"Angular version", nil, `<app-root ng-version="19.2.1"></app-root>`, "Angular", "19.2.1"},
		{"PHP version", http.Header{"X-Powered-By": {"PHP/8.3.7"}}, "", "PHP", "8.3.7"},
		{"ASP.NET version", http.Header{"X-Aspnet-Version": {"4.0.30319"}}, "", "ASP.NET", "4.0.30319"},
		{"Laravel cookie", http.Header{"Set-Cookie": {"laravel_session=abc; Path=/; HttpOnly"}}, "", "Laravel", ""},
		{"Django paired signals", http.Header{"Set-Cookie": {"csrftoken=abc; Path=/"}}, `<input name="csrfmiddlewaretoken" value="token">`, "Django", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := detectTechnologies(test.headers, []byte(test.body))
			for _, technology := range got {
				if technology.Name == test.technology {
					if technology.Version != test.version || technology.Evidence == "" {
						t.Fatalf("unexpected match: %#v", technology)
					}
					return
				}
			}
			t.Fatalf("%s not detected in %#v", test.technology, got)
		})
	}

	for _, test := range []struct {
		name    string
		headers http.Header
		body    string
	}{
		{"WordPress prose", nil, `<p>Move files out of wp-content/ when hardening.</p>`},
		{"Next prose", nil, `<code>__NEXT_DATA__</code>`},
		{"Django cookie alone", http.Header{"Set-Cookie": {"csrftoken=abc; Path=/"}}, ""},
		{"similar powered-by", http.Header{"X-Powered-By": {"NotPHP/8.3"}}, ""},
	} {
		t.Run("negative "+test.name, func(t *testing.T) {
			if got := detectTechnologies(test.headers, []byte(test.body)); len(got) != 0 {
				t.Fatalf("false positive: %#v", got)
			}
		})
	}
}

func TestEndpointRunnerLimit(t *testing.T) {
	var active, peak atomic.Int32
	endpoints := make([]Endpoint, 8)
	err := runEndpointsWithLimit(context.Background(), endpoints, make(chan struct{}, 8), 2,
		func(context.Context, Endpoint) Observation {
			current := active.Add(1)
			for {
				old := peak.Load()
				if current <= old || peak.CompareAndSwap(old, current) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			active.Add(-1)
			return Observation{}
		}, func(Observation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak concurrency = %d, want 2", got)
	}
}

func TestServiceFingerprints(t *testing.T) {
	mysqlPayload := append([]byte{10}, []byte("8.0.36-ubuntu\x00")...)
	mysqlPayload = append(mysqlPayload, make([]byte, 5)...)
	mysqlBanner := string(append([]byte{byte(len(mysqlPayload)), 0, 0, 0}, mysqlPayload...))
	tests := []struct {
		name                      string
		port                      int
		banner                    string
		service, product, version string
	}{
		{"OpenSSH", 2222, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8\r\n", "ssh", "OpenSSH", "9.6p1"},
		{"unknown SSH software", 22, "SSH-1.99-vendor_appliance\r\n", "ssh", "vendor_appliance", ""},
		{"nginx HTTP", 8080, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n", "http", "nginx", "1.24.0"},
		{"unknown HTTP server", 8080, "HTTP/1.1 200 OK\r\nServer: nginxplus\r\n\r\n", "http", "nginxplus", ""},
		{"Postfix SMTP", 2525, "220 mail.example ESMTP Postfix\r\n", "smtp", "Postfix", ""},
		{"vsftpd", 2121, "220 (vsFTPd 3.0.5)\r\n", "ftp", "vsftpd", "3.0.5"},
		{"MySQL handshake", 3306, mysqlBanner, "mysql", "MySQL", "8.0.36-ubuntu"},
		{"Redis PONG", 6379, "+PONG\r\n", "redis", "Redis", ""},
		{"memcached version", 11211, "VERSION 1.6.24\r\n", "memcached", "Memcached", "1.6.24"},
		{"known port without evidence", 6379, "", "", "", ""},
		{"generic error is not Redis", 6379, "-ERR arbitrary service error\r\n", "", "", ""},
		{"SMTP prose is not a banner", 1234, "Welcome to the SMTP documentation server\r\n", "", "", ""},
		{"malformed SSH does not panic", 22, "SSH-2.0-   \r\n", "ssh", "SSH-2.0-", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, product, version := identifyService(test.port, test.banner)
			if service != test.service || product != test.product || version != test.version {
				t.Fatalf("got (%q, %q, %q), want (%q, %q, %q)", service, product, version, test.service, test.product, test.version)
			}
		})
	}
	if got := serviceProbe(6379, "example.test"); got != "PING\r\n" {
		t.Fatalf("Redis probe = %q", got)
	}
	if got := serviceProbe(11211, "example.test"); got != "version\r\n" {
		t.Fatalf("memcached probe = %q", got)
	}
	if got := serviceProbe(12345, "example.test"); got != "" {
		t.Fatalf("unexpected unknown-port probe = %q", got)
	}
}
