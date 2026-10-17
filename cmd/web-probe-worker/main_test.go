package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"scanplatform/internal/webevidence"
)

func TestProbeTLSIdentityAndLimits(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(r.Host, "fixture.test:") || r.TLS.ServerName != "fixture.test" {
			t.Errorf("Host/SNI lost: %s / %s", r.Host, r.TLS.ServerName)
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<title>fixture</title>fixture-marker<link rel="icon" href="https://outside.invalid/icon"><link rel="icon" href="/icon">`))
		case "/icon":
			w.Write([]byte("icon-bytes"))
		case "/large":
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			gz.Write(bytes.Repeat([]byte("a"), webevidence.MaxBody+4096))
			gz.Close()
		case "/redirect":
			w.Header().Set("Location", "https://outside.invalid/")
			w.WriteHeader(302)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	input := webevidence.ProbeRequest{Protocol: webevidence.Protocol, URL: "https://fixture.test:" + port + "/", ConnectIP: "127.0.0.1", CFF: []byte(`{"apps":{"Fixture":{"html":["fixture-marker"]}}}`)}
	input.CFFSHA256 = webevidence.SHA256(input.CFF)
	result, err := probe(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Response.Completeness != "full" || result.Response.TLS == nil || result.Response.TLS.Source != "same_http_connection" || len(result.Response.TLS.PeerCertificates) == 0 {
		t.Fatalf("missing actual TLS evidence: %+v", result.Response)
	}
	if len(result.Technologies) != 1 || result.Technologies[0] != "Fixture" || result.Title != "fixture" {
		t.Fatalf("SDK/Wapp result %+v", result)
	}
	if result.Requests != 3 || requests.Load() != 3 || len(result.Icons) != 2 {
		t.Fatalf("unbounded/foreign icon fetch: %d / %d", result.Requests, requests.Load())
	}
	input.URL = "https://fixture.test:" + port + "/large"
	result, err = probe(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Response.Completeness != "partial" || len(result.Response.Body) != webevidence.MaxBody || len(result.Technologies) != 0 {
		t.Fatalf("decompression bound not enforced: %s %d", result.Response.Completeness, len(result.Response.Body))
	}
	input.URL = "https://fixture.test:" + port + "/redirect"
	result, err = probe(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Response.StatusCode != 302 {
		t.Fatalf("redirect followed: %+v", result.Response)
	}
	input.CFFSHA256 = "wrong"
	if _, err = probe(context.Background(), input); err == nil {
		t.Fatal("accepted wrong rules digest")
	}
}
