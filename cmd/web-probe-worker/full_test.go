package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/webevidence"
)

func fullInput(serverURL string) webevidence.ProbeRequest {
	return webevidence.ProbeRequest{ID: "full-synthetic", Protocol: webevidence.Protocol, ExecutionProfile: webevidence.FullProfile, URL: serverURL, ConnectIP: "127.0.0.1", CFF: []byte(`{"apps":{"FullFixture":{"html":["full-marker"]}}}`), TimeoutMillis: 1000, EntryTimeoutMillis: 5000}
}

func TestFullRunnerTLSFaviconAdmission(t *testing.T) {
	icon := []byte{0, 0, 1, 0, 1, 0, 0xff, 0xfe, 0, 0x80, 0x13, 0x37}
	var requests, permits atomic.Int32
	target, _ := enrichmentFixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "virtual.fixture.test" || r.TLS.ServerName != "sni.fixture.test" {
			t.Errorf("identity lost: %s / %s", r.Host, r.TLS.ServerName)
		}
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Location", "/final")
			w.WriteHeader(302)
			fmt.Fprint(w, "redirect-body")
		case "/final":
			fmt.Fprint(w, `<html><title>full runner</title>full-marker<link rel="icon" href="/favicon.ico"></html>`)
		default:
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write(icon)
		}
	})
	callback, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		var frame struct {
			Seq int `json:"request_seq"`
		}
		if json.NewDecoder(r.Body).Decode(&frame) != nil || frame.Seq != int(permits.Add(1)) {
			t.Errorf("admission sequence: %+v", frame)
		}
		json.NewEncoder(w).Encode(map[string]int64{"valid_for_ms": 475, "waited_ms": 0})
	})
	input := fullInput(strings.Replace(target.URL, "127.0.0.1", "logical.fixture.test", 1) + "/start")
	input.Host = "virtual.fixture.test"
	input.SNI = "sni.fixture.test"
	input.AdmissionURL = callback.URL
	input.AdmissionToken = "synthetic-token"
	result, err := probe(context.Background(), input)
	if err != nil {
		t.Fatalf("runner failed: %v %+v", err, result)
	}
	if result.Profile != webevidence.FullProfile || result.Response.StatusCode != 200 || result.Title != "full runner" || len(result.Technologies) != 1 || result.Technologies[0] != "FullFixture" {
		t.Fatalf("runner evidence incomplete: %+v", result)
	}
	if len(result.Icons) != 1 || !bytes.Equal(result.Icons[0].Body, icon) {
		t.Fatalf("favicon bytes lost: %+v", result.Icons)
	}
	if result.Requests != 3 || requests.Load() != 3 || permits.Load() != 3 {
		t.Fatalf("not all requests gated: result=%d actual=%d permits=%d", result.Requests, requests.Load(), permits.Load())
	}
	if result.Response.TLS == nil || len(result.Response.TLS.PeerCertificates) == 0 || len(result.SDKResult) == 0 {
		t.Fatal("native TLS/metadata lost")
	}
	if len(result.Redirects) != 1 || result.Redirects[0].Outcome != "followed" {
		t.Fatalf("redirect evidence lost: %+v", result.Redirects)
	}
}

func TestFullRunnerTruncationAndCancellation(t *testing.T) {
	for _, kind := range []string{"encoded", "decoded", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			target, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
				if kind == "canceled" {
					<-r.Context().Done()
					return
				}
				if r.URL.Path == "/favicon.ico" {
					w.Write([]byte{0, 0, 1, 0})
					return
				}
				if kind == "decoded" {
					w.Header().Set("Content-Encoding", "gzip")
					var data bytes.Buffer
					writer := gzip.NewWriter(&data)
					writer.Write(bytes.Repeat([]byte("x"), webevidence.MaxBody+100))
					writer.Close()
					w.Write(data.Bytes())
					return
				}
				w.Write(bytes.Repeat([]byte("x"), webevidence.MaxBody+100))
			})
			input := fullInput(target.URL)
			ctx := context.Background()
			if kind == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 80*time.Millisecond)
				defer cancel()
			}
			started := time.Now()
			result, err := probe(ctx, input)
			if kind == "canceled" {
				if err == nil || time.Since(started) > 2*time.Second {
					t.Fatalf("cancel failed: %v %v", err, time.Since(started))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Response.Completeness != "partial" || result.Response.Error == "" || len(result.Response.Body) != webevidence.MaxBody {
				t.Fatalf("truncation not explicit: %+v", metadata(result.Response))
			}
		})
	}
}

func TestFullRunnerRetryAndSlowTLSPermits(t *testing.T) {
	t.Run("retry", func(t *testing.T) {
		target, rec := enrichmentFixture(t, false, func(http.ResponseWriter, *http.Request) {})
		var permits atomic.Int32
		callback, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
			var frame struct {
				Seq int `json:"request_seq"`
			}
			json.NewDecoder(r.Body).Decode(&frame)
			if frame.Seq != int(permits.Add(1)) {
				t.Errorf("retry not independently gated: %+v", frame)
			}
			json.NewEncoder(w).Encode(map[string]int64{"valid_for_ms": 475, "waited_ms": 0})
		})
		input := fullInput(target.URL + "/close")
		input.AdmissionURL = callback.URL
		input.AdmissionToken = "synthetic"
		result, err := probe(context.Background(), input)
		rec.mu.Lock()
		actual := len(rec.exchanges)
		rec.mu.Unlock()
		if err == nil || result.Requests != 2 || permits.Load() != 2 || actual != 2 {
			t.Fatalf("retry admission mismatch: %v result=%d actual=%d permits=%d", err, result.Requests, actual, permits.Load())
		}
	})
	t.Run("slow_tls", func(t *testing.T) {
		var actual, permits atomic.Int32
		target, _ := enrichmentFixture(t, true, func(w http.ResponseWriter, r *http.Request) { actual.Add(1); fmt.Fprint(w, "full-marker") }, 600*time.Millisecond)
		callback, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
			var frame struct {
				Seq int `json:"request_seq"`
			}
			json.NewDecoder(r.Body).Decode(&frame)
			n := permits.Add(1)
			if frame.Seq != int((n+1)/2) {
				t.Errorf("renewal charged new request: seq=%d callbacks=%d", frame.Seq, n)
			}
			json.NewEncoder(w).Encode(map[string]int64{"valid_for_ms": 475, "waited_ms": 0})
		})
		input := fullInput(target.URL)
		input.TimeoutMillis = 2000
		input.AdmissionURL = callback.URL
		input.AdmissionToken = "synthetic"
		result, err := probe(context.Background(), input)
		if err != nil || result.Requests != 2 || actual.Load() != 2 || permits.Load() != 4 {
			t.Fatalf("slow TLS gate mismatch: %v result=%d actual=%d permits=%d", err, result.Requests, actual.Load(), permits.Load())
		}
	})
}

func TestFullRunnerCapabilityGaps(t *testing.T) {
	for _, test := range []struct {
		name, cff string
		wantGap   bool
	}{
		{name: "response_only", cff: `{"apps":{"Fixture":{"html":["full-marker"]}}}`},
		{name: "js_property", cff: `{"apps":{"Fixture":{"html":["full-marker"],"js":{"fixture.version":""}}}}`, wantGap: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "full-marker") })
			input := fullInput(target.URL)
			input.CFF = []byte(test.cff)
			result, err := probe(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantGap {
				if len(result.CapabilityGaps) != 1 || result.CapabilityGaps[0] != "wappalyzer-browser-js-dom" {
					t.Fatalf("selected JS requirement missing: %v", result.CapabilityGaps)
				}
			} else if len(result.CapabilityGaps) != 0 {
				t.Fatalf("response-only CFF falsely incomplete: %v", result.CapabilityGaps)
			}
		})
	}
}
