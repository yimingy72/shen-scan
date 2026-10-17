package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
)

func batchFixtureRule(t *testing.T, id, word string) rulelib.Rule {
	t.Helper()
	source := fmt.Sprintf("id: %s\ninfo:\n  name: %s\n  author: shen\n  severity: info\n  metadata:\n    product: ShenBatchFixture\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/health\"]\n    matchers:\n      - type: word\n        part: body\n        words: [\"%s\"]\n", id, id, word)
	rule, err := rulelib.ParseNucleiOriginal(source)
	if err != nil {
		t.Fatal(err)
	}
	rule.Enabled = true
	return rule
}

func TestNucleiBatchMissingEventsStayUnknown(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "nuclei-empty")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: Config{NucleiBinary: binary}, policy: targetPolicy{allowPrivate: true}}
	a.nucleiOriginalOnce.Do(func() { a.nucleiOriginalOK = true; a.nucleiEngineVersion = "3.11.1"; a.nucleiBatchOK = true })
	rules := []rulelib.Rule{batchFixtureRule(t, "missing-a", "ready"), batchFixtureRule(t, "missing-b", "absent")}
	var observations []Observation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.runNucleiBatch(ctx, Endpoint{IP: "127.0.0.1", URL: "http://127.0.0.1:1234"}, rules, func(o Observation) error { observations = append(observations, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 {
		t.Fatalf("missing manifest entries=%d", len(observations))
	}
	for _, o := range observations {
		if o.FindingStatus != "unknown" || o.CanProveNoMatch {
			t.Fatalf("exit0 inferred negative: %+v", o)
		}
	}
}

func TestRealNucleiBatchSingleResponseAndCancelResume(t *testing.T) {
	binary := os.Getenv("NUCLEI_TEST_BINARY")
	if binary == "" {
		t.Skip("NUCLEI_TEST_BINARY is not set")
	}
	rules := []rulelib.Rule{batchFixtureRule(t, "batch-match", "ready"), batchFixtureRule(t, "batch-miss", "absent")}
	for _, tls := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", tls), func(t *testing.T) {
			var requests atomic.Int32
			fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = io.WriteString(w, "shen-batch-ready")
			}))
			if tls {
				fixture.StartTLS()
			} else {
				fixture.Start()
			}
			defer fixture.Close()
			a := &Agent{cfg: Config{NucleiBinary: binary}, policy: targetPolicy{allowPrivate: true}}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var got []Observation
			if err := a.runNucleiBatch(ctx, Endpoint{IP: "127.0.0.1", URL: fixture.URL}, rules, func(o Observation) error { got = append(got, o); return nil }); err != nil {
				t.Fatal(err)
			}
			seen := map[string]string{}
			for _, o := range got {
				seen[o.TemplateID] = o.FindingStatus
				if o.RequestRaw == "" || o.ResponseRaw == "" || o.ContentSHA256 == "" {
					t.Fatalf("missing per-template evidence: %+v", o)
				}
				if o.FindingStatus == "not_matched" && !o.CanProveNoMatch {
					t.Fatal("negative lacked coverage proof")
				}
			}
			if seen["batch-match"] != "matched" || seen["batch-miss"] != "not_matched" || requests.Load() != 2 {
				t.Fatalf("batch results=%v requests=%d", seen, requests.Load())
			}
			if path := os.Getenv("NUCLEI_BATCH_EVIDENCE"); path != "" {
				raw, _ := json.MarshalIndent(got, "", "  ")
				if err := os.WriteFile(fmt.Sprintf("%s-%v.json", path, tls), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("cancel accepted prefix and resume remaining", func(t *testing.T) {
		var requests atomic.Int32
		fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) == 2 {
				<-r.Context().Done()
				return
			}
			_, _ = io.WriteString(w, "shen-batch-ready")
		}))
		defer fixture.Close()
		a := &Agent{cfg: Config{NucleiBinary: binary}, policy: targetPolicy{allowPrivate: true}}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var accepted []Observation
		err := a.runNucleiBatch(ctx, Endpoint{IP: "127.0.0.1", URL: fixture.URL}, rules, func(o Observation) error { accepted = append(accepted, o); cancel(); return nil })
		if !errors.Is(err, context.Canceled) || len(accepted) != 1 {
			t.Fatalf("cancel err=%v accepted=%d", err, len(accepted))
		}
		var remaining []rulelib.Rule
		for _, r := range rules {
			if r.ID != accepted[0].RuleID {
				remaining = append(remaining, r)
			}
		}
		// Restore a live fixture for the unaccepted tail. The database test exercises
		// the authoritative claim filter; this checks the executor's resumed manifest.
		requests.Store(2)
		ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel2()
		var resumed []Observation
		if err := a.runNucleiBatch(ctx2, Endpoint{IP: "127.0.0.1", URL: fixture.URL}, remaining, func(o Observation) error { resumed = append(resumed, o); return nil }); err != nil {
			t.Fatal(err)
		}
		if len(resumed) != 1 || resumed[0].RuleID == accepted[0].RuleID || requests.Load() != 3 {
			t.Fatalf("resumed completed work: got=%+v requests=%d", resumed, requests.Load())
		}
	})
}

func TestRealNucleiBatchProxy502CannotBecomeTargetEvidence(t *testing.T) {
	binary := os.Getenv("NUCLEI_TEST_BINARY")
	if binary == "" {
		t.Skip("NUCLEI_TEST_BINARY is not set")
	}
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		_, _ = io.WriteString(w, "target-ready")
	}))
	defer target.Close()
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "permit unavailable", 503) }))
	defer central.Close()
	a := newHTTPXTestAgent(t, "unused")
	a.cfg.NucleiBinary = binary
	a.client.baseURL = central.URL
	rules := []rulelib.Rule{batchFixtureRule(t, "proxy-error-match", "blocked by scan scope"), batchFixtureRule(t, "proxy-error-miss", "absent")}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx = a.withHTTPBudget(ctx, Task{ID: "denied-batch", AttemptNo: 1})
	var got []Observation
	if err := a.runNucleiBatch(ctx, Endpoint{IP: "127.0.0.1", URL: target.URL}, rules, func(o Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if targetRequests.Load() != 0 || len(got) != 2 {
		t.Fatalf("denial reached target or lost outcomes: requests=%d outcomes=%d", targetRequests.Load(), len(got))
	}
	for _, o := range got {
		if o.FindingStatus != "unknown" || o.CanProveNoMatch {
			t.Fatalf("proxy502 became target proof: %+v", o)
		}
	}
}
