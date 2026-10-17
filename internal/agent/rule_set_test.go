package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/rulelib"
)

func TestRuleSetSingleflightCacheAndRunIsolation(t *testing.T) {
	var downloads atomic.Int32
	rule := testHTTPRule()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer worker-token" || request.URL.Query().Get("worker_id") != "worker" || request.URL.Query().Get("session_id") != "session" || request.URL.Query().Get("attempt_no") != "1" {
			t.Errorf("invalid rule request: %s %#v", request.Header.Get("Authorization"), request.URL.Query())
		}
		downloads.Add(1)
		time.Sleep(30 * time.Millisecond)
		runID := "run-a"
		if request.URL.Path == "/api/tasks/task-b/rules" {
			runID = "run-b"
		}
		_ = json.NewEncoder(response).Encode(ruleSetResponse{Ref: runID + ":http", Kind: "http", Rules: []rulelib.Rule{rule}})
	}))
	defer server.Close()
	agent := testRuleSetAgent(t, server.URL)

	var wg sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			task := Task{ID: fmt.Sprintf("task-a-%d", index), RunID: "run-a", Type: "http", AttemptNo: 1}
			rules, err := agent.resolveTaskRules(context.Background(), task, "run-a:http", nil, "http")
			if err == nil && (len(rules) != 1 || rules[0].ID != rule.ID) {
				err = fmt.Errorf("unexpected rules: %#v", rules)
			}
			errorsSeen <- err
		}(index)
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if downloads.Load() != 1 {
		t.Fatalf("same run downloaded %d times", downloads.Load())
	}

	cached, err := agent.resolveTaskRules(context.Background(), Task{ID: "cached", RunID: "run-a", Type: "http", AttemptNo: 1}, "run-a:http", nil, "http")
	if err != nil {
		t.Fatal(err)
	}
	cached[0].Definition.Matchers[0].Words[0] = "mutated"
	again, err := agent.resolveTaskRules(context.Background(), Task{ID: "cached-2", RunID: "run-a", Type: "http", AttemptNo: 1}, "run-a:http", nil, "http")
	if err != nil || again[0].Definition.Matchers[0].Words[0] != "fixture" || downloads.Load() != 1 {
		t.Fatalf("cached rules were mutable or re-downloaded: %#v downloads=%d err=%v", again, downloads.Load(), err)
	}

	_, err = agent.resolveTaskRules(context.Background(), Task{ID: "task-b", RunID: "run-b", Type: "http", AttemptNo: 1}, "run-b:http", nil, "http")
	if err != nil || downloads.Load() != 2 {
		t.Fatalf("different run did not use an isolated snapshot: downloads=%d err=%v", downloads.Load(), err)
	}
}

func TestRuleSetFailuresAndBadReferencesAreNotCached(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attempt := requests.Add(1)
		if attempt == 1 {
			http.Error(response, `{"error":"temporary"}`, http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(response).Encode(ruleSetResponse{Ref: "run:http", Kind: "http", Rules: []rulelib.Rule{testHTTPRule()}})
	}))
	defer server.Close()
	agent := testRuleSetAgent(t, server.URL)
	task := Task{ID: "task", RunID: "run", Type: "http", AttemptNo: 1}

	if _, err := agent.resolveTaskRules(context.Background(), task, "wrong:http", nil, "http"); err == nil || requests.Load() != 0 {
		t.Fatalf("bad payload ref reached control: requests=%d err=%v", requests.Load(), err)
	}
	if _, err := agent.resolveTaskRules(context.Background(), task, "run:http", nil, "http"); err == nil {
		t.Fatal("download failure was hidden")
	} else {
		var taskErr *TaskError
		if !errors.As(err, &taskErr) || !taskErr.Retryable || taskErr.FailureClass != "" {
			t.Fatalf("download failure is not retryable infrastructure error: %v", err)
		}
	}
	if _, err := agent.resolveTaskRules(context.Background(), task, "run:http", nil, "http"); err != nil || requests.Load() != 2 {
		t.Fatalf("failed download was cached: requests=%d err=%v", requests.Load(), err)
	}
}

func TestRuleSetInvalidResponseAndCancellationAreNotCached(t *testing.T) {
	t.Run("mismatched response ref", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			ref := "other:http"
			if requests.Add(1) > 1 {
				ref = "run:http"
			}
			_ = json.NewEncoder(response).Encode(ruleSetResponse{Ref: ref, Kind: "http", Rules: []rulelib.Rule{testHTTPRule()}})
		}))
		defer server.Close()
		agent := testRuleSetAgent(t, server.URL)
		task := Task{ID: "task", RunID: "run", Type: "http", AttemptNo: 1}
		if _, err := agent.resolveTaskRules(context.Background(), task, "run:http", nil, "http"); err == nil {
			t.Fatal("mismatched response ref was accepted")
		}
		if _, err := agent.resolveTaskRules(context.Background(), task, "run:http", nil, "http"); err != nil || requests.Load() != 2 {
			t.Fatalf("invalid response was cached: requests=%d err=%v", requests.Load(), err)
		}
	})

	t.Run("cancelled download", func(t *testing.T) {
		var requests atomic.Int32
		firstStarted := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if requests.Add(1) == 1 {
				close(firstStarted)
				<-request.Context().Done()
				return
			}
			_ = json.NewEncoder(response).Encode(ruleSetResponse{Ref: "run:http", Kind: "http", Rules: []rulelib.Rule{testHTTPRule()}})
		}))
		defer server.Close()
		agent := testRuleSetAgent(t, server.URL)
		task := Task{ID: "task", RunID: "run", Type: "http", AttemptNo: 1}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := agent.resolveTaskRules(ctx, task, "run:http", nil, "http")
			done <- err
		}()
		<-firstStarted
		cancel()
		if err := <-done; err == nil {
			t.Fatal("cancelled download succeeded")
		}
		deadline := time.Now().Add(time.Second)
		for {
			_, err := agent.resolveTaskRules(context.Background(), task, "run:http", nil, "http")
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("cancelled result remained cached/in-flight: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if requests.Load() != 2 {
			t.Fatalf("cancelled partial download affected cache: requests=%d", requests.Load())
		}
	})
}

func TestRuleSetInlineCompatibilityAndLRUBound(t *testing.T) {
	agent := &Agent{ruleSets: newRuleSetCache(8)}
	inline := []rulelib.Rule{testHTTPRule()}
	rules, err := agent.resolveTaskRules(context.Background(), Task{Type: "http"}, "", inline, "http")
	if err != nil || len(rules) != 1 || rules[0].ID != inline[0].ID {
		t.Fatalf("old inline rules failed: %#v err=%v", rules, err)
	}
	legacy, err := agent.resolveTaskRules(context.Background(), Task{Type: "http"}, "", nil, "http")
	if err != nil || legacy != nil {
		t.Fatalf("legacy nil rules changed semantics: %#v err=%v", legacy, err)
	}
	for index := 0; index < 9; index++ {
		agent.ruleSets.add(fmt.Sprintf("run-%d:http", index), inline)
	}
	if _, ok := agent.ruleSets.get("run-0:http"); ok {
		t.Fatal("LRU retained more than eight snapshots")
	}
	if _, ok := agent.ruleSets.get("run-8:http"); !ok {
		t.Fatal("LRU evicted newest snapshot")
	}
}

func TestClaimRequestsRuleSets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if enabled, ok := body["use_rule_sets"].(bool); !ok || !enabled {
			t.Fatalf("claim omitted use_rule_sets: %#v", body)
		}
		if supported, ok := body["supports_httpx_cff"].(bool); !ok || !supported {
			t.Fatalf("claim omitted supports_httpx_cff: %#v", body)
		}
		_, _ = response.Write([]byte(`{"task":null}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "join", "")
	if err != nil {
		t.Fatal(err)
	}
	client.workerToken = "worker-token"
	if _, err := client.Claim(context.Background(), "worker", "session", "request", []string{"http"}); err != nil {
		t.Fatal(err)
	}
}

func testRuleSetAgent(t *testing.T, controlURL string) *Agent {
	t.Helper()
	client, err := NewClient(controlURL, "join", "")
	if err != nil {
		t.Fatal(err)
	}
	client.workerToken = "worker-token"
	return &Agent{client: client, workerID: "worker", cfg: Config{SessionID: "session"}, ruleSets: newRuleSetCache(8)}
}

func testHTTPRule() rulelib.Rule {
	return rulelib.Rule{
		ID: "test-http-rule", Kind: "http", Name: "fixture", Engine: "native", Severity: "info", Enabled: true, Revision: 1,
		Definition: rulelib.Definition{Service: "http", Product: "Fixture", Condition: "and", Matchers: []rulelib.Matcher{{
			Part: "body", Type: "word", Words: []string{"fixture"}, Condition: "or", CaseSensitive: true,
		}}},
	}
}
