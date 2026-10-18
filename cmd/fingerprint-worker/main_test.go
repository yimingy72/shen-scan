package main

import (
	fingers "github.com/chainreactors/fingers"
	"net/http"
	"scanplatform/internal/webevidence"
	"testing"
)

func TestPassiveMatcherEvidenceAndPartialGuard(t *testing.T) {
	engine, err := fingers.NewEngine(engines...)
	if err != nil {
		t.Fatal(err)
	}
	engine.EnableMatchDetail()
	input := webevidence.MatchRequest{Response: webevidence.Response{StatusCode: 200, Proto: "HTTP/1.1", Completeness: "full", Headers: http.Header{"Server": []string{"nginx"}, "Content-Type": []string{"text/html"}}, Body: []byte(`<html><meta name="generator" content="WordPress 6.4"><script src="/wp-includes/test.js"></script></html>`)}}
	matches, err := match(engine, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("passive fixture produced no matches")
	}
	for _, m := range matches {
		if m.Engine == "" || len(m.Evidence) == 0 {
			t.Fatalf("missing provenance: %+v", m)
		}
	}
	input.Response.BodyStorage = "hash_only"
	if _, err = match(engine, input); err == nil {
		t.Fatal("accepted persisted hash as complete matching input")
	}
	input.Response.BodyStorage = ""
	input.Response.Completeness = "partial"
	if matches, err = match(engine, input); err != nil || len(matches) != 0 {
		t.Fatalf("partial input produced product claims: %+v %v", matches, err)
	}
	if len(bundleID()) != 64 {
		t.Fatal("invalid bundle digest")
	}
}

func TestExplicitScanOptionsSkipUnselectedMatchers(t *testing.T) {
	for _, active := range []bool{false, true} {
		input := webevidence.MatchRequest{WebScanOptions: &webevidence.WebScanOptions{Active: active}, Response: webevidence.Response{BodyStorage: "hash_only"}}
		// A nil engine and deliberately unusable passive evidence prove the guard
		// returns before invoking any SDK passive matcher, including active-only.
		matches, err := matchEvidence(nil, input, false, false)
		if err != nil || len(matches) != 0 {
			t.Fatal("disabled passive matcher executed")
		}
	}
	input := webevidence.MatchRequest{WebScanOptions: &webevidence.WebScanOptions{}, Active: &webevidence.ActiveRequest{AdmissionURL: "must-not-call"}}
	matches, state, err := executeActive(nil, input)
	if err != nil || len(matches) != 0 || state == nil || state.Requests != 0 || state.StopReason != "active-disabled" {
		t.Fatal("disabled active matcher executed")
	}
}
