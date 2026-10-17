package agent

import (
	"encoding/json"
	"net/url"
	"testing"

	"scanplatform/internal/rulelib"
)

func TestNucleiNegativeRequiresExecutionEvidence(t *testing.T) {
	base, _ := url.Parse("https://fixture.invalid")
	proxy := &scopeProxy{base: base, allowedPaths: map[string]bool{"/": true},
		allowed: map[string]bool{"GET /": true}, requestCount: 1}
	negative := false
	event := nucleiEvent{TemplateID: "local-single", MatchedAt: base.String(), MatcherStatus: &negative,
		Request:  "GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"}
	verified := Observation{EngineVersion: "3.11.1", EvidenceProfile: nucleiSingleResponseProfile, ContentSHA256: "dispatched-template"}
	for _, test := range []struct {
		name        string
		observation Observation
		response    string
		want        string
	}{
		{"verified single response", verified, event.Response, "not_matched"},
		{"unverified execution profile", Observation{}, event.Response, "incomplete"},
		{"missing body bytes", verified, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort", "incomplete"},
		{"missing response", verified, "", "incomplete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := event
			entry.Response = test.response
			output, _ := json.Marshal(entry)
			got := nucleiOutcome(test.observation, rulelib.Rule{ID: event.TemplateID}, event.TemplateID, output, proxy, false)
			if got.FindingStatus != test.want || got.CanProveNoMatch != (test.want == "not_matched") {
				t.Fatalf("outcome=%s can_prove_no_match=%v; want %s", got.FindingStatus, got.CanProveNoMatch, test.want)
			}
		})
	}
}
