package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"scanplatform/internal/webevidence"
)

func TestFullWebAdmissionUsesConfiguredCumulativeBound(t *testing.T) {
	base, _ := url.Parse("http://fixture.example:8080/")
	budget := &webEntryBudget{used: 7, maximum: 12}
	endpoint, token, closeAdmission, err := startWebAdmissionLimited(context.Background(), "full-entry", "192.0.2.1", base, false, &webAdmissionLimit{entry: budget, maxRequests: 12})
	if err != nil {
		t.Fatal(err)
	}
	defer closeAdmission()
	for n := 1; n <= 6; n++ {
		body := []byte(fmt.Sprintf(`{"id":"full-entry","url":"http://fixture.example:8080/path/%d","request_seq":%d}`, n, n))
		req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		want := 200
		if n == 6 {
			want = 429
		}
		if response.StatusCode != want {
			t.Fatalf("request %d got %d want %d", n, response.StatusCode, want)
		}
	}
	if budget.count() != 12 {
		t.Fatalf("budget not cumulative: %d", budget.count())
	}
}
func TestFullWebIdentityAndCoverage(t *testing.T) {
	response := webevidence.Response{URL: "https://logical.example/", ConnectIP: "192.0.2.1", StatusCode: 200, Completeness: "full", Body: []byte("ok"), DecodedBytes: 2, BodySHA256: webevidence.SHA256([]byte("ok"))}
	identity := webevidence.ExecutionIdentity{TaskID: "task", AttemptNo: 2, EntryID: "entry", Segment: 1}
	input := webevidence.ProbeRequest{ID: "id", Protocol: webevidence.Protocol, ExecutionProfile: webevidence.FullProfile, Identity: identity, URL: response.URL, ConnectIP: response.ConnectIP, MaxRequests: 16, CFFSHA256: webevidence.SHA256(nil)}
	result := webevidence.ProbeResult{ID: input.ID, Protocol: input.Protocol, Profile: webevidence.FullProfile, ExecutionProfile: webevidence.FullProfile, Identity: identity, Response: response, Requests: 12, CFFSHA256: input.CFFSHA256}
	if err := validateFullWebResult(input, result); err != nil {
		t.Fatal(err)
	}
	result.Identity.AttemptNo--
	if validateFullWebResult(input, result) == nil {
		t.Fatal("accepted stale helper attempt")
	}
	result.Identity = identity
	result.Icons = []webevidence.Response{{URL: "https://foreign.example/favicon.ico", ConnectIP: response.ConnectIP}}
	if validateFullWebResult(input, result) == nil {
		t.Fatal("accepted foreign favicon")
	}
	result.Icons = nil
	progress := webevidence.EntryProgress{MaxRequests: 16384, MaxSegments: 32, Deadline: time.Now(), Matches: []webevidence.Match{{Name: "prior-positive", Engine: "fingers"}}}
	obs := fullWebObservation(Observation{Kind: "http", Coverage: "complete"}, result, webevidence.MatchResult{}, httpPayload{}, progress)
	if obs.Coverage != "partial" || obs.Outcome != "incomplete" || len(obs.Technologies) != 1 {
		t.Fatalf("unfinished execution lost positive or claimed coverage: %+v", obs)
	}
}

func TestCandidateTechnologyPromotesOnlyWithConfirmedEvidence(t *testing.T) {
	candidate := Technology{Name: "rdp", Version: "untrusted-version", Candidate: true, CandidateReason: "bare feature substring", RuleID: "goby:rdp", Evidence: "Goby feature rdp matches WordPress substring"}
	confirmed := Technology{Name: "RDP", RuleID: "native:rdp-handshake", Evidence: "confirmed RDP protocol response"}
	for _, group := range [][]Technology{{candidate, confirmed}, {confirmed, candidate}} {
		merged := mergeTechnologies(group)
		if len(merged) != 1 || merged[0].Candidate || merged[0].CandidateReason != "" || merged[0].Version != "" || !strings.Contains(merged[0].Evidence, candidate.Evidence) || !strings.Contains(merged[0].Evidence, confirmed.Evidence) {
			t.Fatalf("confirmed promotion lost quality/evidence: %+v", merged)
		}
	}
	only := mergeTechnologies([]Technology{candidate, candidate})
	if len(only) != 1 || !only[0].Candidate || only[0].Evidence != candidate.Evidence {
		t.Fatalf("candidate promoted without confirmation: %+v", only)
	}
	native := mergeFullMatches([]webevidence.Match{{Name: "rdp", Engine: "goby", Candidate: true, Evidence: json.RawMessage(`{"feature":"rdp"}`)}}, []webevidence.Match{{Name: "rdp", Engine: "goby", Evidence: json.RawMessage(`{"confirmed":true}`)}})
	if len(native) != 2 || !native[0].Candidate || native[1].Candidate {
		t.Fatalf("native source evidence was collapsed: %+v", native)
	}
}
