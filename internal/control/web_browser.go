package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/webevidence"
)

func browserTaskPayload(payload []byte) bool {
	var p webevidence.BrowserAssignment
	return json.Unmarshal(payload, &p) == nil && p.Phase == "browser"
}

func initializeBrowserAssignment(ctx context.Context, tx pgx.Tx, taskID string, payload []byte) ([]byte, error) {
	if !browserTaskPayload(payload) {
		return payload, nil
	}
	if err := validateBrowserParent(ctx, tx, payload); err != nil {
		return nil, err
	}
	var deadlineJSON []byte
	err := tx.QueryRow(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{browser_deadline}',to_jsonb(CASE WHEN NULLIF(payload->>'browser_deadline','')::timestamptz>'1970-01-01'::timestamptz THEN (payload->>'browser_deadline')::timestamptz ELSE first_started_at+interval '30 seconds' END)) WHERE id=$1 RETURNING payload->'browser_deadline'`, taskID).Scan(&deadlineJSON)
	if err != nil {
		return nil, err
	}
	// Rule declarations are attached to this claim response only. Never replace
	// them with the persisted task payload or persist a second rule snapshot.
	var response map[string]json.RawMessage
	if err = json.Unmarshal(payload, &response); err != nil {
		return nil, err
	}
	response["browser_deadline"] = deadlineJSON
	return json.Marshal(response)
}

func browserCFF(snapshot ruleSnapshot) ([]byte, bool, error) {
	apps := map[string]json.RawMessage{}
	needed := false
	for _, r := range snapshot.HTTP {
		if r.Engine != "httpx-cff" || !r.Enabled {
			continue
		}
		if _, exists := apps[r.Definition.Product]; exists {
			return nil, false, errors.New("duplicate frozen CFF product")
		}
		apps[r.Definition.Product] = r.Fingerprint
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(r.Fingerprint, &fields); err != nil {
			return nil, false, err
		}
		for _, key := range []string{"js", "dom"} {
			v := strings.TrimSpace(string(fields[key]))
			if v != "" && v != "null" && v != "{}" && v != "[]" && v != `""` {
				needed = true
			}
		}
	}
	if len(apps) == 0 {
		return nil, false, nil
	}
	raw, err := json.Marshal(struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}{apps})
	return raw, needed, err
}

// Freeze once at run creation; later parent completions read just these small
// immutable selection facts rather than decoding/marshalling the whole CFF.
func freezeBrowserMetadata(snapshot *ruleSnapshot) error {
	cff, needed, err := browserCFF(*snapshot)
	if err != nil {
		return err
	}
	snapshot.BrowserCFFSHA256 = webevidence.SHA256(cff)
	snapshot.BrowserRulesRequired = &needed
	return nil
}

func loadBrowserMetadata(ctx context.Context, tx pgx.Tx, runID string) (string, bool, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT jsonb_build_object('profile',rules_snapshot->'web_browser_profile','sha256',rules_snapshot->'browser_cff_sha256','required',rules_snapshot->'browser_rules_required') FROM runs WHERE id=$1`, runID).Scan(&raw); err != nil {
		return "", false, err
	}
	var metadata struct {
		Profile  string `json:"profile"`
		SHA256   string `json:"sha256"`
		Required *bool  `json:"required"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return "", false, err
	}
	if metadata.Profile != "" && metadata.Profile != webevidence.BrowserProfile {
		return "", false, errors.New("browser metadata profile mismatch")
	}
	if len(metadata.SHA256) == 64 && metadata.Required != nil {
		return metadata.SHA256, *metadata.Required, nil
	}
	// Only pre-metadata opted-in runs/fixtures enter this compatibility path. Seal
	// its deterministic result so subsequent entries do not repeat the large read.
	if err := tx.QueryRow(ctx, `SELECT rules_snapshot FROM runs WHERE id=$1`, runID).Scan(&raw); err != nil {
		return "", false, err
	}
	var snapshot ruleSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return "", false, err
	}
	if err := freezeBrowserMetadata(&snapshot); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE runs SET rules_snapshot=rules_snapshot||jsonb_build_object('browser_cff_sha256',$2::text,'browser_rules_required',$3::boolean) WHERE id=$1`, runID, snapshot.BrowserCFFSHA256, *snapshot.BrowserRulesRequired); err != nil {
		return "", false, err
	}
	return snapshot.BrowserCFFSHA256, *snapshot.BrowserRulesRequired, nil
}

func deriveBrowserTasks(ctx context.Context, tx pgx.Tx, parentID, runID string, attempt int, completionID string, payload []byte) error {
	var parent webevidence.BrowserAssignment
	if json.Unmarshal(payload, &parent) != nil || parent.WebBrowserProfile != webevidence.BrowserProfile {
		return nil
	}
	wantJS := parent.WebScanOptions == nil || parent.WebScanOptions.JSDOM
	wantScreenshot := parent.WebScanOptions != nil && parent.WebScanOptions.Screenshot
	if !wantJS && !wantScreenshot {
		return nil
	}
	digest, needed := "", false
	var err error
	if wantJS {
		digest, needed, err = loadBrowserMetadata(ctx, tx, runID)
		if err != nil {
			return err
		}
	}
	if !needed && !wantScreenshot {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id,observation,target_key FROM assets WHERE task_id=$1 AND attempt_no=$2 AND observation->>'kind'='http' ORDER BY batch_seq DESC,item_index DESC`, parentID, attempt)
	if err != nil {
		return err
	}
	type record struct {
		id, target string
		raw        []byte
	}
	var records []record
	for rows.Next() {
		var r record
		if err = rows.Scan(&r.id, &r.raw, &r.target); err != nil {
			rows.Close()
			return err
		}
		records = append(records, r)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range records {
		var base Observation
		var evidence struct {
			Probe webevidence.ProbeResult `json:"probe"`
		}
		if json.Unmarshal(r.raw, &base) != nil || json.Unmarshal([]byte(base.Evidence), &evidence) != nil {
			continue
		}
		probe := evidence.Probe
		jsRequired := wantJS && needed && webevidence.BrowserApplicable(probe.Response)
		if probe.Response.StatusCode <= 0 || (!jsRequired && !wantScreenshot) || seen[base.WorkKey+"\x00"+base.URL] {
			continue
		}
		seen[base.WorkKey+"\x00"+base.URL] = true
		if jsRequired && probe.CFFSHA256 != digest || net.ParseIP(probe.Response.ConnectIP) == nil {
			return errors.New("browser parent CFF or fixed connect IP mismatch")
		}
		u, err := url.Parse(probe.Response.URL)
		if err != nil || u.Hostname() == "" {
			return errors.New("invalid browser parent URL")
		}
		host := probe.Response.Host
		if host == "" {
			host = u.Host
		}
		sni := u.Hostname()
		if probe.Response.TLS != nil && probe.Response.TLS.ServerName != "" {
			sni = probe.Response.TLS.ServerName
		}
		binding := webevidence.BrowserParentIdentity{TaskID: parentID, AttemptNo: attempt, CompletionID: completionID, ObservationID: r.id, ObservationSHA256: webevidence.SHA256(r.raw), Identity: probe.Identity}
		assignment := webevidence.BrowserAssignment{WebScanOptions: parent.WebScanOptions, BrowserJSDOMRequired: &jsRequired, Phase: "browser", WebBrowserProfile: webevidence.BrowserProfile, BrowserParent: binding, BrowserURL: u.String(), BrowserConnectIP: probe.Response.ConnectIP, BrowserHost: host, BrowserSNI: sni, BrowserCFFSHA256: probe.CFFSHA256}
		// The excerpt is a seed only when it is provably the entire decoded body.
		body := []byte(base.BodyExcerpt)
		if len(body) <= 32<<10 && len(body) == probe.Response.DecodedBytes && probe.Response.Completeness == "full" && webevidence.SHA256(body) == probe.Response.BodySHA256 {
			seed := probe.Response
			seed.Body = body
			seed.BodyStorage = "inline"
			assignment.BrowserSeed = &seed
		}
		child, _ := json.Marshal(assignment)
		var p map[string]any
		_ = json.Unmarshal(child, &p)
		p["endpoints"] = []taskEndpoint{{IP: assignment.BrowserConnectIP, URL: assignment.BrowserURL, WorkKey: base.WorkKey}}
		p["source_task_id"], p["source_attempt_no"], p["source_completion_id"] = parentID, attempt, completionID
		p["execution_timeout_seconds"], p["max_requests"] = 15, 32
		if wantScreenshot {
			p["execution_timeout_seconds"] = 20
		}
		child, _ = json.Marshal(p)
		id := newID()
		result, err := tx.Exec(ctx, `INSERT INTO tasks(id,run_id,type,payload,derived_key,target_key) VALUES($1,$2,'http',$3,$4,$5) ON CONFLICT(run_id,derived_key) DO NOTHING`, id, runID, child, fmt.Sprintf("browser:%s:%d:%s", parentID, attempt, r.id), r.target)
		if err != nil {
			return err
		}
		if result.RowsAffected() > 0 {
			if _, err = tx.Exec(ctx, `INSERT INTO task_targets(task_id,target_key) VALUES($1,$2)`, id, r.target); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadBrowserParent(ctx context.Context, tx pgx.Tx, p webevidence.BrowserAssignment) (Observation, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT a.observation FROM assets a JOIN tasks t ON t.id=a.task_id WHERE a.id=$1 AND a.task_id=$2 AND a.attempt_no=$3 AND t.state='completed' AND t.accepted_attempt_no=$3 AND t.completion_id=$4`, p.BrowserParent.ObservationID, p.BrowserParent.TaskID, p.BrowserParent.AttemptNo, p.BrowserParent.CompletionID).Scan(&raw)
	if err != nil {
		return Observation{}, errors.New("browser source execution is no longer accepted")
	}
	if webevidence.SHA256(raw) != p.BrowserParent.ObservationSHA256 {
		return Observation{}, errors.New("browser source observation changed")
	}
	var base Observation
	if err = json.Unmarshal(raw, &base); err != nil {
		return base, err
	}
	if p.WebScanOptions != nil && (base.WebScanOptions == nil || *p.WebScanOptions != *base.WebScanOptions) {
		return base, errors.New("browser child changed frozen scan options")
	}
	var e struct {
		Probe webevidence.ProbeResult `json:"probe"`
	}
	if json.Unmarshal([]byte(base.Evidence), &e) != nil || e.Probe.Identity != p.BrowserParent.Identity || e.Probe.CFFSHA256 != p.BrowserCFFSHA256 || e.Probe.Response.URL != p.BrowserURL || e.Probe.Response.ConnectIP != p.BrowserConnectIP {
		return base, errors.New("browser source evidence binding changed")
	}
	return base, nil
}

func validateBrowserParent(ctx context.Context, tx pgx.Tx, payload []byte) error {
	var p webevidence.BrowserAssignment
	if json.Unmarshal(payload, &p) != nil || p.Phase != "browser" || p.WebBrowserProfile != webevidence.BrowserProfile {
		return errors.New("invalid browser assignment")
	}
	_, err := loadBrowserParent(ctx, tx, p)
	return err
}

func mergeBrowserObservation(ctx context.Context, tx pgx.Tx, taskID string, attempt int, payload []byte, item *Observation) error {
	var p webevidence.BrowserAssignment
	_ = json.Unmarshal(payload, &p)
	base, err := loadBrowserParent(ctx, tx, p)
	if err != nil {
		return err
	}
	var e struct {
		Browser webevidence.BrowserResult `json:"browser"`
	}
	if json.Unmarshal([]byte(item.Evidence), &e) != nil {
		return errors.New("invalid browser result evidence")
	}
	b := e.Browser
	expected := p.BrowserParent.Identity
	expected.TaskID = taskID
	expected.AttemptNo = attempt
	expected.Segment = 0
	if b.ID == "" || b.Protocol != webevidence.Protocol || b.Profile != webevidence.BrowserProfile || b.Identity != expected || b.Parent != p.BrowserParent || b.CFFSHA256 != p.BrowserCFFSHA256 || b.Requests < 0 || b.Requests > 32 || b.Requests < p.BrowserRequestsUsed && attempt == 1 {
		return errors.New("browser result identity or request count mismatch")
	}
	jsSelected := p.WebScanOptions == nil || p.WebScanOptions.JSDOM
	jsRequired := jsSelected && (p.BrowserJSDOMRequired == nil || *p.BrowserJSDOMRequired)
	screenshotSelected := p.WebScanOptions != nil && p.WebScanOptions.Screenshot
	enabled := jsRequired
	b.JSDOMEnabled = &enabled
	jsStage := webevidence.WebStage{State: "not_applicable"}
	networkComplete := len(b.Blocked) == 0 && b.BlockedCount == 0
	for _, r := range b.Attempts {
		u, ok := observedEndpoint(taskEndpoint{IP: p.BrowserConnectIP, URL: p.BrowserURL}, r.URL)
		if !ok || u.Scheme != mustBrowserScheme(p.BrowserURL) || r.ConnectIP != p.BrowserConnectIP || r.Host != p.BrowserHost {
			return errors.New("browser response escaped fixed origin or Host")
		}
		if r.Completeness != "full" || r.Error != "" {
			networkComplete = false
		}
	}
	terminalComplete := b.Complete && b.Error == ""
	if b.JSDOM != nil {
		terminalComplete = b.JSDOM.State == "complete" && b.JSDOM.Error == ""
		jsStage = *b.JSDOM
	}
	jsComplete := !jsRequired
	if jsRequired {
		jsComplete = terminalComplete && (b.JSDOM != nil || networkComplete) && len(b.PlanSHA256) == 64 && b.TotalRules > 0 && b.EvaluatedRules == b.TotalRules && b.UnsupportedRules == 0 && b.IncompleteRules == 0
		for _, r := range b.Rules {
			if r.Status != "matched" && r.Status != "not_matched" && r.Status != "not_applicable" {
				jsComplete = false
			}
		}
		jsStage.State = "partial"
		if jsComplete {
			jsStage.State = "complete"
		}
		if jsStage.StopReason == "" && (b.JSDOM == nil || !jsComplete) {
			jsStage.StopReason = b.StopReason
		}
		if jsStage.Error == "" && !jsComplete && b.JSDOM == nil {
			jsStage.Error = b.Error
		}
	}
	if p.BrowserDeadline.IsZero() {
		return errors.New("browser assignment has no fixed deadline")
	}
	if time.Now().After(p.BrowserDeadline) {
		if jsRequired {
			jsComplete = false
			jsStage.State = "partial"
			jsStage.StopReason = "cumulative_deadline"
		}
		if b.Screenshot != nil {
			b.Screenshot.State = "partial"
			b.Screenshot.StopReason = "cumulative_deadline"
		}
	}
	var screenshot *webevidence.ScreenshotMetadata
	screenshotComplete := true
	if screenshotSelected {
		screenshot, err = storeBrowserScreenshot(ctx, tx, taskID, attempt, p, b.Screenshot)
		if err != nil {
			return err
		}
		screenshotComplete = screenshot.State == "complete"
	} else {
		b.Screenshot = nil
	}
	if !jsRequired {
		b.Matches = nil
		b.Rules = nil
	}
	var original struct {
		Probe       webevidence.ProbeResult `json:"probe"`
		Fingerprint webevidence.MatchResult `json:"fingerprint"`
	}
	if json.Unmarshal([]byte(base.Evidence), &original) != nil {
		return errors.New("invalid frozen browser base")
	}
	baseComplete := base.Error == "" && original.Probe.Response.Completeness == "full" && base.HTTPProgress != nil && base.HTTPProgress.Complete && original.Fingerprint.Active != nil && original.Fingerprint.Active.Complete
	for _, gap := range original.Probe.CapabilityGaps {
		switch gap {
		case "wappalyzer-browser-js-dom", "http2-probe", "unsafe", "ztls", "headless":
		default:
			baseComplete = false
		}
	}
	if original.Fingerprint.Active != nil {
		for _, r := range original.Fingerprint.Active.Rules {
			if r.Status == "failed" || r.Status == "partial" {
				baseComplete = false
			}
		}
	}
	for _, m := range b.Matches {
		if m.Name == "" || b.Engine == "" || m.Engine == "" || (m.Engine != b.Engine && !strings.HasPrefix(b.Engine, m.Engine+"+")) {
			return errors.New("invalid browser technology match")
		}
		t := Technology{Candidate: m.Candidate, CandidateReason: m.CandidateReason, Name: m.Name, Version: m.Version, RuleID: "httpx-browser:" + m.Name, Evidence: string(m.Evidence)}
		found := false
		for _, old := range base.Technologies {
			if old.Name == t.Name && old.Version == t.Version && old.Candidate == t.Candidate {
				found = true
				break
			}
		}
		if !found {
			base.Technologies = append(base.Technologies, t)
		}
	}
	base.Coverage, base.Outcome = "partial", "incomplete"
	state := "partial"
	if jsComplete {
		state = "complete"
	}
	if jsComplete && screenshotComplete && baseComplete {
		base.Coverage, base.Outcome = "complete", "identified"
	}
	base.Browser = nil
	if jsSelected {
		if !jsRequired {
			state = "not_applicable"
		}
		base.Browser = &webevidence.BrowserStage{Profile: webevidence.BrowserProfile, State: state, StopReason: jsStage.StopReason, Requests: max(b.Requests, p.BrowserRequestsUsed), JSDOM: &jsStage}
	}
	base.Screenshot = screenshot
	if jsSelected {
		b.JSDOM = &jsStage
	}
	if p.WebScanOptions != nil {
		base.WebScanOptions = p.WebScanOptions
	}
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal([]byte(base.Evidence), &envelope)
	// Evidence is kept separate; the original probe's execution identity is intact.
	raw, _ := json.Marshal(b)
	envelope["browser"] = raw
	raw, _ = json.Marshal(envelope)
	base.Evidence = string(raw)
	*item = base
	return nil
}

func mustBrowserScheme(raw string) string { u, _ := url.Parse(raw); return u.Scheme }
