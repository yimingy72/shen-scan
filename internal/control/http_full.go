package control

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/webevidence"
)

type fullHTTPPayload struct {
	WebScanOptions *webevidence.WebScanOptions `json:"web_scan_options,omitempty"`
	RulesRef       string                      `json:"rules_ref"`
	Bundle         string                      `json:"fingerprint_bundle"`
	Profile        string                      `json:"web_execution_profile"`
	Endpoints      []taskEndpoint              `json:"endpoints"`
	Progress       *webevidence.EntryProgress  `json:"http_progress,omitempty"`
}

func initializeHTTPProgress(ctx context.Context, tx pgx.Tx, taskID string, payload []byte) ([]byte, error) {
	var p fullHTTPPayload
	if json.Unmarshal(payload, &p) != nil || p.Profile != webevidence.FullProfile {
		return payload, nil
	}
	if len(p.Endpoints) != 1 {
		return nil, errors.New("full HTTP requires one stable entry per task")
	}

	if p.RulesRef == "" {
		if err := tx.QueryRow(ctx, `SELECT run_id||':http' FROM tasks WHERE id=$1`, taskID).Scan(&p.RulesRef); err != nil {
			return nil, err
		}
	}
	var progress webevidence.EntryProgress
	if p.Progress != nil {
		progress = *p.Progress
	} else {
		var started time.Time
		if err := tx.QueryRow(ctx, `SELECT first_started_at FROM tasks WHERE id=$1`, taskID).Scan(&started); err != nil {
			return nil, err
		}
		entry, err := endpointBaseURL(p.Endpoints[0])
		if err != nil {
			return nil, err
		}
		manifestHash := webevidence.EmbeddedManifestHash
		if p.Bundle != fb.EmbeddedBundle {
			if err = tx.QueryRow(ctx, `SELECT manifest_hash FROM fingerprint_bundles WHERE digest=$1`, p.Bundle).Scan(&manifestHash); err != nil {
				return nil, err
			}
			if len(manifestHash) != 64 {
				return nil, errors.New("assigned full HTTP package has no frozen manifest hash")
			}
		}
		selection := webevidence.FullProfile + "|" + fb.SelectionProfile + "|" + fb.EngineRevision
		if p.WebScanOptions != nil {
			options, _ := json.Marshal(p.WebScanOptions)
			selection += "|" + string(options)
		}
		progress = webevidence.EntryProgress{EntryURL: entry.String(), RulesRef: p.RulesRef, SelectionProfileHash: webevidence.SHA256([]byte(selection)), ManifestHash: manifestHash, Deadline: started.Add(20 * time.Minute), MaxRequests: 16384, MaxSegments: 32}
	}
	// Reserve the whole next segment before handing its lease to a Worker. A
	// stopped or lost attempt never refunds unknown request consumption.
	progress.Segment = max(progress.Segment, progress.ReservedSegment) + 1
	reserveHTTPFullSegment(&progress, progress.Segment)
	raw, _ := json.Marshal(progress)
	if _, err := tx.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{http_progress}',$2::jsonb) WHERE id=$1`, taskID, raw); err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(payload, &result); err != nil {
		return nil, err
	}
	result["http_progress"] = raw
	return json.Marshal(result)
}

// Batch identity, lease and cancellation have already been fenced and locked.
// Keep one current asset per HTTP entry; immutable task_batches retain every
// checkpoint's digest and submitted bytes for replay and completion manifests.
func acceptHTTPProgress(ctx context.Context, tx pgx.Tx, taskID string, attempt int, payload []byte, items []Observation) error {
	var p fullHTTPPayload
	if json.Unmarshal(payload, &p) != nil || p.Profile != webevidence.FullProfile {
		return nil
	}
	if p.Progress == nil || len(p.Endpoints) != 1 || len(items) != 1 {
		return errors.New("full HTTP requires one initialized entry checkpoint")
	}
	next := items[0].HTTPProgress
	if next == nil {
		return nil
	} // Explicit setup errors still have a terminal outcome.
	if err := validateHTTPProgress(*p.Progress, *next); err != nil {
		return err
	}
	// The admission transaction charges every grant, including requests lost in a
	// crash. An Agent checkpoint can never lower this cumulative authoritative count.
	next.RequestsUsed = max(next.RequestsUsed, p.Progress.RequestsUsed)
	next.ReservedRequests = p.Progress.ReservedRequests
	next.ReservedSegment = p.Progress.ReservedSegment
	next.SegmentRequestLimit = p.Progress.SegmentRequestLimit
	next.SegmentRequestsUsed = p.Progress.SegmentRequestsUsed
	raw, _ := json.Marshal(next)
	if _, err := tx.Exec(ctx, `UPDATE tasks SET payload=jsonb_set(payload,'{http_progress}',$2::jsonb) WHERE id=$1`, taskID, raw); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM assets WHERE task_id=$1 AND observation->>'kind'='http'`, taskID)
	return err
}

func validateHTTPProgress(previous, next webevidence.EntryProgress) error {
	if next.EntryURL != previous.EntryURL || next.RulesRef != previous.RulesRef || next.SelectionProfileHash != previous.SelectionProfileHash || next.ManifestHash != previous.ManifestHash {
		return errors.New("HTTP checkpoint changed immutable entry or manifest identity")
	}
	if !next.Deadline.Equal(previous.Deadline) || next.MaxRequests != previous.MaxRequests || next.MaxSegments != previous.MaxSegments || next.Segment < previous.Segment || next.Segment > next.MaxSegments || next.RequestsUsed < 0 || next.RequestsUsed > next.MaxRequests {
		return errors.New("HTTP checkpoint reset its fixed deadline, budget or segment bounds")
	}
	completed := map[string]bool{}
	for _, id := range next.CompletedRuleIDs {
		if id == "" || completed[id] {
			return errors.New("duplicate or empty completed HTTP rule")
		}
		completed[id] = true
	}
	for _, id := range previous.CompletedRuleIDs {
		if !completed[id] {
			return errors.New("HTTP checkpoint lost a completed rule")
		}
	}
	for _, id := range next.RemainingRuleIDs {
		if id == "" || completed[id] {
			return errors.New("HTTP remaining rules overlap completed rules")
		}
	}
	if next.Complete && len(next.RemainingRuleIDs) > 0 {
		return errors.New("HTTP checkpoint claims complete with remaining rules")
	}
	priorMatches := map[string]bool{}
	for _, m := range next.Matches {
		priorMatches[m.Engine+"\x00"+m.Name+"\x00"+m.Version] = true
	}
	for _, m := range previous.Matches {
		if !priorMatches[m.Engine+"\x00"+m.Name+"\x00"+m.Version] {
			return errors.New("HTTP checkpoint lost a prior positive match")
		}
	}
	return nil
}

func validateFullHTTPEvidence(endpoint taskEndpoint, item *Observation) error {
	var envelope struct {
		Probe       *webevidence.ProbeResult `json:"probe"`
		Fingerprint *webevidence.MatchResult `json:"fingerprint"`
	}
	if json.Unmarshal([]byte(item.Evidence), &envelope) != nil || envelope.Probe == nil {
		if item.StatusCode == 0 && item.Error != "" && item.Outcome == "error" {
			return nil
		}
		return errors.New("full HTTP observation requires primary probe evidence")
	}
	p := envelope.Probe
	if p.ExecutionProfile != webevidence.FullProfile || p.Profile != webevidence.FullProfile || p.Protocol != webevidence.Protocol || item.ExecutionProfile != webevidence.FullProfile {
		return errors.New("full HTTP evidence profile mismatch")
	}
	if endpoint.URL != "" && !sameHTTPEntry(endpoint.URL, p.InputURL) {
		return errors.New("full HTTP input changed assigned entry")
	}
	if _, ok := observedEndpoint(endpoint, p.InputURL); !ok {
		return errors.New("full HTTP input escaped assigned endpoint")
	}
	if !sameHTTPEntry(item.URL, p.Response.URL) {
		return errors.New("full HTTP primary result changed response URL")
	}
	if p.Requests < 1 || p.Requests > 16384 {
		return errors.New("invalid full HTTP probe request count")
	}
	responses := append([]webevidence.Response{p.Response}, p.Attempts...)
	responses = append(responses, p.Icons...)
	if envelope.Fingerprint != nil && envelope.Fingerprint.Active != nil {
		responses = append(responses, envelope.Fingerprint.Active.Responses...)
	}
	for _, r := range responses {
		if _, ok := httpEvidenceURL(r.URL); !ok {
			return errors.New("invalid full HTTP response URL")
		}
		if _, ok := observedEndpoint(endpoint, r.URL); !ok {
			return errors.New("full HTTP response escaped assigned endpoint")
		}
		if r.ConnectIP != "" && canonicalTarget(r.ConnectIP) != canonicalTarget(item.IP) {
			return errors.New("full HTTP response changed connect IP")
		}
	}
	for _, gap := range p.CapabilityGaps {
		switch gap {
		case "http2-probe", "unsafe", "ztls", "headless":
		default:
			if item.Coverage == "complete" {
				return errors.New("HTTP result claims complete with missing rule evidence capability")
			}
		}
	}
	if item.HTTPProgress == nil {
		return errors.New("full HTTP result omitted execution progress")
	}
	if !item.HTTPProgress.Complete && item.Coverage == "complete" {
		return errors.New("unfinished full HTTP result claims complete coverage")
	}
	if item.HTTPProgress.Complete && (envelope.Fingerprint == nil || envelope.Fingerprint.Active == nil || !envelope.Fingerprint.Active.Complete) {
		return errors.New("full HTTP completion omitted complete matcher attestation")
	}
	return nil
}

func fullHTTPRunLive(ctx context.Context, tx pgx.Tx, runID string, payload []byte) bool {
	var p fullHTTPPayload
	if json.Unmarshal(payload, &p) != nil || p.Profile != webevidence.FullProfile && !browserTaskPayload(payload) {
		return true
	}
	var live bool
	return tx.QueryRow(ctx, `SELECT status IN('pending','running') FROM runs WHERE id=$1`, runID).Scan(&live) == nil && live
}

// A failed recollection after restart cannot erase a previously accepted HTTP
// response or its positive technologies. The entry remains explicitly partial.
func preserveFullHTTPPositive(ctx context.Context, tx pgx.Tx, taskID string, payload []byte, item *Observation) error {
	var p fullHTTPPayload
	if json.Unmarshal(payload, &p) == nil && p.Profile == webevidence.FullProfile && p.Progress != nil && item.HTTPProgress != nil {
		item.HTTPProgress.RequestsUsed = max(item.HTTPProgress.RequestsUsed, p.Progress.RequestsUsed)
		item.HTTPProgress.ReservedRequests = p.Progress.ReservedRequests
		item.HTTPProgress.ReservedSegment = p.Progress.ReservedSegment
		item.HTTPProgress.SegmentRequestLimit = p.Progress.SegmentRequestLimit
		item.HTTPProgress.SegmentRequestsUsed = p.Progress.SegmentRequestsUsed
	}
	if json.Unmarshal(payload, &p) != nil || p.Profile != webevidence.FullProfile || item.StatusCode > 0 {
		return nil
	}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT observation FROM assets WHERE task_id=$1 AND observation->>'kind'='http' ORDER BY attempt_no DESC,batch_seq DESC,item_index DESC LIMIT 1`, taskID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var prior Observation
	if err = json.Unmarshal(raw, &prior); err != nil {
		return err
	}
	if prior.StatusCode == 0 {
		return nil
	}
	prior.Error = item.Error
	prior.Coverage = "partial"
	prior.Outcome = "incomplete"
	prior.HTTPProgress = item.HTTPProgress
	// The retained probe is evidence from its original fenced attempt, not a new
	// successful collection. Keep its identity intact and mark the recovery error.
	var evidence map[string]json.RawMessage
	if json.Unmarshal([]byte(prior.Evidence), &evidence) == nil {
		failure, _ := json.Marshal(map[string]any{"error": item.Error, "retained_prior_evidence": true})
		evidence["recovery"] = failure
		updated, _ := json.Marshal(evidence)
		prior.Evidence = string(updated)
	}
	*item = prior
	return nil
}

func validateFullHTTPIdentity(item Observation, taskID string, attempt int, payload []byte) error {
	if item.ExecutionProfile != webevidence.FullProfile {
		return nil
	}
	var assignment fullHTTPPayload
	if json.Unmarshal(payload, &assignment) != nil || assignment.Profile != webevidence.FullProfile || assignment.Progress == nil {
		return errors.New("full HTTP identity missing assigned progress")
	}
	if assignment.WebScanOptions != nil && (item.WebScanOptions == nil || *item.WebScanOptions != *assignment.WebScanOptions) {
		return errors.New("HTTP result changed frozen scan options")
	}
	var identity struct {
		Probe       *webevidence.ProbeResult `json:"probe"`
		Fingerprint *webevidence.MatchResult `json:"fingerprint"`
	}
	if json.Unmarshal([]byte(item.Evidence), &identity) == nil && identity.Probe != nil {
		p := assignment.Progress
		bound := func(i webevidence.ExecutionIdentity) bool {
			return i.TaskID == taskID && i.AttemptNo == attempt && i.EntryURL == p.EntryURL && i.RulesRef == p.RulesRef && i.ManifestHash == p.ManifestHash && i.SelectionProfileHash == p.SelectionProfileHash
		}
		if !bound(identity.Probe.Identity) {
			return errors.New("full probe has stale execution identity")
		}
		if identity.Fingerprint != nil && identity.Fingerprint.ID != "" && !bound(identity.Fingerprint.Identity) {
			return errors.New("full matcher has stale execution identity")
		}
	}

	return nil
}

func reserveHTTPFullSegment(progress *webevidence.EntryProgress, segment int) {
	if segment <= progress.ReservedSegment {
		return
	}
	progress.SegmentRequestLimit = max(0, min(1024, progress.MaxRequests-progress.ReservedRequests))
	progress.ReservedRequests += progress.SegmentRequestLimit
	progress.ReservedSegment = segment
	progress.SegmentRequestsUsed = 0
}
