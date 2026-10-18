// Package webevidence is the bounded IPC contract between Agent and its helpers.
// It deliberately has no scanner SDK dependencies.
package webevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	Protocol                = "shen-web-v1"
	FingerprintBundle       = "6f267d12bdb5e7f6fc64db8b44c71cdae78b70175dd93a346a9d05405867e84e"
	LegacyFingerprintBundle = "b5946286a877ff75a1c7b9914e9c3e4b0aba4e15287ee1cf594eef6db8e18538"
	Profile                 = "bounded-passive-v1"
	EnrichmentProfile       = "bounded-enrichment-v1"
	FullProfile             = "web-full-v2"
	BrowserProfile          = "wapp-browser-v1"
	WebScanOptionsProfile   = "independent-web-options-v1"
	EmbeddedManifestHash    = "cf8c2a02feaf3c9fc9fc24def2798f119967325484b1817e5f2c9fea32bfd1c8"
	MaxBody                 = 2 << 20
	MaxIcon                 = 256 << 10
	MaxMessage              = 12 << 20
	MaxScreenshot           = 768 << 10
)

// A nil options pointer preserves historical frozen execution. New runs always
// carry an explicit object, including the valid collection-only all-false case.
type WebScanOptions struct {
	Passive    bool `json:"passive"`
	Active     bool `json:"active"`
	JSDOM      bool `json:"js_dom"`
	Screenshot bool `json:"screenshot"`
}

func DefaultWebScanOptions() WebScanOptions { return WebScanOptions{Passive: true, Active: true} }

type WebStage struct {
	State      string `json:"state"`
	Error      string `json:"error,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
}

type BrowserCapability struct {
	Ready             bool   `json:"browser_ready"`
	Version           string `json:"browser_version,omitempty"`
	UnavailableReason string `json:"browser_unavailable_reason,omitempty"`
}

// PNG is IPC/upload only; Control removes it from indexed evidence and stores
// validated bytes separately. No worker-supplied local filesystem path is used.
type BrowserScreenshot struct {
	WebStage
	PNG    []byte `json:"png,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type ScreenshotMetadata struct {
	WebStage
	ID     string `json:"id,omitempty"`
	URL    string `json:"url,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
}

type ProbeRequest struct {
	WebScanOptions     *WebScanOptions   `json:"web_scan_options,omitempty"`
	Profile            string            `json:"profile,omitempty"`
	HTTPHost           string            `json:"http_host,omitempty"`
	TLSSNI             string            `json:"tls_sni,omitempty"`
	ExecutionProfile   string            `json:"execution_profile,omitempty"`
	Identity           ExecutionIdentity `json:"identity,omitempty"`
	Host               string            `json:"host,omitempty"`
	SNI                string            `json:"sni,omitempty"`
	ID                 string            `json:"id"`
	EnrichmentProfile  string            `json:"enrichment_profile,omitempty"`
	Step               string            `json:"step,omitempty"`
	MaxRequests        int               `json:"max_requests,omitempty"`
	AdmissionURL       string            `json:"admission_url,omitempty"`
	AdmissionToken     string            `json:"admission_token,omitempty"`
	Protocol           string            `json:"protocol"`
	URL                string            `json:"url"`
	ConnectIP          string            `json:"connect_ip"`
	AlternateScheme    bool              `json:"alternate_scheme,omitempty"`
	TimeoutMillis      int               `json:"timeout_ms"`
	EntryTimeoutMillis int               `json:"entry_timeout_ms"`
	CFF                json.RawMessage   `json:"cff,omitempty"`
	CFFSHA256          string            `json:"cff_sha256,omitempty"`
}

type TLS struct {
	Source           string   `json:"source"`
	ServerName       string   `json:"server_name,omitempty"`
	Version          uint16   `json:"version"`
	PeerCertificates [][]byte `json:"peer_certificates,omitempty"`
}

type Response struct {
	URL          string      `json:"url"`
	ConnectIP    string      `json:"connect_ip"`
	Host         string      `json:"host"`
	ObservedAt   time.Time   `json:"observed_at"`
	StatusCode   int         `json:"status_code"`
	Proto        string      `json:"proto,omitempty"`
	Headers      http.Header `json:"headers,omitempty"`
	RequestRaw   string      `json:"request_raw,omitempty"`
	HeaderRaw    string      `json:"header_raw,omitempty"`
	Body         []byte      `json:"body,omitempty"`
	BodyStorage  string      `json:"body_storage,omitempty"`
	BodySHA256   string      `json:"body_sha256,omitempty"`
	EncodedBytes int64       `json:"encoded_bytes"`
	DecodedBytes int         `json:"decoded_bytes"`
	Completeness string      `json:"completeness"`
	Error        string      `json:"error,omitempty"`
	TLS          *TLS        `json:"tls,omitempty"`
}

type ProbeResult struct {
	WebScanOptions    *WebScanOptions   `json:"web_scan_options,omitempty"`
	SDKResult         json.RawMessage   `json:"sdk_result,omitempty"`
	CapabilityGaps    []string          `json:"capability_gaps,omitempty"`
	ExecutionProfile  string            `json:"execution_profile,omitempty"`
	Identity          ExecutionIdentity `json:"identity,omitempty"`
	ID                string            `json:"id"`
	EnrichmentProfile string            `json:"enrichment_profile,omitempty"`
	InputURL          string            `json:"input_url,omitempty"`
	Redirects         []RedirectStep    `json:"redirects,omitempty"`
	Protocol          string            `json:"protocol"`
	Engine            string            `json:"engine"`
	Profile           string            `json:"profile"`
	Response          Response          `json:"response"`
	Attempts          []Response        `json:"attempts,omitempty"`
	Icons             []Response        `json:"icons,omitempty"`
	Title             string            `json:"title,omitempty"`
	Technologies      []string          `json:"technologies,omitempty"`
	CFFSHA256         string            `json:"cff_sha256,omitempty"`
	Requests          int               `json:"requests"`
	Error             string            `json:"error,omitempty"`
}

// BrowserParentIdentity binds supplementation to one immutable accepted HTTP
// observation, independently of the browser child's own lease identity.
type BrowserParentIdentity struct {
	TaskID            string            `json:"task_id"`
	AttemptNo         int               `json:"attempt_no"`
	CompletionID      string            `json:"completion_id"`
	ObservationID     string            `json:"observation_id"`
	ObservationSHA256 string            `json:"observation_sha256"`
	Identity          ExecutionIdentity `json:"identity"`
}

type BrowserRequest struct {
	ProbeRequest
	Parent BrowserParentIdentity `json:"parent"`
	Seed   *Response             `json:"seed,omitempty"`
}

type BrowserBlockedRequest struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Reason string `json:"reason"`
}

type BrowserResult struct {
	JSDOMEnabled           *bool                   `json:"js_dom_enabled,omitempty"`
	JSDOM                  *WebStage               `json:"js_dom,omitempty"`
	Screenshot             *BrowserScreenshot      `json:"screenshot,omitempty"`
	ID                     string                  `json:"id"`
	Protocol               string                  `json:"protocol"`
	Profile                string                  `json:"profile"`
	Identity               ExecutionIdentity       `json:"identity"`
	Parent                 BrowserParentIdentity   `json:"parent"`
	CFFSHA256              string                  `json:"cff_sha256"`
	Engine                 string                  `json:"engine"`
	BrowserVersion         string                  `json:"browser_version,omitempty"`
	PlanSHA256             string                  `json:"plan_sha256,omitempty"`
	TotalRules             int                     `json:"total_rules"`
	EvaluatedRules         int                     `json:"evaluated_rules"`
	UnsupportedRules       int                     `json:"unsupported_rules"`
	IncompleteRules        int                     `json:"incomplete_rules"`
	OmittedNegativeRules   int                     `json:"omitted_negative_rules,omitempty"`
	NegativeOutcomesSHA256 string                  `json:"negative_outcomes_sha256,omitempty"`
	SampleWindow           string                  `json:"sample_window,omitempty"`
	Matches                []Match                 `json:"matches,omitempty"`
	Rules                  []RuleExecution         `json:"rules,omitempty"`
	Attempts               []Response              `json:"attempts,omitempty"`
	Blocked                []BrowserBlockedRequest `json:"blocked,omitempty"`
	BlockedCount           int                     `json:"blocked_count,omitempty"`
	EvidenceSHA256         string                  `json:"evidence_sha256,omitempty"`
	Requests               int                     `json:"requests"`
	Complete               bool                    `json:"complete"`
	StopReason             string                  `json:"stop_reason,omitempty"`
	Error                  string                  `json:"error,omitempty"`
}

type BrowserStage struct {
	JSDOM      *WebStage `json:"js_dom,omitempty"`
	Screenshot *WebStage `json:"screenshot,omitempty"`
	Profile    string    `json:"profile"`
	State      string    `json:"state"` // pending, complete, partial, not_applicable
	StopReason string    `json:"stop_reason,omitempty"`
	Requests   int       `json:"requests,omitempty"`
}

// BrowserAssignment is fixed when the parent completes. Only deadline and
// requests_used are updated by Control, never refunded on a lost attempt.
type BrowserAssignment struct {
	BrowserJSDOMRequired *bool                 `json:"browser_js_dom_required,omitempty"`
	WebScanOptions       *WebScanOptions       `json:"web_scan_options,omitempty"`
	Phase                string                `json:"phase,omitempty"`
	WebBrowserProfile    string                `json:"web_browser_profile,omitempty"`
	BrowserParent        BrowserParentIdentity `json:"browser_parent"`
	BrowserURL           string                `json:"browser_url"`
	BrowserConnectIP     string                `json:"browser_connect_ip"`
	BrowserHost          string                `json:"browser_host"`
	BrowserSNI           string                `json:"browser_sni"`
	BrowserCFFSHA256     string                `json:"browser_cff_sha256"`
	BrowserSeed          *Response             `json:"browser_seed,omitempty"`
	BrowserDeadline      time.Time             `json:"browser_deadline,omitempty"`
	BrowserRequestsUsed  int                   `json:"browser_requests_used"`
}

// BrowserApplicable rejects known non-HTML documents. An unknown media type is
// deliberately eligible; its first controlled browser collection can resolve it.
func BrowserApplicable(response Response) bool {
	if response.StatusCode <= 0 {
		return false
	}
	contentType := response.Headers.Get("Content-Type")
	for i, c := range contentType {
		if c == ';' {
			contentType = contentType[:i]
			break
		}
	}
	return contentType == "" || strings.EqualFold(strings.TrimSpace(contentType), "text/html") || strings.EqualFold(strings.TrimSpace(contentType), "application/xhtml+xml")
}

// Attempts hold the bounded response evidence; each redirect names its source
// attempt. A stopped destination is recorded without making a request to it.
type RedirectStep struct {
	FromURL      string `json:"from_url"`
	ToURL        string `json:"to_url,omitempty"`
	StatusCode   int    `json:"status_code"`
	Outcome      string `json:"outcome"`
	AttemptIndex int    `json:"attempt_index"`
}

type MatchRequest struct {
	WebScanOptions   *WebScanOptions   `json:"web_scan_options,omitempty"`
	ExecutionProfile string            `json:"execution_profile,omitempty"`
	Identity         ExecutionIdentity `json:"identity,omitempty"`
	Active           *ActiveRequest    `json:"active,omitempty"`
	Protocol         string            `json:"protocol"`
	ID               string            `json:"id"`
	ExpectedBundle   string            `json:"expected_bundle,omitempty"`
	Response         Response          `json:"response"`
	Icons            []Response        `json:"icons,omitempty"`
}

type Match struct {
	Candidate       bool            `json:"candidate,omitempty"`
	CandidateReason string          `json:"candidate_reason,omitempty"`
	Name            string          `json:"name"`
	Version         string          `json:"version,omitempty"`
	Engine          string          `json:"engine"`
	Evidence        json.RawMessage `json:"evidence,omitempty"`
}

type MatchResult struct {
	ExecutionProfile string            `json:"execution_profile,omitempty"`
	Identity         ExecutionIdentity `json:"identity,omitempty"`
	Active           *ActiveResult     `json:"active,omitempty"`
	Protocol         string            `json:"protocol"`
	ID               string            `json:"id"`
	Bundle           string            `json:"bundle"`
	Matches          []Match           `json:"matches,omitempty"`
	Error            string            `json:"error,omitempty"`
}

func SHA256(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// ExecutionIdentity fences each helper invocation while EntryID remains stable
// across bounded segments of the same HTTP work item.
type ExecutionIdentity struct {
	EntryURL             string `json:"entry_url,omitempty"`
	RulesRef             string `json:"rules_ref,omitempty"`
	SelectionProfileHash string `json:"selection_profile_hash,omitempty"`
	ManifestHash         string `json:"manifest_hash,omitempty"`
	TaskID               string `json:"task_id,omitempty"`
	AttemptNo            int    `json:"attempt_no,omitempty"`
	EntryID              string `json:"entry_id,omitempty"`
	Segment              int    `json:"segment,omitempty"`
}

// ActiveRequest keeps a whole native template as the smallest resumable unit.
// Interrupted stateful templates restart from their first request; completed
// templates never rerun. All network requests use the Agent admission callback.
type ActiveRequest struct {
	EntryURL           string     `json:"entry_url"`
	ConnectIP          string     `json:"connect_ip"`
	Host               string     `json:"host,omitempty"`
	SNI                string     `json:"sni,omitempty"`
	Responses          []Response `json:"responses,omitempty"`
	CompletedRuleIDs   []string   `json:"completed_rule_ids,omitempty"`
	RemainingRuleIDs   []string   `json:"remaining_rule_ids,omitempty"`
	CandidateProducts  []string   `json:"candidate_products,omitempty"`
	RequestsUsed       int        `json:"requests_used"`
	MaxRequests        int        `json:"max_requests"`
	SegmentDeadline    time.Time  `json:"segment_deadline,omitempty"`
	SegmentMaxRequests int        `json:"segment_max_requests"`
	Deadline           time.Time  `json:"deadline"`
	AdmissionURL       string     `json:"admission_url"`
	AdmissionToken     string     `json:"admission_token"`
	TimeoutMillis      int        `json:"timeout_ms,omitempty"`
}

type RuleExecution struct {
	RuleID   string `json:"rule_id"`
	Status   string `json:"status"` // matched, not_matched, failed, partial, not_applicable
	Requests int    `json:"requests"`
	Error    string `json:"error,omitempty"`
}

type ActiveResult struct {
	Rules            []RuleExecution `json:"rules,omitempty"`
	CompletedRuleIDs []string        `json:"completed_rule_ids,omitempty"`
	RemainingRuleIDs []string        `json:"remaining_rule_ids,omitempty"`
	Requests         int             `json:"requests"` // this segment only, including failed network attempts
	Complete         bool            `json:"complete"`
	StopReason       string          `json:"stop_reason,omitempty"`
	Errors           []string        `json:"errors,omitempty"`
	Responses        []Response      `json:"responses,omitempty"`
}

// EntryProgress is an Agent checkpoint accepted only inside the ordinary result
// batch transaction. The Control plane owns the fixed deadline and request count.
type EntryProgress struct {
	EntryURL             string    `json:"entry_url,omitempty"`
	RulesRef             string    `json:"rules_ref,omitempty"`
	SelectionProfileHash string    `json:"selection_profile_hash,omitempty"`
	ManifestHash         string    `json:"manifest_hash,omitempty"`
	ReservedRequests     int       `json:"reserved_requests"`
	ReservedSegment      int       `json:"reserved_segment"`
	SegmentRequestLimit  int       `json:"segment_request_limit"`
	SegmentRequestsUsed  int       `json:"segment_requests_used"`
	Segment              int       `json:"segment"`
	MaxSegments          int       `json:"max_segments"`
	Deadline             time.Time `json:"deadline"`
	MaxRequests          int       `json:"max_requests"`
	RequestsUsed         int       `json:"requests_used"`
	CompletedRuleIDs     []string  `json:"completed_rule_ids,omitempty"`
	RemainingRuleIDs     []string  `json:"remaining_rule_ids,omitempty"`
	Matches              []Match   `json:"matches,omitempty"`
	Complete             bool      `json:"complete"`
	StopReason           string    `json:"stop_reason,omitempty"`
}
