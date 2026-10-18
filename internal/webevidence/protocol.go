// Package webevidence is the bounded IPC contract between Agent and its helpers.
// It deliberately has no scanner SDK dependencies.
package webevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

const (
	Protocol          = "shen-web-v1"
	FingerprintBundle = "b5946286a877ff75a1c7b9914e9c3e4b0aba4e15287ee1cf594eef6db8e18538"
	Profile           = "bounded-passive-v1"
	EnrichmentProfile = "bounded-enrichment-v1"
	MaxBody           = 2 << 20
	MaxIcon           = 256 << 10
	MaxMessage        = 12 << 20
)

type ProbeRequest struct {
	ID                 string          `json:"id"`
	EnrichmentProfile  string          `json:"enrichment_profile,omitempty"`
	Step               string          `json:"step,omitempty"`
	MaxRequests        int             `json:"max_requests,omitempty"`
	AdmissionURL       string          `json:"admission_url,omitempty"`
	AdmissionToken     string          `json:"admission_token,omitempty"`
	Protocol           string          `json:"protocol"`
	URL                string          `json:"url"`
	ConnectIP          string          `json:"connect_ip"`
	AlternateScheme    bool            `json:"alternate_scheme,omitempty"`
	TimeoutMillis      int             `json:"timeout_ms"`
	EntryTimeoutMillis int             `json:"entry_timeout_ms"`
	CFF                json.RawMessage `json:"cff,omitempty"`
	CFFSHA256          string          `json:"cff_sha256,omitempty"`
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
	ID                string         `json:"id"`
	EnrichmentProfile string         `json:"enrichment_profile,omitempty"`
	InputURL          string         `json:"input_url,omitempty"`
	Redirects         []RedirectStep `json:"redirects,omitempty"`
	Protocol          string         `json:"protocol"`
	Engine            string         `json:"engine"`
	Profile           string         `json:"profile"`
	Response          Response       `json:"response"`
	Attempts          []Response     `json:"attempts,omitempty"`
	Icons             []Response     `json:"icons,omitempty"`
	Title             string         `json:"title,omitempty"`
	Technologies      []string       `json:"technologies,omitempty"`
	CFFSHA256         string         `json:"cff_sha256,omitempty"`
	Requests          int            `json:"requests"`
	Error             string         `json:"error,omitempty"`
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
	Protocol       string     `json:"protocol"`
	ID             string     `json:"id"`
	ExpectedBundle string     `json:"expected_bundle,omitempty"`
	Response       Response   `json:"response"`
	Icons          []Response `json:"icons,omitempty"`
}

type Match struct {
	Name     string          `json:"name"`
	Version  string          `json:"version,omitempty"`
	Engine   string          `json:"engine"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

type MatchResult struct {
	Protocol string  `json:"protocol"`
	ID       string  `json:"id"`
	Bundle   string  `json:"bundle"`
	Matches  []Match `json:"matches,omitempty"`
	Error    string  `json:"error,omitempty"`
}

func SHA256(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
