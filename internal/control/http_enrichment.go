package control

import (
	"encoding/json"
	"errors"
	"net/url"

	"scanplatform/internal/webevidence"
)

func httpEvidenceURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func sameHTTPEntry(a, b string) bool {
	x, ok := httpEvidenceURL(a)
	if !ok {
		return false
	}
	y, ok := httpEvidenceURL(b)
	if !ok || origin(x) != origin(y) {
		return false
	}
	xPath, yPath := x.EscapedPath(), y.EscapedPath()
	if xPath == "" {
		xPath = "/"
	}
	if yPath == "" {
		yPath = "/"
	}
	return xPath == yPath && x.RawQuery == y.RawQuery && x.ForceQuery == y.ForceQuery
}

// The primary observation owns the assigned work. Redirect/collection responses
// remain nested evidence and cannot create another HTTP or PoC observation.
func validateHTTPEnrichmentEvidence(endpoint taskEndpoint, item *Observation, profile string) error {
	if profile == "" {
		return nil
	}
	var envelope struct {
		Probe       *webevidence.ProbeResult `json:"probe"`
		Supplements []struct {
			URL      string                `json:"url"`
			Response *webevidence.Response `json:"response"`
		} `json:"supplements"`
	}
	if json.Unmarshal([]byte(item.Evidence), &envelope) != nil || envelope.Probe == nil {
		// Setup failures have no probe to attest. The caller has already bound
		// their work key and target; no successful result gets this exception.
		if item.StatusCode == 0 && item.Error != "" && (item.Outcome == "error" || item.Outcome == "incomplete") {
			return nil
		}
		return errors.New("HTTP enrichment observation requires primary probe evidence")
	}
	probe := envelope.Probe
	if probe.EnrichmentProfile != profile || probe.Protocol != webevidence.Protocol {
		return errors.New("HTTP enrichment evidence profile does not match assignment")
	}
	input, ok := httpEvidenceURL(probe.InputURL)
	if !ok {
		return errors.New("HTTP enrichment evidence has no valid input URL")
	}
	if endpoint.URL != "" {
		if !sameHTTPEntry(endpoint.URL, probe.InputURL) {
			return errors.New("HTTP enrichment input URL does not match assigned entry")
		}
	} else if _, ok := observedEndpoint(endpoint, probe.InputURL); !ok || (input.Path != "" && input.Path != "/") || input.RawQuery != "" {
		return errors.New("HTTP enrichment input URL is outside assigned entry")
	}
	if !sameHTTPEntry(probe.Response.URL, item.URL) {
		return errors.New("HTTP primary observation does not match its response evidence")
	}
	if probe.Requests < 0 || probe.Requests > 8 || len(probe.Attempts) > 8 || len(probe.Icons) > 2 || len(probe.Redirects) > 8 {
		return errors.New("HTTP enrichment evidence exceeds assigned bounds")
	}
	responses := append([]webevidence.Response{probe.Response}, probe.Attempts...)
	responses = append(responses, probe.Icons...)
	for _, response := range responses {
		_, valid := httpEvidenceURL(response.URL)
		if !valid {
			return errors.New("HTTP enrichment response has an invalid URL")
		}
		if _, valid = observedEndpoint(endpoint, response.URL); !valid {
			return errors.New("HTTP enrichment response is outside assigned origin")
		}
		// Alternate scheme confirmation remains legal for an implicit URL;
		// explicit URL inputs never authorize an alternate origin.
		if endpoint.IP != "" && canonicalTarget(response.ConnectIP) != canonicalTarget(endpoint.IP) {
			return errors.New("HTTP enrichment response changed assigned connect IP")
		}
		if item.IP != "" && response.ConnectIP != "" && canonicalTarget(response.ConnectIP) != canonicalTarget(item.IP) {
			return errors.New("HTTP enrichment response changed observed connect IP")
		}
	}
	current := probe.InputURL
	if endpoint.URL == "" && len(probe.Attempts) > 1 && probe.Attempts[0].StatusCode == 0 {
		alternate, valid := httpEvidenceURL(probe.Attempts[1].URL)
		if valid && alternate.Scheme != input.Scheme && alternate.EscapedPath() == input.EscapedPath() && alternate.RawQuery == input.RawQuery {
			current = probe.Attempts[1].URL
		}
	}
	for _, redirect := range probe.Redirects {
		if redirect.AttemptIndex < 0 || redirect.AttemptIndex >= len(probe.Attempts) ||
			!sameHTTPEntry(redirect.FromURL, probe.Attempts[redirect.AttemptIndex].URL) || redirect.StatusCode != probe.Attempts[redirect.AttemptIndex].StatusCode {
			return errors.New("HTTP redirect does not bind to a recorded attempt")
		}
		if redirect.Outcome == "followed" {
			from, fromOK := httpEvidenceURL(redirect.FromURL)
			to, toOK := httpEvidenceURL(redirect.ToURL)
			if !fromOK || !toOK || origin(from) != origin(to) {
				return errors.New("HTTP followed redirect changed origin")
			}
			if !sameHTTPEntry(current, redirect.FromURL) {
				return errors.New("HTTP redirect chain does not continue its input")
			}
			current = redirect.ToURL
		}
	}
	if !sameHTTPEntry(current, probe.Response.URL) {
		// An implicit endpoint can confirm the alternate protocol on the same
		// port. A redirect, however, must always stay on its source origin.
		final, _ := httpEvidenceURL(probe.Response.URL)
		before, _ := httpEvidenceURL(current)
		if endpoint.URL != "" || final.EscapedPath() != before.EscapedPath() || final.RawQuery != before.RawQuery {
			return errors.New("HTTP final response is not bound to its input/redirect chain")
		}
	}
	final, _ := httpEvidenceURL(probe.Response.URL)
	for _, supplement := range envelope.Supplements {
		u, valid := httpEvidenceURL(supplement.URL)
		if !valid || origin(u) != origin(final) {
			return errors.New("HTTP supplement is outside primary origin")
		}
		if supplement.Response != nil && (!sameHTTPEntry(supplement.URL, supplement.Response.URL) ||
			canonicalTarget(supplement.Response.ConnectIP) != canonicalTarget(probe.Response.ConnectIP)) {
			return errors.New("HTTP supplement response changed its entry or connect IP")
		}
	}
	return nil
}
