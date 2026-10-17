// fingerprint-worker is a persistent, passive-only fingers SDK process.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"

	fingers "github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/logs"
	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/webevidence"
)

var engines = []string{fingers.FingersEngine, fingers.FingerPrintEngine, fingers.EHoleEngine}

func bundleID() string {
	hash := sha256.New()
	for _, data := range [][]byte{resources.FingersHTTPData, resources.FingerprinthubWebData, resources.EholeData, resources.AliasesData} {
		hash.Write(data)
		hash.Write([]byte{0})
	}
	hash.Write([]byte("e870395e8984/passive-detail-v1"))
	return hex.EncodeToString(hash.Sum(nil))
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--bundle" {
		fmt.Println(bundleID())
		return
	}
	// Upstream progress logs must not corrupt the JSONL protocol.
	output := os.Stdout
	os.Stdout = os.Stderr
	logs.Log.SetOutput(os.Stderr)
	// Per-record SDK preflight is intentionally quiet. Rejections are retained
	// in Package.Validation; real CLI failures still use bundleFatal's stderr.
	if (len(os.Args) == 2 && os.Args[1] == "--prepare-bundle") || (len(os.Args) == 3 && os.Args[1] == "--check-bundle") {
		logs.Log.SetOutput(io.Discard)
	}
	if len(os.Args) == 2 && os.Args[1] == "--capabilities" {
		if err := json.NewEncoder(output).Encode(fb.CurrentCapabilities()); err != nil {
			bundleFatal(err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--prepare-bundle" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, fb.MaxInputBytes+1))
		if err != nil {
			bundleFatal(err)
		}
		if len(data) > fb.MaxInputBytes {
			bundleFatal(fmt.Errorf("bundle input exceeds limit"))
		}
		var input fb.RawInput
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&input); err != nil {
			bundleFatal(err)
		}
		var extra any
		if err = decoder.Decode(&extra); err != io.EOF {
			bundleFatal(fmt.Errorf("bundle input must contain one JSON value"))
		}
		p, err := prepareBundle(input)
		if err != nil {
			bundleFatal(err)
		}
		if _, err = loadSnapshotEngine(p); err != nil {
			bundleFatal(err)
		}
		encoded, err := fb.Encode(p)
		if err != nil {
			bundleFatal(err)
		}
		if _, err = output.Write(encoded); err != nil {
			bundleFatal(err)
		}
		return
	}
	bundle := bundleID()
	rootOnly := false
	var snapshot *fb.Package
	if len(os.Args) == 3 && (os.Args[1] == "--bundle-file" || os.Args[1] == "--check-bundle") {
		p, data, err := readBundle(os.Args[2])
		if err != nil {
			bundleFatal(err)
		}
		snapshot = &p
		bundle = fb.Digest(data)
		rootOnly = true
	} else if len(os.Args) != 1 {
		bundleFatal(fmt.Errorf("unsupported helper arguments"))
	}
	var engine *fingers.Engine
	var err error
	if snapshot != nil {
		engine, err = loadSnapshotEngine(*snapshot)
	} else {
		engine, err = fingers.NewEngine(engines...)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	engine.EnableMatchDetail()
	if snapshot == nil && bundle != webevidence.FingerprintBundle {
		fmt.Fprintln(os.Stderr, "embedded fingerprint bundle differs from protocol snapshot")
		os.Exit(1)
	}
	if snapshot != nil && os.Args[1] == "--check-bundle" {
		capabilities := fb.CurrentCapabilities()
		capabilities.Bundle = bundle
		capabilities.Validation = snapshot.Validation
		if err = json.NewEncoder(output).Encode(capabilities); err != nil {
			bundleFatal(err)
		}
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), webevidence.MaxMessage)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		var input webevidence.MatchRequest
		result := webevidence.MatchResult{Protocol: webevidence.Protocol, Bundle: bundle}
		if err := json.Unmarshal(scanner.Bytes(), &input); err != nil {
			result.Error = err.Error()
		} else {
			result.ID = input.ID
			if input.Protocol != webevidence.Protocol {
				result.Error = "unsupported IPC protocol"
			} else if (rootOnly && input.ExpectedBundle != bundle) || (input.ExpectedBundle != "" && input.ExpectedBundle != bundle) {
				result.Error = "fingerprint bundle mismatch"
			} else {
				result.Matches, err = matchSnapshot(engine, input, rootOnly)
				if err != nil {
					result.Error = err.Error()
				}
			}
		}
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func bundleFatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func match(engine *fingers.Engine, input webevidence.MatchRequest) ([]webevidence.Match, error) {
	return matchSnapshot(engine, input, false)
}
func matchSnapshot(engine *fingers.Engine, input webevidence.MatchRequest, rootOnly bool) ([]webevidence.Match, error) {
	if input.Response.BodyStorage == "hash_only" || (input.Response.BodySHA256 != "" && input.Response.BodySHA256 != webevidence.SHA256(input.Response.Body)) {
		return nil, fmt.Errorf("full matching evidence is unavailable")
	}
	if len(input.Response.Body) > webevidence.MaxBody || len(input.Icons) > 2 {
		return nil, fmt.Errorf("evidence exceeds profile")
	}
	// The SDK's generic results cannot distinguish negative/hash rules over a
	// prefix. Preserve partial evidence, but do not turn it into product claims.
	if input.Response.Completeness != "full" || input.Response.StatusCode == 0 {
		return nil, nil
	}
	var output []webevidence.Match
	appendMatches := func(name string, frames common.Frameworks) {
		keys := make([]string, 0, len(frames))
		for key := range frames {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			frame := frames[key]
			detail, _ := json.Marshal(frame)
			version := ""
			if frame.Attributes != nil {
				version = frame.Version
			}
			output = append(output, webevidence.Match{Name: frame.Name, Version: version, Engine: name, Evidence: detail})
		}
	}
	for _, name := range engines {
		if rootOnly && name == fingers.FingerPrintEngine {
			u, err := url.Parse(input.Response.URL)
			if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || (u.RawPath != "" && u.RawPath != "/") || u.RawQuery != "" || u.ForceQuery {
				continue
			}
		}
		for _, other := range engines {
			engine.Disable(other)
		}
		engine.Enable(name)
		response := &http.Response{StatusCode: input.Response.StatusCode, Status: fmt.Sprintf("%d %s", input.Response.StatusCode, http.StatusText(input.Response.StatusCode)), Proto: input.Response.Proto, ProtoMajor: 1, ProtoMinor: 1, Header: input.Response.Headers.Clone(), Body: io.NopCloser(bytes.NewReader(input.Response.Body)), ContentLength: int64(len(input.Response.Body))}
		// The envelope body is decoded; do not label it as a compressed wire body.
		response.Header.Del("Content-Encoding")
		response.Header.Del("Transfer-Encoding")
		response.Header.Del("Content-Length")
		if input.Response.TLS != nil && input.Response.TLS.Source == "same_http_connection" {
			state := &tls.ConnectionState{Version: input.Response.TLS.Version, ServerName: input.Response.TLS.ServerName}
			for _, der := range input.Response.TLS.PeerCertificates {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("invalid TLS evidence: %w", err)
				}
				state.PeerCertificates = append(state.PeerCertificates, cert)
			}
			response.TLS = state
		}
		appendMatches(name, engine.WebMatch(response))
	}
	for _, icon := range input.Icons {
		if icon.BodyStorage == "hash_only" || (icon.BodySHA256 != "" && icon.BodySHA256 != webevidence.SHA256(icon.Body)) {
			continue
		}
		if len(icon.Body) > webevidence.MaxIcon {
			return nil, fmt.Errorf("icon exceeds profile")
		}
		if icon.Completeness == "full" && icon.StatusCode >= 200 && icon.StatusCode < 300 {
			appendMatches(fingers.FaviconEngine, engine.MatchFavicon(icon.Body))
		}
	}
	return output, nil
}
