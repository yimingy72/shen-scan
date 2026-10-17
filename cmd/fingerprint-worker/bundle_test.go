package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainreactors/fingers/resources"
	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/webevidence"
)

func snapshotFixture(t *testing.T, aliasName string) fb.RawInput {
	t.Helper()
	gzipData := func(s string) []byte {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		if _, err := z.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	return fb.RawInput{SourceRevision: fb.EngineRevision, Files: map[string][]byte{
		"resources/fingers_http.json.gz":       gzipData(`[{"name":"fixture-native","rule":[{"regexps":{"body":["snapshot-token"]}}]},{"name":"active","rule":[{"send_data":"/admin","regexps":{"body":["snapshot-token"]}}]},{"name":"broken","rule":[{"regexps":{"regexp":["("]}}]}]`),
		"resources/fingerprinthub_web.json.gz": gzipData(`[{"id":"fixture-hub","info":{"name":"fixture-hub"},"http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers":[{"type":"word","words":["snapshot-token"]}]}]},{"id":"path-only","http":[{"method":"GET","path":["{{BaseURL}}/admin"],"matchers":[{"type":"word","words":["snapshot-token"]}]}]},{"id":"favicon-only","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers":[{"type":"favicon","hash":["123"]}]}]},{"id":"broken-hub","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers":[{"type":"regex","regex":["("]}]}]}]`),
		"resources/ehole.json.gz":              gzipData(`{"fingerprint":[{"cms":"fixture-ehole","method":"keyword","location":"body","keyword":["snapshot-token"]},{"cms":"broken","method":"regular","location":"body","keyword":["("]}]}`),
		"resources/aliases.yaml":               []byte(`[{"name":"` + aliasName + `","alias":{"fingers":["fixture-native"]}}]`),
	}}
}

func TestSnapshotIsolationAndRejectedEvidence(t *testing.T) {
	// Resources are process-global in the SDK; production changes them only in a new helper.
	a, b, c, d, e, f, g := resources.FingersHTTPData, resources.FingerprinthubWebData, resources.EholeData, resources.AliasesData, resources.FingersSocketData, resources.FingerprinthubServiceData, resources.PortData
	t.Cleanup(func() {
		resources.FingersHTTPData = a
		resources.FingerprinthubWebData = b
		resources.EholeData = c
		resources.AliasesData = d
		resources.FingersSocketData = e
		resources.FingerprinthubServiceData = f
		resources.PortData = g
	})
	if bundleID() != fb.EmbeddedBundle {
		t.Fatal("embedded bundle changed")
	}
	input := webevidence.MatchRequest{Response: webevidence.Response{URL: "http://fixture.invalid/", StatusCode: 200, Proto: "HTTP/1.1", Completeness: "full", Headers: http.Header{"Content-Type": []string{"text/html"}}, Body: []byte("snapshot-token")}}
	var digests []string
	for _, name := range []string{"snapshot-a", "snapshot-b"} {
		p, err := prepareBundle(snapshotFixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if s := p.Validation["fingers"]; s.Total != 3 || s.Loaded != 1 || s.ExcludedActive != 1 || s.CompileFailed != 1 {
			t.Fatalf("native classification: %+v", s)
		}
		if s := p.Validation["fingerprinthub"]; s.Total != 4 || s.Loaded != 1 || s.ExcludedActive != 1 || s.ExcludedUnsupported != 1 || s.CompileFailed != 1 {
			t.Fatalf("hub classification: %+v", s)
		}
		data, err := fb.Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, fb.Digest(data))
		path := filepath.Join(t.TempDir(), "bundle.json")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = readBundle(path); err != nil {
			t.Fatal(err)
		}
		engine, err := loadSnapshotEngine(p)
		if err != nil {
			t.Fatal(err)
		}
		matches, err := matchSnapshot(engine, input, true)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, m := range matches {
			seen[m.Name] = true
		}
		if !seen[name] || !seen["fixture-hub"] || !seen["fixture-ehole"] {
			t.Fatalf("snapshot or updated alias missing: %+v", matches)
		}
		nonroot := input
		nonroot.Response.URL = "http://fixture.invalid/admin"
		matches, err = matchSnapshot(engine, nonroot, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if m.Engine == "fingerprinthub" {
				t.Fatal("root-only rule matched non-root evidence")
			}
		}
		partial := input
		partial.Response.Completeness = "partial"
		if matches, err = matchSnapshot(engine, partial, true); err != nil || len(matches) != 0 {
			t.Fatal("partial evidence produced claims")
		}
		partial = input
		partial.Response.BodyStorage = "hash_only"
		if _, err = matchSnapshot(engine, partial, true); err == nil {
			t.Fatal("accepted hash-only evidence")
		}
		// Even internally consistent digests cannot substitute invented effective rules.
		file := p.Files["resources/fingers_http.json.gz"]
		file.Effective = []byte("[]")
		file.EffectiveSHA256 = fb.Digest(file.Effective)
		p.Files["resources/fingers_http.json.gz"] = file
		tampered, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, tampered, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = readBundle(path); err == nil {
			t.Fatal("accepted effective rules unrelated to raw data")
		}
	}
	if digests[0] == digests[1] {
		t.Fatal("different alias snapshots have identical identity")
	}
}
