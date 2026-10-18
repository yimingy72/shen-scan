package main

import (
	"fmt"
	"github.com/chainreactors/fingers/fingerprinthub"
	native "github.com/chainreactors/fingers/fingers"
	"os"
	fb "scanplatform/internal/fingerprintbundle"
	"testing"
)

func TestFullPublicHTTPBundle(t *testing.T) {
	input := fb.RawInput{SourceRevision: fb.EngineRevision, Files: map[string][]byte{}}
	for _, path := range fb.Paths() {
		data, err := os.ReadFile("third_party/fingers/" + path)
		if err != nil {
			t.Fatal(err)
		}
		input.Files[path] = data
	}
	p, err := prepareBundle(input)
	if err != nil {
		t.Fatal(err)
	}
	for key, s := range p.Validation {
		if s.Total != s.Loaded || len(s.Rejections) != 0 {
			t.Fatalf("%s excludes source records: %+v", key, s)
		}
		t.Logf("%s loaded %d/%d", key, s.Loaded, s.Total)
	}
	if p.Validation["fingers"].Total != 8727 || p.Validation["goby"].Total != 7085 {
		t.Fatal("public source records changed")
	}

	catalog, err := p.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 19948 {
		t.Fatalf("catalog omitted source records: %d", len(catalog))
	}
	keys := map[string]bool{}
	for _, r := range catalog {
		if keys[r.UnitKey] {
			t.Fatalf("catalog key collapsed source record: %+v", r)
		}
		keys[r.UnitKey] = true
		if r.LoadStatus != "loaded" || r.ContentHash == "" || r.OriginalReference == "" {
			t.Fatalf("incomplete metadata: %+v", r)
		}
	}
	fs, err := native.LoadFingers(p.Files["resources/fingers_http.json.gz"].Effective)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range fs {
		if !keys[fb.UnitKey("fingers", fmt.Sprintf("resources/fingers_http.json.gz#/%d", i), f.Name, f.SourceHash)] {
			t.Fatalf("native execution unit is not frozen in catalog: %s", f.Name)
		}
	}
	hub, err := fingerprinthub.NewFingerPrintHubEngine(p.Files["resources/fingerprinthub_web.json.gz"].Effective, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range hub.HTTPTemplates() {
		if !keys[u.ID] {
			t.Fatalf("template execution unit is not frozen in catalog: %s", u.ID)
		}
	}
	if manifest, err := p.ManifestHash(); err != nil || len(manifest) != 64 {
		t.Fatalf("manifest: %s %v", manifest, err)
	}
	if _, err = fb.Encode(p); err != nil {
		t.Fatal(err)
	}
}
