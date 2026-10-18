package main

import (
	"encoding/json"
	"fmt"

	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	native "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/goby"
	fb "scanplatform/internal/fingerprintbundle"
)

// prepareBundle retains every HTTP record. A failed record rejects the update;
// the caller continues using its already installed bundle.
func prepareBundle(input fb.RawInput) (p fb.Package, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("HTTP resource compile failed: %v", v)
		}
	}()
	p = fb.Package{Schema: fb.Schema, EngineRevision: fb.EngineRevision, SelectionProfile: fb.SelectionProfile, Source: fb.Source{Repository: fb.Repository, Revision: input.SourceRevision}, Files: map[string]fb.File{}, Validation: map[string]fb.Stats{}}
	if len(input.Files) != len(fb.Paths()) {
		return p, fmt.Errorf("all %d HTTP resources are required", len(fb.Paths()))
	}
	total := 0
	for _, path := range fb.Paths() {
		decoded, err := fb.DecodeRaw(path, input.Files[path])
		if err != nil {
			return p, err
		}
		total += len(decoded)
		if total > fb.MaxDecodedTotalBytes {
			return p, fmt.Errorf("decoded resources exceed total limit")
		}
		key := ""
		count := 0
		effective := decoded
		switch path {
		case "resources/fingers_http.json.gz":
			key = "fingers"
			var records native.Fingers
			if err = json.Unmarshal(decoded, &records); err != nil {
				return p, err
			}
			for i, f := range records {
				if f == nil || f.Name == "" || len(f.Rules) == 0 || (f.Protocol != "" && f.Protocol != "http") {
					return p, fmt.Errorf("native HTTP record %d invalid", i)
				}
				for _, r := range f.Rules {
					if r == nil {
						return p, fmt.Errorf("native HTTP record %d has null rule", i)
					}
				}
				if err = f.Compile(false); err != nil {
					return p, fmt.Errorf("native HTTP record %d %s: %w", i, f.Name, err)
				}
			}
			count = len(records)
		case "resources/fingerprinthub_web.json.gz":
			key = "fingerprinthub"
			var records []json.RawMessage
			if err = json.Unmarshal(decoded, &records); err != nil {
				return p, err
			}
			impl, e := fingerprinthub.NewFingerPrintHubEngine(decoded, []byte("[]"))
			if e != nil {
				return p, e
			}
			count = impl.Len()
			if count != len(records) {
				return p, fmt.Errorf("FingerprintHub incomplete load: %d/%d", count, len(records))
			}
		case "resources/ehole.json.gz":
			key = "ehole"
			var wrapper struct {
				Fingerprint []json.RawMessage `json:"fingerprint"`
			}
			if err = json.Unmarshal(decoded, &wrapper); err != nil {
				return p, err
			}
			for i, r := range wrapper.Fingerprint {
				var f ehole.Fingerprint
				if err = json.Unmarshal(r, &f); err != nil {
					return p, err
				}
				if f.Cms == "" || len(f.Keyword) == 0 {
					return p, fmt.Errorf("EHole record %d invalid", i)
				}
				if f.Method != "keyword" && f.Method != "regular" && f.Method != "faviconhash" {
					return p, fmt.Errorf("EHole %s unknown method", f.Cms)
				}
				if f.Method != "faviconhash" && f.Location != "body" && f.Location != "header" && f.Location != "title" {
					return p, fmt.Errorf("EHole %s unknown location", f.Cms)
				}
			}
			impl, e := ehole.NewEHoleEngine(decoded)
			if e != nil {
				return p, e
			}
			count = impl.Len()
		case "resources/goby.json.gz":
			key = "goby"
			impl, e := goby.NewGobyEngine(decoded)
			if e != nil {
				return p, e
			}
			count = impl.Len()
		case "resources/aliases.yaml":
			key = "aliases"
			var stats fb.Stats
			effective, stats, err = filterAliases(decoded)
			if err != nil {
				return p, err
			}
			if stats.Loaded != stats.Total {
				return p, fmt.Errorf("alias validation rejected records: %+v", stats.Rejections)
			}
			count = stats.Loaded
		}
		if count > fb.MaxRecords {
			return p, fmt.Errorf("%s exceeds record limit", key)
		}
		p.Files[path] = fb.File{Raw: input.Files[path], RawSHA256: fb.Digest(input.Files[path]), DecodedSHA256: fb.Digest(decoded), DecodedBytes: len(decoded), Effective: effective, EffectiveSHA256: fb.Digest(effective)}
		p.Validation[key] = fb.Stats{Total: count, Loaded: count, Reasons: map[string]int{}, Rejections: []fb.Rejection{}}
	}
	return p, fb.Validate(p)
}
