package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	fingers "github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/alias"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	native "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/neutron/operators"
	"gopkg.in/yaml.v3"
	fb "scanplatform/internal/fingerprintbundle"
)

func prepareLegacyBundle(input fb.RawInput) (fb.Package, error) {
	p := fb.Package{Schema: fb.LegacySchema, EngineRevision: fb.EngineRevision, SelectionProfile: fb.LegacySelectionProfile, Source: fb.Source{Repository: fb.Repository, Revision: input.SourceRevision}, Files: map[string]fb.File{}, Validation: map[string]fb.Stats{}}
	if len(input.Files) != 4 {
		return p, fmt.Errorf("exactly four allowed resources are required")
	}
	decoded := map[string][]byte{}
	total := 0
	for _, path := range fb.LegacyPaths() {
		data, err := fb.DecodeRaw(path, input.Files[path])
		if err != nil {
			return p, err
		}
		total += len(data)
		if total > fb.MaxDecodedTotalBytes {
			return p, fmt.Errorf("decoded resources exceed total limit")
		}
		decoded[path] = data
	}
	for _, path := range fb.LegacyPaths() {
		key := ""
		var data []byte
		var stats fb.Stats
		var err error
		switch path {
		case "resources/fingers_http.json.gz":
			key = "fingers"
			data, stats, err = filterJSON(decoded[path], false, checkNative)
		case "resources/fingerprinthub_web.json.gz":
			key = "fingerprinthub"
			data, stats, err = filterJSON(decoded[path], false, checkHub)
		case "resources/ehole.json.gz":
			key = "ehole"
			data, stats, err = filterJSON(decoded[path], true, checkEHole)
		case "resources/aliases.yaml":
			key = "aliases"
			data, stats, err = filterAliases(decoded[path])
		}
		if err != nil {
			return p, fmt.Errorf("%s: %w", path, err)
		}
		p.Files[path] = fb.File{Raw: input.Files[path], RawSHA256: fb.Digest(input.Files[path]), DecodedSHA256: fb.Digest(decoded[path]), DecodedBytes: len(decoded[path]), Effective: data, EffectiveSHA256: fb.Digest(data)}
		p.Validation[key] = stats
	}
	return p, fb.Validate(p)
}

type recordCheck func(json.RawMessage) (id, category, detail string)

func filterJSON(data []byte, wrapped bool, check recordCheck) ([]byte, fb.Stats, error) {
	s := fb.Stats{Reasons: map[string]int{}, Rejections: []fb.Rejection{}}
	var records []json.RawMessage
	if wrapped {
		var v struct {
			Fingerprint []json.RawMessage `json:"fingerprint"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, s, err
		}
		records = v.Fingerprint
	} else if err := json.Unmarshal(data, &records); err != nil {
		return nil, s, err
	}
	if len(records) > fb.MaxRecords || records == nil {
		return nil, s, fmt.Errorf("invalid record collection")
	}
	s.Total = len(records)
	accepted := make([]json.RawMessage, 0, len(records))
	for i, r := range records {
		id, category, detail := safeCheck(check, r)
		if category == "" {
			s.Loaded++
			accepted = append(accepted, r)
		} else {
			reject(&s, i, id, category, detail)
		}
	}
	var effective []byte
	var err error
	if wrapped {
		effective, err = json.Marshal(struct {
			Fingerprint []json.RawMessage `json:"fingerprint"`
		}{accepted})
	} else {
		effective, err = json.Marshal(accepted)
	}
	return effective, s, err
}
func reject(s *fb.Stats, index int, id, category, detail string) {
	switch category {
	case "active":
		s.ExcludedActive++
	case "compile":
		s.CompileFailed++
	default:
		s.ExcludedUnsupported++
	}
	s.Reasons[category]++
	s.Rejections = append(s.Rejections, fb.Rejection{Index: index, ID: id, Reason: category, Detail: detail})
}
func safeCheck(check recordCheck, r json.RawMessage) (id, category, detail string) {
	defer func() {
		if v := recover(); v != nil {
			category = "compile"
			detail = fmt.Sprintf("SDK rejected record: %v", v)
		}
	}()
	return check(r)
}
func checkNative(raw json.RawMessage) (string, string, string) {
	var f *native.Finger
	if err := json.Unmarshal(raw, &f); err != nil || f == nil {
		return "", "unsupported", "invalid native record"
	}
	if f.SendDataStr != "" || f.Level > 0 {
		return f.Name, "active", "finger requires active probing"
	}
	for _, r := range f.Rules {
		if r == nil {
			return f.Name, "unsupported", "null rule"
		}
		if r.SendDataStr != "" || r.Level > 0 {
			return f.Name, "active", "rule requires active probing"
		}
		if r.Regexps == nil {
			return f.Name, "unsupported", "rule has no passive regexps"
		}
	}
	if f.Name == "" || len(f.Rules) == 0 || (f.Protocol != "" && f.Protocol != "http") {
		return f.Name, "unsupported", "requires named HTTP passive rules"
	}
	if err := f.Compile(false); err != nil {
		return f.Name, "compile", err.Error()
	}
	return f.Name, "", ""
}
func checkEHole(raw json.RawMessage) (string, string, string) {
	var f *ehole.Fingerprint
	if err := json.Unmarshal(raw, &f); err != nil || f == nil {
		return "", "unsupported", "invalid EHole record"
	}
	if f.Cms == "" || len(f.Keyword) == 0 {
		return f.Cms, "unsupported", "empty product or match values"
	}
	if f.Method != "keyword" && f.Method != "regular" && f.Method != "faviconhash" {
		return f.Cms, "unsupported", "unknown match method"
	}
	if f.Method != "faviconhash" && f.Location != "body" && f.Location != "header" {
		return f.Cms, "unsupported", "only body/header locations are supported"
	}
	for _, v := range f.Keyword {
		if v == "" {
			return f.Cms, "unsupported", "empty match value"
		}
		if f.Method == "regular" {
			if _, err := regexp.Compile(strings.ToLower(v)); err != nil {
				return f.Cms, "compile", err.Error()
			}
		}
	}
	data, _ := json.Marshal(struct {
		Fingerprint []*ehole.Fingerprint `json:"fingerprint"`
	}{[]*ehole.Fingerprint{f}})
	if _, err := ehole.NewEHoleEngine(data); err != nil {
		return f.Cms, "compile", err.Error()
	}
	return f.Cms, "", ""
}
func onlyKeys(v map[string]json.RawMessage, keys ...string) bool {
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for k := range v {
		if !allowed[k] {
			return false
		}
	}
	return true
}
func checkHub(raw json.RawMessage) (string, string, string) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return "", "unsupported", "invalid FingerprintHub record"
	}
	var id string
	_ = json.Unmarshal(top["id"], &id)
	if id == "" || !onlyKeys(top, "id", "info", "http", "requests", "_source_file") {
		return id, "unsupported", "unsupported template fields or empty id"
	}
	if top["http"] != nil && top["requests"] != nil {
		return id, "unsupported", "ambiguous request collections"
	}
	requests := top["http"]
	if requests == nil {
		requests = top["requests"]
	}
	var rs []map[string]json.RawMessage
	if json.Unmarshal(requests, &rs) != nil || len(rs) != 1 || rs[0] == nil {
		return id, "active", "requires exactly one root GET request"
	}
	r := rs[0]
	var method string
	var paths []string
	_ = json.Unmarshal(r["method"], &method)
	_ = json.Unmarshal(r["path"], &paths)
	if method != "GET" || len(paths) != 1 || paths[0] != "{{BaseURL}}/" {
		return id, "active", "request method/path is outside passive root profile"
	}
	if !onlyKeys(r, "method", "path", "matchers", "matchers-condition") {
		return id, "unsupported", "request requires unsupported headers/body/extractors/options"
	}
	var matchers []map[string]json.RawMessage
	if json.Unmarshal(r["matchers"], &matchers) != nil || len(matchers) == 0 {
		return id, "unsupported", "missing matchers"
	}
	for _, m := range matchers {
		if m == nil || !onlyKeys(m, "type", "condition", "part", "negative", "name", "words", "regex", "status", "case-insensitive") {
			return id, "unsupported", "unsupported matcher fields"
		}
		var kind, part, condition string
		var negative bool
		_ = json.Unmarshal(m["type"], &kind)
		_ = json.Unmarshal(m["part"], &part)
		_ = json.Unmarshal(m["condition"], &condition)
		_ = json.Unmarshal(m["negative"], &negative)
		if negative || (kind != "word" && kind != "regex" && kind != "status") || (part != "" && part != "body" && part != "header" && part != "all_headers" && part != "status_code") || (condition != "" && condition != "and" && condition != "or") {
			return id, "unsupported", "unsupported matcher semantics"
		}
		field := "words"
		if kind == "regex" {
			field = "regex"
		}
		if kind == "status" {
			field = "status"
		}
		var values []json.RawMessage
		if json.Unmarshal(m[field], &values) != nil || len(values) == 0 {
			return id, "unsupported", "empty matcher values"
		}
	}
	var condition string
	if v := r["matchers-condition"]; v != nil {
		if json.Unmarshal(v, &condition) != nil || (condition != "" && condition != "and" && condition != "or") {
			return id, "unsupported", "invalid matcher condition"
		}
	}
	// The public compiler provides exact per-record errors which the SDK loader hides.
	data, _ := json.Marshal(r)
	var ops operators.Operators
	if err := json.Unmarshal(data, &ops); err != nil {
		return id, "unsupported", err.Error()
	}
	if err := ops.Compile(); err != nil {
		return id, "compile", err.Error()
	}
	single, _ := json.Marshal([]json.RawMessage{raw})
	impl, err := fingerprinthub.NewFingerPrintHubEngine(single, []byte("[]"))
	if err != nil {
		return id, "compile", err.Error()
	}
	if impl.Len() != 1 {
		return id, "compile", "SDK did not load the passive record"
	}
	return id, "", ""
}
func filterAliases(data []byte) ([]byte, fb.Stats, error) {
	s := fb.Stats{Reasons: map[string]int{}, Rejections: []fb.Rejection{}}
	var entries []*alias.Alias
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&entries); err != nil {
		return nil, s, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, s, fmt.Errorf("alias requires exactly one YAML document")
	}
	if entries == nil || len(entries) > fb.MaxRecords {
		return nil, s, fmt.Errorf("invalid alias collection")
	}
	s.Total = len(entries)
	accepted := make([]*alias.Alias, 0, len(entries))
	seen := map[string]bool{}
	for i, a := range entries {
		id := ""
		if a != nil {
			id = a.Name
		}
		invalid := a == nil || id == "" || len(a.AliasMap) == 0 || seen[strings.ToLower(id)]
		if a != nil {
			for _, names := range a.AliasMap {
				for _, name := range names {
					if name == "" {
						invalid = true
					}
				}
			}
		}
		if invalid {
			reject(&s, i, id, "unsupported", "invalid or duplicate alias")
			continue
		}
		seen[strings.ToLower(id)] = true
		accepted = append(accepted, a)
		s.Loaded++
	}
	// JSON is a YAML subset and avoids nondeterministic YAML map ordering.
	effective, err := json.Marshal(accepted)
	return effective, s, err
}

func readBundle(path string) (fb.Package, []byte, error) {
	var empty fb.Package
	f, err := os.Open(path)
	if err != nil {
		return empty, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, fb.MaxPackageBytes+1))
	if err != nil {
		return empty, nil, err
	}
	p, err := fb.Decode(data)
	if err != nil {
		return p, nil, err
	}
	// Recompute effective records and statistics from raw bytes, never trust caller claims.
	files := map[string][]byte{}
	for k, v := range p.Files {
		files[k] = v.Raw
	}
	prepare := prepareBundle
	if p.Legacy() {
		prepare = prepareLegacyBundle
	}
	regenerated, err := prepare(fb.RawInput{SourceRevision: p.Source.Revision, Files: files})
	if err != nil {
		return p, nil, err
	}
	want, err := fb.Encode(regenerated)
	if err != nil {
		return p, nil, err
	}
	if !bytes.Equal(data, want) {
		return p, nil, fmt.Errorf("effective resources or validation differ from fixed SDK preparation")
	}
	return p, data, nil
}

func installResources(p fb.Package) {
	resources.FingersHTTPData = p.Files["resources/fingers_http.json.gz"].Effective
	resources.FingerprinthubWebData = p.Files["resources/fingerprinthub_web.json.gz"].Effective
	resources.EholeData = p.Files["resources/ehole.json.gz"].Effective
	resources.AliasesData = p.Files["resources/aliases.yaml"].Effective
	if !p.Legacy() {
		resources.GobyData = p.Files["resources/goby.json.gz"].Effective
	}
	resources.FingersSocketData = []byte("[]")
	resources.FingerprinthubServiceData = []byte("[]")
	resources.PortData = []byte("[]")
}

func loadSnapshotEngine(p fb.Package) (*fingers.Engine, error) {
	installResources(p)
	names := engines
	if p.Legacy() {
		names = legacyEngines
	}
	engine, err := fingers.NewEngine(names...)
	if err != nil {
		return nil, err
	}
	if len(engine.Fingers().HTTPFingers) != p.Validation["fingers"].Loaded || engine.FingerPrintHub().Len() != p.Validation["fingerprinthub"].Loaded || engine.EHole().Len() != p.Validation["ehole"].Loaded {
		return nil, fmt.Errorf("SDK loaded counts differ from package validation")
	}
	if !p.Legacy() && engine.Goby().Len() != p.Validation["goby"].Loaded {
		return nil, fmt.Errorf("Goby loaded count differs from package validation")
	}
	engine.EnableMatchDetail()
	return engine, nil
}
