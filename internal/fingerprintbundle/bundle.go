// Package fingerprintbundle defines passive rule snapshots without scanner SDK dependencies.
package fingerprintbundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

const (
	Schema               = "shen-fingerprint-bundle-v1"
	EngineRevision       = "e870395e898422e43e271ec08f47ff2ccb4003ee"
	SelectionProfile     = "passive-subset-v1"
	Repository           = "https://github.com/chainreactors/fingers"
	EmbeddedBundle       = "b5946286a877ff75a1c7b9914e9c3e4b0aba4e15287ee1cf594eef6db8e18538"
	MaxInputBytes        = 48 << 20
	MaxPackageBytes      = 96 << 20
	MaxRawFileBytes      = 8 << 20
	MaxDecodedFileBytes  = 16 << 20
	MaxDecodedTotalBytes = 32 << 20
	MaxAliasBytes        = 1 << 20
	MaxRecords           = 100000
)

func Paths() []string {
	return []string{"resources/aliases.yaml", "resources/ehole.json.gz", "resources/fingerprinthub_web.json.gz", "resources/fingers_http.json.gz"}
}

type RawInput struct {
	SourceRevision string            `json:"source_revision"`
	Files          map[string][]byte `json:"files"`
}
type Source struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
}
type File struct {
	Raw             []byte `json:"raw"`
	RawSHA256       string `json:"raw_sha256"`
	DecodedSHA256   string `json:"decoded_sha256"`
	DecodedBytes    int    `json:"decoded_bytes"`
	Effective       []byte `json:"effective"`
	EffectiveSHA256 string `json:"effective_sha256"`
}
type Rejection struct {
	Index  int    `json:"index"`
	ID     string `json:"id"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}
type Stats struct {
	Total               int            `json:"total"`
	Loaded              int            `json:"loaded"`
	ExcludedActive      int            `json:"excluded_active"`
	ExcludedUnsupported int            `json:"excluded_unsupported"`
	CompileFailed       int            `json:"compile_failed"`
	Reasons             map[string]int `json:"reasons"`
	Rejections          []Rejection    `json:"rejections"`
}
type Package struct {
	Schema           string           `json:"schema"`
	EngineRevision   string           `json:"engine_revision"`
	SelectionProfile string           `json:"selection_profile"`
	Source           Source           `json:"source"`
	Files            map[string]File  `json:"files"`
	Validation       map[string]Stats `json:"validation"`
}
type Capabilities struct {
	Schema           string           `json:"schema"`
	EngineRevision   string           `json:"engine_revision"`
	SelectionProfile string           `json:"selection_profile"`
	EmbeddedBundle   string           `json:"embedded_bundle"`
	Bundle           string           `json:"bundle,omitempty"`
	Validation       map[string]Stats `json:"validation,omitempty"`
}

func CurrentCapabilities() Capabilities {
	return Capabilities{Schema: Schema, EngineRevision: EngineRevision, SelectionProfile: SelectionProfile, EmbeddedBundle: EmbeddedBundle}
}
func Digest(data []byte) string { v := sha256.Sum256(data); return hex.EncodeToString(v[:]) }

func DecodeRaw(path string, raw []byte) ([]byte, error) {
	allowed := false
	for _, p := range Paths() {
		if path == p {
			allowed = true
		}
	}
	if !allowed || len(raw) == 0 || len(raw) > MaxRawFileBytes {
		return nil, fmt.Errorf("invalid resource path or raw size: %s", path)
	}
	if path == "resources/aliases.yaml" {
		if len(raw) > MaxAliasBytes {
			return nil, fmt.Errorf("alias resource exceeds limit")
		}
		return append([]byte(nil), raw...), nil
	}
	stream := bytes.NewReader(raw)
	z, err := gzip.NewReader(stream)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer z.Close()
	z.Multistream(false)
	decoded, err := io.ReadAll(io.LimitReader(z, MaxDecodedFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(decoded) > MaxDecodedFileBytes || stream.Len() != 0 {
		return nil, fmt.Errorf("%s: decoded limit or trailing gzip content", path)
	}
	return decoded, nil
}

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func Validate(p Package) error {
	if p.Schema != Schema || p.EngineRevision != EngineRevision || p.SelectionProfile != SelectionProfile || p.Source.Repository != Repository || !revisionPattern.MatchString(p.Source.Revision) {
		return fmt.Errorf("unsupported fingerprint package identity")
	}
	if len(p.Files) != 4 || len(p.Validation) != 4 {
		return fmt.Errorf("package requires four resources and four validation records")
	}
	total, effectiveTotal := 0, 0
	for _, path := range Paths() {
		f, ok := p.Files[path]
		if !ok {
			return fmt.Errorf("missing resource %s", path)
		}
		decoded, err := DecodeRaw(path, f.Raw)
		if err != nil {
			return err
		}
		total += len(decoded)
		effectiveTotal += len(f.Effective)
		limit := MaxDecodedFileBytes
		if path == "resources/aliases.yaml" {
			limit = MaxAliasBytes
		}
		if f.RawSHA256 != Digest(f.Raw) || f.DecodedSHA256 != Digest(decoded) || f.DecodedBytes != len(decoded) || f.EffectiveSHA256 != Digest(f.Effective) || len(f.Effective) == 0 || len(f.Effective) > limit {
			return fmt.Errorf("resource digest/size mismatch: %s", path)
		}
	}
	if total > MaxDecodedTotalBytes || effectiveTotal > MaxDecodedTotalBytes {
		return fmt.Errorf("package decoded/effective resources exceed total limit")
	}
	for _, key := range []string{"fingers", "fingerprinthub", "ehole", "aliases"} {
		s, ok := p.Validation[key]
		if !ok || s.Total < 0 || s.Total > MaxRecords || s.Loaded < 0 || s.ExcludedActive < 0 || s.ExcludedUnsupported < 0 || s.CompileFailed < 0 || s.Total != s.Loaded+s.ExcludedActive+s.ExcludedUnsupported+s.CompileFailed {
			return fmt.Errorf("invalid validation totals: %s", key)
		}
		counts := map[string]int{}
		for _, r := range s.Rejections {
			if r.Index < 0 || r.Index >= s.Total || r.Reason == "" {
				return fmt.Errorf("invalid rejection: %s", key)
			}
			counts[r.Reason]++
		}
		if len(s.Rejections) != s.Total-s.Loaded || len(counts) != len(s.Reasons) {
			return fmt.Errorf("invalid rejection count: %s", key)
		}
		for reason, n := range s.Reasons {
			if n <= 0 || counts[reason] != n {
				return fmt.Errorf("invalid rejection reason: %s", key)
			}
		}
	}
	return nil
}
func Encode(p Package) ([]byte, error) {
	if err := Validate(p); err != nil {
		return nil, err
	}
	data, err := json.Marshal(p)
	if len(data) > MaxPackageBytes {
		return nil, fmt.Errorf("package exceeds byte limit")
	}
	return data, err
}
func Decode(data []byte) (Package, error) {
	var p Package
	if len(data) == 0 || len(data) > MaxPackageBytes {
		return p, fmt.Errorf("package exceeds byte limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	canonical, err := Encode(p)
	if err != nil {
		return p, err
	}
	if !bytes.Equal(data, canonical) {
		return p, fmt.Errorf("package JSON must be canonical without trailing bytes")
	}
	return p, nil
}
