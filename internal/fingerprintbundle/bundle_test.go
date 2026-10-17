package fingerprintbundle

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestResourceBoundsAndCanonicalSnapshot(t *testing.T) {
	var zipped bytes.Buffer
	z := gzip.NewWriter(&zipped)
	_, _ = z.Write([]byte("[]"))
	_ = z.Close()
	p := Package{Schema: Schema, EngineRevision: EngineRevision, SelectionProfile: SelectionProfile, Source: Source{Repository: Repository, Revision: "e870395e898422e43e271ec08f47ff2ccb4003ee"}, Files: map[string]File{}, Validation: map[string]Stats{}}
	for _, path := range Paths() {
		raw := zipped.Bytes()
		if path == "resources/aliases.yaml" {
			raw = []byte("[]")
		}
		decoded, err := DecodeRaw(path, raw)
		if err != nil {
			t.Fatal(err)
		}
		p.Files[path] = File{Raw: raw, RawSHA256: Digest(raw), DecodedSHA256: Digest(decoded), DecodedBytes: len(decoded), Effective: []byte("[]"), EffectiveSHA256: Digest([]byte("[]"))}
	}
	for _, key := range []string{"fingers", "fingerprinthub", "ehole", "aliases"} {
		p.Validation[key] = Stats{Reasons: map[string]int{}, Rejections: []Rejection{}}
	}
	data, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(data); err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(append(data, '\n')); err == nil {
		t.Fatal("accepted alternate noncanonical package bytes")
	}
	f := p.Files["resources/aliases.yaml"]
	f.Effective = []byte("tampered")
	p.Files["resources/aliases.yaml"] = f
	if Validate(p) == nil {
		t.Fatal("accepted changed effective data with old digest")
	}
	if _, err = DecodeRaw("resources/../aliases.yaml", []byte("[]")); err == nil {
		t.Fatal("accepted unknown path")
	}
	if _, err = DecodeRaw("resources/aliases.yaml", make([]byte, MaxAliasBytes+1)); err == nil {
		t.Fatal("accepted oversized aliases")
	}
	if _, err = DecodeRaw("resources/fingers_http.json.gz", append(append([]byte(nil), zipped.Bytes()...), zipped.Bytes()...)); err == nil {
		t.Fatal("accepted concatenated gzip members")
	}
}
