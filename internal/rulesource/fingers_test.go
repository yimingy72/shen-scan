package rulesource

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"scanplatform/internal/fingerprintbundle"
)

type fingersFixtureTransport func(*http.Request) (*http.Response, error)

func (transport fingersFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return transport(r)
}

func TestFingersDownloaderUsesOnlyPinnedDataPaths(t *testing.T) {
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, _ = z.Write([]byte("[]"))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("a", 40)
	wanted := map[string]bool{}
	for _, path := range fingerprintbundle.Paths() {
		wanted["https://api.github.com/repos/chainreactors/fingers/contents/"+path+"?ref="+revision] = true
	}
	count, fail, tooLarge := 0, false, false
	client := &http.Client{Transport: fingersFixtureTransport(func(r *http.Request) (*http.Response, error) {
		if !wanted[r.URL.String()] || r.Method != http.MethodGet || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		count++
		data := compressed.Bytes()
		if strings.HasSuffix(r.URL.Path, "aliases.yaml") {
			data = []byte("[]")
		}
		status := 200
		if fail {
			status = 404
		}
		hash := sha1.New()
		fmt.Fprintf(hash, "blob %d\x00", len(data))
		hash.Write(data)
		payload, _ := json.Marshal(map[string]any{"type": "file", "path": strings.TrimPrefix(r.URL.Path, "/repos/chainreactors/fingers/contents/"), "size": len(data), "encoding": "base64", "sha": hex.EncodeToString(hash.Sum(nil)), "content": base64.StdEncoding.EncodeToString(data) + "\n"})
		if tooLarge {
			payload = bytes.Repeat([]byte(" "), maxFingersAPIResponse+1)
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(bytes.NewReader(payload)), Header: http.Header{}}, nil
	})}
	input, err := fetchFingersRevision(context.Background(), revision, client)
	if err != nil || count != len(fingerprintbundle.Paths()) || len(input.Files) != len(fingerprintbundle.Paths()) || input.SourceRevision != revision {
		t.Fatalf("download did not preserve fixed resources: %v, %d", err, count)
	}
	if !bytes.Equal(input.Files["resources/fingers_http.json.gz"], compressed.Bytes()) {
		t.Fatal("raw file was altered")
	}
	for _, invalid := range []string{"HEAD", strings.Repeat("A", 40), "https://other.invalid/"} {
		if _, err = fetchFingersRevision(context.Background(), invalid, client); err == nil {
			t.Fatalf("accepted revision %q", invalid)
		}
	}
	if count != len(fingerprintbundle.Paths()) {
		t.Fatal("invalid revision performed a download")
	}
	fail = true
	if _, err = fetchFingersRevision(context.Background(), revision, client); err == nil {
		t.Fatal("accepted missing resource")
	}
	fail, tooLarge = false, true
	if _, err = fetchFingersRevision(context.Background(), revision, client); err == nil {
		t.Fatal("accepted oversized API response")
	}
	if _, err = FetchRevision(context.Background(), FingersID, revision); err == nil {
		t.Fatal("allowed data source to enter Rule conversion")
	}
}

func TestFingersContentsRejectsInvalidMetadataAndData(t *testing.T) {
	path := "resources/aliases.yaml"
	data := []byte("[]")
	hash := sha1.Sum(append([]byte("blob 2\x00"), data...))
	valid := map[string]any{"type": "file", "path": path, "size": len(data), "encoding": "base64", "sha": hex.EncodeToString(hash[:]), "content": base64.StdEncoding.EncodeToString(data)}
	for _, test := range []struct {
		key   string
		value any
	}{
		{"type", "symlink"}, {"path", "resources/other.yaml"}, {"encoding", "none"}, {"size", 0}, {"size", fingerprintbundle.MaxRawFileBytes + 1},
		{"size", 3}, {"sha", strings.Repeat("a", 40)}, {"content", "invalid!"}, {"content", base64.StdEncoding.EncodeToString([]byte("{}"))},
	} {
		copy := map[string]any{}
		for key, value := range valid {
			copy[key] = value
		}
		copy[test.key] = test.value
		payload, _ := json.Marshal(copy)
		if _, err := decodeFingersContents(path, payload); err == nil {
			t.Fatalf("accepted invalid %s=%v", test.key, test.value)
		}
	}
}
