package rulesource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testArchive(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	for name, value := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(value)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestRetryTransportRetriesNetworkErrorsOnly(t *testing.T) {
	var networkAttempts, statusAttempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/network":
			if networkAttempts.Add(1) < 3 {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				connection.Close()
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/status":
			statusAttempts.Add(1)
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	base := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: &retryTransport{base: base, attempts: 3, backoff: time.Millisecond}, Timeout: 2 * time.Second}
	response, err := client.Get(server.URL + "/network")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || networkAttempts.Load() != 3 {
		t.Fatalf("network status/attempts=%d/%d", response.StatusCode, networkAttempts.Load())
	}
	response, err = client.Get(server.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || statusAttempts.Load() != 1 {
		t.Fatalf("HTTP status/attempts=%d/%d", response.StatusCode, statusAttempts.Load())
	}
}

func TestUnpackArchivePathFence(t *testing.T) {
	data := testArchive(t, map[string]string{"repo-sha/LICENSE.md": "MIT", "repo-sha/data/file.json": "{}"})
	files, err := unpackArchive(data)
	if err != nil || string(files["data/file.json"]) != "{}" || digestArchiveFiles(files) == "" {
		t.Fatalf("unpack=%v err=%v", files, err)
	}
	unsafe := testArchive(t, map[string]string{"repo-sha/../escape": "bad"})
	if _, err := unpackArchive(unsafe); err == nil {
		t.Fatal("archive traversal was accepted")
	}
}
