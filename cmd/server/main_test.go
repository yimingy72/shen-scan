package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSPACompressedAssetsAndRevalidation(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	plain := []byte("console.log('workbench')")
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(plain)
	_ = writer.Close()
	for name, body := range map[string][]byte{"index.html": []byte("<html></html>"), "assets/index-hash.js": plain, "assets/index-hash.js.gz": compressed.Bytes()} {
		if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	handler := spaHandler(directory)
	for _, test := range []struct {
		encoding string
		gzip     bool
	}{{"gzip, br", true}, {"gzip;q=0, *;q=1", false}, {"*;q=0.5", true}, {"", false}} {
		request := httptest.NewRequest("GET", "/assets/index-hash.js", nil)
		request.Header.Set("Accept-Encoding", test.encoding)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		body := response.Body.Bytes()
		if got := response.Header().Get("Content-Encoding") == "gzip"; got != test.gzip {
			t.Fatalf("encoding %q: gzip=%v", test.encoding, got)
		}
		if test.gzip {
			reader, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(reader)
			_ = reader.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(body, plain) || response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || response.Header().Get("Vary") != "Accept-Encoding" {
			t.Fatalf("wrong asset response: %v", response.Header())
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/", nil))
	if response.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("entry HTML must revalidate after deployment")
	}
}

func TestDownloadHandlerServesOnlyVisibleRegularFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "agent.tar.gz"), []byte("package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := downloadHandler(directory)
	for _, test := range []struct {
		path string
		want int
	}{
		{"/downloads/agent.tar.gz", http.StatusOK},
		{"/downloads/.env", http.StatusNotFound},
		{"/downloads/", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.want {
			t.Errorf("GET %s: got %d, want %d", test.path, response.Code, test.want)
		}
	}
}
