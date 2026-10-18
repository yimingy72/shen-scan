package control

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestGzipJSON(t *testing.T) {
	handler := gzipJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"value": strings.Repeat("rule", 100)})
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("response was not gzip encoded")
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || !strings.Contains(string(data), `"value"`) {
		t.Fatalf("gzip body=%q err=%v", data, err)
	}
}

func TestAcceptsGzipQuality(t *testing.T) {
	tests := map[string]bool{
		"":                   false,
		"br":                 false,
		"gzip":               true,
		"br, gzip; q=0.5":    true,
		"gzip;q=0":           false,
		"gzip;q=invalid":     false,
		"*;q=1":              true,
		"gzip;q=0, *;q=1":    false,
		"gzip;q=1, gzip;q=0": true,
	}
	for header, wanted := range tests {
		if got := acceptsGzip(header); got != wanted {
			t.Errorf("acceptsGzip(%q)=%t, want %t", header, got, wanted)
		}
	}
}

func TestScreenshotPNGBypassesGzip(t *testing.T) {
	data := []byte("\x89PNG\r\n\x1a\nfixture")
	h := gzipJSON(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	}))
	for _, suffix := range []string{"", "?thumbnail=true"} {
		r := httptest.NewRequest("GET", "/api/observations/fixture/screenshot"+suffix, nil)
		r.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Header().Get("Content-Encoding") != "" || !bytes.Equal(w.Body.Bytes(), data) || w.Header().Get("Content-Length") != strconv.Itoa(len(data)) {
			t.Fatal("binary PNG was altered by gzip middleware")
		}
	}
}
