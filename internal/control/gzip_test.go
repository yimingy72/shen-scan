package control

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
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
