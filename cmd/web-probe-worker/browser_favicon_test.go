package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/webevidence"
)

func TestBrowserScreenshotOtherFavicon(t *testing.T) {
	requireBrowserIntegration(t)
	defer closeBrowserRuntime()
	var targetHits, icons, permits, files atomic.Int32
	var icon bytes.Buffer
	picture := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	picture.SetNRGBA(5, 5, color.NRGBA{R: 220, A: 255})
	png.Encode(&icon, picture)
	evidenceDir := os.Getenv("FAVICON_EVIDENCE_DIR")
	if evidenceDir != "" {
		os.MkdirAll(filepath.Join(evidenceDir, "screenshots"), 0700)
	}
	record := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			requestRaw, _ := httputil.DumpRequest(r, true)
			captured := httptest.NewRecorder()
			handler(captured, r)
			captured.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			captured.Header().Set("Content-Length", fmt.Sprint(captured.Body.Len()))
			response := captured.Result()
			response.Header = captured.Header().Clone()
			response.ContentLength = int64(captured.Body.Len())
			raw, _ := httputil.DumpResponse(response, true)
			response.Body.Close()
			if evidenceDir != "" {
				os.WriteFile(filepath.Join(evidenceDir, fmt.Sprintf("http-%02d.txt", files.Add(1))), append(append(requestRaw, []byte("\n\n--- RESPONSE ---\n")...), raw...), 0600)
			}
			for key, values := range captured.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(captured.Code)
			w.Write(captured.Body.Bytes())
		}
	}
	target := httptest.NewServer(record(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><link rel="icon" href="/brandmark?variant=compact"></head><body style="margin:0;background:#1e2832;color:white"><h1>Other favicon screenshot fixture</h1><p>Custom icon URL has no file extension.</p></body></html>`)
		case "/brandmark":
			icons.Add(1)
			w.Header().Set("Content-Type", "image/png")
			w.Write(icon.Bytes())
		default:
			t.Errorf("unexpected fixture request: %s", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer target.Close()
	admission := httptest.NewServer(record(func(w http.ResponseWriter, r *http.Request) {
		permits.Add(1)
		var frame struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&frame); err != nil {
			t.Error(err)
			return
		}
		started := time.Now()
		waited := int64(0)
		if strings.Contains(frame.URL, "/brandmark?") {
			select {
			case <-time.After(400 * time.Millisecond):
				waited = time.Since(started).Milliseconds()
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprintf(w, `{"valid_for_ms":475,"waited_ms":%d}`, waited)
	}))
	defer admission.Close()
	request := webevidence.ProbeRequest{ID: "other-favicon", Protocol: webevidence.Protocol, URL: target.URL + "/", ConnectIP: "127.0.0.1", MaxRequests: 32, Profile: webevidence.BrowserProfile, AdmissionURL: admission.URL, AdmissionToken: "synthetic-favicon-permit"}
	output, err := runBrowser(context.Background(), browserRunInput{Request: request, Screenshot: true})
	if err != nil || output.Screenshot == nil || output.Screenshot.State != "complete" || output.Partial || output.BlockedCount != 0 {
		t.Fatalf("favicon downgraded screenshot: %v %+v", err, output)
	}
	if output.ResourceTypes["Other"] == 0 || icons.Load() != 1 || targetHits.Load() != 2 || permits.Load() != 2 || len(output.Attempts) != 2 {
		t.Fatalf("Other favicon was not admitted once: types=%v icons=%d HTTP=%d permits=%d", output.ResourceTypes, icons.Load(), targetHits.Load(), permits.Load())
	}
	if len(output.Screenshot.PNG) == 0 || len(output.Screenshot.PNG) > webevidence.MaxScreenshot || output.Screenshot.Width != 1280 || output.Screenshot.Height != 720 {
		t.Fatal("invalid first-screen PNG")
	}
	if evidenceDir != "" {
		os.WriteFile(filepath.Join(evidenceDir, "screenshots", "other-favicon.png"), output.Screenshot.PNG, 0600)
		output.Screenshot.PNG = nil
		raw, _ := json.MarshalIndent(output, "", "  ")
		os.WriteFile(filepath.Join(evidenceDir, "result.json"), raw, 0600)
	}
	t.Logf("custom no-extension favicon with400ms admission delay: resource types=%v HTTP=%d permits=%d icons=%d screenshot=complete partial=false", output.ResourceTypes, targetHits.Load(), permits.Load(), icons.Load())
}
