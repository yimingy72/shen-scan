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

func TestBrowserScreenshotModes(t *testing.T) {
	requireBrowserIntegration(t)
	defer closeBrowserRuntime()
	evidenceDir := os.Getenv("SCREENSHOT_EVIDENCE_DIR")
	if evidenceDir != "" {
		if err := os.MkdirAll(filepath.Join(evidenceDir, "screenshots"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	var requests, permits, images, fonts, files atomic.Int32
	var logo bytes.Buffer
	picture := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			picture.SetNRGBA(x, y, color.NRGBA{R: 210, G: 20, B: 30, A: 255})
		}
	}
	if err := png.Encode(&logo, picture); err != nil {
		t.Fatal(err)
	}
	var font []byte
	for _, candidate := range []string{"/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"} {
		if raw, err := os.ReadFile(candidate); err == nil {
			font = raw
			break
		}
	}
	if len(font) == 0 {
		t.Fatal("self-hosted font fixture unavailable")
	}
	const document = `<!doctype html><html><head><link rel="icon" href="data:,"><link rel="stylesheet" href="/style.css"></head><body><img id="logo" src="/logo.png"><h1>httpx SDK screenshot fixture</h1><div id="marker">Screenshot and JS/DOM share this page</div><script src="/app.js"></script></body></html>`
	record := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			raw, _ := httputil.DumpRequest(r, true)
			captured := httptest.NewRecorder()
			handler(captured, r)
			captured.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			captured.Header().Set("Content-Length", fmt.Sprint(captured.Body.Len()))
			response := captured.Result()
			response.Header = captured.Header().Clone()
			response.ContentLength = int64(captured.Body.Len())
			responseRaw, _ := httputil.DumpResponse(response, true)
			response.Body.Close()
			if evidenceDir != "" {
				os.WriteFile(filepath.Join(evidenceDir, fmt.Sprintf("http-%03d.txt", files.Add(1))), append(append(raw, []byte("\n\n--- RESPONSE ---\n")...), responseRaw...), 0600)
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
	target := httptest.NewTLSServer(record(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "screenshot.virtual.fixture" || r.TLS.ServerName != "screenshot.sni.fixture" {
			t.Errorf("fixed screenshot identity lost: Host=%q SNI=%q", r.Host, r.TLS.ServerName)
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, document)
		case "/style.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, `@font-face{font-family:Fixture;src:url('/font.ttf')}body{margin:0;background:rgb(30,40,50);color:white;font-family:Fixture}#logo{position:absolute;left:10px;top:10px;width:64px;height:64px}h1{padding:100px 20px 0}`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `window.ShotFixture={version:'5.1'};setTimeout(()=>document.querySelector('#marker').dataset.ready='yes',30);`)
		case "/logo.png":
			images.Add(1)
			w.Header().Set("Content-Type", "image/png")
			w.Write(logo.Bytes())
		case "/font.ttf":
			fonts.Add(1)
			w.Header().Set("Content-Type", "font/ttf")
			w.Write(font)
		case "/noise":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><link rel="icon" href="data:,"></head><body style="margin:0"><div id="marker"></div><canvas width="1280" height="720" style="position:fixed;left:0;top:0"></canvas><script>window.ShotFixture={version:'5.1'};const c=document.querySelector('canvas'),x=c.getContext('2d'),im=x.createImageData(1280,720);let s=123456789;for(let i=0;i<im.data.length;i+=4){for(let j=0;j<3;j++){s=(Math.imul(s,1664525)+1013904223)>>>0;im.data[i+j]=s>>>24;}im.data[i+3]=255}x.putImageData(im,0,0);</script></body></html>`)
		case "/tall":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><link rel="icon" href="data:,"></head><body style="margin:0;height:60000px;background:#123456">Only first screen is requested</body></html>`)
		default:
			t.Errorf("unexpected fixture request: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer target.Close()
	admission := httptest.NewServer(record(func(w http.ResponseWriter, r *http.Request) {
		permits.Add(1)
		fmt.Fprint(w, `{"valid_for_ms":475,"waited_ms":0}`)
	}))
	defer admission.Close()
	base := webevidence.BrowserRequest{ProbeRequest: webevidence.ProbeRequest{ID: "screenshot-local", Protocol: webevidence.Protocol, Profile: webevidence.BrowserProfile, URL: strings.Replace(target.URL, "127.0.0.1", "screenshot.logical.fixture", 1) + "/", ConnectIP: "127.0.0.1", Host: "screenshot.virtual.fixture", SNI: "screenshot.sni.fixture", MaxRequests: 32, EntryTimeoutMillis: 10000, AdmissionURL: admission.URL, AdmissionToken: "synthetic-screenshot-permit"}}
	selected := []byte(`{"apps":{"JSOnlyFixture":{"js":{"ShotFixture.version":"(5\\.1)\\;version:\\1"},"dom":{"#marker":{"exists":""}}}}}`)
	closeBrowserRuntime()
	cases := []struct {
		name     string
		js, shot bool
		path     string
		noise    bool
		badRules bool
	}{
		{"both-disabled", false, false, "/", false, false}, {"screenshot-only", false, true, "/", false, false}, {"js-dom-only", true, false, "/", false, false}, {"both-enabled", true, true, "/", false, false}, {"png-byte-limit-keeps-js", true, true, "/noise", true, false}, {"tall-page-first-screen", false, true, "/tall", false, false}, {"bad-js-library-still-screenshot", true, true, "/", false, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.ID = test.name
			input.WebScanOptions = &webevidence.WebScanOptions{JSDOM: test.js, Screenshot: test.shot}
			input.CFF = []byte("invalid JSON must never be compiled in screenshot-only mode")
			if test.js && !test.badRules {
				input.CFF = selected
			}
			input.URL = strings.TrimSuffix(base.URL, "/") + test.path
			before, grants, beforeImages, beforeFonts := requests.Load(), permits.Load(), images.Load(), fonts.Load()
			if evidenceDir != "" {
				raw, _ := json.MarshalIndent(input, "", "  ")
				os.WriteFile(filepath.Join(evidenceDir, test.name+"-request.json"), raw, 0600)
			}
			started := time.Now()
			result, err := probeBrowser(context.Background(), input)
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("browser mode failed: %v %+v", err, result)
			}
			if evidenceDir != "" {
				metadata := result
				if result.Screenshot != nil {
					shot := *result.Screenshot
					shot.PNG = nil
					metadata.Screenshot = &shot
				}
				raw, _ := json.MarshalIndent(metadata, "", "  ")
				os.WriteFile(filepath.Join(evidenceDir, test.name+".json"), raw, 0600)
			}
			if test.badRules {
				if result.JSDOM.State != "failed" || result.JSDOM.Error == "" || result.Complete {
					t.Fatal("invalid JS library did not keep independent failure")
				}
			}
			if requests.Load()-before != permits.Load()-grants || result.Requests != int(requests.Load()-before) {
				t.Fatalf("HTTP permit mismatch: target=%d permit=%d result=%d", requests.Load()-before, permits.Load()-grants, result.Requests)
			}
			if !test.js && !test.shot {
				if result.Requests != 0 || controlledBrowser.engine != nil || !result.Complete {
					t.Fatal("disabled flags launched browser/work")
				}
				return
			}
			if !test.js {
				if result.JSDOM == nil || result.JSDOM.State != "disabled" || result.TotalRules != 0 || result.PlanSHA256 != "" {
					t.Fatal("screenshot-only compiled Wapp plan")
				}
			}
			if test.js && !test.badRules {
				found := false
				for _, match := range result.Matches {
					if match.Engine != result.Engine {
						t.Fatalf("combined match engine differs: match=%q result=%q", match.Engine, result.Engine)
					}
					if match.Name == "JSOnlyFixture" && match.Version == "5.1" {
						found = true
					}
				}
				if !found {
					t.Fatalf("JS positive lost: %+v", result.Matches)
				}
			}
			if !test.shot {
				if result.Screenshot != nil || images.Load() != beforeImages || fonts.Load() != beforeFonts {
					t.Fatal("JS-only captured screenshot/downloaded image/font")
				}
				return
			}
			if result.Screenshot == nil {
				t.Fatal("screenshot result omitted")
			}
			if test.noise {
				if result.Screenshot.State != "partial" || len(result.Screenshot.PNG) != 0 || result.JSDOM.State != "complete" || result.Complete {
					t.Fatalf("PNG limit poisoned JS coverage: %+v", result)
				}
			} else {
				if result.Screenshot.State != "complete" || len(result.Screenshot.PNG) == 0 || len(result.Screenshot.PNG) > webevidence.MaxScreenshot || result.Screenshot.Width != 1280 || result.Screenshot.Height != 720 || result.Screenshot.SHA256 != webevidence.SHA256(result.Screenshot.PNG) {
					t.Fatalf("invalid screenshot: %+v", result.Screenshot)
				}
				if test.path == "/" {
					if images.Load()-beforeImages != 1 || fonts.Load()-beforeFonts != 1 || result.Requests != 5 {
						t.Fatalf("screenshot did not fetch image/font once: image=%d font=%d requests=%d", images.Load()-beforeImages, fonts.Load()-beforeFonts, result.Requests)
					}
					decoded, decodeErr := png.Decode(bytes.NewReader(result.Screenshot.PNG))
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					red, green, blue, _ := decoded.At(20, 20).RGBA()
					if red < 45000 || green > 10000 || blue > 12000 {
						t.Fatalf("screenshot image missing/blank pixel: %d %d %d", red, green, blue)
					}
				}
				if test.js && !test.badRules && result.JSDOM.State != "complete" {
					t.Fatalf("same-page JS/DOM incomplete: %+v", result.JSDOM)
				}
				if evidenceDir != "" {
					os.WriteFile(filepath.Join(evidenceDir, "screenshots", test.name+".png"), result.Screenshot.PNG, 0600)
				}
			}
			t.Logf("mode=%s elapsed=%s HTTP=%d permits=%d JS=%s screenshot=%s PNG=%d dimensions=%dx%d", test.name, elapsed, result.Requests, permits.Load()-grants, result.JSDOM.State, result.Screenshot.State, len(result.Screenshot.PNG), result.Screenshot.Width, result.Screenshot.Height)
			if evidenceDir != "" {
				result.Screenshot.PNG = nil
				raw, _ := json.MarshalIndent(result, "", "  ")
				os.WriteFile(filepath.Join(evidenceDir, test.name+".json"), raw, 0600)
			}
		})
	}
}

func TestFullPassiveDisabledCollectsInfo(t *testing.T) {
	target, _ := enrichmentFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.0")
		w.Header().Set("X-Powered-By", "PHP/8.2")
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			w.Write([]byte{0, 0, 1, 0})
			return
		}
		fmt.Fprint(w, `<html><title>Collection only</title><meta name="generator" content="WordPress 6.3">full-marker</html>`)
	})
	input := fullInput(target.URL)
	input.CFF = []byte("invalid JSON must not be compiled when passive is false")
	input.WebScanOptions = &webevidence.WebScanOptions{}
	result, err := probeFull(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Tech      []string `json:"tech"`
		CPE       []any    `json:"cpe"`
		WordPress any      `json:"wordpress"`
	}
	if json.Unmarshal(result.SDKResult, &native) != nil || len(result.Technologies) != 0 || len(result.CapabilityGaps) != 0 || len(native.Tech) != 0 || len(native.CPE) != 0 || native.WordPress != nil || result.Title != "Collection only" || result.Response.StatusCode != 200 {
		t.Fatalf("passive-disabled result invalid: %+v native=%s", result, string(result.SDKResult))
	}
	input.CFF = []byte(`{"apps":{"FullFixture":{"html":["full-marker"],"js":{"Invisible.version":""}}}}`)
	input.WebScanOptions = &webevidence.WebScanOptions{Passive: true}
	passiveResult, passiveErr := probeFull(context.Background(), input)
	if passiveErr != nil || len(passiveResult.CapabilityGaps) != 0 || len(passiveResult.Technologies) == 0 {
		t.Fatalf("JS-disabled passive run gained browser gap or lost static match: %v %+v", passiveErr, passiveResult)
	}

}
