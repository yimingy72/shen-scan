package main

import (
	"fmt"
	"net/http"
	"testing"

	fingers "github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/ehole"
	"github.com/chainreactors/fingers/fingerprinthub"
	native "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/goby"
	"github.com/chainreactors/utils/encode"
	"scanplatform/internal/webevidence"
)

func fixtureEngine(t *testing.T, n, h, e string) *fingers.Engine {
	t.Helper()
	engine, err := fingers.NewEngine(fingers.FaviconEngine)
	if err != nil {
		t.Fatal(err)
	}
	nativeEngine, err := native.NewFingersEngine([]byte(n), []byte("[]"), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	hub, err := fingerprinthub.NewFingerPrintHubEngine([]byte(h), []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	eh, err := ehole.NewEHoleEngine([]byte(e))
	if err != nil {
		t.Fatal(err)
	}
	gb, err := goby.NewGobyEngine([]byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	engine.Register(nativeEngine)
	engine.Register(hub)
	engine.Register(eh)
	engine.Register(gb)
	if err = engine.Compile(); err != nil {
		t.Fatal(err)
	}
	engine.EnableMatchDetail()
	return engine
}
func TestFullFaviconAndTrueTitle(t *testing.T) {
	icon := []byte("synthetic-icon-bytes")
	hash := encode.Mmh3Hash32(icon)
	nativeJSON := fmt.Sprintf(`[{"name":"native-icon-a","rule":[{"favicon":{"mmh3":[%q]}}]},{"name":"native-icon-b","rule":[{"favicon":{"mmh3":[%q]}}]}]`, hash, hash)
	hub := fmt.Sprintf(`[{"id":"icon","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers":[{"type":"favicon","hash":[%q]}]}]},{"id":"and","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers-condition":"and","matchers":[{"type":"word","words":["page-token"]},{"type":"favicon","hash":[%q]}]}]},{"id":"or","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers-condition":"or","matchers":[{"type":"word","words":["absent"]},{"type":"favicon","hash":[%q]}]}]},{"id":"bad-and","http":[{"method":"GET","path":["{{BaseURL}}/"],"matchers-condition":"and","matchers":[{"type":"word","words":["absent"]},{"type":"favicon","hash":[%q]}]}]}]`, hash, hash, hash, hash)
	engine := fixtureEngine(t, nativeJSON, hub, `{"fingerprint":[{"cms":"title-only","method":"keyword","location":"title","keyword":["unique-title"]}]}`)
	input := webevidence.MatchRequest{Response: webevidence.Response{URL: "http://fixture.invalid/", StatusCode: 200, Proto: "HTTP/1.1", Completeness: "full", Headers: http.Header{"Content-Type": {"text/html"}}, Body: []byte(`<title>unique-title</title>page-token`)}, Icons: []webevidence.Response{{StatusCode: 200, Completeness: "full", Body: icon}}}
	matches, err := match(engine, input)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range matches {
		seen[m.Name] = true
	}
	for _, name := range []string{"native-icon-a", "native-icon-b", "icon", "and", "or", "title-only"} {
		if !seen[name] {
			t.Fatalf("missing %s: %+v", name, matches)
		}
	}
	if seen["bad-and"] {
		t.Fatal("favicon bypassed AND page condition")
	}
	input.Response.Body = []byte(`<title>other</title><body>unique-title page-token</body>`)
	input.Icons = nil
	matches, err = match(engine, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if m.Name == "title-only" || m.Name == "icon" || m.Name == "and" || m.Name == "native-icon-a" {
			t.Fatalf("wrong evidence matched %+v", m)
		}
	}
}
