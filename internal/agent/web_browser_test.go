package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"scanplatform/internal/webevidence"
)

func TestBrowserSlotPreservesOrdinaryCapacity(t *testing.T) {
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "join", InstanceID: "test", Hostname: "test", SessionID: "test", MaxTasks: 1})
	if err != nil {
		t.Fatal(err)
	}
	a.active["slow-browser"] = activeTask{typeName: "http", browser: true}
	if ports, ordinary := a.activeTypeCounts(); ports != 0 || ordinary != 0 {
		t.Fatal("browser consumed ordinary task capacity")
	}
	if a.activeStageCount("http") != 0 || a.canAdmitBrowser() {
		t.Fatal("browser occupied httpx capacity or admitted a second browser")
	}
	if got := fmt.Sprint(a.claimOptions()); got != "[[port] [http poc]]" && got != "[[port] [service http poc]]" {
		t.Fatalf("ordinary claim blocked by slow browser: %s", got)
	}
	if used, _ := a.connectionEstimate(); used != 2 {
		t.Fatalf("browser connection resource weight missing: %d", used)
	}
	// Browser stage must execute through its own helper path, before ordinary slots.
	payload, _ := json.Marshal(webevidence.BrowserAssignment{Phase: "browser", WebBrowserProfile: webevidence.BrowserProfile})
	if !browserTask(payload) || browserTask([]byte(`{"web_browser_profile":"wapp-browser-v1"}`)) {
		t.Fatal("phase detection mixed parent and browser tasks")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = (&browserProcess{}).run(ctx, "/missing-browser-helper", webevidence.BrowserRequest{}, a.resources)
	if err == nil {
		t.Fatal("missing browser helper silently succeeded")
	}
}

func TestBrowserEvidencePreservesIndependentPNG(t *testing.T) {
	data := bytes.Repeat([]byte{17, 23, 31, 47}, 100<<10)
	input := webevidence.BrowserResult{Complete: true, TotalRules: 1, EvaluatedRules: 1, Screenshot: &webevidence.BrowserScreenshot{WebStage: webevidence.WebStage{State: "partial"}, PNG: data}, Matches: []webevidence.Match{{Name: "retained JS", Evidence: json.RawMessage(`{"ok":true}`)}}}
	result := compactBrowserEvidence(input)
	if !bytes.Equal(result.Screenshot.PNG, data) || len(result.Matches) != 1 || result.Matches[0].Name != "retained JS" {
		t.Fatal("PNG budget consumed JS evidence or image was dropped")
	}
}
