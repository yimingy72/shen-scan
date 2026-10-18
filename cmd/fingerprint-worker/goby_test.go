package main

import (
	"testing"

	fingers "github.com/chainreactors/fingers"
	"github.com/chainreactors/fingers/goby"
)

func TestGobyEmbeddedRDPIsCandidateWithoutChangingMatches(t *testing.T) {
	engine, err := fingers.NewEngine(fingers.GobyEngine)
	if err != nil {
		t.Fatal(err)
	}
	engine.EnableMatchDetail()

	frames, quality := gobyMatches(engine, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nWordPress")
	for _, name := range []string{"windows", "microsoft-windows远程连接"} {
		frame := frames[name]
		if frame == nil || quality[frame] != goby.EmbeddedRDPCandidateReason || frame.MatchDetail.MatcherValue != "rdp" {
			t.Fatalf("original hit / assessment missing: %s %+v %v", name, frame, quality)
		}
	}
	frames, quality = gobyMatches(engine, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nMicrosoft WordPress")
	if frame := frames["windows"]; frame == nil || quality[frame] != "" {
		t.Fatal("independent Microsoft branch was incorrectly downgraded")
	}
	frames, quality = gobyMatches(engine, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nrdp")
	if frame := frames["microsoft-windows远程连接"]; frame == nil || quality[frame] != "" {
		t.Fatal("standalone token semantics were changed")
	}
}
