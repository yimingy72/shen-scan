package main

import (
	"os"
	"testing"
	"time"
)

func TestBrowserIdleRecyclesWithoutTouchingActiveEntry(t *testing.T) {
	profile := t.TempDir()
	browser := browserRuntime{profile: profile}
	browser.scheduleIdle(time.Hour)
	// A timer that fires during an entry must wait for the same runtime mutex.
	// Cancel its generation before releasing the entry, as the JSONL loop does.
	browser.mu.Lock()
	browser.idleTimer.Reset(10 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	_, activeErr := os.Stat(profile)
	browser.stopIdleLocked()
	browser.mu.Unlock()
	if activeErr != nil {
		t.Fatal("idle callback closed an active entry")
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := os.Stat(profile); err != nil {
		t.Fatal("stale idle callback closed the next active generation")
	}
	browser.scheduleIdle(10 * time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		browser.mu.Lock()
		closed := browser.profile == ""
		browser.mu.Unlock()
		if closed {
			if _, err := os.Stat(profile); !os.IsNotExist(err) {
				t.Fatal("idle recycle retained profile")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("idle browser was not recycled")
}
