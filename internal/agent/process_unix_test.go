//go:build unix

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessGroupCancellationStopsDescendant(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "escaped-child")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", `(sleep 0.3; printf survived > "$1") & wait`, "fixture", marker)
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := cmd.Wait(); err == nil {
		t.Fatal("cancelled process reported success")
	}
	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("descendant escaped cancellation: %v", err)
	}
}

func TestProcessGroupSupportsExplicitCancellationOwner(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 0")
	setProcessGroup(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatalf("ordinary Command must retain its caller-owned cancellation: %v", err)
	}
}
