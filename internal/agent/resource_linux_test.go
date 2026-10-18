//go:build linux

package agent

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLinuxProcessStatIdentityAndRSS(t *testing.T) {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[19] = "12345"
	fields[21] = "256"
	sample := parseToolProcessStat("42 (name with ) parentheses) "+strings.Join(fields, " "), 4096)
	if !sample.alive || !sample.identityKnown || sample.identity != 12345 || !sample.rssKnown || sample.rssMiB != 1 {
		t.Fatalf("incorrect stat fields: %+v", sample)
	}
	fields[0] = "Z"
	if dead := parseToolProcessStat("42 (exited) "+strings.Join(fields, " "), 4096); dead.alive {
		t.Fatalf("zombie counted: %+v", dead)
	}
}
func TestLinuxLiveToolRSSAndZeroMemoryAdmission(t *testing.T) {
	a := newHTTPXTestAgent(t, "unused")
	cmd := exec.Command("sh", "-c", "exec sleep 30")
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	release := a.resources.trackTool(toolNmap, cmd.Process.Pid)
	defer func() { killProcessGroup(cmd.Process); _ = cmd.Wait(); release() }()
	var metrics map[string]any
	deadline := time.Now().Add(time.Second)
	for {
		metrics = a.resources.metrics()
		rss, _ := metrics["nmap_rss_mib"].(float64)
		if rss > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rss, known := metrics["nmap_rss_mib"].(float64)
	if !known || rss <= 0 || metrics["nmap_processes"] != 1 || metrics["tools_processes"] != 1 {
		t.Fatalf("missing actualLinuxRSS: %+v", metrics)
	}
	t.Logf("Linux direct child PID=%d nmap_rss_mib=%.3f tools_processes=%v page_size=%d", cmd.Process.Pid, rss, metrics["tools_processes"], os.Getpagesize())
	a.resources.mu.Lock()
	a.resources.memoryKnown = true
	a.resources.memoryAvailable = 0
	a.resources.mu.Unlock()
	if a.canAdmitWork() {
		t.Fatal("known MemAvailable=0 must pause new work")
	}
	a.resources.mu.Lock()
	a.resources.memoryKnown = false
	a.resources.mu.Unlock()
	if _, present := a.resources.metrics()["mem_available_mib"]; present {
		t.Fatal("unknown memory emitted stale/zero sample")
	}
}

func TestLinuxBrowserTreeRSSIncludesChildren(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 30 & wait")
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { killProcessGroup(cmd.Process); _ = cmd.Wait() }()
	deadline := time.Now().Add(time.Second)
	for {
		single := readToolProcess(cmd.Process.Pid)
		tree := readBrowserProcessTree(cmd.Process.Pid)
		if tree.rssKnown && single.rssKnown && tree.rssMiB > single.rssMiB && tree.cpuKnown {
			t.Logf("PASS browser tree RSS %.3f MiB > helper RSS %.3f MiB; tree CPU sampled", tree.rssMiB, single.rssMiB)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("browser child resources missing: helper=%+v tree=%+v", single, tree)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
