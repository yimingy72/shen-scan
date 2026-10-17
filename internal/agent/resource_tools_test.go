package agent

import (
	"os/exec"
	"runtime"
	"testing"
)

func TestToolTrackerIdentityReuseAndUnknownRSS(t *testing.T) {
	current := toolProcessSample{alive: true, identityKnown: true, identity: 11, rssKnown: true, rssMiB: 2}
	tracker := toolTracker{read: func(int) toolProcessSample { return current }}
	releaseOld := tracker.track(toolWebProbe, 42)
	if metrics := tracker.metrics(); metrics["web_probe_processes"] != 1 || metrics["tools_processes"] != 1 {
		t.Fatalf("missing controlled helper: %+v", metrics)
	}
	current.identity = 22
	if metrics := tracker.metrics(); metrics["tools_processes"] != 0 {
		t.Fatalf("reused PID was attributed to old process: %+v", metrics)
	}
	releaseNew := tracker.track(toolNmap, 42)
	releaseOld()
	if metrics := tracker.metrics(); metrics["nmap_processes"] != 1 {
		t.Fatalf("late cleanup removed newer registration: %+v", metrics)
	}
	current.identityKnown = false
	if metrics := tracker.metrics(); metrics["nmap_processes"] != 1 {
		t.Fatal("unknown read lost controlled lifetime")
	} else if _, ok := metrics["nmap_rss_mib"]; ok {
		t.Fatalf("unknown RSS fabricated: %+v", metrics)
	}
	releaseNew()
	releaseNew()
	if metrics := tracker.metrics(); metrics["tools_processes"] != 0 {
		t.Fatalf("cleanup leaked process count: %+v", metrics)
	}
}

func TestToolTrackerDirectProcessLifetimes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix local process fixture")
	}
	sampler := newResourceSampler()
	for kind := toolMasscan; kind < toolKindCount; kind++ {
		cmd := exec.Command("sh", "-c", "exec sleep 30")
		setProcessGroup(cmd)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		release := sampler.trackTool(kind, cmd.Process.Pid)
		metrics := sampler.metrics()
		killProcessGroup(cmd.Process)
		_ = cmd.Wait()
		release()
		if metrics[toolMetricNames[kind]+"_processes"] != 1 || metrics["tools_processes"] != 1 {
			t.Fatalf("kind=%d missing live process: %+v", kind, metrics)
		}
		if !toolRSSSupported {
			if _, ok := metrics["tools_rss_mib"]; ok {
				t.Fatal("nonLinux RSS must be absent")
			}
		}
		if after := sampler.metrics(); after["tools_processes"] != 0 {
			t.Fatalf("kind=%d dead process retained: %+v", kind, after)
		}
	}
}
