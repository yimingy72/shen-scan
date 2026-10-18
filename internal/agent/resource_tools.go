package agent

import (
	"sync"
	"time"
)

type toolKind uint8

const (
	toolMasscan toolKind = iota
	toolNmap
	toolHTTPX
	toolWebProbe
	toolFingerprint
	toolNuclei
	toolBrowser
	toolKindCount
)

var toolMetricNames = [toolKindCount]string{"masscan", "nmap", "httpx", "web_probe", "fingerprint", "nuclei", "browser"}

type toolProcessSample struct {
	alive, identityKnown, rssKnown bool
	identity                       uint64
	rssMiB                         float64
	cpuTicks                       uint64
	cpuKnown                       bool
}
type trackedToolProcess struct {
	kind          toolKind
	identity      uint64
	identityKnown bool
	lastCPUTicks  uint64
	lastCPUTime   time.Time
}
type toolTracker struct {
	mu                     sync.Mutex
	processes              map[int]*trackedToolProcess
	read                   func(int) toolProcessSample
	peakTotal, peakMasscan float64
	rssSampled             bool
}

func (t *toolTracker) readProcess(pid int) toolProcessSample {
	if t.read != nil {
		return t.read(pid)
	}
	return readToolProcess(pid)
}

// Register immediately after Start, before any goroutine can Wait/reap the PID.
// The captured record also fences late cleanup against a newer PID registration.
func (t *toolTracker) track(kind toolKind, pid int) func() {
	if kind >= toolKindCount || pid <= 0 {
		return func() {}
	}
	sample := t.readProcess(pid)
	if !sample.alive {
		return func() {}
	}
	record := &trackedToolProcess{kind: kind, identity: sample.identity, identityKnown: sample.identityKnown}
	t.mu.Lock()
	if t.processes == nil {
		t.processes = make(map[int]*trackedToolProcess)
	}
	t.processes[pid] = record
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		if t.processes[pid] == record {
			delete(t.processes, pid)
		}
		t.mu.Unlock()
	}
}
func (t *toolTracker) metrics() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	var counts [toolKindCount]int
	var rss [toolKindCount]float64
	var unknown [toolKindCount]bool
	browserCPU, browserCPUKnown := 0.0, false
	for pid, record := range t.processes {
		sample := t.readProcess(pid)
		if record.kind == toolBrowser && t.read == nil {
			sample = readBrowserProcessTree(pid)
		}
		if !sample.alive || record.identityKnown && sample.identityKnown && sample.identity != record.identity {
			delete(t.processes, pid)
			continue
		}
		counts[record.kind]++
		if record.kind == toolBrowser && sample.cpuKnown {
			now := time.Now()
			if !record.lastCPUTime.IsZero() && sample.cpuTicks >= record.lastCPUTicks && now.After(record.lastCPUTime) {
				// Linux /proc exports process CPU in USER_HZ (100 ticks/second).
				browserCPU = 100 * float64(sample.cpuTicks-record.lastCPUTicks) / 100 / now.Sub(record.lastCPUTime).Seconds()
				browserCPUKnown = true
			}
			record.lastCPUTicks, record.lastCPUTime = sample.cpuTicks, now
		}
		if record.identityKnown && sample.identityKnown && sample.rssKnown {
			rss[record.kind] += sample.rssMiB
		} else {
			unknown[record.kind] = true
		}
	}
	result := make(map[string]any, 17)
	if browserCPUKnown {
		result["browser_cpu_percent"] = browserCPU
	}
	totalCount, totalRSS := 0, 0.0
	complete := toolRSSSupported
	for kind, name := range toolMetricNames {
		result[name+"_processes"] = counts[kind]
		totalCount += counts[kind]
		if toolRSSSupported && !unknown[kind] {
			result[name+"_rss_mib"] = rss[kind]
			totalRSS += rss[kind]
		} else {
			complete = false
		}
	}
	result["tools_processes"] = totalCount
	if complete {
		result["tools_rss_mib"] = totalRSS
		if totalRSS > t.peakTotal {
			t.peakTotal = totalRSS
		}
		t.rssSampled = true
	}
	if toolRSSSupported && !unknown[toolMasscan] && rss[toolMasscan] > t.peakMasscan {
		t.peakMasscan = rss[toolMasscan]
	}
	if t.rssSampled {
		result["peak_tools_rss_mib"] = t.peakTotal
		result["peak_masscan_rss_mib"] = t.peakMasscan
	}
	return result
}
func (s *resourceSampler) trackTool(kind toolKind, pid int) func() {
	if s == nil {
		return func() {}
	}
	return s.tools.track(kind, pid)
}
