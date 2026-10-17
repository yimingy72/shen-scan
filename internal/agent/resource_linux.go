//go:build linux

package agent

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const toolRSSSupported = true

type resourceSampler struct {
	mu                                               sync.Mutex
	tools                                            toolTracker
	memorySampled                                    bool
	lastTotal, lastIdle                              uint64
	cpu, peakCPU                                     float64
	memoryTotal, memoryAvailable, minMemoryAvailable float64
	agentRSS, peakAgentRSS                           float64
	cpuKnown, memoryKnown, agentKnown                bool
}

func newResourceSampler() *resourceSampler { return &resourceSampler{} }
func (s *resourceSampler) run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		s.sample()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *resourceSampler) sample() {
	stat, statErr := os.ReadFile("/proc/stat")
	mem, memErr := os.ReadFile("/proc/meminfo")
	agentRSS, agentKnown := readRSSMiB("/proc/self/status")
	s.mu.Lock()
	s.cpuKnown = false
	s.memoryKnown = false
	if statErr == nil {
		line, _, _ := strings.Cut(string(stat), "\n")
		if total, idle, ok := parseCPUTotals(line); ok {
			if s.lastTotal != 0 && total > s.lastTotal && idle >= s.lastIdle && idle-s.lastIdle <= total-s.lastTotal {
				s.cpu = 100 * float64(total-s.lastTotal-(idle-s.lastIdle)) / float64(total-s.lastTotal)
				s.cpuKnown = true
				if s.cpu > s.peakCPU {
					s.peakCPU = s.cpu
				}
			}
			s.lastTotal, s.lastIdle = total, idle
		}
	}
	if memErr == nil {
		total, available := parseMemoryKiB(string(mem))
		if total > 0 {
			s.memoryKnown = true
			s.memoryTotal, s.memoryAvailable = kibToMiB(total), kibToMiB(available)
			if !s.memorySampled || s.memoryAvailable < s.minMemoryAvailable {
				s.minMemoryAvailable = s.memoryAvailable
			}
			s.memorySampled = true
		}
	}
	s.agentKnown = agentKnown
	if agentKnown {
		s.agentRSS = agentRSS
		if agentRSS > s.peakAgentRSS {
			s.peakAgentRSS = agentRSS
		}
	}
	s.mu.Unlock()
	s.tools.metrics() // Preserve sampled peaks even between heartbeats.
}
func readRSSMiB(path string) (float64, bool) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	if !strings.Contains(string(contents), "VmRSS:") {
		return 0, false
	}
	_, rss := parseMemoryKiB(string(contents))
	return kibToMiB(rss), true
}
func (s *resourceSampler) metrics() map[string]any {
	result := s.tools.metrics()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cpuKnown {
		result["cpu_percent"] = s.cpu
		result["peak_cpu_percent"] = s.peakCPU
	}
	if s.memoryKnown {
		result["mem_total_mib"] = s.memoryTotal
		result["mem_available_mib"] = s.memoryAvailable
		result["min_mem_available_mib"] = s.minMemoryAvailable
	}
	if s.agentKnown {
		result["agent_rss_mib"] = s.agentRSS
		result["peak_agent_rss_mib"] = s.peakAgentRSS
	}
	return result
}

// Start time and RSS come from one stat read, so PID reuse cannot splice a new
// process's memory onto the old identity. Exited/zombie children consume no RSS.
func readToolProcess(pid int) toolProcessSample {
	contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return toolProcessSample{}
	}
	if err != nil {
		return toolProcessSample{alive: true}
	}
	return parseToolProcessStat(string(contents), os.Getpagesize())
}
func parseToolProcessStat(contents string, pageSize int) toolProcessSample {
	end := strings.LastIndex(contents, ")")
	if end < 0 {
		return toolProcessSample{alive: true}
	}
	fields := strings.Fields(contents[end+1:])
	if len(fields) < 22 {
		return toolProcessSample{alive: true}
	}
	if fields[0] == "Z" || fields[0] == "X" {
		return toolProcessSample{}
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return toolProcessSample{alive: true}
	}
	sample := toolProcessSample{alive: true, identityKnown: true, identity: start}
	pages, err := strconv.ParseUint(fields[21], 10, 64)
	if err == nil && pageSize > 0 {
		sample.rssKnown = true
		sample.rssMiB = float64(pages) * float64(pageSize) / (1024 * 1024)
	}
	return sample
}
