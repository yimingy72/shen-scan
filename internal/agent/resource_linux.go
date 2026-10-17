//go:build linux

package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type resourceSampler struct {
	mu                                                 sync.Mutex
	masscanPIDs                                        map[int]struct{}
	lastTotal, lastIdle                                uint64
	cpu, peakCPU                                       float64
	memoryTotal, memoryAvailable, minMemoryAvailable   float64
	agentRSS, peakAgentRSS, masscanRSS, peakMasscanRSS float64
}

func newResourceSampler() *resourceSampler {
	return &resourceSampler{masscanPIDs: make(map[int]struct{})}
}

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
	agentRSS := readRSSMiB("/proc/self/status")
	s.mu.Lock()
	defer s.mu.Unlock()
	if statErr == nil {
		line, _, _ := strings.Cut(string(stat), "\n")
		if total, idle, ok := parseCPUTotals(line); ok {
			if s.lastTotal != 0 && total > s.lastTotal && idle >= s.lastIdle && idle-s.lastIdle <= total-s.lastTotal {
				deltaTotal, deltaIdle := total-s.lastTotal, idle-s.lastIdle
				s.cpu = 100 * float64(deltaTotal-deltaIdle) / float64(deltaTotal)
				if s.cpu > s.peakCPU {
					s.peakCPU = s.cpu
				}
			}
			s.lastTotal, s.lastIdle = total, idle
		}
	}
	if memErr == nil {
		total, available := parseMemoryKiB(string(mem))
		s.memoryTotal, s.memoryAvailable = kibToMiB(total), kibToMiB(available)
		if available > 0 && (s.minMemoryAvailable == 0 || s.memoryAvailable < s.minMemoryAvailable) {
			s.minMemoryAvailable = s.memoryAvailable
		}
	}
	s.agentRSS = agentRSS
	if agentRSS > s.peakAgentRSS {
		s.peakAgentRSS = agentRSS
	}
	s.masscanRSS = 0
	for pid := range s.masscanPIDs {
		s.masscanRSS += readRSSMiB(fmt.Sprintf("/proc/%d/status", pid))
	}
	if s.masscanRSS > s.peakMasscanRSS {
		s.peakMasscanRSS = s.masscanRSS
	}
}

func readRSSMiB(path string) float64 {
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	_, rss := parseMemoryKiB(string(contents))
	return kibToMiB(rss)
}

func (s *resourceSampler) metrics() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"cpu_percent": s.cpu, "peak_cpu_percent": s.peakCPU,
		"mem_total_mib": s.memoryTotal, "mem_available_mib": s.memoryAvailable,
		"min_mem_available_mib": s.minMemoryAvailable,
		"agent_rss_mib":         s.agentRSS, "peak_agent_rss_mib": s.peakAgentRSS,
		"masscan_rss_mib": s.masscanRSS, "peak_masscan_rss_mib": s.peakMasscanRSS,
	}
}

func (s *resourceSampler) addMasscanPID(pid int) {
	s.mu.Lock()
	s.masscanPIDs[pid] = struct{}{}
	s.mu.Unlock()
}
func (s *resourceSampler) removeMasscanPID(pid int) {
	s.mu.Lock()
	delete(s.masscanPIDs, pid)
	if len(s.masscanPIDs) == 0 {
		s.masscanRSS = 0
	}
	s.mu.Unlock()
}
