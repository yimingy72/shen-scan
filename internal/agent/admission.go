package agent

import (
	"encoding/json"
	"time"
)

func (a *Agent) httpSlots(endpoints int, helper, cli bool) int {
	parallel := 2
	if helper {
		parallel = min(2, a.cfg.HTTPXMaxProcesses)
	} else if cli {
		return max(1, a.cfg.HTTPXThreads)
	}
	if endpoints <= 0 {
		return max(1, parallel)
	}
	return max(1, min(endpoints, parallel))
}

// A claim does not yet know its payload. Helper reservations can share only
// the existing global pool; unknown legacy payloads keep the CLI/native maximum.
func (a *Agent) httpReservation(payload json.RawMessage) (int, bool) {
	_, helper := webProbeBinary()
	var plan struct {
		Endpoints []struct{} `json:"endpoints"`
		RulesRef  string     `json:"rules_ref"`
		Rules     []struct {
			Engine  string `json:"engine"`
			Enabled bool   `json:"enabled"`
		} `json:"rules"`
	}
	if json.Unmarshal(payload, &plan) != nil {
		return a.httpSlots(0, helper, true), helper
	}
	cli := plan.RulesRef != ""
	for _, rule := range plan.Rules {
		if rule.Enabled && rule.Engine == "httpx-cff" {
			cli = true
		}
	}
	if !helper && plan.RulesRef != "" {
		return max(a.httpSlots(len(plan.Endpoints), false, true), a.httpSlots(len(plan.Endpoints), false, false)), false
	}
	return a.httpSlots(len(plan.Endpoints), helper, cli), helper
}
func (a *Agent) updateHTTPReservation(taskID string, endpoints int, helper, cli bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if task, ok := a.active[taskID]; ok && task.typeName == "http" {
		task.connectionSlots = a.httpSlots(endpoints, helper, cli)
		task.webHelper = helper
		a.active[taskID] = task
	}
}
func (a *Agent) connectionEstimate() (used, nextHTTP int) {
	_, helperAvailable := webProbeBinary()
	a.mu.Lock()
	defer a.mu.Unlock()
	helperSlots := 0
	for _, task := range a.active {
		if task.browser {
			used += 2
			continue
		}
		switch task.typeName {
		case "service", "poc":
			used += 4
		case "http":
			slots, helper := task.connectionSlots, task.webHelper
			if slots <= 0 {
				helper = helperAvailable
				slots = a.httpSlots(0, helper, true)
				if !helper {
					slots = max(slots, 2)
				}
			}
			if helper {
				helperSlots += slots
			} else {
				used += slots
			}
		}
	}
	helperSlots = min(helperSlots, a.cfg.HTTPXMaxProcesses)
	used += helperSlots
	if helperAvailable {
		nextHTTP = min(a.cfg.HTTPXMaxProcesses, helperSlots+a.httpSlots(0, true, false)) - helperSlots
	} else {
		nextHTTP = max(2, a.cfg.HTTPXThreads)
	}
	return used, nextHTTP
}

func (a *Agent) setServicePreference(prefer bool, ttl int, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.preferServiceUntil = time.Time{}
	if !prefer {
		return
	}
	if ttl <= 0 {
		ttl = 20
	}
	if ttl > 60 {
		ttl = 60
	}
	a.preferServiceUntil = now.Add(time.Duration(ttl) * time.Second)
}
func (a *Agent) servicePreferred(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return now.Before(a.preferServiceUntil)
}
