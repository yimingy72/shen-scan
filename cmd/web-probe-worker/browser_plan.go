package main

import (
	"encoding/json"
	"sync"

	"scanplatform/internal/webevidence"
	"scanplatform/webprobe/browserfp"
)

type browserExecutionPlan struct {
	matcher    *browserfp.Matcher
	collector  string
	planSHA256 string
	hasRules   bool
}

// Matcher already caches four immutable compiled snapshots. Keep only the last
// serialized collection plan here; never cache a target, observation or result.
var browserPlanCache struct {
	sync.Mutex
	digest string
	plan   browserExecutionPlan
}

func cachedBrowserExecutionPlan(cff []byte, digest string) (browserExecutionPlan, error) {
	browserPlanCache.Lock()
	defer browserPlanCache.Unlock()
	if digest != "" && browserPlanCache.digest == digest {
		return browserPlanCache.plan, nil
	}
	matcher, err := browserfp.Compile(cff)
	if err != nil {
		return browserExecutionPlan{}, err
	}
	plan := matcher.Plan()
	raw, err := json.Marshal(plan)
	if err != nil {
		return browserExecutionPlan{}, err
	}
	collector, err := browserCollector(plan)
	if err != nil {
		return browserExecutionPlan{}, err
	}
	compiled := browserExecutionPlan{matcher: matcher, collector: collector, planSHA256: webevidence.SHA256(raw), hasRules: len(plan.JS) > 0 || len(plan.DOM) > 0}
	browserPlanCache.digest, browserPlanCache.plan = digest, compiled
	return compiled, nil
}
