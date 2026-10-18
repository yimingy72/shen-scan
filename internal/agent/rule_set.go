package agent

import (
	"container/list"
	"context"
	"fmt"
	"sync"

	"scanplatform/internal/rulelib"
)

type ruleSetEntry struct {
	ref   string
	rules []rulelib.Rule
	cff   []byte
}

type ruleSetCache struct {
	mu       sync.Mutex
	capacity int
	order    *list.List
	items    map[string]*list.Element
}

func newRuleSetCache(capacity int) *ruleSetCache {
	return &ruleSetCache{capacity: capacity, order: list.New(), items: make(map[string]*list.Element)}
}

func (cache *ruleSetCache) get(ref string) ([]rulelib.Rule, bool) {
	cache.mu.Lock()
	element := cache.items[ref]
	if element == nil {
		cache.mu.Unlock()
		return nil, false
	}
	cache.order.MoveToFront(element)
	rules := element.Value.(ruleSetEntry).rules
	cache.mu.Unlock()
	return cloneRules(rules), true
}

func (cache *ruleSetCache) add(ref string, rules []rulelib.Rule) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	stored := cloneRules(rules)
	cff, _ := buildHTTPXCFF(rules)
	if element := cache.items[ref]; element != nil {
		element.Value = ruleSetEntry{ref: ref, rules: stored, cff: append([]byte(nil), cff...)}
		cache.order.MoveToFront(element)
		return
	}
	element := cache.order.PushFront(ruleSetEntry{ref: ref, rules: stored, cff: append([]byte(nil), cff...)})
	cache.items[ref] = element
	if cache.order.Len() > cache.capacity {
		oldest := cache.order.Back()
		delete(cache.items, oldest.Value.(ruleSetEntry).ref)
		cache.order.Remove(oldest)
	}
}

func (cache *ruleSetCache) cff(ref string) ([]byte, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element := cache.items[ref]
	if element == nil || len(element.Value.(ruleSetEntry).cff) == 0 {
		return nil, false
	}
	cache.order.MoveToFront(element)
	return append([]byte(nil), element.Value.(ruleSetEntry).cff...), true
}

func (a *Agent) resolveTaskRules(ctx context.Context, task Task, ref string, inline []rulelib.Rule, kind string) ([]rulelib.Rule, error) {
	if ref == "" {
		if err := validateTaskRules(inline, kind); err != nil {
			return nil, &TaskError{Reason: "invalid " + kind + " rules: " + err.Error(), Retryable: false}
		}
		return inline, nil
	}
	if inline != nil {
		return nil, &TaskError{Reason: "task payload cannot contain both rules and rules_ref", Retryable: false}
	}
	wantRef := task.RunID + ":" + task.Type
	if task.RunID == "" || ref != wantRef {
		return nil, &TaskError{Reason: fmt.Sprintf("invalid rules_ref %q; expected %q", ref, wantRef), Retryable: false}
	}
	if cached, ok := a.ruleSets.get(ref); ok {
		return cached, nil
	}
	result := a.ruleSetFlights.DoChan(ref, func() (any, error) {
		if cached, ok := a.ruleSets.get(ref); ok {
			return cached, nil
		}
		response, err := a.client.Rules(ctx, a.workerID, a.cfg.SessionID, task)
		if err != nil {
			return nil, &TaskError{Reason: "download rule set: " + err.Error(), Retryable: true}
		}
		if response.Ref != ref {
			return nil, &TaskError{Reason: fmt.Sprintf("rule set response ref %q does not match %q", response.Ref, ref), Retryable: true}
		}
		if response.Kind != kind {
			return nil, &TaskError{Reason: fmt.Sprintf("rule set response kind %q does not match %q", response.Kind, kind), Retryable: true}
		}
		if response.Rules == nil {
			return nil, &TaskError{Reason: "rule set response omitted rules", Retryable: true}
		}
		if err := validateTaskRules(response.Rules, kind); err != nil {
			return nil, &TaskError{Reason: "invalid downloaded rule set: " + err.Error(), Retryable: false}
		}
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		a.ruleSets.add(ref, response.Rules)
		return cloneRules(response.Rules), nil
	})
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case outcome := <-result:
		if outcome.Err != nil {
			return nil, outcome.Err
		}
		return cloneRules(outcome.Val.([]rulelib.Rule)), nil
	}
}

func cloneRules(rules []rulelib.Rule) []rulelib.Rule {
	if rules == nil {
		return nil
	}
	cloned := make([]rulelib.Rule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule
		cloned[index].Tags = append([]string(nil), rule.Tags...)
		cloned[index].AppliesTo = append([]string(nil), rule.AppliesTo...)
		cloned[index].Fingerprint = append([]byte(nil), rule.Fingerprint...)
		if rule.Collection != nil {
			collection := *rule.Collection
			collection.Products = append([]string(nil), rule.Collection.Products...)
			cloned[index].Collection = &collection
		}
		if rule.Upstream != nil {
			upstream := *rule.Upstream
			cloned[index].Upstream = &upstream
		}
		if rule.Nuclei != nil {
			nuclei := *rule.Nuclei
			nuclei.Protocols = append([]string(nil), rule.Nuclei.Protocols...)
			nuclei.Capabilities = append([]string(nil), rule.Nuclei.Capabilities...)
			nuclei.Info = append([]byte(nil), rule.Nuclei.Info...)
			nuclei.Classification = append([]byte(nil), rule.Nuclei.Classification...)
			if rule.Nuclei.RequestCount != nil {
				requestCount := *rule.Nuclei.RequestCount
				nuclei.RequestCount = &requestCount
			}
			cloned[index].Nuclei = &nuclei
		}
		if rule.Verification != nil {
			verification := *rule.Verification
			verification.CVEs = append([]string(nil), rule.Verification.CVEs...)
			verification.References = append([]string(nil), rule.Verification.References...)
			cloned[index].Verification = &verification
		}
		cloned[index].Definition.Matchers = cloneMatchers(rule.Definition.Matchers)
		cloned[index].Definition.Requests = make([]rulelib.Request, len(rule.Definition.Requests))
		for requestIndex, request := range rule.Definition.Requests {
			cloned[index].Definition.Requests[requestIndex] = request
			cloned[index].Definition.Requests[requestIndex].Matchers = cloneMatchers(request.Matchers)
			if request.Headers != nil {
				cloned[index].Definition.Requests[requestIndex].Headers = make(map[string]string, len(request.Headers))
				for name, value := range request.Headers {
					cloned[index].Definition.Requests[requestIndex].Headers[name] = value
				}
			}
		}
	}
	return cloned
}

func cloneMatchers(matchers []rulelib.Matcher) []rulelib.Matcher {
	cloned := make([]rulelib.Matcher, len(matchers))
	for index, matcher := range matchers {
		cloned[index] = matcher
		cloned[index].Words = append([]string(nil), matcher.Words...)
		cloned[index].Regex = append([]string(nil), matcher.Regex...)
		cloned[index].Status = append([]int(nil), matcher.Status...)
	}
	return cloned
}
