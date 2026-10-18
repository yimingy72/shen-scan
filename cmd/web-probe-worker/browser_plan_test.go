package main

import (
	"scanplatform/internal/webevidence"
	"scanplatform/webprobe/browserfp"
	"testing"
)

func TestBrowserExecutionPlanCache(t *testing.T) {
	cff := []byte(`{"apps":{"Cached":{"js":{"Cached.version":""}}}}`)
	digest := webevidence.SHA256(cff)
	first, err := cachedBrowserExecutionPlan(cff, digest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cachedBrowserExecutionPlan(cff, digest)
	if err != nil || second.matcher != first.matcher || second.collector != first.collector || second.planSHA256 != first.planSHA256 {
		t.Fatal("immutable plan/collector cache missed")
	}
	positive := first.matcher.Match(browserfp.Observations{JS: map[string]browserfp.Value{"Cached.version": {Exists: true, Type: "string", Value: "1.2"}}})
	absent := second.matcher.Match(browserfp.Observations{JS: map[string]browserfp.Value{"Cached.version": {Exists: false, Type: "undefined"}}})
	if len(positive.Matches) != 1 || len(absent.Matches) != 0 {
		t.Fatal("entry-specific matches were cached with plan")
	}
	changed := []byte(`{"apps":{"Other":{"js":{"Other.version":""}}}}`)
	different, err := cachedBrowserExecutionPlan(changed, webevidence.SHA256(changed))
	if err != nil || different.planSHA256 == first.planSHA256 || different.collector == first.collector {
		t.Fatal("CFF change reused old collector")
	}
}
