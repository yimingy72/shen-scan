package rulelib

import "testing"

func TestHTTPCollectionIsolationAndBindings(t *testing.T) {
	// Legacy/custom collection parsing remains compatible; no collection is seeded.
	gitlab := Rule{ID: "legacy-custom-http-collect", Kind: "http", Engine: "native", Name: "GitLab legacy confirmation", Severity: "info", Enabled: true, Revision: 1,
		Collection: &HTTPCollection{Path: "/-/health", Products: []string{"GitLab"}},
		Definition: Definition{Product: "GitLab", Condition: "and", Matchers: []Matcher{{Part: "status", Type: "status", Status: []int{200}}, {Part: "body", Type: "word", Words: []string{"GitLab OK"}}}}}
	if err := Validate(gitlab); err != nil {
		t.Fatal(err)
	}
	if !CollectionMatchesProducts(gitlab, []string{"GitLab"}) || CollectionMatchesProducts(gitlab, []string{"UnknownProduct"}) {
		t.Fatal("legacy product bindings changed")
	}
	input := Input{Status: 200, Body: "GitLab OK\n"}
	if _, ok := Match(gitlab, input); ok {
		t.Fatal("collection rule incorrectly matched the primary page")
	}
	if _, ok := MatchCollectedHTTP(gitlab, input); !ok {
		t.Fatal("separate confirmation response did not match")
	}
	if _, ok := MatchCollectedHTTP(gitlab, Input{Status: 404, Body: input.Body}); ok {
		t.Fatal("matched a wrong-status confirmation")
	}
	for _, path := range []string{"https://outside.test/", "//outside.test/", "/../private", "/?action=reset"} {
		copy := gitlab
		collection := *gitlab.Collection
		collection.Path = path
		copy.Collection = &collection
		if Validate(copy) == nil {
			t.Fatalf("invalid collection path accepted: %s", path)
		}
	}
	copy := gitlab
	copy.Kind = "poc"
	if Validate(copy) == nil {
		t.Fatal("PoC rule may not carry HTTP collection execution")
	}
}
