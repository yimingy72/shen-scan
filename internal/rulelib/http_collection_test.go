package rulelib

import "testing"

func TestHTTPCollectionIsolationAndBindings(t *testing.T) {
	rules := builtinHTTPCollections(append(builtinPoCRules(), expandedPoCRules()...))
	if len(rules) != 6 {
		t.Fatalf("explicit collection list: got %d, want 6", len(rules))
	}
	var gitlab Rule
	for _, rule := range rules {
		if err := Validate(rule); err != nil {
			t.Fatalf("%s: %v", rule.ID, err)
		}
		if !CollectionMatchesProducts(rule, []string{rule.Definition.Product}) || CollectionMatchesProducts(rule, []string{"UnknownProduct"}) {
			t.Fatalf("invalid candidate selection: %s", rule.ID)
		}
		if rule.Definition.Product == "GitLab" {
			gitlab = rule
		}
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
