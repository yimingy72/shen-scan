package control

import (
	"context"
	"encoding/json"
	"testing"

	"scanplatform/internal/rulelib"
)

func TestPostgresBuiltinHTTPRetirement(t *testing.T) {
	s, _ := newPolicyTestServer(t, "http_retirement")
	ctx := context.Background()
	ids, sources := rulelib.RetiredHTTPSeeds()
	if len(ids) != 157 || len(sources) != len(ids) {
		t.Fatalf("retirement manifest: %d IDs, %d sources", len(ids), len(sources))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate retired ID %s", id)
		}
		seen[id] = true
	}
	var original rulelib.Rule
	for index := 0; index < 3; index++ {
		rule := rulelib.Rule{ID: ids[index], Source: sources[index], Kind: "http", Engine: "native", Name: "retirement fixture", Builtin: true, Enabled: true, Severity: "info", Revision: 1,
			Definition: rulelib.Definition{Product: "Legacy", Matchers: []rulelib.Matcher{{Part: "status", Type: "status", Status: []int{200}}}}}
		if index == 0 {
			original = rule
		}
		if index == 1 {
			rule.Builtin = false
		}
		if index == 2 {
			rule.Source = "user-owned different source"
		}
		raw, _ := json.Marshal(rule)
		if _, err := s.db.Exec(ctx, `INSERT INTO rule_library(id,rule,seed_version) VALUES($1,$2,1)`, rule.ID, raw); err != nil {
			t.Fatal(err)
		}
	}
	runID := newID()
	snapshot, _ := json.Marshal(ruleSnapshot{HTTP: []rulelib.Rule{original}})
	if _, err := s.db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,rules_snapshot) VALUES($1,'historical retirement fixture','["192.0.2.4"]','{http}','pending',$2)`, runID, snapshot); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		if err := seedRuleLibrary(ctx, s.db); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 3; index++ {
			var deleted bool
			if err := s.db.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM rule_library WHERE id=$1`, ids[index]).Scan(&deleted); err != nil {
				t.Fatal(err)
			}
			if deleted != (index == 0) {
				t.Fatalf("iteration %d, fixture %d deleted=%t", iteration, index, deleted)
			}
		}
	}
	var raw []byte
	if err := s.db.QueryRow(ctx, `SELECT rules_snapshot FROM runs WHERE id=$1`, runID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var preserved ruleSnapshot
	if json.Unmarshal(raw, &preserved) != nil || len(preserved.HTTP) != 1 || preserved.HTTP[0].ID != original.ID {
		t.Fatal("historical snapshot was rewritten")
	}
	for _, rule := range rulelib.Builtins() {
		if rule.Kind == "http" {
			t.Fatalf("HTTP builtin would be reseeded: %s", rule.ID)
		}
	}
}
