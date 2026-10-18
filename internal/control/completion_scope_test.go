package control

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestPortCompletionScopeExcludesStatisticalProfile(t *testing.T) {
	base := `{"port_cost_profile":"artifact-a","ports":"1-65535","targets":["192.0.2.1"],"rate_pps":5000,"wait_seconds":15,"execution_timeout_seconds":180,"http_enabled":true,"extra":{"port_cost_profile":"nested-execution-value"},"exact_number":9007199254740993}`
	want := completionScopeHash("port", []byte(base))
	if got := completionScopeHash("port", []byte(strings.Replace(base, "artifact-a", "artifact-b", 1))); got != want {
		t.Fatal("statistical artifact identity changed execution scope")
	}
	for _, change := range []struct{ old, replacement string }{
		{`"1-65535"`, `"1-32767"`},
		{`"192.0.2.1"`, `"192.0.2.2"`},
		{`5000`, `10000`},
		{`15`, `10`},
		{`180`, `120`},
		{`true`, `false`},
		{`nested-execution-value`, `different-nested-value`},
		{`9007199254740993`, `9007199254740992`},
	} {
		if got := completionScopeHash("port", []byte(strings.Replace(base, change.old, change.replacement, 1))); got == want {
			t.Fatalf("execution field change %q did not alter scope", change.old)
		}
	}
	legacy := []byte("{\n  \"ports\": \"1-65535\", \"targets\": [\"192.0.2.1\"], \"rate_pps\": 5000\n}\n")
	if got := completionScopeHash("port", legacy); got != sha256.Sum256(legacy) {
		t.Fatal("legacy scope input was re-encoded")
	}
	if got := completionScopeHash("http", []byte(base)); got != sha256.Sum256([]byte(base)) {
		t.Fatal("non-port scope behavior changed")
	}
}
