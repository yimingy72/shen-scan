package rulelib

import (
	"sync"
	"testing"
)

func TestPatternCacheKeepsMatchingSemanticsConcurrent(t *testing.T) {
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			sensitive, err := compilePattern(`^Product$`)
			if err != nil || !sensitive.MatchString("Product") || sensitive.MatchString("product") {
				t.Error("case-sensitive pattern changed")
			}
			folded, err := compilePattern(`(?i:^Product$)`)
			if err != nil || !folded.MatchString("product") || folded.MatchString("not Product") {
				t.Error("pattern flags or anchors changed")
			}
			if _, err = compilePattern(`[`); err == nil {
				t.Error("invalid expression accepted")
			}
		}()
	}
	group.Wait()
}
