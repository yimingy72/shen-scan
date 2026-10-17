package rulelib

import (
	"container/list"
	"regexp"
	"sync"
)

const patternCacheLimit = 8192

func matcherPattern(pattern string, caseSensitive bool) string {
	if caseSensitive {
		return pattern
	}
	return "(?i:" + pattern + ")"
}

type cachedPattern struct {
	key        string
	expression *regexp.Regexp
	err        error
}

var patternCache = struct {
	sync.Mutex
	entries map[string]*list.Element
	order   *list.List
}{entries: make(map[string]*list.Element), order: list.New()}

// A bounded cache avoids compiling the same upstream patterns for every target.
// Patterns retain their complete flags and anchors as part of the cache key.
func compilePattern(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > 4096 {
		return regexp.Compile(pattern)
	}
	patternCache.Lock()
	if item := patternCache.entries[pattern]; item != nil {
		patternCache.order.MoveToFront(item)
		value := item.Value.(cachedPattern)
		patternCache.Unlock()
		return value.expression, value.err
	}
	patternCache.Unlock()
	expression, err := regexp.Compile(pattern)
	patternCache.Lock()
	defer patternCache.Unlock()
	if item := patternCache.entries[pattern]; item != nil {
		patternCache.order.MoveToFront(item)
		value := item.Value.(cachedPattern)
		return value.expression, value.err
	}
	item := patternCache.order.PushFront(cachedPattern{pattern, expression, err})
	patternCache.entries[pattern] = item
	if patternCache.order.Len() > patternCacheLimit {
		oldest := patternCache.order.Back()
		delete(patternCache.entries, oldest.Value.(cachedPattern).key)
		patternCache.order.Remove(oldest)
	}
	return expression, err
}
