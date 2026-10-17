package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

func canonicalTarget(value string) string {
	if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
		value = u.Hostname()
	}
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.String()
	}
	return value
}

func taskTargetKeys(payload []byte) []string {
	var p struct {
		Targets   []string                         `json:"targets"`
		Endpoints []struct{ IP, Host, URL string } `json:"endpoints"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	keys := make(map[string]bool)
	for _, value := range p.Targets {
		if key := canonicalTarget(value); key != "" {
			keys[key] = true
		}
	}
	for _, ep := range p.Endpoints {
		value := ep.Host
		if value == "" {
			value = ep.URL
		}
		if value == "" {
			value = ep.IP
		}
		if key := canonicalTarget(value); key != "" {
			keys[key] = true
		}
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func insertTaskTargets(ctx context.Context, tx pgx.Tx, taskID string, payload []byte) error {
	keys := taskTargetKeys(payload)
	if len(keys) == 0 {
		return errors.New("task has no source targets")
	}
	rows := make([][]any, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, []any{taskID, key})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"task_targets"}, []string{"task_id", "target_key"}, pgx.CopyFromRows(rows))
	return err
}

func observationTarget(typeName string, payload []byte, source string, item Observation) (string, error) {
	if item.Kind != typeName {
		return "", errors.New("observation kind does not match task type")
	}
	keys := taskTargetKeys(payload)
	if len(keys) == 0 {
		return "", errors.New("task has no source target")
	}
	if typeName == "http" {
		if source == "" {
			source = keys[0]
		}
		if item.Target != "" && !contains(keys, canonicalTarget(item.Target)) {
			return "", errors.New("HTTP observation belongs to a different source target")
		}
		return source, nil
	}
	value := item.IP
	if value == "" {
		value = item.Target
	}
	key := canonicalTarget(value)
	if !contains(keys, key) {
		return "", errors.New("observation IP is outside the task targets")
	}
	if item.Port < 1 || item.Port > 65535 {
		return "", errors.New("observation port is outside TCP 1–65535")
	}
	if typeName == "service" {
		var p struct {
			Endpoints []struct {
				IP   string
				Port int
			} `json:"endpoints"`
		}
		if json.Unmarshal(payload, &p) != nil {
			return "", errors.New("invalid endpoint payload")
		}
		found := false
		for _, ep := range p.Endpoints {
			if canonicalTarget(ep.IP) == key && ep.Port == item.Port {
				found = true
				break
			}
		}
		if !found {
			return "", errors.New("service observation is outside assigned endpoints")
		}
	}
	return key, nil
}
