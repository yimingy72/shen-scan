package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cms"
)

func (c *controller) pollInterruptionEvents(ctx context.Context, instances map[string]*managedInstance) error {
	now := time.Now().UTC()
	seen := make(map[string]bool)
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		request := cms.CreateDescribeSystemEventAttributeRequest()
		request.Product = "ECS"
		request.EventType = "StatusNotification"
		request.Name = "Instance:PreemptibleInstanceInterruption"
		request.StartTime = strconv.FormatInt(now.Add(-10*time.Minute).UnixMilli(), 10)
		request.EndTime = strconv.FormatInt(now.UnixMilli(), 10)
		request.PageNumber = requests.NewInteger(page)
		request.PageSize = requests.NewInteger(100)
		response, err := c.cms.DescribeSystemEventAttribute(request)
		if err != nil {
			return err
		}
		for _, event := range response.SystemEvents.SystemEvent {
			isDelete, ids := parseInterruptionContent(event.Content)
			if isDelete && len(ids) == 0 && event.ResourceId != "" {
				ids = append(ids, event.ResourceId)
			}
			for _, id := range ids {
				instance := instances[id]
				if instance == nil || seen[id] {
					continue
				}
				seen[id] = true
				c.markDraining(ctx, instance, "Alibaba Cloud spot interruption event", nil)
			}
		}
		if len(response.SystemEvents.SystemEvent) < 100 {
			return nil
		}
	}
}

func parseInterruptionContent(raw string) (bool, []string) {
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return false, nil
	}
	ids := make(map[string]bool)
	deleted := walkEvent(value, false, ids)
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	return deleted, out
}

func walkEvent(value any, inheritedDelete bool, ids map[string]bool) bool {
	switch current := value.(type) {
	case map[string]any:
		deleted := inheritedDelete
		for key, child := range current {
			if normalizeKey(key) == "action" && strings.EqualFold(fmt.Sprint(child), "delete") {
				deleted = true
			}
		}
		foundDelete := deleted
		for key, child := range current {
			normalized := normalizeKey(key)
			if deleted && (normalized == "instanceid" || normalized == "instanceids" || normalized == "resourceid") {
				collectIDs(child, ids)
			}
			if walkEvent(child, deleted, ids) {
				foundDelete = true
			}
		}
		return foundDelete
	case []any:
		deleted := inheritedDelete
		for _, child := range current {
			if walkEvent(child, inheritedDelete, ids) {
				deleted = true
			}
		}
		return deleted
	case string:
		trimmed := strings.TrimSpace(current)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, `"`) {
			var nested any
			if json.Unmarshal([]byte(trimmed), &nested) == nil {
				return walkEvent(nested, inheritedDelete, ids)
			}
		}
	}
	return inheritedDelete
}

func collectIDs(value any, ids map[string]bool) {
	switch current := value.(type) {
	case string:
		if current = strings.TrimSpace(current); current != "" {
			ids[current] = true
		}
	case []any:
		for _, item := range current {
			collectIDs(item, ids)
		}
	}
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
}
