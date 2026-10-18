package fingerprinthub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/chainreactors/utils/encode"
	"regexp"
	"sort"
	"strings"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/logs"
	"gopkg.in/yaml.v3"
)

// activeLoader is set by active.go's init() to load full templates
// for HTTPActiveMatch and ServiceMatch. Nil in passive_only builds.
var activeLoader func(engine *FingerPrintHubEngine, webRaw, serviceRaw []map[string]interface{}) error

// FingerPrintHubEngine provides fingerprint matching using neutron-style templates.
type FingerPrintHubEngine struct {
	legacyPassive    bool
	webTemplates     []*passiveTemplate
	webTemplateIndex *TemplateKeywordIndex

	// CaseInsensitive controls whether matching ignores case (default true).
	CaseInsensitive bool

	// MatchDetailEnabled records on each hit the snippet its matcher matched.
	// Hits then skip the keyword-index fast path, which knows no snippet.
	MatchDetailEnabled bool

	// active holds full neutron templates for HTTPActiveMatch/ServiceMatch.
	// Nil in passive_only builds.
	active *activeState
}

// NewFingerPrintHubEngine creates a new engine instance.
func NewFingerPrintHubEngine(webData, serviceData []byte) (*FingerPrintHubEngine, error) {
	engine := &FingerPrintHubEngine{
		CaseInsensitive: true,
	}

	var webRaw []map[string]interface{}
	if err := resources.UnmarshalData(webData, &webRaw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal web fingerprints: %w", err)
	}

	var serviceRaw []map[string]interface{}
	if err := resources.UnmarshalData(serviceData, &serviceRaw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service fingerprints: %w", err)
	}

	webCount, webErrors := engine.loadPassiveTemplates(webRaw)

	if len(webErrors) > 0 {
		return nil, fmt.Errorf("FingerprintHub passive compile: %v", webErrors)
	}
	if len(webErrors) > 0 && len(webErrors) < 10 {
		for _, e := range webErrors {
			logs.Log.Warn(e)
		}
	}

	// Load active templates if the active build is linked
	if activeLoader != nil {
		if err := activeLoader(engine, webRaw, serviceRaw); err != nil {
			return nil, err
		}
	}

	logs.Log.Infof("resources type=fingerprints source=fingerprinthub web=%d", webCount)

	engine.webTemplateIndex = NewTemplateKeywordIndex(engine.webTemplates)

	return engine, nil
}

func (engine *FingerPrintHubEngine) loadPassiveTemplates(templateData []map[string]interface{}) (int, []error) {
	loadedCount := 0
	var errors []error

	for _, raw := range templateData {
		sanitizeTemplateForTinyGo(raw)

		pt, err := parsePassiveTemplate(raw)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if len(pt.requests) == 0 {
			continue
		}

		if engine.CaseInsensitive {
			for _, req := range pt.requests {
				for _, matcher := range req.Matchers {
					if matcher.Type == "word" {
						matcher.CaseInsensitive = true
					}
				}
				if req.compiledOperators != nil {
					req.compiledOperators.Compile()
				}
			}
		}

		engine.webTemplates = append(engine.webTemplates, pt)
		loadedCount++
	}

	return loadedCount, errors
}

// LoadFromJSON loads fingerprints from JSON data.
func (engine *FingerPrintHubEngine) LoadFromJSON(data []byte) error {
	var templateData []map[string]interface{}
	if err := json.Unmarshal(data, &templateData); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	loadedCount := 0
	var errors []error

	for _, raw := range templateData {
		sanitizeTemplateForTinyGo(raw)

		pt, err := parsePassiveTemplate(raw)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if len(pt.requests) == 0 {
			continue
		}

		if engine.CaseInsensitive {
			for _, req := range pt.requests {
				for _, matcher := range req.Matchers {
					if matcher.Type == "word" {
						matcher.CaseInsensitive = true
					}
				}
				if req.compiledOperators != nil {
					req.compiledOperators.Compile()
				}
			}
		}

		engine.webTemplates = append(engine.webTemplates, pt)
		loadedCount++
	}

	if len(errors) > 0 && len(errors) < 10 {
		for _, e := range errors {
			logs.Log.Warn(e)
		}
	}
	_ = loadedCount

	return nil
}

// Name returns the engine name.
func (engine *FingerPrintHubEngine) Name() string {
	return "fingerprinthub"
}

// Len returns the number of fingerprints.
func (engine *FingerPrintHubEngine) Len() int {
	n := len(engine.webTemplates)
	if engine.active != nil {
		// active.go exposes activeLen()
		n += activeServiceLen(engine)
	}
	return n
}

// Compile is a no-op — templates are compiled during loading.
func (engine *FingerPrintHubEngine) Compile() error {
	return nil
}

// Capability returns the engine's capabilities.
func (engine *FingerPrintHubEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,
		SupportService: engine.active != nil,
	}
}

// WebMatch performs passive web fingerprint matching against raw HTTP content.
func (engine *FingerPrintHubEngine) WebMatch(content []byte) common.Frameworks {
	event, ok := parseRawHTTPEvent(content, engine.CaseInsensitive)
	if !ok {
		return make(common.Frameworks)
	}

	if engine.legacyPassive {
		body := content
		if i := bytes.Index(content, []byte("\r\n\r\n")); i >= 0 {
			body = content[i+4:]
		} else if i := bytes.Index(content, []byte("\n\n")); i >= 0 {
			body = content[i+2:]
		}
		event["favicon_hash"] = encode.Mmh3Hash32(body)
	}
	frames := make(common.Frameworks)

	bodyStr, _ := event["body"].(string)
	headerStr, _ := event["all_headers"].(string)
	lowerBodyStr := bodyStr
	lowerHeaderStr := headerStr
	if !engine.CaseInsensitive {
		lowerBodyStr = strings.ToLower(bodyStr)
		lowerHeaderStr = strings.ToLower(headerStr)
	}

	mr := engine.webTemplateIndex.Match(lowerHeaderStr, lowerBodyStr)

	if engine.CaseInsensitive && !engine.MatchDetailEnabled {
		for _, ti := range sortedIndices(mr.Matched) {
			frames.Add(engine.newFramework(engine.webTemplates[ti]))
		}
	}

	if !engine.CaseInsensitive || engine.MatchDetailEnabled {
		for ti := range mr.Matched {
			mr.NeedsCheck[ti] = true
		}
	}
	// Templates run in index order: the first to hit a product keeps its details.
	for _, ti := range sortedIndices(mr.NeedsCheck) {
		tmpl := engine.webTemplates[ti]
		if len(tmpl.requests) == 0 {
			continue
		}

		for _, req := range tmpl.requests {
			if len(req.Matchers) == 0 {
				continue
			}
			if matched, detail := matchPassiveRequestDetail(req, event); matched {
				frame := engine.newFramework(tmpl)
				if engine.MatchDetailEnabled {
					frame.MatchDetail = detail
				}
				frames.Add(frame)
				break
			}
		}
	}

	return frames
}

func (engine *FingerPrintHubEngine) newFramework(tmpl *passiveTemplate) *common.Framework {
	name := tmpl.name
	if name == "" {
		name = tmpl.id
	}
	frame := common.NewFramework(name, common.FrameFromFingerprintHub)
	if tmpl.metadata != nil {
		if vendor, ok := tmpl.metadata["vendor"].(string); ok {
			frame.Attributes.Vendor = vendor
		}
		if product, ok := tmpl.metadata["product"].(string); ok {
			frame.Attributes.Product = product
		}
	}
	return frame
}

// ─── Helpers shared between passive and active builds ───

// activeServiceLen returns the number of service templates in active state.
// Called from Len() — safe to call when engine.active is nil.
func activeServiceLen(engine *FingerPrintHubEngine) int {
	_ = engine
	return 0 // overridden by active.go via init or linker
}

// yamlMarshal is a convenience wrapper.
func yamlMarshal(v interface{}) ([]byte, error) {
	return yaml.Marshal(v)
}

func sortedIndices(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for i := range set {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

// WebMatchWithIcons evaluates the original matcher condition against page
// body/headers plus one associated icon, never the HTML body as favicon bytes.
func (engine *FingerPrintHubEngine) WebMatchWithIcons(content []byte, icons [][]byte) common.Frameworks {
	event, ok := parseRawHTTPEvent(content, engine.CaseInsensitive)
	frames := make(common.Frameworks)
	if !ok {
		return frames
	}
	for _, tmpl := range engine.webTemplates {
		for _, req := range tmpl.requests {
			events := []string{""}
			for _, icon := range icons {
				events = append(events, encode.Mmh3Hash32(icon)+" "+encode.Md5Hash(icon))
			}
			matched := false
			for _, hash := range events {
				delete(event, "favicon_hash")
				if hash != "" {
					event["favicon_hash"] = hash
				}
				if ok, detail := matchPassiveRequestDetail(req, event); ok {
					frame := engine.newFramework(tmpl)
					if engine.MatchDetailEnabled {
						frame.MatchDetail = detail
					}
					frames.Add(frame)
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}
	return frames
}

// EnableLegacyPassive reproduces the pinned v1 embedded passive compiler and event profile.
func (engine *FingerPrintHubEngine) EnableLegacyPassive() {
	engine.legacyPassive = true
	accepted := make([]*passiveTemplate, 0, len(engine.webTemplates))
	for _, t := range engine.webTemplates {
		valid := true
		for _, r := range t.requests {
			for _, m := range r.Matchers {
				for _, expr := range m.Regex {
					if _, err := regexp.Compile(expr); err != nil {
						valid = false
					}
				}
			}
			for _, e := range r.Extractors {
				for _, expr := range e.Regex {
					if _, err := regexp.Compile(expr); err != nil {
						valid = false
					}
				}
			}
		}
		if valid {
			accepted = append(accepted, t)
		}
	}
	engine.webTemplates = accepted
	engine.webTemplateIndex = NewTemplateKeywordIndex(accepted)
}
