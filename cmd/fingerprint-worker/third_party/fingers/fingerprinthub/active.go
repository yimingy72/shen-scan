//go:build !passive_only
// +build !passive_only

package fingerprinthub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

type activeState struct {
	webTemplates     []*templates.Template
	webHashes        []string
	serviceTemplates []*templates.Template
	executerOptions  *protocols.ExecuterOptions
}

func init() {
	activeLoader = func(engine *FingerPrintHubEngine, webRaw, serviceRaw []map[string]interface{}) error {
		engine.active = &activeState{
			executerOptions: &protocols.ExecuterOptions{
				Options: &protocols.Options{Timeout: 10},
			},
		}

		for _, raw := range webRaw {
			sanitizeTemplateForTinyGo(raw)
			yamlBytes, err := yaml.Marshal(raw)
			if err != nil {
				return fmt.Errorf("FingerprintHub template %v: %w", raw["id"], err)
			}
			tmpl := &templates.Template{}
			if err := yaml.Unmarshal(yamlBytes, tmpl); err != nil {
				return fmt.Errorf("FingerprintHub template %v: %w", raw["id"], err)
			}
			if engine.CaseInsensitive {
				for _, req := range tmpl.GetRequests() {
					for _, matcher := range req.Matchers {
						if matcher.Type == "word" {
							matcher.CaseInsensitive = true
						}
					}
				}
			}
			if err := tmpl.Compile(engine.active.executerOptions); err != nil {
				return fmt.Errorf("FingerprintHub template %v: %w", raw["id"], err)
			}
			engine.active.webTemplates = append(engine.active.webTemplates, tmpl)
			canonical, _ := json.Marshal(raw)
			engine.active.webHashes = append(engine.active.webHashes, common.SourceRecordHash(canonical))
		}

		for _, raw := range serviceRaw {
			sanitizeTemplateForTinyGo(raw)
			yamlBytes, err := yaml.Marshal(raw)
			if err != nil {
				return fmt.Errorf("FingerprintHub template %v: %w", raw["id"], err)
			}
			tmpl := &templates.Template{}
			if err := yaml.Unmarshal(yamlBytes, tmpl); err != nil {
				return fmt.Errorf("FingerprintHub template %v: %w", raw["id"], err)
			}
			if err := tmpl.Compile(engine.active.executerOptions); err != nil {
				return fmt.Errorf("FingerprintHub template %v: %w", raw["id"], err)
			}
			for _, netReq := range tmpl.RequestsNetwork {
				for _, input := range netReq.Inputs {
					if input.Read == 0 {
						input.Read = 1024
					}
				}
				if netReq.ReadSize == 0 {
					netReq.ReadSize = 1024
				}
			}
			engine.active.serviceTemplates = append(engine.active.serviceTemplates, tmpl)
		}
		return nil
	}
}

// HTTPActiveMatch performs active HTTP fingerprinting using a provided transport.
func (engine *FingerPrintHubEngine) HTTPActiveMatch(baseURL string, level int, transport http.RoundTripper, callback func(*common.Framework, *common.Vuln)) (common.Frameworks, common.Vulns) {
	if baseURL == "" || transport == nil || engine.active == nil {
		return nil, nil
	}

	allFrameworks := make(common.Frameworks)
	allVulns := make(common.Vulns)

	for _, tmpl := range engine.active.webTemplates {
		if len(tmpl.RequestsHTTP) == 0 {
			continue
		}
		result, err := tmpl.ExecuteWithTransport(baseURL, nil, transport)
		if err == nil && result != nil && result.Matched {
			name := tmpl.Info.Name
			if name == "" {
				name = tmpl.Id
			}
			frame := common.NewFramework(name, common.FrameFromFingerprintHub)
			if tmpl.Info.Metadata != nil {
				if vendor, ok := tmpl.Info.Metadata["vendor"].(string); ok {
					frame.Attributes.Vendor = vendor
				}
				if product, ok := tmpl.Info.Metadata["product"].(string); ok {
					frame.Attributes.Product = product
				}
			}
			allFrameworks.Add(frame)
			if callback != nil {
				callback(frame, nil)
			}
		}
	}

	return allFrameworks, allVulns
}

// ServiceMatch performs service fingerprinting via network probes.
func (engine *FingerPrintHubEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	if engine.active == nil {
		return nil
	}

	target := fmt.Sprintf("%s:%s", host, portStr)
	scanCtx := &protocols.ScanContext{Input: target}

	for _, tmpl := range engine.active.serviceTemplates {
		if len(tmpl.RequestsNetwork) == 0 {
			continue
		}
		for _, networkReq := range tmpl.RequestsNetwork {
			var matched bool
			networkReq.ExecuteWithResults(scanCtx, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
				if event.OperatorsResult != nil {
					if event.OperatorsResult.Matched || len(event.OperatorsResult.OutputExtracts()) > 0 {
						matched = true
						name := tmpl.Info.Name
						if name == "" {
							name = tmpl.Id
						}
						frame := common.NewFramework(name, common.FrameFromFingerprintHub)
						if tmpl.Info.Metadata != nil {
							if vendor, ok := tmpl.Info.Metadata["vendor"].(string); ok {
								frame.Attributes.Vendor = vendor
							}
							if product, ok := tmpl.Info.Metadata["product"].(string); ok {
								frame.Attributes.Product = product
							}
						}
						if callback != nil {
							callback(&common.ServiceResult{Framework: frame})
						}
					}
				}
			})
			_ = matched
		}
	}

	return nil
}

// HTTPTemplate identifies a complete original neutron request chain.
type HTTPTemplate struct {
	ID, Name string
	Requests int
}

func (engine *FingerPrintHubEngine) HTTPTemplates() []HTTPTemplate {
	var out []HTTPTemplate
	if engine.active == nil {
		return out
	}
	for i, t := range engine.active.webTemplates {
		out = append(out, HTTPTemplate{ID: common.SourceUnitID("fingerprinthub", fmt.Sprintf("resources/fingerprinthub_web.json.gz#/%d", i), t.Id, engine.active.webHashes[i]), Name: t.Info.Name, Requests: t.TotalRequests})
	}
	return out
}
func (engine *FingerPrintHubEngine) HTTPTemplateMatch(ctx context.Context, id, baseURL string, transport http.RoundTripper) (*common.Framework, error) {
	if engine.active == nil {
		return nil, fmt.Errorf("active HTTP templates unavailable")
	}
	for i, t := range engine.active.webTemplates {
		if id != common.SourceUnitID("fingerprinthub", fmt.Sprintf("resources/fingerprinthub_web.json.gz#/%d", i), t.Id, engine.active.webHashes[i]) {
			continue
		}
		result, err := t.ExecuteWithContextAndTransport(ctx, baseURL, nil, transport)
		if err != nil {
			return nil, err
		}
		if result == nil || !result.Matched {
			return nil, nil
		}
		name := t.Info.Name
		if name == "" {
			name = t.Id
		}
		frame := common.NewFramework(name, common.FrameFromFingerprintHub)
		frame.MatchDetail = &common.MatchDetail{MatcherType: "template", MatcherValue: t.Id}
		if t.Info.Metadata != nil {
			if v, ok := t.Info.Metadata["vendor"].(string); ok {
				frame.Attributes.Vendor = v
			}
			if v, ok := t.Info.Metadata["product"].(string); ok {
				frame.Attributes.Product = v
			}
		}
		return frame, nil
	}
	return nil, fmt.Errorf("unknown HTTP template %s", id)
}
