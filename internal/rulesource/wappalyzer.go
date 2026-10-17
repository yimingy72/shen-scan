package rulesource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"scanplatform/internal/rulelib"
)

const WappalyzerLicenseText = `MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

const maxWappalyzerBytes = 32 << 20

type wappalyzerDocument struct {
	Apps map[string]json.RawMessage `json:"apps"`
}

func ConvertWappalyzer(data []byte) (Catalog, error) {
	if len(data) == 0 || len(data) > maxWappalyzerBytes {
		return Catalog{}, fmt.Errorf("wappalyzer catalog must be 1..%d bytes", maxWappalyzerBytes)
	}
	var document wappalyzerDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return Catalog{}, fmt.Errorf("decode wappalyzer catalog: %w", err)
	}
	if len(document.Apps) == 0 {
		return Catalog{}, fmt.Errorf("wappalyzer catalog has no apps")
	}
	digest := sha256.Sum256(data)
	digestHex := hex.EncodeToString(digest[:])
	catalog := Catalog{
		Rules: make([]rulelib.Rule, 0, len(document.Apps)), Total: len(document.Apps), Skipped: map[string]int{},
		Revision: digestHex[:16], Digest: "sha256:" + digestHex, Repository: WappalyzerRepository,
		License: WappalyzerLicense, LicenseText: WappalyzerLicenseText,
		Files: []SourceFile{{Path: "fingerprints_data.json", SHA256: digestHex, Data: append([]byte(nil), data...)}},
	}
	names := make([]string, 0, len(document.Apps))
	for name := range document.Apps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := document.Apps[name]
		if name == "" || len(name) > 200 || !utf8.ValidString(name) {
			catalog.Skipped["product-invalid"]++
			addSample(&catalog, "apps."+name, "product name is empty, invalid UTF-8, or exceeds 200 bytes")
			continue
		}
		var app map[string]any
		if len(raw) == 0 || json.Unmarshal(raw, &app) != nil || app == nil {
			catalog.Skipped["product-invalid"]++
			addSample(&catalog, "apps."+name, "fingerprint must be a JSON object")
			continue
		}
		appDigest := sha256.Sum256(raw)
		description, _ := app["description"].(string)
		rule := rulelib.Rule{
			ID: stableWappalyzerID(name), Kind: "http", Purpose: "discovery", Name: name,
			Description: truncateWappalyzerText(description, 4096), Engine: "httpx-cff", Severity: "info",
			Enabled: true, Builtin: false, Revision: 1, Tags: []string{"fingerprint", "http", WappalyzerID},
			Upstream:    &rulelib.Upstream{SourceID: WappalyzerID, Path: "fingerprints_data.json", SHA256: hex.EncodeToString(appDigest[:])},
			Fingerprint: append(json.RawMessage(nil), raw...), Source: WappalyzerRepository,
			Definition: rulelib.Definition{Service: "http", Product: name},
		}
		if err := rulelib.Validate(rule); err != nil {
			catalog.Skipped["product-invalid"]++
			addSample(&catalog, "apps."+name, err.Error())
			continue
		}
		catalog.Rules = append(catalog.Rules, rule)
	}
	return catalog, nil
}

func addSample(catalog *Catalog, path, reason string) {
	if len(catalog.Samples) < 100 {
		catalog.Samples = append(catalog.Samples, Rejection{Path: path, Reason: reason})
	}
}

func stableWappalyzerID(name string) string {
	digest := sha256.Sum256([]byte(name))
	slug := strings.Trim(slugify(name), "-")
	if slug == "" {
		slug = "product"
	}
	if len(slug) > 59 {
		slug = strings.TrimRight(slug[:59], "-")
	}
	return "wa-" + slug + "-" + hex.EncodeToString(digest[:])
}

func slugify(value string) string {
	var output strings.Builder
	dash := false
	for _, char := range strings.ToLower(value) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			output.WriteRune(char)
			dash = false
		} else if output.Len() > 0 && !dash {
			output.WriteByte('-')
			dash = true
		}
	}
	return output.String()
}

func truncateWappalyzerText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	value = value[:max]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
