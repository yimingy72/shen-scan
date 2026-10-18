package fingerprintbundle

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// CatalogRecord indexes original source records; it is never a converted rule.
type CatalogRecord struct {
	UnitKey           string   `json:"unit_key"`
	Engine            string   `json:"engine"`
	Source            string   `json:"source"`
	SourceRecord      string   `json:"source_record"`
	SourceRevision    string   `json:"source_revision"`
	OriginalID        string   `json:"original_id"`
	Path              string   `json:"path"`
	Index             int      `json:"index"`
	ContentHash       string   `json:"content_hash"`
	Name              string   `json:"name"`
	Capabilities      []string `json:"capabilities"`
	LoadStatus        string   `json:"load_status"`
	OriginalReference string   `json:"original_reference"`
}

// UnitKey binds progress to one unchanged original source record.
func UnitKey(engine, source, id, contentHash string) string {
	return engine + ":" + Digest([]byte(strings.Join([]string{engine, source, id, contentHash}, "\x00")))
}
func CanonicalRecord(raw []byte) ([]byte, error) {
	var record any
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	return json.Marshal(record)
}

func (p Package) Catalog() ([]CatalogRecord, error) {
	if err := Validate(p); err != nil {
		return nil, err
	}
	var catalog []CatalogRecord
	for _, path := range p.Paths() {
		decoded, err := DecodeRaw(path, p.Files[path].Raw)
		if err != nil {
			return nil, err
		}
		engine := ""
		wrapped := false
		switch path {
		case "resources/fingers_http.json.gz":
			engine = "fingers"
		case "resources/fingerprinthub_web.json.gz":
			engine = "fingerprinthub"
		case "resources/ehole.json.gz":
			engine = "ehole"
			wrapped = true
		case "resources/goby.json.gz":
			engine = "goby"
		case "resources/aliases.yaml":
			engine = "aliases"
		}
		var records []json.RawMessage
		if engine == "aliases" {
			var entries []map[string]any
			if err = yaml.Unmarshal(decoded, &entries); err != nil {
				return nil, err
			}
			for _, entry := range entries {
				raw, e := json.Marshal(entry)
				if e != nil {
					return nil, e
				}
				records = append(records, raw)
			}
		} else if wrapped {
			var v struct {
				Fingerprint []json.RawMessage `json:"fingerprint"`
			}
			if err = json.Unmarshal(decoded, &v); err != nil {
				return nil, err
			}
			records = v.Fingerprint
		} else if err = json.Unmarshal(decoded, &records); err != nil {
			return nil, err
		}
		rejections := map[int]Rejection{}
		for _, r := range p.Validation[engine].Rejections {
			rejections[r.Index] = r
		}
		for i, raw := range records {
			canonical, e := CanonicalRecord(raw)
			if e != nil {
				return nil, e
			}
			var fields map[string]json.RawMessage
			if e = json.Unmarshal(canonical, &fields); e != nil {
				return nil, e
			}
			text := func(key string) string { var s string; _ = json.Unmarshal(fields[key], &s); return s }
			name := text("name")
			id := name
			caps := []string{"http_passive"}
			switch engine {
			case "fingerprinthub":
				id = text("id")
				var info struct {
					Name string `json:"name"`
				}
				_ = json.Unmarshal(fields["info"], &info)
				name = info.Name
				if name == "" {
					name = id
				}
				caps = append(caps, "http_active")
			case "ehole":
				name = text("cms")
				id = name
			case "fingers":
				var f struct {
					Send  string `json:"send_data"`
					Rules []struct {
						Send string `json:"send_data"`
					} `json:"rule"`
				}
				_ = json.Unmarshal(canonical, &f)
				active := f.Send != ""
				for _, r := range f.Rules {
					active = active || r.Send != ""
				}
				if active {
					caps = append(caps, "http_active")
				}
			case "aliases":
				caps = []string{"alias"}
			}
			if id == "" {
				id = strconv.Itoa(i)
			}
			if bytesContainKey(canonical, "favicon") || text("method") == "faviconhash" || strings.Contains(string(canonical), `"type":"favicon"`) {
				caps = append(caps, "favicon")
			}
			if engine == "ehole" && text("location") == "title" {
				caps = append(caps, "title")
			}
			status := "loaded"
			if r, ok := rejections[i]; ok {
				status = "excluded_legacy:" + r.Reason
			}
			hash := Digest(canonical)
			pointer := "/" + strconv.Itoa(i)
			if wrapped {
				pointer = "/fingerprint" + pointer
			}
			catalog = append(catalog, CatalogRecord{UnitKey: UnitKey(engine, path+"#"+pointer, id, hash), SourceRecord: path + "#" + pointer, Engine: engine, Source: "chainreactors/fingers", SourceRevision: p.Source.Revision, OriginalID: id, Path: path, Index: i, ContentHash: hash, Name: name, Capabilities: caps, LoadStatus: status, OriginalReference: fmt.Sprintf("%s/blob/%s/%s#%s", Repository, p.Source.Revision, path, pointer)})
		}
	}
	return catalog, nil
}
func bytesContainKey(data []byte, key string) bool {
	return strings.Contains(string(data), `"`+key+`":`)
}

// OriginalRecord returns exact original JSON record bytes (aliases become JSON,
// a YAML subset) for catalogue detail/download without converting its semantics.
func (p Package) OriginalRecord(path string, index int) ([]byte, error) {
	if index < 0 {
		return nil, fmt.Errorf("invalid source record index")
	}
	f, ok := p.Files[path]
	if !ok {
		return nil, fmt.Errorf("missing source resource")
	}
	decoded, err := DecodeRaw(path, f.Raw)
	if err != nil {
		return nil, err
	}
	var records []json.RawMessage
	if path == "resources/aliases.yaml" {
		var entries []map[string]any
		if err = yaml.Unmarshal(decoded, &entries); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			raw, e := json.Marshal(entry)
			if e != nil {
				return nil, e
			}
			records = append(records, raw)
		}
	} else if path == "resources/ehole.json.gz" {
		var v struct {
			Fingerprint []json.RawMessage `json:"fingerprint"`
		}
		if err = json.Unmarshal(decoded, &v); err != nil {
			return nil, err
		}
		records = v.Fingerprint
	} else if err = json.Unmarshal(decoded, &records); err != nil {
		return nil, err
	}
	if index >= len(records) {
		return nil, fmt.Errorf("invalid source record index")
	}
	return append([]byte(nil), records[index]...), nil
}
func (p Package) ManifestHash() (string, error) {
	catalog, err := p.Catalog()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		Source  Source          `json:"source"`
		Records []CatalogRecord `json:"records"`
	}{p.Source, catalog})
	if err != nil {
		return "", err
	}
	return Digest(raw), nil
}
