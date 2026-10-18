package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/rulelib"
)

// Import uses the exact same compiler and atomic publisher as an online update.
// No downloaded content selects executable paths or command arguments.
func (s *Server) importHTTPBundle(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fingerprintbundle.MaxPackageBytes))
	if err != nil {
		writeError(w, 400, "fingerprint package exceeds size limit")
		return
	}
	pkg, err := fingerprintbundle.Decode(data)
	if err != nil || pkg.Legacy() {
		writeError(w, 400, "a complete v2 HTTP package is required")
		return
	}
	input := fingerprintbundle.RawInput{SourceRevision: pkg.Source.Revision, Files: map[string][]byte{}}
	for path, file := range pkg.Files {
		input.Files[path] = file.Raw
	}
	s.sourceMu.Lock()
	if s.sourceRunning["fingers"] {
		s.sourceMu.Unlock()
		writeError(w, 409, "fingers source is updating")
		return
	}
	s.sourceRunning["fingers"] = true
	s.sourceMu.Unlock()
	defer func() { s.sourceMu.Lock(); delete(s.sourceRunning, "fingers"); s.sourceMu.Unlock() }()
	prepared, err := prepareFingerprintBundle(r.Context(), input)
	if err != nil {
		writeError(w, 400, "fingerprint package compatibility check failed: "+err.Error())
		return
	}
	if err = s.applyFingerprintBundle(r.Context(), input, prepared); err != nil {
		writeError(w, 500, "publish HTTP fingerprint package failed")
		return
	}
	verified, _ := fingerprintbundle.Decode(prepared)
	writeJSON(w, 200, map[string]any{"bundle": fingerprintbundle.Digest(prepared), "validation": verified.Validation})
}

// This is a searchable index of original records, never an execution conversion.
type httpCatalogItem struct {
	ruleSummary
	Bundle  string                           `json:"bundle,omitempty"`
	Managed bool                             `json:"source_managed,omitempty"`
	Record  *fingerprintbundle.CatalogRecord `json:"record,omitempty"`
}

func indexHTTPBundle(ctx context.Context, tx pgx.Tx, pkg fingerprintbundle.Package, digest string) error {
	records, err := pkg.Catalog()
	if err != nil {
		return err
	}
	rows := make([][]any, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if record.Engine == "aliases" || seen[record.UnitKey] {
			continue
		}
		seen[record.UnitKey] = true
		item := httpCatalogItem{ruleSummary: ruleSummary{ID: record.UnitKey, Kind: "http", Name: record.Name, Engine: record.Engine, Enabled: record.LoadStatus == "loaded", Revision: 1, SourceID: "fingers", Source: record.Source, Capabilities: record.Capabilities, ExecutionAvailable: record.LoadStatus == "loaded"}, Bundle: digest, Managed: true, Record: &record}
		raw, notes, err := catalogIndexJSON(item)
		if err != nil {
			return err
		}
		rows = append(rows, []any{"fingers", pkg.Source.Revision, pkg.SelectionProfile, record.UnitKey, raw, record.ContentHash, notes})
	}
	// Same immutable bundle can be published twice. Refresh its derived index in
	// this transaction, without touching original packages or historical runs.
	if _, err = tx.Exec(ctx, `DELETE FROM rule_source_catalog WHERE source_id='fingers' AND revision=$1 AND converter_version=$2`, pkg.Source.Revision, pkg.SelectionProfile); err != nil {
		return err
	}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"rule_source_catalog"}, []string{"source_id", "revision", "converter_version", "id", "rule", "content_hash", "sanitized_fields"}, pgx.CopyFromRows(rows))
	return err
}

const httpCatalogUnion = `WITH entries AS (
 SELECT id,rule,source_id FROM rule_library WHERE deleted_at IS NULL AND rule->>'kind'='http'
 UNION ALL
 SELECT c.id,c.rule,c.source_id FROM rule_source_catalog c
 JOIN rule_sources s ON s.id=c.source_id AND s.revision=c.revision AND s.converter_version=c.converter_version
 WHERE c.source_id='fingers' AND c.rule->>'kind'='http'
) `

func (s *Server) listHTTPFingerprints(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	enabled, err := libraryFilter(r.URL.Query().Get("enabled"), "enabled", "true", "false")
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	args := []any{strings.TrimSpace(r.URL.Query().Get("q")), strings.TrimSpace(r.URL.Query().Get("source_id")), strings.TrimSpace(r.URL.Query().Get("engine")), enabled, strings.TrimSpace(r.URL.Query().Get("capability"))}
	const filter = ` FROM entries WHERE ($1='' OR rule::text ILIKE '%'||$1||'%') AND ($2='' OR source_id=$2)
 AND ($3='' OR rule->>'engine'=$3) AND ($4='' OR rule->>'enabled'=$4)
 AND ($5='' OR rule->'capabilities' ? $5 OR ($5='http_passive' AND rule->>'engine'='httpx-cff'))`
	var total int64
	if err = s.db.QueryRow(r.Context(), httpCatalogUnion+`SELECT count(*)`+filter, args...).Scan(&total); err != nil {
		writeError(w, 500, "load HTTP fingerprints failed")
		return
	}
	rows, err := s.db.Query(r.Context(), httpCatalogUnion+`SELECT rule,source_id`+filter+` ORDER BY lower(rule->>'name'),id LIMIT $6 OFFSET $7`, append(args, limit, offset)...)
	if err != nil {
		writeError(w, 500, "load HTTP fingerprints failed")
		return
	}
	items := make([]httpCatalogItem, 0, limit)
	for rows.Next() {
		var raw []byte
		var sourceID string
		if err = rows.Scan(&raw, &sourceID); err != nil {
			break
		}
		var item httpCatalogItem
		if sourceID == "fingers" {
			err = json.Unmarshal(raw, &item)
		} else {
			var rule rulelib.Rule
			if err = json.Unmarshal(raw, &rule); err == nil {
				item.ruleSummary = summarizeRule(rule, sourceID)
				item.Capabilities = []string{"http_passive"}
			}
		}
		if err != nil {
			break
		}
		items = append(items, item)
	}
	rows.Close()
	if err != nil || rows.Err() != nil {
		writeError(w, 500, "decode HTTP fingerprints failed")
		return
	}
	counts := map[string]int64{"http": 0, "port": 0, "poc": 0}
	var httpCount int64
	if err = s.db.QueryRow(r.Context(), httpCatalogUnion+`SELECT count(*) FROM entries`).Scan(&httpCount); err != nil {
		writeError(w, 500, "count HTTP fingerprints failed")
		return
	}
	counts["http"] = httpCount
	countRows, err := s.db.Query(r.Context(), `SELECT rule->>'kind',count(*) FROM rule_library WHERE deleted_at IS NULL AND rule->>'kind' IN('port','poc') GROUP BY 1`)
	if err != nil {
		writeError(w, 500, "count rules failed")
		return
	}
	for countRows.Next() {
		var kind string
		var count int64
		if err = countRows.Scan(&kind, &count); err != nil {
			break
		}
		counts[kind] = count
	}
	countRows.Close()
	if err != nil || countRows.Err() != nil {
		writeError(w, 500, "count rules failed")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "counts": counts})
}

func (s *Server) getHTTPFingerprint(w http.ResponseWriter, r *http.Request) {
	var raw, data []byte
	err := s.db.QueryRow(r.Context(), `SELECT c.rule,b.package FROM rule_source_catalog c
 JOIN rule_sources s ON s.id=c.source_id AND s.revision=c.revision AND s.converter_version=c.converter_version
 JOIN fingerprint_bundles b ON b.digest=c.rule->>'bundle'
 WHERE c.source_id='fingers' AND c.id=$1`, r.PathValue("id")).Scan(&raw, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "HTTP fingerprint not found")
		return
	}
	if err != nil {
		writeError(w, 500, "load HTTP fingerprint failed")
		return
	}
	var item httpCatalogItem
	if json.Unmarshal(raw, &item) != nil || item.Record == nil {
		writeError(w, 500, "invalid HTTP index")
		return
	}
	pkg, err := fingerprintbundle.Decode(data)
	if err != nil {
		writeError(w, 500, "invalid HTTP bundle")
		return
	}
	original, err := pkg.OriginalRecord(item.Record.Path, item.Record.Index)
	if err != nil {
		writeError(w, 500, "read original HTTP record failed")
		return
	}
	writeJSON(w, 200, struct {
		httpCatalogItem
		Original json.RawMessage `json:"original"`
	}{item, original})
}
