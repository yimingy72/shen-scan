package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/rulelib"
)

const catalogNULDisplay = "␀"

func catalogRuleJSON(rule rulelib.Rule) ([]byte, []string, error) {
	// Original template bytes live in rule_source_files. Keeping them out of
	// JSONB avoids PostgreSQL's U+0000 restriction and removes a large duplicate.
	rule.Template = ""
	return catalogIndexJSON(rule)
}

func catalogIndexJSON(input any) ([]byte, []string, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err = decoder.Decode(&value); err != nil {
		return nil, nil, err
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return nil, nil, errors.New("catalog rule JSON contains trailing data")
	}
	notes := make([]string, 0)
	value = sanitizeCatalogJSON(value, "$", &notes)
	sort.Strings(notes)
	notes = uniqueCatalogNotes(notes)
	raw, err = json.Marshal(value)
	return raw, notes, err
}

func sanitizeCatalogJSON(value any, jsonPath string, notes *[]string) any {
	switch typed := value.(type) {
	case string:
		if strings.ContainsRune(typed, 0) {
			*notes = append(*notes, jsonPath+": NUL displayed as "+catalogNULDisplay)
			return strings.ReplaceAll(typed, "\x00", catalogNULDisplay)
		}
		return typed
	case []any:
		for index := range typed {
			typed[index] = sanitizeCatalogJSON(typed[index], jsonPath+"["+strconv.Itoa(index)+"]", notes)
		}
		return typed
	case map[string]any:
		result := make(map[string]any, len(typed))
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			displayKey := key
			if strings.ContainsRune(displayKey, 0) {
				displayKey = strings.ReplaceAll(displayKey, "\x00", catalogNULDisplay)
				*notes = append(*notes, jsonPath+": object key NUL displayed as "+catalogNULDisplay)
			}
			if _, collision := result[displayKey]; collision {
				base := displayKey
				for suffix := 2; ; suffix++ {
					displayKey = base + " [catalog key " + strconv.Itoa(suffix) + "]"
					if _, exists := result[displayKey]; !exists {
						break
					}
				}
				*notes = append(*notes, jsonPath+": sanitized object key collision was disambiguated")
			}
			result[displayKey] = sanitizeCatalogJSON(typed[key], jsonPath+"."+displayKey, notes)
		}
		return result
	default:
		return value
	}
}

func uniqueCatalogNotes(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func persistSourceCatalog(ctx context.Context, tx pgx.Tx, sourceID, revision, converterVersion,
	previousRevision, previousConverterVersion string, rules []rulelib.Rule, hashes map[string]string, stats *ruleSourceStats) error {
	previous := make(map[string]string)
	if previousRevision != "" && previousConverterVersion != "" {
		rows, err := tx.Query(ctx, `SELECT id,content_hash FROM rule_source_catalog
			WHERE source_id=$1 AND revision=$2 AND converter_version=$3`, sourceID, previousRevision, previousConverterVersion)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, hash string
			if err = rows.Scan(&id, &hash); err != nil {
				rows.Close()
				return err
			}
			previous[id] = hash
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
	}
	current := make(map[string]string)
	rows, err := tx.Query(ctx, `SELECT id,content_hash FROM rule_source_catalog
		WHERE source_id=$1 AND revision=$2 AND converter_version=$3`, sourceID, revision, converterVersion)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, hash string
		if err = rows.Scan(&id, &hash); err != nil {
			rows.Close()
			return err
		}
		current[id] = hash
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	copyRows := make([][]any, 0, len(rules))
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		hash := hashes[rule.ID]
		seen[rule.ID] = true
		if prior, exists := previous[rule.ID]; !exists {
			stats.Added++
		} else if prior == hash {
			stats.Unchanged++
		} else {
			stats.Updated++
		}
		if stored, exists := current[rule.ID]; exists {
			if stored != hash {
				return fmt.Errorf("immutable source catalog rule %q changed for revision %s converter %s", rule.ID, revision, converterVersion)
			}
			continue
		}
		raw, sanitizedFields, marshalErr := catalogRuleJSON(rule)
		if marshalErr != nil {
			return fmt.Errorf("encode source catalog rule %q: %w", rule.ID, marshalErr)
		}
		copyRows = append(copyRows, []any{sourceID, revision, converterVersion, rule.ID, raw, hash, sanitizedFields})
	}
	for id := range previous {
		if !seen[id] {
			stats.Retired++
		}
	}
	if len(copyRows) == 0 {
		return nil
	}
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"rule_source_catalog"},
		[]string{"source_id", "revision", "converter_version", "id", "rule", "content_hash", "sanitized_fields"}, pgx.CopyFromRows(copyRows))
	if err != nil {
		return err
	}
	if copied != int64(len(copyRows)) {
		return fmt.Errorf("stored %d of %d source catalog rules", copied, len(copyRows))
	}
	return nil
}

func (s *Server) sourceCatalogVersion(ctx context.Context, sourceID, requestedRevision string) (string, string, error) {
	if strings.TrimSpace(requestedRevision) == "" {
		var revision, converterVersion string
		err := s.db.QueryRow(ctx, `SELECT revision,converter_version FROM rule_sources WHERE id=$1`, sourceID).Scan(&revision, &converterVersion)
		if err != nil || revision == "" || converterVersion == "" {
			return "", "", pgx.ErrNoRows
		}
		return revision, converterVersion, nil
	}
	revision := strings.TrimSpace(requestedRevision)
	var converterVersion string
	err := s.db.QueryRow(ctx, `SELECT converter_version FROM rule_source_catalog WHERE source_id=$1 AND revision=$2
		ORDER BY converter_version DESC LIMIT 1`, sourceID, revision).Scan(&converterVersion)
	return revision, converterVersion, err
}

func (s *Server) listRuleSourceCatalog(w http.ResponseWriter, r *http.Request) {
	sourceID := r.PathValue("id")
	revision, converterVersion, err := s.sourceCatalogVersion(r.Context(), sourceID, r.URL.Query().Get("revision"))
	if err != nil {
		writeError(w, http.StatusNotFound, "rule source revision not found")
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	kind, err := libraryFilter(r.URL.Query().Get("kind"), "kind", "http", "port", "poc")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	engine := strings.TrimSpace(r.URL.Query().Get("engine"))
	purpose, err := libraryFilter(r.URL.Query().Get("purpose"), "purpose", "discovery", "verification", "check")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled, err := libraryFilter(r.URL.Query().Get("enabled"), "enabled", "true", "false")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	runtime, err := libraryFilter(r.URL.Query().Get("runtime"), "runtime", "available", "catalog_only")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	const filtered = ` FROM rule_source_catalog WHERE source_id=$1 AND revision=$2 AND converter_version=$3
		AND ($4='' OR rule->>'kind'=$4) AND ($5='' OR rule->>'engine'=$5)
		AND ($6='' OR CASE WHEN rule->>'purpose' IN ('verification','check') THEN rule->>'purpose' ELSE 'discovery' END=$6)
		AND ($7='' OR rule->>'enabled'=$7) AND ($8='' OR rule::text ILIKE '%'||$8||'%')
		AND ($9='' OR CASE WHEN COALESCE(rule#>>'{nuclei,runtime_reason}','')='' THEN 'available' ELSE 'catalog_only' END=$9)`
	args := []any{sourceID, revision, converterVersion, kind, engine, purpose, enabled, query, runtime}
	var total int64
	if err = s.db.QueryRow(r.Context(), `SELECT count(*)`+filtered, args...).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule source catalog failed")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT rule,sanitized_fields`+filtered+` ORDER BY rule->>'kind',lower(rule->>'name'),id LIMIT $10 OFFSET $11`,
		append(args, limit, offset)...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule source catalog failed")
		return
	}
	defer rows.Close()
	items := make([]ruleSummary, 0, limit)
	for rows.Next() {
		var raw []byte
		var sanitizedFields []string
		var rule rulelib.Rule
		if err = rows.Scan(&raw, &sanitizedFields); err != nil || json.Unmarshal(raw, &rule) != nil {
			writeError(w, http.StatusInternalServerError, "load rule source catalog failed")
			return
		}
		item := summarizeRule(rule, sourceID)
		item.CatalogSanitizedFields = sanitizedFields
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule source catalog failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "revision": revision, "converter_version": converterVersion})
}

func (s *Server) getRuleSourceCatalogRule(w http.ResponseWriter, r *http.Request) {
	revision, converterVersion, err := s.sourceCatalogVersion(r.Context(), r.PathValue("id"), r.URL.Query().Get("revision"))
	if err != nil {
		writeError(w, http.StatusNotFound, "rule source revision not found")
		return
	}
	var raw []byte
	var sanitizedFields []string
	err = s.db.QueryRow(r.Context(), `SELECT rule,sanitized_fields FROM rule_source_catalog WHERE source_id=$1 AND revision=$2 AND converter_version=$3 AND id=$4`,
		r.PathValue("id"), revision, converterVersion, r.PathValue("ruleID")).Scan(&raw, &sanitizedFields)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "source catalog rule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load source catalog rule failed")
		return
	}
	var rule rulelib.Rule
	if json.Unmarshal(raw, &rule) != nil {
		writeError(w, http.StatusInternalServerError, "decode source catalog rule failed")
		return
	}
	if rule.Engine == "nuclei" && rule.Nuclei != nil && rule.Upstream != nil {
		var template []byte
		if err = s.db.QueryRow(r.Context(), `SELECT data FROM rule_source_files WHERE source_id=$1 AND revision=$2 AND path=$3`,
			rule.Upstream.SourceID, rule.Upstream.Revision, rule.Upstream.Path).Scan(&template); err != nil {
			writeError(w, http.StatusInternalServerError, "load source catalog template failed")
			return
		}
		rule.Template = string(template)
	}
	writeJSON(w, http.StatusOK, struct {
		rulelib.Rule
		CatalogSanitizedFields []string `json:"catalog_sanitized_fields,omitempty"`
	}{Rule: rule, CatalogSanitizedFields: sanitizedFields})
}
