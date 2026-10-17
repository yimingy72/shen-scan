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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/rulelib"
	"scanplatform/internal/rulesource"
)

const (
	maxImportedRuleCount   = 10_000
	maxRuleBatchCount      = 1000
	currentRuleSeedVersion = 1
)

type ruleSummary struct {
	MatchSummary string   `json:"match_summary"`
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Engine       string   `json:"engine"`
	Severity     string   `json:"severity"`
	Enabled      bool     `json:"enabled"`
	Builtin      bool     `json:"builtin"`
	Revision     int      `json:"revision"`
	Tags         []string `json:"tags,omitempty"`
	Source       string   `json:"source,omitempty"`
	AppliesTo    []string `json:"applies_to,omitempty"`
	SourceID     string   `json:"source_id,omitempty"`
}

type ruleExportLicense struct {
	SourceID    string `json:"source_id"`
	Repository  string `json:"repository"`
	Revision    string `json:"revision"`
	License     string `json:"license"`
	LicenseText string `json:"license_text"`
}

type ruleExportNotice struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type ruleExportPackage struct {
	Items    []rulelib.Rule      `json:"items"`
	Licenses []ruleExportLicense `json:"licenses"`
	Notices  []ruleExportNotice  `json:"notices"`
}

type ruleSnapshot struct {
	HTTP               []rulelib.Rule `json:"http"`
	Port               []rulelib.Rule `json:"port"`
	POC                []rulelib.Rule `json:"poc"`
	POCPolicy          string         `json:"poc_policy,omitempty"`
	ExplicitPOCRuleIDs []string       `json:"explicit_poc_rule_ids,omitempty"`
}

type executionRule struct {
	ID         string             `json:"id"`
	Kind       string             `json:"kind"`
	Name       string             `json:"name"`
	Engine     string             `json:"engine"`
	Severity   string             `json:"severity"`
	Enabled    bool               `json:"enabled"`
	Revision   int                `json:"revision"`
	Definition rulelib.Definition `json:"definition"`
}

func executionRules(rules []rulelib.Rule) []executionRule {
	result := make([]executionRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, executionRule{ID: rule.ID, Kind: rule.Kind, Name: rule.Name, Engine: rule.Engine,
			Severity: rule.Severity, Enabled: rule.Enabled, Revision: rule.Revision, Definition: rule.Definition})
	}
	return result
}

func loadRuleSnapshot(ctx context.Context, tx pgx.Tx, pocEnabled bool, selected []string) (ruleSnapshot, error) {
	rows, err := tx.Query(ctx, `SELECT rule FROM rule_library WHERE deleted_at IS NULL AND (rule->>'enabled')::boolean ORDER BY rule->>'kind',id`)
	if err != nil {
		return ruleSnapshot{}, err
	}
	defer rows.Close()
	wanted := make(map[string]bool, len(selected))
	explicit := make([]string, 0, len(selected))
	selectAllPOC := len(selected) == 0
	for _, id := range selected {
		id = strings.TrimSpace(id)
		if id == "" || wanted[id] {
			return ruleSnapshot{}, errors.New("poc_rule_ids must contain unique non-empty ids")
		}
		wanted[id] = true
		explicit = append(explicit, id)
	}
	snapshot := ruleSnapshot{HTTP: []rulelib.Rule{}, Port: []rulelib.Rule{}, POC: []rulelib.Rule{},
		POCPolicy: "fingerprint", ExplicitPOCRuleIDs: explicit}
	for rows.Next() {
		var raw []byte
		var rule rulelib.Rule
		if err = rows.Scan(&raw); err != nil || json.Unmarshal(raw, &rule) != nil {
			return ruleSnapshot{}, errors.New("invalid stored rule")
		}
		switch rule.Kind {
		case "http":
			snapshot.HTTP = append(snapshot.HTTP, rule)
		case "port":
			snapshot.Port = append(snapshot.Port, rule)
		case "poc":
			if pocEnabled && ((selectAllPOC && len(rule.AppliesTo) != 0) || wanted[rule.ID]) {
				snapshot.POC = append(snapshot.POC, rule)
				delete(wanted, rule.ID)
			}
		}
	}
	if err = rows.Err(); err != nil {
		return ruleSnapshot{}, err
	}
	if len(wanted) != 0 {
		return ruleSnapshot{}, errors.New("poc_rule_ids contains a missing or disabled PoC rule")
	}
	return snapshot, nil
}

func attachClaimRules(ctx context.Context, tx pgx.Tx, runID, taskType string, payload json.RawMessage, useRuleSets bool) (json.RawMessage, error) {
	if taskType != "http" && taskType != "service" {
		return payload, nil
	}
	if useRuleSets {
		var hasSnapshot bool
		if err := tx.QueryRow(ctx, `SELECT rules_snapshot IS NOT NULL AND jsonb_typeof(rules_snapshot)='object' FROM runs WHERE id=$1`, runID).Scan(&hasSnapshot); err != nil {
			return nil, err
		}
		if !hasSnapshot {
			return payload, nil
		}
		var value map[string]any
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		delete(value, "rules")
		delete(value, "poc_rules")
		value["rules_ref"] = runID + ":" + taskType
		return json.Marshal(value)
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT rules_snapshot FROM runs WHERE id=$1`, runID).Scan(&raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return payload, nil
	}
	var snapshot ruleSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, err
	}
	if taskType == "service" {
		value["rules"] = executionRules(snapshot.Port)
	} else {
		value["rules"] = executionRules(snapshot.HTTP)
		delete(value, "poc_rules")
	}
	delete(value, "rules_ref")
	return json.Marshal(value)
}

func summarizeRule(rule rulelib.Rule, sourceID string) ruleSummary {
	parts := []string{}
	if rule.Kind == "poc" {
		for _, request := range rule.Definition.Requests {
			parts = append(parts, request.Method+" "+request.Path)
		}
	} else {
		for _, matcher := range rule.Definition.Matchers {
			values := append(append([]string{}, matcher.Words...), matcher.Regex...)
			if matcher.Type == "status" {
				for _, status := range matcher.Status {
					values = append(values, strconv.Itoa(status))
				}
			}
			prefix := matcher.Part + " · "
			if matcher.Negative {
				prefix += "NOT "
			}
			parts = append(parts, prefix+strings.Join(values, " | "))
		}
	}
	summary := []rune(strings.Join(parts, "; "))
	if len(summary) > 180 {
		summary = append(summary[:180], '…')
	}
	return ruleSummary{MatchSummary: string(summary), ID: rule.ID, Kind: rule.Kind, Name: rule.Name, Description: rule.Description,
		Engine: rule.Engine, Severity: rule.Severity, Enabled: rule.Enabled, Builtin: rule.Builtin,
		Revision: rule.Revision, Tags: rule.Tags, Source: rule.Source, AppliesTo: rule.AppliesTo, SourceID: sourceID}
}

func seedRuleLibrary(ctx context.Context, db *pgxpool.Pool) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, rule := range rulelib.Builtins() {
		if err := rulelib.Validate(rule); err != nil {
			return fmt.Errorf("builtin %s: %w", rule.ID, err)
		}
		raw, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		inserted, err := tx.Exec(ctx, `INSERT INTO rule_library(id,rule,seed_version) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING`,
			rule.ID, raw, currentRuleSeedVersion)
		if err != nil {
			return err
		}
		if inserted.RowsAffected() != 0 {
			continue
		}
		var currentRaw []byte
		var deletedAt *time.Time
		var seedVersion int
		if err = tx.QueryRow(ctx, `SELECT rule,deleted_at,seed_version FROM rule_library WHERE id=$1 FOR UPDATE`, rule.ID).Scan(&currentRaw, &deletedAt, &seedVersion); err != nil {
			return err
		}
		if seedVersion >= currentRuleSeedVersion {
			continue
		}
		if deletedAt != nil {
			_, err = tx.Exec(ctx, `UPDATE rule_library SET seed_version=$2 WHERE id=$1`, rule.ID, currentRuleSeedVersion)
			if err != nil {
				return err
			}
			continue
		}
		var current rulelib.Rule
		if json.Unmarshal(currentRaw, &current) != nil {
			return fmt.Errorf("decode stored builtin %s", rule.ID)
		}
		if current.Builtin && current.Kind == "poc" && len(current.AppliesTo) == 0 && len(rule.AppliesTo) != 0 {
			current.AppliesTo = append([]string(nil), rule.AppliesTo...)
			current.Revision++
			if err = rulelib.Validate(current); err != nil {
				return fmt.Errorf("upgrade builtin %s: %w", rule.ID, err)
			}
			currentRaw, _ = json.Marshal(current)
		}
		if _, err = tx.Exec(ctx, `UPDATE rule_library SET rule=$2,seed_version=$3,updated_at=now() WHERE id=$1`,
			rule.ID, currentRaw, currentRuleSeedVersion); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func libraryFilter(value, name string, allowed ...string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "" && !contains(allowed, value) {
		return "", fmt.Errorf("invalid %s %q", name, value)
	}
	return value, nil
}

func ruleSourceFilter(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if _, ok := rulesource.SourceByID(value); !ok {
		return "", fmt.Errorf("invalid source_id %q", value)
	}
	return value, nil
}

func (s *Server) listLibrary(w http.ResponseWriter, r *http.Request) {
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
	engine, err := libraryFilter(r.URL.Query().Get("engine"), "engine", "native", "nuclei")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("enabled")))
	if enabled != "" && enabled != "true" && enabled != "false" {
		writeError(w, http.StatusBadRequest, "enabled must be true or false")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	sourceID, err := ruleSourceFilter(r.URL.Query().Get("source_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	const filtered = ` FROM rule_library WHERE deleted_at IS NULL AND ($1='' OR rule->>'kind'=$1) AND ($2='' OR rule->>'engine'=$2)
	 AND ($3='' OR rule->>'enabled'=$3) AND ($4='' OR rule::text ILIKE '%'||$4||'%') AND ($5='' OR source_id=$5)`
	var total int64
	if err = s.db.QueryRow(r.Context(), `SELECT count(*)`+filtered, kind, engine, enabled, query, sourceID).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule library failed")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT rule,source_id`+filtered+` ORDER BY rule->>'kind',lower(rule->>'name'),id LIMIT $6 OFFSET $7`, kind, engine, enabled, query, sourceID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule library failed")
		return
	}
	defer rows.Close()
	items := make([]ruleSummary, 0)
	for rows.Next() {
		var raw []byte
		var itemSourceID string
		var rule rulelib.Rule
		if err = rows.Scan(&raw, &itemSourceID); err != nil || json.Unmarshal(raw, &rule) != nil {
			writeError(w, http.StatusInternalServerError, "load rule library failed")
			return
		}
		items = append(items, summarizeRule(rule, itemSourceID))
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule library failed")
		return
	}
	counts := map[string]int64{"http": 0, "port": 0, "poc": 0}
	countRows, err := s.db.Query(r.Context(), `SELECT rule->>'kind',count(*) FROM rule_library
		WHERE deleted_at IS NULL GROUP BY rule->>'kind'`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule library failed")
		return
	}
	defer countRows.Close()
	for countRows.Next() {
		var value string
		var count int64
		if err = countRows.Scan(&value, &count); err != nil {
			writeError(w, http.StatusInternalServerError, "load rule library failed")
			return
		}
		counts[value] = count
	}
	if err = countRows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule library failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "counts": counts})
}

func (s *Server) loadLibraryRule(ctx context.Context, id string) (rulelib.Rule, error) {
	var raw []byte
	var rule rulelib.Rule
	err := s.db.QueryRow(ctx, `SELECT rule FROM rule_library WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &rule)
	}
	return rule, err
}

func (s *Server) getLibraryRule(w http.ResponseWriter, r *http.Request) {
	rule, err := s.loadLibraryRule(r.Context(), r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule failed")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func normalizeNewRule(rule *rulelib.Rule) error {
	rule.Builtin = false
	rule.Revision = 1
	if err := normalizeNucleiDefinition(rule); err != nil {
		return err
	}
	return rulelib.Validate(*rule)
}

func normalizeNucleiDefinition(rule *rulelib.Rule) error {
	if rule.Engine != "nuclei" {
		return nil
	}
	parsed, err := rulelib.ParseNuclei(rule.Template)
	if err != nil {
		return err
	}
	if parsed.ID != rule.ID {
		return errors.New("nuclei template id does not match rule id")
	}
	rule.Definition = parsed.Definition
	rule.Template = parsed.Template
	return nil
}

func (s *Server) createLibraryRule(w http.ResponseWriter, r *http.Request) {
	var rule rulelib.Rule
	if err := decodeJSON(w, r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := normalizeNewRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, _ := json.Marshal(rule)
	result, err := s.db.Exec(r.Context(), `INSERT INTO rule_library(id,rule,seed_version) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING`, rule.ID, raw, currentRuleSeedVersion)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create rule failed")
		return
	}
	if result.RowsAffected() == 0 {
		writeError(w, http.StatusConflict, "rule id already exists")
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) updateLibraryRule(w http.ResponseWriter, r *http.Request) {
	var request struct {
		rulelib.Rule
		ExpectedRevision int `json:"expected_revision"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.ID != r.PathValue("id") || request.ExpectedRevision < 1 {
		writeError(w, http.StatusBadRequest, "rule id must match path and expected_revision must be positive")
		return
	}
	current, err := s.loadLibraryRule(r.Context(), request.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule failed")
		return
	}
	request.Builtin = current.Builtin
	request.Revision = request.ExpectedRevision + 1
	if err = normalizeNucleiDefinition(&request.Rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err = rulelib.Validate(request.Rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, _ := json.Marshal(request.Rule)
	result, err := s.db.Exec(r.Context(), `UPDATE rule_library SET rule=$1,
		local_modified=CASE WHEN source_id<>'' THEN true ELSE local_modified END,updated_at=now()
		WHERE id=$2 AND deleted_at IS NULL AND (rule->>'revision')::int=$3`, raw, request.ID, request.ExpectedRevision)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update rule failed")
		return
	}
	if result.RowsAffected() == 0 {
		writeError(w, http.StatusConflict, "rule revision conflict")
		return
	}
	writeJSON(w, http.StatusOK, request.Rule)
}

func (s *Server) patchLibraryRule(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled          *bool `json:"enabled"`
		ExpectedRevision int   `json:"expected_revision"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Enabled == nil || request.ExpectedRevision < 1 {
		writeError(w, http.StatusBadRequest, "enabled and positive expected_revision are required")
		return
	}
	result, err := s.db.Exec(r.Context(), `UPDATE rule_library SET rule=jsonb_set(jsonb_set(rule,'{enabled}',to_jsonb($1::boolean)),'{revision}',to_jsonb($2::int)),
	 enabled_override=CASE WHEN source_id<>'' THEN $1 ELSE enabled_override END,updated_at=now()
	 WHERE id=$3 AND deleted_at IS NULL AND (rule->>'revision')::int=$4`, *request.Enabled, request.ExpectedRevision+1, r.PathValue("id"), request.ExpectedRevision)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update rule failed")
		return
	}
	if result.RowsAffected() == 0 {
		var exists bool
		_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM rule_library WHERE id=$1 AND deleted_at IS NULL)`, r.PathValue("id")).Scan(&exists)
		if !exists {
			writeError(w, http.StatusNotFound, "rule not found")
		} else {
			writeError(w, http.StatusConflict, "rule revision conflict")
		}
		return
	}
	rule, err := s.loadLibraryRule(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load updated rule failed")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) deleteLibraryRule(w http.ResponseWriter, r *http.Request) {
	revision, err := strconv.Atoi(r.URL.Query().Get("expected_revision"))
	if err != nil || revision < 1 {
		writeError(w, http.StatusBadRequest, "positive expected_revision is required")
		return
	}
	result, err := s.db.Exec(r.Context(), `UPDATE rule_library SET deleted_at=now(),updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL AND (rule->>'revision')::int=$2`, r.PathValue("id"), revision)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete rule failed")
		return
	}
	if result.RowsAffected() == 0 {
		var exists bool
		if err = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM rule_library WHERE id=$1 AND deleted_at IS NULL)`, r.PathValue("id")).Scan(&exists); err != nil {
			writeError(w, http.StatusInternalServerError, "delete rule failed")
		} else if exists {
			writeError(w, http.StatusConflict, "rule revision conflict")
		} else {
			writeError(w, http.StatusNotFound, "rule not found")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

type ruleDeleteItem struct {
	ID               string `json:"id"`
	ExpectedRevision int    `json:"expected_revision"`
}

func (s *Server) deleteLibraryRules(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Items []ruleDeleteItem `json:"items"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(request.Items) == 0 || len(request.Items) > maxRuleBatchCount {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("items must contain 1 to %d rules", maxRuleBatchCount))
		return
	}
	ids := make([]string, 0, len(request.Items))
	wanted := make(map[string]int, len(request.Items))
	for _, item := range request.Items {
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" || item.ExpectedRevision < 1 {
			writeError(w, http.StatusBadRequest, "each item requires id and positive expected_revision")
			return
		}
		if _, duplicate := wanted[item.ID]; duplicate {
			writeError(w, http.StatusBadRequest, "items contains duplicate rule id "+item.ID)
			return
		}
		wanted[item.ID] = item.ExpectedRevision
		ids = append(ids, item.ID)
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	rows, err := tx.Query(r.Context(), `SELECT id,(rule->>'revision')::int FROM rule_library
		WHERE id=ANY($1) AND deleted_at IS NULL FOR UPDATE`, ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete rules failed")
		return
	}
	found := make(map[string]int, len(ids))
	for rows.Next() {
		var id string
		var revision int
		if err = rows.Scan(&id, &revision); err != nil {
			rows.Close()
			writeError(w, http.StatusInternalServerError, "delete rules failed")
			return
		}
		found[id] = revision
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "delete rules failed")
		return
	}
	for _, id := range ids {
		revision, ok := found[id]
		if !ok {
			writeError(w, http.StatusNotFound, "rule not found: "+id)
			return
		}
		if revision != wanted[id] {
			writeError(w, http.StatusConflict, "rule revision conflict: "+id)
			return
		}
	}
	result, err := tx.Exec(r.Context(), `UPDATE rule_library SET deleted_at=now(),updated_at=now() WHERE id=ANY($1)`, ids)
	if err != nil || result.RowsAffected() != int64(len(ids)) {
		writeError(w, http.StatusInternalServerError, "delete rules failed")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted_count": len(ids)})
}

func decodeRuleJSON(content string) ([]rulelib.Rule, error) {
	decode := func(dst any) error {
		decoder := json.NewDecoder(bytes.NewReader([]byte(content)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(dst); err != nil {
			return err
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return errors.New("content must contain one JSON value")
		}
		return nil
	}
	var rules []rulelib.Rule
	if err := decode(&rules); err == nil {
		return rules, nil
	}
	var exported ruleExportPackage
	if err := decode(&exported); err == nil {
		return exported.Items, nil
	}
	var rule rulelib.Rule
	if err := decode(&rule); err != nil {
		return nil, err
	}
	return []rulelib.Rule{rule}, nil
}

func (s *Server) importLibrary(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Format  string `json:"format"`
		Content string `json:"content"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	request.Format = strings.ToLower(strings.TrimSpace(request.Format))
	var rules []rulelib.Rule
	var err error
	switch request.Format {
	case "json":
		rules, err = decodeRuleJSON(request.Content)
	case "nuclei":
		var rule rulelib.Rule
		rule, err = rulelib.ParseNuclei(request.Content)
		rules = []rulelib.Rule{rule}
	default:
		err = errors.New("format must be json or nuclei")
	}
	if err != nil || len(rules) == 0 || len(rules) > maxImportedRuleCount {
		if err == nil {
			err = fmt.Errorf("import must contain 1 to %d rules", maxImportedRuleCount)
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids := make([]string, 0, len(rules))
	seen := make(map[string]bool)
	for index := range rules {
		rules[index].Enabled = false
		if err = normalizeNewRule(&rules[index]); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("rule %d: %v", index+1, err))
			return
		}
		if seen[rules[index].ID] {
			writeError(w, http.StatusConflict, "import contains duplicate rule id "+rules[index].ID)
			return
		}
		seen[rules[index].ID] = true
		ids = append(ids, rules[index].ID)
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	defer tx.Rollback(r.Context())
	rows, err := tx.Query(r.Context(), `SELECT id,(rule->>'revision')::int,deleted_at IS NOT NULL FROM rule_library WHERE id=ANY($1) FOR UPDATE`, ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "import rules failed")
		return
	}
	type existingRule struct {
		revision int
		deleted  bool
	}
	existing := make(map[string]existingRule, len(ids))
	for rows.Next() {
		var id string
		var state existingRule
		if err = rows.Scan(&id, &state.revision, &state.deleted); err != nil {
			rows.Close()
			writeError(w, http.StatusInternalServerError, "import rules failed")
			return
		}
		existing[id] = state
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "import rules failed")
		return
	}
	for _, rule := range rules {
		if state, ok := existing[rule.ID]; ok && !state.deleted {
			writeError(w, http.StatusConflict, "rule id already exists: "+rule.ID)
			return
		}
	}
	for index := range rules {
		state, restoring := existing[rules[index].ID]
		if restoring {
			rules[index].Revision = state.revision + 1
		}
		raw, _ := json.Marshal(rules[index])
		if restoring {
			_, err = tx.Exec(r.Context(), `UPDATE rule_library SET rule=$2,deleted_at=NULL,seed_version=$3,
				local_modified=CASE WHEN source_id<>'' THEN true ELSE local_modified END,upstream_retired=false,updated_at=now() WHERE id=$1`,
				rules[index].ID, raw, currentRuleSeedVersion)
		} else {
			_, err = tx.Exec(r.Context(), `INSERT INTO rule_library(id,rule,seed_version) VALUES($1,$2,$3)`,
				rules[index].ID, raw, currentRuleSeedVersion)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "import rules failed")
			return
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"items": rules, "count": len(rules)})
}

func (s *Server) exportLibrary(w http.ResponseWriter, r *http.Request) {
	kind, err := libraryFilter(r.URL.Query().Get("kind"), "kind", "http", "port", "poc")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	engine, err := libraryFilter(r.URL.Query().Get("engine"), "engine", "native", "nuclei")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("enabled")))
	if enabled != "" && enabled != "true" && enabled != "false" {
		writeError(w, http.StatusBadRequest, "enabled must be true or false")
		return
	}
	ids, err := parseRuleIDs(r.URL.Query().Get("ids"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sourceID, err := ruleSourceFilter(r.URL.Query().Get("source_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	rows, err := s.db.Query(r.Context(), `SELECT rule,source_id FROM rule_library WHERE deleted_at IS NULL
		AND ($1='' OR rule->>'kind'=$1) AND ($2='' OR rule->>'engine'=$2) AND ($3='' OR rule->>'enabled'=$3)
		AND ($4='' OR rule::text ILIKE '%'||$4||'%') AND ($5='' OR source_id=$5) AND (NOT $6 OR id=ANY($7))
		ORDER BY rule->>'kind',lower(rule->>'name'),id`, kind, engine, enabled, query, sourceID, len(ids) != 0, ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export rules failed")
		return
	}
	items := make([]rulelib.Rule, 0)
	sourceIDs := make(map[string]bool)
	includeBuiltinNotice := false
	bootstrapNoticeIDs := make(map[string]bool)
	for _, builtin := range rulelib.Builtins() {
		if strings.Contains(strings.ToLower(builtin.Source), "projectdiscovery/wappalyzergo") {
			bootstrapNoticeIDs[builtin.ID] = true
		}
	}
	for rows.Next() {
		var raw []byte
		var itemSourceID string
		var rule rulelib.Rule
		if err = rows.Scan(&raw, &itemSourceID); err != nil || json.Unmarshal(raw, &rule) != nil {
			rows.Close()
			writeError(w, http.StatusInternalServerError, "export rules failed")
			return
		}
		items = append(items, rule)
		if itemSourceID != "" {
			sourceIDs[itemSourceID] = true
		}
		if bootstrapNoticeIDs[rule.ID] {
			includeBuiltinNotice = true
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "export rules failed")
		return
	}
	licenses, err := s.loadExportLicenses(r.Context(), sourceIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "export rule licenses failed")
		return
	}
	notices := make([]ruleExportNotice, 0, 1)
	if includeBuiltinNotice {
		notice := rulelib.ThirdPartyNotices()
		if notice == "" {
			writeError(w, http.StatusInternalServerError, "export rule notices failed")
			return
		}
		notices = append(notices, ruleExportNotice{Name: "internal/rulelib/THIRD_PARTY_NOTICES.md", Text: notice})
	}
	writeJSON(w, http.StatusOK, ruleExportPackage{Items: items, Licenses: licenses, Notices: notices})
}

func (s *Server) loadExportLicenses(ctx context.Context, wanted map[string]bool) ([]ruleExportLicense, error) {
	licenses := make([]ruleExportLicense, 0, len(wanted))
	if len(wanted) == 0 {
		return licenses, nil
	}
	ids := make([]string, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows, err := s.db.Query(ctx, `SELECT id,repository,revision,license,license_text FROM rule_sources WHERE id=ANY($1) ORDER BY id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item ruleExportLicense
		if err = rows.Scan(&item.SourceID, &item.Repository, &item.Revision, &item.License, &item.LicenseText); err != nil {
			rows.Close()
			return nil, err
		}
		if item.Repository == "" || item.Revision == "" || item.License == "" || item.LicenseText == "" {
			rows.Close()
			return nil, errors.New("exported rule source license is incomplete")
		}
		licenses = append(licenses, item)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(licenses) != len(ids) {
		return nil, errors.New("exported rule source metadata is missing")
	}
	return licenses, nil
}

func parseRuleIDs(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxRuleBatchCount {
		return nil, fmt.Errorf("ids must contain at most %d rules", maxRuleBatchCount)
	}
	ids := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, id := range parts {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, errors.New("ids contains an empty rule id")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (s *Server) listLibraryProducts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT min(btrim(rule->'definition'->>'product')) product FROM rule_library
		WHERE deleted_at IS NULL AND rule->>'kind' IN ('http','port')
		AND COALESCE(btrim(rule->'definition'->>'product'),'')<>''
		GROUP BY lower(btrim(rule->'definition'->>'product')) ORDER BY lower(btrim(rule->'definition'->>'product'))`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load library products failed")
		return
	}
	defer rows.Close()
	items := make([]string, 0)
	for rows.Next() {
		var product string
		if err = rows.Scan(&product); err != nil {
			writeError(w, http.StatusInternalServerError, "load library products failed")
			return
		}
		items = append(items, product)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "load library products failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
