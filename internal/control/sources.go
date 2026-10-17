package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/rulelib"
	"scanplatform/internal/rulesource"
)

const sourceUpdateTimeout = 10 * time.Minute

type ruleSourceStats struct {
	Total     int            `json:"total"`
	Accepted  int            `json:"accepted"`
	Skipped   int            `json:"skipped"`
	Reasons   map[string]int `json:"reasons"`
	Added     int            `json:"added"`
	Updated   int            `json:"updated"`
	Unchanged int            `json:"unchanged"`
	Preserved int            `json:"preserved"`
	Retired   int            `json:"retired"`
}

type ruleSourceStatus struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Repository string                 `json:"repository"`
	License    string                 `json:"license"`
	Status     string                 `json:"status"`
	Revision   string                 `json:"revision"`
	UpdatedAt  *time.Time             `json:"updated_at,omitempty"`
	Error      string                 `json:"error"`
	Stats      ruleSourceStats        `json:"stats"`
	Samples    []rulesource.Rejection `json:"samples"`
}

func initializeRuleSources(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, `UPDATE rule_sources SET status='failed',error='update interrupted by process restart',updated_at=now()
		WHERE status='updating'`)
	return err
}

func (s *Server) listRuleSources(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT id,name,repository,license,status,revision,updated_at,error,stats,samples
		FROM rule_sources ORDER BY id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule sources failed")
		return
	}
	defer rows.Close()
	items := make([]ruleSourceStatus, 0, 2)
	for rows.Next() {
		var item ruleSourceStatus
		var statsRaw, samplesRaw []byte
		if err = rows.Scan(&item.ID, &item.Name, &item.Repository, &item.License, &item.Status, &item.Revision,
			&item.UpdatedAt, &item.Error, &statsRaw, &samplesRaw); err != nil ||
			json.Unmarshal(statsRaw, &item.Stats) != nil || json.Unmarshal(samplesRaw, &item.Samples) != nil {
			writeError(w, http.StatusInternalServerError, "load rule sources failed")
			return
		}
		if item.Stats.Reasons == nil {
			item.Stats.Reasons = map[string]int{}
		}
		if item.Samples == nil {
			item.Samples = []rulesource.Rejection{}
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule sources failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) updateRuleSource(w http.ResponseWriter, r *http.Request) {
	if !consumeEmptyAction(w, r) {
		return
	}
	id := r.PathValue("id")
	if _, ok := rulesource.SourceByID(id); !ok {
		writeError(w, http.StatusNotFound, "rule source not found")
		return
	}
	s.sourceMu.Lock()
	if s.sourceRunning[id] {
		s.sourceMu.Unlock()
		item, err := s.loadRuleSource(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load rule source failed")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"source": item})
		return
	}
	result, err := s.db.Exec(r.Context(), `UPDATE rule_sources SET status='updating',error='',updated_at=now()
		WHERE id=$1 AND status<>'updating'`, id)
	if err != nil {
		s.sourceMu.Unlock()
		writeError(w, http.StatusInternalServerError, "start rule source update failed")
		return
	}
	if result.RowsAffected() == 0 {
		s.sourceMu.Unlock()
		item, loadErr := s.loadRuleSource(r.Context(), id)
		if loadErr != nil {
			writeError(w, http.StatusInternalServerError, "load rule source failed")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"source": item})
		return
	}
	s.sourceRunning[id] = true
	s.sourceMu.Unlock()
	item, err := s.loadRuleSource(r.Context(), id)
	if err != nil {
		s.finishSourceRun(id)
		_, _ = s.db.Exec(r.Context(), `UPDATE rule_sources SET status='failed',error='failed to load started update',updated_at=now() WHERE id=$1`, id)
		writeError(w, http.StatusInternalServerError, "load rule source failed")
		return
	}
	go s.runRuleSourceUpdate(id)
	writeJSON(w, http.StatusAccepted, map[string]any{"source": item})
}

func (s *Server) runRuleSourceUpdate(id string) {
	defer s.finishSourceRun(id)
	ctx, cancel := context.WithTimeout(s.ctx, sourceUpdateTimeout)
	defer cancel()
	revision, err := rulesource.LatestRevision(ctx, id)
	if err == nil {
		var currentRevision, converterVersion string
		err = s.db.QueryRow(ctx, `SELECT revision,converter_version FROM rule_sources WHERE id=$1`, id).Scan(&currentRevision, &converterVersion)
		if err == nil && revision == currentRevision && converterVersion == rulesource.ConverterVersion {
			err = s.markRuleSourceUnchanged(ctx, id)
			if err == nil {
				return
			}
		}
	}
	var catalog rulesource.Catalog
	if err == nil {
		catalog, err = rulesource.FetchRevision(ctx, id, revision)
	}
	if err == nil {
		err = s.applyRuleSourceCatalog(ctx, id, catalog)
	}
	if err != nil {
		failureCtx, failureCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer failureCancel()
		message := err.Error()
		if len(message) > 2000 {
			message = message[:2000]
		}
		_, _ = s.db.Exec(failureCtx, `UPDATE rule_sources SET status='failed',error=$2,updated_at=now() WHERE id=$1`, id, message)
	}
}

func (s *Server) markRuleSourceUnchanged(ctx context.Context, id string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT stats FROM rule_sources WHERE id=$1 FOR UPDATE`, id).Scan(&raw); err != nil {
		return err
	}
	var stats ruleSourceStats
	if json.Unmarshal(raw, &stats) != nil {
		return errors.New("decode stored rule source stats")
	}
	stats.Added, stats.Updated, stats.Preserved, stats.Retired = 0, 0, 0, 0
	stats.Unchanged = stats.Accepted
	raw, _ = json.Marshal(stats)
	_, err = tx.Exec(ctx, `UPDATE rule_sources SET status='ready',converter_version=$2,stats=$3,error='',updated_at=now() WHERE id=$1`,
		id, rulesource.ConverterVersion, raw)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) finishSourceRun(id string) {
	s.sourceMu.Lock()
	delete(s.sourceRunning, id)
	s.sourceMu.Unlock()
}

func (s *Server) loadRuleSource(ctx context.Context, id string) (ruleSourceStatus, error) {
	var item ruleSourceStatus
	var statsRaw, samplesRaw []byte
	err := s.db.QueryRow(ctx, `SELECT id,name,repository,license,status,revision,updated_at,error,stats,samples
		FROM rule_sources WHERE id=$1`, id).Scan(&item.ID, &item.Name, &item.Repository, &item.License,
		&item.Status, &item.Revision, &item.UpdatedAt, &item.Error, &statsRaw, &samplesRaw)
	if err == nil {
		err = json.Unmarshal(statsRaw, &item.Stats)
	}
	if err == nil {
		err = json.Unmarshal(samplesRaw, &item.Samples)
	}
	if item.Stats.Reasons == nil {
		item.Stats.Reasons = map[string]int{}
	}
	if item.Samples == nil {
		item.Samples = []rulesource.Rejection{}
	}
	return item, err
}

func (s *Server) getRuleSourceLicense(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := rulesource.SourceByID(id); !ok {
		writeError(w, http.StatusNotFound, "rule source not found")
		return
	}
	var license, licenseText, revision string
	if err := s.db.QueryRow(r.Context(), `SELECT license,license_text,revision FROM rule_sources WHERE id=$1`, id).Scan(
		&license, &licenseText, &revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "rule source not found")
		} else {
			writeError(w, http.StatusInternalServerError, "load rule source license failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"license": license, "license_text": licenseText, "revision": revision})
}

type sourceRuleRecord struct {
	rule            rulelib.Rule
	sourceID        string
	upstreamHash    string
	localModified   bool
	enabledOverride *bool
	retired         bool
	deleted         bool
}

func (s *Server) applyRuleSourceCatalog(ctx context.Context, sourceID string, catalog rulesource.Catalog) error {
	source, ok := rulesource.SourceByID(sourceID)
	if !ok {
		return errors.New("unknown rule source")
	}
	if catalog.Repository != source.Repository || !strings.EqualFold(catalog.License, "MIT") ||
		catalog.Revision == "" || !strings.HasPrefix(catalog.Digest, "sha256:") || catalog.LicenseText == "" {
		return errors.New("rule source catalog metadata is incomplete or unexpected")
	}
	skippedTotal := 0
	for reason, count := range catalog.Skipped {
		if strings.TrimSpace(reason) == "" || count < 0 {
			return errors.New("rule source catalog has invalid skipped statistics")
		}
		skippedTotal += count
	}
	if catalog.Total <= 0 || len(catalog.Rules) == 0 || catalog.Total != len(catalog.Rules)+skippedTotal {
		return errors.New("rule source catalog total must equal accepted plus skipped and contain usable rules")
	}
	prefix := "wa-"
	if sourceID == rulesource.NucleiID {
		prefix = "nt-"
	}
	rules := append([]rulelib.Rule(nil), catalog.Rules...)
	ids := make([]string, 0, len(rules))
	hashes := make(map[string]string, len(rules))
	seen := make(map[string]bool, len(rules))
	for index := range rules {
		rules[index].Enabled = true
		rules[index].Builtin = false
		if !strings.HasPrefix(rules[index].ID, prefix) || seen[rules[index].ID] {
			return fmt.Errorf("source catalog contains invalid or duplicate rule id %q", rules[index].ID)
		}
		if err := rulelib.Validate(rules[index]); err != nil {
			return fmt.Errorf("source rule %s: %w", rules[index].ID, err)
		}
		seen[rules[index].ID] = true
		ids = append(ids, rules[index].ID)
		hashes[rules[index].ID] = sourceRuleHash(rules[index])
	}
	stats := ruleSourceStats{Total: catalog.Total, Accepted: len(rules), Reasons: map[string]int{}}
	for reason, count := range catalog.Skipped {
		stats.Reasons[reason] = count
		stats.Skipped += count
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var lockedID string
	if err = tx.QueryRow(ctx, `SELECT id FROM rule_sources WHERE id=$1 FOR UPDATE`, sourceID).Scan(&lockedID); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id,rule,source_id,upstream_hash,local_modified,enabled_override,
		upstream_retired,deleted_at IS NOT NULL FROM rule_library WHERE source_id=$1 OR id=ANY($2) FOR UPDATE`, sourceID, ids)
	if err != nil {
		return err
	}
	existing := make(map[string]sourceRuleRecord)
	for rows.Next() {
		var id string
		var raw []byte
		var record sourceRuleRecord
		if err = rows.Scan(&id, &raw, &record.sourceID, &record.upstreamHash, &record.localModified,
			&record.enabledOverride, &record.retired, &record.deleted); err != nil || json.Unmarshal(raw, &record.rule) != nil {
			rows.Close()
			return errors.New("decode stored source rule")
		}
		existing[id] = record
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for _, incoming := range rules {
		record, exists := existing[incoming.ID]
		if !exists {
			raw, _ := json.Marshal(incoming)
			batch.Queue(`INSERT INTO rule_library(id,rule,seed_version,source_id,upstream_hash)
				VALUES($1,$2,$3,$4,$5)`, incoming.ID, raw, currentRuleSeedVersion, sourceID, hashes[incoming.ID])
			stats.Added++
			continue
		}
		if record.sourceID != sourceID || record.deleted || record.localModified {
			stats.Preserved++
			continue
		}
		if record.upstreamHash == hashes[incoming.ID] && !record.retired {
			stats.Unchanged++
			continue
		}
		if record.enabledOverride != nil {
			incoming.Enabled = *record.enabledOverride
		}
		incoming.Revision = record.rule.Revision + 1
		raw, _ := json.Marshal(incoming)
		batch.Queue(`UPDATE rule_library SET rule=$2,upstream_hash=$3,upstream_retired=false,updated_at=now()
			WHERE id=$1`, incoming.ID, raw, hashes[incoming.ID])
		stats.Updated++
	}
	for id, record := range existing {
		if record.sourceID != sourceID || seen[id] {
			continue
		}
		if record.deleted || record.localModified {
			stats.Preserved++
			continue
		}
		if record.retired {
			continue
		}
		record.rule.Enabled = false
		record.rule.Revision++
		raw, _ := json.Marshal(record.rule)
		batch.Queue(`UPDATE rule_library SET rule=$2,upstream_retired=true,updated_at=now() WHERE id=$1`, id, raw)
		stats.Retired++
	}
	if batch.Len() != 0 {
		if err = tx.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
	}
	statsRaw, _ := json.Marshal(stats)
	samples := catalog.Samples
	if len(samples) > 100 {
		samples = samples[:100]
	}
	samplesRaw, _ := json.Marshal(samples)
	_, err = tx.Exec(ctx, `UPDATE rule_sources SET license=$2,license_text=$3,status='ready',revision=$4,converter_version=$5,digest=$6,
		stats=$7,samples=$8,error='',updated_at=now() WHERE id=$1`, sourceID, catalog.License, catalog.LicenseText,
		catalog.Revision, rulesource.ConverterVersion, catalog.Digest, statsRaw, samplesRaw)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func sourceRuleHash(rule rulelib.Rule) string {
	rule.Revision = 1
	rule.Enabled = true
	rule.Builtin = false
	raw, _ := json.Marshal(rule)
	hash := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}
