package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/rulesource"
)

const fingerprintBundleSchema = `
CREATE TABLE IF NOT EXISTS fingerprint_bundles (
 digest text PRIMARY KEY CHECK(digest ~ '^[0-9a-f]{64}$'),
 source_revision text NOT NULL CHECK(source_revision ~ '^[0-9a-f]{40}$'),
 engine_revision text NOT NULL,
 package bytea NOT NULL,
 stats jsonb NOT NULL,
 source_notice text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS fingerprint_bundle_default (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 digest text NOT NULL REFERENCES fingerprint_bundles(digest)
);
CREATE OR REPLACE FUNCTION protect_fingerprint_bundle() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'fingerprint bundles are immutable'; END $$;
DROP TRIGGER IF EXISTS fingerprint_bundle_immutable ON fingerprint_bundles;
CREATE TRIGGER fingerprint_bundle_immutable BEFORE UPDATE OR DELETE ON fingerprint_bundles
 FOR EACH ROW EXECUTE FUNCTION protect_fingerprint_bundle();
INSERT INTO rule_sources(id,name,repository,license,license_text)
 VALUES('fingers','fingers passive fingerprints','https://github.com/chainreactors/fingers',
 'Mixed upstream provenance; see notices','')
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,repository=EXCLUDED.repository;
`

func initializeFingerprintBundles(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, fingerprintBundleSchema); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `UPDATE rule_sources SET license_text=$1 WHERE id='fingers'`, rulesource.FingersNotice)
	return err
}

// defaultFingerprintBundle must run inside the run-creation transaction so each
// run stores one stable digest, regardless of later source updates.
func defaultFingerprintBundle(ctx context.Context, tx pgx.Tx) (string, error) {
	var digest string
	err := tx.QueryRow(ctx, `SELECT digest FROM fingerprint_bundle_default WHERE singleton`).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return fingerprintbundle.EmbeddedBundle, nil
	}
	return digest, err
}

func (s *Server) updateFingerprintBundle(ctx context.Context) error {
	revision, err := rulesource.LatestRevision(ctx, rulesource.FingersID)
	if err != nil {
		return err
	}
	input, err := rulesource.FetchFingersRevision(ctx, revision)
	if err != nil {
		return err
	}
	data, err := prepareFingerprintBundle(ctx, input)
	if err != nil {
		return err
	}
	return s.applyFingerprintBundle(ctx, input, data)
}

// The checker is an installed, fixed-engine binary. Neither the HTTP request nor
// the downloaded resources can choose a program, argument, or network source.
func fingerprintCheckerBinary() string {
	if binary := strings.TrimSpace(os.Getenv("FINGERPRINT_CHECKER_BINARY")); binary != "" {
		return binary
	}
	if executable, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(executable), "tools", "fingerprint-worker")
	}
	return filepath.Join("tools", "fingerprint-worker")
}

type fingerprintOutput struct {
	buffer   bytes.Buffer
	max      int
	exceeded bool
}

func (output *fingerprintOutput) Write(data []byte) (int, error) {
	if len(data) > output.max-output.buffer.Len() {
		output.exceeded = true
		return 0, errors.New("fingerprint checker output limit exceeded")
	}
	return output.buffer.Write(data)
}

type fingerprintStderr struct {
	data []byte
	max  int
}

func (output *fingerprintStderr) Write(data []byte) (int, error) {
	n := len(data)
	if len(data) >= output.max {
		output.data = append(output.data[:0], data[len(data)-output.max:]...)
	} else {
		if overflow := len(output.data) + len(data) - output.max; overflow > 0 {
			copy(output.data, output.data[overflow:])
			output.data = output.data[:len(output.data)-overflow]
		}
		output.data = append(output.data, data...)
	}
	return n, nil
}

func runFingerprintChecker(ctx context.Context, input []byte, maxOutput int, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, fingerprintCheckerBinary(), args...)
	command.Stdin = bytes.NewReader(input)
	output := &fingerprintOutput{max: maxOutput}
	stderr := &fingerprintStderr{max: 16 << 10}
	command.Stdout, command.Stderr = output, stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("fingerprint checker: %w", ctx.Err())
		}
		return nil, fmt.Errorf("fingerprint checker failed: %w: %s", err, strings.TrimSpace(string(stderr.data)))
	}
	if output.exceeded {
		return nil, errors.New("fingerprint checker output limit exceeded")
	}
	return output.buffer.Bytes(), nil
}

func prepareFingerprintBundle(ctx context.Context, input fingerprintbundle.RawInput) ([]byte, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(raw) > fingerprintbundle.MaxInputBytes {
		return nil, errors.New("fingerprint checker input limit exceeded")
	}
	data, err := runFingerprintChecker(ctx, raw, fingerprintbundle.MaxPackageBytes, "--prepare-bundle")
	if err != nil {
		return nil, err
	}
	pkg, err := validatePreparedFingerprintBundle(input, data)
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp("", "shen-fingerprint-check-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	checked, err := runFingerprintChecker(ctx, nil, fingerprintbundle.MaxPackageBytes, "--check-bundle", file.Name())
	if err != nil {
		return nil, err
	}
	var result fingerprintbundle.Capabilities
	if err = json.Unmarshal(checked, &result); err != nil {
		return nil, fmt.Errorf("decode fingerprint checker response: %w", err)
	}
	if result.Bundle != fingerprintbundle.Digest(data) || result.Schema != pkg.Schema || result.EngineRevision != pkg.EngineRevision ||
		result.SelectionProfile != pkg.SelectionProfile || !reflect.DeepEqual(result.Validation, pkg.Validation) {
		return nil, errors.New("fingerprint checker validation does not match prepared package")
	}
	return data, nil
}

func validatePreparedFingerprintBundle(input fingerprintbundle.RawInput, data []byte) (fingerprintbundle.Package, error) {
	pkg, err := fingerprintbundle.Decode(data)
	if err != nil {
		return pkg, fmt.Errorf("validate prepared fingerprint package: %w", err)
	}
	if pkg.Source.Revision != input.SourceRevision || len(input.Files) != len(pkg.Files) {
		return pkg, errors.New("prepared fingerprint package source does not match download")
	}
	loaded := 0
	for _, filePath := range fingerprintbundle.Paths() {
		if !bytes.Equal(input.Files[filePath], pkg.Files[filePath].Raw) {
			return pkg, fmt.Errorf("prepared fingerprint package altered raw resource %s", filePath)
		}
	}
	for key, stats := range pkg.Validation {
		if key != "aliases" {
			loaded += stats.Loaded
		}
	}
	if loaded == 0 {
		return pkg, errors.New("fingerprint package contains no usable passive fingerprints")
	}
	return pkg, nil
}

func (s *Server) applyFingerprintBundle(ctx context.Context, input fingerprintbundle.RawInput, data []byte) error {
	pkg, err := validatePreparedFingerprintBundle(input, data)
	if err != nil {
		return err
	}
	digest := fingerprintbundle.Digest(data)
	stats := ruleSourceStats{Bundle: digest, EngineRevision: pkg.EngineRevision, Validation: pkg.Validation, Reasons: map[string]int{}}
	samples := make([]rulesource.Rejection, 0)
	for key, sourceStats := range pkg.Validation {
		stats.Total += sourceStats.Total
		stats.Accepted += sourceStats.Loaded
		stats.Skipped += sourceStats.Total - sourceStats.Loaded
		for reason, count := range sourceStats.Reasons {
			stats.Reasons[key+":"+reason] += count
		}
		for _, rejection := range sourceStats.Rejections {
			if len(samples) < 100 {
				samples = append(samples, rulesource.Rejection{Path: fmt.Sprintf("%s[%d]:%s", key, rejection.Index, rejection.ID), Reason: rejection.Reason + ": " + rejection.Detail})
			}
		}
	}
	statsRaw, _ := json.Marshal(stats)
	validationRaw, _ := json.Marshal(pkg.Validation)
	samplesRaw, _ := json.Marshal(samples)
	files := make([]storedSourceFile, 0, len(pkg.Files))
	for _, filePath := range fingerprintbundle.Paths() {
		file := pkg.Files[filePath]
		files = append(files, storedSourceFile{Path: filePath, SHA256: file.RawSHA256, Data: file.Raw})
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var sourceID string
	if err = tx.QueryRow(ctx, `SELECT id FROM rule_sources WHERE id='fingers' FOR UPDATE`).Scan(&sourceID); err != nil {
		return err
	}
	if err = persistCatalogSourceFiles(ctx, tx, rulesource.FingersID, pkg.Source.Revision, files); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO fingerprint_bundles(digest,source_revision,engine_revision,package,stats,source_notice)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(digest) DO NOTHING`, digest, pkg.Source.Revision, pkg.EngineRevision, data, validationRaw, rulesource.FingersNotice); err != nil {
		return err
	}
	var stored []byte
	if err = tx.QueryRow(ctx, `SELECT package FROM fingerprint_bundles WHERE digest=$1`, digest).Scan(&stored); err != nil {
		return err
	}
	if !bytes.Equal(stored, data) {
		return errors.New("immutable fingerprint digest already has different package bytes")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO fingerprint_bundle_default(singleton,digest) VALUES(true,$1)
		ON CONFLICT(singleton) DO UPDATE SET digest=EXCLUDED.digest`, digest); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE rule_sources SET status='ready',revision=$1,converter_version=$2,digest=$3,
		stats=$4,samples=$5,error='',updated_at=now() WHERE id='fingers'`, pkg.Source.Revision, fingerprintbundle.SelectionProfile, digest, statsRaw, samplesRaw); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) getFingerprintBundleStatus(w http.ResponseWriter, r *http.Request) {
	item, err := s.loadRuleSource(r.Context(), rulesource.FingersID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load fingerprint source failed")
		return
	}
	var digest string
	err = s.db.QueryRow(r.Context(), `SELECT digest FROM fingerprint_bundle_default WHERE singleton`).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		digest, err = fingerprintbundle.EmbeddedBundle, nil
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load fingerprint default failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": item, "default_bundle": digest, "engine_revision": fingerprintbundle.EngineRevision, "selection_profile": fingerprintbundle.SelectionProfile})
}

// Admin route, wrapped by s.admin at registration. Worker routes must authenticate
// task+attempt+lease first, then call writeFingerprintBundle with the run's pinned
// digest. A worker supplied digest must never authorize access on its own.
func (s *Server) getFingerprintBundle(w http.ResponseWriter, r *http.Request) {
	s.writeFingerprintBundle(w, r, r.PathValue("digest"))
}

func (s *Server) writeFingerprintBundle(w http.ResponseWriter, r *http.Request, digest string) {
	if len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		writeError(w, http.StatusBadRequest, "invalid fingerprint bundle digest")
		return
	}
	var data []byte
	err := s.db.QueryRow(r.Context(), `SELECT package FROM fingerprint_bundles WHERE digest=$1`, digest).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "fingerprint bundle not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load fingerprint bundle failed")
		return
	}
	if fingerprintbundle.Digest(data) != digest {
		writeError(w, http.StatusInternalServerError, "fingerprint bundle integrity failure")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set("X-Content-SHA256", digest)
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
