package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"scanplatform/internal/fingerprintbundle"
)

func fingerprintStorageFixture(t *testing.T, revision string) (fingerprintbundle.RawInput, []byte) {
	t.Helper()
	input := fingerprintbundle.RawInput{SourceRevision: revision, Files: map[string][]byte{}}
	pkg := fingerprintbundle.Package{Schema: fingerprintbundle.Schema, EngineRevision: fingerprintbundle.EngineRevision,
		SelectionProfile: fingerprintbundle.SelectionProfile, Source: fingerprintbundle.Source{Repository: fingerprintbundle.Repository, Revision: revision},
		Files: map[string]fingerprintbundle.File{}, Validation: map[string]fingerprintbundle.Stats{}}
	for _, path := range fingerprintbundle.Paths() {
		decoded := []byte("[]")
		key := "aliases"
		switch path {
		case "resources/fingers_http.json.gz":
			key = "fingers"
			decoded = []byte(`[{"name":"fixture-native","rule":[{"regexps":{"body":["snapshot-token"]}}]}]`)
		case "resources/fingerprinthub_web.json.gz":
			key = "fingerprinthub"
		case "resources/ehole.json.gz":
			key = "ehole"
			decoded = []byte(`{"fingerprint":[]}`)
		}
		raw := decoded
		if strings.HasSuffix(path, ".gz") {
			var buf bytes.Buffer
			writer := gzip.NewWriter(&buf)
			_, _ = writer.Write(decoded)
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			raw = buf.Bytes()
		}
		input.Files[path] = raw
		pkg.Files[path] = fingerprintbundle.File{Raw: raw, RawSHA256: fingerprintbundle.Digest(raw), DecodedSHA256: fingerprintbundle.Digest(decoded), DecodedBytes: len(decoded), Effective: decoded, EffectiveSHA256: fingerprintbundle.Digest(decoded)}
		stats := fingerprintbundle.Stats{Reasons: map[string]int{}, Rejections: []fingerprintbundle.Rejection{}}
		if key == "fingers" {
			stats.Total = 1
			stats.Loaded = 1
		}
		pkg.Validation[key] = stats
	}
	data, err := fingerprintbundle.Encode(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return input, data
}

func TestFingerprintCheckerFailureAndOutputLimit(t *testing.T) {
	file := filepath.Join(t.TempDir(), "checker")
	if err := os.WriteFile(file, []byte("#!/bin/sh\nprintf rejected >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FINGERPRINT_CHECKER_BINARY", file)
	if _, err := runFingerprintChecker(context.Background(), nil, 64, "--prepare-bundle"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("checker failure was hidden: %v", err)
	}
	if err := os.WriteFile(file, []byte("#!/bin/sh\nprintf 123456789\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := runFingerprintChecker(context.Background(), nil, 4); err == nil {
		t.Fatal("accepted oversized checker output")
	}
	if err := os.WriteFile(file, []byte("#!/bin/sh\nprintf '%020000d' 0 >&2\nprintf valid\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := runFingerprintChecker(context.Background(), nil, 64); err != nil || string(output) != "valid" {
		t.Fatalf("normal stderr volume interrupted valid checker output: %q %v", output, err)
	}
	input, data := fingerprintStorageFixture(t, strings.Repeat("a", 40))
	input.Files["resources/aliases.yaml"] = []byte("[1]")
	if _, err := validatePreparedFingerprintBundle(input, data); err == nil {
		t.Fatal("accepted checker-altered raw source")
	}
}

func TestFingerprintCheckerBuildsAndValidates(t *testing.T) {
	binary := os.Getenv("TEST_FINGERPRINT_BINARY")
	if binary == "" {
		t.Skip("TEST_FINGERPRINT_BINARY is not set")
	}
	t.Setenv("FINGERPRINT_CHECKER_BINARY", binary)
	input, _ := fingerprintStorageFixture(t, strings.Repeat("a", 40))
	data, err := prepareFingerprintBundle(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := fingerprintbundle.Decode(data)
	if err != nil || pkg.Validation["fingers"].Loaded != 1 {
		t.Fatalf("real checker did not load native fixture: %v", err)
	}
}

func TestFingerprintBundlePublicationIsAtomicAndImmutable(t *testing.T) {
	databaseURL := os.Getenv("CONTROL_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTROL_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := "fingerprint_test_" + strings.ReplaceAll(newID(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+name); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, `DROP SCHEMA `+name+` CASCADE`)
	u, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", name)
	u.RawQuery = query.Encode()
	db, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(ctx, schema); err != nil {
		t.Fatal(err)
	}
	if err = initializeFingerprintBundles(ctx, db); err != nil {
		t.Fatal(err)
	}
	server := &Server{db: db, adminHash: sha256.Sum256([]byte("local-test-admin"))}
	inputA, dataA := fingerprintStorageFixture(t, strings.Repeat("a", 40))
	digestA := fingerprintbundle.Digest(dataA)
	if err = server.applyFingerprintBundle(ctx, inputA, dataA); err != nil {
		t.Fatal(err)
	}
	if err = server.applyFingerprintBundle(ctx, inputA, dataA); err != nil {
		t.Fatalf("idempotent publication failed: %v", err)
	}
	if _, err = db.Exec(ctx, `INSERT INTO runs(id,name,targets,modes,status,rules_snapshot) VALUES('old-run','old','[]','{}','pending',$1)`, map[string]string{"fingerprint_bundle": digestA}); err != nil {
		t.Fatal(err)
	}
	inputB, dataB := fingerprintStorageFixture(t, strings.Repeat("b", 40))
	// Force a failure inside the publication transaction, after source locking.
	if _, err = db.Exec(ctx, `INSERT INTO rule_source_files(source_id,revision,path,sha256,data) VALUES('fingers',$1,'resources/aliases.yaml','conflicting-hash','bad')`, inputB.SourceRevision); err != nil {
		t.Fatal(err)
	}
	if err = server.applyFingerprintBundle(ctx, inputB, dataB); err == nil {
		t.Fatal("accepted conflicting immutable source data")
	}
	var digest string
	if err = db.QueryRow(ctx, `SELECT digest FROM fingerprint_bundle_default`).Scan(&digest); err != nil || digest != digestA {
		t.Fatalf("failed update switched default: %s, %v", digest, err)
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM fingerprint_bundles`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed publication stored a package: %d, %v", count, err)
	}
	inputC, dataC := fingerprintStorageFixture(t, strings.Repeat("c", 40))
	if err = server.applyFingerprintBundle(ctx, inputC, dataC); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE fingerprint_bundles SET package='tampered' WHERE digest=$1`, digestA); err == nil {
		t.Fatal("old immutable bundle was updated")
	}
	if _, err = db.Exec(ctx, `DELETE FROM fingerprint_bundles WHERE digest=$1`, digestA); err == nil {
		t.Fatal("old immutable bundle was deleted")
	}
	if err = db.QueryRow(ctx, `SELECT rules_snapshot->>'fingerprint_bundle' FROM runs WHERE id='old-run'`).Scan(&digest); err != nil || digest != digestA {
		t.Fatal("old run digest changed")
	}
	request := httptest.NewRequest(http.MethodGet, "/api/library/fingerprint-bundles/"+digest, nil)
	request.Header.Set("Authorization", "Bearer local-test-admin")
	request.SetPathValue("digest", digest)
	response := httptest.NewRecorder()
	server.admin(server.getFingerprintBundle)(response, request)
	if response.Code != 200 || !bytes.Equal(response.Body.Bytes(), dataA) || response.Header().Get("X-Content-SHA256") != digestA {
		t.Fatalf("old run could not download original bytes: %d", response.Code)
	}
	downloadResponse := response
	response = httptest.NewRecorder()
	server.getFingerprintBundleStatus(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	var status struct {
		Default string `json:"default_bundle"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &status); err != nil || status.Default != fingerprintbundle.Digest(dataC) {
		t.Fatalf("status not updated: %s %v", response.Body.String(), err)
	}
	if outputDir := os.Getenv("FINGERPRINT_TEST_EVIDENCE_DIR"); outputDir != "" {
		if err = os.MkdirAll(outputDir, 0700); err != nil {
			t.Fatal(err)
		}
		requestBytes, dumpErr := httputil.DumpRequest(request, true)
		if dumpErr != nil {
			t.Fatal(dumpErr)
		}
		responseBytes, dumpErr := httputil.DumpResponse(downloadResponse.Result(), true)
		if dumpErr != nil {
			t.Fatal(dumpErr)
		}
		full := append(append(requestBytes, '\n'), responseBytes...)
		if err = os.WriteFile(filepath.Join(outputDir, "old-package-download.http"), full, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(outputDir, "current-source-status.json"), response.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
