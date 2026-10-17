package control

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"scanplatform/internal/rulesource"
)

const (
	maxSourceFileBytes  = 16 << 20
	maxSourceFilesBytes = 256 << 20
	sourceManifestPath  = ".shen-source-manifest.json"
)

type storedSourceFile struct {
	Path       string
	SHA256     string
	Data       []byte
	IsTemplate bool
}

type sourceFileSummary struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	IsTemplate bool   `json:"is_template"`
}

type sourceFileManifest struct {
	SourceRef string               `json:"source_ref"`
	Digest    string               `json:"digest"`
	Files     []sourceManifestFile `json:"files"`
}

type sourceManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func catalogSourceFiles(sourceID string, catalog rulesource.Catalog) ([]storedSourceFile, error) {
	files := make(map[string]storedSourceFile, len(catalog.Files)+len(catalog.Rules))
	totalBytes := 0
	add := func(file storedSourceFile) error {
		if err := validateSourceFile(file); err != nil {
			return err
		}
		if prior, exists := files[file.Path]; exists {
			if prior.SHA256 != file.SHA256 || prior.IsTemplate != file.IsTemplate {
				return fmt.Errorf("source file %q is duplicated with different metadata", file.Path)
			}
			return nil
		}
		totalBytes += len(file.Data)
		if totalBytes > maxSourceFilesBytes {
			return fmt.Errorf("source files exceed %d bytes", maxSourceFilesBytes)
		}
		files[file.Path] = file
		return nil
	}
	for _, file := range catalog.Files {
		if err := add(storedSourceFile{Path: file.Path, SHA256: file.SHA256, Data: file.Data}); err != nil {
			return nil, err
		}
	}
	for _, rule := range catalog.Rules {
		if rule.Template == "" {
			continue
		}
		if rule.Upstream == nil || rule.Upstream.SourceID != sourceID || rule.Upstream.Revision != catalog.Revision {
			return nil, fmt.Errorf("source rule %q template has incomplete upstream identity", rule.ID)
		}
		if err := add(storedSourceFile{Path: rule.Upstream.Path, SHA256: rule.Upstream.SHA256,
			Data: []byte(rule.Template), IsTemplate: true}); err != nil {
			return nil, fmt.Errorf("source rule %q: %w", rule.ID, err)
		}
	}
	result := make([]storedSourceFile, 0, len(files))
	for _, file := range files {
		result = append(result, file)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func validateSourceFile(file storedSourceFile) error {
	if file.Path == "" || len(file.Path) > 1024 || file.Path == sourceManifestPath || path.Clean(file.Path) != file.Path ||
		strings.HasPrefix(file.Path, "/") || strings.HasPrefix(file.Path, "../") || strings.ContainsAny(file.Path, "\\\x00") {
		return fmt.Errorf("invalid source file path %q", file.Path)
	}
	if len(file.Data) > maxSourceFileBytes {
		return fmt.Errorf("source file %q exceeds %d bytes", file.Path, maxSourceFileBytes)
	}
	expected := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(file.SHA256)), "sha256:")
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("source file %q has invalid sha256", file.Path)
	}
	actual := sha256.Sum256(file.Data)
	if hex.EncodeToString(actual[:]) != expected {
		return fmt.Errorf("source file %q sha256 does not match data", file.Path)
	}
	return nil
}

func persistCatalogSourceFiles(ctx context.Context, tx pgx.Tx, sourceID, revision string, files []storedSourceFile) error {
	if len(files) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT path,sha256,is_template FROM rule_source_files WHERE source_id=$1 AND revision=$2`, sourceID, revision)
	if err != nil {
		return err
	}
	existing := make(map[string]storedSourceFile)
	for rows.Next() {
		var file storedSourceFile
		if err = rows.Scan(&file.Path, &file.SHA256, &file.IsTemplate); err != nil {
			rows.Close()
			return err
		}
		existing[file.Path] = file
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	copyRows := make([][]any, 0, len(files))
	for _, file := range files {
		if prior, ok := existing[file.Path]; ok {
			if prior.SHA256 != file.SHA256 || prior.IsTemplate != file.IsTemplate {
				return fmt.Errorf("immutable source file %q changed for revision %s", file.Path, revision)
			}
			continue
		}
		copyRows = append(copyRows, []any{sourceID, revision, file.Path, file.SHA256, file.Data, file.IsTemplate})
	}
	if len(copyRows) == 0 {
		return nil
	}
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"rule_source_files"},
		[]string{"source_id", "revision", "path", "sha256", "data", "is_template"}, pgx.CopyFromRows(copyRows))
	if err != nil {
		return err
	}
	if copied != int64(len(copyRows)) {
		return fmt.Errorf("stored %d of %d source files", copied, len(copyRows))
	}
	return nil
}

func (s *Server) sourceRevision(ctx context.Context, sourceID, requested string) (string, error) {
	if _, ok := rulesource.SourceByID(sourceID); !ok {
		return "", pgx.ErrNoRows
	}
	if revision := strings.TrimSpace(requested); revision != "" {
		var exists bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rule_source_files WHERE source_id=$1 AND revision=$2)`,
			sourceID, revision).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return "", pgx.ErrNoRows
		}
		return revision, nil
	}
	var revision string
	if err := s.db.QueryRow(ctx, `SELECT revision FROM rule_sources WHERE id=$1`, sourceID).Scan(&revision); err != nil {
		return "", err
	}
	if revision == "" {
		return "", pgx.ErrNoRows
	}
	return revision, nil
}

func (s *Server) listRuleSourceFiles(w http.ResponseWriter, r *http.Request) {
	revision, err := s.sourceRevision(r.Context(), r.PathValue("id"), r.URL.Query().Get("revision"))
	if err != nil {
		writeError(w, http.StatusNotFound, "rule source revision not found")
		return
	}
	limit, offset, err := pagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	var total int64
	if err = s.db.QueryRow(r.Context(), `SELECT count(*) FROM rule_source_files WHERE source_id=$1 AND revision=$2
		AND ($3='' OR path ILIKE '%'||$3||'%')`, r.PathValue("id"), revision, query).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule source files failed")
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT path,sha256,octet_length(data),is_template FROM rule_source_files
		WHERE source_id=$1 AND revision=$2 AND ($3='' OR path ILIKE '%'||$3||'%') ORDER BY path LIMIT $4 OFFSET $5`,
		r.PathValue("id"), revision, query, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule source files failed")
		return
	}
	defer rows.Close()
	items := make([]sourceFileSummary, 0, limit)
	for rows.Next() {
		var item sourceFileSummary
		if err = rows.Scan(&item.Path, &item.SHA256, &item.Size, &item.IsTemplate); err != nil {
			writeError(w, http.StatusInternalServerError, "load rule source files failed")
			return
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "load rule source files failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "revision": revision})
}

func (s *Server) getRuleSourceFile(w http.ResponseWriter, r *http.Request) {
	revision, err := s.sourceRevision(r.Context(), r.PathValue("id"), r.URL.Query().Get("revision"))
	if err != nil {
		writeError(w, http.StatusNotFound, "rule source revision not found")
		return
	}
	filePath := strings.TrimSpace(r.URL.Query().Get("path"))
	if filePath == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	var data []byte
	var digest string
	err = s.db.QueryRow(r.Context(), `SELECT data,sha256 FROM rule_source_files WHERE source_id=$1 AND revision=$2 AND path=$3`,
		r.PathValue("id"), revision, filePath).Scan(&data, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "rule source file not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rule source file failed")
		return
	}
	w.Header().Set("Content-Type", http.DetectContentType(data))
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(path.Base(filePath), `"`, "")+`"`)
	w.Header().Set("X-Content-SHA256", digest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) exportRuleSource(w http.ResponseWriter, r *http.Request) {
	revision, err := s.sourceRevision(r.Context(), r.PathValue("id"), r.URL.Query().Get("revision"))
	if err != nil {
		writeError(w, http.StatusNotFound, "rule source revision not found")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.zip"`, r.PathValue("id"), revision))
	if _, err = s.writeSourceZip(r.Context(), w, r.PathValue("id"), revision, true); err != nil {
		return
	}
}

func sourceFilesDigest(files []sourceFileSummary) string {
	manifestFiles := make([]sourceManifestFile, len(files))
	for index, file := range files {
		manifestFiles[index] = sourceManifestFile{Path: file.Path, SHA256: file.SHA256, Size: file.Size}
	}
	raw, _ := json.Marshal(manifestFiles)
	hash := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func (s *Server) sourceFileMetadata(ctx context.Context, sourceID, revision string, includeTemplates bool) ([]sourceFileSummary, error) {
	rows, err := s.db.Query(ctx, `SELECT path,sha256,octet_length(data),is_template FROM rule_source_files
		WHERE source_id=$1 AND revision=$2 AND ($3 OR NOT is_template) ORDER BY path`, sourceID, revision, includeTemplates)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	files := make([]sourceFileSummary, 0)
	for rows.Next() {
		var file sourceFileSummary
		if err = rows.Scan(&file.Path, &file.SHA256, &file.Size, &file.IsTemplate); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, rows.Err()
}

func (s *Server) writeSourceZip(ctx context.Context, response http.ResponseWriter, sourceID, revision string, includeTemplates bool) (string, error) {
	files, err := s.sourceFileMetadata(ctx, sourceID, revision, includeTemplates)
	if err != nil {
		return "", err
	}
	digest := sourceFilesDigest(files)
	response.Header().Set("X-Source-Ref", sourceID+":"+revision)
	response.Header().Set("X-Source-Files-Digest", digest)
	archive := zip.NewWriter(response)
	rows, err := s.db.Query(ctx, `SELECT path,data FROM rule_source_files
		WHERE source_id=$1 AND revision=$2 AND ($3 OR NOT is_template) ORDER BY path`, sourceID, revision, includeTemplates)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var filePath string
		var data []byte
		if err = rows.Scan(&filePath, &data); err != nil {
			break
		}
		header := &zip.FileHeader{Name: filePath, Method: zip.Deflate}
		header.SetMode(0o644)
		header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		var writer interface{ Write([]byte) (int, error) }
		writer, err = archive.CreateHeader(header)
		if err == nil {
			_, err = writer.Write(data)
		}
		if err != nil {
			break
		}
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err == nil {
		manifestFiles := make([]sourceManifestFile, len(files))
		for index, file := range files {
			manifestFiles[index] = sourceManifestFile{Path: file.Path, SHA256: file.SHA256, Size: file.Size}
		}
		manifest, _ := json.MarshalIndent(sourceFileManifest{SourceRef: sourceID + ":" + revision, Digest: digest, Files: manifestFiles}, "", "  ")
		var writer interface{ Write([]byte) (int, error) }
		writer, err = archive.Create(sourceManifestPath)
		if err == nil {
			_, err = writer.Write(manifest)
		}
	}
	closeErr := archive.Close()
	if err == nil {
		err = closeErr
	}
	return digest, err
}
