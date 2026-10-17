package rulesource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	// Bump when conversion or read-only eligibility changes so a fixed upstream
	// commit is converted again.
	ConverterVersion   = "3"
	maxArchiveBytes    = 128 << 20
	maxExpandedBytes   = 256 << 20
	maxSourceFileBytes = 16 << 20
	maxSourceFiles     = 100_000
	maxAPIResponse     = 1 << 20
)

type Source struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Owner      string `json:"-"`
	Repo       string `json:"-"`
}

var sources = []Source{
	{ID: WappalyzerID, Name: "Wappalyzer fingerprints", Repository: "https://github.com/projectdiscovery/wappalyzergo", Owner: "projectdiscovery", Repo: "wappalyzergo"},
	{ID: NucleiID, Name: "Nuclei templates", Repository: "https://github.com/projectdiscovery/nuclei-templates", Owner: "projectdiscovery", Repo: "nuclei-templates"},
}

func Sources() []Source { return append([]Source(nil), sources...) }

func SourceByID(id string) (Source, bool) {
	for _, source := range sources {
		if source.ID == id {
			return source, true
		}
	}
	return Source{}, false
}

func Fetch(ctx context.Context, sourceID string) (Catalog, error) {
	_, ok := SourceByID(sourceID)
	if !ok {
		return Catalog{}, fmt.Errorf("unknown rule source %q", sourceID)
	}
	revision, err := LatestRevision(ctx, sourceID)
	if err != nil {
		return Catalog{}, err
	}
	return FetchRevision(ctx, sourceID, revision)
}

func LatestRevision(ctx context.Context, sourceID string) (string, error) {
	source, ok := SourceByID(sourceID)
	if !ok {
		return "", fmt.Errorf("unknown rule source %q", sourceID)
	}
	return latestRevision(ctx, source)
}

func FetchRevision(ctx context.Context, sourceID, revision string) (Catalog, error) {
	source, ok := SourceByID(sourceID)
	if !ok {
		return Catalog{}, fmt.Errorf("unknown rule source %q", sourceID)
	}
	if !validCommitSHA(revision) {
		return Catalog{}, errors.New("rule source revision must be a full commit SHA")
	}
	files, err := downloadArchive(ctx, source, revision)
	if err != nil {
		return Catalog{}, err
	}
	licenseText, err := requiredFile(files, "LICENSE.md")
	if err != nil {
		return Catalog{}, fmt.Errorf("verify %s license: %w", sourceID, err)
	}
	if !isMITLicense(licenseText) {
		return Catalog{}, fmt.Errorf("verify %s license: repository license is not an accepted MIT text", sourceID)
	}
	var catalog Catalog
	switch sourceID {
	case WappalyzerID:
		fingerprints, fileErr := requiredFile(files, "fingerprints_data.json")
		if fileErr != nil {
			return Catalog{}, fmt.Errorf("load Wappalyzer fingerprints: %w", fileErr)
		}
		catalog, err = ConvertWappalyzer(fingerprints)
	case NucleiID:
		catalog, err = ConvertNuclei(files)
	}
	if err != nil {
		return Catalog{}, err
	}
	catalog.Revision = revision
	catalog.Digest = digestArchiveFiles(files)
	catalog.Repository = source.Repository
	catalog.License = "MIT"
	catalog.LicenseText = string(licenseText)
	return catalog, nil
}

func latestRevision(ctx context.Context, source Source) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/HEAD", source.Owner, source.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "scanplatform-rule-source/1")
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := sourceHTTPClient("api.github.com").Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve %s revision: %w", source.ID, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolve %s revision: GitHub API returned %s", source.ID, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponse+1))
	if err != nil {
		return "", fmt.Errorf("resolve %s revision: %w", source.ID, err)
	}
	if len(data) > maxAPIResponse {
		return "", fmt.Errorf("resolve %s revision: GitHub API response is too large", source.ID)
	}
	var result struct {
		SHA string `json:"sha"`
	}
	if json.Unmarshal(data, &result) != nil || !validCommitSHA(result.SHA) {
		return "", fmt.Errorf("resolve %s revision: GitHub API returned an invalid commit", source.ID)
	}
	return strings.ToLower(result.SHA), nil
}

func downloadArchive(ctx context.Context, source Source, revision string) (map[string][]byte, error) {
	url := fmt.Sprintf("https://codeload.github.com/%s/%s/tar.gz/%s", source.Owner, source.Repo, revision)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "scanplatform-rule-source/1")
	response, err := sourceHTTPClient("codeload.github.com").Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s archive: %w", source.ID, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s archive: codeload returned %s", source.ID, response.Status)
	}
	if response.ContentLength > maxArchiveBytes {
		return nil, fmt.Errorf("download %s archive: compressed archive exceeds %d bytes", source.ID, maxArchiveBytes)
	}
	compressed, err := io.ReadAll(io.LimitReader(response.Body, maxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download %s archive: %w", source.ID, err)
	}
	if len(compressed) > maxArchiveBytes {
		return nil, fmt.Errorf("download %s archive: compressed archive exceeds %d bytes", source.ID, maxArchiveBytes)
	}
	return unpackArchive(compressed)
}

func sourceHTTPClient(host string) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	base.TLSHandshakeTimeout = 15 * time.Second
	base.ResponseHeaderTimeout = 30 * time.Second
	return &http.Client{Transport: &retryTransport{base: base, attempts: 3, backoff: 250 * time.Millisecond}, Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Hostname(), host) || req.URL.Port() != "" {
			return errors.New("rule source redirect left the permitted HTTPS origin")
		}
		return nil
	}}
}

type retryTransport struct {
	base     http.RoundTripper
	attempts int
	backoff  time.Duration
}

func (transport *retryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet || transport.attempts <= 1 {
		return transport.base.RoundTrip(request)
	}
	var lastErr error
	for attempt := 0; attempt < transport.attempts; attempt++ {
		response, err := transport.base.RoundTrip(request.Clone(request.Context()))
		if err == nil {
			return response, nil
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		lastErr = err
		if attempt+1 == transport.attempts || request.Context().Err() != nil {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * transport.backoff)
		select {
		case <-request.Context().Done():
			timer.Stop()
			return nil, request.Context().Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func unpackArchive(compressed []byte) (map[string][]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open source archive: %w", err)
	}
	defer gzipReader.Close()
	archive := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	root := ""
	var expanded int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read source archive: %w", err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}
		name, entryRoot, err := archivePath(header.Name)
		if err != nil {
			return nil, err
		}
		if root == "" {
			root = entryRoot
		} else if root != entryRoot {
			return nil, errors.New("source archive contains multiple roots")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return nil, fmt.Errorf("source archive contains unsupported entry %q", header.Name)
		}
		if name == "" || header.Size < 0 || header.Size > maxSourceFileBytes {
			return nil, fmt.Errorf("source archive file %q exceeds the per-file limit", header.Name)
		}
		expanded += header.Size
		if expanded > maxExpandedBytes {
			return nil, fmt.Errorf("source archive expands beyond %d bytes", maxExpandedBytes)
		}
		if len(files) >= maxSourceFiles {
			return nil, fmt.Errorf("source archive contains more than %d files", maxSourceFiles)
		}
		if _, duplicate := files[name]; duplicate {
			return nil, fmt.Errorf("source archive contains duplicate path %q", name)
		}
		data, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return nil, fmt.Errorf("read source archive file %q", name)
		}
		files[name] = data
	}
	if len(files) == 0 {
		return nil, errors.New("source archive contains no files")
	}
	return files, nil
}

func archivePath(name string) (relative, root string, err error) {
	if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", "", fmt.Errorf("source archive contains unsafe path %q", name)
	}
	original := name
	name = strings.TrimSuffix(name, "/")
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return "", "", fmt.Errorf("source archive contains unsafe path %q", original)
	}
	parts := strings.Split(clean, "/")
	if len(parts) == 1 {
		return "", parts[0], nil
	}
	return strings.Join(parts[1:], "/"), parts[0], nil
}

func requiredFile(files map[string][]byte, wanted string) ([]byte, error) {
	var found []byte
	for name, data := range files {
		if strings.EqualFold(path.Clean(name), wanted) {
			if found != nil {
				return nil, fmt.Errorf("archive contains multiple %s files", wanted)
			}
			found = data
		}
	}
	if found == nil {
		return nil, fmt.Errorf("archive does not contain repository-root %s", wanted)
	}
	return found, nil
}

func isMITLicense(data []byte) bool {
	text := strings.ToLower(string(data))
	return strings.Contains(text, "mit license") && strings.Contains(text, "permission is hereby granted") &&
		strings.Contains(text, "without restriction") && strings.Contains(text, "the software is provided \"as is\"")
}

func validCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestArchiveFiles(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		_, _ = io.WriteString(hash, name)
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(files[name])
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
