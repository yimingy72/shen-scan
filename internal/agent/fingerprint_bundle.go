package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	fb "scanplatform/internal/fingerprintbundle"
)

var fingerprintDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FingerprintBundle downloads only the snapshot assigned to this execution.
// There is deliberately no caller-controlled digest in the server request.
func (c *Client) FingerprintBundle(ctx context.Context, workerID, sessionID string, task Task, expected string) ([]byte, error) {
	if !fingerprintDigestPattern.MatchString(expected) || task.ID == "" || task.AttemptNo < 1 || workerID == "" || sessionID == "" {
		return nil, fmt.Errorf("invalid fingerprint download identity")
	}
	query := url.Values{"worker_id": {workerID}, "session_id": {sessionID}, "attempt_no": {fmt.Sprint(task.AttemptNo)}}
	downloadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(downloadCtx, http.MethodGet, c.baseURL+"/api/tasks/"+url.PathEscape(task.ID)+"/fingerprint-bundle?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.workerToken)
	client := *c.upload
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fingerprint bundle download returned %s", response.Status)
	}
	if response.ContentLength > fb.MaxPackageBytes {
		return nil, fmt.Errorf("fingerprint bundle download exceeds limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, fb.MaxPackageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > fb.MaxPackageBytes {
		return nil, fmt.Errorf("fingerprint bundle download exceeds limit")
	}
	if fb.Digest(data) != expected {
		return nil, fmt.Errorf("fingerprint bundle download digest mismatch")
	}
	if _, err = fb.Decode(data); err != nil {
		return nil, fmt.Errorf("invalid downloaded fingerprint bundle: %w", err)
	}
	return data, nil
}

// ponytail: one cached package and one active matcher per Agent. The matcher
// slot is held, and its old process stopped, before replacing cached data.
type fingerprintBundleCache struct {
	mu     sync.Mutex
	path   string
	digest string
	info   os.FileInfo
}

func (cache *fingerprintBundleCache) get(ctx context.Context, c *Client, workerID, sessionID string, task Task, digest string) (string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", context.Cause(ctx)
	}
	if !fingerprintDigestPattern.MatchString(digest) {
		return "", fmt.Errorf("invalid fingerprint bundle digest")
	}
	dir := os.Getenv("FINGERPRINT_CACHE_DIR")
	if dir == "" {
		root, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(root, "shen-scan", "fingerprints")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, digest+".json")
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > fb.MaxPackageBytes {
			return "", fmt.Errorf("fingerprint cache entry is not a private bounded regular file")
		}
		if cache.path == path && cache.digest == digest && cache.info != nil && os.SameFile(cache.info, info) && cache.info.Size() == info.Size() && cache.info.ModTime().Equal(info.ModTime()) {
			return path, nil
		}
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, fb.MaxPackageBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		if len(data) > fb.MaxPackageBytes || fb.Digest(data) != digest {
			return "", fmt.Errorf("fingerprint cache digest mismatch")
		}
		if _, err = fb.Decode(data); err != nil {
			return "", fmt.Errorf("invalid fingerprint cache: %w", err)
		}
		if err = pruneFingerprintCache(dir, path); err != nil {
			return "", err
		}
		cache.path, cache.digest, cache.info = path, digest, info
		return path, nil
	}
	if !os.IsNotExist(statErr) {
		return "", statErr
	}
	// The previous helper has exited before this call. Retain at most one package
	// plus an atomic temporary write, including after an Agent restart.
	if err = pruneFingerprintCache(dir, ""); err != nil {
		return "", err
	}
	data, err := c.FingerprintBundle(ctx, workerID, sessionID, task, digest)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".bundle-*")
	if err != nil {
		return "", err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if err = os.Rename(temporary, path); err != nil {
		return "", err
	}
	info, err = os.Lstat(path)
	if err != nil {
		return "", err
	}
	cache.path, cache.digest, cache.info = path, digest, info
	return path, nil
}

func pruneFingerprintCache(dir, keep string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		managed := len(name) == 69 && name[64:] == ".json" && fingerprintDigestPattern.MatchString(name[:64])
		// Clean abandoned atomic writes from this dedicated cache as well.
		if len(name) >= 8 && name[:8] == ".bundle-" {
			managed = true
		}
		path := filepath.Join(dir, name)
		if managed && path != keep && !entry.IsDir() {
			if err = os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}
