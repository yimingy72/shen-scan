package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fb "scanplatform/internal/fingerprintbundle"
	"scanplatform/internal/webevidence"
)

func TestFingerprintBundleDownloadCacheAndMatcherSwitch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "fingerprint-worker")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-tags", "passive_only", "-o", binary, ".")
	build.Dir = "../../cmd/fingerprint-worker"
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build local helper: %v: %s", err, output)
	}
	t.Setenv("FINGERPRINT_WORKER_BINARY", binary)
	t.Setenv("FINGERPRINT_CACHE_DIR", t.TempDir())
	zipped := func(data string) []byte {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		_, _ = z.Write([]byte(data))
		_ = z.Close()
		return b.Bytes()
	}
	prepare := func(name string) []byte {
		input := fb.RawInput{SourceRevision: fb.EngineRevision, Files: map[string][]byte{
			"resources/fingers_http.json.gz":       zipped(`[{"name":"fixture-native","rule":[{"regexps":{"body":["snapshot-token"]}}]}]`),
			"resources/fingerprinthub_web.json.gz": zipped(`[]`),
			"resources/ehole.json.gz":              zipped(`{"fingerprint":[]}`),
			"resources/aliases.yaml":               []byte(`[{"name":"` + name + `","alias":{"fingers":["fixture-native"]}}]`),
		}}
		data, _ := json.Marshal(input)
		command := exec.CommandContext(ctx, binary, "--prepare-bundle")
		command.Stdin = bytes.NewReader(data)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		if err != nil {
			t.Fatalf("prepare fixture: %v: %s", err, stderr.String())
		}
		if _, err = fb.Decode(output); err != nil {
			t.Fatal(err)
		}
		return output
	}
	packageA, packageB := prepare("snapshot-a"), prepare("snapshot-b")
	digestA, digestB := fb.Digest(packageA), fb.Digest(packageB)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer fixture-worker-token" || len(r.URL.Query()) != 3 || r.URL.Query().Get("worker_id") != "worker-a" || r.URL.Query().Get("session_id") != "session-a" || r.URL.Query().Get("attempt_no") != "7" {
			t.Error("download lost authorized execution identity")
			http.Error(w, "identity", 401)
			return
		}
		switch r.URL.Path {
		case "/api/tasks/task-a/fingerprint-bundle":
			_, _ = w.Write(packageA)
		case "/api/tasks/task-b/fingerprint-bundle":
			_, _ = w.Write(packageB)
		default:
			t.Errorf("unexpected assigned bundle route %s", r.URL.String())
			http.Error(w, "scope", 403)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	client.workerToken = "fixture-worker-token"
	taskA := Task{ID: "task-a", AttemptNo: 7}
	taskB := Task{ID: "task-b", AttemptNo: 7}
	process := fingerprintProcess{slot: make(chan struct{}, 1)}
	t.Cleanup(process.stop)
	var wg sync.WaitGroup
	paths := make(chan string, 12)
	errors := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path, err := process.cache.get(ctx, client, "worker-a", "session-a", taskA, digestA)
			if err != nil {
				errors <- err
				return
			}
			paths <- path
		}()
	}
	wg.Wait()
	close(errors)
	close(paths)
	for err := range errors {
		t.Fatal(err)
	}
	pathA := ""
	for path := range paths {
		if pathA != "" && pathA != path {
			t.Fatal("concurrent download paths differ")
		}
		pathA = path
	}
	if requests.Load() != 1 {
		t.Fatalf("concurrent downloads not deduplicated: %d", requests.Load())
	}
	info, err := os.Stat(pathA)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("cache permissions are not private")
	}
	if err = os.WriteFile(pathA, []byte("bad cached snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = process.cache.get(ctx, client, "worker-a", "session-a", taskA, digestA); err == nil {
		t.Fatal("bad disk cache accepted")
	}
	if err = os.WriteFile(pathA, packageA, 0600); err != nil {
		t.Fatal(err)
	}
	input := webevidence.MatchRequest{Protocol: webevidence.Protocol, ID: "fixture-observation", ExpectedBundle: digestA, Response: webevidence.Response{URL: "http://fixture.invalid/", StatusCode: 200, Proto: "HTTP/1.1", Completeness: "full", Headers: http.Header{"Content-Type": []string{"text/html"}}, Body: []byte("snapshot-token")}}
	resolve := func(task Task, digest string) func(context.Context) (string, error) {
		return func(ctx context.Context) (string, error) {
			return process.cache.get(ctx, client, "worker-a", "session-a", task, digest)
		}
	}
	assertMatch := func(digest, name string, task Task) {
		input.ExpectedBundle = digest
		result, err := process.matchBundle(ctx, input, fb.Schema, resolve(task, digest))
		if err != nil {
			t.Fatal(err)
		}
		if result.Bundle != digest || len(result.Matches) != 1 || result.Matches[0].Name != name {
			t.Fatalf("wrong snapshot matcher: %+v", result)
		}
	}
	assertMatch(digestA, "snapshot-a", taskA)
	firstPID := process.cmd.Process.Pid
	assertMatch(digestA, "snapshot-a", taskA)
	if process.cmd.Process.Pid != firstPID || requests.Load() != 1 {
		t.Fatal("same bundle restarted or downloaded again")
	}
	assertMatch(digestB, "snapshot-b", taskB)
	if process.cmd.Process.Pid == firstPID || requests.Load() != 2 {
		t.Fatal("bundle switch failed to restart once")
	}
	if _, err = os.Stat(pathA); !os.IsNotExist(err) {
		t.Fatal("old package was not evicted after its matcher stopped")
	}
	entries, err := os.ReadDir(os.Getenv("FINGERPRINT_CACHE_DIR"))
	if err != nil || len(entries) != 1 {
		t.Fatal("cache did not retain exactly one package")
	}
	if _, err = client.FingerprintBundle(ctx, "worker-a", "session-a", taskA, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted download with incorrect assigned digest")
	}
	if _, err = client.FingerprintBundle(ctx, "worker-a", "session-a", Task{ID: "task-a"}, digestA); err == nil {
		t.Fatal("accepted missing attempt identity")
	}
	process.stop()
	input.ExpectedBundle = fb.EmbeddedBundle
	if result, err := process.match(ctx, input); err != nil || result.Bundle != fb.EmbeddedBundle {
		t.Fatal(fmt.Sprintf("legacy embedded mode failed: %+v %v", result, err))
	}
}
