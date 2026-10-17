package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanplatform/internal/webevidence"
)

func TestWebProbePoolParallelReuseAndCancelIsolation(t *testing.T) {
	binary := os.Getenv("TEST_WEB_PROBE_BINARY")
	if binary == "" {
		t.Skip("set TEST_WEB_PROBE_BINARY to built helper")
	}
	wave, survive := make(chan struct{}), make(chan struct{})
	entered := make(chan string, 8)
	var active, peak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(404)
			return
		}
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		var gate <-chan struct{}
		switch {
		case strings.HasPrefix(r.URL.Path, "/wave/"):
			gate = wave
		case r.URL.Path == "/cancel":
			gate = make(chan struct{})
		case r.URL.Path == "/survive":
			gate = survive
		}
		if gate != nil {
			entered <- r.URL.Path
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprint(w, r.URL.Path)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := newHTTPXTestAgent(t, "unused")
	if cap(a.webProbes) != 2 {
		t.Fatalf("pool capacity=%d", cap(a.webProbes))
	}
	type reply struct {
		id  string
		err error
	}
	run := func(ctx context.Context, id string) <-chan reply {
		done := make(chan reply, 1)
		go func() {
			raw, err := a.runWebHelper(ctx, binary, webevidence.ProbeRequest{Protocol: webevidence.Protocol, ID: id, URL: server.URL + id, ConnectIP: "127.0.0.1", CFFSHA256: webevidence.SHA256(nil)})
			var result webevidence.ProbeResult
			if err == nil {
				err = json.Unmarshal(raw, &result)
			}
			if err == nil && (result.ID != id || result.Response.StatusCode != 200) {
				err = fmt.Errorf("unrelated/incomplete item: %+v", result)
			}
			done <- reply{id, err}
		}()
		return done
	}
	wait := func(done <-chan reply) reply {
		select {
		case result := <-done:
			return result
		case <-ctx.Done():
			t.Fatal("helper pool fixture timed out")
			return reply{}
		}
	}
	enteredOne := func() string {
		select {
		case id := <-entered:
			return id
		case <-ctx.Done():
			t.Fatal("entries did not overlap")
			return ""
		}
	}
	snapshot := func() map[int]*exec.Cmd {
		processes := make([]*webProbeProcess, 0, cap(a.webProbes))
		result := map[int]*exec.Cmd{}
		for i := 0; i < cap(a.webProbes); i++ {
			p := <-a.webProbes
			processes = append(processes, p)
			if p.cmd != nil {
				result[p.cmd.Process.Pid] = p.cmd
			}
		}
		for _, p := range processes {
			a.webProbes <- p
		}
		return result
	}
	pids := func(commands map[int]*exec.Cmd) []int {
		var result []int
		for pid := range commands {
			result = append(result, pid)
		}
		sort.Ints(result)
		return result
	}
	first := []<-chan reply{run(ctx, "/wave/one"), run(ctx, "/wave/two"), run(ctx, "/wave/three")}
	enteredOne()
	enteredOne()
	select {
	case id := <-entered:
		t.Fatalf("third entry bypassed cap2: %s", id)
	case <-time.After(40 * time.Millisecond):
	}
	close(wave)
	for _, done := range first {
		if result := wait(done); result.err != nil {
			t.Fatal(result.err)
		}
	}
	enteredOne() // Third entry starts after one of the two processes is returned.
	original := snapshot()
	if metrics := a.resources.metrics(); metrics["web_probe_processes"] != 2 {
		t.Fatalf("resident helpers not tracked: %+v", metrics)
	}
	if len(original) != 2 || peak.Load() != 2 {
		t.Fatalf("helpers did not overlap at bounded2: pids=%v peak=%d", pids(original), peak.Load())
	}
	warm := []<-chan reply{run(ctx, "/warm/one"), run(ctx, "/warm/two")}
	for _, done := range warm {
		if result := wait(done); result.err != nil {
			t.Fatal(result.err)
		}
	}
	if current := snapshot(); !reflect.DeepEqual(pids(original), pids(current)) {
		t.Fatalf("warm helpers restarted: before=%v after=%v", pids(original), pids(current))
	}
	cancelCtx, cancelOne := context.WithCancel(ctx)
	canceled, other := run(cancelCtx, "/cancel"), run(ctx, "/survive")
	enteredOne()
	enteredOne()
	cancelOne()
	if result := wait(canceled); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("canceled item=%+v", result)
	}
	select {
	case result := <-other:
		t.Fatalf("canceling peer completed surviving item: %+v", result)
	case <-time.After(40 * time.Millisecond):
	}
	close(survive)
	if result := wait(other); result.err != nil || result.id != "/survive" {
		t.Fatalf("peer poisoned by cancellation: %+v", result)
	}
	surviving := snapshot()
	if metrics := a.resources.metrics(); metrics["web_probe_processes"] != 1 {
		t.Fatalf("canceled helper remains tracked: %+v", metrics)
	}
	if len(surviving) != 1 {
		t.Fatalf("cancel should reap exactly one process: pids=%v", pids(surviving))
	}
	for pid := range surviving {
		if original[pid] == nil {
			t.Fatalf("unrelated surviving process: %d", pid)
		}
	}
	if result := wait(run(ctx, "/recovered")); result.err != nil {
		t.Fatal(result.err)
	}
	recovered := snapshot()
	if len(recovered) != 2 {
		t.Fatalf("canceled slot did not recover: %v", pids(recovered))
	}
	for pid := range surviving {
		if recovered[pid] == nil {
			t.Fatal("recovering canceled slot restarted surviving helper")
		}
	}
	a.stopWebProbes()
	if metrics := a.resources.metrics(); metrics["web_probe_processes"] != 0 {
		t.Fatalf("stopped helpers remain tracked: %+v", metrics)
	}
	if remaining := snapshot(); len(remaining) != 0 {
		t.Fatalf("close left helpers: %v", pids(remaining))
	}
	for _, command := range recovered {
		if command.ProcessState == nil {
			t.Fatal("helper close did not wait for process exit")
		}
	}
}
