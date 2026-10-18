package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestMasscanCostProfileRegistration(t *testing.T) {
	observed := make(chan map[string]any, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		var spec map[string]any
		if err := json.Unmarshal(request.Spec, &spec); err != nil {
			t.Error(err)
		}
		observed <- spec
		json.NewEncoder(w).Encode(RegisterResponse{WorkerID: "fixture-worker", WorkerToken: "fixture-token"})
	}))
	defer server.Close()
	dir := t.TempDir()
	binary := filepath.Join(dir, "masscan")
	t.Setenv("PATH", dir)
	for _, contents := range []string{"#!/bin/sh\n# old artifact\n", "#!/bin/sh\n# changed artifact\n", ""} {
		if contents == "" {
			if err := os.Remove(binary); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(binary, []byte(contents), 0700); err != nil {
			t.Fatal(err)
		}
		a, err := New(Config{ControlURL: server.URL, JoinToken: "fixture-join", InstanceID: "fixture", Hostname: "local", SessionID: "s1", PortExecutor: "connect", AllowPrivateTargets: true, Spec: json.RawMessage(`{"port_profile":"declared-calibration-group","port_cost_profile":"forged"}`)})
		if err != nil {
			t.Fatal(err)
		}
		a.portExecutor = "masscan" // Registration does not execute the fixture file.
		if _, err = a.register(context.Background()); err != nil {
			t.Fatal(err)
		}
		spec := <-observed
		want := ""
		if contents != "" {
			digest := sha256.Sum256([]byte(contents))
			want = "masscan-sha256:" + hex.EncodeToString(digest[:])
		}
		if spec["port_cost_profile"] != want || spec["port_profile"] != "declared-calibration-group" {
			t.Fatalf("spec=%+v want actual profile=%s", spec, want)
		}
	}
}
