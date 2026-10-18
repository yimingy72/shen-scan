package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func admissionFixture(t *testing.T) *Agent {
	t.Helper()
	a := newHTTPXTestAgent(t, "unused")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.NmapBinary = binary
	a.cfg.HTTPXThreads = 8
	return a
}
func TestHTTPConnectionReservationsFollowExecutionPath(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a := admissionFixture(t)
	for _, test := range []struct {
		name, helper, payload string
		want                  int
		isHelper              bool
	}{
		{"single helper", binary, `{"endpoints":[{}]}`, 1, true},
		{"multi helper", binary, `{"endpoints":[{},{},{}]}`, 2, true},
		{"CLI conservative threads", "disabled", `{"endpoints":[{}],"rules":[{"enabled":true,"engine":"httpx-cff"}]}`, 8, false},
		{"native fanout", "disabled", `{"endpoints":[{},{},{}]}`, 2, false},
		{"native singleton", "disabled", `{"endpoints":[{}]}`, 1, false},
		{"unknown rule reference", "disabled", `{"endpoints":[{}],"rules_ref":"unresolved"}`, 8, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("WEB_PROBE_BINARY", test.helper)
			slots, helper := a.httpReservation(json.RawMessage(test.payload))
			if slots != test.want || helper != test.isHelper {
				t.Fatalf("reservation=%d helper=%v", slots, helper)
			}
		})
	}
	t.Setenv("WEB_PROBE_BINARY", binary)
	a.active = map[string]activeTask{"service": {typeName: "service"}, "poc": {typeName: "poc"}, "http": {typeName: "http", connectionSlots: 1, webHelper: true}}
	if used, next := a.connectionEstimate(); used != 9 || next != 1 {
		t.Fatalf("helper slots used=%d next=%d", used, next)
	}
	if got := fmt.Sprint(a.claimOptions()); got != "[[port] [http]]" {
		t.Fatalf("second helper was unnecessarily blocked: %s", got)
	}
	a.active["http2"] = activeTask{typeName: "http", connectionSlots: 2, webHelper: true}
	if a.estimatedConnections() != 10 {
		t.Fatal("shared helper pool ceiling was not honored")
	}
	t.Setenv("WEB_PROBE_BINARY", "disabled")
	a.active = map[string]activeTask{"service": {typeName: "service"}, "poc": {typeName: "poc"}, "http": {typeName: "http", connectionSlots: 8}}
	if a.estimatedConnections() != 16 || fmt.Sprint(a.claimOptions()) != "[[port]]" {
		t.Fatal("CLI connection reservation was relaxed")
	}
	a.updateHTTPReservation("http", 1, false, false)
	if a.estimatedConnections() != 9 {
		t.Fatal("resolved native plan did not update conservative reservation")
	}
}

func TestServicePreferenceBoundsAndExistingFairness(t *testing.T) {
	a := admissionFixture(t)
	now := time.Now()
	a.setServicePreference(true, 0, now)
	if !a.servicePreferred(now) || a.servicePreferred(now.Add(21*time.Second)) {
		t.Fatal("default hint TTL not20s")
	}
	a.setServicePreference(true, 999, now)
	if a.servicePreferred(now.Add(61 * time.Second)) {
		t.Fatal("hint TTL unbounded")
	}
	a.setServicePreference(true, 20, now.Add(-21*time.Second))
	if got := a.claimOptions(); len(got) == 0 || fmt.Sprint(got[0]) != "[port]" {
		t.Fatalf("expired hint reordered claims: %v", got)
	}
	a.setServicePreference(true, 20, now)
	got := a.claimOptions()
	if fmt.Sprint(got[0]) != "[service]" || fmt.Sprint(got[1]) != "[port]" {
		t.Fatalf("live hint not first: %v", got)
	}
	count := 0
	for _, types := range got {
		for _, kind := range types {
			if kind == "service" {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatal("service duplicated in later group")
	}
	saved := a.cfg.NmapBinary
	a.cfg.NmapBinary = filepath.Join(t.TempDir(), "missing")
	if got := a.claimOptions(); len(got) == 0 || fmt.Sprint(got[0]) != "[port]" {
		t.Fatalf("missingNmap hint changed order: %v", got)
	}
	a.cfg.NmapBinary = saved
	a.active["service"] = activeTask{typeName: "service"}
	if got := a.claimOptions(); len(got) == 0 || fmt.Sprint(got[0]) != "[port]" {
		t.Fatalf("occupiedservice hint changed order: %v", got)
	}
	delete(a.active, "service")
	a.cfg.EndpointConcurrency = 3
	if got := a.claimOptions(); len(got) == 0 || fmt.Sprint(got[0]) != "[port]" {
		t.Fatalf("hint ignored local connection bound: %v", got)
	}
	a.cfg.EndpointConcurrency = 16
	a.cfg.MaxTasks = 1
	if got := fmt.Sprint(a.claimOptions()); got != "[[port] [service http poc]]" {
		t.Fatalf("single-slot fairness changed: %s", got)
	}
	a.lastTaskType = "port"
	if got := fmt.Sprint(a.claimOptions()); got != "[[service http poc] [port]]" {
		t.Fatalf("single-slot rotation changed: %s", got)
	}
	a.cfg.MaxTasks = 17
	a.setServicePreference(false, 20, now)
	if a.servicePreferred(now) {
		t.Fatal("false hint did not clear preference")
	}
}

type admissionEvidenceTransport struct {
	base http.RoundTripper
	t    *testing.T
}

func (e admissionEvidenceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	rawRequest, err := httputil.DumpRequestOut(request, true)
	if err != nil {
		return nil, err
	}
	response, err := e.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	rawResponse, err := httputil.DumpResponse(response, true)
	if err != nil {
		return nil, err
	}
	// This fixture has no Authorization header or real deployment credentials.
	e.t.Logf("LOCAL HTTP %s\n%s\n%s", request.URL, rawRequest, rawResponse)
	return response, nil
}
func TestHeartbeatServiceHintAndNilClaimFallsBackToPort(t *testing.T) {
	a := admissionFixture(t)
	a.workerID = "local-worker"
	var types [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/workers/heartbeat" {
			var in HeartbeatRequest
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				t.Error("bad heartbeat")
			}
			for _, key := range []string{"tools_processes", "web_probe_processes", "fingerprint_processes", "connection_slots_used", "connection_slots_limit", "upload_queued_bytes", "admission_paused"} {
				if _, ok := in.Metrics[key]; !ok {
					t.Errorf("missing metric %s", key)
				}
			}
			fmt.Fprint(w, `{"action":"continue","prefer_service":true,"preference_ttl_seconds":20}`)
			return
		}
		var in struct {
			Types    []string `json:"types"`
			Phase    string   `json:"http_phase"`
			Reserved bool     `json:"port_start_reserved"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if in.Phase == "browser" {
			fmt.Fprint(w, `{"task":null}`)
			return
		}
		types = append(types, in.Types)
		if len(types) == 1 {
			fmt.Fprint(w, `{"task":null}`)
			return
		}
		if !in.Reserved {
			t.Error("port fallback lost real start reservation")
		}
		fmt.Fprint(w, `{"task":{"id":"local-port","type":"port","attempt_no":1,"payload":{}}}`)
	}))
	defer server.Close()
	a.client.baseURL = server.URL
	a.client.control.Transport = admissionEvidenceTransport{base: a.client.control.Transport, t: t}
	a.client.serviceCapabilityOnce.Do(func() { a.client.serviceProfile = "nmap-light-v1" })
	a.client.webCapabilityOnce.Do(func() {})
	a.sendHeartbeat(context.Background(), func() {})
	if !a.servicePreferred(time.Now()) {
		t.Fatal("heartbeat hint not applied")
	}
	task, err := a.claimAvailable(context.Background())
	if err != nil || task == nil || task.Type != "port" || !reflect.DeepEqual(types, [][]string{{"service"}, {"port"}}) || a.portStartReserved.Load() {
		t.Fatalf("nil service claim did not fall back/release reservation: task=%+v err=%v types=%v", task, err, types)
	}
}
