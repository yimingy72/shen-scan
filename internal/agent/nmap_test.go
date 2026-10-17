package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTCPIntervalsAndStrictMasscanRecords(t *testing.T) {
	for value, want := range map[string][2]int{"1-65535": {1, 65535}, "1-16383": {1, 16383}, "16384-32767": {16384, 32767}, "65535": {65535, 65535}} {
		first, last, err := parseTCPPortRange(value)
		if err != nil || first != want[0] || last != want[1] {
			t.Fatalf("%s = %d..%d, %v", value, first, last, err)
		}
	}
	for _, value := range []string{"", "0-10", "2-1", "1-65536", "1,2", "T:1-65535", "1-2 --rate 1000000", "+1", "1-2-3"} {
		if _, _, err := parseTCPPortRange(value); err == nil {
			t.Fatalf("accepted malformed range %q", value)
		}
	}
	if captureLossError("no capture statistics") == nil {
		t.Fatal("missing capture quality proof counted as complete")
	}
	for _, line := range []string{"open tcp bad 192.0.2.1\n", "open tcp 443 not-an-ip\n", "open tcp 443\n"} {
		if err := scanMasscan(strings.NewReader(line), func(Observation) error { return nil }); err == nil {
			t.Fatalf("silently ignored malformed record %q", line)
		}
	}
}

func TestNmapStreamPreservesCompletedPortsAndRejectsGuesses(t *testing.T) {
	endpoints := []Endpoint{{IP: "192.0.2.10", Port: 18081, WorkKey: "http"}, {IP: "192.0.2.10", Port: 443}, {IP: "192.0.2.10", Port: 2222}}
	input := `<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>` +
		`<port protocol="tcp" portid="18081"><state state="open"/><service name="http" product="fixture" method="probed" conf="10"/></port>` +
		`<port protocol="tcp" portid="443"><state state="open"/><service name="https" method="table" conf="3"/></port>` +
		`<port protocol="tcp" portid="2222"><state state="open"/><service name="ssh" method="probed" conf="10"/></port>`
	var got []Observation
	parsed, err := parseNmapXML(strings.NewReader(input), endpoints, func(obs Observation) error { got = append(got, obs); return nil })
	if err == nil || len(parsed.seen) != 3 || len(got) != 3 {
		t.Fatalf("lost completed records: %+v %v", got, err)
	}
	if !got[0].WebCandidate || got[0].WorkKey != "http" || got[0].Outcome != "identified" {
		t.Fatalf("nonstandard HTTP not identified: %+v", got[0])
	}
	if got[1].Outcome != "unknown" || got[1].Service != "unknown" || !got[1].WebCandidate {
		t.Fatalf("table guess treated as identity: %+v", got[1])
	}
	if got[2].WebCandidate {
		t.Fatalf("known SSH sent to Web: %+v", got[2])
	}
	_, err = parseNmapXML(strings.NewReader(`<nmaprun><host><ports><port protocol="tcp" portid="80"/></ports></host></nmaprun>`), endpoints, func(Observation) error { return nil })
	if err == nil {
		t.Fatal("accepted out-of-scope port")
	}
	_, err = parseNmapXML(strings.NewReader(input), endpoints, func(Observation) error { return io.ErrClosedPipe })
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestNmapBatchRetainsSuccessAndAccountsMissingEndpoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	path := filepath.Join(t.TempDir(), "nmap-fixture")
	fixture := `#!/bin/sh
printf '%s' '<nmaprun><host><address addr="127.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="18081"><state state="open"/><service name="http" method="probed" conf="10"/></port>'
exit 1
`
	if err := os.WriteFile(path, []byte(fixture), 0700); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "test", InstanceID: "test", Hostname: "test", SessionID: "test", NmapBinary: path, AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	var got []Observation
	err = a.runNmapService(context.Background(), servicePayload{Endpoints: []Endpoint{{IP: "127.0.0.2", Port: 18081}, {IP: "127.0.0.2", Port: 18082}}, TimeoutSeconds: 2}, func(obs Observation) error { got = append(got, obs); return nil })
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Outcome != "identified" || got[1].Coverage != "incomplete" || got[1].Error == "" {
		t.Fatalf("missing endpoint counted success or sibling lost: %+v", got)
	}
	args := strings.Join(nmapArgs([]Endpoint{{IP: "127.0.0.2", Port: 18082}, {IP: "127.0.0.2", Port: 18081}}, time.Minute), " ")
	if !strings.Contains(args, "-p 18081,18082") || strings.Contains(args, "-A") || strings.Contains(args, "--script") {
		t.Fatal(args)
	}
}

func TestNmapLoopbackHTTP(t *testing.T) {
	if os.Getenv("SCAN_NMAP_INTEGRATION") != "1" {
		t.Skip("set SCAN_NMAP_INTEGRATION=1 for installed Nmap against a loopback-only HTTP fixture")
	}
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.26.0")
		fmt.Fprint(w, "<html><title>Local Nmap Fixture</title></html>")
	}))
	defer fixture.Close()
	address := fixture.Listener.Addr().(*net.TCPAddr)
	a, err := New(Config{ControlURL: "http://127.0.0.1:1", JoinToken: "test", InstanceID: "test", Hostname: "test", SessionID: "test", AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	var got []Observation
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = a.runNmapService(ctx, servicePayload{Endpoints: []Endpoint{{IP: "127.0.0.1", Port: address.Port}}, TimeoutSeconds: 15}, func(obs Observation) error { got = append(got, obs); return nil })
	if err != nil || len(got) != 1 || !got[0].WebCandidate || got[0].Outcome != "identified" {
		t.Fatalf("loopback result %+v, %v", got, err)
	}
	t.Logf("loopback TCP %d: service=%s product=%s version=%s outcome=%s candidate=%v", address.Port, got[0].Service, got[0].Product, got[0].Version, got[0].Outcome, got[0].WebCandidate)
}

func TestPortClaimHoldsLocalReservation(t *testing.T) {
	var a *Agent
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PortStartReserved  bool `json:"port_start_reserved"`
			SupportsPortRanges bool `json:"supports_port_ranges"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if !a.portStartReserved.Load() || !body.PortStartReserved || !body.SupportsPortRanges {
			t.Error("port slot not reserved for in-flight claim")
		}
		fmt.Fprint(w, `{"task":null}`)
	}))
	defer control.Close()
	var err error
	a, err = New(Config{ControlURL: control.URL, JoinToken: "test", InstanceID: "test", Hostname: "test", SessionID: "test", NucleiBinary: "missing-nuclei-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.claim(context.Background(), []string{"port"}); err != nil {
		t.Fatal(err)
	}
	if a.portStartReserved.Load() {
		t.Fatal("reservation not released after response")
	}
	a.cfg.NmapBinary = "missing-nmap-fixture"
	for _, types := range a.claimOptions() {
		for _, stage := range types {
			if stage == "service" {
				t.Fatal("claimed service without nmap")
			}
		}
	}
}
