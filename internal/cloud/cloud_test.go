package cloud

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
)

func TestBootstrapScript(t *testing.T) {
	script, err := BootstrapScript(BootstrapConfig{
		ControlURL:       "https://control.example.com",
		ControlCAPEM:     "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----\n",
		AgentPackageURL:  "https://packages.example.com/scan-agent.tar.gz",
		AgentPackageHash: strings.Repeat("a", 64),
		JoinToken:        "test-join-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"sha256sum -c", "/opt/scan-agent/scan-agent", "agent-bootstrap.sh /opt/scan-agent", "AGENT_CA_FILE", "AGENT_VERSION=bundle-aaaaaaaaaaaa"} {
		if !strings.Contains(script, required) {
			t.Fatalf("bootstrap script missing %q", required)
		}
	}
	if strings.Contains(script, "test-join-token") {
		t.Fatal("bootstrap script contains the join token as plaintext")
	}
	redacted := shortError(assertError("request?AccessKeyId=secret-id&Signature=secret-signature&SecurityToken=secret-token"))
	if strings.Contains(redacted, "secret-") {
		t.Fatalf("cloud error was not redacted: %s", redacted)
	}
}

type assertError string

func (e assertError) Error() string { return string(e) }

func TestInstanceIsSpot(t *testing.T) {
	for _, tc := range []struct {
		strategy string
		legacy   bool
		want     bool
	}{
		{"SpotAsPriceGo", false, true},
		{"SpotWithPriceLimit", false, true},
		{"NoSpot", true, false},
		{"", true, true},
		{"", false, false},
		{"unknown", true, false},
	} {
		t.Run(tc.strategy+"/"+strconv.FormatBool(tc.legacy), func(t *testing.T) {
			got := instanceIsSpot(ecs.Instance{SpotStrategy: tc.strategy, IsSpot: tc.legacy})
			if got != tc.want {
				t.Fatalf("instanceIsSpot() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCloudClientsRequireHTTPS(t *testing.T) {
	e, c, v, err := newAliyunClients(config{region: "cn-hangzhou", accessKeyID: "test-id", accessKeySecret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	for name, scheme := range map[string]string{"ecs": e.GetConfig().Scheme, "cms": c.GetConfig().Scheme, "vpc": v.GetConfig().Scheme} {
		if scheme != "HTTPS" {
			t.Fatalf("%s configured with %s", name, scheme)
		}
	}
}

func TestParseInterruptionContent(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"object", `{"action":"delete","instanceId":"i-one"}`, "i-one"},
		{"string wrapper", `{"content":"{\"action\":\"delete\",\"instanceId\":\"i-two\"}"}`, "i-two"},
		{"array wrapper", `[{"content":{"action":"delete","instanceIds":["i-three"]}}]`, "i-three"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deleted, ids := parseInterruptionContent(tc.raw)
			if !deleted || len(ids) != 1 || ids[0] != tc.want {
				t.Fatalf("parseInterruptionContent() = %v, %v", deleted, ids)
			}
		})
	}
	instance := ecs.Instance{Tags: ecs.TagsInDescribeInstances{Tag: []ecs.Tag{{TagKey: poolTag, TagValue: "pool-real"}}}}
	if got := tagValue(instance, poolTag); got != "pool-real" {
		t.Fatalf("tagValue() = %q, want TagKey/TagValue response", got)
	}
	if got := capacityDeficit(1, 0, 3); got != 0 {
		t.Fatalf("capacityDeficit() = %d; unconfirmed instances must prevent creation", got)
	}
	want := time.Date(2026, 10, 16, 16, 7, 0, 0, time.UTC)
	if got := instanceCreatedAt(ecs.Instance{CreationTime: "2026-10-16T16:07Z"}); !got.Equal(want) {
		t.Fatalf("instanceCreatedAt() = %s, want %s", got, want)
	}
}
