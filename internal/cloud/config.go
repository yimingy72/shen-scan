package cloud

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type config struct {
	provider          string
	accessKeyID       string
	accessKeySecret   string
	securityToken     string
	region            string
	zone              string
	imageID           string
	vswitchIDs        []string
	instanceTypes     []string
	securityGroupID   string
	poolID            string
	controlURL        string
	controlCAFile     string
	controlCAPEM      string
	agentPackageURL   string
	agentPackageHash  string
	joinToken         string
	priceLimit        *float64
	minMemoryGiB      float64
	publicBandwidth   int
	validationFixture bool
}

// BootstrapConfig contains the values needed to install and register one Agent.
// JoinToken is written only to the instance's root-readable environment file.
type BootstrapConfig struct {
	ControlURL        string
	ControlCAPEM      string
	AgentPackageURL   string
	AgentPackageHash  string
	JoinToken         string
	ValidationFixture bool
}

func configFromEnv() (config, error) {
	c := config{
		provider:          strings.ToLower(strings.TrimSpace(env("SCAN_CLOUD_PROVIDER", "manual"))),
		accessKeyID:       strings.TrimSpace(os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")),
		accessKeySecret:   strings.TrimSpace(os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")),
		securityToken:     strings.TrimSpace(os.Getenv("ALIBABA_CLOUD_SECURITY_TOKEN")),
		region:            strings.TrimSpace(os.Getenv("SCAN_ALI_REGION")),
		zone:              strings.TrimSpace(env("SCAN_ALI_ZONE_ID", env("SCAN_ALI_ZONE", "cn-hangzhou-h"))),
		imageID:           strings.TrimSpace(os.Getenv("SCAN_ALI_IMAGE_ID")),
		vswitchIDs:        csv(os.Getenv("SCAN_ALI_VSWITCH_IDS")),
		instanceTypes:     csv(os.Getenv("SCAN_ALI_INSTANCE_TYPES")),
		securityGroupID:   strings.TrimSpace(os.Getenv("SCAN_ALI_SECURITY_GROUP_ID")),
		poolID:            strings.TrimSpace(os.Getenv("SCAN_POOL_ID")),
		controlURL:        strings.TrimRight(strings.TrimSpace(os.Getenv("SCAN_CONTROL_PUBLIC_URL")), "/"),
		controlCAFile:     strings.TrimSpace(os.Getenv("SCAN_CONTROL_CA_FILE")),
		agentPackageURL:   strings.TrimSpace(os.Getenv("SCAN_AGENT_PACKAGE_URL")),
		agentPackageHash:  strings.ToLower(strings.TrimSpace(os.Getenv("SCAN_AGENT_PACKAGE_SHA256"))),
		joinToken:         os.Getenv("SCAN_JOIN_TOKEN"),
		minMemoryGiB:      2,
		publicBandwidth:   10,
		validationFixture: parseBool(os.Getenv("SCAN_AGENT_VALIDATION_FIXTURE")),
	}
	if c.provider != "manual" && c.provider != "aliyun" {
		return c, fmt.Errorf("unsupported SCAN_CLOUD_PROVIDER %q", c.provider)
	}
	if value := strings.TrimSpace(os.Getenv("SCAN_ALI_PRICE_LIMIT")); value != "" {
		price, err := strconv.ParseFloat(value, 64)
		if err != nil || price <= 0 {
			return c, errors.New("SCAN_ALI_PRICE_LIMIT must be a positive number")
		}
		c.priceLimit = &price
	}
	if value := strings.TrimSpace(os.Getenv("SCAN_ALI_MIN_MEMORY_GIB")); value != "" {
		memory, err := strconv.ParseFloat(value, 64)
		if err != nil || memory < 1 || memory > 64 {
			return c, errors.New("SCAN_ALI_MIN_MEMORY_GIB must be a number between 1 and 64")
		}
		c.minMemoryGiB = memory
	}
	if value := strings.TrimSpace(os.Getenv("SCAN_ALI_PUBLIC_BANDWIDTH_MBIT")); value != "" {
		bandwidth, err := strconv.Atoi(value)
		if err != nil || bandwidth < 1 || bandwidth > 100 {
			return c, errors.New("SCAN_ALI_PUBLIC_BANDWIDTH_MBIT must be an integer between 1 and 100")
		}
		c.publicBandwidth = bandwidth
	}
	if c.provider == "manual" {
		return c, nil
	}
	err := c.validate()
	return c, err
}

func (c *config) validate() error {
	if c.provider == "manual" {
		return nil
	}
	var missing []string
	for name, value := range map[string]string{
		"ALIBABA_CLOUD_ACCESS_KEY_ID":     c.accessKeyID,
		"ALIBABA_CLOUD_ACCESS_KEY_SECRET": c.accessKeySecret,
		"SCAN_ALI_REGION":                 c.region,
		"SCAN_POOL_ID":                    c.poolID,
		"SCAN_CONTROL_PUBLIC_URL":         c.controlURL,
		"SCAN_CONTROL_CA_FILE":            c.controlCAFile,
		"SCAN_AGENT_PACKAGE_URL":          c.agentPackageURL,
		"SCAN_AGENT_PACKAGE_SHA256":       c.agentPackageHash,
		"SCAN_JOIN_TOKEN":                 c.joinToken,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing Alibaba Cloud configuration: %s", strings.Join(missing, ", "))
	}
	ca, err := os.ReadFile(c.controlCAFile)
	if err != nil {
		return fmt.Errorf("read SCAN_CONTROL_CA_FILE: %w", err)
	}
	c.controlCAPEM = string(ca)
	_, err = BootstrapScript(BootstrapConfig{
		ControlURL: c.controlURL, ControlCAPEM: c.controlCAPEM, AgentPackageURL: c.agentPackageURL,
		AgentPackageHash: c.agentPackageHash, JoinToken: c.joinToken, ValidationFixture: c.validationFixture,
	})
	return err
}

func (c config) readyError() error {
	var missing []string
	if c.imageID == "" {
		missing = append(missing, "SCAN_ALI_IMAGE_ID or cloud setup")
	}
	if c.securityGroupID == "" {
		missing = append(missing, "SCAN_ALI_SECURITY_GROUP_ID or cloud setup")
	}
	if len(c.vswitchIDs) == 0 {
		missing = append(missing, "SCAN_ALI_VSWITCH_IDS or cloud setup")
	}
	if len(c.instanceTypes) == 0 {
		missing = append(missing, "SCAN_ALI_INSTANCE_TYPES or cloud setup")
	}
	if len(missing) > 0 {
		return fmt.Errorf("Alibaba Cloud worker resources are not configured: %s", strings.Join(missing, ", "))
	}
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func csv(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// BootstrapScript returns cloud-init user data without logging or persisting its secrets.
func BootstrapScript(c BootstrapConfig) (string, error) {
	if err := validHTTPURL("SCAN_CONTROL_PUBLIC_URL", c.ControlURL, false); err != nil {
		return "", err
	}
	if err := validHTTPURL("SCAN_AGENT_PACKAGE_URL", c.AgentPackageURL, true); err != nil {
		return "", err
	}
	if len(c.AgentPackageHash) != sha256.Size*2 {
		return "", errors.New("SCAN_AGENT_PACKAGE_SHA256 must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(c.AgentPackageHash); err != nil {
		return "", errors.New("SCAN_AGENT_PACKAGE_SHA256 must contain 64 hexadecimal characters")
	}
	if c.JoinToken == "" || strings.ContainsAny(c.JoinToken, "\r\n\x00") {
		return "", errors.New("SCAN_JOIN_TOKEN must be non-empty and single-line")
	}
	if !strings.Contains(c.ControlCAPEM, "-----BEGIN CERTIFICATE-----") {
		return "", errors.New("SCAN_CONTROL_CA_FILE must contain a PEM certificate")
	}
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	fixture := "false"
	if c.ValidationFixture {
		fixture = "true"
	}
	script := `#!/bin/sh
set -eu
umask 077
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
package_url=$(printf '%s' '` + encode(c.AgentPackageURL) + `' | base64 -d)
printf '%s' '` + encode(c.ControlCAPEM) + `' | base64 -d > "$tmp_dir/control-ca.crt"
curl --cacert "$tmp_dir/control-ca.crt" -fsSL --retry 4 --retry-connrefused "$package_url" -o "$tmp_dir/scan-agent.tar.gz"
printf '%s  %s\n' '` + c.AgentPackageHash + `' "$tmp_dir/scan-agent.tar.gz" | sha256sum -c -
install -d -m 0755 /opt/scan-agent
tar -xzf "$tmp_dir/scan-agent.tar.gz" -C /opt/scan-agent
if [ ! -x /opt/scan-agent/scan-agent ] && [ -x /opt/scan-agent/agent ]; then
  ln -sf agent /opt/scan-agent/scan-agent
fi
test -x /opt/scan-agent/scan-agent
test -x /opt/scan-agent/agent-bootstrap.sh
test -s /opt/scan-agent/ca.crt
control_url=$(printf '%s' '` + encode(c.ControlURL) + `' | base64 -d)
join_token=$(printf '%s' '` + encode(c.JoinToken) + `' | base64 -d)
{
  printf 'AGENT_CONTROL_URL=%s\n' "$control_url"
  printf 'SCAN_JOIN_TOKEN=%s\n' "$join_token"
  printf 'AGENT_CA_FILE=/opt/scan-agent/ca.crt\n'
  printf 'AGENT_VALIDATION_FIXTURE=` + fixture + `\n'
  printf 'AGENT_VERSION=bundle-` + c.AgentPackageHash[:12] + `\n'
} > /opt/scan-agent/agent.env
chmod 0600 /opt/scan-agent/agent.env
/opt/scan-agent/agent-bootstrap.sh /opt/scan-agent
`
	if len(script) > 32<<10 {
		return "", errors.New("generated Alibaba Cloud user data exceeds 32 KiB")
	}
	return script, nil
}

func validHTTPURL(name, value string, requireTLS bool) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL", name)
	}
	if requireTLS && u.Scheme != "https" {
		return fmt.Errorf("%s must use HTTPS", name)
	}
	return nil
}
