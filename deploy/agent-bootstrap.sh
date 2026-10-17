#!/bin/sh
set -eu
umask 077

source_dir=${1:?usage: agent-bootstrap.sh EXTRACTED_DIRECTORY}
source_dir=$(readlink -f "$source_dir")
install_dir=/opt/scan-agent

test -d "$source_dir"
test -x "$source_dir/scan-agent"
test -x "$source_dir/masscan"
test -x "$source_dir/nuclei"
test -s "$source_dir/ca.crt"
test -f "$source_dir/agent.env"
test -x "$source_dir/cloud-fixture.sh"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends masscan iproute2 python3 ca-certificates
install -m 0755 "$source_dir/masscan" /usr/local/bin/masscan.next
mv -f /usr/local/bin/masscan.next /usr/local/bin/masscan
install -m 0755 "$source_dir/nuclei" /usr/local/bin/nuclei.next
mv -f /usr/local/bin/nuclei.next /usr/local/bin/nuclei

install -d -m 0755 "$install_dir"
if [ "$source_dir" != "$install_dir" ]; then
  install -m 0755 "$source_dir/scan-agent" "$install_dir/scan-agent"
  install -m 0755 "$source_dir/agent-bootstrap.sh" "$install_dir/agent-bootstrap.sh"
  install -m 0755 "$source_dir/cloud-fixture.sh" "$install_dir/cloud-fixture.sh"
  install -m 0644 "$source_dir/ca.crt" "$install_dir/ca.crt"
  install -m 0600 "$source_dir/agent.env" "$install_dir/agent.env"
  cp -R "$source_dir/licenses" "$install_dir/"
fi
chmod 0600 "$install_dir/agent.env"
test -s "$install_dir/ca.crt"
grep -Eq '^AGENT_CONTROL_URL=https://' "$install_dir/agent.env"

metadata=$(/usr/bin/python3 <<'PY'
import time
import urllib.request

base = "http://100.100.100.200/latest"
token = ""
try:
    request = urllib.request.Request(base + "/api/token", method="PUT")
    request.add_header("X-aliyun-ecs-metadata-token-ttl-seconds", "21600")
    with urllib.request.urlopen(request, timeout=2) as response:
        token = response.read(4096).decode().strip()
except Exception:
    pass

def get(path, required):
    for _ in range(5):
        try:
            request = urllib.request.Request(base + "/meta-data/" + path)
            if token:
                request.add_header("X-aliyun-ecs-metadata-token", token)
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.read(4096).decode().strip().replace("\n", "")
        except Exception:
            time.sleep(1)
    if required:
        raise SystemExit("required ECS instance metadata is unavailable")
    return ""

print(get("instance-id", True))
print(get("zone-id", False))
PY
)
instance_id=$(printf '%s\n' "$metadata" | sed -n '1p')
zone_id=$(printf '%s\n' "$metadata" | sed -n '2p')
test -n "$instance_id"

env_tmp=$(mktemp)
trap 'rm -f "$env_tmp"' EXIT
sed '/^AGENT_INSTANCE_ID=/d;/^AGENT_AZ=/d;/^AGENT_CA_FILE=/d' "$install_dir/agent.env" > "$env_tmp"
{
  printf 'AGENT_INSTANCE_ID=%s\n' "$instance_id"
  printf 'AGENT_AZ=%s\n' "$zone_id"
  printf 'AGENT_CA_FILE=%s\n' "$install_dir/ca.crt"
} >> "$env_tmp"
install -m 0600 "$env_tmp" "$install_dir/agent.env"
rm -f "$env_tmp"
trap - EXIT

fixture_enabled=$(sed -n 's/^AGENT_VALIDATION_FIXTURE=//p' "$install_dir/agent.env" | tail -n 1 | tr -d "'\"")
case "$fixture_enabled" in
  1|true|TRUE|yes|YES)
    AGENT_VALIDATION_FIXTURE=true "$install_dir/cloud-fixture.sh"
    ;;
  *)
    rm -f "$install_dir/fixture.env" /etc/systemd/system/scan-agent.service.d/validation-fixture.conf
    ;;
esac

cat > /etc/systemd/system/scan-agent.service <<'UNIT'
[Unit]
Description=Scan Platform Worker Agent
After=network-online.target scan-fixture.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/opt/scan-agent/agent.env
EnvironmentFile=-/opt/scan-agent/fixture.env
ExecStart=/opt/scan-agent/scan-agent
KillMode=control-group
TimeoutStopSec=5
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now scan-agent.service

