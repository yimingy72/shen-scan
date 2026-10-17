#!/bin/sh
set -eu
umask 077

case "${AGENT_VALIDATION_FIXTURE:-false}" in
  1|true|TRUE|yes|YES) ;;
  *) exit 0 ;;
esac

namespace=scan-fixture
host_interface=scan-test0
peer_interface=scan-test1
install_dir=/opt/scan-agent

teardown() {
  ip netns delete "$namespace" 2>/dev/null || true
  ip link delete "$host_interface" 2>/dev/null || true
}

setup_network() {
  teardown
  ip netns add "$namespace"
  ip link add "$host_interface" type veth peer name "$peer_interface"
  ip link set "$peer_interface" netns "$namespace"
  ip address add 172.31.255.1/30 dev "$host_interface"
  ip link set "$host_interface" up
  ip netns exec "$namespace" ip link set lo up
  ip netns exec "$namespace" ip link set "$peer_interface" name eth0
  ip netns exec "$namespace" ip address add 172.31.255.2/30 dev eth0
  ip netns exec "$namespace" ip link set eth0 up

  router_mac=$(ip netns exec "$namespace" cat /sys/class/net/eth0/address)
  printf '%s\n' "$router_mac" | grep -Eq '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
  {
    printf 'SCAN_MASSCAN_INTERFACE=%s\n' "$host_interface"
    printf 'SCAN_MASSCAN_ROUTER_MAC=%s\n' "$router_mac"
    printf 'SCAN_ALLOW_PRIVATE_TARGETS=true\n'
  } > "$install_dir/fixture.env"
  chmod 0600 "$install_dir/fixture.env"

  hosts_tmp=$(mktemp)
  awk '$2 != "scan-fixture.test"' /etc/hosts > "$hosts_tmp"
  printf '172.31.255.2 scan-fixture.test\n' >> "$hosts_tmp"
  cat "$hosts_tmp" > /etc/hosts
  rm -f "$hosts_tmp"
}

case "${1:-}" in
  --network-only)
    setup_network
    exit 0
    ;;
  --teardown)
    teardown
    exit 0
    ;;
esac

install -d -m 0755 "$install_dir"
cat > "$install_dir/fixture-server.py" <<'PY'
#!/usr/bin/python3
import http.server
import signal
import socketserver
import threading

WORDPRESS = b"""<!doctype html><html><head><title>Scan Fixture WordPress</title>
<meta name="generator" content="WordPress 6.0"></head>
<body><p>Authorized isolated validation target.</p><a href="/wp-content/test.css">fixture</a></body></html>"""
SIMPLE = b"<!doctype html><title>Scan Fixture 8080</title><p>Authorized isolated validation target.</p>"

class HTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ScanPlatformValidationFixture/1.0"
    def reply(self, include_body):
        body = WORDPRESS if self.server.server_port == 80 else SIMPLE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)
    def do_GET(self):
        self.reply(True)
    def do_HEAD(self):
        self.reply(False)
    def log_message(self, *_):
        pass

class SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-ScanPlatformValidationFixture_1.0\r\n")

class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

servers = [
    http.server.ThreadingHTTPServer(("0.0.0.0", 80), HTTPHandler),
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), HTTPHandler),
    TCPServer(("0.0.0.0", 2222), SSHHandler),
]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()

stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
signal.signal(signal.SIGINT, lambda *_: stop.set())
stop.wait()
for server in servers:
    server.shutdown()
PY
chmod 0755 "$install_dir/fixture-server.py"

install -d -m 0755 /etc/systemd/system/scan-agent.service.d
cat > /etc/systemd/system/scan-agent.service.d/validation-fixture.conf <<'UNIT'
[Unit]
Requires=scan-fixture.service
After=scan-fixture.service
UNIT

cat > /etc/systemd/system/scan-fixture-netns.service <<'UNIT'
[Unit]
Description=Scan Platform isolated validation network namespace
Before=scan-fixture.service scan-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AGENT_VALIDATION_FIXTURE=true
ExecStart=/opt/scan-agent/cloud-fixture.sh --network-only
ExecStop=/opt/scan-agent/cloud-fixture.sh --teardown

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/scan-fixture.service <<'UNIT'
[Unit]
Description=Scan Platform authorized isolated validation targets
Requires=scan-fixture-netns.service
After=scan-fixture-netns.service
Before=scan-agent.service

[Service]
Type=simple
NetworkNamespacePath=/run/netns/scan-fixture
ExecStart=/usr/bin/python3 /opt/scan-agent/fixture-server.py
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable scan-fixture-netns.service scan-fixture.service
systemctl stop scan-fixture.service 2>/dev/null || true
systemctl restart scan-fixture-netns.service
systemctl restart scan-fixture.service

