#!/bin/sh
set -eu
umask 077

# This fixture only simulates protocol fingerprints. WordPress, Next.js, nginx,
# and OpenSSH are not installed products and must not be reported as such.
# SCAN_LOAD_FILTER_CLOSED=true (default) drops initial SYNs for closed fixture
# ports. Set it to false to retain the kernel-RST network model.

namespace=scan-load
host_interface=scan-load0
peer_interface=scan-load1
install_dir=/opt/scan-agent
targets_file=$install_dir/load-targets.txt

teardown() {
	ip netns delete "$namespace" 2>/dev/null || true
	ip link delete "$host_interface" 2>/dev/null || true
}

require_enabled() {
	case "${SCAN_LOAD_FIXTURE:-false}" in
		1 | true | TRUE | yes | YES) ;;
		*)
			printf '%s\n' 'set SCAN_LOAD_FIXTURE=true to enable the isolated load fixture' >&2
			exit 1
			;;
	esac
}

install_network_tools() {
	if command -v iptables >/dev/null 2>&1 && command -v ping >/dev/null 2>&1; then
		return
	fi
	if command -v apt-get >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get update
		DEBIAN_FRONTEND=noninteractive apt-get install -y iptables iputils-ping
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y iptables iputils
	elif command -v yum >/dev/null 2>&1; then
		yum install -y iptables iputils
	else
		printf '%s\n' 'iptables and ping are required for the isolated load fixture' >&2
		exit 1
	fi
	command -v iptables >/dev/null
	command -v ping >/dev/null
}

configure_closed_port_model() {
	case "${SCAN_LOAD_FILTER_CLOSED:-true}" in
		1 | true | TRUE | yes | YES)
			ip netns exec "$namespace" iptables -w 5 -N SCAN_LOAD_SYN
			ip netns exec "$namespace" iptables -w 5 -A SCAN_LOAD_SYN -d 172.31.243.250 -j RETURN
			ip netns exec "$namespace" iptables -w 5 -A SCAN_LOAD_SYN -d 172.31.243.251 -p tcp --dport 8081 -j RETURN
			ip netns exec "$namespace" iptables -w 5 -A SCAN_LOAD_SYN -d 172.31.243.251 -j DROP
			ip netns exec "$namespace" iptables -w 5 -A SCAN_LOAD_SYN -m iprange --dst-range 172.31.240.2-172.31.243.233 -p tcp -m multiport --dports 80,8080,2222 -j RETURN
			ip netns exec "$namespace" iptables -w 5 -A SCAN_LOAD_SYN -m iprange --dst-range 172.31.240.2-172.31.243.233 -j DROP
			ip netns exec "$namespace" iptables -w 5 -A INPUT -p tcp --syn -j SCAN_LOAD_SYN
			;;
		0 | false | FALSE | no | NO) ;;
		*)
			printf '%s\n' 'SCAN_LOAD_FILTER_CLOSED must be true or false' >&2
			exit 1
			;;
	esac
}

setup_network() {
	teardown
	install -d -m 0755 "$install_dir"
	ip netns add "$namespace"
	ip link add "$host_interface" type veth peer name "$peer_interface"
	ip link set "$peer_interface" netns "$namespace"
	ip address add 172.31.240.1/20 dev "$host_interface"
	ip link set "$host_interface" up
	ip netns exec "$namespace" ip link set lo up
	ip netns exec "$namespace" ip link set "$peer_interface" name eth0
	ip netns exec "$namespace" ip address add 172.31.240.2/20 dev eth0
	ip netns exec "$namespace" ip link set eth0 up

	address_batch=$(mktemp)
	trap 'rm -f "$address_batch"' EXIT INT TERM
	awk -v targets="$targets_file" -v batch="$address_batch" 'BEGIN {
		for (n = 2; n <= 1001; n++) {
			ip = sprintf("172.31.%d.%d", 240 + int(n / 256), n % 256)
			print ip > targets
			if (n != 2) print "address add " ip "/32 dev eth0" > batch
		}
		print "address add 172.31.243.250/32 dev eth0" > batch
		print "address add 172.31.243.251/32 dev eth0" > batch
	}'
	ip netns exec "$namespace" ip -batch "$address_batch"
	rm -f "$address_batch"
	trap - EXIT INT TERM
	configure_closed_port_model

	router_mac=$(ip netns exec "$namespace" cat /sys/class/net/eth0/address)
	printf '%s\n' "$router_mac" | grep -Eq '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
	{
		printf 'SCAN_MASSCAN_INTERFACE=%s\n' "$host_interface"
		printf 'SCAN_MASSCAN_ROUTER_MAC=%s\n' "$router_mac"
		printf 'SCAN_ALLOW_PRIVATE_TARGETS=true\n'
		printf 'SCAN_LOAD_TARGETS_FILE=%s\n' "$targets_file"
		printf 'SCAN_LOAD_HIGH_TARGET=172.31.243.250\n'
		printf 'SCAN_LOAD_SLOW_TARGET=172.31.243.251\n'
	} > "$install_dir/load-fixture.env"
	chmod 0600 "$install_dir/load-fixture.env"
}

install_fixture() {
	install_network_tools
	install -d -m 0755 "$install_dir"
	if [ "$(readlink -f "$0")" != "$install_dir/load-fixture.sh" ]; then
		install -m 0755 "$0" "$install_dir/load-fixture.sh"
	fi
	cat > "$install_dir/load-fixture-server.py" <<'PY'
#!/usr/bin/python3
import os
import queue
import resource
import selectors
import shutil
import signal
import socket
import subprocess
import threading
import time

TARGETS_FILE = "/opt/scan-agent/load-targets.txt"
HIGH_TARGET = "172.31.243.250"
SLOW_TARGET = "172.31.243.251"
HIGH_PORTS = int(os.environ.get("SCAN_LOAD_HIGH_OPEN_PORTS", "1000"))
SLOW_SECONDS = float(os.environ.get("SCAN_LOAD_SLOW_SECONDS", "2"))
if not 1 <= HIGH_PORTS <= 65535:
    raise SystemExit("SCAN_LOAD_HIGH_OPEN_PORTS must be between 1 and 65535")
if not 0 <= SLOW_SECONDS <= 120:
    raise SystemExit("SCAN_LOAD_SLOW_SECONDS must be between 0 and 120")

def http_response(body, *headers):
    lines = [
        b"HTTP/1.1 200 OK",
        b"Content-Type: text/html; charset=utf-8",
        b"Content-Length: " + str(len(body)).encode("ascii"),
        b"Connection: close",
        *headers,
    ]
    return b"\r\n".join(lines) + b"\r\n\r\n" + body

WORDPRESS_BODY = (b'<!doctype html><html><head><meta name="generator" content="WordPress 6.6">'
                  b'<title>Synthetic WordPress Fixture</title></head><body>'
                  b'<link rel="stylesheet" href="/wp-content/fixture.css">'
                  b'Synthetic fingerprint response; WordPress is not installed.</body></html>')
NEXT_BODY = (b'<!doctype html><html><head><title>Synthetic Next.js Fixture</title></head><body>'
             b'<script id="__NEXT_DATA__" type="application/json">{"buildId":"synthetic"}</script>'
             b'Synthetic fingerprint response; Next.js is not installed.</body></html>')
GENERIC_BODY = b"Synthetic isolated HTTP response; no product is installed."
WORDPRESS_HTTP = http_response(WORDPRESS_BODY, b"Server: nginx/1.26")
NEXT_HTTP = http_response(NEXT_BODY, b"Server: synthetic-fixture", b"X-Powered-By: Next.js")
GENERIC_HTTP = http_response(GENERIC_BODY, b"Server: synthetic-fixture")
SSH = b"SSH-2.0-OpenSSH_9.6p1 ScanPlatformSyntheticFixture\r\n"

def check_response(response, body, marker):
    head, actual_body = response.split(b"\r\n\r\n", 1)
    lengths = [line for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")]
    assert len(lengths) == 1
    assert int(lengths[0].split(b":", 1)[1]) == len(body) == len(actual_body)
    assert marker in response

selector = selectors.DefaultSelector()
listeners = []
stopping = threading.Event()
http_jobs = queue.Queue(maxsize=128)
slow_jobs = queue.Queue(maxsize=8)

def listen(ip, port, protocol, response, delay=0.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind((ip, port))
    sock.listen(128)
    selector.register(sock, selectors.EVENT_READ, (protocol, response, delay))
    listeners.append(sock)

def read_request_header(conn):
    conn.settimeout(0.5)
    request = bytearray()
    while len(request) < 4096 and b"\r\n\r\n" not in request:
        try:
            chunk = conn.recv(min(1024, 4096 - len(request)))
        except TimeoutError:
            break
        if not chunk:
            break
        request.extend(chunk)
    return bytes(request)

def graceful_http_reply(conn, response, delay):
    try:
        request = read_request_header(conn)
        # Controlled queue/concurrency fixture; ordinary discovery stays fast.
        line = request.split(b"\r\n", 1)[0].split()
        if len(line) >= 2 and line[1].startswith(b"/__scan_delay__/"):
            delay = max(delay, 8.0 if line[1].startswith(b"/__scan_delay__/8") else 2.0)
        if delay:
            time.sleep(delay)
        conn.sendall(response)
        conn.shutdown(socket.SHUT_WR)
        conn.settimeout(0.5)
        while conn.recv(1024):
            pass
    except OSError:
        pass
    finally:
        conn.close()

if os.environ.get("SCAN_LOAD_FIXTURE_SELFTEST") == "true":
    check_response(WORDPRESS_HTTP, WORDPRESS_BODY, b"wp-content")
    check_response(NEXT_HTTP, NEXT_BODY, b"__NEXT_DATA__")
    check_response(GENERIC_HTTP, GENERIC_BODY, b"no product is installed")
    assert SSH.startswith(b"SSH-2.0-OpenSSH_9.6p1")
    server_sock, client_sock = socket.socketpair()
    exchange = threading.Thread(target=graceful_http_reply, args=(server_sock, WORDPRESS_HTTP, 0))
    exchange.start()
    client_sock.sendall(b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n")
    client_sock.shutdown(socket.SHUT_WR)
    received = bytearray()
    while True:
        chunk = client_sock.recv(4096)
        if not chunk:
            break
        received.extend(chunk)
    client_sock.close()
    exchange.join(timeout=1)
    assert not exchange.is_alive()
    assert bytes(received) == WORDPRESS_HTTP
    print("load fixture response self-check passed")
    raise SystemExit(0)

required_fds = 1000 * 3 + HIGH_PORTS + 1024
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
if soft < required_fds:
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(required_fds, hard), hard))
if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < required_fds:
    raise SystemExit(f"open-file limit must be at least {required_fds}")

def http_worker(jobs):
    while not stopping.is_set():
        try:
            job = jobs.get(timeout=0.2)
        except queue.Empty:
            continue
        graceful_http_reply(*job)
        jobs.task_done()

def dispatch(jobs, conn, response, delay):
    conn.setblocking(True)
    try:
        jobs.put_nowait((conn, response, delay))
    except queue.Full:
        conn.close()

def send_ssh_banner(conn):
    try:
        conn.settimeout(0.5)
        conn.sendall(SSH)
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    finally:
        conn.close()

for _ in range(32):
    threading.Thread(target=http_worker, args=(http_jobs,), daemon=True).start()
for _ in range(4):
    threading.Thread(target=http_worker, args=(slow_jobs,), daemon=True).start()

with open(TARGETS_FILE, encoding="ascii") as target_stream:
    targets = [line.strip() for line in target_stream if line.strip()]
if len(targets) != 1000:
    raise SystemExit(f"expected 1000 ordinary targets, got {len(targets)}")
for target in targets:
    listen(target, 80, "http", WORDPRESS_HTTP)
    listen(target, 8080, "http", NEXT_HTTP)
    listen(target, 2222, "ssh", SSH)
for port in range(1, HIGH_PORTS + 1):
    listen(HIGH_TARGET, port, "http", GENERIC_HTTP)
listen(SLOW_TARGET, 8081, "slow", GENERIC_HTTP, SLOW_SECONDS)

signal.signal(signal.SIGTERM, lambda *_: stopping.set())
signal.signal(signal.SIGINT, lambda *_: stopping.set())
ping_path = shutil.which("ping")
if not ping_path:
    raise SystemExit("ping is required for the isolated load fixture")
ping_process = subprocess.Popen(
    [ping_path, "-n", "-i", "1", "-W", "1", "172.31.240.1"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    while not stopping.is_set():
        if ping_process.poll() is not None:
            raise SystemExit("fixture liveness ping stopped unexpectedly")
        for key, _ in selector.select(timeout=1):
            try:
                conn, _ = key.fileobj.accept()
            except OSError:
                continue
            protocol, response, delay = key.data
            if protocol == "ssh":
                send_ssh_banner(conn)
            elif protocol == "slow":
                dispatch(slow_jobs, conn, response, delay)
            else:
                dispatch(http_jobs, conn, response, delay)
finally:
    for listener in listeners:
        listener.close()
    selector.close()
    if ping_process.poll() is None:
        ping_process.terminate()
        try:
            ping_process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            ping_process.kill()
            ping_process.wait()
PY
	chmod 0755 "$install_dir/load-fixture-server.py"
	cat > "$install_dir/load-fixture-NOTICE.txt" <<'NOTICE'
This isolated fixture emits synthetic WordPress 6.6, Next.js, nginx 1.26,
and OpenSSH 9.6p1 fingerprint strings. It does not install or run those
products and its responses must not be used as evidence of a real deployment.

SCAN_LOAD_FILTER_CLOSED=true is the default model: the namespace drops initial
TCP SYNs to closed ordinary-target ports, while allowing 80/8080/2222, all
ports on 172.31.243.250, and 8081 on 172.31.243.251. Set it to false in
load-fixture.conf to retain kernel closed-port RST replies. Both models keep
masscan's configured 5000 PPS total send rate unchanged and do not use --noreset.

The fixture service sends one ICMP echo per second to 172.31.240.1 solely to
keep isolated-veth packet capture active; the ping process stops with the
fixture service.
NOTICE

	cat > /etc/systemd/system/scan-load-fixture-netns.service <<'UNIT'
[Unit]
Description=Scan Platform isolated load-test network namespace
Before=scan-load-fixture.service scan-agent.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=SCAN_LOAD_FIXTURE=true
Environment=SCAN_LOAD_FILTER_CLOSED=true
EnvironmentFile=-/opt/scan-agent/load-fixture.conf
ExecStart=/opt/scan-agent/load-fixture.sh --network-only
ExecStop=/opt/scan-agent/load-fixture.sh --teardown

[Install]
WantedBy=multi-user.target
UNIT

	cat > /etc/systemd/system/scan-load-fixture.service <<'UNIT'
[Unit]
Description=Scan Platform isolated multi-IP load targets
Requires=scan-load-fixture-netns.service
After=scan-load-fixture-netns.service
Before=scan-agent.service

[Service]
Type=simple
NetworkNamespacePath=/run/netns/scan-load
Environment=SCAN_LOAD_HIGH_OPEN_PORTS=1000
Environment=SCAN_LOAD_SLOW_SECONDS=2
EnvironmentFile=-/opt/scan-agent/load-fixture.conf
ExecStart=/usr/bin/python3 /opt/scan-agent/load-fixture-server.py
LimitNOFILE=131072
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT

	install -d -m 0755 /etc/systemd/system/scan-agent.service.d
	cat > /etc/systemd/system/scan-agent.service.d/load-fixture.conf <<'UNIT'
[Unit]
Requires=scan-load-fixture.service
After=scan-load-fixture.service

[Service]
EnvironmentFile=/opt/scan-agent/load-fixture.env
UNIT

	systemctl daemon-reload
	systemctl enable scan-load-fixture-netns.service scan-load-fixture.service
	systemctl stop scan-load-fixture.service 2>/dev/null || true
	systemctl restart scan-load-fixture-netns.service
	systemctl restart scan-load-fixture.service
}

case "${1:---install}" in
	--teardown)
	teardown
	;;
	--status)
	ip netns list | grep -F "$namespace" || true
	systemctl --no-pager --full status scan-load-fixture-netns.service scan-load-fixture.service
	;;
	--network-only)
	require_enabled
	setup_network
	;;
	--install)
	require_enabled
	install_fixture
	;;
	*)
	printf 'usage: %s [--install|--network-only|--status|--teardown]\n' "$0" >&2
	exit 2
	;;
esac
