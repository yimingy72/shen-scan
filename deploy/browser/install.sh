#!/bin/sh
# Browser setup is optional to ordinary scanning. This script returns nonzero
# and removes readiness on failure; bootstrap records the gap and continues.
set -eu
umask 077
source_dir=${1:?usage: install.sh BROWSER_SCRIPT_DIRECTORY}
source_dir=$(CDPATH= cd -- "$source_dir" && pwd)
test "$(id -u)" -eq 0
state=/var/lib/shen-browser-install-status.json
ready=/var/lib/shen-browser-runtime.ready
stage=platform
minimum=
installed=
finished=false
scratch=
rm -f "$ready"
write_status() {
  status_tmp=$(mktemp /var/lib/.shen-browser-status.XXXXXX)
  printf '{"browser_ready":%s,"stage":"%s","required_version":"%s","installed_version":"%s"}\n' "$1" "$stage" "$minimum" "$installed" > "$status_tmp"
  chmod 0644 "$status_tmp"
  mv -f "$status_tmp" "$state"
}
cleanup() {
  if [ "$finished" != true ]; then
    rm -f "$ready"
    write_status false
    printf 'Browser unavailable: installation failed at %s; ordinary scanning remains available.\n' "$stage" >&2
  fi
  if [ -n "$scratch" ]; then rm -rf "$scratch"; fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:*) dpkg --compare-versions "$VERSION_ID" ge 22.04 ;;
  debian:*) dpkg --compare-versions "$VERSION_ID" ge 12 ;;
  *) printf '%s\n' 'Browser installer supports Ubuntu >=22.04 or Debian >=12 only.' >&2; exit 1 ;;
esac
test "$(dpkg --print-architecture)" = amd64
export DEBIAN_FRONTEND=noninteractive
stage=prerequisites
missing=false
for utility in python3 curl gpg iptables ip6tables systemctl runuser; do
  command -v "$utility" >/dev/null 2>&1 || missing=true
done
if [ "$missing" = true ] || [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
  apt-get update -qq
  apt-get install -y --no-install-recommends python3 curl gnupg ca-certificates iptables systemd util-linux
fi
minimum=$(python3 - "$source_dir/runtime.json" <<'PY'
import json, re, sys
policy = json.load(open(sys.argv[1]))
expected = {
    'package': 'google-chrome-stable', 'version_policy': 'minimum-no-downgrade',
    'architecture': 'amd64', 'repository': 'https://dl.google.com/linux/chrome/deb/',
    'suite': 'stable', 'component': 'main',
    'signing_key_url': 'https://dl.google.com/linux/linux_signing_key.pub',
    'signing_key_fingerprint': 'EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796',
}
if any(policy.get(k) != v for k, v in expected.items()) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}-[0-9]+', policy.get('minimum_version', '')):
    raise SystemExit('Invalid browser runtime policy')
print(policy['minimum_version'])
PY
)
installed=$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' google-chrome-stable 2>/dev/null | awk '$1 == "installed" {print $2}' || true)
needs_browser=true
if [ -n "$installed" ] && dpkg --compare-versions "$installed" ge "$minimum"; then needs_browser=false; fi
stage=official-signing-key
scratch=$(mktemp -d)
mkdir -m 0700 "$scratch/gnupg"
fingerprint=EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796
keyring=/usr/share/keyrings/shen-google-chrome.gpg
key_valid() {
  test -s "$1" && gpg --batch --homedir "$scratch/gnupg" --show-keys --with-colons "$1" 2>/dev/null |
    awk -F: -v expected="$fingerprint" '$1 == "pub" {primary=1; next} primary && $1 == "fpr" {if ($10 == expected) found=1; primary=0} END {exit !found}'
}
if [ "$needs_browser" = true ] || ! key_valid "$keyring"; then
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 45 --retry 2 \
    https://dl.google.com/linux/linux_signing_key.pub -o "$scratch/google.pub"
  key_valid "$scratch/google.pub" || { printf '%s\n' 'Official Google signing-key fingerprint verification failed.' >&2; exit 1; }
  key_source="$scratch/google.pub"
else
  key_source="$keyring"
fi
# Export only the pinned primary key and its signed subkeys; do not trust other
# keys that may share Google's public bundle or an existing keyring.
gpg --batch --homedir "$scratch/gnupg" --import-options import-minimal --import "$key_source" >/dev/null 2>&1
gpg --batch --homedir "$scratch/gnupg" --export "$fingerprint" > "$scratch/google.gpg"
test -s "$scratch/google.gpg"
install -m 0644 "$scratch/google.gpg" "$keyring"
stage=official-apt-source
configure_source() {
  printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/shen-google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main' > "$scratch/google-chrome.list"
  install -m 0644 "$scratch/google-chrome.list" /etc/apt/sources.list.d/google-chrome.list
}
configure_source
# Chrome's own post-install script may rewrite its list; restore signed-by below.
if [ "$needs_browser" = true ]; then
  stage=browser-package
  # Refresh distribution dependency indices as well as the signed Chrome source.
  apt-get update
  candidate=$(apt-cache madison google-chrome-stable | awk '$5 ~ /^https:\/\/dl.google.com\/linux\/chrome\/deb\/?$/ {print $3; exit}')
  test -n "$candidate"
  dpkg --compare-versions "$candidate" ge "$minimum"
  if [ -n "$installed" ]; then dpkg --compare-versions "$candidate" ge "$installed"; fi
  # Select an actual version advertised by the official signed source. Apt's
  # normal signature/hash verification remains enabled; never allow unauthenticated.
  apt-get install -y --no-install-recommends "google-chrome-stable=$candidate"
  configure_source
else
  printf 'Chrome %s already satisfies minimum %s; skip browser download/install.\n' "$installed" "$minimum"
fi
stage=browser-version
installed=$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' google-chrome-stable | awk '$1 == "installed" {print $2}')
test -n "$installed"
dpkg --compare-versions "$installed" ge "$minimum"
test -x /usr/bin/google-chrome-stable
actual=$(/usr/bin/google-chrome-stable --version | awk 'NR == 1 {print $3}')
dpkg --compare-versions "$actual" ge "${minimum%-*}"
stage=isolation-user
if ! id shen-browser >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/shen-browser --shell /usr/sbin/nologin shen-browser
fi
test "$(id -u shen-browser)" -gt 0
install -d -m 0700 -o shen-browser -g shen-browser /var/lib/shen-browser
install -d -m 0755 /usr/local/libexec
install -m 0755 "$source_dir/network.sh" /usr/local/libexec/shen-browser-network
install -m 0755 "$source_dir/chrome.sh" /usr/local/libexec/shen-browser-chrome
stage=isolation-service
cat > /etc/systemd/system/shen-browser-network.service <<'UNIT'
[Unit]
Description=Restrict scanner Chrome direct network egress
Before=scan-agent.service
After=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/shen-browser-network
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable shen-browser-network.service
systemctl restart shen-browser-network.service
systemctl is-active --quiet shen-browser-network.service
install -m 0644 "$source_dir/runtime.json" /var/lib/shen-browser-runtime.json
stage=ready
# Root-owned marker is outside the browser-writable home and is installed last.
: > "$scratch/ready"
install -m 0644 "$scratch/ready" "$ready"
write_status true
finished=true
printf 'Browser installed: Chrome %s, nonroot UID %s, isolated network ready.\n' "$installed" "$(id -u shen-browser)"
