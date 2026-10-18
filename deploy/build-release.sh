#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
release_dir=${RELEASE_DIR:-"$project_dir/bin/release"}
target_arch=${TARGET_ARCH:-amd64}
nuclei_binary=${NUCLEI_BINARY:-"$project_dir/bin/nuclei/nuclei"}
httpx_binary=${HTTPX_BINARY:-"$project_dir/bin/httpx/httpx"}
masscan_binary=${MASSCAN_BINARY:-"$project_dir/bin/masscan/masscan"}
masscan_source=${MASSCAN_SOURCE_ARCHIVE:-"$(dirname -- "$masscan_binary")/masscan-source-1.3.2-scan-platform.tar.gz"}
if [ ! -x "$masscan_binary" ] || [ ! -s "$masscan_source" ]; then
  printf '%s\n' 'Build the pinned Linux amd64 scanner with deploy/masscan/build.sh first (see deploy/masscan/README.md).' >&2
  exit 1
fi
if [ "$target_arch" != amd64 ]; then
  printf '%s\n' 'The bundled Masscan build currently supports Linux amd64 only.' >&2
  exit 1
fi
if [ ! -s "${CONTROL_CA_FILE:-}" ] || ! grep -q 'BEGIN CERTIFICATE' "$CONTROL_CA_FILE" || grep -q 'PRIVATE KEY' "$CONTROL_CA_FILE"; then
  printf '%s\n' 'CONTROL_CA_FILE must name a public PEM CA certificate without a private key.' >&2
  exit 1
fi
verify_hash() {
  file=$1
  test -s "$file.sha256"
  expected=$(awk 'NR==1 {print $1}' "$file.sha256")
  actual=$(shasum -a 256 "$file" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    printf 'SHA-256 mismatch: %s\n' "$file" >&2
    exit 1
  fi
}
verify_hash "$masscan_binary"
verify_hash "$masscan_source"
if [ ! -x "$nuclei_binary" ] || [ ! -s "$(dirname -- "$nuclei_binary")/LICENSE.nuclei" ]; then
  printf '%s\n' 'Run deploy/nuclei/download.sh before building the complete Worker package.' >&2
  exit 1
fi
verify_hash "$nuclei_binary"
if [ ! -x "$httpx_binary" ] || [ ! -s "$(dirname -- "$httpx_binary")/LICENSE.httpx" ]; then
  printf '%s\n' 'Run deploy/httpx/download.sh before building the complete Worker package.' >&2
  exit 1
fi
verify_hash "$httpx_binary"
if ! file "$httpx_binary" | grep -Eq 'ELF 64-bit.*x86-64'; then
  printf '%s\n' 'HTTPX_BINARY must be a Linux amd64 executable.' >&2
  exit 1
fi
if ! file "$nuclei_binary" | grep -Eq 'ELF 64-bit.*x86-64'; then
  printf '%s\n' 'NUCLEI_BINARY must be a Linux amd64 executable.' >&2
  exit 1
fi
mkdir -p "$release_dir"
release_dir=$(CDPATH= cd -- "$release_dir" && pwd)
staging_dir=$(mktemp -d "$release_dir/.agent.XXXXXX")
trap 'rm -rf "$staging_dir"' EXIT INT TERM
CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go build -trimpath -ldflags '-s -w' -o "$release_dir/scan-server" ./cmd/server
CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go build -trimpath -ldflags '-s -w' -o "$staging_dir/scan-agent" ./cmd/agent
WEB_HELPERS_OUTPUT_DIR="$staging_dir" TARGET_OS=linux TARGET_ARCH="$target_arch" sh deploy/build-web-helpers.sh
mkdir -p "$release_dir/tools"
cp "$staging_dir/fingerprint-worker" "$release_dir/tools/fingerprint-worker"
cp deploy/agent-bootstrap.sh deploy/cloud-fixture.sh "$staging_dir/"
mkdir -p "$staging_dir/browser"
cp deploy/browser/runtime.json deploy/browser/install.sh deploy/browser/network.sh deploy/browser/chrome.sh deploy/browser/README.md "$staging_dir/browser/"
chmod 0755 "$staging_dir/browser/"*.sh
cp "$masscan_binary" "$staging_dir/masscan"
cp "$nuclei_binary" "$staging_dir/nuclei"
cp "$httpx_binary" "$staging_dir/httpx"
cp "$CONTROL_CA_FILE" "$staging_dir/ca.crt"
mkdir -p "$staging_dir/licenses"
cp "$(dirname -- "$nuclei_binary")/LICENSE.nuclei" "$staging_dir/licenses/"
cp "$(dirname -- "$httpx_binary")/LICENSE.httpx" "$httpx_binary.sha256" "$staging_dir/licenses/"
cp internal/rulelib/THIRD_PARTY_NOTICES.md "$staging_dir/licenses/RULES-NOTICES.md"
cp deploy/WEB_HELPERS.md "$staging_dir/licenses/WEB-HELPERS.md"
for helper in web-probe-worker fingerprint-worker; do
  cp "$project_dir/cmd/$helper/go.mod" "$staging_dir/licenses/$helper.go.mod"
  cp "$project_dir/cmd/$helper/go.sum" "$staging_dir/licenses/$helper.go.sum"
done
(
  cd "$project_dir/cmd/web-probe-worker"
  for module in httpx wappalyzergo; do
    module_dir=$(go list -m -f '{{.Dir}}' "github.com/projectdiscovery/$module")
    cp "$module_dir/LICENSE.md" "$staging_dir/licenses/LICENSE.$module-sdk"
  done
)
(
  cd "$project_dir/cmd/fingerprint-worker"
  module_dir=$(go list -m -f '{{.Dir}}' github.com/chainreactors/fingers)
  cp "$module_dir/README.md" "$staging_dir/licenses/FINGERS-UPSTREAM-README.md"
  for notice in "$module_dir/LICENSE" "$module_dir/LICENSE.md" "$module_dir/NOTICE"; do
    if [ -f "$notice" ]; then cp "$notice" "$staging_dir/licenses/FINGERS-$(basename "$notice")"; fi
  done
)
cp "$nuclei_binary.sha256" "$staging_dir/licenses/nuclei.sha256"
cp "$masscan_source" deploy/masscan/LICENSE.masscan deploy/masscan/SOURCE.md "$staging_dir/licenses/"
cp "$masscan_binary.sha256" "$masscan_source.sha256" "$staging_dir/licenses/"
tar -xOf "$masscan_source" masscan-source-1.3.2-scan-platform/AGPL-3.0.txt > "$staging_dir/licenses/AGPL-3.0.txt"
chmod 0755 "$staging_dir/"*.sh "$staging_dir/scan-agent" "$staging_dir/masscan" "$staging_dir/nuclei" "$staging_dir/httpx" "$staging_dir/web-probe-worker" "$staging_dir/fingerprint-worker"
# Explicit staging allowlist: do not create a project-root source archive here.
# Private work/ and downloaded browser packages must never enter the release.
if find "$staging_dir" -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.dmg' \) | grep -q . || [ -e "$staging_dir/work" ]; then
  printf '%s\n' 'Release staging contains a forbidden package archive or private work directory.' >&2
  exit 1
fi
COPYFILE_DISABLE=1 tar -czf "$release_dir/scan-agent-linux-$target_arch.tar.gz.next" -C "$staging_dir" .
mv "$release_dir/scan-agent-linux-$target_arch.tar.gz.next" "$release_dir/scan-agent-linux-$target_arch.tar.gz"
shasum -a 256 "$release_dir/scan-agent-linux-$target_arch.tar.gz"
printf 'Release files: %s\n' "$release_dir"
