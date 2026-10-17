#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=1.12.0
archive=httpx_${version}_linux_amd64.zip
expected=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
cache=${HTTPX_CACHE_DIR:-"$project_dir/.cache/httpx"}
output=${HTTPX_OUTPUT_DIR:-"$project_dir/bin/httpx"}
mkdir -p "$cache" "$output"
if [ ! -s "$cache/$archive" ]; then
  curl -fL --retry 3 --connect-timeout 15 --max-time 600 --output "$cache/$archive.download" "https://github.com/projectdiscovery/httpx/releases/download/v$version/$archive"
  mv "$cache/$archive.download" "$cache/$archive"
fi
actual=$(shasum -a 256 "$cache/$archive" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
  printf '%s\n' 'HTTPx archive checksum mismatch' >&2
  exit 1
fi
unzip -p "$cache/$archive" httpx > "$output/httpx.next"
unzip -p "$cache/$archive" LICENSE.md > "$output/LICENSE.httpx"
chmod 0755 "$output/httpx.next"
mv "$output/httpx.next" "$output/httpx"
shasum -a 256 "$output/httpx" > "$output/httpx.sha256"
printf 'HTTPx %s Linux amd64 ready: %s/httpx\n' "$version" "$output"
