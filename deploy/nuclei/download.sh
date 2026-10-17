#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=3.11.1
archive=nuclei_${version}_linux_amd64.zip
expected=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
cache=${NUCLEI_CACHE_DIR:-"$project_dir/.cache/nuclei"}
output=${NUCLEI_OUTPUT_DIR:-"$project_dir/bin/nuclei"}
mkdir -p "$cache" "$output"
if [ ! -s "$cache/$archive" ]; then
  curl -fL --retry 3 --connect-timeout 15 --max-time 600 --output "$cache/$archive.download" "https://github.com/projectdiscovery/nuclei/releases/download/v$version/$archive"
  mv "$cache/$archive.download" "$cache/$archive"
fi
actual=$(shasum -a 256 "$cache/$archive" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
  printf '%s\n' 'Nuclei archive checksum mismatch' >&2
  exit 1
fi
unzip -p "$cache/$archive" nuclei > "$output/nuclei.next"
unzip -p "$cache/$archive" LICENSE.md > "$output/LICENSE.nuclei"
chmod 0755 "$output/nuclei.next"
mv "$output/nuclei.next" "$output/nuclei"
shasum -a 256 "$output/nuclei" > "$output/nuclei.sha256"
printf 'Nuclei %s Linux amd64 ready: %s/nuclei\n' "$version" "$output"
