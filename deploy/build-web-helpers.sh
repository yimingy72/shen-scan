#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${WEB_HELPERS_OUTPUT_DIR:-"$project_dir/bin/web-helpers"}
target_os=${TARGET_OS:-linux}
target_arch=${TARGET_ARCH:-amd64}
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
(cd "$project_dir/cmd/web-probe-worker" && CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -mod=readonly -trimpath -ldflags '-s -w' -o "$output/web-probe-worker" .)
(cd "$project_dir/cmd/fingerprint-worker" && CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -mod=readonly -trimpath -ldflags '-s -w' -o "$output/fingerprint-worker" .)
shasum -a 256 "$output/web-probe-worker" "$output/fingerprint-worker" > "$output/helpers.sha256"
printf 'Web helpers ready: %s\n' "$output"
