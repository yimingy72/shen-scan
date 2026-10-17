#!/bin/sh
set -eu

version=1.3.2
commit=06902c40d1494881c17b7968ef530e1d6bbd320c
source_sha=00bb562686bc765b76b7c02d161d311ff60bc845fa0dfde0ad5b602b6ebcbf3d
patch_sha=4383b50052db4c7c9ecffbcee6e74a780dc0315d1796c02dd9d01aadcc7a3d1a
source_epoch=1612084410
source_name=masscan-$commit.tar.gz
source_url=https://github.com/robertdavidgraham/masscan/archive/$commit.tar.gz
license_sha=0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0
license_url=https://www.gnu.org/licenses/agpl-3.0.txt

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
candidate_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
if [ -f "$candidate_root/go.mod" ]; then
	project_root=$candidate_root
	default_cache=$project_root/.cache/masscan-source
	default_output=$project_root/bin/masscan
else
	project_root=$script_dir
	default_cache=$script_dir/cache
	default_output=$script_dir/bin/masscan
fi
source_cache=${MASSCAN_SOURCE_CACHE:-$default_cache}
output_dir=${MASSCAN_OUTPUT_DIR:-$default_output}
build_jobs=${MASSCAN_BUILD_JOBS:-2}
patch_file=$script_dir/masscan-1.3.2-recv-buffer.patch

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
	printf '%s\n' 'build.sh requires Linux amd64; use the documented Ubuntu 22.04 container command' >&2
	exit 1
fi
case "$build_jobs" in
	'' | 0 | *[!0-9]*)
		printf '%s\n' 'MASSCAN_BUILD_JOBS must be a positive integer' >&2
		exit 1
		;;
esac
for command_name in curl gcc gzip make patch sha256sum strings tar; do
	command -v "$command_name" >/dev/null 2>&1 || {
		printf 'missing build command: %s\n' "$command_name" >&2
		exit 1
	}
done
printf '%s  %s\n' "$patch_sha" "$patch_file" | sha256sum -c -

mkdir -p "$source_cache" "$output_dir"
if [ -f "$script_dir/$source_name" ]; then
	source_archive=$script_dir/$source_name
else
	source_archive=$source_cache/$source_name
	if [ ! -f "$source_archive" ]; then
		download=$source_archive.download
		curl -fL --retry 3 --output "$download" "$source_url"
		mv "$download" "$source_archive"
	fi
fi
printf '%s  %s\n' "$source_sha" "$source_archive" | sha256sum -c -

if [ -f "$script_dir/AGPL-3.0.txt" ]; then
	license_file=$script_dir/AGPL-3.0.txt
else
	license_file=$source_cache/AGPL-3.0.txt
	if [ ! -f "$license_file" ]; then
		download=$license_file.download
		curl -fL --retry 3 --output "$download" "$license_url"
		mv "$download" "$license_file"
	fi
fi
printf '%s  %s\n' "$license_sha" "$license_file" | sha256sum -c -

work_dir=$(mktemp -d "$source_cache/build.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT INT TERM
tar -xzf "$source_archive" -C "$work_dir"
source_dir=$work_dir/masscan-$commit
patch --batch --forward -d "$source_dir" -p1 < "$patch_file"

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH=$source_epoch
make -C "$source_dir" clean
make -C "$source_dir" -j"$build_jobs" CC=gcc GITVER=$version-scan-platform
"$source_dir/bin/masscan" --selftest
"$source_dir/bin/masscan" --version | grep -F "Masscan version $version"
strings "$source_dir/bin/masscan" | grep -F 'scan_capture: received='
strings "$source_dir/bin/masscan" | grep -F 'setnonblock:'

install -m 0755 "$source_dir/bin/masscan" "$output_dir/masscan"
(
	cd "$output_dir"
	sha256sum masscan > masscan.sha256
)

package_name=masscan-source-$version-scan-platform
package_dir=$work_dir/$package_name
mkdir -p "$package_dir"
install -m 0644 "$source_archive" "$package_dir/$source_name"
install -m 0644 "$patch_file" "$package_dir/masscan-1.3.2-recv-buffer.patch"
install -m 0644 "$script_dir/LICENSE.masscan" "$package_dir/LICENSE.masscan"
install -m 0644 "$license_file" "$package_dir/AGPL-3.0.txt"
install -m 0644 "$script_dir/SOURCE.md" "$package_dir/SOURCE.md"
install -m 0644 "$script_dir/README.md" "$package_dir/README.md"
install -m 0755 "$script_dir/build.sh" "$package_dir/build.sh"
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
	-C "$work_dir" -cf - "$package_name" | gzip -n > "$output_dir/$package_name.tar.gz"
(
	cd "$output_dir"
	sha256sum "$package_name.tar.gz" > "$package_name.tar.gz.sha256"
)

printf 'binary: %s\n' "$output_dir/masscan"
printf 'source: %s\n' "$output_dir/$package_name.tar.gz"
