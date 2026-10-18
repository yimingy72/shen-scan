#!/bin/sh
set -eux
# Portable export of the previously executed fixture; not rerun during evidence packaging.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${EVIDENCE_OUTPUT_DIR:-$script_dir/../reproduced-run}
mkdir -p "$out"
cc -O2 -Wall -Wextra "$script_dir/micro-fixture.c" -o "$out/micro-fixture"
ip netns add speedtarget
ip link add speedsrc type veth peer name eth0 netns speedtarget
trap 'ip netns del speedtarget 2>/dev/null || true; ip link del speedsrc 2>/dev/null || true' EXIT INT TERM
ip link set speedsrc addrgenmode none address 02:00:00:00:00:11
ip -n speedtarget link set eth0 addrgenmode none address 02:00:00:00:00:12
ip addr add 198.18.0.1/24 dev speedsrc
ip link set speedsrc up
ip -n speedtarget link set eth0 up
# No target IP assigned: only the fixture raw responder can answer.
for variant in mixed-default mixed-candidate; do
  ip netns exec speedtarget "$out/micro-fixture" mixed eth0 "$out/$variant.pcap" >"$out/$variant-capture.log" & capture=$!
  sleep 1
  case "$variant" in
    mixed-default) binary="${MASSCAN_ORIGINAL:?Set MASSCAN_ORIGINAL to the original Linux amd64 binary}";;
    mixed-candidate) binary="${MASSCAN_CANDIDATE:?Set MASSCAN_CANDIDATE to the statusOpen Linux amd64 binary}";;
  esac
  /usr/bin/time -f 'elapsed=%e user=%U sys=%S exit=%x' -o "$out/$variant.time" \
    timeout -k 1 10 "$binary" --adapter speedsrc --adapter-ip 198.18.0.3 \
    --adapter-mac 02:00:00:00:00:11 --router-mac 02:00:00:00:00:12 \
    --rate 10 --wait 1 --seed 42 -p8080 -oL "$out/$variant.list" 198.18.0.2 \
    >"$out/$variant.stdout" 2>"$out/$variant.stderr"
  kill "$capture"
  wait "$capture"
  cat "$out/$variant.time" "$out/$variant-capture.log" "$out/$variant.list"
done
