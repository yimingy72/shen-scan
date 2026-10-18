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
ip -n speedtarget addr add 198.18.0.2/24 dev eth0
ip link set speedsrc up
ip -n speedtarget link set eth0 up
ip -n speedtarget link set lo up
# Captured SYNACKs will also reach the scanner host kernel; use an unassigned
# source IP so it cannot synthesize its own reset or skew Masscan's TX counts.
ip netns exec speedtarget "$out/micro-fixture" serve & server=$!
for variant in candidate; do
  if [ "$variant" = silent ]; then
    ip -n speedtarget addr del 198.18.0.2/24 dev eth0
  fi
  ip netns exec speedtarget "$out/micro-fixture" capture eth0 "$out/$variant.pcap" >"$out/$variant-capture.log" & capture=$!
  sleep 1
  extra=
  if [ "$variant" = noreset ]; then extra=--noreset; fi
  /usr/bin/time -f 'elapsed=%e user=%U sys=%S exit=%x' -o "$out/$variant.time" \
    timeout -k 1 20 "${MASSCAN_CANDIDATE:?Set MASSCAN_CANDIDATE to the statusOpen Linux amd64 binary}" \
    --adapter speedsrc --adapter-ip 198.18.0.3 --adapter-mac 02:00:00:00:00:11 \
    --router-mac 02:00:00:00:00:12 --rate 5000 --wait 2 --seed 42 \
    -p1-12000 -oL "$out/$variant.list" $extra 198.18.0.2 \
    >"$out/$variant.stdout" 2>"$out/$variant.stderr"
  kill "$capture"
  wait "$capture"
  cat "$out/$variant.time" "$out/$variant-capture.log" "$out/$variant.list"
done
kill "$server"
wait "$server"
