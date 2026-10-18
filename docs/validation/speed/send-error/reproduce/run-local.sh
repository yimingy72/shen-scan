#!/bin/sh
set -eux
out=/shen/work/masscan-send-diagnostic
cc -O2 -Wall -Wextra "$out/micro-fixture.c" -o "$out/micro-fixture"
cc -O2 -Wall -Wextra -shared -fPIC "$out/inject-send.c" -o "$out/inject-send.so" -ldl
case=$1
case "$case" in
 persistent-original) binary=/shen/work/speed-regression-analysis/candidate-bin/masscan;mode=persistent;ports=8000-8255;rate=10000;;
 persistent-fixed) binary=$out/bin/masscan;mode=persistent;ports=8000-8255;rate=10000;;
 transient-fixed) binary=$out/bin/masscan;mode=transient;ports=8000-8255;rate=10000;;
 normal-cold) binary=$out/bin/masscan;mode=;ports=1-65535;rate=10000;;
 *) exit 2;;
esac
cleanup() {
 ip netns del send-src 2>/dev/null || true
 ip netns del send-dst 2>/dev/null || true
}
trap cleanup EXIT INT TERM
ip netns add send-src
ip netns add send-dst
ip link add underS netns send-src type veth peer name underT netns send-dst
ip -n send-src addr add 192.0.2.1/30 dev underS
ip -n send-dst addr add 192.0.2.2/30 dev underT
ip -n send-src link set lo up
ip -n send-dst link set lo up
ip -n send-src link set underS up
ip -n send-dst link set underT up
ip -n send-src link add vxlan42 type vxlan id 42 local 192.0.2.1 remote 192.0.2.2 dstport 4789
ip -n send-dst link add vxlan42 type vxlan id 42 local 192.0.2.2 remote 192.0.2.1 dstport 4789
ip -n send-src link set vxlan42 addrgenmode none address 02:00:00:00:00:11 mtu 1400 up
ip -n send-dst link set vxlan42 addrgenmode none address 02:00:00:00:00:12 mtu 1400 up
ip -n send-src addr add 198.18.0.1/24 dev vxlan42
ip -n send-dst addr add 198.18.0.2/24 dev vxlan42
# Raw source198.18.0.3 is unassigned: no host-kernelRST contamination. No default routes.
ip netns exec send-dst "$out/micro-fixture" serve & server=$!
ip netns exec send-src "$out/micro-fixture" capture vxlan42 "$out/$case-source.pcap" >"$out/$case-source-capture.log" & sourcecap=$!
ip netns exec send-dst "$out/micro-fixture" capture vxlan42 "$out/$case-target.pcap" >"$out/$case-target-capture.log" & targetcap=$!
sleep 1
status=0
if [ -n "$mode" ]; then
 ip netns exec send-src /usr/bin/time -f 'elapsed=%e user=%U sys=%S exit=%x' -o "$out/$case.time" \
  timeout -k 1 15 env LD_PRELOAD="$out/inject-send.so" SEND_INJECT_INTERFACE=vxlan42 SEND_INJECT_MODE="$mode" \
  "$binary" --adapter vxlan42 --adapter-ip 198.18.0.3 --adapter-mac 02:00:00:00:00:11 \
  --router-mac 02:00:00:00:00:12 --rate "$rate" --wait 1 --seed 42 \
  -p"$ports" -oL "$out/$case.list" 198.18.0.2 >"$out/$case.stdout" 2>"$out/$case.stderr" || status=$?
else
 ip netns exec send-src /usr/bin/time -f 'elapsed=%e user=%U sys=%S exit=%x' -o "$out/$case.time" \
  timeout -k 1 20 "$binary" --adapter vxlan42 --adapter-ip 198.18.0.3 --adapter-mac 02:00:00:00:00:11 \
  --router-mac 02:00:00:00:00:12 --rate "$rate" --wait 1 --seed 42 \
  -p"$ports" -oL "$out/$case.list" 198.18.0.2 >"$out/$case.stdout" 2>"$out/$case.stderr" || status=$?
fi
printf '%s\n' "$status" > "$out/$case.exit"
kill "$sourcecap" "$targetcap" "$server"
wait "$sourcecap"
wait "$targetcap"
wait "$server"
printf 'case=%s exit=%s\n' "$case" "$status"
cat "$out/$case.time" "$out/$case-source-capture.log" "$out/$case-target-capture.log"
grep -E 'scan_send:|send_inject:|scan_capture:' "$out/$case.stderr" || true
