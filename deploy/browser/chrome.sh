#!/bin/sh
# Chrome can reply to the helper's loopback CDP connection, but cannot initiate
# target, DNS, WebRTC or other outbound traffic. Fetch is fulfilled by Go.
set -eu
test "$(id -u)" -eq 0
test -f /var/lib/shen-browser-runtime.ready
test ! -L /var/lib/shen-browser-runtime.ready
test "$(stat -c %u /var/lib/shen-browser-runtime.ready)" -eq 0
test -f /var/lib/shen-browser-runtime.json
test "$(stat -c %u /var/lib/shen-browser-runtime.json)" -eq 0
test -x /usr/bin/google-chrome-stable
minimum=$(python3 - /var/lib/shen-browser-runtime.json <<'PYTHON'
import json, re, sys
version = json.load(open(sys.argv[1])).get('minimum_version', '')
if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}-[0-9]+', version):
    raise SystemExit('Invalid installed browser version policy')
print(version)
PYTHON
)
installed=$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' google-chrome-stable 2>/dev/null | awk '$1 == "installed" {print $2}')
dpkg --compare-versions "$installed" ge "$minimum"
actual=$(/usr/bin/google-chrome-stable --version | awk 'NR == 1 {print $3}')
dpkg --compare-versions "$actual" ge "${minimum%-*}"
uid=$(id -u shen-browser)
test "$uid" -gt 0
for firewall in /usr/sbin/iptables /usr/sbin/ip6tables; do
  first=$("$firewall" -w 5 -S OUTPUT | sed -n '/^-A /{p;q;}')
  test "$first" = "-A OUTPUT -m owner --uid-owner $uid -j SHEN_BROWSER"
  "$firewall" -w 5 -C SHEN_BROWSER -j REJECT >/dev/null 2>&1
  count=$("$firewall" -w 5 -S SHEN_BROWSER | sed -n '/^-A /p' | wc -l)
  if [ "$firewall" = /usr/sbin/iptables ]; then
    test "$count" -eq 2
    "$firewall" -w 5 -C SHEN_BROWSER -o lo -s 127.0.0.1/32 -d 127.0.0.1/32 -p tcp --sport 19222 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT >/dev/null 2>&1
  else
    test "$count" -eq 1
  fi
done
if [ "$#" -eq 1 ] && [ "$1" = --shen-browser-isolation-check ]; then
  printf '{"isolation":"uid-firewall-v1","uid":%s,"verified":true,"cdp_port":19222}\n' "$uid"
  exit 0
fi
profile=
port=
address=
for argument in "$@"; do
  case "$argument" in
    --no-sandbox*|--disable-setuid-sandbox*|--disable-web-security*)
      printf '%s\n' 'Unsafe Chrome launch flag rejected' >&2; exit 1 ;;
    --user-data-dir=*) profile=${argument#--user-data-dir=} ;;
    --remote-debugging-port=*) test -z "$port"; port=${argument#--remote-debugging-port=} ;;
    --remote-debugging-address=*) test -z "$address"; address=${argument#--remote-debugging-address=} ;;
  esac
done
test "$port" = 19222
test "$address" = 127.0.0.1
case "$profile" in /tmp/shen-browser-*) ;; *) printf '%s\n' 'A dedicated temporary browser profile is required' >&2; exit 1 ;; esac
test -d "$profile"
test ! -L "$profile"
test "$(readlink -f "$profile")" = "$profile"
owner=$(stat -c %u "$profile")
test "$owner" -eq 0 -o "$owner" -eq "$uid"
chmod 0700 "$profile"
chown shen-browser:shen-browser "$profile"
unset TMPDIR TMP TEMP XDG_CONFIG_HOME XDG_CACHE_HOME
exec /usr/sbin/runuser -u shen-browser -- /usr/bin/nice -n 10 /usr/bin/google-chrome-stable "$@"
