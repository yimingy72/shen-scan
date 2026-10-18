#!/bin/sh
# Only the dedicated Chrome UID is restricted. Agent/Go transport retain their
# access and enforce task scope plus shared HTTP request admission.
set -eu
uid=$(id -u shen-browser)
test "$uid" -gt 0
chain=SHEN_BROWSER
for firewall in /usr/sbin/iptables /usr/sbin/ip6tables; do
  test -x "$firewall"
  # Keep direct browser traffic denied while replacing old rules. Any failed
  # update leaves this guard in place; never flush a live allow-linked chain.
  "$firewall" -w 5 -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
  "$firewall" -w 5 -N "$chain" 2>/dev/null || "$firewall" -w 5 -S "$chain" >/dev/null
  "$firewall" -w 5 -F "$chain"
  if [ "$firewall" = /usr/sbin/iptables ]; then
    "$firewall" -w 5 -A "$chain" -o lo -s 127.0.0.1/32 -d 127.0.0.1/32 -p tcp --sport 19222 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
  fi
  "$firewall" -w 5 -A "$chain" -j REJECT
  while "$firewall" -w 5 -C OUTPUT -m owner --uid-owner "$uid" -j "$chain" >/dev/null 2>&1; do
    "$firewall" -w 5 -D OUTPUT -m owner --uid-owner "$uid" -j "$chain"
  done
  "$firewall" -w 5 -I OUTPUT 1 -m owner --uid-owner "$uid" -j "$chain"
  while "$firewall" -w 5 -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1; do
    "$firewall" -w 5 -D OUTPUT -m owner --uid-owner "$uid" -j REJECT
  done
  # Retire only the earlier experimental rule for this same dedicated UID.
  while "$firewall" -w 5 -C OUTPUT -m owner --uid-owner "$uid" -m conntrack ! --ctstate ESTABLISHED,RELATED -j REJECT >/dev/null 2>&1; do
    "$firewall" -w 5 -D OUTPUT -m owner --uid-owner "$uid" -m conntrack ! --ctstate ESTABLISHED,RELATED -j REJECT
  done
  first=$("$firewall" -w 5 -S OUTPUT | sed -n '/^-A /{p;q;}')
  test "$first" = "-A OUTPUT -m owner --uid-owner $uid -j $chain"
  count=$("$firewall" -w 5 -S "$chain" | sed -n '/^-A /p' | wc -l)
  if [ "$firewall" = /usr/sbin/iptables ]; then test "$count" -eq 2; else test "$count" -eq 1; fi
done
