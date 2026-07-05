#!/bin/sh
set -e

# Host network mode shares the host network namespace, so forwarding is
# enabled here instead of via per-container sysctls.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || \
  echo "WARN: could not enable net.ipv4.ip_forward, set it on the host"
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true

# NAT and peer isolation rules are managed per interface by the app
# (app/wireguard/sync.py) when configs are applied.

# Relay wg clients into extra networks (e.g. another wg tunnel on the host).
WG_SUBNET="${WG_SUBNET:-10.8.0.0/24}"
OLD_IFS="$IFS"; IFS=','
for subnet in ${WG_RELAY_SUBNETS:-}; do
  subnet="$(echo "$subnet" | tr -d ' ')"
  [ -n "$subnet" ] || continue
  relay_iface="$(ip route get "${subnet%/*}" 2>/dev/null | awk '/dev/ {for (i=1;i<NF;i++) if ($i=="dev") print $(i+1); exit}')"
  [ -n "$relay_iface" ] || { echo "WARN: no route to relay subnet $subnet, skipping"; continue; }
  iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -d "$subnet" -o "$relay_iface" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -d "$subnet" -o "$relay_iface" -j MASQUERADE
done
IFS="$OLD_IFS"

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
