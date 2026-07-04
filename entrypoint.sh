#!/bin/sh
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_SUBNET="${WG_SUBNET:-10.8.0.0/24}"
OUT_IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"

iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE
# Peer isolation: block peer-to-peer traffic inside the wg subnet.
if [ "${WG_PEER_ISOLATION:-false}" = "true" ]; then
  iptables -C FORWARD -i "$WG_INTERFACE" -o "$WG_INTERFACE" -j DROP 2>/dev/null \
    || iptables -I FORWARD 1 -i "$WG_INTERFACE" -o "$WG_INTERFACE" -j DROP
else
  iptables -D FORWARD -i "$WG_INTERFACE" -o "$WG_INTERFACE" -j DROP 2>/dev/null || true
fi

iptables -C FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
iptables -C FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT

# Relay wg clients into extra networks (e.g. another wg tunnel on the host).
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
