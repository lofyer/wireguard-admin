#!/bin/sh
set -e

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_SUBNET="${WG_SUBNET:-10.8.0.0/24}"
OUT_IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"

iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o "$OUT_IFACE" -j MASQUERADE
iptables -C FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
iptables -C FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
