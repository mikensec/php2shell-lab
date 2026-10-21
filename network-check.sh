#!/usr/bin/env bash
# Verify the VM is isolated: can reach the peer VM, cannot reach host/internet.
# Run on BOTH VMs after netplan apply. Exit 0 = properly isolated.
set -u
PEER="${1:-}"   # pass the other VM's IP, e.g. ./network-check.sh 192.168.190.20
fail=0

echo "== Interfaces / routes =="
ip -brief addr; ip route
if ip route | grep -q '^default'; then
  echo "[FAIL] a default route exists -> traffic can leave the segment. Remove gateway from netplan."
  fail=1
else
  echo "[ok] no default route"
fi

echo "== DNS should NOT resolve =="
if getent hosts example.com >/dev/null 2>&1; then
  echo "[FAIL] DNS resolved example.com -> VM has a resolver/route off-segment."
  fail=1
else
  echo "[ok] DNS does not resolve"
fi

echo "== Public hosts should be UNREACHABLE =="
for ip in 1.1.1.1 8.8.8.8; do
  if ping -c1 -W2 "$ip" >/dev/null 2>&1; then
    echo "[FAIL] reached $ip -> NOT isolated. Check the network adapter is Custom/VMnet10, no NAT."
    fail=1
  else
    echo "[ok] cannot reach $ip"
  fi
done

if [ -n "$PEER" ]; then
  echo "== Peer VM $PEER should be REACHABLE =="
  if ping -c1 -W2 "$PEER" >/dev/null 2>&1; then
    echo "[ok] peer reachable"
  else
    echo "[warn] peer $PEER not reachable yet (is it powered on? right subnet?)"
  fi
fi

[ "$fail" -eq 0 ] && echo "RESULT: isolated OK" || echo "RESULT: NOT ISOLATED — do not detonate"
exit "$fail"
