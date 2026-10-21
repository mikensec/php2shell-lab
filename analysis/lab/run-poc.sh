#!/usr/bin/env bash
# Detonate an untrusted PoC under capture, inside the isolated analysis container.
# Captures: full pcap of analysis-side traffic + strace of all syscalls + created files.
# You supply the PoC path (mounted read-only at /sample). Nothing here is an exploit.
#
# Usage (inside container, via ../lab.sh run): run-poc.sh /sample/poc.py [args...]
set -u
POC="${1:?usage: run-poc.sh /sample/<file>.py [args...]}"; shift || true
ART=/artifacts; mkdir -p "$ART"
TARGET_IP="$(getent hosts target | awk '{print $1}')"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

echo "[*] target resolves to: ${TARGET_IP:-<none>}"
echo "[*] poc sha256: $(sha256sum "$POC" | awk '{print $1}')"

# Snapshot filesystem state so we can diff what the PoC creates/drops.
find / -xdev -type f -newermt '1 minute ago' 2>/dev/null > "$ART/pre.filelist" || true
ls -laR /tmp /home 2>/dev/null > "$ART/pre.tmp-home.txt"

# Analysis-side capture (what the PoC emits).
tcpdump -i any -s 0 -U -w "$ART/analysis-$TS.pcap" >/dev/null 2>&1 &
TCPD=$!
sleep 1

echo "[*] detonating under strace with a 120s hard timeout, read-only sample..."
# -f follow forks, -tt timestamps, -y decode fds, limited string length.
timeout --signal=KILL 120 \
  strace -f -tt -yy -s 256 -o "$ART/strace-$TS.log" \
  python3 -I "$POC" "$@" \
  > "$ART/stdout-$TS.txt" 2> "$ART/stderr-$TS.txt"
RC=$?
echo "[*] poc exited rc=$RC"

sleep 1; kill "$TCPD" 2>/dev/null; wait "$TCPD" 2>/dev/null

# What changed on disk during detonation = dropped files / persistence.
ls -laR /tmp /home 2>/dev/null > "$ART/post.tmp-home.txt"
diff "$ART/pre.tmp-home.txt" "$ART/post.tmp-home.txt" > "$ART/dropped-files.diff" || true
# Hash anything new in common drop locations.
find /tmp /home /dev/shm -type f -newer "$POC" 2>/dev/null | while read -r f; do
  sha256sum "$f" 2>/dev/null
done > "$ART/dropped-files.sha256"

echo "[*] artifacts in $ART:"
ls -la "$ART"
echo "[*] review strace for: connect() to unexpected IPs, execve of shells,"
echo "    open()/write() outside the sample dir, chmod +x on drops."
