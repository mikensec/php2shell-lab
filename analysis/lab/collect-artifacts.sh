#!/usr/bin/env bash
# Bundle everything a detection engineer needs, from both the analysis and target side.
# Output: /artifacts/bundle-<ts>.tar.gz  (inert data only: pcaps, logs, traces, hashes)
set -u
ART=/artifacts; CAP=/captures; TS="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE="$ART/bundle-$TS"; mkdir -p "$STAGE"

# Pull target-side capture + php logs off the shared volume.
cp -a "$CAP"/. "$STAGE"/ 2>/dev/null || true
# Keep analysis-side artifacts.
cp -a "$ART"/*.pcap "$ART"/*.log "$ART"/*.txt "$ART"/*.diff "$ART"/*.sha256 "$STAGE"/ 2>/dev/null || true

# Quick machine-readable summary of network endpoints seen (helps rule-writing).
{
  echo "# endpoints observed (src/dst) — from analysis pcap"
  if command -v tcpdump >/dev/null; then
    for p in "$ART"/analysis-*.pcap "$STAGE"/target.pcap; do
      [ -f "$p" ] || continue
      echo "## $p"
      tcpdump -nr "$p" 2>/dev/null | awk '{print $3" -> "$5}' | sort | uniq -c | sort -rn | head -50
    done
  fi
} > "$STAGE/endpoints.txt" 2>/dev/null

( cd "$ART" && tar czf "bundle-$TS.tar.gz" "bundle-$TS" )
echo "[*] bundle: $ART/bundle-$TS.tar.gz"
echo "[*] copy it out of the lab with:  docker cp php2shell-analysis:$ART/bundle-$TS.tar.gz ."
echo "[*] it contains only inert capture/log data — safe to hand to Claude for rule generation."
