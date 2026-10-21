#!/usr/bin/env bash
# Static-only triage of an untrusted Python PoC. Reads the file; never executes it.
# Produces a report you (and Claude) can review to decide if it is a real PoC or malware.
# Usage: ./static-triage.sh /home/analyst/sample/poc.py
set -u
F="${1:?usage: static-triage.sh <file.py>}"
OUT="${2:-$HOME/artifacts}"; mkdir -p "$OUT"
R="$OUT/static-triage.txt"
: > "$R"

say(){ echo "$@" | tee -a "$R"; }

say "== file: $F =="
say "sha256: $(sha256sum "$F" | awk '{print $1}')"
say "size:   $(stat -c %s "$F") bytes"
file "$F" | tee -a "$R"
say ""

say "== suspicious imports / calls (review each) =="
grep -nEi \
 'os\.system|subprocess|popen|pty\.spawn|socket|eval\(|exec\(|compile\(|marshal|pickle|base64|codecs\.decode|zlib|gzip|__import__|ctypes|urllib|requests|http\.client|shutil\.rmtree|os\.remove|os\.unlink|rm -rf|mkfs|dd if=|crontab|systemctl|chmod \+x|/etc/passwd|authorized_keys|\.ssh' \
 "$F" | tee -a "$R"
say ""

say "== network indicators (hosts/URLs/IPs the PoC references) =="
grep -nEo 'https?://[^"'"'"' ]+|([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' "$F" | tee -a "$R"
say ""

say "== possible obfuscation / packed payload =="
# long one-line base64/hex blobs are a classic trojan-dropper tell
grep -nE '[A-Za-z0-9+/=]{200,}' "$F" | cut -c1-120 | tee -a "$R"
grep -nE '(\\x[0-9a-fA-F]{2}){60,}' "$F" | cut -c1-120 | tee -a "$R"
say ""

say "== decoder-then-exec chains (strong malware signal) =="
grep -nEi 'exec\(.*b?(64decode|fromhex|decompress|loads)|eval\(.*decode' "$F" | tee -a "$R"
say ""

say "== printable strings =="
strings -n 6 "$F" | sort -u | head -200 >> "$R"

echo
echo "Report written to $R"
echo "Review it (or hand $R to Claude). If you see: decode-then-exec, a baked-in"
echo "external host/IP, destructive FS ops, or a large opaque blob -> treat as MALWARE,"
echo "do not run it even in the VM beyond what you've already done statically."
