#!/usr/bin/env bash
# Detection validation: benign canary probe -> confirm poison -> run rules.
# Runs entirely inside the offline lab. Nothing here is an exploit.
set -uo pipefail
cd "$(dirname "$0")"
C="docker compose"

echo "== 0. isolation check =="
./lab.sh check || { echo "[abort] lab is not isolated"; exit 1; }

echo "== 1. benign canary probe (inert PHP comment, lab target only) =="
$C exec analysis python3 -I /sample/../tests/canary_probe.py --url "http://target/index.php" 2>/dev/null \
  || $C cp tests/canary_probe.py analysis:/tmp/canary_probe.py \
     && $C exec analysis python3 -I /tmp/canary_probe.py --url "http://target/index.php"

echo "== 2. confirm session poison in target (read-only) =="
$C cp tests/check_poison.py target:/tmp/check_poison.py
$C exec target python3 /tmp/check_poison.py || true

echo "== 3. run detection rules on what the probe produced =="
if $C exec target sh -lc 'command -v yara >/dev/null 2>&1'; then
  $C cp rules/yara target:/tmp/yara
  $C exec target sh -lc 'SP="$(php -r "echo ini_get(\"session.save_path\")?:\"/tmp\";")"; \
      yara -r /tmp/yara/php_uploadprogress_session_poison.yar "$SP" || echo "(no yara match)"'
else
  echo "   [skip] yara not installed in target; the python poison check above is the proof."
fi

echo "== 4. (optional) check Suricata over a captured pcap, if you have suricata =="
echo "   suricata -r artifacts/analysis-*.pcap -S rules/suricata/php_uploadprogress.rules -l ./artifacts"
echo
echo "Done. Network rules key on the request shape; YARA on the poisoned session file."
