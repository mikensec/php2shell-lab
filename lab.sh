#!/usr/bin/env bash
# Host-side control wrapper for the PHP2Shell detection lab.
# Thin shim over `docker compose` so contributors have one entrypoint.
set -euo pipefail
cd "$(dirname "$0")"

# Scenario selects which victim comes up. `analysis` (attacker) is always on.
#   plain      -> stock PHP target (service: target,    host: target)
#   wordpress  -> WordPress + MariaDB (service: wp-victim, host: wp-victim)
SCENARIO_FILE=".scenario"
default_profile(){ [ -f "$SCENARIO_FILE" ] && cat "$SCENARIO_FILE" || echo plain; }
PROFILE="$(default_profile)"
C="docker compose --profile $PROFILE"

victim_host(){ [ "$PROFILE" = wordpress ] && echo wp-victim || echo target; }
victim_svc(){  victim_host; }   # service name == hostname here

usage(){ cat <<EOF
PHP2Shell detection lab — offline analysis harness (bring your own sample).

  ./lab.sh up [plain|wordpress]  build + start the chosen victim + attacker (default: plain)
  ./lab.sh check                 verify the attacker box has NO internet route
  ./lab.sh target                print the victim's in-lab URL to aim at
  ./lab.sh triage <file>         static-only review of a PoC in ./sample (does not run it)
  ./lab.sh run <file> [args]     detonate the PoC under strace+tcpdump capture
  ./lab.sh probe                 fire the BENIGN canary probe at the current victim
  ./lab.sh collect               bundle artifacts -> ./artifacts/bundle-*.tar.gz
  ./lab.sh logs                  tail the victim's php error log
  ./lab.sh down                  stop and remove everything (incl. volumes)

Current scenario: $PROFILE   (victim host: $(victim_host))
Put your sample in ./sample/ (.gitignored). Paths are relative to ./sample.
EOF
}

san(){ local f="$1"; f="${f#./sample/}"; f="${f#sample/}"; echo "/sample/$f"; }

case "${1:-}" in
  up)
    prof="${2:-$PROFILE}"
    case "$prof" in plain|wordpress) ;; *) echo "scenario must be plain|wordpress"; exit 1;; esac
    echo "$prof" > "$SCENARIO_FILE"
    docker compose --profile "$prof" up -d --build
    echo "[*] scenario '$prof' up. victim host: $([ "$prof" = wordpress ] && echo wp-victim || echo target)"
    [ "$prof" = wordpress ] && echo "[*] WordPress may take ~30-60s to finish first-run DB setup."
    ;;
  check)
    $C exec analysis sh -lc '
      echo "[*] route table:"; ip route;
      if ip route | grep -q default; then echo "[FAIL] default route present"; exit 1; fi
      if curl -sS -m3 https://1.1.1.1 >/dev/null 2>&1; then echo "[FAIL] reached internet"; exit 1; fi
      echo "[ok] no internet route — isolated"' ;;
  target)
    h="$(victim_host)"; port=$([ "$h" = wp-victim ] && echo 80 || echo 8080)
    echo "http://$h:$port/" ;;
  triage)  [ $# -ge 2 ] || { usage; exit 1; }
           $C exec analysis bash /opt/lab/static-triage.sh "$(san "$2")" ;;
  run)     [ $# -ge 2 ] || { usage; exit 1; }
           f="$(san "$2")"; shift 2
           $C exec analysis bash /opt/lab/run-poc.sh "$f" "$@" ;;
  probe)
    h="$(victim_host)"; port=$([ "$h" = wp-victim ] && echo 80 || echo 8080)
    $C cp tests/canary_probe.py analysis:/tmp/canary_probe.py
    $C exec analysis python3 -I /tmp/canary_probe.py --url "http://$h:$port/index.php" ;;
  collect) $C exec analysis bash /opt/lab/collect-artifacts.sh ;;
  logs)
    svc="$(victim_svc)"
    $C exec "$svc" sh -lc 'tail -n 100 -f /captures/*php_error.log 2>/dev/null || tail -n 100 -f /captures/php_error.log' ;;
  down)    $C down -v; rm -f "$SCENARIO_FILE" ;;
  *)       usage ;;
esac
