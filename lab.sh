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

DC=""   # Compose CLI, resolved by preflight (either "docker compose" or "docker-compose")

# Resolve the Compose CLI: v2 plugin ("docker compose") or standalone ("docker-compose").
resolve_compose(){
  if docker compose version >/dev/null 2>&1; then DC="docker compose"; return 0; fi
  command -v docker-compose >/dev/null 2>&1 && { DC="docker-compose"; return 0; }
  return 1
}

# Verify host prerequisites before touching the stack. Prints actionable guidance
# and exits non-zero if anything is missing, instead of failing deep inside docker.
preflight(){
  local ok=1
  if ! command -v docker >/dev/null 2>&1; then
    echo "[FAIL] docker is not installed.        fix: sudo apt install docker.io" >&2; ok=0
  elif ! docker info >/dev/null 2>&1; then
    echo "[FAIL] cannot reach the Docker daemon (not running, or no permission)." >&2
    echo "       start it:  sudo systemctl start docker" >&2
    echo "       add perms: sudo usermod -aG docker \"\$USER\"   (then log out/in)" >&2
    echo "       or just:   sudo ./lab.sh $*" >&2
    ok=0
  fi
  if ! resolve_compose; then
    echo "[FAIL] Docker Compose is not installed. fix: sudo apt install docker-compose" >&2; ok=0
  fi
  [ "$ok" = 1 ] || exit 1
}

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
  ./lab.sh doctor                check host prerequisites (docker, daemon, compose)

Current scenario: $PROFILE   (victim host: $(victim_host))
Put your sample in ./sample/ (.gitignored). Paths are relative to ./sample.
EOF
}

san(){ local f="$1"; f="${f#./sample/}"; f="${f#sample/}"; echo "/sample/$f"; }

# Everything except help/target/doctor needs a working Docker + Compose stack.
case "${1:-}" in
  up|check|triage|run|probe|collect|logs|down)
    preflight "$@"
    C="$DC --profile $PROFILE" ;;
esac

case "${1:-}" in
  up)
    prof="${2:-$PROFILE}"
    case "$prof" in plain|wordpress) ;; *) echo "scenario must be plain|wordpress"; exit 1;; esac
    echo "$prof" > "$SCENARIO_FILE"
    $DC --profile "$prof" up -d --build
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
    h="$(victim_host)"; port=80   # both victims serve on apache's port 80 inside labnet
    echo "http://$h:$port/" ;;
  triage)  [ $# -ge 2 ] || { usage; exit 1; }
           $C exec analysis bash /opt/lab/static-triage.sh "$(san "$2")" ;;
  run)     [ $# -ge 2 ] || { usage; exit 1; }
           f="$(san "$2")"; shift 2
           $C exec analysis bash /opt/lab/run-poc.sh "$f" "$@" ;;
  probe)
    h="$(victim_host)"; port=80   # both victims serve on apache's port 80 inside labnet
    $C cp tests/canary_probe.py analysis:/tmp/canary_probe.py
    $C exec analysis python3 -I /tmp/canary_probe.py --url "http://$h:$port/index.php" ;;
  collect) $C exec analysis bash /opt/lab/collect-artifacts.sh ;;
  logs)
    svc="$(victim_svc)"
    $C exec "$svc" sh -lc 'tail -n 100 -f /captures/*php_error.log 2>/dev/null || tail -n 100 -f /captures/php_error.log' ;;
  down)    $C down -v; rm -f "$SCENARIO_FILE" ;;
  doctor)
    preflight "$@"
    echo "[ok] docker:  $(docker --version)"
    echo "[ok] daemon:  reachable"
    echo "[ok] compose: $DC ($($DC version --short 2>/dev/null || echo present))"
    echo "[ok] prerequisites satisfied — ./lab.sh up to start." ;;
  *)       usage ;;
esac
