#!/usr/bin/env bash
# Host-side control wrapper for the PHP2Shell detection lab.
# Thin shim over `docker compose` so contributors have one entrypoint.
set -euo pipefail
cd "$(dirname "$0")"
C="docker compose"
A="php2shell-analysis"

usage(){ cat <<EOF
PHP2Shell detection lab — offline analysis harness (bring your own sample).

  ./lab.sh up                 build + start target and analysis (isolated network)
  ./lab.sh check              verify the analysis box has NO internet route
  ./lab.sh triage <file>      static-only review of a PoC in ./sample  (does not run it)
  ./lab.sh run <file> [args]  detonate the PoC under strace+tcpdump capture
  ./lab.sh collect            bundle artifacts -> ./artifacts/bundle-*.tar.gz
  ./lab.sh logs               tail target php error log
  ./lab.sh down               stop and remove everything (incl. volumes)

Put your sample in ./sample/ (that dir is .gitignored — it never gets committed).
Paths you pass are relative to ./sample, e.g.  ./lab.sh run poc.py
EOF
}

san(){ # map a host-side ./sample path to the in-container /sample path
  local f="$1"; f="${f#./sample/}"; f="${f#sample/}"; echo "/sample/$f"; }

case "${1:-}" in
  up)      $C up -d --build ;;
  check)   $C exec analysis sh -lc '
             echo "[*] route table:"; ip route;
             if ip route | grep -q default; then echo "[FAIL] default route present"; exit 1; fi
             if curl -sS -m3 https://1.1.1.1 >/dev/null 2>&1; then echo "[FAIL] reached internet"; exit 1; fi
             echo "[ok] no internet route — isolated"' ;;
  triage)  [ $# -ge 2 ] || { usage; exit 1; }
           $C exec analysis bash /opt/lab/static-triage.sh "$(san "$2")" ;;
  run)     [ $# -ge 2 ] || { usage; exit 1; }
           f="$(san "$2")"; shift 2
           $C exec analysis bash /opt/lab/run-poc.sh "$f" "$@" ;;
  collect) $C exec analysis bash /opt/lab/collect-artifacts.sh ;;
  logs)    $C exec target sh -lc 'tail -n 100 -f /captures/php_error.log' ;;
  down)    $C down -v ;;
  *)       usage ;;
esac
