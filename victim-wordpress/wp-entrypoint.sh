#!/usr/bin/env bash
# Start capture, then run the stock WordPress entrypoint (DB wait, wp-config, apache).
set -e
mkdir -p /captures
tcpdump -i any -s 0 -U -w /captures/wp-target.pcap >/captures/wp-tcpdump.log 2>&1 &
echo "[wp-victim] capture started -> /captures/wp-target.pcap"
# docker-entrypoint.sh is the upstream WordPress entrypoint; it configures wp-config
# from WORDPRESS_* env and then execs the CMD (apache2-foreground).
exec docker-entrypoint.sh "$@"
