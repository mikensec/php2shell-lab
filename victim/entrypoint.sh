#!/usr/bin/env bash
# Start full packet capture on the target, then hand off to the PHP server.
set -e
mkdir -p /captures
# Capture everything the target sees on the lab network (what the exploit sends).
tcpdump -i any -s 0 -U -w /captures/target.pcap >/captures/tcpdump.log 2>&1 &
echo "[target] capture started -> /captures/target.pcap"
exec "$@"
