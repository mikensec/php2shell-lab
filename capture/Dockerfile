FROM alpine:3.20
# Tiny packet-capture sidecar. Shares the victim's network namespace and writes
# a pcap to the shared volume. No application logic.
RUN apk add --no-cache tcpdump
ENTRYPOINT ["sh", "-c", "mkdir -p /captures && exec tcpdump -i any -s 0 -U -w /captures/victim.pcap"]
