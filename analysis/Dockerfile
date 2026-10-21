FROM python:3.12-slim

# Analysis box: runs an untrusted PoC under strace+tcpdump and triages it statically.
# No exploit ships here; the sample is mounted read-only at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump strace file binutils iproute2 curl ca-certificates jq procps libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Let the non-root analyst use the capture/trace tools (compose grants the caps to
# the container; file capabilities let a non-root process actually use them).
RUN setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v tcpdump)")" \
    && setcap cap_sys_ptrace+eip "$(readlink -f "$(command -v strace)")"

# Run as non-root; SYS_PTRACE/NET_RAW are granted via compose for the tooling.
RUN useradd -m -u 1000 analyst
COPY --chown=analyst:analyst lab/ /opt/lab/
RUN chmod +x /opt/lab/*.sh
USER analyst
WORKDIR /opt/lab
