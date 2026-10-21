# php2shell-lab

A reproducible, **offline** lab for safely analysing an untrusted proof-of-concept for
the PHP core RCEs **CVE-2026-109618** and **CVE-2026-109619** ("PHP2Shell"), and for
turning what you observe into detection content (YARA / Sigma / Suricata).

> This repository ships **no exploit and no PoC**. It is a detection/analysis harness.
> You bring your own sample; it is mounted read-only and is never committed. The point
> is to let defenders watch a sample behave in a sealed environment and extract IOCs.

## ⚠️ Authorized use only

- Run this only against targets **you own** (the bundled target container), in this
  isolated lab. Never point a PoC at systems you are not explicitly authorised to test.
- Treat every PoC as **malware** until you have reviewed it. Trojanised "PoCs" for
  hyped CVEs are common.
- The lab network is `internal: true` — no host access, no internet. Keep it that way.

## Requirements

- Docker + Docker Compose v2 (`docker compose`). Linux host, WSL2, or Docker Desktop.
- No internet needed at run time (only to build images the first time).

## Quick start

```bash
cp .env.example .env            # optionally pin PHP_TAG to the version you assess
./lab.sh up                     # build + start target and analysis box (sealed net)
./lab.sh check                  # prove the analysis box has no internet route

# put YOUR sample in ./sample/ (gitignored), then:
./lab.sh triage poc.py          # static-only review — does NOT execute the sample
#   read the report. if it shows decode-then-exec, baked-in external IPs,
#   destructive FS ops, or large opaque blobs -> it's malware, stop here.

./lab.sh run poc.py             # detonate under strace + full packet capture
./lab.sh collect                # -> ./artifacts/bundle-<ts>.tar.gz (inert data)
./lab.sh down                   # tear everything down (-v removes volumes)
```

Copy the bundle out and feed it to your detection workflow:

```bash
docker cp php2shell-analysis:/artifacts/bundle-<ts>.tar.gz .
```

## Scenarios: plain PHP or WordPress victim

The attacker box (`analysis`) is always up. Pick one victim:

```bash
./lab.sh up               # plain stock-PHP target  (host: target:8080)
./lab.sh up wordpress     # WordPress + MariaDB      (host: wp-victim:80)
./lab.sh target           # prints the current victim URL to aim at
./lab.sh probe            # fire the BENIGN canary at the current victim
./lab.sh run poc.py --url http://wp-victim/    # your own PoC vs WordPress
```

The WordPress victim is **stock WordPress + PHP + MariaDB**, instrumented for
packet capture and verbose PHP logging. There is no planted vulnerability, no
include-sink, and no webshell — it is a realistic PHP app to fire at and observe.
First boot takes ~30-60s for WordPress to set up its database. Both WordPress and
its DB sit on the same `internal` network: no host, no internet.

> Reminder: `session.upload_progress` content-injection only becomes code
> execution through an application-side `include()`/`require()` of the session
> file. Stock WordPress does not hand you that sink. The lab lets you observe the
> primitives and validate detections on a real stack; turning it into RCE would
> require a separately vulnerable app/plugin, which this repo does not provide.

## What you get in a bundle

| Artifact | Use |
|----------|-----|
| `analysis-*.pcap` | what the PoC sent — basis for **Suricata** rules |
| `target.pcap` | what the server received — request shape, URIs, headers |
| `strace-*.log` | syscalls: `connect()`, `execve()`, file writes — **Sigma** host rules |
| `dropped-files.diff` / `.sha256` | files the PoC created — **YARA** rules + IOC hashes |
| `php_error.log` | server-side errors the exploit triggers — log detections |
| `endpoints.txt` | summarised talk pairs | 
| `static-triage.txt` | pre-run static review |

## How it's isolated

```
        docker network "labnet"  (internal: true  ->  no host, no internet)
   ┌──────────────────────────┐          ┌──────────────────────────┐
   │ php2shell-analysis        │  pcap    │ php2shell-target          │
   │ python3 + strace+tcpdump  │◄────────►│ stock PHP (PHP_TAG) +     │
   │ /sample (ro), /artifacts  │          │ tcpdump, verbose logging  │
   └──────────────────────────┘          └──────────────────────────┘
   cap_drop ALL; no-new-privileges; non-root; pids/mem limits; no published ports
```

The target is a **stock** `php:<tag>` image plus capture — there is no deliberately
vulnerable code in this repo. To reproduce a specific affected build, set `PHP_TAG`
in `.env` to that version once php.net publishes the affected range.

## For stronger isolation

Docker shares the host kernel. For a kernel-0day or anything you don't trust against a
container boundary, use the VM version of this lab ([`vmware-network.md`](vmware-network.md),
[`network-check.sh`](network-check.sh)) with two host-only VMs and snapshots, or — the
most robust option — run this whole compose stack *inside* a disposable VMware VM.

## Troubleshooting

- **`tcpdump`/`strace` permission denied in the analysis box** — the image sets file
  capabilities so the non-root user can use them; make sure you rebuilt (`./lab.sh up`
  does `--build`). The caps are also granted in `docker-compose.yml`.
- **Can't write `./artifacts` on native Linux** — the container runs as uid 1000. Either
  run `chmod 777 artifacts` once, or match your host uid by rebuilding with
  `--build-arg`/editing the `useradd` line. On Docker Desktop (Win/Mac) this is automatic.
- **`./lab.sh check` says it reached the internet** — your Docker has an override; confirm
  the network still has `internal: true` and you have no other compose override file.

## Detection rules

Drafts land in [`rules/`](rules/) once artifacts from a verified PoC (or the official
PHP advisory) are available. They are written to match observed behaviour, not to
reproduce the exploit.

## License

See [LICENSE](LICENSE). Provided as-is, for defensive research and education.
