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

- **Docker Engine** (the daemon must be running).
- **Docker Compose** — either the v2 plugin (`docker compose`) or the standalone
  `docker-compose` binary. `lab.sh` auto-detects whichever is present.
- A Linux host, WSL2, or Docker Desktop.
- No internet needed at run time (only to build images the first time).

### Install the prerequisites (Debian / Kali / Ubuntu)

```bash
sudo apt update
sudo apt install -y docker.io docker-compose     # engine + compose v2
sudo systemctl enable --now docker               # start the daemon
sudo usermod -aG docker "$USER"                   # run docker without sudo
#   log out and back in (or run `newgrp docker`) for the group to take effect
```

On other distros / Docker Desktop, install Docker from docker.com; Compose v2
ships with it.

### Check your host is ready

```bash
./lab.sh doctor     # verifies docker is installed, the daemon is reachable,
                    # and Compose is available — with a fix for anything missing
```

Run this first if `./lab.sh up` errors (e.g. `unknown flag: --profile` means
Compose is not installed; `permission denied ... docker.sock` means the daemon
isn't reachable or your user isn't in the `docker` group).

## Quick start

```bash
./lab.sh doctor                 # verify docker + compose are ready (see Requirements)
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
./lab.sh up               # plain stock-PHP target  (host: target:80)
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
vulnerable code in this repo. The "vulnerability" is simply the PHP version you pin:
pick an affected release and PHP itself provides the flaw. See
[Reproducing the vulnerable build](#reproducing-the-vulnerable-build) below.

## Reproducing the vulnerable build

CVE-2026-109618 / CVE-2026-109619 ("php2shell") were published **2026-10-21**: a
`session.upload_progress` use-after-free in PHP core leading to RCE. Upstream fixes:

| Branch | Fixed in | Last vulnerable |
|--------|----------|-----------------|
| 8.5    | 8.5.12   | 8.5.11 |
| 8.4    | 8.4.27   | 8.4.26 |
| 8.3    | 8.3.36   | **8.3.35** |
| 8.2    | 8.2.35   | 8.2.34 |
| ≤ 8.1  | EOL — no official fix | (confirm on php.net) |

A build **below** the fix for its branch is vulnerable; `>=` the fix is patched.
Always confirm the range against the official advisory on
[php.net](https://www.php.net/) / NVD before trusting it.

**The lab now ships vulnerable by default:** `.env` pins `PHP_TAG=8.3.35-apache`
(the last 8.3 before the 8.3.36 fix). Do **not** use a floating tag like
`8.3-apache` to reproduce — it resolves to the patched 8.3.36.

```bash
cp .env.example .env            # already pins 8.3.35-apache + FIXED_IN=8.3.36
docker pull php:8.3.35-apache   # fetch the exact vulnerable image
./lab.sh up                     # build + start against it
./lab.sh version                # -> [VULNERABLE] 8.3.35 < 8.3.36
```

`./lab.sh version` runs `php -v` inside the current victim and compares it to
`FIXED_IN` in `.env`, printing `VULNERABLE` or `PATCHED`. To confirm a fix closes
it, set `PHP_TAG=8.3.36-apache`, `./lab.sh up` again, and re-check.

For a frozen, bit-for-bit image, pin by **digest** instead of tag:

```bash
docker image inspect php:8.3.35-apache --format '{{index .RepoDigests 0}}'
# -> php@sha256:...   put that in PHP_TAG so the build can never drift to a fix
```

### WordPress

The `wordpress:*-php8.3-apache` tags bake PHP in and float to the latest 8.3.x,
which is now the **patched** 8.3.36. To keep the WP victim vulnerable, capture the
digest of an image that still carries PHP ≤ 8.3.35 **before** WordPress rebuilds,
and pin it:

```bash
docker pull wordpress:6.6-php8.3-apache
docker run --rm wordpress:6.6-php8.3-apache php -v      # verify it's <= 8.3.35
docker image inspect wordpress:6.6-php8.3-apache \
  --format '{{index .RepoDigests 0}}'                  # -> wordpress@sha256:...
# set WP_TAG to that digest in .env, then: ./lab.sh up wordpress && ./lab.sh version
```

> Even on a vulnerable PHP, `session.upload_progress` injection only becomes code
> execution through an app-side `include()`/`require()` of the session file. Stock
> WordPress does not provide that sink — the WP scenario is for observing the
> primitive and validating detections on a realistic stack, not turnkey RCE.

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
