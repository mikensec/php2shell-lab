# Safe testing — how to prove it without weaponizing it

This directory validates **detection**, not exploitation. It reproduces the two
*observable* primitives of the `session.upload_progress` issue (CVE-2026-109618 /
CVE-2026-109619 research) and confirms the rules in [`../rules`](../rules) fire.

## The safety boundary (what we deliberately do NOT do)

Per the public research (19h's verified report, the ASAN audit), this is **not** a
memory-corruption RCE in PHP core. It is:

1. **P1** — a multipart body field `PHPSESSID` sets the session id before your
   script runs (no cookie needed), and
2. **P2** — `PHP_SESSION_UPLOAD_PROGRESS` value + the upload filename are written
   verbatim into the session file.

Code execution only happens if a **victim application** then `include()`s that
session file. That include sink is the actual vulnerability, and it is an app bug.

So this kit stops at P1+P2 with an **inert canary** (`<?php /* ... */ ?>` — a PHP
*comment*, no statements, not a shell). It never sets `cleanup=0`, never grooms
the heap, and never wires up an include/require sink. There is nothing here that
turns the canary into running code. That is enough to prove the behavior and to
make the detections fire.

## Run order

Offline logic check (no containers, no network) — safe anywhere:
```bash
python3 tests/rules_selftest.py      # proves the rule matching logic
```

Live validation in the isolated lab:
```bash
./lab.sh up && ./lab.sh check        # start lab, confirm NO internet route
./validate.sh                        # probe -> check poison -> run rules -> report
```

`validate.sh` runs:
1. `tests/canary_probe.py` — one benign request to the lab `target` (guarded: it
   refuses any non-lab/non-private host).
2. `tests/check_poison.py` in the target container — confirms a `sess_*` file was
   created cookie-lessly and contains the canary (proof P1+P2 reproduced).
3. YARA over the session dir + Suricata over the captured pcap (if installed) —
   confirms the rules alert on what the probe produced.

## Interpreting results

- **cleanup=1 (stock default)**: the poison is wiped at end of request, so
  `check_poison.py` may find nothing — that is the mitigation working. You will
  still see the network rules fire on the request. To observe a persisted poisoned
  file you must pin an affected/misconfigured build (`PHP_TAG` in `.env`,
  `session.upload_progress.cleanup=0`), which you do at your own risk in the lab.
- A real PoC you obtain separately can be detonated with `./lab.sh run` and its
  capture compared against these same rules. Send the **artifact bundle** (pcap,
  session files, logs — inert) for rule tuning; you never need to share the PoC.

## Authorized use only

Everything here targets your own lab container, offline. Do not point any probe
at systems you do not own or are not explicitly authorized to test.
