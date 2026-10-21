# Detection rules

Behavioral detections for the PHP `session.upload_progress` issue
(CVE-2026-109618 / CVE-2026-109619). **Pre-advisory** — derived from public
research (19h's verified report; the ASAN audit), corroborated across independent
repos, and logic-tested by [`../tests/rules_selftest.py`](../tests/rules_selftest.py).
Validate against your own lab capture before production use.

| File | Engine | Detects |
|------|--------|---------|
| `suricata/php_uploadprogress.rules` | Suricata | arming (`PHP_SESSION_UPLOAD_PROGRESS` + `PHPSESSID` in one multipart POST), content injection (progress marker + `<?php`), filename-carried PHP tags, repeated-array grooming. sids 30260001-4 |
| `yara/php_uploadprogress_session_poison.yar` | YARA | `sess_*` files poisoned with `upload_progress_` + PHP tags; the `\|` write-denial key |
| `sigma/php_uploadprogress_session_poison.yml` | Sigma | PHP "Unknown on line 0" startup warning; web/php-fpm worker spawning a shell |

## What they key on

- **Network:** the request *shape* — a multipart body that sets a session id from a
  field and/or carries the progress marker plus a PHP open tag. This is the part an
  attacker cannot avoid if they use this primitive.
- **File:** the *artifact* — a session file containing `upload_progress_` next to a
  PHP open tag. That only appears when the feature has been abused.
- **Host:** the *follow-on* — the startup warning on the parse-bail path, and the
  universal "PHP process spawned a shell" post-exploitation tell.

## Tuning notes

- Suricata needs request-body inspection on with a body limit large enough to see
  the markers (`request-body-limit` / `http` app-layer settings).
- The groom rule (sid 30260003) has a count threshold — set it from your own
  baseline; legitimate multi-file uploads can use repeated array parts.
- The Sigma process rule will catch legitimate apps that shell out; pair it with the
  session-poison file/network signals to cut false positives.

Once the official PHP advisory lands (or you detonate a real PoC in the lab and run
`./validate.sh`), tune these against the real capture and bump `rev:`.
