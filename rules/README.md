# Detection rules

Rules go here once we have artifacts from a verified PoC **or** the official PHP
advisory for CVE-2026-109618 / CVE-2026-109619. They are written to detect the
attack and its tooling, not to reproduce the exploit.

Planned coverage:
- `suricata/` — network signatures for the exploit request (built from `analysis-*.pcap`).
- `sigma/` — host rules: PHP/php-fpm spawning a shell, unexpected `connect()`,
  new `.php` files in web roots (built from `strace-*.log` and server logs).
- `yara/` — the PoC tooling and any dropped files (built from `dropped-files.*`).

Until a real sample is detonated here, writing concrete rules would be guesswork.
Run the lab, collect a bundle, and generate rules from the observed behaviour.
