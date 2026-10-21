#!/usr/bin/env python3
"""
canary_probe.py — SAFE detection-validation probe for the PHP
session.upload_progress primitives (CVE-2026-109618 / CVE-2026-109619 research).

What it does (and deliberately does NOT do)
--------------------------------------------
It sends ONE benign multipart/form-data POST that exercises the two *detectable*
primitives only:
  P1  a body field named PHPSESSID (cookie-less session-id set)
  P2  a PHP_SESSION_UPLOAD_PROGRESS value + filename carrying an INERT canary

The canary is a PHP *comment* — `<?php /* ... */ ?>` — with no statements. Its
only purpose is to make the session file match the YARA/Suricata rules so you
can confirm detection works. It is not a web shell.

It does NOT implement the RCE chain: it never sets cleanup=0, never grooms the
heap, and never touches an include()/require() sink. There is nothing here to
turn session content into code execution.

Guardrails: refuses to run against anything that is not an obvious lab target
(the compose service name `target`, localhost, or an RFC1918/loopback address).
Run it only inside the offline lab, against your own container.
"""
import argparse, ipaddress, socket, sys, urllib.parse, urllib.request, uuid

CANARY = f"<?php /* php2shell-lab inert canary {uuid.uuid4().hex[:8]} - NOT a shell */ ?>"
LAB_NAMES = {"target", "localhost", "php2shell-target", "wp-victim", "php2shell-wp"}


def is_lab_target(host: str) -> bool:
    if host in LAB_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except Exception:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def build_body(boundary: str, sid: str) -> bytes:
    def part(disp, value):
        return (f"--{boundary}\r\nContent-Disposition: form-data; {disp}\r\n\r\n"
                f"{value}\r\n").encode()
    body = b""
    # P1: cookie-less session id from a body field
    body += part('name="PHPSESSID"', sid)
    # P2: progress marker value carries the inert canary
    body += part('name="PHP_SESSION_UPLOAD_PROGRESS"', CANARY)
    # a real file part so upload parsing runs; filename also carries the canary
    body += (f"--{boundary}\r\n"
             f'Content-Disposition: form-data; name="file1"; filename="{CANARY}"\r\n'
             f"Content-Type: application/octet-stream\r\n\r\n").encode()
    body += b"CANARYDATA\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://target/index.php",
                    help="lab target URL (default compose service 'target')")
    ap.add_argument("--sid", default="labcanary" + uuid.uuid4().hex[:24],
                    help="session id to inject (must be [A-Za-z0-9,-])")
    ap.add_argument("--force", action="store_true",
                    help="override the lab-target guard (not recommended)")
    args = ap.parse_args()

    host = urllib.parse.urlsplit(args.url).hostname or ""
    if not is_lab_target(host) and not args.force:
        sys.exit(f"[REFUSED] '{host}' is not a lab target (compose 'target', "
                 f"localhost, or a private IP). This probe is for your offline lab "
                 f"only. Use --force only if you are certain.")

    boundary = "----php2shelllab" + uuid.uuid4().hex
    body = build_body(boundary, args.sid)
    req = urllib.request.Request(
        args.url, data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                 "User-Agent": "php2shell-lab/canary"})
    print(f"[*] target : {args.url}")
    print(f"[*] sid     : {args.sid}")
    print(f"[*] canary  : {CANARY}")
    print(f"[*] body    : {len(body)} bytes, no cookie header")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"[*] response: HTTP {r.status}")
    except Exception as e:
        print(f"[*] response: {e} (a 404/500 is fine; the parser runs regardless)")
    print("[*] now run check_poison.py in the target container to confirm the")
    print("    session file was created and contains the canary, then run the rules.")


if __name__ == "__main__":
    main()
