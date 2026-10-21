#!/usr/bin/env python3
"""
check_poison.py — confirm the canary primitive worked, inside the target container.

Scans PHP's session save_path for sess_* files and reports which ones were
created cookie-lessly and which contain the inert canary / upload_progress_
marker. Read-only: it inspects files, runs nothing. This is the "proof" step —
if a session file appears with the canary in it, P1+P2 reproduced on this build.

Run inside the target container, e.g.:
    docker compose exec target python3 - < tests/check_poison.py
or copy it in and:  docker compose exec target python3 /tmp/check_poison.py
"""
import glob, os, subprocess, sys

def save_path():
    for p in ("/tmp", "/var/lib/php/sessions", "/var/lib/php"):
        if os.path.isdir(p) and glob.glob(os.path.join(p, "sess_*")):
            return p
    # ask PHP itself
    try:
        out = subprocess.run(["php", "-r", "echo ini_get('session.save_path');"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        return out or "/tmp"
    except Exception:
        return "/tmp"

def main():
    sp = save_path()
    files = sorted(glob.glob(os.path.join(sp, "sess_*")))
    print(f"[*] save_path: {sp}")
    print(f"[*] session files: {len(files)}")
    hits = 0
    for f in files:
        try:
            data = open(f, "rb").read()
        except Exception as e:
            print(f"    [skip] {f}: {e}"); continue
        has_up = b"upload_progress_" in data
        has_php = b"<?php" in data or b"<?=" in data
        has_canary = b"php2shell-lab inert canary" in data
        st = os.stat(f)
        flags = []
        if has_up: flags.append("upload_progress_")
        if has_php: flags.append("PHP-tag")
        if has_canary: flags.append("CANARY")
        if flags:
            hits += 1
            print(f"    [POISONED] {os.path.basename(f)} "
                  f"(mode {oct(st.st_mode)[-4:]}, {st.st_size}B): {', '.join(flags)}")
    print()
    if hits:
        print(f"[RESULT] {hits} poisoned session file(s) — primitives P1/P2 reproduced "
              f"on this PHP build. This is content injection, NOT code execution.")
        sys.exit(0)
    print("[RESULT] no poisoned session files found. With stock cleanup=1 the key is "
          "wiped at end of request — that is the mitigation working. Try pinning an "
          "affected build and/or inspect during an in-flight upload.")
    sys.exit(1)

if __name__ == "__main__":
    main()
