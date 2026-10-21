#!/usr/bin/env python3
"""
rules_selftest.py — offline, no network, no containers.

Mirrors the matching logic of the Suricata/YARA rules in ../rules and asserts it
against synthetic request bodies and session-file blobs: the arming/poison shapes
must match, benign traffic must NOT. This proves the rule logic is sound before
you run the live lab (which validates the real engines against real captures).

Run: python3 tests/rules_selftest.py
"""
import re, sys

# ---- mirrors of the rule conditions (kept deliberately simple/explicit) ----
def suri_arming(body: bytes) -> bool:
    return bool(b"multipart/form-data" in body.lower()
                and re.search(rb"(?i)PHP_SESSION_UPLOAD_PROGRESS", body)
                and re.search(rb"(?i)PHPSESSID", body))

def suri_content_injection(body: bytes) -> bool:
    return bool(re.search(rb"(?i)(PHP_SESSION_UPLOAD_PROGRESS|upload_progress_)", body)
                and re.search(rb"(?i)<\?(php|=)", body))

def suri_filename_phptag(body: bytes) -> bool:
    return bool(re.search(rb'(?i)filename="[^"]*<\?(php|=)', body))

def yara_session_poison(blob: bytes) -> bool:
    marker = b"upload_progress_" in blob
    chain = bool(re.search(rb"(?i)upload_progress_[^\x00|]{0,256}<\?", blob))
    ser = bool(re.search(rb"[A-Za-z0-9_]{1,64}\|(a:\d+:\{|s:\d+:|i:\d+;|O:\d+:)", blob))
    php = (b"<?php" in blob.lower()) or (b"<?=" in blob)
    return marker and (chain or (ser and php))

def yara_write_denial(blob: bytes) -> bool:
    return bool(re.search(rb"upload_progress_[^\x00]{0,128}\|", blob))

# ---------------------------- fixtures ----------------------------
B = "----b"
def mp(*parts):
    s = f"Content-Type: multipart/form-data; boundary={B}\r\n\r\n".encode()
    for disp, val in parts:
        s += f"--{B}\r\nContent-Disposition: form-data; {disp}\r\n\r\n".encode() + val + b"\r\n"
    return s + f"--{B}--\r\n".encode()

CANARY = b"<?php /* php2shell-lab inert canary deadbeef - NOT a shell */ ?>"

arming_body   = b"POST /index.php HTTP/1.1\r\n" + mp(('name="PHPSESSID"', b"labcanary1234"),
                                                     ('name="PHP_SESSION_UPLOAD_PROGRESS"', CANARY))
inject_body   = b"POST /index.php HTTP/1.1\r\n" + mp(('name="PHP_SESSION_UPLOAD_PROGRESS"', CANARY),
                                                     ('name="file1"; filename="ok.txt"', b"data"))
filename_body = b"POST /index.php HTTP/1.1\r\n" + mp(('name="PHPSESSID"', b"x"),
                                                     (f'name="f"; filename="{CANARY.decode()}"'.encode(), b"d"))
benign_upload = b"POST /upload.php HTTP/1.1\r\n" + mp(('name="PHP_SESSION_UPLOAD_PROGRESS"', b"myupload"),
                                                     ('name="file1"; filename="doc.pdf"', b"%PDF-1.7 ...."))
benign_login  = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&pass=b"

poisoned_sess = b"upload_progress_" + CANARY + b"|a:2:{s:4:\"name\";s:3:\"x.p\";s:5:\"bytes\";i:10;}"
denial_sess   = b"upload_progress_a|b|a:0:{}"
benign_sess   = b"user|s:5:\"admin\";role|s:5:\"guest\";csrf|s:16:\"0123456789abcdef\";"

CASES = [
    # (name, fn, input, expected)
    ("arming matches",              suri_arming,            arming_body,   True),
    ("arming ignores benign login", suri_arming,            benign_login,  False),
    ("arming ignores benign upload (no sid)", suri_arming,  benign_upload, False),
    ("content-injection matches",   suri_content_injection, inject_body,   True),
    ("content-injection skips benign upload", suri_content_injection, benign_upload, False),
    ("filename php-tag matches",    suri_filename_phptag,   filename_body, True),
    ("filename php-tag skips benign", suri_filename_phptag, benign_upload, False),
    ("yara poison matches",         yara_session_poison,    poisoned_sess, True),
    ("yara poison skips benign sess", yara_session_poison,  benign_sess,   False),
    ("yara write-denial matches",   yara_write_denial,      denial_sess,   True),
    ("yara write-denial skips benign sess", yara_write_denial, benign_sess, False),
]

def main():
    bad = 0
    for name, fn, inp, want in CASES:
        got = bool(fn(inp))
        ok = got == want
        bad += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  (got={got}, want={want})")
    print()
    if bad:
        print(f"[RESULT] {bad} case(s) FAILED")
        sys.exit(1)
    print(f"[RESULT] all {len(CASES)} cases passed — rule logic distinguishes "
          f"attack shapes from benign traffic.")

if __name__ == "__main__":
    main()
