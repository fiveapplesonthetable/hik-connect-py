#!/usr/bin/env python3
"""
hik_login_probe.py — direct Hik-Connect login via the same endpoint the
official Android app uses.

API surface (from the tomasbedrich/hikconnect library, which mirrors the
app):
    POST https://api.hik-connect.com/v3/users/login/v2
    headers: clientType=55, lang=en-US, featureCode=<any-hex>
    body:    account=<email>&password=<md5(password)>

Meta codes we handle:
    200   -> ok, response carries loginSession + loginArea
    1013  -> wrong username
    1014  -> wrong password
    1015  -> CAPTCHA required (login again from real app to clear it)
    1100  -> wrong region; response carries loginArea.apiDomain to retry on
    others -> printed verbatim

This script does NOT chase 1100 redirects with the real creds — it stops
after one hop to apply rate-limit hygiene. The redirect domain is just
written to logs/login_endpoint so a follow-up run can target it directly.

Modes:
    --probe   send fake creds to confirm the endpoint is reachable
              (cheap "negative" test that doesn't risk the real account)
    --real    one attempt with HIK_EMAIL / HIK_PASSWORD from secrets.env
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

DEFAULT_BASE = "https://api.hik-connect.com"
FEATURE_CODE = secrets.token_hex(8)  # any non-empty hex string works

HEADERS = {
    "clientType": "55",
    "lang": "en-US",
    "featureCode": FEATURE_CODE,
    "User-Agent": "okhttp/4.9.1",
}


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def attempt_login(base: str, email: str, password_md5: str,
                  timeout: float = 15.0) -> dict:
    url = f"{base}/v3/users/login/v2"
    data = {"account": email, "password": password_md5}
    t0 = time.monotonic()
    r = requests.post(url, headers=HEADERS, data=data, timeout=timeout)
    elapsed = time.monotonic() - t0
    out = {
        "url": url,
        "http_status": r.status_code,
        "elapsed_s": round(elapsed, 3),
        "headers": dict(r.headers),
    }
    try:
        out["json"] = r.json()
    except ValueError:
        out["text"] = r.text[:500]
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=("probe", "real"), required=True)
    p.add_argument("--email", help="override HIK_EMAIL for --real")
    args = p.parse_args()

    if args.mode == "probe":
        # Fake credentials. Random local part so we don't bonk a real
        # account by accident. you@example is the sandbox
        # gmail; using a known-bad-password locally — server only sees the
        # md5, no risk of disclosing anything.
        local = f"probe-{secrets.token_hex(4)}+fiveapplesonthetable"
        email = f"{local}@gmail.com"
        password_md5 = md5_hex(f"definitely-not-a-real-password-{secrets.token_hex(8)}")
        label = "PROBE"
    else:
        email = args.email or os.environ.get("HIK_EMAIL", "").strip()
        raw_password = os.environ.get("HIK_PASSWORD", "")
        if not email or not raw_password:
            print("ERROR: --real needs HIK_EMAIL + HIK_PASSWORD in env",
                  file=sys.stderr)
            return 2
        password_md5 = md5_hex(raw_password)
        label = "REAL"
        # Safety: scribble a marker so we never retry without explicit human
        # decision. If this file already exists from a prior run, refuse.
        marker = LOG_DIR / "real_attempt_used"
        if marker.exists():
            print(f"ERROR: {marker} exists — a real-account attempt already "
                  f"happened. Delete it manually if you want to try again.",
                  file=sys.stderr)
            return 3
        marker.write_text(f"{time.time()}\n")

    print(f"[{label}] POST → {DEFAULT_BASE}/v3/users/login/v2 "
          f"account={email[:3]}*** featureCode={FEATURE_CODE}")
    try:
        result = attempt_login(DEFAULT_BASE, email, password_md5)
    except requests.RequestException as e:
        print(f"[{label}] network error: {e}", file=sys.stderr)
        return 4

    out_file = LOG_DIR / f"hik_login_{label.lower()}.json"
    out_file.write_text(json.dumps(result, indent=2))

    j = result.get("json", {})
    meta = j.get("meta", {})
    code = meta.get("code")
    msg = meta.get("message")
    print(f"[{label}] http={result['http_status']} code={code} message={msg}")

    # Interpret
    if code == 200:
        try:
            session = j["loginSession"]["sessionId"]
            print(f"[{label}] SUCCESS — sessionId len={len(session)}")
        except KeyError:
            print(f"[{label}] code 200 but no sessionId: {j}")
    elif code == 1100:
        new_domain = (j.get("loginArea") or {}).get("apiDomain")
        print(f"[{label}] region redirect → https://{new_domain}")
        (LOG_DIR / "login_endpoint").write_text(f"https://{new_domain}\n")
    elif code in (1013, 1014):
        print(f"[{label}] account-not-found OR wrong-password — endpoint OK")
    elif code == 1015:
        print(f"[{label}] CAPTCHA — clear via real Hik-Connect app, then retry")
    else:
        print(f"[{label}] unhandled meta: {meta}")

    print(f"[{label}] full response → {out_file}")
    return 0 if code == 200 else (10 + (code or 99) % 90)


if __name__ == "__main__":
    sys.exit(main())
