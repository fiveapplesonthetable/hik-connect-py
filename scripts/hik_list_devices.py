#!/usr/bin/env python3
"""
hik_list_devices.py — after a successful hik_login_probe.py --real, list
the cameras on this Hik-Connect account and figure out what we can stream.

Uses the session JWT from logs/hik_login_real.json. Single device-list call,
single per-camera info call. No retries. No looping.

Output:
    logs/devices.json     — sanitized per-camera record
    logs/raw_devices.json — full raw response (for debugging)
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"

LOGIN_FILE = LOG_DIR / "hik_login_real.json"
if not LOGIN_FILE.exists():
    print("ERROR: no login session — run hik_login_probe.py --real first",
          file=sys.stderr)
    sys.exit(2)

login = json.loads(LOGIN_FILE.read_text())
session_id = login["json"]["loginSession"]["sessionId"]
api_domain = login["json"]["loginArea"]["apiDomain"]
BASE = f"https://{api_domain}"

HEADERS = {
    "clientType": "55",
    "lang": "en-US",
    "featureCode": "deadbeef",
    "sessionId": session_id,
    "User-Agent": "okhttp/4.9.1",
}


def get(path: str) -> dict:
    r = requests.get(f"{BASE}{path}", headers=HEADERS, timeout=15)
    r.raise_for_status()
    return r.json()


print(f"[list] base={BASE}")
print("[list] GET /v3/userdevices/v1/devices/pagelist …")
res = get("/v3/userdevices/v1/devices/pagelist?groupId=-1&limit=50&offset=0&"
          "filter=TIME_PLAN,CONNECTION,SWITCH,STATUS,STATUS_EXT,WIFI,NODISTURB,P2P,KMS,HIDDNS")
(LOG_DIR / "raw_devices.json").write_text(json.dumps(res, indent=2))

devices = res.get("deviceInfos", []) or []
connections = res.get("connectionInfos", {}) or {}
p2p_infos = res.get("p2pInfos", {}) or {}
status_infos = res.get("statusInfos", {}) or {}
kms = res.get("kmsInfos", {}) or {}
wifi = res.get("wifiInfos", {}) or {}

print(f"[list] {len(devices)} device(s)")

manifest: list[dict] = []
for d in devices:
    serial = d["deviceSerial"]
    name = d.get("name") or serial
    cap = connections.get(serial, {}) or {}
    p2p_list = p2p_infos.get(serial, []) or []
    st = status_infos.get(serial, {}) or {}
    ws = wifi.get(serial, {}) or {}
    km = kms.get(serial, {}) or {}

    entry = {
        "serial": serial,
        "name": name,
        "model": d.get("deviceType"),
        "device_category": d.get("deviceCategory"),
        "device_sub_category": d.get("deviceSubCategory"),
        "version": d.get("version"),
        "status": d.get("status"),
        "cas_ip": d.get("casIp"),
        "cas_port": d.get("casPort"),
        "channel_number": d.get("channelNumber"),
        "device_domain": d.get("deviceDomain"),
        "local_ip": cap.get("localIp"),
        "wan_ip": cap.get("netIp"),
        "wan_ip2": cap.get("wanIp"),
        "local_rtsp_port": cap.get("localRtspPort") or 554,
        "net_rtsp_port": cap.get("netRtspPort"),
        "local_cmd_port": cap.get("localCmdPort"),
        "net_cmd_port": cap.get("netCmdPort"),
        "local_stream_port": cap.get("localStreamPort"),
        "net_stream_port": cap.get("netStreamPort"),
        "net_http_port": cap.get("netHttpPort"),
        "upnp": cap.get("upnp"),
        "net_type": cap.get("netType"),
        "encrypted": bool(st.get("isEncrypt")),
        "encrypted_pwd_hash": st.get("encryptPwd"),
        "global_status": st.get("globalStatus"),
        "p2p_relays": [{"ip": x.get("ip"), "port": x.get("port")} for x in p2p_list],
        "wifi": {"ssid": ws.get("ssid"), "signal": ws.get("signal"),
                 "address": ws.get("address")},
        "kms_secret_key_present": bool(km.get("secretKey")),
        "kms_version": km.get("version"),
    }
    manifest.append(entry)
    print(f"  • {name} ({serial}) cat={entry['device_category']} "
          f"sub={entry['device_sub_category']} model={entry['model']} "
          f"channels={entry['channel_number']}")
    print(f"      LAN={entry['local_ip']}  WAN={entry['wan_ip']}/{entry['wan_ip2']}  "
          f"rtsp={entry['local_rtsp_port']}/{entry['net_rtsp_port']}  "
          f"cmd={entry['local_cmd_port']}/{entry['net_cmd_port']}  "
          f"stream={entry['local_stream_port']}/{entry['net_stream_port']}  "
          f"upnp={entry['upnp']}  encrypted={entry['encrypted']}")
    print(f"      CAS={entry['cas_ip']}:{entry['cas_port']}  status={entry['status']}  "
          f"global_status={entry['global_status']}")
    for relay in entry['p2p_relays']:
        print(f"      p2p relay: {relay['ip']}:{relay['port']}")

(LOG_DIR / "devices.json").write_text(json.dumps(manifest, indent=2))
print(f"[list] wrote {LOG_DIR / 'devices.json'}")
print(f"[list] wrote {LOG_DIR / 'raw_devices.json'} (raw)")
