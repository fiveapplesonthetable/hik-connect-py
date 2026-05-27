#!/usr/bin/env python3
"""
hik.py — Hik-Connect cloud camera streaming, pure Python.

Sub-commands:

    login     Login with email + password, cache the session
    list      List cameras (channels) for the account
    stream    Capture one channel's live stream to a file or stdout
    ffmpeg    Pipe one channel's live stream into a user-supplied ffmpeg command
    refresh   Force a fresh session token (auto-runs when needed)

Reverse-engineered from the official Android app's wire bytes
(2026-05-27 capture against a real DVR). The protocol:

    POST /v3/users/login/v2          → sessionId + loginArea.apiDomain
    GET  /v3/userdevices/v1/devices/pagelist (filter=CONNECTION,KMS_INFO)
    POST /api/user/token/get         → short-lived "ut.XXX" tokens (use exactly 1
                                       per stream attempt; refill every ~5 mins)
    GET  /v3/streaming/vtm/{serial}/{channel}  → per-channel VTM host:port

    TCP to VTM:
      packet: 1 magic 0x24 | 1 channel=0 | 2 length BE | 2 seq BE | 2 mcode BE
      step 1 (seq=1, mcode=0x13B): protobuf with
          field 1 streamurl = ysproto://<host>:<port>/live?
                              dev=<serial>&chn=N&stream=1&cln=55&isp=0&auth=1
                              &ssn=ut.XXX&lid=<uuid>&biz=1
          field 3,6 useragent = "v3.2.6.20200311"
          field 4 proxytype = 0
          field 5 pdsstring = empty
        → mcode=0x13C, result=5302, vtmstreamkey, redirect URL

      step 2 (seq=2, same socket... actually new TCP to redirect host:port):
          field 1 streamurl = redirect_url + "&timestamp=<epoch_ms>"
          field 2 vtmstreamkey = the 30-hex returned in step 1
          rest same
        → result=0, datakey, streamssn, streamhead (base64 IMKH header)

      then the same socket pushes channel=1 frames with mcode=0x9e03/0xdc5e
      until the server kills it (~75s without keepalive).

      Frames carry a Hikvision custom outer envelope, then MPEG-PS/H.264.

Usage examples:

    python3 scripts/hik.py login --email a@b.com --password 'secret'
    python3 scripts/hik.py list
    python3 scripts/hik.py stream --channel 1 --duration 30 --out cam1.bin
    python3 scripts/hik.py stream --channel 1 --duration 30 --out -  |
        ffmpeg -f data -i - -c copy out.mp4
    python3 scripts/hik.py ffmpeg --channel 1 -- \
        -f data -i pipe:0 -c copy out.mp4
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

import requests

# ---------- Paths ----------

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / "logs"
STATE_DIR.mkdir(parents=True, exist_ok=True)
SESSION_PATH = STATE_DIR / "hik_session.json"
DEVICES_PATH = STATE_DIR / "hik_devices.json"

# ---------- Constants ----------

UA = "v3.2.6.20200311"        # streamclient SDK version embedded in the Android app
CLN_TYPE = 55                  # Android client type (from wire capture)
FEATURE_CODE = "deadbeef"      # any 8-hex string works
CLIENT_TYPE = "55"

VTM_MAGIC = 0x24
CH_MESSAGE = 0x00
CH_STREAM = 0x01
MCODE_STREAMINFO_REQ = 0x13B
MCODE_STREAMINFO_RSP = 0x13C

# ---------- Tiny proto encoder ----------

def _varint(value: int) -> bytes:
    out = bytearray()
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _proto_string(field: int, value: str) -> bytes:
    return _proto_bytes(field, value.encode("utf-8"))


def _proto_bytes(field: int, value: bytes) -> bytes:
    tag = (field << 3) | 2
    return _varint(tag) + _varint(len(value)) + value


def _proto_varint(field: int, value: int) -> bytes:
    tag = (field << 3) | 0
    return _varint(tag) + _varint(value)


# ---------- Tiny proto decoder ----------

@dataclass
class StreamInfoRsp:
    result: int | None = None
    datakey: int | None = None
    streamhead: bytes | None = None
    streamssn: str | None = None
    vtmstreamkey: str | None = None
    serverinfo: str | None = None
    streamurl: str | None = None


def _parse_stream_info_rsp(data: bytes) -> StreamInfoRsp:
    r = StreamInfoRsp()
    i = 0
    while i < len(data):
        tag, i = _read_varint(data, i)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            v, i = _read_varint(data, i)
            if field == 1:
                r.result = v
            elif field == 2:
                r.datakey = v
        elif wire == 2:
            ln, i = _read_varint(data, i)
            v = data[i:i + ln]
            i += ln
            if field == 3:
                r.streamhead = v
            elif field == 4:
                with suppress(UnicodeDecodeError):
                    r.streamssn = v.decode("utf-8")
            elif field == 5:
                with suppress(UnicodeDecodeError):
                    r.vtmstreamkey = v.decode("utf-8")
            elif field == 6:
                with suppress(UnicodeDecodeError):
                    r.serverinfo = v.decode("utf-8")
            elif field == 7:
                with suppress(UnicodeDecodeError):
                    r.streamurl = v.decode("utf-8")
    return r


def _read_varint(data: bytes, i: int) -> tuple[int, int]:
    v = 0
    shift = 0
    while True:
        b = data[i]
        i += 1
        v |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            return v, i
        shift += 7


# ---------- VTM TCP framing ----------

def vtm_encode(body: bytes, *, channel: int, mcode: int, seq: int) -> bytes:
    return struct.pack(">BBHHH", VTM_MAGIC, channel & 0xff,
                       len(body) & 0xffff, seq & 0xffff,
                       mcode & 0xffff) + body


@dataclass
class VtmHeader:
    channel: int
    length: int
    sequence: int
    mcode: int


def vtm_decode_header(h: bytes) -> VtmHeader:
    if len(h) != 8 or h[0] != VTM_MAGIC:
        raise IOError(f"bad VTM header: {h.hex() if h else 'empty'}")
    return VtmHeader(
        channel=h[1],
        length=(h[2] << 8) | h[3],
        sequence=(h[4] << 8) | h[5],
        mcode=(h[6] << 8) | h[7],
    )


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError("peer closed mid-packet")
        out += chunk
    return out


def recv_packet(sock: socket.socket) -> tuple[VtmHeader, bytes] | None:
    try:
        head = recv_exact(sock, 8)
    except ConnectionError:
        return None
    hdr = vtm_decode_header(head)
    body = recv_exact(sock, hdr.length) if hdr.length else b""
    return hdr, body


# ---------- REST API ----------

class HikSession:
    """Hik-Connect REST session — persistent across runs via logs/hik_session.json."""

    def __init__(self, session_id: str, api_domain: str, username: str,
                 feature_code: str = FEATURE_CODE):
        self.session_id = session_id
        self.api_domain = api_domain
        self.username = username
        self.feature_code = feature_code

    @property
    def base(self) -> str:
        return f"https://{self.api_domain}"

    @property
    def _headers(self) -> dict:
        return {
            "clientType": CLIENT_TYPE,
            "lang": "en-US",
            "featureCode": self.feature_code,
            "sessionId": self.session_id,
            "User-Agent": "okhttp/4.9.1",
        }

    # --- factories ---

    @classmethod
    def login(cls, email: str, password: str, *,
              feature_code: str = FEATURE_CODE) -> "HikSession":
        # Hik-Connect accepts both plain and md5'd password depending on
        # account region. The original tomasbedrich/hikconnect repo MD5's it;
        # our captured Android app sends it plain via HTTPS. Try MD5 first
        # (matches official server's "hashed password" mode for new accounts).
        password_md5 = hashlib.md5(password.encode("utf-8"),
                                   usedforsecurity=False).hexdigest()
        body = {
            "account": email,
            "password": password_md5,
            "areaId": "0",
            "featureCode": feature_code,
        }
        r = requests.post(
            "https://api.hik-connect.com/v3/users/login/v2",
            headers={"clientType": CLIENT_TYPE, "lang": "en-US",
                     "featureCode": feature_code, "User-Agent": "okhttp/4.9.1"},
            data=body, timeout=15,
        )
        j = r.json()
        meta = j.get("meta", {})
        if meta.get("code") != 200:
            raise RuntimeError(f"login failed: {meta}")
        sess = j["loginSession"]
        area = j["loginArea"]
        user = j["loginUser"]
        return cls(session_id=sess["sessionId"],
                   api_domain=area["apiDomain"],
                   username=user["username"],
                   feature_code=feature_code)

    @classmethod
    def load(cls) -> "HikSession | None":
        if not SESSION_PATH.exists():
            return None
        j = json.loads(SESSION_PATH.read_text())
        return cls(session_id=j["sessionId"],
                   api_domain=j["apiDomain"],
                   username=j["username"],
                   feature_code=j.get("featureCode", FEATURE_CODE))

    def save(self) -> None:
        SESSION_PATH.write_text(json.dumps({
            "sessionId": self.session_id,
            "apiDomain": self.api_domain,
            "username": self.username,
            "featureCode": self.feature_code,
        }, indent=2))

    # --- REST calls ---

    def devices(self) -> dict:
        r = requests.get(
            f"{self.base}/v3/userdevices/v1/devices/pagelist",
            headers=self._headers,
            params={"filter": "CONNECTION,KMS_INFO,P2P_INFO,CAMERA",
                    "groupId": "-1", "limit": 30, "offset": 0},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def token_batch(self, count: int = 10) -> list[str]:
        """Get N short-lived stream tokens. The SDK pre-fetches in batches of
        50; refill when fewer than ~10 remain or after >5 minutes."""
        r = requests.post(
            f"{self.base}/api/user/token/get",
            headers=self._headers,
            data={"featureCode": self.feature_code, "count": count},
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("tokenArray", [])

    def vtm(self, serial: str, channel: int) -> dict:
        r = requests.get(
            f"{self.base}/v3/streaming/vtm/{serial}/{channel}",
            headers=self._headers, timeout=15,
        )
        r.raise_for_status()
        return r.json()["streamServerConfig"]


# ---------- VTM stream client ----------

@dataclass
class StreamHandle:
    socket: socket.socket
    datakey: int
    streamssn: str | None
    streamhead: bytes | None
    serverinfo: str | None


def stream_connect(sess: HikSession, serial: str, channel: int,
                   *, vtm_info: dict | None = None,
                   token: str | None = None,
                   timeout: float = 10.0) -> StreamHandle:
    """Run step 1 + step 2; return a StreamHandle whose socket is ready to read
    media packets."""

    if vtm_info is None:
        vtm_info = sess.vtm(serial, channel)
    host, port = vtm_info["externalIp"], int(vtm_info["port"])
    if token is None:
        toks = sess.token_batch(count=5)
        if not toks:
            raise RuntimeError("token_batch returned 0 tokens")
        token = toks[0]
    lid = str(uuid.uuid4())

    def build_body(url: str, vtmkey: str = "") -> bytes:
        parts = [_proto_string(1, url)]
        if vtmkey:
            parts.append(_proto_string(2, vtmkey))
        parts.extend([_proto_string(3, UA), _proto_varint(4, 0),
                      _proto_string(5, ""), _proto_string(6, UA)])
        return b"".join(parts)

    # Step 1 — connect to per-channel VTM
    url1 = (f"ysproto://{host}:{port}/live?dev={serial}&chn={channel}"
            f"&stream=1&cln={CLN_TYPE}&isp=0&auth=1&ssn={token}"
            f"&lid={lid}&biz=1")
    s1 = socket.create_connection((host, port), timeout=timeout)
    s1.settimeout(timeout)
    s1.sendall(vtm_encode(build_body(url1),
                          channel=CH_MESSAGE,
                          mcode=MCODE_STREAMINFO_REQ, seq=1))
    pkt = recv_packet(s1)
    s1.close()
    if pkt is None or pkt[0].mcode != MCODE_STREAMINFO_RSP:
        raise RuntimeError("step 1: no STREAMINFO_RSP")
    info1 = _parse_stream_info_rsp(pkt[1])
    if info1.result != 5302:
        raise RuntimeError(f"step 1: unexpected result {info1.result}")

    # Step 2 — TCP to the redirect host:port, append &timestamp=, keep socket open
    p = urlparse(info1.streamurl)
    url2 = info1.streamurl + f"&timestamp={int(time.time()*1000)}"
    s2 = socket.create_connection((p.hostname, p.port), timeout=timeout)
    s2.settimeout(timeout)
    s2.sendall(vtm_encode(build_body(url2, info1.vtmstreamkey),
                          channel=CH_MESSAGE,
                          mcode=MCODE_STREAMINFO_REQ, seq=2))
    pkt = recv_packet(s2)
    if pkt is None or pkt[0].mcode != MCODE_STREAMINFO_RSP:
        s2.close()
        raise RuntimeError("step 2: no STREAMINFO_RSP")
    info2 = _parse_stream_info_rsp(pkt[1])
    if info2.result != 0:
        s2.close()
        raise RuntimeError(f"step 2: unexpected result {info2.result}")

    return StreamHandle(socket=s2,
                        datakey=info2.datakey or 0,
                        streamssn=info2.streamssn,
                        streamhead=info2.streamhead,
                        serverinfo=info2.serverinfo)


def stream_drain(handle: StreamHandle, *,
                 duration: float | None = None,
                 max_bytes: int | None = None,
                 idle_timeout: float = 8.0) -> Iterator[tuple[VtmHeader, bytes]]:
    """Yield (header, body) for each media packet from the server until
    `duration` seconds elapse, `max_bytes` total received, or the server
    closes the connection (~75 s without keepalive)."""

    deadline = time.time() + duration if duration else float("inf")
    handle.socket.settimeout(idle_timeout)
    total = 0
    while time.time() < deadline:
        try:
            pkt = recv_packet(handle.socket)
        except (socket.timeout, TimeoutError):
            return
        if pkt is None:
            return
        h, body = pkt
        total += len(body)
        yield h, body
        if max_bytes is not None and total >= max_bytes:
            return


# ---------- RTP demuxer (RFC 3550 + 6184 for H.264) ----------

@dataclass
class RtpFrame:
    payload_type: int
    sequence: int
    timestamp: int
    marker: bool
    payload: bytes


def parse_rtp(body: bytes) -> RtpFrame | None:
    """Parse one RTP packet body from a VTM STREAM channel packet.

    The Hikvision VTM uses standard RTP with a fixed SSRC = 0x55667788.
    """
    if len(body) < 12:
        return None
    v_p_x_cc = body[0]
    m_pt = body[1]
    if (v_p_x_cc >> 6) != 2:
        return None  # not RTP v2
    cc = v_p_x_cc & 0x0F
    pt = m_pt & 0x7F
    marker = bool(m_pt & 0x80)
    seq = (body[2] << 8) | body[3]
    ts = struct.unpack(">I", body[4:8])[0]
    # bytes 8-11 are SSRC; bytes 12..12+4*cc are CSRC list
    payload_start = 12 + 4 * cc
    # extension header (X bit)
    if v_p_x_cc & 0x10 and len(body) >= payload_start + 4:
        ext_len_words = (body[payload_start + 2] << 8) | body[payload_start + 3]
        payload_start += 4 + 4 * ext_len_words
    return RtpFrame(payload_type=pt, sequence=seq, timestamp=ts,
                    marker=marker, payload=body[payload_start:])


_ANNEX_B_START = b"\x00\x00\x00\x01"


def h264_depacketize(rtp_packets: Iterator[RtpFrame]) -> Iterator[bytes]:
    """Convert a stream of RFC 6184 H.264 RTP frames into Annex-B NAL units.

    Yields one bytes object per complete NAL unit, including the
    4-byte start code prefix.
    """
    fu_buf: bytes | None = None
    fu_nal_header: int = 0
    for rtp in rtp_packets:
        if not rtp.payload:
            continue
        nal_hdr = rtp.payload[0]
        nal_type = nal_hdr & 0x1F
        if 1 <= nal_type <= 23:
            # Single NAL unit
            yield _ANNEX_B_START + rtp.payload
        elif nal_type == 24:
            # STAP-A: aggregated NALs
            data = rtp.payload[1:]
            while len(data) >= 2:
                ln = (data[0] << 8) | data[1]
                if len(data) < 2 + ln:
                    break
                yield _ANNEX_B_START + data[2:2 + ln]
                data = data[2 + ln:]
        elif nal_type == 28:
            # FU-A
            if len(rtp.payload) < 2:
                continue
            fu_hdr = rtp.payload[1]
            start = bool(fu_hdr & 0x80)
            end = bool(fu_hdr & 0x40)
            orig_nal_type = fu_hdr & 0x1F
            if start:
                fu_nal_header = (nal_hdr & 0xE0) | orig_nal_type
                fu_buf = bytes([fu_nal_header]) + rtp.payload[2:]
            elif fu_buf is not None:
                fu_buf += rtp.payload[2:]
            if end and fu_buf is not None:
                yield _ANNEX_B_START + fu_buf
                fu_buf = None


# ---------- High-level: capture H.264 to file or ffmpeg ----------

def stream_h264(sess: HikSession, serial: str, channel: int, *,
                duration: float = 15.0, video_pt: int = 96) -> Iterator[bytes]:
    """Connect, drain the VTM stream, yield Annex-B H.264 NALs.

    By default uses RTP payload type 96 (which is what every Hikvision DVR
    we've seen uses for H.264 video). Audio (PT=0 / PCMU) is dropped.
    """
    handle = stream_connect(sess, serial, channel)

    def rtp_iter() -> Iterator[RtpFrame]:
        for _, body in stream_drain(handle, duration=duration):
            f = parse_rtp(body)
            if f is None or f.payload_type != video_pt:
                continue
            yield f
    try:
        yield from h264_depacketize(rtp_iter())
    finally:
        with suppress(Exception):
            handle.socket.close()


def stream_av(sess: HikSession, serial: str, channel: int, *,
              duration: float = 15.0,
              video_pt: int = 96, audio_pt: int = 0
              ) -> Iterator[tuple[str, bytes]]:
    """Drain the VTM stream, yielding ('v', annex_b_nal) for video and
    ('a', pcmu_bytes) for audio. The PCMU (G.711 µ-law) audio runs at
    8000 Hz mono 8-bit and the RTP payload is the raw samples (no
    fragmentation needed; one packet = one chunk).
    """
    handle = stream_connect(sess, serial, channel)
    try:
        # Internal state for video depacketization (we have to fuse into one
        # iterator because we don't want to pre-buffer 30s of packets).
        fu_buf: bytes | None = None
        fu_nal_header: int = 0
        for _, body in stream_drain(handle, duration=duration):
            f = parse_rtp(body)
            if f is None:
                continue
            if f.payload_type == audio_pt and f.payload:
                yield ("a", f.payload)
                continue
            if f.payload_type != video_pt or not f.payload:
                continue
            nal_hdr = f.payload[0]
            nal_type = nal_hdr & 0x1F
            if 1 <= nal_type <= 23:
                yield ("v", _ANNEX_B_START + f.payload)
            elif nal_type == 24:
                data = f.payload[1:]
                while len(data) >= 2:
                    ln = (data[0] << 8) | data[1]
                    if len(data) < 2 + ln:
                        break
                    yield ("v", _ANNEX_B_START + data[2:2 + ln])
                    data = data[2 + ln:]
            elif nal_type == 28:
                if len(f.payload) < 2:
                    continue
                fu_hdr = f.payload[1]
                start = bool(fu_hdr & 0x80)
                end = bool(fu_hdr & 0x40)
                orig_nal_type = fu_hdr & 0x1F
                if start:
                    fu_nal_header = (nal_hdr & 0xE0) | orig_nal_type
                    fu_buf = bytes([fu_nal_header]) + f.payload[2:]
                elif fu_buf is not None:
                    fu_buf += f.payload[2:]
                if end and fu_buf is not None:
                    yield ("v", _ANNEX_B_START + fu_buf)
                    fu_buf = None
    finally:
        with suppress(Exception):
            handle.socket.close()


# ---------- CLI ----------

def cmd_login(args) -> int:
    print(f"[*] logging in as {args.email}…")
    sess = HikSession.login(args.email, args.password)
    sess.save()
    print(f"[OK] session saved → {SESSION_PATH}")
    print(f"     username={sess.username}  apiDomain={sess.api_domain}")
    return 0


def cmd_list(args) -> int:
    sess = HikSession.load()
    if sess is None:
        raise SystemExit("no session — run `hik.py login` first")
    j = sess.devices()
    DEVICES_PATH.write_text(json.dumps(j, indent=2))
    infos = j.get("deviceInfos", [])
    if not infos:
        print("[!] no devices found")
        return 1
    print(f"[*] {len(infos)} device(s):")
    for d in infos:
        ser = d.get("deviceSerial")
        name = d.get("name")
        chans = d.get("channelNumber", 1)
        cat = d.get("deviceCategory", "?")
        model = d.get("version", "?")
        print(f"  • {ser}  {name!r}  cat={cat}  chans={chans}  fw={model}")
    return 0


def cmd_stream(args) -> int:
    sess = HikSession.load()
    if sess is None:
        raise SystemExit("no session — run `hik.py login` first")

    serial = args.serial or _first_serial(sess)

    out: object
    if args.out == "-":
        out = sys.stdout.buffer
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out = open(out_path, "wb")

    fmt = args.format
    print(f"[*] streaming {serial}/{args.channel} for up to {args.duration}s "
          f"(format={fmt})", file=sys.stderr)

    if fmt == "raw":
        # Raw VTM packet bodies (RTP-framed; you parse them yourself)
        handle = stream_connect(sess, serial, args.channel)
        print(f"[*] step 2 ok: datakey={handle.datakey} "
              f"streamhead={len(handle.streamhead or b'')}B",
              file=sys.stderr)
        if handle.streamhead and args.include_streamhead:
            out.write(handle.streamhead)
        n_pkts = 0; n_bytes = 0; start = time.time()
        for hdr, body in stream_drain(handle, duration=args.duration,
                                      max_bytes=args.max_bytes):
            out.write(body)
            n_pkts += 1; n_bytes += len(body)
            if args.verbose and n_pkts <= 5:
                print(f"  pkt {n_pkts}: ch=0x{hdr.channel:02x} "
                      f"mc=0x{hdr.mcode:04x} len={hdr.length}",
                      file=sys.stderr)
        handle.socket.close()
        elapsed = time.time() - start
        print(f"[OK] {n_pkts} pkts, {n_bytes/1024:.1f} KiB in {elapsed:.1f}s "
              f"({n_bytes*8/elapsed/1024:.1f} kbit/s)", file=sys.stderr)
    else:  # fmt == "h264"
        n_nals = 0; n_bytes = 0; start = time.time()
        for nal in stream_h264(sess, serial, args.channel,
                               duration=args.duration):
            out.write(nal)
            n_nals += 1; n_bytes += len(nal)
            if args.verbose and n_nals <= 6:
                nal_type = nal[4] & 0x1F if len(nal) > 4 else 0
                print(f"  NAL {n_nals}: type={nal_type} len={len(nal)}",
                      file=sys.stderr)
        elapsed = time.time() - start
        print(f"[OK] {n_nals} NALs, {n_bytes/1024:.1f} KiB in {elapsed:.1f}s "
              f"({n_bytes*8/elapsed/1024:.1f} kbit/s)", file=sys.stderr)

    if out is not sys.stdout.buffer:
        out.close()
    return 0


def cmd_ffmpeg(args) -> int:
    sess = HikSession.load()
    if sess is None:
        raise SystemExit("no session — run `hik.py login` first")
    if not shutil.which("ffmpeg"):
        raise SystemExit("ffmpeg binary not on PATH")
    serial = args.serial or _first_serial(sess)

    # Custom ffmpeg args path (video-only via stdin) — power-user escape hatch
    if args.ffmpeg_args:
        ff_args = list(args.ffmpeg_args)
        print(f"[*] {serial}/{args.channel} → ffmpeg {' '.join(ff_args)}",
              file=sys.stderr)
        proc = subprocess.Popen(["ffmpeg"] + ff_args, stdin=subprocess.PIPE)
        try:
            for nal in stream_h264(sess, serial, args.channel,
                                   duration=args.duration):
                proc.stdin.write(nal)
        finally:
            with suppress(Exception):
                proc.stdin.close()
        return proc.wait()

    if args.out is None and args.hls_dir is None:
        raise SystemExit("either --out OUTPUT, --hls-dir DIR, or "
                         "`-- <ffmpeg args>` required")
    if not args.audio and not args.video:
        raise SystemExit("nothing to mux — both --no-audio and --no-video?")

    # Build ffmpeg command depending on which streams are requested.
    v_r = v_w = a_r = a_w = -1
    pass_fds: list[int] = []
    inputs: list[str] = []
    maps: list[str] = []
    codecs: list[str] = []

    if args.video:
        v_r, v_w = os.pipe()
        pass_fds.append(v_r)
        inputs += ["-thread_queue_size", "512",
                   "-f", "h264", "-r", "25", "-i", f"pipe:{v_r}"]
    if args.audio:
        a_r, a_w = os.pipe()
        pass_fds.append(a_r)
        inputs += ["-thread_queue_size", "512",
                   "-f", "mulaw", "-ar", "8000", "-ac", "1", "-i", f"pipe:{a_r}"]

    if args.video and args.audio:
        maps = ["-map", "0:v:0", "-map", "1:a:0"]
        codecs = ["-c:v", "copy",
                  "-ar", "16000", "-c:a", "aac", "-b:a", "48k"]
    elif args.video:
        maps = ["-map", "0:v:0"]
        codecs = ["-c:v", "copy"]
    else:  # audio only
        maps = ["-map", "0:a:0"]
        codecs = ["-ar", "16000", "-c:a", "aac", "-b:a", "48k"]

    if args.hls_dir:
        out_dir = Path(args.hls_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in list(out_dir.glob("*.ts")) + list(out_dir.glob("*.m3u8")):
            f.unlink(missing_ok=True)
        ff_out = [
            "-f", "hls",
            "-hls_time", "2",
            "-hls_list_size", "6",
            "-hls_flags", "delete_segments+independent_segments+omit_endlist",
            "-hls_segment_filename", str(out_dir / "seg_%05d.ts"),
            "-y", str(out_dir / "index.m3u8"),
        ]
    else:
        ff_out = ["-y", args.out]

    ff_cmd = (["ffmpeg", "-loglevel", "warning",
               "-fflags", "+genpts+nobuffer"]
              + inputs + maps + codecs + ff_out)

    label = "+".join(x for x, on in (("video", args.video), ("audio", args.audio)) if on)
    target = args.hls_dir or args.out
    print(f"[*] {serial}/{args.channel} ({label}) → {target}",
          file=sys.stderr)
    proc = subprocess.Popen(ff_cmd, pass_fds=pass_fds, start_new_session=True)
    for fd in pass_fds:
        os.close(fd)

    n_v = 0; n_a = 0; v_bytes = 0; a_bytes = 0
    try:
        for kind, data in stream_av(sess, serial, args.channel,
                                    duration=args.duration):
            if kind == "v" and args.video:
                with suppress(BrokenPipeError):
                    os.write(v_w, data)
                n_v += 1; v_bytes += len(data)
            elif kind == "a" and args.audio:
                with suppress(BrokenPipeError):
                    os.write(a_w, data)
                n_a += 1; a_bytes += len(data)
    finally:
        for fd in (v_w, a_w):
            if fd > 0:
                with suppress(OSError):
                    os.close(fd)
    rc = proc.wait()
    print(f"[OK] video={n_v} NALs/{v_bytes/1024:.1f} KiB  "
          f"audio={n_a} pkts/{a_bytes/1024:.1f} KiB  ffmpeg={rc}",
          file=sys.stderr)
    return rc


def cmd_probe(args) -> int:
    """Probe every channel up to N to find which ones have a live camera."""
    sess = HikSession.load()
    if sess is None:
        raise SystemExit("no session — run `hik.py login` first")
    serial = args.serial or _first_serial(sess)
    j = json.loads(DEVICES_PATH.read_text()) if DEVICES_PATH.exists() \
        else sess.devices()
    nchan = 1
    for d in j.get("deviceInfos", []):
        if d.get("deviceSerial") == serial:
            nchan = int(d.get("channelNumber", 1))
            break
    print(f"[*] probing {serial} channels 1..{nchan} (3s each)…", file=sys.stderr)
    alive = []
    for ch in range(1, nchan + 1):
        try:
            handle = stream_connect(sess, serial, ch, timeout=6.0)
        except Exception as e:
            print(f"  ch{ch:02d}: SETUP FAIL ({e!s:.60})", file=sys.stderr)
            continue
        # try receiving one packet — if we get bytes within 3s, channel is live
        handle.socket.settimeout(3.0)
        live = False
        try:
            pkt = recv_packet(handle.socket)
            if pkt is not None:
                live = True
        except (socket.timeout, TimeoutError):
            pass
        handle.socket.close()
        print(f"  ch{ch:02d}: {'LIVE' if live else 'silent'}", file=sys.stderr)
        if live:
            alive.append(ch)
    print(f"\n[OK] live channels on {serial}: {alive}")
    return 0


def cmd_refresh(args) -> int:
    sess = HikSession.load()
    if sess is None:
        raise SystemExit("no session — run `hik.py login` first")
    devs = sess.devices()
    print(f"[OK] session alive — username={sess.username} "
          f"devices={len(devs.get('deviceInfos', []))}")
    return 0


def _first_serial(sess: HikSession) -> str:
    j = json.loads(DEVICES_PATH.read_text()) if DEVICES_PATH.exists() \
        else sess.devices()
    if not j.get("deviceInfos"):
        raise SystemExit("no devices found")
    return j["deviceInfos"][0]["deviceSerial"]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("login", help="log in and cache session")
    pl.add_argument("--email", required=True)
    pl.add_argument("--password", required=True)
    pl.set_defaults(func=cmd_login)

    pls = sub.add_parser("list", help="list cameras")
    pls.set_defaults(func=cmd_list)

    ps = sub.add_parser("stream", help="capture stream to a file or stdout")
    ps.add_argument("--serial")
    ps.add_argument("--channel", type=int, default=1)
    ps.add_argument("--duration", type=float, default=15)
    ps.add_argument("--out", required=True,
                    help='output path, or "-" for stdout')
    ps.add_argument("--format", choices=("h264", "raw"), default="h264",
                    help="h264: Annex-B NAL bytes (default; pipe into ffmpeg). "
                         "raw: VTM body bytes (still RTP-framed; for analysis)")
    ps.add_argument("--max-bytes", type=int)
    ps.add_argument("--include-streamhead", action="store_true",
                    help="(raw only) include the base64-encoded IMKH init "
                         "header in output")
    ps.add_argument("-v", "--verbose", action="store_true")
    ps.set_defaults(func=cmd_stream)

    pf = sub.add_parser("ffmpeg",
                        help="pipe H.264 NALs into ffmpeg (default: write MP4)")
    pf.add_argument("--serial")
    pf.add_argument("--channel", type=int, default=1)
    pf.add_argument("--duration", type=float, default=15)
    pf.add_argument("--out",
                    help="output file (mp4/mkv/...) — A/V muxed.")
    pf.add_argument("--hls-dir",
                    help="output as HLS segments (index.m3u8 + seg_*.ts) "
                         "with A/V interleaved. Use for live web playback.")
    pf.add_argument("--no-audio", dest="audio", action="store_false",
                    help="skip audio (default: include both)")
    pf.add_argument("--no-video", dest="video", action="store_false",
                    help="skip video")
    pf.set_defaults(audio=True, video=True)
    pf.add_argument("ffmpeg_args", nargs=argparse.REMAINDER,
                    help='custom ffmpeg arguments after "--" (e.g. -f h264 '
                         '-i pipe:0 -c:v libx265 out.mkv)')
    pf.set_defaults(func=cmd_ffmpeg)

    pp = sub.add_parser("probe", help="find which channels have a live camera")
    pp.add_argument("--serial")
    pp.set_defaults(func=cmd_probe)

    pr = sub.add_parser("refresh", help="check if cached session is still valid")
    pr.set_defaults(func=cmd_refresh)

    args = p.parse_args()
    # strip leading "--" from ffmpeg_args
    if hasattr(args, "ffmpeg_args") and args.ffmpeg_args and args.ffmpeg_args[0] == "--":
        args.ffmpeg_args = args.ffmpeg_args[1:]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
