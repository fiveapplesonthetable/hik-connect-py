# Hik-Connect Cloud Streaming — Pure-Python, Ground Up

How to pull live H.264 from a Hik-Connect / EZVIZ cloud-connected DVR using
only Python + an HTTP session, no Android SDK, no rooted phone, no emulator.
Includes how the protocol was reverse-engineered against a real DVR
(Hikvision DVR/DVS-18-A, EU region) and the actual wire bytes we
captured from the official app.

## What you'll have at the end

```
$ python3 scripts/hik.py login --email a@b.com --password 'secret'
[OK] session saved → logs/hik_session.json

$ python3 scripts/hik.py list
[*] 1 device(s):
  • C12345678  'Home'  cat=COMMON  chans=18  fw=V4.30.120 build 200630

$ python3 scripts/hik.py probe
  ch01: LIVE   ch02: LIVE   ch03: LIVE   ch04: silent   ch05: LIVE
  ch06: LIVE   ch07: LIVE   ch08: LIVE   ch09..ch18: SETUP FAIL (6106)
[OK] live channels: [1, 2, 3, 5, 6, 7, 8]

$ python3 scripts/hik.py stream --channel 1 --duration 5 --out cam1.bin
[*] streaming C12345678/1 for up to 5.0s
[*] step 2 ok: datakey=63978 ssn=streamssnk8s_pop172.18.2... streamhead=56B
[OK] 74 pkts, 41.5 KiB in 5.0s (65.8 kbit/s)
```

7 of 18 channels stream cleanly. Channel 4 is offline (camera disconnected),
9–18 are empty DVR slots (`result=6106`).

## Layout of the code

```
scripts/hik.py              — the production CLI (login/list/probe/stream/ffmpeg/refresh)
scripts/hik_login_probe.py  — used during RE to find the login endpoint
scripts/hik_list_devices.py — used during RE to enumerate device metadata
scripts/hik_ecdh.py         — pure-Python ECDH envelope encoders (NOT needed for cloud
                              preview — preserved because the .so used them for
                              other code paths)
docs/vtm_redirect_re.md     — the full code map of libezstreamclient.so as we
                              reverse-engineered it (some of it turned out to be
                              the wrong code path — see "What we learned")
apk/hikconnect-4.19.0.apk   — the official app, used as ground truth
apk/libs/arm64/             — the .so we disassembled
logs/captures/              — pcap from the real Android app + raw byte dumps
logs/screenshots/           — Pixel UI screenshots from the capture session
```

## What you need

```bash
cd /mnt/agent/hikvision_e2e
python3 -m venv venv
. venv/bin/activate
pip install -q requests cryptography pycryptodome
```

Optional for the wire-capture validation step (not needed for the streaming itself):
- `binutils-aarch64-linux-gnu` (objdump for the .so)
- `tshark` (parse the pcap)
- The Hik-Connect APK + libs (already in `apk/`)

## The protocol

The Hik-Connect Android app talks to a small REST stack at
`api.hik-connect.com` (and a region-specific apiDomain after login), then
opens a raw TCP socket to a per-channel **VTM** (Video Transfer Mediator).
Everything runs over plaintext TCP **on port 8554** for initial contact and
a server-load-balanced 6xxx range for the redirected stream.

### Step 0. REST login → session

```http
POST https://api.hik-connect.com/v3/users/login/v2
Headers:
  clientType: 55
  lang: en-US
  featureCode: deadbeef
  User-Agent: okhttp/4.9.1
Body (form):
  account=<email>
  password=<md5(password) hex>
  areaId=0
  featureCode=deadbeef
```

Returns `{loginSession.sessionId, loginArea.apiDomain, loginUser.username}`.
The session is good for ~24 h. Don't retry on 1226 (locked-account) — wait it out.

### Step 1. List devices

```http
GET https://{apiDomain}/v3/userdevices/v1/devices/pagelist
?filter=CONNECTION,KMS_INFO,P2P_INFO
&groupId=-1&limit=30&offset=0
Headers: clientType:55, lang:en-US, featureCode:deadbeef, sessionId:<jwt>
```

Gives you the list of cloud-bound devices. The DVR appears as a single
device with `channelNumber:18`. **The per-channel camera list is NOT
returned by this endpoint** — you have to probe each channel individually
or trust the device's `channelNumber` and try each.

The `kmsInfos[serial].secretKey` field is a 64-char hex string. Looks
important; **it is not used for the cloud-preview protocol** — see
"What we learned" at the bottom.

### Step 2. Stream-token batch

```http
POST https://{apiDomain}/api/user/token/get
Headers: …same…
Body (form):
  featureCode=deadbeef
  count=10           ← the SDK asks for 50 in practice
```

Returns `{tokenArray: ["ut.AAA...", "ut.BBB...", ...]}`. Each token is a
**single-use 64-char string** for one stream attempt. The SDK pre-fetches
50 at a time and pops one per stream. They go stale after ~5 minutes if
unused.

### Step 3. Per-channel VTM endpoint

```http
GET https://{apiDomain}/v3/streaming/vtm/{serial}/{channel}
```

Returns `{streamServerConfig: {externalIp, port, ...}}`. The host is a
geographic VTM cluster member (e.g. `vtmcdsfra.ezvizlife.com` → resolves
to a specific `148.153.115.x` IP in the EU). Port is **8554**.

### Step 4. VTM step 1 — initial STREAMINFO_REQ

```python
# Connect to vtm.externalIp:vtm.port (TCP, plaintext)
url = (f"ysproto://{host}:{port}/live?"
       f"dev={serial}&chn={channel}&stream=1"
       f"&cln=55&isp=0&auth=1"
       f"&ssn={token}"        # ut.XXX from /api/user/token/get
       f"&lid={uuid4}"        # fresh UUID per session
       f"&biz=1")
body = (
    proto_string(1, url) +
    proto_string(3, "v3.2.6.20200311") +    # useragent
    proto_varint(4, 0) +                    # proxytype
    proto_string(5, "") +                   # pdsstring (EMPTY — see below)
    proto_string(6, "v3.2.6.20200311")      # clnversion
)
# Send as VTM packet:
#   magic 0x24 | channel 0 | length BE u16 | seq=1 BE u16 | mcode 0x13B BE u16
header = bytes([0x24, 0, len(body)>>8, len(body)&0xff, 0, 1, 0x01, 0x3B])
sock.send(header + body)
```

The server responds with a `STREAMINFO_RSP` (mcode `0x13C`):

```
field 1 result        = 5302    (always; this is the "redirect required" code)
field 5 vtmstreamkey  = 30-char hex (e.g. "0b4a3b1b25a09b09c7f35d772417186")
field 6 serverinfo    = "ys7-vtm vtmk81.183 v2.18.5 build 20251127"
field 7 streamurl     = ysproto://<NEW_HOST>:<NEW_PORT>/live?dev=...&ssn=<same>&biz=1
```

The redirect URL keeps the same ssn, biz=1, but no timestamp and no signature.

### Step 5. VTM step 2 — to the redirect target

Open a **new** TCP connection to the redirect host:port. Send STREAMINFO_REQ
again with seq=2:

```python
url2 = info1.streamurl + f"&timestamp={int(time.time()*1000)}"   # client adds timestamp
body = (
    proto_string(1, url2) +
    proto_string(2, info1.vtmstreamkey) +   # echo the 30-hex key
    proto_string(3, "v3.2.6.20200311") +
    proto_varint(4, 0) +
    proto_string(5, "") +
    proto_string(6, "v3.2.6.20200311")
)
header = bytes([0x24, 0, len(body)>>8, len(body)&0xff, 0, 2, 0x01, 0x3B])
sock.send(header + body)
```

Server responds with:

```
field 1 result     = 0     (success)
field 2 datakey    = uint32 (e.g. 63978)
field 3 streamhead = base64-encoded IMKH init header (~56 bytes)
field 4 streamssn  = "streamssn-redacted"
```

If you got `result=6106` here: that channel has no camera attached (DVR slot
empty). If `result=6001`: you're back to the pre-breakthrough mistake — see
the troubleshooting section at the bottom.

### Step 6. Drain stream packets

The same TCP socket starts pushing media packets:

```
header: 0x24 | channel 0x01 (STREAM) | length BE | seq BE | mcode BE
mcode varies per stream (observed 0xdc5e, 0x9e03, 0x0a43 — appears stream-specific)
body:  Hikvision custom envelope + MPEG-PS/H.264 inside
```

Frame sizes alternate between small (~64B) headers and ~1376B (just under
TCP MSS) data chunks. About 65 kbit/s at default DVR quality settings.

Send the server nothing back until the next keepalive interval (~75 s);
omit keepalives and the server will close the socket after that idle time.

## Putting it all together — `scripts/hik.py`

```bash
# One-time login (saves session to logs/hik_session.json)
python3 scripts/hik.py login --email a@b.com --password 'pw'

# List devices
python3 scripts/hik.py list

# Find which channels have live cameras
python3 scripts/hik.py probe

# Stream one channel for N seconds to a file
python3 scripts/hik.py stream --channel 1 --duration 30 --out cam1.bin

# Stream to stdout (pipe into anything)
python3 scripts/hik.py stream --channel 1 --duration 30 --out - | \
    ffmpeg -f data -i pipe:0 -c copy out.mp4

# Or use the bundled `ffmpeg` subcommand
python3 scripts/hik.py ffmpeg --channel 1 --duration 30 -- \
    -f data -i pipe:0 -c copy out.mp4

# Verify session is still alive (auto re-login if not, future-extension)
python3 scripts/hik.py refresh
```

## How the protocol was reverse-engineered (chronological)

Step-by-step, ground up. Every step here actually happened — no
glossing-over of dead ends, because the dead ends explain why the working
protocol is so simple.

### 1. APK + .so

```bash
mkdir -p apk
curl -sL -o apk/hikconnect-4.19.0.apk \
  https://archive.org/download/hik-connect-apk/hik-connect-4-19-0-1014.apk
unzip -j -o apk/hikconnect-4.19.0.apk 'lib/arm64-v8a/*.so' -d apk/libs/arm64
# 5 MB libezstreamclient.so contains the streaming logic
```

Then decompiled the Java with jadx (`jadx -d apk/decompiled apk/hikconnect-4.19.0.apk`),
and dumped the .so with `aarch64-linux-gnu-objdump -d`.

### 2. Login + device + ticket + VTM endpoints

These four REST endpoints came straight from reading the Java source
(`UserApi.java:43`, `CameraApi.java`, `…`). Within an hour we had:

```python
session_id = login(email, password_md5)
devices    = GET /v3/userdevices/v1/devices/pagelist
ticket     = GET /v3/cameras/ticketInfo?deviceSerial=...&channelNo=1
vtm        = GET /v3/streaming/vtm/{serial}/{channel}
```

This took us all the way to opening a TCP connection to the VTM. But our
first STREAMINFO_REQ guesses got nothing back (server silently closed).

### 3. The protobuf wire format

Disassembling `libezstreamclient.so` showed the protobuf message
`hik::ys::streamprotocol::StreamInfoReq` with these fields:

| Field | Setter symbol               | Type   |
|-------|------------------------------|--------|
| 1     | `set_streamurl`              | string |
| 2     | `set_vtmstreamkey`           | string |
| 3     | `set_useragent`              | string |
| 4     | `set_proxytype`              | int    |
| 5     | `set_pdsstring`              | string |
| 6     | `set_clnversion`             | string |

And `StreamInfoRsp` had a parallel set of getters. Easy enough to recreate
from `_proto_string` / `_proto_varint`.

### 4. The hdSign trap (~3 days lost)

In the .so's `EZVIZECDHCrypter::ezviz_ecdh_encECDHReqPackage` there's an
elaborate envelope:

```
+0   1   tag = 0x24
+1   1   sub-version = 0x01
+3   2   plaintext length (BE)
+11  32  AES-256-ECB(session_key32, kms_key32)   ← uses kmsInfos.secretKey
+43  91  DER-encoded P-256 ephemeral pubkey
+134 N   ChaCha20-encrypted plaintext
+134+N 32  HMAC-SHA256("<crc_hdr><crc_data>", kms_key32)
```

We **recreated all of this in Python** (`scripts/hik_ecdh.py`) — mbedTLS
calls cross-referenced against the cryptography lib. Round-trip works.

We also found `hdSign` in vendor strings and built an HMAC-SHA256 formula:

```python
hdSign = HMAC(kms_secretKey[:32].utf8, url_base).hex()
```

This produced a `hdSign` value that *byte-exactly* matched the `hdSign`
the server put in its redirect URL. We thought we had cracked it.

Step 1 returned `result=5302` consistently — felt like progress. But
step 2 to the redirect target *always* returned `result=6001`
(`NET_DVR_EZVIZ_OPEN_PLAYFORM_VERIFY_DATA_ERROR`). We tried:

| Variant on step 2                                  | Result |
|----------------------------------------------------|:------:|
| Same hdSign, same pds=base64(DER pubkey)           | 6001   |
| Different ephemeral pubkey (E)                     | 6110   |
| pds = empty / absent                               | 6110   |
| Sequence != 0 in VTM header                        | 6110   |
| pds = base64(full encECDH envelope)                | 6001   |
| pds = the redirect URL itself                      | 6001   |
| Wrapped body in EncECDH on channel 10              | conn-reset |
| Ticket rotation, timestamp replacement, …          | 6110/6001 |

Every code-read of `libezstreamclient.so` pointed at a more elaborate ECDH
post-handshake. The wall held.

### 5. The Pixel breakthrough

A USB-attached **Pixel 4 XL** (Android 13, locked stock — no root) was
passed through to this VM with `virsh attach-device` (one host command,
single USB vendor:product ID). The host did not give shell access; just
made the USB device visible to the VM.

We installed two APKs:

```bash
adb install apk/hikconnect-4.19.0.apk
adb install apk/pcapdroid_1.9.1.apk   # from f-droid.org, no-root packet capture
```

PCAPdroid uses Android's VPN API to mirror per-app traffic into a real
`.pcap` file — no root required, no instrumentation.

Drove the UI via `adb shell input tap …` (no PIN on the device, fully
scriptable). Configured PCAPdroid to capture Hik-Connect, started the
capture, opened Hik-Connect, signed in, played camera 01 (live night
view of the user's home in a private residence), and pulled the pcap:

```bash
adb pull /sdcard/Download/PCAPdroid/PCAPdroid_27_May_22_25_32.pcap \
    logs/captures/hik_app_step2.pcap
```

100 KB of plaintext TCP. The first STREAMINFO_REQ from the real app:

```
url = ysproto://148.153.115.236:8554/live?
      dev=C12345678&chn=1&stream=1
      &cln=55                                       ← we'd been sending cln=3
      &isp=0&auth=1
      &ssn=ut.1vfb43wa243y34yr5sn4s7b78e7j6q07-... ← from /api/user/token/get,
                                                   ← NOT from ticketInfo
      &lid=9580df91-1d41-4ee3-a8f9-693f195e7ec1    ← UUID, NOT username
      &biz=1                                       ← required param, never sent
```

**No `&hdSign=…` parameter at all.** No signature in the URL. Our entire
hdSign HMAC theory was the result of looking at a different code path in
the .so — one used for talkback/playback/local-LAN, not cloud preview.

The pdsstring field was empty. The useragent was `v3.2.6.20200311`
(streamclient SDK version, not app version). The VTM packet sequence was
incrementing 1, 2 across requests, not always 0.

Step 2 added `&timestamp={epoch_ms}` to the URL — that's the only
client-added field.

### 6. Cracking step 2

With the ground truth in hand, the python reimplementation succeeded on
the first try:

```python
url1 = f"ysproto://{host}:{port}/live?dev={serial}&chn={channel}&stream=1" \
       f"&cln=55&isp=0&auth=1&ssn={token}&lid={uuid4()}&biz=1"
# … step 1 → 5302 with redirect URL
url2 = redirect_url + f"&timestamp={int(time.time()*1000)}"
# … step 2 with seq=2 → result=0 ✓
```

`result=0`, `datakey`, `streamhead`, then the server starts pushing video.

### 7. Productionizing

`scripts/hik.py` exposes the full pipeline: `login`, `list`, `probe`,
`stream`, `ffmpeg`, `refresh`. See it for the canonical implementation.

## What we learned

- **Read the actual wire bytes first.** Three days of disassembly were
  almost entirely wasted because the .so has *many* protocols for
  different camera modes (local LAN, talkback, P2P, cloud preview),
  and we were reading code that wasn't on the cloud-preview path.
  Single 10-second wire capture from the real app would have saved all of it.
- **Don't trust the `kmsInfos.secretKey` for cloud preview.** It's a
  device permanent key, but it's only used for local-network direct
  connect, P2P, and talkback — not for cloud streaming through the VTM
  cluster. For VTM the auth currency is the short-lived `ut.XXX` token.
- **The `hdSign` URL param is server-generated.** The server puts a
  hdSign in its redirect URL for *its own internal* tracking (the redirect
  target verifies it). The client never computes or sends it. Our HMAC
  formula matched the server's because we happened to use the same
  `secretKey[:32]` material the server used — but the server was talking
  to itself, not asking the client to.
- **Stock Android phones (no root) work fine as RE test rigs.** PCAPdroid +
  USB pass-through gets you wire bytes without flashing anything. The host
  only needs one `virsh attach-device` command per phone.

## Troubleshooting

| Symptom (after step 2) | Most likely cause | Fix |
|------------------------|-------------------|-----|
| `result=6001`           | Wrong URL params  | check ssn= is a `ut.XXX` token, cln=55, biz=1, timestamp present on step 2, no hdSign |
| `result=6106`           | Channel has no camera | `probe` to find live channels |
| `result=6110`           | Required protobuf field missing | check vtmstreamkey is echoed on step 2 |
| `result=5302` again     | Step 2 sent to wrong host | parse hostname from step 1's redirect URL |
| `Connection reset`      | Sequence number wrong, or wrong VTM magic byte | header is `0x24` (not `0xab`), seq increments |
| 0 packets after step 2  | Token expired between fetch and use | re-fetch via `/api/user/token/get` and start over |

## Open follow-up: stream decoding

The stream packets carry an extra Hikvision header (`5566 7788` magic
appears repeatedly) wrapping MPEG-PS / H.264. ffmpeg doesn't decode the
raw bytes directly. The `datakey` field looks like an AES key seed:
`pyezvizapi/stream.py` (vendored in `apk/pyEzvizApi/`) has
`decrypt_hikvision_ps_video(data, key)` for the encrypted-NAL variant.
Plug datakey-derived material through it to mux into MP4. Tracked as
**Task #41**.
