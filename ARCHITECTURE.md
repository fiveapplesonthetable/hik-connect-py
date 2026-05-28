# Architecture

How `hikvision_e2e` actually streams live video from a Hik-Connect / EZVIZ
cloud-connected DVR to a browser in your hand. Read top-to-bottom: protocol
first, then how we decode the bytes, then how the web mosaic serves them.

```
                ┌──────────────────────────────────────────────────────────┐
                │            Hik-Connect cloud (open.ys7.com)             │
                │   REST /v3/users/login/v2   →   sessionId + apiDomain   │
                │   REST /api/lapp/token/get  →   short-lived stream tok  │
                │   VTM TCP :6500             →   handshake, packet pump  │
                └────────────────┬──────────────────────────────┬─────────┘
                                 │                              │
                       sessionId │                  RTP H.264 / G.711µ
                         + token │                              │
                                 ▼                              ▼
                    ┌────────────────────────┐     ┌────────────────────────┐
                    │  scripts/hik.py login  │     │  scripts/hik.py ffmpeg │
                    │  (cache session JSON)  │     │  (RTP demux → NALs →   │
                    └────────────────────────┘     │   ffmpeg → HLS dir)    │
                                                   └─────────┬──────────────┘
                                                             │  index.m3u8
                                                             │  segN.ts (≈2 s)
                                                             ▼
                                                ┌─────────────────────────┐
                                                │  hik-viewer/app/server  │
                                                │  FastAPI on :8766       │
                                                │   - /api/cams           │
                                                │   - /api/cams/*/start   │
                                                │   - /hls/cam{N}/*       │
                                                │  watchdog: idle stop +  │
                                                │  auto-respawn (75 s)    │
                                                └────────────┬────────────┘
                                                             │
                                                             ▼
                                              ┌──────────────────────────┐
                                              │  browser (any device)    │
                                              │  hls.js → MSE → <video>  │
                                              │  ~4–6 s end-to-end       │
                                              └──────────────────────────┘
```

Latency budget: ~1 s on the wire from the camera, ~2 s ffmpeg HLS segment
duration, ~2 s of playlist buffer in the browser. End-to-end ~5 s.

---

## 1. Login, session, token

`hik.py login --email --password` does three HTTPS round-trips:

1. **`POST /v3/users/login/v2`** to `apiieu.ezvizlife.com` with MD5(password),
   featureCode, osVersion. Response contains `sessionId`, `apiDomain` (e.g.
   `iusopen.ezvizlife.com` for EU users), `userName`. We cache the whole
   blob to `logs/hik_session.json`.

2. **`POST /v3/userdevices/v1/devices/pagelist`** on `apiDomain`, sends back
   every cloud-bound device (DVRs, IPCs, NVRs) under that account. We
   persist the `deviceSerial`s + their `channelNumber`.

3. **`POST /api/lapp/token/get`** with the cached sessionId → ~60-minute
   stream token, used by VTM as `pdsstring`.

All three reuse a single `requests.Session` so HTTP/2 keepalive + cookies
stay warm. Session expires ~24 h; `hik.py refresh` re-checks live state.

## 2. The VTM (Video Transit Manager) wire format

VTM is a TCP-only proxy in the Hik cloud that bridges the camera's stream
to your browser/client. We dial `vtm.*.ys7.com:6500` and speak a small
binary framing on top of TCP.

**VTM packet layout** (all big-endian):

```
 0           1           2           3           4           5  ...
 +-----------+-----------+---+-------+-----------+-----------+----
 | magic     | channel   | length        | seq       | mcode |
 | 0x24      | 1 byte    | 4 bytes BE    | 4 bytes BE| 4 BE  |
 +-----------+-----------+---+-------+-----------+-----------+----
                                                              \____ body (length bytes)
```

- `channel` is the VTM logical channel, not the DVR camera channel. Channel
  1 = control / handshake. Channel 2 = payload (RTP). Channel 10 = the
  ECDH-encrypted control envelope used by some firmware variants (we don't
  need it for the cloud preview path).
- `seq` and `mcode` are bookkeeping for the cloud's session tracking.

**Handshake**, step 1: client sends `pdsstring=<stream_token>` + a server-
chosen `hdSign`. VTM responds with `result=5302` and a redirect URL
containing a new IP + port + freshly-signed `hdSign` (this redirect-hop is
the source of the long, painful RE history — see `docs/vtm_redirect_re.md`).

Step 2: dial the redirect host, send the new `hdSign`. VTM replies
`result=0` and starts pushing the camera stream as channel-2 packets.

After step 2 the only thing flowing is RTP wrapped in VTM frames. Idle
sockets are closed by the server after ~75 s — the `hik-viewer` watchdog
handles that by respawning the pipeline (see §6).

## 3. RTP → H.264 Annex-B (the decode path)

Each VTM channel-2 body is one RTP packet, RFC 3550 framed:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier            |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|                            payload                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The payload is RFC 6184 packetized H.264:

| Payload type | NAL header byte (low 5 bits) | What it is |
|---|---|---|
| Single NAL unit | 1–23 | Whole NAL fits in one RTP packet. Emit as-is. |
| STAP-A | 24 | Concatenation of several small NALs (typically SPS+PPS+IDR). |
| FU-A | 28 | One NAL split across many packets (typically a P-slice). |

`scripts/hik.py` (`h264_depacketize()`) handles all three and emits Annex-B
NALs (each prefixed with `\x00\x00\x00\x01`). The output stream is a clean,
spec-compliant H.264 elementary stream that ffmpeg, VLC, gstreamer, or any
H.264 decoder can consume.

Audio in the same VTM channel uses PT 0 (G.711 µ-law / PCMU, 8 kHz mono).
We tag it `a` in the demux generator and route to a separate ffmpeg input
pipe. The web mosaic disables audio (`--no-audio`) because the cameras
under test ship sparse audio packets that confuse the muxer; the CLI
preserves it for offline `--out file.mp4` captures.

## 4. ffmpeg: from NALs to HLS segments

`hik.py ffmpeg --channel N --hls-dir DIR` opens two anonymous OS pipes
(`os.pipe()`) and spawns ffmpeg with `pass_fds=[...]`. The Python side
writes NALs into the video FD; ffmpeg reads them, segments to HLS:

```
ffmpeg -f h264 -r 25 -i pipe:V \
       -c:v copy \
       -f hls \
       -hls_time 2 \
       -hls_list_size 8 \
       -hls_flags delete_segments+split_by_time \
       -hls_segment_filename '<hls-dir>/seg%05d.ts' \
       '<hls-dir>/index.m3u8'
```

`-c:v copy` matters: we never re-encode. The stream you watch is the bytes
the DVR's H.264 encoder produced, just re-muxed into MPEG-TS chunks.
That's what keeps end-to-end latency under ~6 s on commodity hardware.

`split_by_time` forces a new segment every 2 s of wall clock even if no
IDR has shown up — important because some channels have IDR intervals of
15–30 s, and we'd otherwise wait that long for the first segment.

## 5. The web mosaic — server side (`hik-viewer/app/server.py`)

FastAPI on `:8766`. Three responsibilities:

1. **Probing.** Once at startup it shells out to `hik.py probe`, which
   walks every cloud-listed channel for ~4 s each and measures bytes/s.
   Real 1080p feeds run ≥60 KB/s; the DVR's "NO VIDEO" placeholder is
   ~6 KB/s. Only real channels make it into the UI; placeholders are
   filtered out. Cached to `logs/live_channels.json`.

2. **Pipeline lifecycle.** `/api/cams/{n}/start` spawns one `hik.py ffmpeg`
   per channel as `subprocess.Popen(start_new_session=True)`. Each writes
   to its own `hls/camN/` directory. Pipelines are killed via the process
   group (`os.killpg`) so ffmpeg-under-hik.py dies cleanly.

3. **Watchdog.** A background `asyncio` task wakes every 3 s and does two
   things:
   - **Auto-respawn:** if a pipeline exited but a viewer fetched a segment
     within the idle timeout, respawn it. The VTM closes idle sockets at
     ~75 s — without this the browser would freeze at the 75-s mark.
   - **Idle stop:** if a pipeline has had no viewer GETs for 60 s, kill it.
     Saves DVR stream slots + bandwidth.

The HLS files are served from `/hls/camN/` with `Cache-Control: no-store`
so the browser doesn't cache stale playlists. Each GET updates `_last_seen`
which is what the watchdog uses to decide idle.

## 6. The web mosaic — front-end (`hik-viewer/web/src/app.ts`)

Strict TypeScript (every flag in `tsconfig.json` is on). Compiled to
`hik-viewer/app/static/app.js` via `npm run build`. The runtime loads it
with `<script src="/static/app.js" defer>` after `hls.js` from CDN.

State is tiny:
- `watching: Set<number>` — channels the user has explicitly clicked.
  Page-load never auto-starts anything.
- `cardByChannel: Map<number, HTMLDivElement>` — DOM cards keyed by channel.

Each card has one `<video muted autoplay playsinline>` whose lifecycle is
managed by `attachHls()`. The video element gets an `hlsInstance` property
so detach() can find the active Hls and `.destroy()` it.

Two non-obvious correctness rules — both have failed in practice and both
are documented in the source:

**Rule 1: synchronous attach inside the user gesture.** Chrome's autoplay
policy allows muted-video autoplay only when `.play()` is called inside
the same synchronous event handler as the user click. If you `await`
anything first, the gesture context is gone and play() is rejected with
a `NotAllowedError`. The fix: attach HLS for every card synchronously
inside the click handler, then `void api(...)` for the spawn POST.

**Rule 2: hls.js fragment-loaded backup play.** Even with rule 1, the
initial `.play()` can resolve too early — before any fragment has loaded —
and the video element stays paused. We hook `Hls.Events.FRAG_LOADED` and
call `.play()` again if `videoEl.paused`. Cheap belt-and-braces.

Strict typecheck specifically catches three classes of bug in this app:
- Forgetting to null-check map lookups (`cardByChannel.get(ch)` returns
  `HTMLDivElement | undefined`).
- Using `?.` on a value the type system can prove is non-null (caught by
  `strictNullChecks`).
- Forgetting to `void` a fire-and-forget Promise (caught by
  `noUnusedExpressions` + the explicit `void` markers).

## 7. Operational details

- **systemd unit** ships as `hik-viewer/hik-viewer.service`. Copy to
  `~/.config/systemd/user/hik-viewer.service` and `systemctl --user enable
  --now hik-viewer`. `Restart=always` so a crash is recovered.
- **Logs** land in `hik-viewer/logs/camN.log` (one per channel) — these
  are what to read first when a stream misbehaves.
- **Cache busting:** the front-end appends `?t=<ms>` to every HLS playlist
  load so a respawn never serves a stale segment list.
- **Probe refresh:** `POST /api/cams/probe` re-runs the threshold probe;
  call after adding or unplugging a physical camera.

## 8. Things this doesn't do (intentionally)

- **No HEVC.** The cameras under test stream H.264; a future enhancement
  would auto-detect SPS and pick `hevc_mp4toannexb` accordingly.
- **No client-side TLS pin.** Local LAN deployment, served behind Tailscale.
- **No multi-user auth.** Single-user; whoever can hit the port can watch.
- **No DVR-side recording offload.** Live preview only. Use `hik.py ffmpeg
  --out file.mp4` for archival captures.

---

## Reference: the seven files that matter

| File | What it owns |
|---|---|
| `scripts/hik.py` | The CLI: login, list, probe (with placeholder detection), stream, ffmpeg, refresh |
| `hik-viewer/app/server.py` | FastAPI + watchdog (idle stop + auto-respawn) |
| `hik-viewer/web/src/app.ts` | Strict-TS front-end logic — only file edited for UI work |
| `hik-viewer/web/tsconfig.json` | Every strict flag turned on |
| `hik-viewer/app/static/index.html` | DOM shell — loads `app.js` and hls.js, nothing more |
| `hik-viewer/app/static/style.css` | Dark mosaic, monospace, 16:9 player ratio |
| `hik-viewer/hik-viewer.service` | systemd-user unit for the FastAPI server |
