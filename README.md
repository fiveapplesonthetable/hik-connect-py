# hikvision_e2e — pure-Python Hik-Connect cloud cam streaming

Stream live H.264 video + AAC audio from a Hik-Connect / EZVIZ cloud-connected
DVR or camera without the official mobile app, without an Android device,
without an emulator, without any vendor SDK. Pure Python + ffmpeg.

```bash
python3 -m venv venv && . venv/bin/activate
pip install -q requests cryptography

python3 scripts/hik.py login --email a@b.com --password 'secret'
python3 scripts/hik.py list             # → all cloud devices
python3 scripts/hik.py probe            # → which channels have a live cam
python3 scripts/hik.py ffmpeg --channel 1 --duration 30 --out cam1.mp4
```

The result is a real `cam1.mp4` with H.264 video + AAC audio, both synced.

See **[TUTORIAL.md](TUTORIAL.md)** for the ground-up walkthrough — how the
protocol was reverse-engineered against a real DVR using a Pixel 4 XL +
PCAPdroid wire capture, what we learned, and a code map of
`libezstreamclient.so`.

## What's here

| Path | Purpose |
|---|---|
| `scripts/hik.py` | The CLI: `login` / `list` / `probe` / `stream` / `ffmpeg` / `refresh` |
| `ARCHITECTURE.md` | Wire protocol, decode pipeline, server + front-end design |
| `TUTORIAL.md` | Honest ground-up RE writeup |
| `docs/vtm_redirect_re.md` | Code map of `libezstreamclient.so` paths we explored |
| `docs/ecdh_layer_re.md` | The (unused-for-cloud-preview) ECDH envelope wire format |
| `docs/cas_protocol_re.md` | CAS server protocol notes (also off-path for cloud preview) |
| `scripts/hik_ecdh.py` | Pure-Python ECDH envelope encoders, round-trip tested |
| `scripts/hik_login_probe.py` | RE helper for the login endpoint |
| `scripts/hik_list_devices.py` | RE helper for device-metadata enumeration |
| `hik-viewer/app/` | FastAPI live-cam mosaic, serves HLS on `:8766` |
| `hik-viewer/web/` | Strict-TypeScript front-end (compiles to `app/static/app.js`) |
| `hik-viewer/hik-viewer.service` | systemd-user unit |

## The web mosaic

A phone-friendly browser mosaic of every live cam. Read **ARCHITECTURE.md**
for the full design; quick-start:

```bash
# Install Python deps
python3 -m venv venv && . venv/bin/activate
pip install -q requests cryptography fastapi 'uvicorn[standard]'

# Log in + cache live channel list (filters out DVR placeholders)
python3 scripts/hik.py login --email a@b.com --password 'secret'
python3 scripts/hik.py probe

# Build the TypeScript front-end
cd hik-viewer/web && npm install && npm run build && cd ../..

# Run the server (or install hik-viewer.service for systemd-user)
hik-viewer/app/run-server.sh    # → http://localhost:8766/
```

Click "start all" to begin streaming. Cards never auto-start; pipelines
idle-stop after 60 s with no viewer and auto-respawn when the cloud closes
the upstream socket.

## CLI reference

### `hik.py login --email EMAIL --password PASSWORD`
Logs in via `POST /v3/users/login/v2`, MD5s the password, caches the
sessionId + apiDomain + username to `logs/hik_session.json`. Re-run when
the session expires (~24h).

### `hik.py list`
Lists cloud devices. Writes `logs/hik_devices.json`.

### `hik.py probe [--serial SERIAL]`
Probes every channel from 1..N (where N = `deviceInfo.channelNumber`),
runs the step-1/step-2 handshake, and reports which channels have a
live camera connected. A DVR with 18 slots and 7 cameras returns
`[1, 2, 3, 5, 6, 7, 8]`.

States:
- `LIVE` — camera attached and streaming
- `silent` — handshake OK but no frames (camera offline)
- `SETUP FAIL (result=6106)` — channel has no camera

### `hik.py stream --channel N --duration S --out PATH`
Captures the stream to a file (or stdout if `--out -`).

| Flag | Behavior |
|---|---|
| `--format h264` (default) | Annex-B H.264 NAL units. Pipe-compatible with `ffmpeg -f h264 -i pipe:0`. |
| `--format raw` | Raw VTM packet bodies (RTP-framed; parse with `parse_rtp` from this script). |
| `--include-streamhead` | (raw only) prepend the 40-byte IMKH init header. |
| `--max-bytes N` | Stop after N bytes. |

### `hik.py ffmpeg [--channel N] [--duration S] [--out PATH | --hls-dir DIR] [--no-audio | --no-video]`
Captures + muxes with ffmpeg. **Audio and video are both on by default; either is optional.**

| Flag | Behavior |
|---|---|
| `--out PATH` | Single output file (`.mp4`, `.mkv`, …). ffmpeg picks demuxer from extension. |
| `--hls-dir DIR` | Live HLS segments (`index.m3u8` + `seg_*.ts`, 2-second, 6-deep) — for browser playback. |
| `--no-audio` | Drop the PCMU audio (faster, smaller). |
| `--no-video` | Audio-only output. |
| `-- <ffmpeg args>` | Bypass the default args. You get H.264 NALs on stdin (`pipe:0`) and supply your own ffmpeg invocation. Video-only in this mode. |

Defaults: video = stream-copy (no re-encode), audio = PCMU → AAC 48 k mono @ 16 kHz.
ffmpeg gets two inherited file descriptors (one per stream); no FIFOs or
temp files.

### `hik.py refresh`
Verifies the cached session by hitting `/v3/userdevices/v1/devices/pagelist`.

## ffmpeg usage cookbook

`hik.py ffmpeg` is a thin ffmpeg launcher — anything ffmpeg can do, you
can do. The recipes below stream live, no transcoding latency.

### 1. Just record a 60-second clip
```bash
python3 scripts/hik.py ffmpeg --channel 1 --duration 60 --out cam1.mp4
```

### 2. Audio-only ("baby monitor")
```bash
python3 scripts/hik.py ffmpeg --channel 1 --no-video --duration 600 --out audio.mp4
```

### 3. Video-only (smaller files, no resample CPU)
```bash
python3 scripts/hik.py ffmpeg --channel 1 --no-audio --duration 60 --out v.mp4
```

### 4. Live HLS for browser playback
```bash
python3 scripts/hik.py ffmpeg --channel 1 --duration 600 --hls-dir /tmp/hls/cam1
# Open http://yourhost/.../hls/cam1/index.m3u8
```

### 5. Rolling 1-minute segments for a 24/7 archive
```bash
python3 scripts/hik.py stream --channel 1 --duration 86400 --out - --format h264 | \
    ffmpeg -loglevel warning -f h264 -r 25 -i pipe:0 \
        -c:v copy -f segment -segment_time 60 -strftime 1 \
        archive_%Y%m%d_%H%M%S.mp4
```

### 6. Motion-only recording (drops static frames)
```bash
python3 scripts/hik.py stream --channel 1 --duration 3600 --out - --format h264 | \
    ffmpeg -loglevel warning -f h264 -r 25 -i pipe:0 \
        -vf "select=gt(scene\,0.05),setpts=N/(25*TB)" \
        -c:v libx264 -preset veryfast -crf 23 motion.mp4
```

### 7. Multi-camera 2×4 mosaic
```bash
mkfifo /tmp/c{1,2,3,5,6,7,8}.h264 2>/dev/null
for ch in 1 2 3 5 6 7 8; do
    python3 scripts/hik.py stream --channel $ch --duration 600 \
        --out /tmp/c$ch.h264 &
done
ffmpeg \
    -f h264 -i /tmp/c1.h264 -f h264 -i /tmp/c2.h264 \
    -f h264 -i /tmp/c3.h264 -f h264 -i /tmp/c5.h264 \
    -f h264 -i /tmp/c6.h264 -f h264 -i /tmp/c7.h264 \
    -f h264 -i /tmp/c8.h264 \
    -filter_complex \
      "[0:v][1:v][2:v][3:v]hstack=4[top]; \
       [4:v][5:v][6:v]hstack=3,pad=4*iw/3:ih[bot]; \
       [top][bot]vstack" \
    -c:v libx264 -preset veryfast -crf 22 mosaic.mp4
```

### 8. Real-time motion / object detection with OpenCV
```python
# detect.py
import subprocess, sys, cv2, numpy as np
p = subprocess.Popen(
    ["ffmpeg", "-loglevel", "warning", "-f", "h264", "-i", "pipe:0",
     "-f", "rawvideo", "-pix_fmt", "bgr24", "-"],
    stdin=sys.stdin.buffer, stdout=subprocess.PIPE)
W, H = 960, 1080
while chunk := p.stdout.read(W*H*3):
    frame = np.frombuffer(chunk, np.uint8).reshape(H, W, 3)
    # cv2.HOGDescriptor() / YOLO / whatever
    cv2.imshow("cam", frame); cv2.waitKey(1)
```
Run: `python3 scripts/hik.py stream --channel 1 --duration 9999 --out - | python3 detect.py`.

### 9. HEVC hardware re-encode (NVIDIA)
```bash
python3 scripts/hik.py stream --channel 1 --duration 60 --out - | \
    ffmpeg -loglevel warning -f h264 -i pipe:0 \
        -c:v hevc_nvenc -preset p5 -tune hq -rc vbr -cq 28 cam1.hevc.mp4
```

### 10. Snapshots every N seconds
```bash
python3 scripts/hik.py stream --channel 1 --duration 600 --out - | \
    ffmpeg -loglevel warning -f h264 -i pipe:0 \
        -vf "fps=1/5" -y "snap_%05d.jpg"
```

### 11. RTSP re-broadcast (turn the cloud cam into a local RTSP source)
```bash
python3 scripts/hik.py stream --channel 1 --duration 86400 --out - | \
    ffmpeg -loglevel warning -f h264 -re -i pipe:0 \
        -c:v copy -f rtsp rtsp://localhost:8554/cam1
# (Needs an RTSP sink like MediaMTX / rtsp-simple-server.)
```

## GPU acceleration

The VM doesn't have a GPU by default, but `virsh attach-device` can PCI-pass
one through (same mechanism that was used to attach the Pixel during RE).
Once `/dev/dri/cardN` appears the ffmpeg flags above just work:

- **NVIDIA**: `-hwaccel cuda -c:v h264_cuvid -i ... -c:v hevc_nvenc`
- **Intel**: `-hwaccel qsv -c:v h264_qsv -i ... -c:v hevc_qsv`
- **AMD**:   `-hwaccel vaapi -vaapi_device /dev/dri/renderD128 -i ... -c:v hevc_vaapi`

NVENC HEVC encode is ~50× faster than software libx264. With one GPU you
can transcode all 7 cameras simultaneously and still have plenty of compute
left for ML inference.

For inference over the live feeds (YOLO, Real-ESRGAN, face recognition),
keep the H.264 decode on the GPU (`-hwaccel cuda -hwaccel_output_format cuda`)
so frames never leave VRAM until your model consumes them.

## Security

- `secrets.env` and the session cache (`logs/hik_session.json`) are
  `.gitignore`'d. The session contains a JWT — treat as a password.
- Tokens from `/api/user/token/get` are short-lived (~5 min) and
  per-stream-attempt. The SDK pulls 50 at a time and rotates.
- The cloud-preview protocol never sends the `kmsInfos.secretKey` over
  the wire — see TUTORIAL.md for why my initial hdSign theory was wrong.

## License & ethics

This is for streaming **your own cameras** through Hik-Connect with **your
own credentials**. Use against any other account's cameras would be
unauthorized access under most computer-misuse laws — don't.
