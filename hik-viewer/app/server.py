#!/usr/bin/env python3
"""hik-viewer — tiny FastAPI server that streams live Hik-Connect camera feeds
into a phone-friendly browser mosaic via HLS.

Architecture (matches /mnt/agent/recordings/app/server.py):

    GET  /             → static index.html mosaic
    GET  /api/cams     → list of live channels and current status
    POST /api/cams/{ch}/start  → spawn an ffmpeg HLS pipeline for that channel
    POST /api/cams/{ch}/stop   → kill the pipeline
    POST /api/cams/start_all   → start ffmpeg for every live channel
    POST /api/cams/stop_all    → stop everything
    GET  /hls/cam{N}/index.m3u8 (+ .ts segments)

The HLS pipeline:
    hik.py (RTP demux → Annex-B H.264 + PCMU on two pipes) → ffmpeg
        ffmpeg muxes into HLS (segment-time 2s, max 6 segments in playlist)
    Result: about 4–6s latency, plays in <video> in any browser that has hls.js
            (and natively on Safari/iOS).

This is single-process FastAPI; processes are tracked in-memory.
A graceful shutdown of the server kills all running ffmpegs.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent.parent     # /mnt/agent/hik-viewer
APP_DIR = ROOT / "app"
HLS_DIR = ROOT / "hls"
LOG_DIR = ROOT / "logs"
HIK_DIR = Path("/mnt/agent/hikvision_e2e")
HIK_PY = HIK_DIR / "scripts" / "hik.py"
HIK_VENV_PY = HIK_DIR / "venv" / "bin" / "python3"

# How long ffmpeg should keep running before exiting cleanly. None → no limit
# (server will respawn on crash via watchdog if/when we add one). The Hik VTM
# kills idle sockets after ~75s, so we restart every 60s as a safety margin.
DEFAULT_SEGMENT_TIME = 2
DEFAULT_PLAYLIST_SIZE = 6

app = FastAPI(title="hik-viewer")

# How long to keep a pipeline running with no client requests before we kill it.
# Browsers playing HLS fetch a new .ts every ~2 s, so 20 s is plenty of slack
# for tab-switches / brief network blips. Set to None to disable.
IDLE_TIMEOUT_S: float | None = 60.0

# Per-channel running ffmpeg processes
_procs: dict[int, subprocess.Popen] = {}
_last_started: dict[int, float] = {}
_last_seen: dict[int, float] = {}   # last time a client fetched something
_watchdog_started = False


def _hls_paths(channel: int) -> tuple[Path, Path]:
    cam_dir = HLS_DIR / f"cam{channel}"
    cam_dir.mkdir(parents=True, exist_ok=True)
    return cam_dir, cam_dir / "index.m3u8"


def _spawn_ffmpeg(channel: int) -> subprocess.Popen:
    cam_dir, playlist = _hls_paths(channel)
    # Clean stale segments
    for f in cam_dir.glob("*.ts"):
        f.unlink(missing_ok=True)
    playlist.unlink(missing_ok=True)

    log_path = LOG_DIR / f"cam{channel}.log"
    log_fh = open(log_path, "ab", buffering=0)
    log_fh.write(f"\n=== {time.strftime('%F %T')} starting cam{channel} ===\n"
                 .encode())

    # Video-only — audio is sparse on some channels and confuses ffmpeg HLS.
    # Long duration (1h) so the pipeline doesn't exit while users are watching;
    # the idle watchdog kills it when no one is fetching segments.
    proc = subprocess.Popen(
        [str(HIK_VENV_PY), str(HIK_PY),
         "ffmpeg",
         "--channel", str(channel),
         "--duration", "3600",
         "--no-audio",
         "--hls-dir", str(cam_dir)],
        stdout=log_fh, stderr=log_fh,
        cwd=str(HIK_DIR),
        start_new_session=True,
    )
    return proc


def _stop(channel: int) -> None:
    import contextlib
    proc = _procs.pop(channel, None)
    if proc is None:
        return
    with contextlib.suppress(Exception):
        # Send to the whole process group so ffmpeg under hik.py dies too
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(Exception):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


# ---------- API ----------

async def _idle_watchdog() -> None:
    """Background task with two jobs:

    1. **Idle stop** — kill pipelines that no client has GET'd in IDLE_TIMEOUT_S
       seconds (saves bandwidth + DVR stream slots).
    2. **Auto-respawn** — the Hik VTM closes idle sockets after ~75 s, so hik.py
       exits cleanly. If the channel is still being watched, restart it so the
       browser keeps playing without manual intervention.
    """
    while True:
        await asyncio.sleep(3)
        now = time.time()
        for ch, started in list(_last_started.items()):
            proc = _procs.get(ch)
            if proc is None:
                continue
            seen = _last_seen.get(ch, 0)
            is_watched = (now - seen) < (IDLE_TIMEOUT_S or 1e9)

            if proc.poll() is not None:
                # Pipeline died. Respawn if a viewer is still active.
                if is_watched:
                    print(f"[watchdog] ch{ch}: pipeline died (rc={proc.returncode}) "
                          f"— respawning ({now-seen:.0f}s since last GET)")
                    _procs[ch] = _spawn_ffmpeg(ch)
                    _last_started[ch] = now
                else:
                    print(f"[watchdog] ch{ch}: pipeline died, no viewer — clearing")
                    _procs.pop(ch, None)
                continue

            if IDLE_TIMEOUT_S is None:
                continue
            # Grace period after start (clients haven't fetched yet)
            if now - started < 8:
                continue
            if not is_watched:
                print(f"[watchdog] ch{ch}: idle {now-seen:.0f}s — stopping")
                _stop(ch)


@app.on_event("startup")
async def _startup() -> None:
    global _watchdog_started
    if not _watchdog_started:
        asyncio.create_task(_idle_watchdog())
        _watchdog_started = True


@app.on_event("shutdown")
def _shutdown() -> None:
    for ch in list(_procs):
        _stop(ch)


_LIVE_CHANNELS_CACHE: list[int] | None = None
_LIVE_PROBE_DONE_AT: float = 0


def _live_channels(force: bool = False) -> list[int]:
    """Auto-detect channels that actually have a live camera. Cached for the
    server's lifetime (re-probe via POST /api/cams/probe).
    """
    global _LIVE_CHANNELS_CACHE, _LIVE_PROBE_DONE_AT
    if _LIVE_CHANNELS_CACHE is not None and not force:
        return _LIVE_CHANNELS_CACHE
    live_path = HIK_DIR / "logs" / "live_channels.json"
    # Persistent cache — survives server restarts
    if live_path.exists() and not force:
        try:
            _LIVE_CHANNELS_CACHE = json.loads(live_path.read_text())
            return _LIVE_CHANNELS_CACHE
        except Exception:
            pass
    # Run the probe via hik.py
    print("[probe] enumerating live channels (this takes ~30 s)…")
    try:
        out = subprocess.check_output(
            [str(HIK_VENV_PY), str(HIK_PY), "probe"],
            cwd=str(HIK_DIR), stderr=subprocess.STDOUT, timeout=120,
        ).decode()
    except Exception as e:
        print(f"[probe] failed: {e}")
        return []
    chans: list[int] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("[OK] live channels"):
            # Parse "[OK] live channels on SERIAL: [1, 2, 3, ...]"
            try:
                chans = json.loads(line.split(":", 1)[1].strip())
            except Exception:
                pass
            break
    _LIVE_CHANNELS_CACHE = chans
    _LIVE_PROBE_DONE_AT = time.time()
    live_path.write_text(json.dumps(chans))
    print(f"[probe] live channels: {chans}")
    return chans


@app.get("/api/cams")
def api_cams() -> dict:
    chans = _live_channels()
    out = []
    for ch in chans:
        cam_dir, playlist = _hls_paths(ch)
        running = ch in _procs and _procs[ch].poll() is None
        out.append({
            "channel": ch,
            "running": running,
            "playlist": f"/hls/cam{ch}/index.m3u8" if running else None,
            "uptime_s": round(time.time() - _last_started[ch], 1)
                       if running and ch in _last_started else 0,
        })
    return {"cams": out, "probed_at": _LIVE_PROBE_DONE_AT}


@app.post("/api/cams/probe")
def api_probe() -> dict:
    """Re-probe which channels have a live camera (call after adding/removing
    a camera on the DVR)."""
    chans = _live_channels(force=True)
    return {"live_channels": chans}


@app.post("/api/cams/{ch}/start")
def _spawn_only(ch: int) -> None:
    """Spawn an ffmpeg pipeline without waiting for output. Idempotent."""
    if ch < 1 or ch > 64:
        raise HTTPException(400, "invalid channel")
    if ch in _procs and _procs[ch].poll() is None:
        return
    _procs[ch] = _spawn_ffmpeg(ch)
    _last_started[ch] = time.time()


def api_start(ch: int) -> dict:
    _spawn_only(ch)
    # Wait for the playlist to appear (up to ~6s) so the first GET works.
    cam_dir, playlist = _hls_paths(ch)
    for _ in range(60):
        if playlist.exists() and any(cam_dir.glob("*.ts")):
            return {"status": "started", "playlist": f"/hls/cam{ch}/index.m3u8"}
        time.sleep(0.1)
    return {"status": "starting", "playlist": f"/hls/cam{ch}/index.m3u8"}


# Expose api_start as a path operation (it was already declared via the route
# decorator above). Just give it a small dict-returning wrapper.

@app.post("/api/cams/{ch}/stop")
def api_stop(ch: int) -> dict:
    _stop(ch)
    return {"status": "stopped"}


@app.post("/api/cams/start_all")
def api_start_all() -> dict:
    """Spawn ALL live channels in parallel. Doesn't wait per-channel."""
    j = api_cams()
    chans = [c["channel"] for c in j["cams"]]
    # Spawn all in parallel (each is a non-blocking Popen).
    for ch in chans:
        _spawn_only(ch)
    # Wait once for *any* segment to appear (up to ~10 s), so first-paint
    # latency in the browser is reasonable. Channels with no segment yet
    # are returned with status=starting; hls.js retries until ffmpeg writes.
    deadline = time.time() + 10
    while time.time() < deadline:
        if any((HLS_DIR / f"cam{ch}" / "index.m3u8").exists()
               and any((HLS_DIR / f"cam{ch}").glob("*.ts"))
               for ch in chans):
            break
        time.sleep(0.2)
    out = []
    for ch in chans:
        cam_dir = HLS_DIR / f"cam{ch}"
        ready = (cam_dir / "index.m3u8").exists() and any(cam_dir.glob("*.ts"))
        out.append({
            "channel": ch,
            "status": "started" if ready else "starting",
            "playlist": f"/hls/cam{ch}/index.m3u8",
        })
    return {"started": out}


@app.post("/api/cams/stop_all")
def api_stop_all() -> dict:
    for ch in list(_procs):
        _stop(ch)
    return {"status": "stopped all"}


# ---------- HLS file serving ----------

@app.get("/hls/cam{ch}/{filename}")
def serve_hls(ch: int, filename: str):
    cam_dir, _ = _hls_paths(ch)
    fpath = cam_dir / filename
    if not fpath.exists():
        raise HTTPException(404, "not found")
    # Update presence so the idle watchdog knows somebody is watching
    _last_seen[ch] = time.time()
    media_type = ("application/vnd.apple.mpegurl" if filename.endswith(".m3u8")
                  else "video/mp2t" if filename.endswith(".ts")
                  else "application/octet-stream")
    headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Access-Control-Allow-Origin": "*",
    }
    return FileResponse(fpath, media_type=media_type, headers=headers)


# ---------- Static index ----------

@app.get("/")
def index():
    return FileResponse(APP_DIR / "static" / "index.html")


app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8766, reload=False,
                log_level="info")
