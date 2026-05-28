"use strict";
// hik-viewer front-end. Strict TypeScript.
//
// Loaded after hls.min.js via a <script> tag in index.html. Compiled to
// ../app/static/app.js (committed to the repo) with `npm run build` from
// hik-viewer/web/. No bundler; this is a single-file script module so the
// runtime can load it directly without a server-side build step.
//
// Architecture, briefly:
//
//   browser ─── GET /hls/cam{ch}/index.m3u8 ───►  FastAPI (server.py)
//                                                      │
//                                                      ▼
//                                                hik.py ffmpeg
//                                                (RTP demux → H.264 NALs
//                                                 → ffmpeg HLS muxer
//                                                 → index.m3u8 + segN.ts)
//
//   browser ─◄─ HLS playlist + 2 s .ts segments ─◄─
//   hls.js attaches the playlist to MediaSource Extensions and feeds the
//   <video> element. Latency: ~4–6 s.
//
// The client tracks one Set<channel> (`watching`) and one Map<channel, card>
// (`cardByChannel`). Cards never auto-start; the user explicitly clicks
// "start all" or a per-card start button. We attach HLS *synchronously*
// inside the click handler so the muted-autoplay gesture context is
// preserved — async-awaiting a fetch before .play() makes Chrome treat the
// call as non-gestured and blocks it.
// ---- DOM helpers ----
function qs(sel, root = document) {
    const el = root.querySelector(sel);
    if (el === null)
        throw new Error(`element not found: ${sel}`);
    return el;
}
async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok)
        throw new Error(`${path} → HTTP ${r.toString()}`);
    return (await r.json());
}
// ---- HLS attach/detach ----
function attachHls(videoEl, playlistPath) {
    if (videoEl.hlsInstance !== null) {
        videoEl.hlsInstance.destroy();
        videoEl.hlsInstance = null;
    }
    // The browser will 404 on the playlist for up to ~10 s while ffmpeg is
    // still producing the first segment. Retry generously and rebuild the Hls
    // instance on fatal network errors so the wait survives.
    let attempt = 0;
    const attach = () => {
        attempt += 1;
        const src = `${playlistPath}?t=${Date.now().toString()}`;
        if (Hls.isSupported()) {
            const h = new Hls({
                lowLatencyMode: false,
                liveSyncDuration: 4,
                maxBufferLength: 20,
                manifestLoadingMaxRetry: 30,
                manifestLoadingRetryDelay: 1000,
                manifestLoadingMaxRetryTimeout: 30000,
                levelLoadingMaxRetry: 30,
                levelLoadingRetryDelay: 1000,
                fragLoadingMaxRetry: 30,
                fragLoadingRetryDelay: 1000,
            });
            h.on(Hls.Events.ERROR, (_event, data) => {
                if (!data.fatal)
                    return;
                console.warn('[hls] fatal', data.type, data.details);
                if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
                    try {
                        h.recoverMediaError();
                    }
                    catch { /* ignore */ }
                }
                else if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
                    h.destroy();
                    videoEl.hlsInstance = null;
                    if (attempt < 60)
                        window.setTimeout(attach, 2000);
                }
            });
            // Backup .play() after first segment lands — covers the case where
            // the initial gesture-bound play() got rejected because MSE had no
            // data yet.
            h.on(Hls.Events.FRAG_LOADED, () => {
                if (videoEl.paused)
                    videoEl.play().catch(() => { });
            });
            h.loadSource(src);
            h.attachMedia(videoEl);
            videoEl.hlsInstance = h;
        }
        else if (videoEl.canPlayType('application/vnd.apple.mpegurl') !== '') {
            // Safari / iOS native HLS — no hls.js needed.
            videoEl.src = src;
        }
        videoEl.muted = true; // HLS path is video-only — always muted.
        videoEl.play().catch(() => { });
    };
    attach();
}
function detach(videoEl) {
    if (videoEl.hlsInstance !== null) {
        videoEl.hlsInstance.destroy();
        videoEl.hlsInstance = null;
    }
    videoEl.removeAttribute('src');
    videoEl.load();
}
// ---- Card state ----
const watching = new Set();
const cardByChannel = new Map();
function setCardLive(card, live) {
    card.classList.toggle('live', live);
    const badge = qs('.badge', card);
    const btn = qs('.toggle', card);
    const overlay = qs('.overlay', card);
    badge.textContent = live ? 'LIVE' : 'IDLE';
    btn.textContent = live ? 'stop' : 'start';
    btn.title = live ? 'stop' : 'start';
    if (live) {
        overlay.classList.remove('hidden');
        overlay.classList.add('loading');
        overlay.innerHTML = '<div class="spinner"></div><span>buffering…</span>';
    }
    else {
        overlay.classList.remove('hidden', 'loading');
        overlay.innerHTML = '<span>click start</span>';
    }
}
function startOne(channel) {
    const card = cardByChannel.get(channel);
    if (card === undefined)
        return;
    watching.add(channel);
    setCardLive(card, true);
    attachHls(qs('video', card), `/hls/cam${channel.toString()}/index.m3u8`);
    // Server spawn is fire-and-forget; hls.js retries the manifest until
    // ffmpeg writes it. Must NOT be awaited here — see big comment at top.
    void api(`/api/cams/${channel.toString()}/start`, { method: 'POST' });
}
async function stopOne(channel) {
    const card = cardByChannel.get(channel);
    if (card === undefined)
        return;
    watching.delete(channel);
    detach(qs('video', card));
    setCardLive(card, false);
    await api(`/api/cams/${channel.toString()}/stop`, { method: 'POST' });
}
// ---- Card factory ----
function makeCard(cam, fsVid, fsLabel, fs) {
    const card = document.createElement('div');
    card.className = 'cam';
    card.dataset['channel'] = cam.channel.toString();
    const padded = cam.channel.toString().padStart(2, '0');
    card.innerHTML = `
    <div class="meta">
      <span class="badge">IDLE</span>
      <span class="title">ch ${padded}</span>
      <span class="uptime"></span>
      <button class="toggle" title="start">start</button>
    </div>
    <div class="player">
      <video muted autoplay playsinline></video>
      <div class="overlay"><span>click start</span></div>
    </div>
  `;
    const vid = qs('video', card);
    vid.hlsInstance = null;
    const btn = qs('.toggle', card);
    const player = qs('.player', card);
    const overlay = qs('.overlay', card);
    vid.addEventListener('playing', () => { overlay.classList.add('hidden'); });
    vid.addEventListener('waiting', () => {
        if (watching.has(cam.channel))
            overlay.classList.remove('hidden');
    });
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        btn.disabled = true;
        if (watching.has(cam.channel)) {
            void stopOne(cam.channel).finally(() => { btn.disabled = false; });
        }
        else {
            startOne(cam.channel); // sync — gesture preserved
            btn.disabled = false;
        }
    });
    player.addEventListener('click', () => {
        if (!watching.has(cam.channel))
            return;
        fsLabel.textContent = `Channel ${cam.channel.toString()}`;
        attachHls(fsVid, `/hls/cam${cam.channel.toString()}/index.m3u8`);
        fsVid.muted = true;
        fs.classList.remove('hidden');
        fs.focus();
    });
    return card;
}
// ---- Grid load + top-bar wiring ----
async function main() {
    const grid = qs('#grid');
    const fs = qs('#fullscreen');
    const fsVid = qs('#fs-video');
    fsVid.hlsInstance = null;
    const fsLabel = qs('#fs-label');
    const startAllBtn = qs('#start-all');
    const stopAllBtn = qs('#stop-all');
    const refreshBtn = qs('#refresh');
    const deviceLabel = qs('#device-label');
    const fsCloseBtn = qs('.close', fs);
    async function loadGrid() {
        const data = await api('/api/cams');
        deviceLabel.textContent = `${data.cams.length.toString()} channels`;
        grid.innerHTML = '';
        cardByChannel.clear();
        if (data.cams.length === 0) {
            grid.innerHTML = '<p class="empty">No cameras. Run <code>hik.py login</code> + <code>hik.py probe</code> first.</p>';
            return;
        }
        for (const cam of data.cams) {
            const card = makeCard(cam, fsVid, fsLabel, fs);
            grid.appendChild(card);
            cardByChannel.set(cam.channel, card);
        }
    }
    startAllBtn.addEventListener('click', () => {
        startAllBtn.disabled = true;
        // Attach inside the gesture context — autoplay-policy critical.
        for (const [ch, card] of cardByChannel) {
            watching.add(ch);
            setCardLive(card, true);
            attachHls(qs('video', card), `/hls/cam${ch.toString()}/index.m3u8`);
        }
        void api('/api/cams/start_all', { method: 'POST' })
            .finally(() => { startAllBtn.disabled = false; });
    });
    stopAllBtn.addEventListener('click', () => {
        stopAllBtn.disabled = true;
        for (const ch of Array.from(watching)) {
            const card = cardByChannel.get(ch);
            if (card !== undefined) {
                detach(qs('video', card));
                setCardLive(card, false);
            }
        }
        watching.clear();
        void api('/api/cams/stop_all', { method: 'POST' })
            .finally(() => { stopAllBtn.disabled = false; });
    });
    refreshBtn.addEventListener('click', () => { void loadGrid(); });
    fsCloseBtn.addEventListener('click', () => {
        detach(fsVid);
        fs.classList.add('hidden');
    });
    fs.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            detach(fsVid);
            fs.classList.add('hidden');
        }
    });
    await loadGrid();
}
void main();
//# sourceMappingURL=app.js.map