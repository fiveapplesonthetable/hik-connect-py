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

// ---- Minimal ambient declarations for hls.js (loaded via CDN) ----

interface HlsConfig {
  lowLatencyMode: boolean;
  liveSyncDuration: number;
  maxBufferLength: number;
  manifestLoadingMaxRetry: number;
  manifestLoadingRetryDelay: number;
  manifestLoadingMaxRetryTimeout: number;
  levelLoadingMaxRetry: number;
  levelLoadingRetryDelay: number;
  fragLoadingMaxRetry: number;
  fragLoadingRetryDelay: number;
}

interface HlsErrorData {
  fatal: boolean;
  type: string;
  details: string;
}

interface HlsEvents {
  readonly ERROR: string;
  readonly FRAG_LOADED: string;
  readonly MEDIA_ATTACHED: string;
}

interface HlsErrorTypes {
  readonly MEDIA_ERROR: string;
  readonly NETWORK_ERROR: string;
}

declare class Hls {
  static isSupported(): boolean;
  static readonly Events: HlsEvents;
  static readonly ErrorTypes: HlsErrorTypes;

  constructor(config?: Partial<HlsConfig>);
  loadSource(src: string): void;
  attachMedia(media: HTMLVideoElement): void;
  destroy(): void;
  recoverMediaError(): void;
  on(event: string, cb: (event: string, data: HlsErrorData) => void): void;
}

// Augment the <video> element with our Hls handle so we don't need a
// WeakMap (and so we can detach on rebuild).
interface HTMLVideoElement {
  hlsInstance: Hls | null;
}

// ---- API contract (matches server.py) ----

interface CamInfo {
  channel: number;
  running: boolean;
  playlist: string | null;
  uptime_s: number;
}

interface CamsResponse {
  cams: CamInfo[];
  probed_at: number;
}

// ---- DOM helpers ----

function qs<E extends Element>(sel: string, root: ParentNode = document): E {
  const el = root.querySelector(sel);
  if (el === null) throw new Error(`element not found: ${sel}`);
  return el as E;
}

async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path} → HTTP ${r.toString()}`);
  return (await r.json()) as T;
}

// ---- HLS attach/detach ----

function attachHls(videoEl: HTMLVideoElement, playlistPath: string): void {
  if (videoEl.hlsInstance !== null) {
    videoEl.hlsInstance.destroy();
    videoEl.hlsInstance = null;
  }

  // The browser will 404 on the playlist for up to ~10 s while ffmpeg is
  // still producing the first segment. Retry generously and rebuild the Hls
  // instance on fatal network errors so the wait survives.
  let attempt = 0;
  const attach = (): void => {
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
      h.on(Hls.Events.ERROR, (_event: string, data: HlsErrorData): void => {
        if (!data.fatal) return;
        console.warn('[hls] fatal', data.type, data.details);
        if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
          try { h.recoverMediaError(); } catch { /* ignore */ }
        } else if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
          h.destroy();
          videoEl.hlsInstance = null;
          if (attempt < 60) window.setTimeout(attach, 2000);
        }
      });
      // Backup .play() after first segment lands — covers the case where
      // the initial gesture-bound play() got rejected because MSE had no
      // data yet.
      h.on(Hls.Events.FRAG_LOADED, (): void => {
        if (videoEl.paused) videoEl.play().catch(() => { /* autoplay blocked */ });
      });
      h.loadSource(src);
      h.attachMedia(videoEl);
      videoEl.hlsInstance = h;
    } else if (videoEl.canPlayType('application/vnd.apple.mpegurl') !== '') {
      // Safari / iOS native HLS — no hls.js needed.
      videoEl.src = src;
    }
    videoEl.muted = true; // HLS path is video-only — always muted.
    videoEl.play().catch(() => { /* autoplay blocked */ });
  };
  attach();
}

function detach(videoEl: HTMLVideoElement): void {
  if (videoEl.hlsInstance !== null) {
    videoEl.hlsInstance.destroy();
    videoEl.hlsInstance = null;
  }
  videoEl.removeAttribute('src');
  videoEl.load();
}

// ---- Card state ----

const watching = new Set<number>();
const cardByChannel = new Map<number, HTMLDivElement>();

function setCardLive(card: HTMLDivElement, live: boolean): void {
  card.classList.toggle('live', live);
  const badge = qs<HTMLSpanElement>('.badge', card);
  const btn = qs<HTMLButtonElement>('.toggle', card);
  const overlay = qs<HTMLDivElement>('.overlay', card);
  badge.textContent = live ? 'LIVE' : 'IDLE';
  btn.textContent = live ? 'stop' : 'start';
  btn.title = live ? 'stop' : 'start';
  if (live) {
    overlay.classList.remove('hidden');
    overlay.classList.add('loading');
    overlay.innerHTML = '<div class="spinner"></div><span>buffering…</span>';
  } else {
    overlay.classList.remove('hidden', 'loading');
    overlay.innerHTML = '<span>click start</span>';
  }
}

function startOne(channel: number): void {
  const card = cardByChannel.get(channel);
  if (card === undefined) return;
  watching.add(channel);
  setCardLive(card, true);
  attachHls(qs<HTMLVideoElement>('video', card), `/hls/cam${channel.toString()}/index.m3u8`);
  // Server spawn is fire-and-forget; hls.js retries the manifest until
  // ffmpeg writes it. Must NOT be awaited here — see big comment at top.
  void api(`/api/cams/${channel.toString()}/start`, { method: 'POST' });
}

async function stopOne(channel: number): Promise<void> {
  const card = cardByChannel.get(channel);
  if (card === undefined) return;
  watching.delete(channel);
  detach(qs<HTMLVideoElement>('video', card));
  setCardLive(card, false);
  await api(`/api/cams/${channel.toString()}/stop`, { method: 'POST' });
}

// ---- Card factory ----

function makeCard(cam: CamInfo, fsVid: HTMLVideoElement, fsLabel: HTMLElement,
                  fs: HTMLDivElement): HTMLDivElement {
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
  const vid = qs<HTMLVideoElement>('video', card);
  vid.hlsInstance = null;
  const btn = qs<HTMLButtonElement>('.toggle', card);
  const player = qs<HTMLDivElement>('.player', card);
  const overlay = qs<HTMLDivElement>('.overlay', card);

  vid.addEventListener('playing', () => { overlay.classList.add('hidden'); });
  vid.addEventListener('waiting', () => {
    if (watching.has(cam.channel)) overlay.classList.remove('hidden');
  });

  btn.addEventListener('click', (e: MouseEvent) => {
    e.stopPropagation();
    btn.disabled = true;
    if (watching.has(cam.channel)) {
      void stopOne(cam.channel).finally(() => { btn.disabled = false; });
    } else {
      startOne(cam.channel);                 // sync — gesture preserved
      btn.disabled = false;
    }
  });

  player.addEventListener('click', () => {
    if (!watching.has(cam.channel)) return;
    fsLabel.textContent = `Channel ${cam.channel.toString()}`;
    attachHls(fsVid, `/hls/cam${cam.channel.toString()}/index.m3u8`);
    fsVid.muted = true;
    fs.classList.remove('hidden');
    fs.focus();
  });

  return card;
}

// ---- Grid load + top-bar wiring ----

async function main(): Promise<void> {
  const grid = qs<HTMLElement>('#grid');
  const fs = qs<HTMLDivElement>('#fullscreen');
  const fsVid = qs<HTMLVideoElement>('#fs-video');
  fsVid.hlsInstance = null;
  const fsLabel = qs<HTMLDivElement>('#fs-label');
  const startAllBtn = qs<HTMLButtonElement>('#start-all');
  const stopAllBtn = qs<HTMLButtonElement>('#stop-all');
  const refreshBtn = qs<HTMLButtonElement>('#refresh');
  const deviceLabel = qs<HTMLSpanElement>('#device-label');
  const fsCloseBtn = qs<HTMLButtonElement>('.close', fs);

  async function loadGrid(): Promise<void> {
    const data = await api<CamsResponse>('/api/cams');
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
      attachHls(qs<HTMLVideoElement>('video', card), `/hls/cam${ch.toString()}/index.m3u8`);
    }
    void api('/api/cams/start_all', { method: 'POST' })
      .finally(() => { startAllBtn.disabled = false; });
  });

  stopAllBtn.addEventListener('click', () => {
    stopAllBtn.disabled = true;
    for (const ch of Array.from(watching)) {
      const card = cardByChannel.get(ch);
      if (card !== undefined) {
        detach(qs<HTMLVideoElement>('video', card));
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
  fs.addEventListener('keydown', (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      detach(fsVid);
      fs.classList.add('hidden');
    }
  });

  await loadGrid();
}

void main();
