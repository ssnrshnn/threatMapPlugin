/* Threat Map for BunkerWeb: page logic (included inline by template.html).
 *
 * Two stacked canvases: "base" holds the static world (globe outline, graticule,
 * land dots coloured by attack intensity) and is only redrawn when the data or the
 * size changes; "fx" is cleared and redrawn every animation frame (arcs, ripples,
 * hover / selection overlays, home beacon). Glows are pre-rendered sprites blended
 * with "lighter" instead of shadowBlur, which keeps a full map of arcs at 60 fps.
 */
(() => {
  "use strict";

  const root = document.getElementById("threatmap-root");
  if (!root || root.dataset.tmReady) return;
  root.dataset.tmReady = "1";

  /* ================================================================ config */
  const POLL_MS = 10000;
  const POLL_MAX_MS = 60000;
  const OVERLAP_S = 120; // re-ask for the last 2 minutes: other instances sync their reports late
  const MAX_ARCS = 90;
  const MAX_FEED = 60;
  const MAX_DPR = 2;
  const ARC_STEPS = 48;
  const WINDOW_LABELS = { 0: "entire buffer", 3600: "last hour", 86400: "last 24 hours", 604800: "last 7 days" };
  const DURATIONS = [
    ["1 hour", 3600],
    ["24 hours", 86400],
    ["7 days", 604800],
    ["30 days", 2592000],
    ["Permanent", 0],
  ];
  // Reason colours: identity, fixed per reason (never by rank). The most common
  // reasons take the three hues that stay apart for colour-blind readers too
  // (orange, blue, aqua); reason names are always shown next to the colour.
  const REASON_COLORS = {
    modsecurity: "#d95926",
    "modsecurity-body": "#d95926",
    coraza: "#d95926",
    badbehavior: "#3987e5",
    "bad behavior": "#3987e5",
    limit: "#199e70",
    blacklist: "#c98500",
    greylist: "#c98500",
    dnsbl: "#c98500",
    country: "#d55181",
    bunkernet: "#d55181",
    crowdsec: "#d55181",
    reversescan: "#d55181",
    antibot: "#9085e9",
    cors: "#9085e9",
    authbasic: "#9085e9",
    "threat map": "#8a94a3",
    manual: "#8a94a3",
    ui: "#8a94a3",
    unknown: "#8a94a3",
  };
  const HASH_PALETTE = ["#9085e9", "#d55181", "#c98500", "#e66767"];
  const SERVICE_COLOR = "#3987e5";
  const BLOCKED_COLOR = "#e5484d";
  const DETECTED_COLOR = "#f5a524";
  // Land and countries: one hue, from barely-there to bright as attacks grow.
  const LAND_RGB = [112, 150, 186];
  const RAMP = [
    [96, 30, 54],
    [164, 38, 64],
    [228, 52, 74],
    [255, 86, 92],
    [255, 146, 132],
  ];
  const HOME_RGB = [46, 182, 125];
  const FONT = (getComputedStyle(root).fontFamily || "").trim() || "system-ui, sans-serif";

  /* =============================================================== helpers */
  const $ = (id) => document.getElementById(id);
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);
  const fmt = (n) => Number(n || 0).toLocaleString();
  const rgba = (rgb, a) => "rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + "," + a.toFixed(3) + ")";
  const TAU = Math.PI * 2;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function parseJSON(id) {
    const node = $(id);
    if (!node) return null;
    try {
      return JSON.parse(node.textContent || "null");
    } catch (e) {
      return null;
    }
  }

  function hexToRgb(hex) {
    const h = hex.replace("#", "");
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
  }

  function hashString(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  const colorCache = new Map();
  function reasonColor(reason) {
    const key = String(reason || "unknown").toLowerCase();
    let color = colorCache.get(key);
    if (color) return color;
    color = REASON_COLORS[key];
    if (!color) {
      const prefix = Object.keys(REASON_COLORS).find((k) => k.length > 3 && key.indexOf(k) === 0);
      color = prefix ? REASON_COLORS[prefix] : HASH_PALETTE[hashString(key) % HASH_PALETTE.length];
    }
    colorCache.set(key, color);
    return color;
  }

  const mapColors = new Map();
  function mapColor(hex) {
    let c = mapColors.get(hex);
    if (c) return c;
    const rgb = hexToRgb(hex).map((v) => Math.round(v + (255 - v) * 0.3));
    c = "#" + rgb.map((v) => (v < 16 ? "0" : "") + v.toString(16)).join("");
    mapColors.set(hex, c);
    return c;
  }

  const rampCss = () =>
    "linear-gradient(90deg, " + RAMP.map((c, i) => "rgb(" + c.join(",") + ") " + Math.round((i / (RAMP.length - 1)) * 100) + "%").join(", ") + ")";

  function rampColor(t) {
    const x = clamp(t, 0, 1) * (RAMP.length - 1);
    const i = Math.min(RAMP.length - 2, Math.floor(x));
    const k = x - i;
    return RAMP[i].map((v, j) => Math.round(v + (RAMP[i + 1][j] - v) * k));
  }

  let regionNames = null;
  try {
    regionNames = new Intl.DisplayNames([document.documentElement.lang || navigator.language || "en", "en"], { type: "region" });
  } catch (e) {
    regionNames = null;
  }

  function countryName(cc) {
    if (cc === "LOCAL") return "Private network";
    if (cc === "UNKNOWN") return "Unknown origin";
    if (!/^[A-Z]{2}$/.test(cc)) return String(cc);
    try {
      return (regionNames && regionNames.of(cc)) || cc;
    } catch (e) {
      return cc;
    }
  }

  const pad2 = (n) => (n < 10 ? "0" : "") + n;
  function timeLabel(ts) {
    const d = new Date(ts * 1000);
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
  }
  function dateLabel(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + pad2(d.getHours()) + ":" + pad2(d.getMinutes());
  }
  function ago(ts) {
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return Math.round(s) + "s ago";
    if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  }

  const flagsInput = $("base_flags_url");
  const flagsUrl = flagsInput ? flagsInput.value : "";
  function flagImg(cc, w, h) {
    if (!flagsUrl || !/^[A-Z]{2}$/.test(cc)) {
      const blank = el("span", "tm-flag tm-flag-blank");
      blank.style.width = w + "px";
      blank.style.height = h + "px";
      return blank;
    }
    const img = el("img", "tm-flag");
    img.src = flagsUrl + "/" + cc.toLowerCase() + ".svg";
    img.width = w;
    img.height = h;
    img.alt = "";
    img.decoding = "async";
    img.addEventListener(
      "error",
      () => {
        img.src = flagsUrl + "/zz.svg";
      },
      { once: true },
    );
    return img;
  }

  let REDUCED = false;
  const motionQuery = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  if (motionQuery) {
    REDUCED = motionQuery.matches;
    if (motionQuery.addEventListener) motionQuery.addEventListener("change", (e) => (REDUCED = e.matches));
  }

  /* ================================================================== geo */
  const GEO = parseJSON("threatmap-geo");
  const wrap = $("tm-canvas-wrap");
  const baseCanvas = $("tm-canvas-base");
  const fxCanvas = $("tm-canvas-fx");
  if (!GEO || !GEO.cells || !wrap || !baseCanvas || !fxCanvas) return;

  const COLS = GEO.cols;
  const ROWS = GEO.rows;
  const BX0 = GEO.bounds[0];
  const BY0 = GEO.bounds[1];
  const BX1 = GEO.bounds[2];
  const BY1 = GEO.bounds[3];
  const ASPECT = (BX1 - BX0) / (BY1 - BY0);
  const LAT_MIN = GEO.lat[0];
  const LAT_MAX = GEO.lat[1];
  const CODES = GEO.codes; // cell value v > 0 -> CODES[v - 1]; CODES[0] is land without ISO code
  const codeValue = new Map(CODES.map((cc, i) => [cc, i + 1]));

  // Cells: run-length encoded LEB128 varint pairs (value, run).
  const cellCode = new Uint8Array(COLS * ROWS);
  (() => {
    const bin = atob(GEO.cells);
    let i = 0;
    let pos = 0;
    const read = () => {
      let n = 0;
      let mul = 1;
      let b;
      do {
        b = bin.charCodeAt(i++);
        n += (b & 0x7f) * mul;
        mul *= 128;
      } while (b & 0x80);
      return n;
    };
    while (i < bin.length) {
      const value = read();
      const run = read();
      cellCode.fill(value, pos, pos + run);
      pos += run;
    }
  })();

  const dotIdx = [];
  for (let i = 0; i < cellCode.length; i++) if (cellCode[i]) dotIdx.push(i);
  const DOTS = dotIdx.length;
  const dotU = new Float32Array(DOTS);
  const dotV = new Float32Array(DOTS);
  const dotVal = new Uint8Array(DOTS);
  const dotsByValue = new Map();
  dotIdx.forEach((cell, i) => {
    const r = (cell / COLS) | 0;
    const c = cell - r * COLS;
    dotU[i] = (c + 0.5 + (r & 1 ? 0.5 : 0)) / COLS;
    dotV[i] = (r + 0.5) / ROWS;
    dotVal[i] = cellCode[cell];
    if (!dotsByValue.has(dotVal[i])) dotsByValue.set(dotVal[i], []);
    dotsByValue.get(dotVal[i]).push(i);
  });

  /* Natural Earth I projection (Savric et al. 2011), normalised to the grid bounds. */
  function projectUV(lon, lat) {
    const la = clamp(lat, LAT_MIN, LAT_MAX);
    const lam = (clamp(lon, -180, 180) * Math.PI) / 180;
    const phi = (la * Math.PI) / 180;
    const p2 = phi * phi;
    const p4 = p2 * p2;
    const x = lam * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * (0.003971 * p2 - 0.001529 * p4)));
    const y = phi * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4)));
    return [(x - BX0) / (BX1 - BX0), (BY1 - y) / (BY1 - BY0)];
  }

  const LABELS = {};
  Object.keys(GEO.labels || {}).forEach((cc) => {
    LABELS[cc] = projectUV(GEO.labels[cc][0], GEO.labels[cc][1]);
  });

  /* ================================================================ state */
  let DATA = parseJSON("threatmap-bootstrap") || {};
  if (DATA.error) DATA = {};
  const emptyStats = () => ({ total: 0, blocked: 0, detected: 0, unique_ips: 0, countries: {}, reasons: {}, services: {}, top_ips: [] });
  const state = {
    home: DATA.home || { lat: 48.86, lon: 2.35, label: "BunkerWeb" },
    stats: DATA.stats || emptyStats(),
    stats24: DATA.stats24 || { total: 0, blocked: 0, detected: 0, unique_ips: 0, countries: 0, previous: null },
    histogram: DATA.histogram || null,
    coverage: DATA.coverage || null,
    labels: Object.assign({}, DATA.reason_labels || {}),
    maxEvents: DATA.max_events || 200,
    window: 0,
    events: (DATA.events || []).slice(),
    lastTs: 0,
    readOnly: false,
    offline: false,
    replayUntil: 0,
  };
  let homeUV = projectUV(state.home.lon, state.home.lat);
  const seen = new Map();

  const reasonLabel = (reason) => state.labels[reason] || reason;

  /* =============================================================== layout */
  const baseCtx = baseCanvas.getContext("2d");
  const fxCtx = fxCanvas.getContext("2d");
  const L = { W: 0, H: 0, dpr: 1, mapW: 0, mapH: 0, offX: 0, offY: 0, cell: 0, lw: 1.4, version: 0 };
  const sx = (u) => L.offX + u * L.mapW;
  const sy = (v) => L.offY + v * L.mapH;
  const countryPaths = new Map();
  let outline = null;
  let graticule = null;

  function layout() {
    const rect = wrap.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return false;
    const dpr = Math.min(MAX_DPR, window.devicePixelRatio || 1);
    L.W = rect.width;
    L.H = rect.height;
    L.dpr = dpr;
    [baseCanvas, fxCanvas].forEach((cv) => {
      cv.width = Math.round(L.W * dpr);
      cv.height = Math.round(L.H * dpr);
    });
    baseCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    fxCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const availW = L.W * 0.97;
    const availH = L.H * 0.94;
    if (availW / availH > ASPECT) {
      L.mapH = availH;
      L.mapW = availH * ASPECT;
    } else {
      L.mapW = availW;
      L.mapH = availW / ASPECT;
    }
    L.offX = (L.W - L.mapW) / 2;
    L.offY = (L.H - L.mapH) / 2;
    L.cell = L.mapW / COLS;
    L.lw = clamp(L.mapW / 720, 1.1, 2.4);
    L.version++;
    countryPaths.clear();
    outline = buildOutline();
    graticule = buildGraticule();
    return true;
  }

  function pt(path, lon, lat, move) {
    const uv = projectUV(lon, lat);
    if (move) path.moveTo(sx(uv[0]), sy(uv[1]));
    else path.lineTo(sx(uv[0]), sy(uv[1]));
  }

  function buildOutline() {
    const p = new Path2D();
    for (let lat = LAT_MIN; lat <= LAT_MAX; lat += 2) pt(p, -180, lat, lat === LAT_MIN);
    for (let lon = -180; lon <= 180; lon += 10) pt(p, lon, LAT_MAX);
    for (let lat = LAT_MAX; lat >= LAT_MIN; lat -= 2) pt(p, 180, lat);
    for (let lon = 180; lon >= -180; lon -= 10) pt(p, lon, LAT_MIN);
    p.closePath();
    return p;
  }

  function buildGraticule() {
    const p = new Path2D();
    for (let lon = -150; lon <= 150; lon += 30) {
      for (let lat = LAT_MIN; lat <= LAT_MAX; lat += 4) pt(p, lon, lat, lat === LAT_MIN);
    }
    [-30, 0, 30, 60].forEach((lat) => {
      pt(p, -180, lat, true);
      pt(p, 180, lat);
    });
    return p;
  }

  function dotRadius() {
    return Math.max(0.5, L.cell * 0.3);
  }

  function countryPath(cc) {
    let p = countryPaths.get(cc);
    if (p) return p;
    p = new Path2D();
    const r = Math.max(0.75, L.cell * 0.38);
    const idxs = dotsByValue.get(codeValue.get(cc)) || [];
    idxs.forEach((i) => {
      const x = sx(dotU[i]);
      const y = sy(dotV[i]);
      p.moveTo(x + r, y);
      p.arc(x, y, r, 0, TAU);
    });
    if (!idxs.length && LABELS[cc]) {
      const x = sx(LABELS[cc][0]);
      const y = sy(LABELS[cc][1]);
      p.moveTo(x + r * 1.5, y);
      p.arc(x, y, r * 1.5, 0, TAU);
    }
    countryPaths.set(cc, p);
    return p;
  }

  /* ============================================================ base layer */
  const intensity = new Float32Array(CODES.length + 1);

  // Share of the busiest country, on a gentle power scale: a country with half the
  // attacks of the top one stays clearly lighter, and any activity stays visible.
  function computeIntensity() {
    intensity.fill(0);
    const countries = state.stats.countries || {};
    let max = 0;
    Object.keys(countries).forEach((cc) => {
      if (codeValue.has(cc)) max = Math.max(max, countries[cc].total || 0);
    });
    if (!max) return;
    Object.keys(countries).forEach((cc) => {
      const v = codeValue.get(cc);
      if (v) intensity[v] = Math.max(0.06, Math.pow((countries[cc].total || 0) / max, 0.6));
    });
  }

  function topCountries(n, geolocatedOnly) {
    const countries = state.stats.countries || {};
    return Object.keys(countries)
      .filter((cc) => !geolocatedOnly || LABELS[cc])
      .map((cc) => [cc, countries[cc].total || 0, countries[cc].detected || 0])
      .sort((a, b) => b[1] - a[1])
      .slice(0, n);
  }

  function drawBase() {
    if (!L.W) return;
    const ctx = baseCtx;
    ctx.clearRect(0, 0, L.W, L.H);

    // Globe: a faint body, a hairline rim and a very quiet graticule
    const glow = ctx.createRadialGradient(sx(0.5), sy(0.42), 0, sx(0.5), sy(0.42), L.mapW * 0.6);
    glow.addColorStop(0, "rgba(52, 120, 178, 0.14)");
    glow.addColorStop(0.75, "rgba(36, 88, 132, 0.05)");
    glow.addColorStop(1, "rgba(36, 88, 132, 0.015)");
    ctx.fillStyle = glow;
    ctx.fill(outline);
    ctx.save();
    ctx.clip(outline);
    ctx.strokeStyle = "rgba(140, 186, 222, 0.055)";
    ctx.lineWidth = 0.75;
    ctx.stroke(graticule);
    ctx.restore();
    ctx.strokeStyle = "rgba(140, 186, 222, 0.14)";
    ctx.lineWidth = 1;
    ctx.stroke(outline);

    // A soft glow under the busiest countries only
    const top = topCountries(6, true);
    if (top.length && top[0][1] > 0) {
      ctx.save();
      ctx.globalCompositeOperation = "lighter";
      top.forEach((entry) => {
        const t = Math.pow(entry[1] / top[0][1], 0.6);
        const uv = LABELS[entry[0]];
        const x = sx(uv[0]);
        const y = sy(uv[1]);
        const radius = L.mapW * (0.025 + 0.035 * t);
        const g = ctx.createRadialGradient(x, y, 0, x, y, radius);
        g.addColorStop(0, rgba(rampColor(0.75), 0.05 + 0.08 * t));
        g.addColorStop(1, rgba(rampColor(0.75), 0));
        ctx.fillStyle = g;
        ctx.fillRect(x - radius, y - radius, radius * 2, radius * 2);
      });
      ctx.restore();
    }

    // Land dots: one path per colour step keeps fill-style switches to a dozen
    computeIntensity();
    const r = dotRadius();
    const STEPS = 12;
    const groups = [];
    for (let g = 0; g <= STEPS; g++) groups.push(new Path2D());
    for (let i = 0; i < DOTS; i++) {
      const t = intensity[dotVal[i]];
      const g = t > 0 ? Math.max(1, Math.round(t * STEPS)) : 0;
      const x = sx(dotU[i]);
      const y = sy(dotV[i]);
      const rr = g ? r * (1.12 + 0.12 * t) : r;
      groups[g].moveTo(x + rr, y);
      groups[g].arc(x, y, rr, 0, TAU);
    }
    ctx.fillStyle = rgba(LAND_RGB, 0.26);
    ctx.fill(groups[0]);
    for (let g = 1; g <= STEPS; g++) {
      ctx.fillStyle = rgba(rampColor(g / STEPS), 0.92);
      ctx.fill(groups[g]);
    }

    // Rings around active territories too small to show more than a dot or two
    topCountries(30, true).forEach((entry) => {
      const idxs = dotsByValue.get(codeValue.get(entry[0])) || [];
      if (idxs.length > 2) return;
      const uv = LABELS[entry[0]];
      ctx.strokeStyle = rgba(rampColor(intensity[codeValue.get(entry[0])] || 0.5), 0.8);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(sx(uv[0]), sy(uv[1]), Math.max(3, r * 3.2), 0, TAU);
      ctx.stroke();
    });
  }

  /* ============================================================== sprites */
  const sprites = new Map();
  function glowSprite(hex) {
    let s = sprites.get(hex);
    if (s) return s;
    const size = 64;
    s = document.createElement("canvas");
    s.width = size;
    s.height = size;
    const g = s.getContext("2d");
    const c = hexToRgb(hex);
    const grad = g.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    grad.addColorStop(0, "rgba(255,255,255,1)");
    grad.addColorStop(0.14, rgba(c, 0.95));
    grad.addColorStop(0.42, rgba(c, 0.26));
    grad.addColorStop(1, rgba(c, 0));
    g.fillStyle = grad;
    g.fillRect(0, 0, size, size);
    sprites.set(hex, s);
    return s;
  }

  function sprite(ctx, hex, x, y, radius, alpha) {
    ctx.globalAlpha = clamp(alpha, 0, 1);
    ctx.drawImage(glowSprite(hex), x - radius, y - radius, radius * 2, radius * 2);
  }

  /* ========================================================= arcs & effects */
  const arcs = [];
  const rings = [];
  const flashes = new Map(); // country -> start time
  const queue = []; // scheduled events {due, evt, feed, demo}
  let homeFlash = -1e9;
  let socHighlight = null;
  let hoverCC = null;
  let selectedCC = null;

  function spawnArc(evt, now) {
    const origin = LABELS[evt.country];
    if (!origin || !L.W) return false;
    if (arcs.length >= MAX_ARCS) arcs.shift();
    const color = mapColor(reasonColor(evt.reason));
    const jitter = 0.5 / COLS;
    arcs.push({
      u0: origin[0] + (Math.random() - 0.5) * jitter,
      v0: origin[1] + (Math.random() - 0.5) * jitter * ASPECT,
      color: color,
      rgb: hexToRgb(color),
      detect: evt.mode === "detect",
      start: now,
      dur: 0,
      pts: null,
      ver: -1,
      impacted: false,
    });
    if (!REDUCED) rings.push({ u: origin[0], v: origin[1], start: now, dur: 900, maxR: 12, rgb: hexToRgb(color), dashed: evt.mode === "detect" });
    flashes.set(evt.country, now);
    hideEmpty();
    return true;
  }

  function arcGeometry(a) {
    const x0 = sx(a.u0);
    const y0 = sy(a.v0);
    const x1 = sx(homeUV[0]);
    const y1 = sy(homeUV[1]);
    const dx = x1 - x0;
    const dy = y1 - y0;
    const dist = Math.hypot(dx, dy) || 1;
    let nx = -dy / dist;
    let ny = dx / dist;
    if (ny > 0) {
      nx = -nx;
      ny = -ny;
    }
    const lift = Math.min(dist * 0.3, L.mapH * 0.32) + L.mapH * 0.012;
    const cx = (x0 + x1) / 2 + nx * lift;
    const cy = (y0 + y1) / 2 + ny * lift;
    const pts = new Float32Array((ARC_STEPS + 1) * 2);
    for (let i = 0; i <= ARC_STEPS; i++) {
      const t = i / ARC_STEPS;
      const mt = 1 - t;
      pts[2 * i] = mt * mt * x0 + 2 * mt * t * cx + t * t * x1;
      pts[2 * i + 1] = mt * mt * y0 + 2 * mt * t * cy + t * t * y1;
    }
    a.pts = pts;
    a.ver = L.version;
    if (!a.dur) a.dur = 1300 + 1600 * Math.min(1, dist / L.mapW);
  }

  function pointAt(pts, t) {
    const f = clamp(t, 0, 1) * ARC_STEPS;
    const i = Math.min(ARC_STEPS - 1, Math.floor(f));
    const k = f - i;
    return [pts[2 * i] + (pts[2 * i + 2] - pts[2 * i]) * k, pts[2 * i + 1] + (pts[2 * i + 3] - pts[2 * i + 1]) * k];
  }

  function tracePath(ctx, pts, t0, t1) {
    const a = pointAt(pts, t0);
    const b = pointAt(pts, t1);
    ctx.beginPath();
    ctx.moveTo(a[0], a[1]);
    for (let i = Math.floor(t0 * ARC_STEPS) + 1; i <= Math.ceil(t1 * ARC_STEPS) - 1; i++) ctx.lineTo(pts[2 * i], pts[2 * i + 1]);
    ctx.lineTo(b[0], b[1]);
    return [a, b];
  }

  // returns false once the arc is finished
  function drawArc(ctx, a, now) {
    if (now < a.start) return true;
    if (a.ver !== L.version) arcGeometry(a);
    const p = (now - a.start) / a.dur;
    if (p >= 1) return false;

    if (REDUCED) {
      tracePath(ctx, a.pts, 0, 1);
      ctx.globalAlpha = 0.55 * Math.sin(p * Math.PI);
      ctx.strokeStyle = a.color;
      ctx.lineWidth = L.lw;
      if (a.detect) ctx.setLineDash([3, 4]);
      ctx.stroke();
      if (a.detect) ctx.setLineDash([]);
      ctx.globalAlpha = 1;
      return true;
    }

    const head = easeInOut(clamp(p / 0.68, 0, 1));
    const tail = easeInOut(clamp((p - 0.32) / 0.68, 0, 1));
    // faint contrail along the whole travelled path, fading as the arc completes
    if (head > 0.01) {
      tracePath(ctx, a.pts, 0, head);
      ctx.strokeStyle = rgba(a.rgb, 0.16 * (1 - easeOut(p)));
      ctx.lineWidth = L.lw * 0.8;
      if (a.detect) ctx.setLineDash([L.lw * 2.5, L.lw * 3]);
      ctx.stroke();
      if (a.detect) ctx.setLineDash([]);
    }
    if (head - tail > 0.002) {
      const ends = tracePath(ctx, a.pts, tail, head);
      const grad = ctx.createLinearGradient(ends[0][0], ends[0][1], ends[1][0], ends[1][1]);
      grad.addColorStop(0, rgba(a.rgb, 0));
      grad.addColorStop(0.65, rgba(a.rgb, 0.42));
      grad.addColorStop(1, rgba(a.rgb, 0.95));
      ctx.strokeStyle = grad;
      ctx.lineCap = "round";
      if (a.detect) ctx.setLineDash([L.lw * 2.5, L.lw * 3]);
      ctx.globalCompositeOperation = "lighter";
      ctx.globalAlpha = 0.22;
      ctx.lineWidth = L.lw * 3.2;
      ctx.stroke();
      ctx.globalCompositeOperation = "source-over";
      ctx.globalAlpha = 1;
      ctx.lineWidth = L.lw;
      ctx.stroke();
      if (a.detect) ctx.setLineDash([]);
    }
    if (head < 1) {
      const hp = pointAt(a.pts, head);
      ctx.globalCompositeOperation = "lighter";
      sprite(ctx, a.color, hp[0], hp[1], L.lw * (a.detect ? 3.5 : 5.5), a.detect ? 0.7 : 1);
      ctx.globalCompositeOperation = "source-over";
      ctx.globalAlpha = 1;
    } else if (!a.impacted) {
      a.impacted = true;
      rings.push({ u: homeUV[0], v: homeUV[1], start: now, dur: 750, maxR: a.detect ? 12 : 20, rgb: a.rgb, dashed: a.detect });
      if (!a.detect) homeFlash = now;
    }
    return true;
  }

  function drawRings(ctx, now) {
    for (let i = rings.length - 1; i >= 0; i--) {
      const ring = rings[i];
      const q = (now - ring.start) / ring.dur;
      if (q >= 1) {
        rings.splice(i, 1);
        continue;
      }
      if (q < 0) continue;
      ctx.strokeStyle = rgba(ring.rgb, 0.75 * (1 - q));
      ctx.lineWidth = L.lw * 0.9;
      if (ring.dashed) ctx.setLineDash([2, 3]);
      ctx.beginPath();
      ctx.arc(sx(ring.u), sy(ring.v), 2 + easeOut(q) * ring.maxR * clamp(L.mapW / 1100, 0.7, 1.6), 0, TAU);
      ctx.stroke();
      if (ring.dashed) ctx.setLineDash([]);
    }
  }

  function drawOverlays(ctx, now) {
    // Countries flashing because an attack just left them
    if (flashes.size) {
      ctx.globalCompositeOperation = "lighter";
      flashes.forEach((t, cc) => {
        const q = (now - t) / 1100;
        if (q >= 1) {
          flashes.delete(cc);
          return;
        }
        if (q < 0) return;
        ctx.fillStyle = "rgba(255, 214, 150," + (0.5 * (1 - easeOut(q))).toFixed(3) + ")";
        ctx.fill(countryPath(cc));
      });
      ctx.globalCompositeOperation = "source-over";
    }
    // Selected (drill-down) and SOC-highlighted countries pulse in gold
    const gold = [selectedCC, socHighlight && now < socHighlight.until ? socHighlight.cc : null];
    gold.forEach((cc) => {
      if (!cc || !LABELS[cc]) return;
      const pulse = REDUCED ? 0.75 : 0.6 + 0.3 * Math.sin(now / 320);
      ctx.fillStyle = "rgba(255, 209, 102," + pulse.toFixed(3) + ")";
      ctx.fill(countryPath(cc));
    });
    if (hoverCC && LABELS[hoverCC] && hoverCC !== selectedCC) {
      ctx.fillStyle = "rgba(235, 246, 255, 0.72)";
      ctx.fill(countryPath(hoverCC));
    }
  }

  function pill(ctx, x, y, w, h) {
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(x, y, w, h, h / 2);
    else ctx.rect(x, y, w, h);
  }

  function drawHome(ctx, now) {
    const x = sx(homeUV[0]);
    const y = sy(homeUV[1]);
    if (!REDUCED) {
      for (let k = 0; k < 2; k++) {
        const ph = (((now / 2800 + k / 2) % 1) + 1) % 1;
        ctx.strokeStyle = rgba(HOME_RGB, 0.45 * (1 - ph));
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(x, y, 5 + ph * 22, 0, TAU);
        ctx.stroke();
      }
    }
    const boost = clamp(1 - (now - homeFlash) / 600, 0, 1);
    ctx.globalCompositeOperation = "lighter";
    sprite(ctx, "#2eb67d", x, y, 11 + 9 * boost, 0.55 + 0.35 * boost);
    if (boost > 0) sprite(ctx, "#ff6b70", x, y, 16 * boost + 4, 0.5 * boost);
    ctx.globalCompositeOperation = "source-over";
    ctx.globalAlpha = 1;
    ctx.fillStyle = "#06121e";
    ctx.beginPath();
    ctx.arc(x, y, 4.6, 0, TAU);
    ctx.fill();
    ctx.fillStyle = "#2eb67d";
    ctx.beginPath();
    ctx.arc(x, y, 3.4, 0, TAU);
    ctx.fill();
    ctx.fillStyle = "#e9fff4";
    ctx.beginPath();
    ctx.arc(x, y, 1.3, 0, TAU);
    ctx.fill();

    const label = String(state.home.label || "");
    if (label) {
      ctx.font = "600 11px " + FONT;
      const w = ctx.measureText(label).width + 16;
      const h = 20;
      const lx = x + 14 + w > L.W - 6 ? x - 14 - w : x + 14;
      ctx.fillStyle = "rgba(6, 18, 30, 0.82)";
      ctx.strokeStyle = "rgba(46, 182, 125, 0.45)";
      ctx.lineWidth = 1;
      pill(ctx, lx, y - h / 2, w, h);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = "#e8f0f7";
      ctx.textBaseline = "middle";
      ctx.fillText(label, lx + 8, y + 0.5);
      ctx.textBaseline = "alphabetic";
    }
  }

  function drawSocLabel(ctx, now) {
    if (!socHighlight || now > socHighlight.until || !LABELS[socHighlight.cc]) return;
    const uv = LABELS[socHighlight.cc];
    const x = sx(uv[0]);
    const y = sy(uv[1]);
    const alpha = clamp((socHighlight.until - now) / 800, 0, 1) * clamp((now - socHighlight.from) / 400, 0, 1);
    ctx.font = "650 13px " + FONT;
    const nameW = ctx.measureText(socHighlight.name).width;
    ctx.font = "500 12px " + FONT;
    const countW = ctx.measureText(socHighlight.count).width;
    const w = nameW + countW + 34;
    const h = 28;
    const lx = x + 18 + w > L.W ? x - w - 18 : x + 18;
    ctx.globalAlpha = alpha;
    ctx.fillStyle = "rgba(6, 18, 30, 0.86)";
    ctx.strokeStyle = "rgba(255, 209, 102, 0.55)";
    ctx.lineWidth = 1;
    pill(ctx, lx, y - h / 2, w, h);
    ctx.fill();
    ctx.stroke();
    ctx.textBaseline = "middle";
    ctx.font = "650 13px " + FONT;
    ctx.fillStyle = "#ffe3a3";
    ctx.fillText(socHighlight.name, lx + 12, y + 0.5);
    ctx.font = "500 12px " + FONT;
    ctx.fillStyle = "#a7bbcc";
    ctx.fillText(socHighlight.count, lx + 22 + nameW, y + 0.5);
    ctx.textBaseline = "alphabetic";
    ctx.globalAlpha = 1;
  }

  /* ============================================================= scheduler */
  // Schedule a batch of events (oldest first) at their real relative timing: each gap
  // is clamped to [minGap, maxGap] so bursts stay readable and idle stretches are
  // trimmed, then the whole batch is compressed to fit maxSpread ms. Returns the
  // duration of the batch in ms.
  function scheduleEvents(list, opts) {
    if (!list.length) return 0;
    const now = performance.now();
    const minGap = (opts.minGap || 70) * 0.6;
    const maxGap = opts.maxGap || Infinity;
    const gaps = [0];
    for (let i = 1; i < list.length; i++) gaps.push(clamp((list[i].date - list[i - 1].date) * 1000, minGap, maxGap));
    const total = gaps.reduce((a, b) => a + b, 0);
    const scale = total > opts.maxSpread ? opts.maxSpread / total : 1;
    let due = now + (opts.startDelay || 250);
    list.forEach((evt, i) => {
      due += gaps[i] * scale;
      queue.push({ due: due, evt: evt, feed: !!opts.feed, demo: !!opts.demo });
    });
    queue.sort((a, b) => a.due - b.due);
    return due - now;
  }

  function frame(now) {
    requestAnimationFrame(frame);
    if (document.hidden || !L.W) return;
    while (queue.length && queue[0].due <= now) {
      const item = queue.shift();
      spawnArc(item.evt, now);
      if (item.feed) addFeedItem(item.evt, item.demo);
    }
    const ctx = fxCtx;
    ctx.clearRect(0, 0, L.W, L.H);
    drawOverlays(ctx, now);
    let w = 0;
    for (let i = 0; i < arcs.length; i++) {
      if (drawArc(ctx, arcs[i], now)) arcs[w++] = arcs[i];
    }
    arcs.length = w;
    drawRings(ctx, now);
    drawHome(ctx, now);
    drawSocLabel(ctx, now);
  }

  /* ================================================================== feed */
  const feedEl = $("tm-feed");
  const emptyEl = $("tm-empty");

  function hideEmpty() {
    if (emptyEl) emptyEl.classList.add("d-none");
  }

  function tag(text, color, cls) {
    const node = el("span", "tm-tag" + (cls ? " " + cls : ""), text);
    if (color) node.style.setProperty("--c", color);
    return node;
  }

  // Consecutive requests from the same address for the same reason are folded into
  // one row with a counter, so a scanner does not flush the whole feed.
  const feedKey = (evt, demo) => [evt.ip, evt.country, evt.reason, evt.service, evt.mode, demo ? 1 : 0].join("|");

  function feedItem(evt, demo, count) {
    const li = el("li");
    li.dataset.key = feedKey(evt, demo);
    li.dataset.count = String(count || 1);
    const detail = [evt.method, evt.url].filter(Boolean).join(" ");
    li.title = detail + (evt.status ? " → " + evt.status : "");
    li.appendChild(flagImg(evt.country, 22, 15));
    const ip = el("div", "tm-feed-ip");
    ip.appendChild(el("span", null, evt.ip));
    const counter = el("span", "tm-feed-count", "×" + fmt(count || 1));
    if (!count || count < 2) counter.hidden = true;
    ip.appendChild(counter);
    li.appendChild(ip);
    li.appendChild(el("span", "tm-feed-time", timeLabel(evt.date)));
    li.appendChild(el("div", "tm-feed-meta", countryName(evt.country) + " · " + (evt.service || "?")));
    const tags = el("div", "tm-tags");
    tags.appendChild(tag(reasonLabel(evt.reason), reasonColor(evt.reason)));
    if (evt.mode === "detect") tags.appendChild(tag("detect only", null, "tm-tag-detect"));
    if (demo) tags.appendChild(tag("demo", null, "tm-tag-demo"));
    li.appendChild(tags);
    return li;
  }

  function addFeedItem(evt, demo) {
    if (!feedEl) return;
    const placeholder = feedEl.querySelector(".tm-none");
    if (placeholder) placeholder.remove();
    const first = feedEl.firstElementChild;
    if (first && first.dataset.key === feedKey(evt, demo)) {
      const count = Number(first.dataset.count || 1) + 1;
      first.dataset.count = String(count);
      const counter = first.querySelector(".tm-feed-count");
      counter.textContent = "×" + fmt(count);
      counter.hidden = false;
      first.querySelector(".tm-feed-time").textContent = timeLabel(evt.date);
      first.classList.remove("tm-bump");
      void first.offsetWidth; // restart the highlight
      first.classList.add("tm-bump");
      return;
    }
    feedEl.insertBefore(feedItem(evt, demo), feedEl.firstChild);
    while (feedEl.children.length > MAX_FEED) feedEl.removeChild(feedEl.lastChild);
  }

  function rebuildFeed(events) {
    if (!feedEl) return;
    feedEl.textContent = "";
    if (!events.length) {
      feedEl.appendChild(el("li", "tm-none", "Nothing recorded in this window"));
      return;
    }
    // events are newest first: fold runs of identical requests
    const rows = [];
    events.forEach((evt) => {
      const last = rows[rows.length - 1];
      if (last && last.key === feedKey(evt)) last.count++;
      else rows.push({ key: feedKey(evt), evt: evt, count: 1 });
    });
    const frag = document.createDocumentFragment();
    rows.slice(0, MAX_FEED).forEach((row) => {
      const li = feedItem(row.evt, false, row.count);
      li.style.animation = "none";
      frag.appendChild(li);
    });
    feedEl.appendChild(frag);
  }

  /* ================================================================= stats */
  const counterState = {};
  function tween(id, value) {
    const node = $(id);
    if (!node) return;
    const to = Number(value) || 0;
    const from = counterState[id] === undefined ? 0 : counterState[id];
    counterState[id] = to;
    if (from === to || REDUCED) {
      node.textContent = fmt(to);
      return;
    }
    const start = performance.now();
    const step = (now) => {
      if (counterState[id] !== to) return; // superseded
      const q = clamp((now - start) / 700, 0, 1);
      node.textContent = fmt(Math.round(from + (to - from) * easeOut(q)));
      if (q < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function setSub(id, parts) {
    const node = $(id);
    if (!node) return;
    node.textContent = "";
    parts.forEach((part) => {
      if (typeof part === "string") node.appendChild(document.createTextNode(part));
      else node.appendChild(el("span", part[0], part[1]));
    });
    if (!parts.length) node.textContent = " ";
  }

  function windowLabel() {
    return WINDOW_LABELS[state.window] || "entire buffer";
  }

  // Small hourly area chart along the bottom edge of a stat card.
  function drawSpark(id, values, rgb) {
    const cv = $(id);
    if (!cv) return;
    const rect = cv.getBoundingClientRect();
    if (rect.width < 10 || rect.height < 10) return;
    const dpr = Math.min(MAX_DPR, window.devicePixelRatio || 1);
    cv.width = Math.round(rect.width * dpr);
    cv.height = Math.round(rect.height * dpr);
    const ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const pad = parseFloat(getComputedStyle(cv).paddingTop) || 0;
    const w = rect.width;
    const h = rect.height - pad;
    ctx.clearRect(0, 0, w, rect.height);
    if (!values || values.length < 2) return;
    const max = Math.max(1, Math.max.apply(null, values));
    const step = w / (values.length - 1);
    const y = (v) => pad + h - 2 - (v / max) * (h - 6);
    // smooth curve through the hourly points
    const curve = new Path2D();
    curve.moveTo(0, y(values[0]));
    for (let i = 1; i < values.length; i++) {
      const x0 = (i - 1) * step;
      const x1 = i * step;
      curve.bezierCurveTo(x0 + step / 2, y(values[i - 1]), x1 - step / 2, y(values[i]), x1, y(values[i]));
    }
    const area = new Path2D(curve);
    area.lineTo(w, rect.height);
    area.lineTo(0, rect.height);
    area.closePath();
    const fill = ctx.createLinearGradient(0, pad, 0, rect.height);
    fill.addColorStop(0, rgba(rgb, 0.26));
    fill.addColorStop(1, rgba(rgb, 0));
    ctx.fillStyle = fill;
    ctx.fill(area);
    ctx.strokeStyle = rgba(rgb, 0.95);
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke(curve);
    // the current hour
    ctx.fillStyle = rgba(rgb, 1);
    ctx.beginPath();
    ctx.arc(w - 3, y(values[values.length - 1]), 3, 0, TAU);
    ctx.fill();
  }

  function drawSparks() {
    const hourly = state.stats24.hourly;
    if (!hourly) return;
    drawSpark("tm-spark-24h", hourly.blocked, hexToRgb(BLOCKED_COLOR));
    drawSpark("tm-spark-ips", hourly.ips, hexToRgb(DETECTED_COLOR));
  }

  function segment(color, grow, title) {
    const seg = el("span");
    seg.style.background = color;
    seg.style.flexGrow = String(grow);
    seg.style.flexBasis = "0";
    if (title) seg.title = title;
    return seg;
  }

  function renderCards() {
    const s = state.stats;
    const d = state.stats24;
    tween("tm-count-24h", d.blocked);
    const sub24 = [];
    if (d.previous !== null && d.previous !== undefined) {
      const diff = d.total - d.previous;
      const pct = d.previous ? Math.round((Math.abs(diff) / d.previous) * 100) : null;
      if (diff === 0) sub24.push("same as the previous 24 h");
      else sub24.push([diff > 0 ? "tm-delta tm-up" : "tm-delta tm-down", (diff > 0 ? "▲ " : "▼ ") + (pct === null ? "new" : pct + "%")], "vs previous 24 h");
    } else if (d.detected) {
      sub24.push("+" + fmt(d.detected) + " detected only");
    } else {
      sub24.push("per hour, last 24 h");
    }
    setSub("tm-sub-24h", sub24);

    tween("tm-count-ips", d.unique_ips);
    setSub("tm-sub-ips", d.countries ? ["from " + fmt(d.countries) + (d.countries === 1 ? " country" : " countries")] : ["none in the last 24 h"]);

    const top = topCountries(1, false)[0];
    const origin = $("tm-top-origin");
    const share = top ? top[1] / Math.max(1, s.total) : 0;
    if (origin) {
      origin.textContent = "";
      if (top) {
        origin.appendChild(flagImg(top[0], 30, 21));
        origin.appendChild(el("span", null, countryName(top[0])));
      } else {
        origin.textContent = "–";
      }
    }
    setSub("tm-sub-origin", top ? [fmt(top[1]) + " requests · " + Math.round(share * 100) + "% of " + windowLabel()] : ["no attacks in " + windowLabel()]);
    const meter = $("tm-origin-meter");
    if (meter) meter.style.width = Math.round(share * 1000) / 10 + "%";

    tween("tm-count-total", s.total);
    const totalLabel = $("tm-label-total");
    if (totalLabel) totalLabel.textContent = windowLabel();
    setSub("tm-sub-total", [fmt(s.blocked) + " blocked · " + fmt(s.detected) + " detected only"]);
    const split = $("tm-split");
    if (split) {
      split.textContent = "";
      if (s.blocked) split.appendChild(segment(BLOCKED_COLOR, s.blocked, fmt(s.blocked) + " blocked"));
      if (s.detected) split.appendChild(segment(DETECTED_COLOR, s.detected, fmt(s.detected) + " detected only"));
    }
    drawSparks();
  }

  function buildBars(id, entries, total, opts) {
    const container = $(id);
    if (!container) return;
    container.textContent = "";
    if (!entries.length) {
      container.appendChild(el("p", "tm-none", "Nothing recorded in this window"));
      return;
    }
    const max = entries[0][1] || 1;
    entries.forEach((entry, i) => {
      const key = entry[0];
      const count = entry[1];
      const name = opts.name(key);
      const pct = Math.round((count / Math.max(1, total)) * 1000) / 10;
      const color = opts.color ? opts.color(key) : BLOCKED_COLOR;
      const row = el("div", "tm-bar-row");
      row.title = name + ": " + fmt(count) + " (" + pct + "%)";
      const label = el("span", "tm-bar-label");
      if (opts.rank) label.appendChild(el("span", "tm-rank", String(i + 1)));
      if (opts.flag) label.appendChild(flagImg(opts.flag(key), 20, 14));
      else {
        const sw = el("span", "tm-bar-swatch");
        sw.style.background = color;
        label.appendChild(sw);
      }
      label.appendChild(el("span", opts.mono ? "tm-mono" : null, name));
      const countEl = el("span", "tm-bar-count", fmt(count));
      countEl.appendChild(el("small", null, pct + "%"));
      const track = el("div", "tm-bar-track");
      const fill = el("div", "tm-bar-fill");
      fill.style.width = Math.max(1.5, (count / max) * 100) + "%";
      fill.style.background = color;
      track.appendChild(fill);
      row.appendChild(label);
      row.appendChild(countEl);
      row.appendChild(track);
      if (opts.onClick) {
        row.classList.add("tm-clickable");
        row.tabIndex = 0;
        row.setAttribute("role", "button");
        row.addEventListener("click", () => opts.onClick(key));
        row.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            opts.onClick(key);
          }
        });
      }
      container.appendChild(row);
    });
  }

  // 100% bar: the composition at a glance, above the ranked rows
  function buildMix(id, entries, color, name) {
    const node = $(id);
    if (!node) return;
    node.textContent = "";
    if (entries.length < 2) return;
    entries.slice(0, 8).forEach((entry, i) => {
      const seg = segment(color(entry[0], i), entry[1], name(entry[0]) + ": " + fmt(entry[1]));
      node.appendChild(seg);
    });
  }

  const sortedEntries = (obj, n) =>
    Object.keys(obj || {})
      .map((k) => [k, obj[k]])
      .sort((a, b) => b[1] - a[1])
      .slice(0, n);

  // shades of one hue for the services (they have no colour of their own)
  const serviceShade = (i) => rgba(hexToRgb(SERVICE_COLOR), Math.max(0.35, 1 - i * 0.16));

  function renderBreakdowns() {
    const s = state.stats;
    buildBars(
      "tm-top-countries",
      topCountries(10, false).map((e) => [e[0], e[1]]),
      s.total,
      { flag: (cc) => cc, rank: true, name: countryName, onClick: openCountry, color: () => BLOCKED_COLOR },
    );
    const attackers = s.top_ips || [];
    const attackerCountry = new Map(attackers.map((a) => [a.ip, a.country]));
    buildBars(
      "tm-top-ips",
      attackers.map((a) => [a.ip, a.count]),
      s.total,
      {
        flag: (ip) => attackerCountry.get(ip),
        rank: true,
        mono: true,
        name: (ip) => ip,
        onClick: (ip) => openCountry(attackerCountry.get(ip)),
        color: () => BLOCKED_COLOR,
      },
    );
    const reasons = sortedEntries(s.reasons, 10);
    buildMix("tm-mix-reasons", reasons, reasonColor, reasonLabel);
    buildBars("tm-top-reasons", reasons, s.total, { name: reasonLabel, color: reasonColor });
    const services = sortedEntries(s.services, 10);
    const shadeOf = new Map(services.map((e, i) => [e[0], serviceShade(i)]));
    buildMix(
      "tm-mix-services",
      services,
      (k) => shadeOf.get(k),
      (k) => k,
    );
    buildBars("tm-top-services", services, s.total, { name: (k) => k, color: (k) => shadeOf.get(k) });
  }

  function legendItem(swatch, text) {
    const item = el("span", "tm-legend-item");
    item.appendChild(swatch);
    item.appendChild(el("span", null, text));
    return item;
  }

  function renderLegend() {
    const legend = $("tm-legend");
    if (!legend) return;
    legend.textContent = "";
    const ramp = el("span", "tm-legend-ramp");
    ramp.style.background = rampCss();
    legend.appendChild(legendItem(ramp, "requests per country"));
    const reasons = sortedEntries(state.stats.reasons, 5);
    if (reasons.length) legend.appendChild(el("span", "tm-legend-sep"));
    reasons.forEach((entry) => {
      const swatch = el("span", "tm-legend-swatch");
      swatch.style.color = mapColor(reasonColor(entry[0]));
      legend.appendChild(legendItem(swatch, reasonLabel(entry[0])));
    });
    if (state.stats.detected) legend.appendChild(legendItem(el("span", "tm-legend-dash"), "detect only (not blocked)"));
  }

  function renderCoverage() {
    const node = $("tm-coverage");
    const c = state.coverage;
    if (!node || !c) return;
    let text;
    let warn = false;
    if (c.source === "redis") {
      text = "Redis · " + fmt(c.records) + " reports" + (c.oldest ? " since " + dateLabel(c.oldest) : "");
      if (c.full) {
        warn = true;
        text = "Redis buffer full (" + fmt(c.capacity) + ") · older reports dropped, data since " + dateLabel(c.oldest);
      }
    } else {
      text = "In-memory buffers · " + fmt(c.records) + " reports, cleared on reload (enable Redis to keep history)";
      warn = state.window >= 604800;
    }
    node.textContent = text;
    node.title = "Source of the data shown on this page";
    node.classList.toggle("tm-warn", warn);
  }

  function renderChips() {
    const chips = $("tm-fs-chips");
    if (!chips) return;
    chips.textContent = "";
    const top = topCountries(1, false)[0];
    [
      ["Blocked · 24 h", fmt(state.stats24.blocked)],
      ["Unique IPs · 24 h", fmt(state.stats24.unique_ips)],
      ["Top origin", top ? countryName(top[0]) : "–"],
      [windowLabel(), fmt(state.stats.total)],
    ].forEach((pair) => {
      const chip = el("div", "tm-chip");
      chip.appendChild(el("span", null, pair[0]));
      chip.appendChild(el("strong", null, pair[1]));
      chips.appendChild(chip);
    });
  }

  function renderAll() {
    renderCards();
    renderBreakdowns();
    renderLegend();
    renderCoverage();
    renderChips();
    if (emptyEl) emptyEl.classList.toggle("d-none", state.stats.total > 0 || demoTimer !== null || arcs.length > 0);
    drawBase();
    drawTimeline(-1);
    if (tlCaption) tlCaption.textContent = tlCaptionDefault();
    if (hoverCC) renderTooltip(hoverCC);
  }

  /* ============================================================== timeline */
  const tlCanvas = $("tm-timeline");
  const tlCtx = tlCanvas ? tlCanvas.getContext("2d") : null;
  const tlCaption = $("tm-tl-caption");

  function bucketRange(i) {
    const h = state.histogram;
    const a = h.start + i * h.bucket;
    const b = a + h.bucket;
    const sameDay = new Date(a * 1000).toDateString() === new Date(b * 1000).toDateString() && h.bucket < 86400;
    const t = (ts) => {
      const d = new Date(ts * 1000);
      return pad2(d.getHours()) + ":" + pad2(d.getMinutes());
    };
    return sameDay ? dateLabel(a) + "–" + t(b) : dateLabel(a) + " – " + dateLabel(b);
  }

  const TL = { left: 34, top: 6, bottom: 18, slot: 0 };

  function timeTick(ts, bucket) {
    const d = new Date(ts * 1000);
    if (bucket >= 86400) return d.toLocaleDateString([], { month: "short", day: "numeric" });
    if (d.getHours() === 0 && d.getMinutes() === 0) return d.toLocaleDateString([], { month: "short", day: "numeric" });
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes());
  }

  function niceMax(v) {
    if (v <= 4) return Math.max(1, Math.ceil(v));
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / mag;
    const step = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((k) => n <= k);
    return step * mag;
  }

  function drawTimeline(hoverIdx) {
    if (!tlCtx) return;
    const rect = tlCanvas.getBoundingClientRect();
    if (rect.width < 10) return;
    const dpr = Math.min(MAX_DPR, window.devicePixelRatio || 1);
    if (tlCanvas.width !== Math.round(rect.width * dpr) || tlCanvas.height !== Math.round(rect.height * dpr)) {
      tlCanvas.width = Math.round(rect.width * dpr);
      tlCanvas.height = Math.round(rect.height * dpr);
    }
    const ctx = tlCtx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width;
    const h = rect.height;
    ctx.clearRect(0, 0, w, h);
    const hist = state.histogram;
    if (!hist || !hist.blocked) return;
    const n = hist.blocked.length;
    let max = 0;
    for (let i = 0; i < n; i++) max = Math.max(max, hist.blocked[i] + (hist.detected ? hist.detected[i] : 0));
    const top = niceMax(max);
    const plotW = w - TL.left;
    const plotH = h - TL.top - TL.bottom;
    const base = TL.top + plotH;
    const yOf = (v) => base - (v / top) * plotH;
    TL.slot = plotW / n;

    // recessive grid: baseline, half and full scale, with their values
    ctx.font = "500 10px " + FONT;
    ctx.textBaseline = "middle";
    ctx.textAlign = "right";
    [0, top / 2, top].forEach((v, k) => {
      const yy = Math.round(yOf(v)) + 0.5;
      ctx.strokeStyle = k === 0 ? "rgba(167, 187, 204, 0.28)" : "rgba(167, 187, 204, 0.09)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(TL.left, yy);
      ctx.lineTo(w, yy);
      ctx.stroke();
      if (k > 0 && (top >= 2 || k === 2)) {
        ctx.fillStyle = "rgba(167, 187, 204, 0.7)";
        ctx.fillText(fmt(Math.round(v * 10) / 10), TL.left - 8, yy);
      }
    });

    // bars: blocked at the base, detected stacked on top, 1px surface gap between
    const gap = TL.slot > 6 ? 2 : 1;
    const barW = Math.max(1, TL.slot - gap);
    for (let i = 0; i < n; i++) {
      const b = hist.blocked[i];
      const d = hist.detected ? hist.detected[i] : 0;
      const x = TL.left + i * TL.slot + gap / 2;
      const dim = hoverIdx >= 0 && i !== hoverIdx;
      if (i === hoverIdx) {
        ctx.fillStyle = "rgba(167, 187, 204, 0.08)";
        ctx.fillRect(TL.left + i * TL.slot, TL.top, TL.slot, plotH);
      }
      if (!b && !d) continue;
      const bh = b ? Math.max(2, base - yOf(b)) : 0;
      const dh = d ? Math.max(2, base - yOf(d)) : 0;
      const radius = Math.min(2, barW / 2);
      if (b) {
        ctx.fillStyle = dim ? "rgba(229, 72, 77, 0.55)" : BLOCKED_COLOR;
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x, base - bh, barW, bh, d ? 0 : [radius, radius, 0, 0]);
        else ctx.rect(x, base - bh, barW, bh);
        ctx.fill();
      }
      if (d) {
        const y0 = base - bh - (b ? 1 : 0) - dh;
        ctx.fillStyle = dim ? "rgba(245, 165, 36, 0.5)" : DETECTED_COLOR;
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x, y0, barW, dh, [radius, radius, 0, 0]);
        else ctx.rect(x, y0, barW, dh);
        ctx.fill();
      }
    }

    // time axis: a handful of evenly spaced labels
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "rgba(167, 187, 204, 0.7)";
    const ticks = Math.max(2, Math.min(7, Math.floor(plotW / 110)));
    for (let k = 0; k < ticks; k++) {
      const i = Math.round((k / (ticks - 1)) * n);
      const x = TL.left + i * TL.slot;
      ctx.textAlign = k === 0 ? "left" : k === ticks - 1 ? "right" : "center";
      ctx.fillText(timeTick(hist.start + i * hist.bucket, hist.bucket), x, h - 4);
    }
    ctx.textAlign = "left";
  }

  function tlCaptionDefault() {
    const hist = state.histogram;
    if (!hist) return "";
    const b = (hist.blocked || []).reduce((a, v) => a + v, 0);
    const d = (hist.detected || []).reduce((a, v) => a + v, 0);
    const size = hist.bucket >= 3600 ? hist.bucket / 3600 + " h" : hist.bucket / 60 + " min";
    return fmt(b + d) + " requests · " + size + " per bar";
  }

  if (tlCanvas) {
    tlCanvas.addEventListener("mousemove", (e) => {
      const hist = state.histogram;
      if (!hist || !TL.slot) return;
      if (e.offsetX < TL.left) return;
      const i = clamp(Math.floor((e.offsetX - TL.left) / TL.slot), 0, hist.blocked.length - 1);
      const d = hist.detected ? hist.detected[i] : 0;
      if (tlCaption) tlCaption.textContent = bucketRange(i) + " · " + fmt(hist.blocked[i]) + " blocked" + (d ? " · " + fmt(d) + " detected" : "");
      drawTimeline(i);
    });
    tlCanvas.addEventListener("mouseleave", () => {
      if (tlCaption) tlCaption.textContent = tlCaptionDefault();
      drawTimeline(-1);
    });
  }

  /* ============================================================== tooltip */
  const tooltip = $("tm-tooltip");
  let tooltipCC = null;

  function ttRow(label, value) {
    const row = el("div", "tm-tt-row");
    row.appendChild(el("span", null, label));
    row.appendChild(el("strong", null, value));
    return row;
  }

  function renderTooltip(cc) {
    if (!tooltip) return;
    tooltipCC = cc;
    tooltip.textContent = "";
    const title = el("div", "tm-tt-title");
    title.appendChild(flagImg(cc, 22, 15));
    title.appendChild(el("span", null, countryName(cc)));
    tooltip.appendChild(title);
    const entry = (state.stats.countries || {})[cc];
    if (entry && entry.total) {
      tooltip.appendChild(ttRow("Requests", fmt(entry.total)));
      tooltip.appendChild(ttRow("Share of " + windowLabel(), Math.round((entry.total / Math.max(1, state.stats.total)) * 1000) / 10 + "%"));
      if (entry.detected) tooltip.appendChild(ttRow("Detected only", fmt(entry.detected)));
      tooltip.appendChild(el("div", "tm-tt-hint", "Click for the attacking IPs and bans"));
    } else {
      tooltip.appendChild(el("div", "tm-tt-row", "No blocked requests in the " + windowLabel()));
    }
  }

  function placeTooltip(x, y) {
    if (!tooltip) return;
    tooltip.classList.remove("d-none");
    const tw = tooltip.offsetWidth;
    const th = tooltip.offsetHeight;
    const left = x + 16 + tw > L.W ? x - 16 - tw : x + 16;
    const top = y + 16 + th > L.H ? y - 16 - th : y + 16;
    tooltip.style.transform = "translate(" + Math.round(Math.max(4, left)) + "px," + Math.round(Math.max(4, top)) + "px)";
  }

  function hideTooltip() {
    tooltipCC = null;
    if (tooltip) tooltip.classList.add("d-none");
  }

  /* ========================================================== hit-testing */
  function codeAt(mx, my) {
    if (!L.W) return null;
    const u = (mx - L.offX) / L.mapW;
    const v = (my - L.offY) / L.mapH;
    if (u < -0.02 || u > 1.02 || v < -0.02 || v > 1.02) return null;
    let best = null;
    let bestD = L.cell * 1.05;
    const r0 = Math.round(v * ROWS - 0.5);
    for (let r = r0 - 1; r <= r0 + 1; r++) {
      if (r < 0 || r >= ROWS) continue;
      const off = r & 1 ? 0.5 : 0;
      const c0 = Math.round(u * COLS - 0.5 - off);
      for (let c = c0 - 1; c <= c0 + 1; c++) {
        if (c < 0 || c >= COLS) continue;
        const val = cellCode[r * COLS + c];
        if (val < 2) continue; // sea, or land without an ISO code
        const d = Math.hypot(sx((c + 0.5 + off) / COLS) - mx, sy((r + 0.5) / ROWS) - my);
        if (d < bestD) {
          bestD = d;
          best = CODES[val - 1];
        }
      }
    }
    if (best) return best;
    // Active territories that are smaller than a dot: their label point
    let bestL = null;
    let bestLD = Math.max(8, L.cell * 2);
    Object.keys(state.stats.countries || {}).forEach((cc) => {
      const uv = LABELS[cc];
      if (!uv) return;
      const d = Math.hypot(sx(uv[0]) - mx, sy(uv[1]) - my);
      if (d < bestLD) {
        bestLD = d;
        bestL = cc;
      }
    });
    return bestL;
  }

  let pendingMove = null;
  let moveRaf = 0;
  function handleMove() {
    moveRaf = 0;
    const e = pendingMove;
    if (!e) return;
    if (e.target.closest && e.target.closest(".tm-drill, .tm-fs-feed, .tm-toast")) {
      hoverCC = null;
      wrap.classList.remove("tm-pointer");
      hideTooltip();
      return;
    }
    const rect = wrap.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const cc = codeAt(x, y);
    hoverCC = cc;
    wrap.classList.toggle("tm-pointer", !!cc);
    // the open drill-down already shows the selected country: no tooltip on top of it
    if (!cc || cc === selectedCC) {
      hideTooltip();
      return;
    }
    if (cc !== tooltipCC) renderTooltip(cc);
    placeTooltip(x, y);
  }

  wrap.addEventListener("mousemove", (e) => {
    pendingMove = e;
    if (!moveRaf) moveRaf = requestAnimationFrame(handleMove);
  });
  wrap.addEventListener("mouseleave", () => {
    pendingMove = null;
    hoverCC = null;
    wrap.classList.remove("tm-pointer");
    hideTooltip();
  });
  wrap.addEventListener("click", (e) => {
    if (e.target.closest("#tm-drill, .tm-fs-feed, button, a, input, select")) return;
    const rect = wrap.getBoundingClientRect();
    const cc = codeAt(e.clientX - rect.left, e.clientY - rect.top);
    if (cc) openCountry(cc);
    else closeDrill();
  });

  /* ================================================================ server */
  const csrfInput = $("threatmap-csrf");
  const pageUrl = window.location.pathname;

  function postAction(body) {
    const headers = { "Content-Type": "application/json", Accept: "application/json" };
    if (csrfInput && csrfInput.value) headers["X-CSRFToken"] = csrfInput.value;
    return fetch(pageUrl, { method: "POST", headers: headers, credentials: "same-origin", body: JSON.stringify(body) })
      .then((resp) => {
        if (!resp.ok) {
          const err = new Error(resp.status === 403 ? "forbidden" : "HTTP " + resp.status);
          err.status = resp.status;
          throw err;
        }
        const type = resp.headers.get("content-type") || "";
        if (type.indexOf("json") === -1) throw new Error("unexpected response (session expired? reload the page)");
        return resp.json();
      })
      .then((payload) => {
        const data = (payload && payload.data) || {};
        if (data.error) throw new Error(data.error);
        return data;
      });
  }

  function remember(evt) {
    if (evt.date > state.lastTs) state.lastTs = evt.date;
    if (evt.id) seen.set(evt.id, evt.date);
  }

  function pruneSeen() {
    if (seen.size < 5000) return;
    const cutoff = state.lastTs - OVERLAP_S * 3;
    seen.forEach((date, id) => {
      if (date < cutoff) seen.delete(id);
    });
  }

  function setHome(home) {
    if (!home) return;
    const moved = home.lat !== state.home.lat || home.lon !== state.home.lon;
    state.home = home;
    if (moved) {
      homeUV = projectUV(home.lon, home.lat);
      arcs.forEach((a) => (a.ver = -1));
    }
  }

  function applyData(data, reset) {
    if (!data || !data.stats) return;
    state.stats = data.stats;
    if (data.stats24) state.stats24 = data.stats24;
    if (data.histogram) state.histogram = data.histogram;
    if (data.coverage) state.coverage = data.coverage;
    Object.assign(state.labels, data.reason_labels || {});
    if (typeof data.max_events === "number") state.maxEvents = data.max_events;
    setHome(data.home);
    const events = data.events || [];
    if (reset) {
      seen.clear();
      events.forEach(remember);
      state.events = events.slice();
      queue.length = 0;
      rebuildFeed(state.events);
      scheduleEvents(events.slice(0, 16).reverse(), { maxSpread: 2500, maxGap: 300 });
    } else {
      const fresh = events.filter((evt) => !evt.id || !seen.has(evt.id));
      fresh.forEach(remember);
      if (fresh.length) {
        state.events = fresh.concat(state.events).slice(0, state.maxEvents);
        scheduleEvents(fresh.slice(0, 150).reverse(), { maxSpread: POLL_MS * 0.85, feed: true });
      }
    }
    pruneSeen();
    renderAll();
  }

  /* ================================================================ badge */
  const liveBadge = $("tm-live-badge");
  const liveText = $("tm-live-text");
  let demoTimer = null;

  function updateBadge() {
    let text = "LIVE";
    let cls = "";
    if (state.readOnly) {
      text = "SNAPSHOT";
      cls = "tm-alt";
    } else if (state.offline) {
      text = "OFFLINE";
      cls = "tm-off";
    } else if (demoTimer !== null) {
      text = "DEMO";
      cls = "tm-alt";
    } else if (performance.now() < state.replayUntil) {
      text = "REPLAY";
      cls = "tm-alt";
    }
    if (liveText) liveText.textContent = text;
    if (liveBadge) {
      liveBadge.classList.toggle("tm-alt", cls === "tm-alt");
      liveBadge.classList.toggle("tm-off", cls === "tm-off");
    }
  }

  /* =============================================================== polling */
  let pollTimer = null;
  let failures = 0;

  function schedulePoll(ms) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, ms);
  }

  function poll() {
    if (state.readOnly) return;
    if (document.hidden) {
      schedulePoll(POLL_MS);
      return;
    }
    postAction({ since: Math.max(0, state.lastTs - OVERLAP_S), window: state.window })
      .then((data) => {
        failures = 0;
        state.offline = false;
        applyData(data, false);
      })
      .catch((err) => {
        if (err.status === 403) {
          state.readOnly = true;
          toast("Live updates need an administrator account: showing the snapshot taken at page load", true);
        } else {
          failures++;
          state.offline = true;
        }
      })
      .then(() => {
        updateBadge();
        if (!state.readOnly) schedulePoll(Math.min(POLL_MAX_MS, POLL_MS * Math.pow(2, failures)));
      });
    refreshDrill();
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !state.readOnly) schedulePoll(400);
  });

  function setWindow(sec, btn) {
    state.window = sec;
    root.querySelectorAll(".tm-range-btn").forEach((b) => b.classList.toggle("active", b === btn));
    postAction({ since: 0, window: sec })
      .then((data) => applyData(data, true))
      .catch((e) => toast("Failed to load the window: " + e.message, true));
    refreshDrill(true);
  }

  root.querySelectorAll(".tm-range-btn").forEach((btn) => {
    btn.addEventListener("click", () => setWindow(Number(btn.dataset.window) || 0, btn));
  });

  /* ================================================================= toast */
  let toastTimer = null;
  function toast(msg, isError) {
    const node = $("tm-toast");
    if (!node) return;
    node.textContent = msg;
    node.title = msg;
    node.classList.toggle("tm-toast-error", !!isError);
    node.classList.remove("d-none");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.add("d-none"), isError ? 6000 : 4000);
  }

  /* ============================================================ drill-down */
  const drillEl = $("tm-drill");
  const drillContent = $("tm-drill-content");
  let drillSeq = 0;
  let banDuration = 86400;
  let banScope = "global";

  function closeDrill() {
    if (drillEl) drillEl.classList.add("d-none");
    selectedCC = null;
  }

  const drillClose = $("tm-drill-close");
  if (drillClose) drillClose.addEventListener("click", closeDrill);

  function openCountry(cc) {
    if (!drillEl || !drillContent) return;
    hideTooltip();
    selectedCC = cc;
    drillEl.classList.remove("d-none");
    drillContent.textContent = "";
    drillContent.appendChild(el("p", "tm-drill-sub", "Loading " + countryName(cc) + "…"));
    loadDrill(cc);
  }

  function loadDrill(cc) {
    const seq = ++drillSeq;
    postAction({ action: "country", country: cc, window: state.window })
      .then((data) => {
        if (seq === drillSeq && selectedCC === cc) renderDrill(data);
      })
      .catch((e) => {
        if (seq === drillSeq && selectedCC === cc && !drillContent.querySelector(".tm-drill-ip")) {
          drillContent.textContent = "";
          drillContent.appendChild(el("p", "tm-drill-sub", "Failed to load details: " + e.message));
        }
      });
  }

  function refreshDrill(force) {
    if (!selectedCC || !drillEl || drillEl.classList.contains("d-none")) return;
    // never re-render under an open <select> or a pending ban
    const active = document.activeElement;
    if (!force && active && drillEl.contains(active) && active.tagName === "SELECT") return;
    if (!force && drillContent.querySelector(".tm-ban-btn[data-busy]")) return;
    loadDrill(selectedCC);
  }

  function select(options, current, label, onChange) {
    const node = el("select", "form-select form-select-sm tm-drill-select");
    node.setAttribute("aria-label", label);
    options.forEach((o) => {
      const opt = el("option", null, o[0]);
      opt.value = String(o[1]);
      if (String(o[1]) === String(current)) opt.selected = true;
      node.appendChild(opt);
    });
    node.addEventListener("change", () => onChange(node.value));
    return node;
  }

  function remaining(seconds) {
    if (seconds < 3600) return Math.max(1, Math.round(seconds / 60)) + " min";
    if (seconds < 86400) return Math.round(seconds / 3600) + " h";
    return Math.round(seconds / 86400) + " d";
  }

  function banLabel(bans) {
    return bans
      .map((b) => (b.scope === "service" ? "service " + b.service : "global") + " · " + (b.permanent || !b.exp ? "permanent" : remaining(b.exp) + " left"))
      .join("\n");
  }

  function drillStat(value, label) {
    const box = el("div", "tm-drill-stat");
    box.appendChild(el("b", null, value));
    box.appendChild(el("span", null, label));
    return box;
  }

  function markBanned(btn, bans) {
    btn.disabled = true;
    btn.textContent = "Banned";
    btn.className = "tm-ban-btn tm-banned";
    if (bans) btn.title = banLabel(bans);
  }

  function renderDrill(data) {
    drillContent.textContent = "";
    const title = el("h6");
    title.appendChild(flagImg(data.country, 24, 17));
    title.appendChild(el("span", null, countryName(data.country)));
    drillContent.appendChild(title);
    const when = [windowLabel()];
    if (data.last) when.push("last seen " + ago(data.last));
    drillContent.appendChild(el("p", "tm-drill-sub", when.join(" · ")));

    const stats = el("div", "tm-drill-stats");
    stats.appendChild(drillStat(fmt(data.total), data.total === 1 ? "request" : "requests"));
    stats.appendChild(drillStat(fmt(data.unique_ips), data.unique_ips === 1 ? "IP address" : "IP addresses"));
    stats.appendChild(drillStat(fmt(data.detected || 0), "detected only"));
    drillContent.appendChild(stats);

    if (!data.ips.length) {
      drillContent.appendChild(el("p", "tm-drill-sub mt-2", "No requests from here in the selected window."));
      return;
    }

    drillContent.appendChild(el("div", "tm-drill-section", "Top attackers"));
    const controls = el("div", "tm-drill-controls");
    controls.appendChild(select(DURATIONS, banDuration, "Ban duration", (v) => (banDuration = Number(v) || 0)));
    controls.appendChild(
      select(
        [
          ["Global ban", "global"],
          ["This service only", "service"],
        ],
        banScope,
        "Ban scope",
        (v) => (banScope = v),
      ),
    );
    drillContent.appendChild(controls);

    data.ips.forEach((entry) => {
      const row = el("div", "tm-drill-ip");
      const body = el("div");
      const addr = el("div", "tm-drill-ip-addr");
      addr.appendChild(el("span", null, entry.ip));
      addr.appendChild(el("span", "tm-feed-count", "×" + fmt(entry.count)));
      body.appendChild(addr);
      const meta =
        reasonLabel(entry.reason) + " → " + entry.service + " · " + ago(entry.last) + (entry.detected ? " · " + fmt(entry.detected) + " detected" : "");
      body.appendChild(el("span", "tm-drill-ip-meta", meta));
      row.appendChild(body);
      const btn = el("button", "tm-ban-btn", "Ban");
      btn.type = "button";
      if (entry.bans && entry.bans.length) markBanned(btn, entry.bans);
      else if (entry.ip === "unknown") btn.disabled = true;
      else btn.addEventListener("click", () => banIp(entry, btn));
      row.appendChild(btn);
      drillContent.appendChild(row);
    });

    const reasons = sortedEntries(data.reasons, 6);
    const services = sortedEntries(data.services, 4);
    if (reasons.length || services.length) {
      drillContent.appendChild(el("div", "tm-drill-section", "Reasons & services"));
      const tags = el("div", "tm-tags");
      reasons.forEach((entry) => tags.appendChild(tag(reasonLabel(entry[0]) + " ×" + fmt(entry[1]), reasonColor(entry[0]))));
      services.forEach((entry) => tags.appendChild(tag(entry[0] + " ×" + fmt(entry[1]), null, "tm-tag-demo")));
      drillContent.appendChild(tags);
    }
    Object.assign(state.labels, data.reason_labels || {});
  }

  function banIp(entry, btn) {
    const useService = banScope === "service";
    if (useService && (!entry.service || entry.service === "unknown" || entry.service === "_")) {
      toast("No service recorded for " + entry.ip + ": use a global ban", true);
      return;
    }
    const dur = DURATIONS.find((d) => d[1] === banDuration) || DURATIONS[1];
    const what = (useService ? "on " + entry.service : "globally") + (banDuration === 0 ? " permanently" : " for " + dur[0].toLowerCase());
    if (!window.confirm("Ban " + entry.ip + " " + what + "?")) return;
    btn.disabled = true;
    btn.dataset.busy = "1";
    btn.textContent = "…";
    postAction({ action: "ban", ip: entry.ip, exp: banDuration, scope: useService ? "service" : "global", service: useService ? entry.service : "" })
      .then((res) => {
        delete btn.dataset.busy;
        markBanned(btn);
        toast(res.ip + " banned " + what);
        refreshDrill(true);
      })
      .catch((e) => {
        delete btn.dataset.busy;
        btn.disabled = false;
        btn.textContent = "Ban";
        toast("Ban failed: " + e.message, true);
      });
  }

  /* ================================================================ replay */
  const replayBtn = $("tm-replay-btn");
  function replay() {
    const now = performance.now();
    if (now < state.replayUntil) return;
    const events = state.events.slice(0, 200).reverse();
    if (!events.length) {
      toast("Nothing to replay in this window", true);
      return;
    }
    // real order and rhythm, idle stretches trimmed to 0.9 s, at most 25 s in total
    const duration = scheduleEvents(events, { maxSpread: 25000, maxGap: 900, minGap: 60, startDelay: 100 });
    state.replayUntil = now + duration + 3000;
    updateBadge();
    setTimeout(updateBadge, duration + 3100);
    toast("Replaying " + fmt(events.length) + " recorded attacks in " + Math.max(1, Math.round(duration / 1000)) + " s");
  }
  if (replayBtn) replayBtn.addEventListener("click", replay);

  /* ================================================================== demo */
  const demoBtn = $("tm-demo-btn");
  // prettier-ignore
  const DEMO_ORIGINS = [
    ["US", 14], ["CN", 13], ["RU", 9], ["NL", 7], ["DE", 7], ["SG", 6], ["VN", 5], ["IN", 5], ["BR", 5], ["HK", 4],
    ["GB", 4], ["FR", 4], ["KR", 3], ["ID", 3], ["UA", 3], ["TR", 2], ["IR", 2], ["JP", 2], ["CA", 2], ["RO", 2],
    ["BG", 2], ["TH", 2], ["PK", 1], ["ZA", 1], ["AR", 1], ["MX", 1], ["NG", 1], ["EG", 1], ["AU", 1], ["SE", 1],
    ["PL", 1], ["IT", 1], ["ES", 1], ["CO", 1], ["BD", 1], ["KZ", 1], ["MA", 1], ["CL", 1], ["PH", 1], ["MY", 1],
  ];
  // prettier-ignore
  const DEMO_REASONS = [["modsecurity", 30], ["badbehavior", 18], ["limit", 14], ["dnsbl", 10], ["blacklist", 10], ["antibot", 8], ["country", 5], ["bunkernet", 5]];
  const TEST_NETS = ["192.0.2.", "198.51.100.", "203.0.113."]; // RFC 5737 documentation ranges

  function weighted(list) {
    let total = 0;
    list.forEach((e) => (total += e[1]));
    let r = Math.random() * total;
    for (let i = 0; i < list.length; i++) {
      r -= list[i][1];
      if (r <= 0) return list[i][0];
    }
    return list[0][0];
  }

  function demoTick() {
    const evt = {
      id: "",
      ip: TEST_NETS[(Math.random() * TEST_NETS.length) | 0] + (1 + ((Math.random() * 254) | 0)),
      country: weighted(DEMO_ORIGINS),
      date: Date.now() / 1000,
      reason: weighted(DEMO_REASONS),
      service: "demo",
      method: "GET",
      url: "/",
      status: 403,
      mode: Math.random() < 0.08 ? "detect" : "block",
    };
    spawnArc(evt, performance.now());
    addFeedItem(evt, true);
    demoTimer = setTimeout(demoTick, 220 + Math.random() * 650);
  }

  function toggleDemo() {
    if (demoTimer !== null) {
      clearTimeout(demoTimer);
      demoTimer = null;
    } else {
      demoTick();
    }
    if (demoBtn) demoBtn.classList.toggle("tm-on", demoTimer !== null);
    updateBadge();
  }
  if (demoBtn) demoBtn.addEventListener("click", toggleDemo);

  /* ============================================================ fullscreen */
  const mapCard = $("tm-map-card");
  const fsBtn = $("tm-fs-btn");
  const fsChips = $("tm-fs-chips");
  const fsFeed = $("tm-fs-feed");
  const fsFeedHolder = $("tm-fs-feed-holder");
  const feedHome = $("tm-feed-home");
  let cycleTimer = null;
  let cycleIdx = -1;

  function cycleHighlight() {
    const top = topCountries(6, true);
    if (!top.length) return;
    cycleIdx = (cycleIdx + 1) % top.length;
    const now = performance.now();
    socHighlight = { cc: top[cycleIdx][0], from: now, until: now + 5600, name: countryName(top[cycleIdx][0]), count: fmt(top[cycleIdx][1]) + " requests" };
  }

  // SOC mode is an overlay covering the whole window. The BunkerWeb UI sends
  // "Permissions-Policy: fullscreen=()", so the Fullscreen API is usually refused;
  // when a deployment allows it, the overlay is additionally made truly fullscreen.
  let socActive = false;
  let socPortal = null;
  let socAnchor = null;

  function setSoc(active) {
    if (active === socActive || !mapCard) return;
    socActive = active;
    if (active) {
      // move the card to <body> so that no layout ancestor can trap position: fixed
      socAnchor = document.createComment("threatmap card");
      mapCard.parentNode.insertBefore(socAnchor, mapCard);
      socPortal = el("div", "tm-fs");
      socPortal.id = "threatmap-soc";
      document.body.appendChild(socPortal);
      socPortal.appendChild(mapCard);
    } else if (socAnchor) {
      socAnchor.parentNode.replaceChild(mapCard, socAnchor);
      socPortal.remove();
      socAnchor = socPortal = null;
    }
    root.classList.toggle("tm-fs", active);
    mapCard.classList.toggle("tm-soc", active);
    document.documentElement.classList.toggle("tm-soc-open", active);
    if (fsChips) fsChips.classList.toggle("d-none", !active);
    if (fsFeed) fsFeed.classList.toggle("d-none", !active);
    if (active) {
      if (fsFeedHolder && feedEl) fsFeedHolder.appendChild(feedEl);
      renderChips();
      cycleHighlight();
      cycleTimer = setInterval(cycleHighlight, 7000);
      if (document.fullscreenEnabled && mapCard.requestFullscreen) {
        mapCard.requestFullscreen().catch(() => {
          /* refused by the permissions policy: the overlay is enough */
        });
      }
    } else {
      if (feedHome && feedEl) feedHome.appendChild(feedEl);
      clearInterval(cycleTimer);
      cycleTimer = null;
      socHighlight = null;
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    }
    const icon = fsBtn && fsBtn.querySelector("i");
    if (icon) icon.className = active ? "bx bx-exit-fullscreen" : "bx bx-fullscreen";
    if (fsBtn) fsBtn.setAttribute("aria-pressed", String(active));
  }

  if (fsBtn && mapCard) {
    fsBtn.addEventListener("click", () => setSoc(!socActive));
    // leaving real fullscreen with the browser's own Esc also leaves SOC mode
    document.addEventListener("fullscreenchange", () => {
      if (!document.fullscreenElement && socActive) setSoc(false);
    });
  }

  // Esc closes the innermost thing first: the drill-down panel, then SOC mode
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (selectedCC) closeDrill();
    else if (socActive) setSoc(false);
  });

  /* ================================================================== init */
  let layoutRaf = 0;
  function relayout() {
    layoutRaf = 0;
    if (layout()) {
      drawBase();
      drawTimeline(-1);
    }
  }
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => {
      if (!layoutRaf) layoutRaf = requestAnimationFrame(relayout);
    }).observe(wrap);
    let chartsRaf = 0;
    new ResizeObserver(() => {
      if (chartsRaf) return;
      chartsRaf = requestAnimationFrame(() => {
        chartsRaf = 0;
        drawSparks();
        drawTimeline(-1);
      });
    }).observe(root);
  } else {
    window.addEventListener("resize", () => {
      if (!layoutRaf) layoutRaf = requestAnimationFrame(relayout);
    });
  }

  state.events.forEach(remember);
  rebuildFeed(state.events);
  layout();
  renderAll();
  updateBadge();
  scheduleEvents(state.events.slice(0, 24).reverse(), { maxSpread: 3500, maxGap: 400, startDelay: 600 });
  requestAnimationFrame(frame);
  schedulePoll(POLL_MS);
})();
