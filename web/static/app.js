/* RAG-IDS range: front end. No framework, no build step. */
'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const state = { meta: null, phase: 'armory', flow: null, lastOpts: null, mode: 'kb', asking: false, timers: [], resultsLoaded: false };

async function api(path, body) {
  const r = await fetch(path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {});
  if (!r.ok) {
    let m = r.statusText;
    try { m = (await r.json()).detail || m; } catch (e) { /* keep status text */ }
    throw new Error(m);
  }
  return r.json();
}
function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast'; t.textContent = msg; document.body.appendChild(t);
  setTimeout(() => t.remove(), 5000);
}

/* ================================================================
   Network simulation (canvas)
   ================================================================ */
const MOTION = {
  flood:   { rate: 80, speed: 2.5, size: 3,   off: 26, color: 'attack' },
  slow:    { rate: 2.4, speed: .75, size: 5,  off: 6,  color: 'attack' },
  scan:    { rate: 22, speed: 2.7, size: 3,   off: 10, color: 'attack' },
  spoof:   { rate: 7,  speed: 2.8, size: 4,   off: 4,  color: 'attack' },
  brute:   { rate: 8,  speed: 2.3, size: 3.5, off: 5,  color: 'attack' },
  normal:  { rate: 2.2, speed: 1.4, size: 4,  off: 5,  color: 'normal' },
  mystery: { rate: 10, speed: 2.1, size: 3.5, off: 14, color: 'neutral' },
  idle:    { rate: 1.1, speed: 1.1, size: 3,  off: 6,  color: 'neutral' },
};
const IDLE = { motion: 'idle', from: 'Sensor', to: 'Cloud', family: 'Normal', color: '#8CA2D9', headline: '' };
const MYSTERY = { motion: 'mystery', from: 'Unknown source', to: 'IoT device', family: 'Mystery', color: '#8CA2D9', headline: 'Unidentified flow' };
const PORTS = [21, 22, 53, 80, 443, 1883, 8080];

class Sim {
  constructor(cv) {
    this.cv = cv; this.ctx = cv.getContext('2d');
    this.layouts = {
      bg:   { src: [.44, .66], hub: [.66, .66], dst: [.9, .66], via: [.66, .26] },
      full: { src: [.11, .56], hub: [.46, .56], dst: [.87, .56], via: [.46, .2] },
      mini: { src: [.1, .6],   hub: [.46, .6],  dst: [.88, .6],  via: [.46, .22] },
    };
    this.pos = JSON.parse(JSON.stringify(this.layouts.bg)); this.target = this.layouts.bg;
    this.parts = []; this.fx = []; this.acc = 0; this.slots = 0; this.hit = 0; this.doorFx = {};
    this.sc = IDLE; this.t0 = performance.now(); this.last = this.t0;
    this.readColors();
    new ResizeObserver(() => this.resize()).observe(cv.parentElement);
    requestAnimationFrame(t => this.loop(t));
  }
  readColors() {
    const s = getComputedStyle(document.documentElement), g = n => s.getPropertyValue(n).trim();
    this.c = { grid: g('--grid'), node: g('--node'), line: g('--line'), text: g('--text'), muted: g('--muted'), faint: g('--faint'), glow: parseFloat(g('--glow')) || .8 };
  }
  resize() {
    const r = this.cv.parentElement.getBoundingClientRect(), d = Math.min(devicePixelRatio || 1, 2);
    this.w = r.width; this.h = r.height; this.cv.width = r.width * d; this.cv.height = r.height * d;
    this.ctx.setTransform(d, 0, 0, d, 0, 0);
  }
  setLayout(name) { this.target = this.layouts[name]; }
  start(sc) { this.sc = sc; this.t0 = performance.now(); this.parts = []; this.fx = []; this.slots = 0; this.hit = 0; this.doorFx = {}; }
  get attack() { return this.sc.family !== 'Normal' && this.sc.motion !== 'idle' && this.sc.motion !== 'mystery'; }
  col(kind) { return kind === 'attack' ? this.sc.color : kind === 'normal' ? '#1FBF9A' : '#8CA2D9'; }
  size() { return Math.max(.62, Math.min(1, this.h / 470)); }
  xy(n) { const p = this.pos[n]; return [p[0] * this.w, p[1] * this.h]; }
  door(i) { const [dx, dy] = this.xy('dst'), span = Math.min(this.h * .6, 210), s = this.size(); return [dx - 80 * s - 14, dy - span / 2 + span * i / 6]; }
  pt(r) { return typeof r === 'number' ? this.door(r) : this.xy(r); }

  spawn() {
    const m = MOTION[this.sc.motion] || MOTION.flood, color = this.col(m.color), mo = this.sc.motion;
    let route = ['src', 'hub', 'dst'];
    if (mo === 'scan') route = ['src', 'hub', Math.floor(Math.random() * 7)];
    if (mo === 'spoof') route = ['src', 'hub', 'via', 'hub', 'dst'];
    this.parts.push({ route, t: 0, speed: m.speed * (.85 + Math.random() * .3), size: m.size, off: (Math.random() - .5) * 2 * m.off, color, kind: mo });
  }
  arrive(p) {
    const mo = p.kind, [x, y] = this.pt(p.route[p.route.length - 1]);
    if (mo === 'flood') this.hit = performance.now();
    if (mo === 'slow') { this.slots = Math.min(20, this.slots + 1); this.hit = performance.now(); }
    if (mo === 'scan') this.doorFx[p.route[2]] = { t: performance.now(), open: Math.random() < .12 };
    if (mo === 'brute') { this.hit = performance.now(); this.fx.push({ x: x + 40, y: y - 40, txt: '✗ denied', t: performance.now(), color: '#FF5A5A' }); }
    if (mo === 'normal' && Math.random() < .6) this.parts.push({ route: ['dst', 'hub', 'src'], t: 0, speed: 1.4, size: 3, off: 0, color: '#6FE3C2', kind: 'reply' });
  }

  loop(now) {
    const dt = Math.min(.05, (now - this.last) / 1000); this.last = now;
    for (const k in this.pos) for (let i = 0; i < 2; i++) this.pos[k][i] += (this.target[k][i] - this.pos[k][i]) * (1 - Math.exp(-dt * 6));
    const m = MOTION[this.sc.motion] || MOTION.flood;
    this.acc += m.rate * dt * (reduced ? .3 : 1);
    while (this.acc >= 1) { this.acc -= 1; this.spawn(); }
    this.parts = this.parts.filter(p => { p.t += p.speed * dt; if (p.t >= p.route.length - 1) { this.arrive(p); return false; } return true; });
    this.draw(now); requestAnimationFrame(t => this.loop(t));
  }

  draw(now) {
    const { ctx, w, h, c } = this, s = this.size(), sc = this.sc;
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = c.grid; ctx.globalAlpha = .55;
    for (let x = 14; x < w; x += 28) for (let y = 14; y < h; y += 28) ctx.fillRect(x, y, 1.5, 1.5);
    ctx.globalAlpha = 1;
    // edges
    const [sx, sy] = this.xy('src'), [hx, hy] = this.xy('hub'), [dx, dy] = this.xy('dst');
    ctx.strokeStyle = c.line; ctx.lineWidth = 1.5; ctx.setLineDash([5, 6]); ctx.beginPath();
    ctx.moveTo(sx, sy); ctx.lineTo(hx, hy); ctx.lineTo(dx, dy);
    if (sc.via) { const [vx, vy] = this.xy('via'); ctx.moveTo(hx, hy); ctx.lineTo(vx, vy); }
    ctx.stroke(); ctx.setLineDash([]);
    if (sc.motion === 'scan') this.drawDoors(now, s);
    // nodes
    const atk = this.attack, shake = now - this.hit < 160 ? (Math.random() - .5) * 4 : 0;
    this.node(sx, sy, this.srcIcon(), sc.from, atk && !sc.via, s, now);
    this.node(hx, hy, '🔀', 'Router', false, s * .78, now);
    if (sc.via) { const [vx, vy] = this.xy('via'); this.node(vx, vy, '🎭', sc.via, true, s, now, false, 'right'); }
    this.node(dx + shake, dy, this.dstIcon(), sc.to, false, s, now, now - this.hit < 700 && atk);
    if (sc.motion === 'flood' || sc.motion === 'slow') this.drawMeter(now, s, dx, dy);
    // packets
    for (const p of this.parts) this.drawPacket(p);
    // floating text
    this.fx = this.fx.filter(f => now - f.t < 900);
    for (const f of this.fx) { const a = 1 - (now - f.t) / 900; ctx.globalAlpha = a; ctx.fillStyle = f.color; ctx.font = '600 12px "IBM Plex Mono", monospace'; ctx.fillText(f.txt, f.x, f.y - (1 - a) * 22); }
    ctx.globalAlpha = 1;
  }
  srcIcon() {
    const f = (this.sc.from || '').toLowerCase();
    if (this.sc.motion === 'mystery') return '❓';
    if (/bulb/.test(f)) return '💡'; if (/sensor/.test(f)) return '🌡️'; if (/device/.test(f)) return '📟';
    return this.attack ? '🕶️' : '📟';
  }
  dstIcon() {
    const t = (this.sc.to || '').toLowerCase();
    if (/cloud/.test(t)) return '☁️'; if (/server|broker/.test(t)) return '🖥️'; if (/router/.test(t)) return '📶'; return '🔌';
  }
  node(x, y, icon, label, hot, s, now, alarm, side) {
    const { ctx, c } = this, S = 62 * s, col = this.sc.color;
    if (hot || alarm) { const pulse = .5 + .5 * Math.sin(now / 260); ctx.save(); ctx.shadowColor = col; ctx.shadowBlur = (18 + 12 * pulse) * c.glow; ctx.strokeStyle = col; ctx.lineWidth = 2; this.rr(x - S / 2, y - S / 2, S, S, 16 * s); ctx.stroke(); ctx.restore(); }
    ctx.fillStyle = c.node; ctx.strokeStyle = (hot || alarm) ? col : c.line; ctx.lineWidth = 1.5; this.rr(x - S / 2, y - S / 2, S, S, 16 * s); ctx.fill(); ctx.stroke();
    ctx.font = `${Math.round(28 * s)}px "Segoe UI Emoji","Apple Color Emoji","Noto Color Emoji",sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillStyle = c.text; ctx.fillText(icon, x, y + 1);
    ctx.font = `600 ${Math.round(10.5 * Math.max(s, .85))}px Archivo, sans-serif`; ctx.fillStyle = c.muted; ctx.textBaseline = 'alphabetic';
    if (side === 'right') { ctx.textAlign = 'start'; ctx.textBaseline = 'middle'; ctx.fillText((label || '').toUpperCase(), x + S / 2 + 10, y); }
    else ctx.fillText((label || '').toUpperCase(), x, y + S / 2 + 16 * Math.max(s, .85));
    ctx.textAlign = 'start';
  }
  rr(x, y, w, h, r) { const { ctx } = this; ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath(); }
  drawDoors(now, s) {
    const { ctx, c } = this;
    for (let i = 0; i < 7; i++) {
      const [x, y] = this.door(i), fx = this.doorFx[i], age = fx ? now - fx.t : 9999, on = age < 420;
      const col = on ? (fx.open ? '#1FBF9A' : this.sc.color) : c.line;
      ctx.fillStyle = on ? col + '55' : c.node; ctx.strokeStyle = col; ctx.lineWidth = on ? 2 : 1.3;
      this.rr(x - 11 * s, y - 9 * s, 22 * s, 18 * s, 5); ctx.fill(); ctx.stroke();
      ctx.font = `500 ${Math.round(9.5 * Math.max(s, .9))}px "IBM Plex Mono", monospace`; ctx.fillStyle = on ? c.text : c.faint; ctx.textAlign = 'right';
      ctx.fillText(':' + PORTS[i], x - 16 * s, y + 3.5); ctx.textAlign = 'start';
    }
  }
  drawMeter(now, s, dx, dy) {
    const { ctx, c } = this, flood = this.sc.motion === 'flood';
    const n = 20, filled = flood ? Math.min(n, Math.floor((now - this.t0) / 1000 * 3.4)) : this.slots, full = filled >= n;
    const cw = 7 * s, gap = 3 * s, x0 = dx - (n * (cw + gap)) / 2, y0 = dy + 62 * s / 2 + 34 * Math.max(s, .85);
    for (let i = 0; i < n; i++) { ctx.fillStyle = i < filled ? (full && Math.sin(now / 150) > 0 ? '#FF8A80' : this.sc.color) : c.grid; ctx.fillRect(x0 + i * (cw + gap), y0, cw, 10 * s); }
    ctx.font = '500 9.5px "IBM Plex Mono", monospace'; ctx.fillStyle = full ? '#FF6B6B' : c.faint; ctx.textAlign = 'center';
    ctx.fillText((flood ? 'SYN BACKLOG' : 'OPEN SOCKETS') + (full ? ' · FULL' : ''), dx, y0 + 24 * s); ctx.textAlign = 'start';
  }
  drawPacket(p) {
    const { ctx } = this, n = p.route.length - 1, k = Math.min(n - 1, Math.floor(p.t)), f = p.t - k;
    const a = this.pt(p.route[k]), b = this.pt(p.route[k + 1]);
    const x = a[0] + (b[0] - a[0]) * f, y = a[1] + (b[1] - a[1]) * f + p.off * Math.sin(Math.PI * f);
    const L = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1, ux = (b[0] - a[0]) / L, uy = (b[1] - a[1]) / L, edge = Math.min(1, f * 6, (1 - f) * 6 + .15);
    ctx.save(); ctx.globalAlpha = Math.max(0, edge); ctx.strokeStyle = p.color; ctx.lineWidth = p.size * .8; ctx.lineCap = 'round'; ctx.globalAlpha *= .45;
    ctx.beginPath(); ctx.moveTo(x - ux * 16, y - uy * 16); ctx.lineTo(x, y); ctx.stroke(); ctx.globalAlpha = Math.max(0, edge);
    ctx.shadowColor = p.color; ctx.shadowBlur = 12 * this.c.glow; ctx.fillStyle = p.color; ctx.beginPath(); ctx.arc(x, y, p.size, 0, 7); ctx.fill(); ctx.restore();
  }
}

/* ================================================================
   Page wiring
   ================================================================ */
let sim;

function setPhase(p) {
  state.phase = p; document.documentElement.dataset.phase = p;
  if (p === 'armory') { delete document.documentElement.dataset.wide; $('#assistant').classList.remove('wide-on'); }
  sim.setLayout(p === 'armory' ? 'bg' : p === 'live' ? 'full' : 'mini');
}
function clearTimers() { state.timers.forEach(clearTimeout); state.timers.forEach(clearInterval); state.timers = []; }
const later = (ms, fn) => state.timers.push(setTimeout(fn, ms));

function setTheme(t) {
  document.documentElement.dataset.theme = t; try { localStorage.setItem('theme', t); } catch (e) { /* private mode */ }
  sim && sim.readColors();
}

/* ---------- armory ---------- */
const MINI = { flood: [12, .9], slow: [3, 3], scan: [8, 1.6], spoof: [5, 2.2], brute: [6, 1.5], normal: [3, 2.6] };
function buildDeck(meta) {
  const rail = $('#rail'); let html = '';
  html += `<button class="play mystery" data-mystery="1"><div class="art"><span class="ico">?</span></div><div class="txt"><h3>Mystery flow</h3><p>A random real flow, attack or normal. You are not told what it is until the detector decides.</p></div><div class="foot"><span class="chip-f" style="--fam:#B7C3EE">unknown</span><span class="go">Launch ▸</span></div></button>`;
  let sawNormal = false;
  for (const s of meta.scenarios) {
    if (!s.attack && !sawNormal) { sawNormal = true; html += '<div class="divider">Normal traffic</div>'; }
    const [n, dur] = MINI[s.motion] || MINI.flood;
    const dots = Array.from({ length: n }, (_, i) => `<i style="--d:${dur}s;--dl:${(-(i * dur / n)).toFixed(2)}s"></i>`).join('');
    html += `<button class="play" data-label="${esc(s.label)}" style="--fam:${s.color}"><div class="art"><span class="ico">${s.icon}</span><div class="mini">${dots}</div></div>` +
      `<div class="txt"><h3>${esc(s.headline)}</h3><p>${esc(s.story)}</p></div><div class="foot"><span class="chip-f">${esc(s.family)}</span><span class="go">Launch ▸</span></div></button>`;
  }
  rail.innerHTML = html;
  rail.onclick = e => { const b = e.target.closest('.play'); if (!b) return; launch(b.dataset.mystery ? { mystery: true } : { label: b.dataset.label }); };
  $('#deckHint').textContent = `${meta.scenarios.length + 1} playbooks · drag, scroll or use the arrows`;
  setupRail(rail);
  $('#stats').innerHTML = `<div><b>${meta.test_flows.toLocaleString()}</b>unseen flows</div><div><b>${meta.labels}</b>scenarios</div><div><b>${meta.macro_f1.toFixed(3)}</b>detector macro-F1</div>`;
  $('#modelPill').textContent = 'analyst: ' + meta.answer_model;
}

/* Make the playbook rail obviously scrollable: edge fades, arrows with disabled ends, a progress bar,
   drag-to-scroll with the mouse, and one small nudge on first view. The native scrollbar is hidden. */
function setupRail(rail) {
  const wrap = $('#railWrap'), bar = $('#railProg i'), prev = $('#prev'), next = $('#next');
  const update = () => {
    const max = rail.scrollWidth - rail.clientWidth, x = rail.scrollLeft, vis = Math.min(1, rail.clientWidth / rail.scrollWidth);
    wrap.classList.toggle('can-left', x > 8); wrap.classList.toggle('can-right', x < max - 8);
    prev.disabled = x <= 8; next.disabled = x >= max - 8;
    bar.style.width = (vis * 100) + '%'; bar.style.marginLeft = ((max > 0 ? x / max : 0) * (1 - vis) * 100) + '%';
  };
  rail.addEventListener('scroll', update, { passive: true }); addEventListener('resize', update); update();
  const step = () => Math.max(260, rail.clientWidth * .8);
  prev.onclick = () => rail.scrollBy({ left: -step(), behavior: 'smooth' });
  next.onclick = () => rail.scrollBy({ left: step(), behavior: 'smooth' });
  let down = false, moved = false, sx = 0, sl = 0;
  rail.addEventListener('pointerdown', e => { if (e.pointerType === 'touch' || e.button !== 0) return; down = true; moved = false; sx = e.clientX; sl = rail.scrollLeft; });
  addEventListener('pointermove', e => { if (!down) return; const dx = e.clientX - sx; if (Math.abs(dx) > 6) { moved = true; rail.classList.add('dragging'); } if (moved) rail.scrollLeft = sl - dx; });
  addEventListener('pointerup', () => { if (!down) return; down = false; setTimeout(() => rail.classList.remove('dragging'), 0); });
  rail.addEventListener('click', e => { if (moved) { e.stopPropagation(); e.preventDefault(); moved = false; } }, true);   // a drag is not a click
  setTimeout(() => {   // one gentle nudge so the sideways movement is noticed
    if (state.phase === 'armory' && rail.scrollLeft === 0 && !reduced) { rail.scrollTo({ left: 110, behavior: 'smooth' }); setTimeout(() => rail.scrollTo({ left: 0, behavior: 'smooth' }), 800); }
  }, 1400);
}

/* ---------- launch ---------- */
async function launch(opts) {
  if (state.launching) return; state.launching = true;
  try {
    const d = await api('/api/launch', opts);
    state.flow = d; state.lastOpts = opts; play(d, !!opts.mystery);
  } catch (e) { toast('Could not launch: ' + e.message); }
  finally { state.launching = false; }
}

function play(d, mystery) {
  clearTimers(); resetAssistant(); setPhase('live');
  const sc = d.true.scenario, det = d.detection, f = d.facts;
  sim.start(mystery ? MYSTERY : { ...sc, motion: sc.motion });
  $('#hudTitle').innerHTML = `<small>SIMULATION · FLOW ${esc(d.sample_id)}</small>${mystery ? 'Unidentified flow' : esc(sc.headline)}`;
  $('#tele').innerHTML = [['Protocol', f.protocol], ['Target port', f.port], ['Duration', f.duration], ['Packets out / back', `${f.packets_out} / ${f.packets_back}`]]
    .map(([k, v]) => `<div><small>${k}</small>${esc(v)}</div>`).join('');
  $('#stampwrap').innerHTML = ''; $('#bars').innerHTML = '';
  const steps = $$('#steps li'); steps.forEach(li => li.className = ''); $('#stepMeasure').textContent = 'Measure features';
  const mark = (i, c) => { steps[i].className = c; };
  const bars = buildBars(det.probabilities);

  const t0 = performance.now(), clk = $('#hudClock');
  const iv = setInterval(() => { clk.textContent = ((performance.now() - t0) / 1000).toFixed(1).padStart(4, '0') + ' s'; }, 100); state.timers.push(iv);
  later(250, () => mark(0, 'now'));
  later(1250, () => { mark(0, 'done'); mark(1, 'now'); count(f.features, 900); });
  later(2250, () => { mark(1, 'done'); $('#stepMeasure').textContent = `Measure ${f.features} features`; mark(2, 'now'); race(bars); });
  later(3500, () => { settle(bars, det); mark(2, 'done'); mark(3, 'now'); });
  later(3950, () => {
    mark(3, 'done'); verdictMoment(d, mystery);
    if (mystery) sim.start({ ...sc });
  });
  later(5700, () => { renderReport(d); setPhase('report'); });
}
function count(target, ms) {
  const t0 = performance.now(), el = $('#stepMeasure');
  const iv = setInterval(() => { const k = Math.min(1, (performance.now() - t0) / ms); el.textContent = `Measure ${Math.round(target * k)} features`; if (k >= 1) clearInterval(iv); }, 40);
  state.timers.push(iv);
}
function buildBars(probs) {
  const names = Object.keys(probs).sort(), box = $('#bars');
  box.innerHTML = names.map(n => `<div class="bar" data-n="${esc(n)}"><span class="n">${esc(n)}</span><span class="t"><i></i></span><span class="p">0%</span></div>`).join('');
  return $$('.bar', box);
}
function race(bars) {
  const iv = setInterval(() => bars.forEach(b => { const v = Math.random() ** 2; $('i', b).style.width = (v * 100) + '%'; $('.p', b).textContent = Math.round(v * 100) + '%'; }), 90);
  state.timers.push(iv); state.raceIv = iv;
}
function settle(bars, det) {
  clearInterval(state.raceIv);
  bars.forEach(b => {
    const p = det.probabilities[b.dataset.n], win = b.dataset.n === det.label;
    $('i', b).style.width = (p * 100) + '%'; $('.p', b).textContent = (p >= .995 ? 100 : Math.round(p * 100)) + '%';
    b.classList.toggle('win', win); if (win) b.style.setProperty('--fam', det.color);
  });
}
function stampHTML(det, cls) {
  return `<div class="stamp ${cls}" style="--fam:${det.color}"><small>detector classified</small><strong>${esc(det.name)}</strong><em>${esc(det.family)} · ${Math.round(det.confidence * 100)}% sure</em></div>`;
}
function verdictMoment(d, mystery) {
  const det = d.detection, st = $('#stage');
  $('#stampwrap').innerHTML = stampHTML(det, 'slam');
  st.style.setProperty('--flash', det.color + 'cc'); st.classList.add('flash'); setTimeout(() => st.classList.remove('flash'), 80);
  if (mystery) $('#hudTitle').innerHTML = `<small>SIMULATION · FLOW ${esc(d.sample_id)}</small>${esc(d.true.scenario.headline)}`;
}

/* ---------- case file ---------- */
function renderReport(d) {
  const det = d.detection, f = d.facts, inc = $('#incident'), pct = Math.round(det.confidence * 100);
  inc.style.setProperty('--fam', det.color);
  const truth = det.correct
    ? `<div class="truth ok">✓ Matches the dataset's label</div>`
    : `<div class="truth bad">✗ The dataset labels this flow <span class="mono">${esc(d.true.label)}</span> (${esc(d.true.name)})</div>`;
  const warn = det.low_confidence ? `<div class="warn"><b>Low confidence.</b> The detector is less than 60% sure, so treat this label as uncertain. The analyst is told the same.</div>` : '';
  inc.innerHTML = `<div class="inc-l">${stampHTML(det, 'rest')}<div class="raw">${esc(det.label)}</div></div>` +
    `<div class="inc-main">` +
    `<div class="facts"><div><small>Protocol</small>${esc(f.protocol)}</div><div><small>Target port</small>${esc(f.port)}</div><div><small>Duration</small>${esc(f.duration)}</div><div><small>Packets out / back</small>${f.packets_out} / ${f.packets_back}</div></div>${truth}${warn}</div>` +
    `<div class="ring"><svg viewBox="0 0 100 100" width="96" height="96"><circle class="bg" cx="50" cy="50" r="42"/><circle class="fg" id="ringfg" cx="50" cy="50" r="42" stroke-dasharray="263.9" stroke-dashoffset="263.9"/></svg><div class="num">${pct}%</div><div class="lbl">confidence</div></div>`;
  const top = Math.max(...det.features.map(x => x.push), .0001);
  $('#why').style.setProperty('--fam', det.color);
  $('#why').innerHTML = `<h3>Why the detector decided this</h3><div class="sub">The five measurements that pushed it hardest towards this label. Longer bar, stronger push.</div>` +
    det.features.map(x => `<div class="feat"><div class="nm">${esc(x.name)}</div><div class="vl">${esc(x.value)}<i><b data-w="${Math.max(5, 100 * x.push / top)}"></b></i></div><div class="mn">${esc(x.meaning || 'No description yet.')}</div></div>`).join('');
  $('#refs').innerHTML = `<h3>Official references</h3><div class="sub">Mapped to this label in our verified mapping file. No AI involved.</div>` +
    (det.references.length ? det.references.map(r => `<a class="ref" ${r.url ? `href="${esc(r.url)}" target="_blank" rel="noopener"` : ''}><span class="chip k-${r.kind}">${esc(r.id)}</span><span class="nm">${esc(r.name)}</span></a>`).join('')
      : `<div class="note">Normal traffic has no attack mapping.</div>`) + `<div class="note">Each chip is the same kind of tag the analyst uses when it cites a source.</div>`;
  $('#crumb').textContent = `flow ${d.sample_id} · ${f.protocol} → port ${f.port}`;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    $('#ringfg').style.strokeDashoffset = 263.9 * (1 - det.confidence);
    $$('.feat i b').forEach(b => { b.style.width = b.dataset.w + '%'; });
  }));
  suggest();
}

/* ---------- analyst ---------- */
const SUGGESTIONS = ['What is this traffic, and why was it flagged?', 'How should I respond to this traffic?', 'Which official technique applies, and are there known CVEs?'];
function suggest() {
  $('#suggest').innerHTML = SUGGESTIONS.map(q => `<button class="sg" type="button">${esc(q)}</button>`).join('');
  $$('#suggest .sg').forEach(b => b.onclick = () => send(b.textContent));
}
function resetAssistant() {
  const m = $('#msgs'); m.innerHTML = ''; m.appendChild($('#aEmpty') || emptyNode()); $('#suggest').innerHTML = '';
}
function emptyNode() {
  const d = document.createElement('div'); d.className = 'empty'; d.id = 'aEmpty';
  d.innerHTML = '<div class="empty-t">Ask about this incident</div><div class="empty-d">Try <b>Compare both</b> to see the same question answered from memory and from the knowledge base, with every cited ID checked against the official MITRE files.</div>';
  return d;
}
function setMode(m) {
  state.mode = m; $$('#modes button').forEach(b => b.classList.toggle('on', b.dataset.mode === m));
  setWide(m === 'compare');
  $('#aSub').textContent = m === 'memory' ? 'answering from memory, no sources' : m === 'kb' ? 'answers cite their sources' : 'asking twice, side by side';
}
function setWide(on) { document.documentElement.dataset.wide = on ? '1' : ''; if (!on) delete document.documentElement.dataset.wide; $('#assistant').classList.toggle('wide-on', on); }

function chip(tag, tags) {
  const i = tags[tag]; if (!i) return `[${tag}]`;
  if (!i.ok) return `<span class="chip missing" title="This tag was not in the evidence the answer was given">${tag}?</span>`;
  return i.url ? `<a class="chip k-${i.kind}" href="${esc(i.url)}" target="_blank" rel="noopener" title="${esc(i.name)}">${tag}</a>` : `<span class="chip k-${i.kind}" title="${esc(i.name)}">${tag}</span>`;
}
function md(text, tags) {
  const inl = s => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>').replace(/\[([A-Za-z0-9_.\-]+)\]/g, (m, t) => chip(t, tags));
  const out = []; let list = null, para = [], tbl = [];
  const flushP = () => { if (para.length) { out.push('<p>' + para.join('<br>') + '</p>'); para = []; } };
  const flushL = () => { if (list) { out.push(`<${list.t}>${list.items.join('')}</${list.t}>`); list = null; } };
  const flushT = () => { if (tbl.length) { const rows = tbl.filter(r => !/^\s*\|?[\s:|-]+\|?\s*$/.test(r)).map(r => r.trim().replace(/^\||\|$/g, '').split('|').map(c => inl(c.trim()))); if (rows.length) out.push('<table><tr>' + rows[0].map(c => `<th>${c}</th>`).join('') + '</tr>' + rows.slice(1).map(r => '<tr>' + r.map(c => `<td>${c}</td>`).join('') + '</tr>').join('') + '</table>'); tbl = []; } };
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    const line = raw.trimEnd();
    if (/^\s*\|/.test(line)) { flushP(); flushL(); tbl.push(line); continue; } else flushT();
    let m;
    if (!line.trim()) { flushP(); flushL(); continue; }
    if ((m = line.match(/^\s*(?:[-*•])\s+(.*)/))) { flushP(); if (!list || list.t !== 'ul') { flushL(); list = { t: 'ul', items: [] }; } list.items.push('<li>' + inl(m[1]) + '</li>'); continue; }
    if ((m = line.match(/^\s*\d+[.)]\s+(.*)/))) { flushP(); if (!list || list.t !== 'ol') { flushL(); list = { t: 'ol', items: [] }; } list.items.push('<li>' + inl(m[1]) + '</li>'); continue; }
    if ((m = line.match(/^#{1,4}\s+(.*)/))) { flushP(); flushL(); out.push('<p><strong>' + inl(m[1]) + '</strong></p>'); continue; }
    flushL(); para.push(inl(line));
  }
  flushP(); flushL(); flushT(); return out.join('');
}
const FLAG = { correct: '✓', mismatched: '≠', fabricated: '✗', unverifiable: '?' };
const FLAGTIP = { correct: 'matches this detection', mismatched: 'real ID, but unrelated to this detection or given the wrong name', fabricated: 'does not exist in the official files', unverifiable: 'real CVE; its link to this attack cannot be checked offline' };
function answerHTML(a) {
  const flags = a.id_flags.length ? `<div class="flags">IDs in this answer, checked against the official MITRE files: ${a.id_flags.map(f => `<span class="flag ${f.outcome}" title="${esc(f.note || FLAGTIP[f.outcome])}">${FLAG[f.outcome]} ${esc(f.id)}</span>`).join('')}</div>` : '';
  const src = a.sources.length ? `<details class="src"><summary>Sources this answer could use (${a.sources.length} + detector output)</summary>${a.sources.map(s => `<div class="srccard"><span class="chip k-${s.kind}">${esc(s.id)}</span> <span class="t">${esc(s.name)}</span>${s.url ? ` <a href="${esc(s.url)}" target="_blank" rel="noopener">official page</a>` : ''}<div class="x">${esc(s.snippet)}…</div></div>`).join('')}</details>` : '';
  const tools = a.tool_trace.length ? `<div class="meta"><span>tools: ${a.tool_trace.map(t => esc(t.tool)).join(' → ')}</span></div>` : '';
  const fb = a.fallback_reason ? `<div class="err">Tool calling failed, so the fixed pipeline answered instead (${esc(a.fallback_reason)}).</div>` : '';
  const warn = (a.warnings || []).map(w => `<div class="err">${esc(w)}</div>`).join('');
  return `<div class="bubble ${a.kind === 'memory' ? 'plain' : ''}">${md(a.text, a.tags)}</div>${fb}${warn}${flags}${tools}${src}<div class="meta"><span>${a.kind === 'memory' ? "from the model's memory, no sources" : 'grounded in the knowledge base'}</span><span>${esc(a.model)}${a.fallback ? ' · fallback model' : ''}${a.cached ? ' · cached' : ''}</span></div>`;
}
function scrollMsgs() { const m = $('#msgs'); m.scrollTop = m.scrollHeight; }
async function send(q) {
  q = (q || '').trim(); if (!q || state.asking) return; state.asking = true;
  $('#aEmpty')?.remove(); $('#suggest').innerHTML = '';
  const msgs = $('#msgs'); msgs.insertAdjacentHTML('beforeend', `<div class="me">${esc(q)}</div>`);
  msgs.insertAdjacentHTML('beforeend', '<div class="typing" id="typing"><i></i><i></i><i></i></div>'); scrollMsgs();
  try {
    const r = await api('/api/ask', { sample_id: state.flow?.sample_id, question: q, mode: state.mode, tools: $('#tools').checked });
    $('#typing')?.remove();
    const html = r.answers.length === 2
      ? `<div class="bot"><div class="vs"><div><div class="vs-h">Without the knowledge base<small>written from the model's memory</small></div>${answerHTML(r.answers[0])}</div><div><div class="vs-h">With the knowledge base<small>only the evidence it was given, cited</small></div>${answerHTML(r.answers[1])}</div></div></div>`
      : `<div class="bot">${answerHTML(r.answers[0])}</div>`;
    msgs.insertAdjacentHTML('beforeend', html);
  } catch (e) { $('#typing')?.remove(); msgs.insertAdjacentHTML('beforeend', `<div class="err"><b>No answer.</b> ${esc(e.message)}</div>`); }
  finally { state.asking = false; suggest(); const last = [...msgs.querySelectorAll('.bot, .err')].pop(); if (last) msgs.scrollTop = Math.max(0, last.offsetTop - 70); else scrollMsgs(); }
}

/* ---------- results ---------- */
const pc = (n, d) => d ? `${n}/${d} (${(100 * n / d).toFixed(1)}%)` : `${n}/0`;
async function loadResults() {
  if (state.resultsLoaded) return;
  const [r, meta] = [await api('/api/results'), state.meta], m = r.metrics, t = m.test;
  const kpi = (k, v, n) => `<div class="card kpi"><div class="k">${k}</div><div class="v">${v}</div><div class="n">${n}</div></div>`;
  const rows = r.per_label.map(p => `<tr><td><b>${esc(p.name)}</b><br><span class="mono" style="color:var(--faint);font-size:.72rem">${esc(p.label)}</span></td><td class="num">${p.rows}</td><td style="width:140px"><div class="hb"><i style="width:${p.f1 * 100}%"></i></div></td><td class="num">${p.f1.toFixed(3)}</td><td class="num">${p.cv_rows}</td><td class="num">${p.cv_f1.toFixed(3)}</td></tr>`).join('');
  const condColor = c => c[0] === 'A' ? '#F2A20C' : c[0] === 'B' ? '#1FBF9A' : '#A56BFF';
  const evalBlock = run => {
    const s = r.eval[run]; if (!s || !s.length) return '';
    const measures = [['Contradicted claims', x => [x.n_contradicted, x.claims], 'Statements that conflict with the reference.'], ['Unsupported claims', x => [x.n_contradicted + x.n_not_in_evidence, x.claims], 'Contradicted plus not found in the reference. Partly true general knowledge in condition A.'], ['Fabricated IDs', x => [x.n_fabricated, x.n_ids], 'IDs that do not exist in the official files.']];
    return `<h2>${esc(s[0].model)}</h2><div class="chart">${measures.map(([h, f, sub]) => `<div class="card grp"><h4>${h}</h4><div class="sub">${sub}</div>${s.map(x => { const [n, d] = f(x); return `<div class="row"><span>${esc(x.condition)}</span><span class="bb"><i style="width:${d ? 100 * n / d : 0}%;background:${condColor(x.condition)}"></i></span><span>${pc(n, d)}</span></div>`; }).join('')}</div>`).join('')}</div>`;
  };
  $('#resultsIn').innerHTML = `<h1>Model results</h1><div class="mono" style="color:var(--muted);font-size:.8rem">${esc(meta.dataset_name)} · ${m.train_rows.toLocaleString()} training flows · ${m.test_rows.toLocaleString()} test flows, each scored once</div>
    <div class="kpis">${kpi('Macro-F1 (headline)', t.macro_f1.toFixed(3), 'average over all labels, each counted equally')}${kpi('Accuracy', (100 * t.accuracy).toFixed(1) + '%', 'test flows labelled correctly')}${kpi('False alarms', (100 * t.false_alarm_rate).toFixed(2) + '%', `${t.false_alarms} of ${t.normal_flows.toLocaleString()} normal flows called an attack`)}${kpi('Port leakage check', (m.leakage_check.difference >= 0 ? '+' : '') + m.leakage_check.difference.toFixed(3), 'macro-F1 change when port columns are removed')}</div>
    <h2>Per label</h2><div class="card"><table class="t"><tr><th>Label</th><th class="num">Test rows</th><th></th><th class="num">Test F1</th><th class="num">CV rows</th><th class="num">CV F1</th></tr>${rows}</table><div class="note">Labels with few test rows have noisy test scores. The cross-validation (CV) F1 uses every training row of that label and is steadier.</div></div>
    <div class="two"><div><h2>Confusion matrix</h2><img class="cm" src="${r.confusion_png}" alt="Confusion matrix of the detector on the test set"></div>
    <div><h2>Model comparison</h2><div class="card"><table class="t"><tr><th>Model</th><th class="num">Macro-F1</th><th class="num">Accuracy</th></tr>${r.comparison.map(c => `<tr><td>${esc(c.model)}</td><td class="num">${c.macro_f1_pooled.toFixed(3)}</td><td class="num">${c.accuracy.toFixed(3)}</td></tr>`).join('')}</table><div class="note">5-fold cross-validation on the training part only.</div></div></div></div>
    <h1 style="margin-top:2.6rem">Hallucination evaluation</h1><div class="callout"><b>Read with care.</b> Counts are small. Condition B is judged against the same evidence it was told to use, so its unsupported rate is partly by design; the ID checks compare against the official files and do not have that bias. The judge is a light model whose agreement with a human has to be measured before these rates are quoted.</div>
    ${evalBlock('main')}${evalBlock('small')}
    <div class="note" style="margin-top:2rem">Dataset: ${esc(meta.citation)}</div>`;
  state.resultsLoaded = true;
}

/* ---------- start ---------- */
function showView(v) {
  $('#view-range').hidden = v !== 'range'; $('#view-results').hidden = v !== 'results';
  $$('.navbtn').forEach(b => b.classList.toggle('on', b.dataset.view === v));
  if (v === 'results') loadResults().catch(e => { $('#resultsIn').innerHTML = `<div class="err">Could not load results: ${esc(e.message)}</div>`; });
  else if (sim) sim.resize();
}
function backToArmory() {
  clearTimers(); resetStage(); resetAssistant(); setPhase('armory'); sim.start(IDLE); showView('range'); window.scrollTo(0, 0);
}
/* Clear everything a run leaves on the stage (stamp, scope bars, step pills, clock, readouts). */
function resetStage() {
  $('#stampwrap').innerHTML = ''; $('#bars').innerHTML = ''; $('#tele').innerHTML = ''; $('#hudTitle').innerHTML = '';
  $('#hudClock').textContent = '00.0 s'; $$('#steps li').forEach(li => { li.className = ''; });
  $('#stepMeasure').textContent = 'Measure features'; $('#stage').classList.remove('flash');
}

async function init() {
  sim = new Sim($('#sim')); sim.start(IDLE); sim.resize();
  $('#themeBtn').onclick = () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  $('#brand').onclick = backToArmory; $('#newattack').onclick = backToArmory;
  $('#again').onclick = () => state.lastOpts && launch(state.lastOpts);
  $$('.navbtn').forEach(b => b.onclick = () => showView(b.dataset.view));
  $$('#modes button').forEach(b => b.onclick = () => setMode(b.dataset.mode));
  $('#widen').onclick = () => setWide(!$('#assistant').classList.contains('wide-on'));
  $('#composer').onsubmit = e => { e.preventDefault(); const q = $('#q').value; $('#q').value = ''; send(q); };
  addEventListener('keydown', e => { if (e.key === 'Escape' && state.phase !== 'armory') backToArmory(); });
  try { state.meta = await api('/api/meta'); buildDeck(state.meta); }
  catch (e) { $('#hero').insertAdjacentHTML('beforeend', `<div class="err">Could not reach the server: ${esc(e.message)}</div>`); }
}
init();
