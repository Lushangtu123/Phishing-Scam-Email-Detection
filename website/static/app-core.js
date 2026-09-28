/* ──────────────────────────────────────────────────────────────────────────
   app-core.js – shared helpers for the PhishGuard homepage
   Translation helpers, errors, requests, HTML escaping, icons, motion and
   the live region. Loaded first of the app-*.js files (after i18n.js); they
   are classic scripts that share one global scope, and app.js (loaded last)
   wires them up.
   ────────────────────────────────────────────────────────────────────────── */

// ── Language ─────────────────────────────────────────────────────────────────
// i18n.js owns the dictionary and the active language. These wrappers keep the
// call sites short; t() returns the key itself only if i18n.js failed to load.
const i18n = () => window.PhishGuardI18n;
function t(key, params) { return i18n() ? i18n().t(key, params) : key; }
function tPlural(key, count, params) { return i18n() ? i18n().plural(key, count, params) : key; }
function uiLang() { return i18n() ? i18n().lang() : 'en'; }
// Server text identified by a stable code is localized only while it matches
// the dictionary's English; anything else is shown exactly as the server sent it.
function knownText(key, serverText) { return i18n() ? i18n().known(key, serverText) : serverText; }
// Risk level codes (high, medium, …) are shown raw in English, localized otherwise.
function levelName(level) { return knownText(`level.${level}`, level); }

// ── Errors & requests ────────────────────────────────────────────────────────
function setError(id, message = '') {
  const el = document.getElementById(id);
  el.textContent = message;
  el.classList.toggle('hidden', !message);
}

async function postJSON(url, payload) {
  return postRequest(url, JSON.stringify(payload), 'application/json');
}

async function postRequest(url, body, contentType) {
  let res;
  try {
    res = await fetch(url, {
      method: 'POST', headers: { 'Content-Type': contentType }, body,
    });
  } catch (_error) {
    throw new Error(t('request.error.network'));
  }
  if (res.status === 429) {
    const retry = res.headers?.get('Retry-After');
    const seconds = /^\d+$/.test(retry || '') ? Number(retry)
      : Math.ceil((Date.parse(retry) - Date.now()) / 1000);
    throw new Error(Number.isFinite(seconds) && seconds > 0
      ? t('request.error.retryIn', { seconds })
      : t('request.error.retryLater'));
  }
  if (res.status === 404 || res.status >= 500) {
    throw new Error(t('request.error.unavailable'));
  }
  let data;
  try { data = await res.json(); } catch (_error) {
    throw new Error(t('request.error.unreadable'));
  }
  if (!res.ok) {
    // A string detail is the server's own (English) message and is shown as sent.
    throw new Error(typeof data.detail === 'string' ? data.detail : t('request.error.invalid'));
  }
  return data;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);
}

// ── Icon system ──────────────────────────────────────────────────────────────
// Single stroke-based icon set (24px grid) so every symbol on the page shares
// the same weight and style, instead of platform-dependent emoji.
const ICON_PATHS = {
  shield:    '<path d="M12 2.5 4.5 5.5v6c0 4.6 3.2 8.6 7.5 9.9 4.3-1.3 7.5-5.3 7.5-9.9v-6L12 2.5z"/><path d="m9 12 2 2 4-4.5"/>',
  mail:      '<rect x="3" y="5" width="18" height="14" rx="3"/><path d="m3.5 7.5 8.5 6 8.5-6"/>',
  file:      '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h4"/>',
  check:     '<circle cx="12" cy="12" r="9"/><path d="m8.5 12.2 2.4 2.4 4.6-5"/>',
  alert:     '<path d="M12 3.8 2.9 19.5h18.2z"/><path d="M12 10v4.2"/><path d="M12 17.3h.01"/>',
  x:         '<circle cx="12" cy="12" r="9"/><path d="m9.2 9.2 5.6 5.6M14.8 9.2l-5.6 5.6"/>',
  search:    '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>',
  info:      '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.2"/><path d="M12 7.8h.01"/>',
  minus:     '<circle cx="12" cy="12" r="9"/><path d="M8.5 12h7"/>',
  trash:     '<path d="M4 7h16"/><path d="M9.5 7V4.5h5V7"/><path d="m6 7 1 13h10l1-13"/><path d="M10 11v5M14 11v5"/>',
  skull:     '<path d="M12 3a8 8 0 0 0-8 8c0 2.6 1.2 4.7 3 6v3.5h10V17c1.8-1.3 3-3.4 3-6a8 8 0 0 0-8-8z"/><circle cx="9.2" cy="11.5" r="1.3"/><circle cx="14.8" cy="11.5" r="1.3"/><path d="M10.5 20.5v-2.5M13.5 20.5v-2.5"/>',
  clock:     '<circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3 2"/>',
  bell:      '<path d="M6.5 9a5.5 5.5 0 0 1 11 0v4.5l1.8 2.7H4.7l1.8-2.7z"/><path d="M10 19.5a2 2 0 0 0 4 0"/>',
  dollar:    '<circle cx="12" cy="12" r="9"/><path d="M12 6.5v11"/><path d="M14.8 9.4c0-1.3-1.3-2-2.8-2s-2.8.7-2.8 2 1.3 1.7 2.8 2.1 2.8 1 2.8 2.3-1.3 2-2.8 2-2.8-.7-2.8-2"/>',
  key:       '<circle cx="8" cy="15" r="3.8"/><path d="m10.7 12.3 8.3-8.3"/><path d="m15.5 7.5 2.2 2.2M18 5l2 2"/>',
  mask:      '<path d="M4 6.5c4-1.6 12-1.6 16 0V12c0 4.2-4 7.3-8 8.5-4-1.2-8-4.3-8-8.5z"/><path d="M7.8 11.3c1-.9 2.2-.9 3.2 0M13 11.3c1-.9 2.2-.9 3.2 0"/>',
  eyeOff:    '<path d="m3 3 18 18"/><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8"/><path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c5 0 9 4.5 10 7-.4 1-1.3 2.4-2.6 3.7"/><path d="M6.6 6.6C4.3 8 2.7 10.2 2 12c1 2.5 5 7 10 7 1.5 0 2.9-.4 4.2-1"/>',
  paperclip: '<path d="m21 11.5-8.5 8.5a5 5 0 0 1-7-7l9-9a3.3 3.3 0 0 1 4.7 4.7l-9 9a1.6 1.6 0 0 1-2.3-2.3L16 7.2"/>',
  monitor:   '<rect x="3" y="4" width="18" height="12" rx="2.5"/><path d="M8 20h8M12 16v4"/>',
  briefcase: '<rect x="3" y="7" width="18" height="13" rx="2.5"/><path d="M8 7V5.5A2.5 2.5 0 0 1 10.5 3h3A2.5 2.5 0 0 1 16 5.5V7"/><path d="M3 12.5h18"/>',
  brain:     '<path d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 3 3h3V4z"/><path d="M15 4a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-3 3h-3V4z"/>',
  link:      '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2"/>',
  globe:     '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a13.5 13.5 0 0 1 0 18M12 3a13.5 13.5 0 0 0 0 18"/>',
  user:      '<circle cx="12" cy="8" r="3.8"/><path d="M4.5 20.5c0-3.9 3.4-6.5 7.5-6.5s7.5 2.6 7.5 6.5"/>',
  inbox:     '<path d="M3 13.5h5l1.8 2.5h4.4l1.8-2.5h5"/><path d="M5.5 5h13l2.5 8.5V19a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 19v-5.5z"/>',
  refresh:   '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/>',
  sparkle:   '<path d="M12 3.5 13.8 9l5.7 1.8-5.7 1.8L12 18.2l-1.8-5.6L4.5 10.8 10.2 9z"/>',
  award:     '<circle cx="12" cy="9" r="5.5"/><path d="m8.8 13.5-1.3 7 4.5-2.5 4.5 2.5-1.3-7"/>',
  dot:       '<circle cx="12" cy="12" r="4"/>',
};

function icon(name, extraClass = '') {
  const paths = ICON_PATHS[name] || ICON_PATHS.info;
  return `<svg class="ico${extraClass ? ' ' + extraClass : ''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
}

// ── Animated numbers & rings ─────────────────────────────────────────────────
function prefersReducedMotion() {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// Runs `update` inside a View Transition when supported and motion is allowed;
// otherwise applies it immediately. `done` always runs afterwards.
function withViewTransition(update, done = () => {}) {
  if (typeof document.startViewTransition !== 'function' || prefersReducedMotion()) {
    update(); done(); return;
  }
  document.startViewTransition(update).finished.finally(done);
}

// Counts el from 0 to target over `duration` ms and always finishes on the
// exact formatted value. Falls back to setting the value immediately when
// requestAnimationFrame is unavailable or reduced motion is requested.
const numberAnimations = new WeakMap();

function animateNumber(el, target, format, duration = 1100) {
  if (!el) return;
  const token = {};
  numberAnimations.set(el, token);
  const finish = () => { el.textContent = format(target); };
  if (typeof requestAnimationFrame !== 'function' || prefersReducedMotion() || !(target > 0)) {
    finish();
    return;
  }
  const start = performance.now();
  const step = now => {
    if (numberAnimations.get(el) !== token) return;
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = format(target * eased);
    if (t < 1) requestAnimationFrame(step); else finish();
  };
  requestAnimationFrame(step);
}

function setupCountUps() {
  document.querySelectorAll('[data-count]').forEach(el => {
    const target = parseFloat(el.dataset.count);
    const decimals = parseInt(el.dataset.decimals || '0', 10);
    const suffix = el.dataset.suffix || '';
    if (Number.isNaN(target)) return;
    animateNumber(el, target, value =>
      value.toLocaleString(i18n() ? i18n().locale() : 'en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix,
      1400);
  });
}

const RING_CIRCUMFERENCE = 2 * Math.PI * 44;

// Fills a .ring-fg circle to `pct` (0–100) in `color`.
function setRing(id, pct, color) {
  const ring = document.getElementById(id);
  if (!ring) return;
  const clamped = Math.max(0, Math.min(100, Number(pct) || 0));
  ring.style.strokeDasharray = `${RING_CIRCUMFERENCE}`;
  ring.style.stroke = color;
  // Start from empty so the fill animates via the CSS transition on the next frame.
  ring.style.strokeDashoffset = `${RING_CIRCUMFERENCE}`;
  const fill = () => { ring.style.strokeDashoffset = `${RING_CIRCUMFERENCE * (1 - clamped / 100)}`; };
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => requestAnimationFrame(fill));
  else fill();
}

function animateBar(id, pct) {
  const el = document.getElementById(id);
  el.style.width = '0%';
  setTimeout(() => { el.style.width = pct + '%'; }, 50);
}

// ── Live region ──────────────────────────────────────────────────────────────
// Speaks `message` through the #copy-status live region. Clearing it first
// makes a repeated identical message announce again.
function announce(message) {
  const status = document.getElementById('copy-status');
  if (!status) return;
  status.textContent = '';
  clearTimeout(status._announceTimer);
  status._announceTimer = setTimeout(() => { status.textContent = message; }, 50);
}
