/* ──────────────────────────────────────────────────────────────────────────
   app-theme.js – theme toggle (auto / light / dark)
   ────────────────────────────────────────────────────────────────────────── */

// ── Theme (auto / light / dark) ──────────────────────────────────────────────
// The <head> bootstrap script sets data-theme before first paint; this keeps it
// in sync with system changes and drives the nav toggle.
const THEME_KEY = 'phishguard-theme';

function resolveTheme(mode) {
  if (mode === 'light' || mode === 'dark') return mode;
  const prefersLight = typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches;
  return prefersLight ? 'light' : 'dark';
}

function applyTheme(mode) {
  const root = document.documentElement;
  if (!root || !root.dataset) return;
  root.dataset.theme = resolveTheme(mode);
  root.dataset.themeMode = mode;
  const toggle = document.getElementById('theme-toggle');
  if (toggle) toggle.title = `Theme: ${mode}`;
  restyleMetricsChart();
}

function cycleTheme(event) {
  const order = ['auto', 'light', 'dark'];
  const root = document.documentElement;
  const current = (root && root.dataset && root.dataset.themeMode) || 'auto';
  const next = order[(order.indexOf(current) + 1) % order.length];
  try {
    if (next === 'auto') localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, next);
  } catch (error) { /* storage unavailable; theme still applies for this page */ }
  const willChange = resolveTheme(next) !== (root && root.dataset && root.dataset.theme);
  if (!willChange || !root) return applyTheme(next);
  // Reveal the new theme as a circle growing from the toggle button.
  const origin = event && event.currentTarget && event.currentTarget.getBoundingClientRect
    ? event.currentTarget.getBoundingClientRect() : null;
  const x = origin ? origin.left + origin.width / 2 : innerWidth / 2;
  const y = origin ? origin.top + origin.height / 2 : 0;
  root.style.setProperty('--vt-x', `${x}px`);
  root.style.setProperty('--vt-y', `${y}px`);
  root.style.setProperty('--vt-r', `${Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y))}px`);
  root.classList.add('theme-transition');
  withViewTransition(() => applyTheme(next), () => root.classList.remove('theme-transition'));
}

function setupTheme() {
  const root = document.documentElement;
  const mode = (root && root.dataset && root.dataset.themeMode) || 'auto';
  applyTheme(mode);
  if (typeof matchMedia === 'function') {
    matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
      const currentMode = (root.dataset && root.dataset.themeMode) || 'auto';
      if (currentMode === 'auto') applyTheme('auto');
    });
  }
}
