/* ──────────────────────────────────────────────────────────────────────────
   app.js – PhishGuard frontend entry point
   Loaded last, after app-core, app-theme, app-layout, app-config,
   app-sender, app-verify, app-content, app-content-render, app-reports
   and app-metrics (classic scripts sharing one global scope). It binds
   page actions and runs the setup functions on DOMContentLoaded.
   ────────────────────────────────────────────────────────────────────────── */

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  setupPageActions();
  setupDemoTabs();
  setupRecentChecks();
  setupTheme();
  setupScrollReveal();
  setupCountUps();
  setupInputEvents();
  setupMobileNav();
  setupCaseLoginLink();
  setupShortcuts();
  await loadPublicConfig();
  await loadMetrics();
  setupSmoothScroll();
});

// ── Page actions ─────────────────────────────────────────────────────────────
// Controls declare data-action (and optional data-arg) instead of inline
// handlers, so the page CSP needs no script-src 'unsafe-inline'. Only actions
// listed here are bound; each listener sits on its element, as inline ones did.
const PAGE_ACTIONS = {
  'cycle-theme':         (_arg, event) => cycleTheme(event),
  'switch-tab':          arg => switchDemoTab(arg),
  'clear-email':         () => clearEmail(),
  'analyze-email':       () => runEmailAnalysis(),
  'set-example':         arg => setExample(arg),
  'copy-summary':        (arg, event) => copySummary(arg, event.currentTarget),
  'open-feedback':       arg => openFeedback(arg),
  'verify-email':        () => runVerification(),
  'clear-content':       () => clearContent(),
  'analyze-content':     () => runContentAnalysis(),
  'set-content-example': arg => setContentExample(arg),
  'download-report':     arg => downloadReport(...String(arg).split(':')),
  'clear-recent':        () => clearRecentChecks(),
};

function setupPageActions() {
  document.querySelectorAll('[data-action]').forEach(element => {
    const action = PAGE_ACTIONS[element.dataset.action];
    if (action) element.addEventListener('click', event => action(element.dataset.arg, event));
  });
  document.getElementById('email-input').addEventListener('keydown', event => {
    if (event.key === 'Enter') runEmailAnalysis();
  });
}

// ── Navbar ───────────────────────────────────────────────────────────────────
window.addEventListener('scroll', () => {
  document.querySelector('.navbar').classList.toggle('scrolled', window.scrollY > 30);
}, { passive: true });
