/* ──────────────────────────────────────────────────────────────────────────
   app.js – PhishGuard frontend entry point
   Loaded last, after i18n.js and app-core, app-theme, app-layout,
   app-config, app-sender, app-verify, app-content, app-content-render,
   app-sms, app-reports and app-metrics (classic scripts sharing one global scope).
   It binds page actions, runs the setup functions on DOMContentLoaded and
   re-renders script-written text when the language changes.
   ────────────────────────────────────────────────────────────────────────── */

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupPageActions();
  setupDemoTabs();
  setupRecentChecks();
  setupTheme();
  setupScrollReveal();
  setupCountUps();
  setupInputEvents();
  setupSmsInput();
  setupMobileNav();
  setupCaseLoginLink();
  setupShortcuts();
  setupSmoothScroll();
  setupMetricsChartLoader();
  // Independent requests: each renders its own part of the page and handles
  // its own errors, so they run in parallel and no page control waits on them.
  return Promise.all([loadPublicConfig(), loadMetrics()]);
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
  'cancel-email':        () => cancelEmailAnalysis(),
  'set-example':         arg => setExample(arg),
  'copy-summary':        (arg, event) => copySummary(arg, event.currentTarget),
  'open-feedback':       arg => openFeedback(arg),
  'verify-email':        () => runVerification(),
  'clear-content':       () => clearContent(),
  'analyze-content':     () => runContentAnalysis(),
  'set-content-example': arg => setContentExample(arg),
  'clear-sms':           () => clearSms(),
  'analyze-sms':         () => runSmsAnalysis(),
  'set-sms-example':     arg => setSmsExample(arg),
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

// ── Language switch ──────────────────────────────────────────────────────────
// i18n.js has already re-applied the static markup. Re-render what scripts
// wrote from the last API responses; no analysis request is repeated.
function rerenderForLanguage() {
  const hidden = id => document.getElementById(id).classList.contains('hidden');
  refreshMobileNavLabel();
  updateThemeToggleTitle(document.documentElement?.dataset?.themeMode || 'auto');
  renderVerificationNotice();
  renderRawStatus();
  document.getElementById('analyze-btn-text').textContent =
    t(document.getElementById('analyze-btn').disabled ? 'sender.analyzing' : 'sender.analyze');
  document.getElementById('content-btn-text').textContent =
    t(document.getElementById('content-analyze-btn').disabled ? 'content.scanning' : 'content.analyze');
  if (lastResults.sender && !hidden('result-area')) {
    renderResult(lastResults.sender, { languageOnly: true });
    if (_lastVerifyResult && !hidden('verify-result')) renderVerifyResult(_lastVerifyResult);
  }
  refreshMailboxHint();
  if (lastResults.content && !hidden('content-result-area')) {
    renderContentResult(lastResults.content, { languageOnly: true });
    window.PhishGuardVision?.render(document.getElementById('visual-evidence'), lastResults.content.visual_analysis, _visualFile);
  }
  rerenderSmsForLanguage();
  renderRecentChecks();
  relabelMetrics();
}

document.addEventListener('phishguard:languagechange', rerenderForLanguage);
// i18n.js could not fetch the Chinese strings; the page stayed in English.
document.addEventListener('phishguard:languageerror', () => announce(t('nav.lang.failed')));

// ── Navbar ───────────────────────────────────────────────────────────────────
window.addEventListener('scroll', () => {
  document.querySelector('.navbar').classList.toggle('scrolled', window.scrollY > 30);
}, { passive: true });
