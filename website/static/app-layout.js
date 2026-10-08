/* ──────────────────────────────────────────────────────────────────────────
   app-layout.js – page chrome and navigation
   Demo tabs and ?tab= deep links, the case login link, the mobile menu,
   scroll reveal, keyboard shortcuts and smooth in-page scrolling.
   ────────────────────────────────────────────────────────────────────────── */

// ── Demo Tab Switcher ─────────────────────────────────────────────────────────
// ?tab=address|content|sms deep-links a tab (sms only while the SMS tab is shown). It is a query parameter rather than
// the hash because in-page links already push #demo, #about, … to the URL.
const TAB_QUERY_VALUES = new Map([['address', 'email-address'], ['content', 'email-content'], ['sms', 'sms']]);

function tabFromSearch(search) {
  try {
    return TAB_QUERY_VALUES.get(new URLSearchParams(search || '').get('tab')) || null;
  } catch (_error) { return null; }
}

// Replaces (never pushes) the URL so switching tabs adds no history entries;
// the current #hash is kept.
function syncTabQuery(tabName) {
  if (typeof history === 'undefined' || typeof location === 'undefined') return;
  const value = [...TAB_QUERY_VALUES].find(([, name]) => name === tabName)?.[0];
  if (!value) return;
  try {
    const url = new URL(location.href);
    url.searchParams.set('tab', value);
    history.replaceState(history.state, '', url.pathname + url.search + url.hash);
  } catch (_error) { /* URL or history unavailable; the tab still switches */ }
}

// A view transition applies its update a frame later, so the requested tab is
// tracked here; a quick second switch (e.g. arrow keys) is then not dropped, and
// whichever update runs last shows the latest request.
let _requestedDemoTab = null;

function switchDemoTab(tabName, { animate = true, updateUrl = true } = {}) {
  const requested = document.getElementById('tab-' + tabName);
  if (!requested || requested.hidden) return;
  const current = _requestedDemoTab || document.querySelector('.demo-tab.active')?.id?.replace(/^tab-/, '');
  if (tabName === current) return;
  _requestedDemoTab = tabName;
  const update = () => {
    const name = _requestedDemoTab;
    const tab = document.getElementById('tab-' + name);
    document.querySelectorAll('.demo-tab').forEach(t => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
      t.setAttribute('tabindex', '-1');
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
    tab.classList.add('active');
    tab.setAttribute('aria-selected', 'true');
    tab.removeAttribute('tabindex');
    document.getElementById('panel-' + name).classList.remove('hidden');
  };
  if (animate) withViewTransition(update); else update();
  if (updateUrl) syncTabQuery(tabName);
}

// Arrow/Home/End keys move between demo tabs (ARIA tab pattern). A ?tab= link
// opens its tab straight away, without the switch animation.
function setupDemoTabs() {
  const linked = typeof location !== 'undefined' ? tabFromSearch(location.search) : null;
  if (linked) switchDemoTab(linked, { animate: false, updateUrl: false });
  const tablist = document.querySelector('.demo-tabs');
  if (!tablist) return;
  tablist.addEventListener('keydown', event => {
    const tabs = [...tablist.querySelectorAll('[role="tab"]')].filter(tab => !tab.hidden);
    const index = tabs.indexOf(document.activeElement);
    const target = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 }[event.key];
    if (index < 0 || target === undefined) return;
    event.preventDefault();
    const tab = tabs[(target + tabs.length) % tabs.length];
    tab.focus();
    switchDemoTab(tab.dataset.arg);
  });
}

// ── Case login link ──────────────────────────────────────────────────────────
// Deployed pages link to the stable production workspace (docs/case-workflow.md);
// a local server should open its own /cases instead.
const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

function caseLoginHref(hostname, deployedHref) {
  return LOCAL_HOSTNAMES.has(hostname) ? '/cases' : deployedHref;
}

function setupCaseLoginLink() {
  if (typeof location === 'undefined') return;
  document.querySelectorAll('.case-login, .case-login-link').forEach(link => {
    link.setAttribute('href', caseLoginHref(location.hostname, link.getAttribute('href')));
  });
}

// ── Mobile section menu ──────────────────────────────────────────────────────
function mobileNavLabel(open) { return t(open ? 'nav.menu.close' : 'nav.menu.open'); }

// Re-labels the menu button for its current state, e.g. after a language switch.
function refreshMobileNavLabel() {
  const navbar = document.querySelector('.navbar');
  const toggle = document.getElementById('nav-menu-toggle');
  if (navbar && toggle) toggle.setAttribute('aria-label', mobileNavLabel(navbar.classList.contains('menu-open')));
}

function setupMobileNav() {
  const navbar = document.querySelector('.navbar');
  const toggle = document.getElementById('nav-menu-toggle');
  if (!navbar || !toggle) return;
  const setOpen = open => {
    navbar.classList.toggle('menu-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', mobileNavLabel(open));
  };
  toggle.addEventListener('click', () => setOpen(!navbar.classList.contains('menu-open')));
  document.querySelectorAll('.nav-links a').forEach(link => link.addEventListener('click', () => setOpen(false)));
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && navbar.classList.contains('menu-open')) { setOpen(false); toggle.focus(); }
  });
  document.addEventListener('click', event => {
    if (navbar.classList.contains('menu-open') && !navbar.contains(event.target)) setOpen(false);
  });
  window.addEventListener('resize', () => { if (window.innerWidth > 900) setOpen(false); }, { passive: true });
}

// ── Scroll reveal ────────────────────────────────────────────────────────────
// Elements fade/slide in the first time they enter the viewport. Without
// IntersectionObserver (or with reduced-motion) nothing is hidden, so content
// is always reachable.
const REVEAL_SELECTORS = [
  '.section-header', '.demo-tabs', '.email-input-card', '.content-input-card',
  '.disposable-info-card', '.metrics-table-wrap', '.chart-card',
  '.signals-all', '.step', '.tech-stack',
];
const REVEAL_GROUPS = [
  '.hero-stats', '.charts-row', '.bento', '.pipeline-steps',
];

function setupScrollReveal() {
  if (typeof IntersectionObserver === 'undefined') return;
  if (typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const targets = new Set(document.querySelectorAll(REVEAL_SELECTORS.join(',')));
  REVEAL_GROUPS.forEach(groupSelector => {
    document.querySelectorAll(groupSelector).forEach(group => {
      Array.from(group.children).forEach(child => targets.add(child));
    });
  });

  const observer = new IntersectionObserver(entries => {
    // Stagger only among siblings that enter the viewport in the same batch,
    // so an element scrolled into view on its own starts immediately.
    const perParent = new Map();
    entries
      .filter(entry => entry.isIntersecting)
      .sort((a, b) => (a.target.compareDocumentPosition(b.target) & 4 ? -1 : 1))
      .forEach(entry => {
        const el = entry.target;
        const parent = el.parentElement;
        const index = perParent.get(parent) || 0;
        perParent.set(parent, index + 1);
        el.style.setProperty('--reveal-delay', `${Math.min(index, 6) * 60}ms`);
        el.addEventListener('animationend', event => {
          if (event.target !== el) return;
          el.classList.remove('reveal', 'in-view');
          el.style.removeProperty('--reveal-delay');
        });
        el.classList.add('in-view');
        observer.unobserve(el);
      });
  }, { rootMargin: '0px 0px -6% 0px', threshold: 0.05 });

  targets.forEach(el => {
    el.classList.add('reveal');
    observer.observe(el);
  });
}

// ── Keyboard shortcuts ───────────────────────────────────────────────────────
function isTypingTarget(el) {
  return Boolean(el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName || '')));
}

function setupShortcuts() {
  document.addEventListener('keydown', event => {
    if (event.key !== '/' || event.metaKey || event.ctrlKey || event.altKey) return;
    if (isTypingTarget(event.target) || document.querySelector('dialog[open]')) return;
    event.preventDefault();
    const contentActive = !document.getElementById('panel-email-content').classList.contains('hidden');
    const field = document.getElementById(contentActive ? 'content-body' : 'email-input');
    field.focus({ preventScroll: true });
    field.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'center' });
  });
  const analyzeOnModEnter = event => {
    if (event.key !== 'Enter' || !(event.metaKey || event.ctrlKey)) return;
    event.preventDefault();
    if (!document.getElementById('content-analyze-btn').disabled) runContentAnalysis();
  };
  ['content-subject', 'content-body'].forEach(id => {
    const field = document.getElementById(id);
    if (field) field.addEventListener('keydown', analyzeOnModEnter);
  });
}

// ── Smooth Scroll & Navbar ────────────────────────────────────────────────────
function setupSmoothScroll() {
  // The skip link keeps native behaviour so keyboard focus moves into <main>.
  document.querySelectorAll('a[href^="#"]:not(.skip-link)').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const href = a.getAttribute('href');
      const target = document.querySelector(href);
      if (!target) return;
      target.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
      // Keep the URL shareable and put keyboard focus where the page scrolled to.
      if (typeof history !== 'undefined') history.pushState(null, '', href);
      if (target.tabIndex < 0 && !target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
      target.focus({ preventScroll: true });
    });
  });
}
