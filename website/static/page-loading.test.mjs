// Page start-up: what runs before the network answers, what is fetched only
// when needed (Chart.js), heading order and the document metadata.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import {FakeElement, loadPage, memoryStorage, VISION_ANALYSIS} from '../tests/fixtures/i18n/scenarios.mjs';

const source = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
const APP_SCRIPTS = ['app-core.js', 'app-theme.js', 'app-layout.js', 'app-config.js', 'app-sender.js', 'app-verify.js',
  'app-content.js', 'app-content-render.js', 'app-reports.js', 'app-metrics.js', 'app.js'];
const METRICS = {'Random Forest': {Accuracy: 0.97, Precision: 0.96, Recall: 0.95, F1: 0.94, ROC_AUC: 0.99},
  'Naive Bayes': {Accuracy: 0.93, Precision: 0.92, Recall: 0.91, F1: 0.9, ROC_AUC: 0.95}};
const CHART_SRC = source('app-metrics.js').match(/const CHART_SRC = '([^']+)'/)[1];
const CHART_INTEGRITY = source('app-metrics.js').match(/const CHART_INTEGRITY = '([^']+)'/)[1];

// A homepage in the fake DOM whose document keeps its listeners and <head>.
function homepage({scripts = ['i18n.js', ...APP_SCRIPTS], ...overrides} = {}) {
  const listeners = {};
  const head = new FakeElement('head');
  const warnings = [];
  const page = loadPage(scripts, {
    document: {
      head,
      addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
      dispatchEvent(event) { (listeners[event.type] || []).forEach(fn => fn(event)); return true; },
    },
    CustomEvent, localStorage: memoryStorage(),
    console: {...console, warn: (...args) => warnings.push(args), error: (...args) => warnings.push(args)},
    ...overrides,
  });
  const read = name => vm.runInContext(name, page.context);
  return {...page, listeners, head, warnings, read};
}

// Chart.js stand-in: records what the page asks it to draw.
function fakeChartLibrary() {
  const instances = [];
  class Chart {
    constructor(ctx, config) { Object.assign(this, {ctx, config, data: config.data, options: config.options, updates: []}); instances.push(this); }
    update(mode) { this.updates.push(mode); }
    destroy() { this.destroyed = true; }
  }
  return {Chart, instances};
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const json = data => ({ok: true, status: 200, json: async () => data});

// ── Start-up order ───────────────────────────────────────────────────────────
test('in-page links work before /api/config and /api/metrics answer, and both requests start together', async () => {
  const requests = new Map();
  const fetch = url => { const pending = deferred(); requests.set(url, pending); return pending.promise; };
  const link = Object.assign(new FakeElement('a'), {getAttribute: () => '#performance'});
  const target = new FakeElement('section');
  const scrolled = [];
  target.tabIndex = -1;
  target.scrollIntoView = options => scrolled.push(options);
  let focused = null;
  target.focus = options => { focused = options; };
  const page = homepage({fetch, history: {pushState() {}}});
  page.document.querySelectorAll = selector => (selector === 'a[href^="#"]:not(.skip-link)' ? [link] : []);
  page.document.querySelector = selector => (selector === '#performance' ? target : new FakeElement());

  const ready = page.listeners.DOMContentLoaded.map(fn => fn());
  // Nothing has answered yet: both requests are already out, and the link works.
  assert.deepEqual([...requests.keys()], ['/api/config', '/api/metrics']);
  assert.equal(typeof link.listeners.click, 'function', 'smooth scrolling is bound without waiting for the network');
  let prevented = false;
  link.listeners.click({preventDefault: () => { prevented = true; }});
  assert.ok(prevented);
  assert.equal(scrolled.length, 1);
  assert.equal(focused.preventScroll, true);

  // Metrics answering first (before config) renders the table at once.
  requests.get('/api/metrics').resolve(json({metrics: METRICS}));
  await tick();
  assert.match(page.elements.get('metrics-tbody').innerHTML, /Random Forest/);
  requests.get('/api/config').resolve(json({feedback_enabled: true}));
  await Promise.all(ready);
  assert.equal(page.read('_publicConfig').feedback_enabled, true);
});

test('a failed config request does not stop the metrics table, and the reverse', async () => {
  for (const failing of ['/api/config', '/api/metrics']) {
    const page = homepage({fetch: async url => {
      if (url === failing) throw new TypeError('offline');
      return json(url === '/api/metrics' ? {metrics: METRICS} : {feedback_enabled: true});
    }});
    await Promise.all(page.listeners.DOMContentLoaded.map(fn => fn()));
    const tbody = page.elements.get('metrics-tbody').innerHTML;
    if (failing === '/api/config') {
      assert.match(tbody, /Random Forest/);
      assert.equal(page.read('_publicConfig').email_verification_enabled, false, 'safe defaults');
    } else {
      assert.match(tbody, /unavailable/);
      assert.equal(page.read('_publicConfig').feedback_enabled, true);
    }
  }
});

// ── Chart.js on demand ───────────────────────────────────────────────────────
test('index.html does not load Chart.js; it is requested with its SRI pin when #performance nears the viewport', () => {
  const html = source('index.html');
  assert.doesNotMatch(html, /chart\.umd|vendor\/chart/);
  const observers = [];
  class IntersectionObserver {
    constructor(callback, options) { Object.assign(this, {callback, options, observed: [], disconnected: false}); observers.push(this); }
    observe(element) { this.observed.push(element); }
    disconnect() { this.disconnected = true; }
  }
  const page = homepage({IntersectionObserver});
  page.context.setupMetricsChartLoader();
  assert.equal(observers.length, 1);
  assert.deepEqual(observers[0].observed, [page.elements.get('performance')]);
  assert.match(observers[0].options.rootMargin, /^600px\b/);
  assert.deepEqual(page.head.children, [], 'nothing is requested while the section is far away');
  observers[0].callback([{isIntersecting: false}]);
  assert.deepEqual(page.head.children, []);
  observers[0].callback([{isIntersecting: true}]);
  assert.equal(page.head.children.length, 1);
  const [script] = page.head.children;
  assert.equal(script.tagName, 'SCRIPT');
  assert.equal(script.src, CHART_SRC);
  assert.equal(script.integrity, CHART_INTEGRITY);
  assert.equal(script.crossOrigin, undefined, 'same-origin: SRI needs no crossorigin attribute');
  assert.equal(observers[0].disconnected, true);
  // Requested once, however often it is asked for.
  page.context.loadChartLibrary();
  assert.equal(page.head.children.length, 1);
});

test('without IntersectionObserver Chart.js is requested at once', () => {
  const page = homepage();
  page.context.setupMetricsChartLoader();
  assert.equal(page.head.children.length, 1);
  assert.equal(page.head.children[0].src, CHART_SRC);
});

test('the table renders without Chart.js; the chart follows when the library arrives, in the current theme and language', async () => {
  const page = homepage({scripts: ['i18n-zh.js', 'i18n.js', ...APP_SCRIPTS], fetch: async () => json({metrics: METRICS})});
  page.elements.set('metricsChart', Object.assign(new FakeElement('canvas'), {getContext: () => ({canvas: true})}));
  await page.context.loadMetrics();
  assert.match(page.elements.get('metrics-tbody').innerHTML, /Random Forest[\s\S]*Naive Bayes/);
  assert.equal(page.read('metricsChart'), null, 'no chart without the library');
  page.context.restyleMetricsChart();
  page.context.relabelMetrics();

  // The visitor switches language and theme before the library arrives.
  page.window.PhishGuardI18n.setLang('zh');
  page.document.documentElement.dataset.theme = 'light';
  page.context.setupMetricsChartLoader();
  const [script] = page.head.children;
  const {Chart, instances} = fakeChartLibrary();
  page.context.Chart = Chart;
  script.listeners.load();
  assert.equal(instances.length, 1);
  const chart = instances[0];
  assert.deepEqual(Array.from(chart.data.labels), ['准确率', '精确率', '召回率', 'F1', 'ROC AUC']);
  assert.deepEqual(Array.from(chart.data.datasets, set => set.label), ['Random Forest', 'Naive Bayes']);
  assert.equal(chart.data.datasets[0].backgroundColor, 'rgba(10,127,214,0.80)', 'light palette');

  // Theme and language changes after the late load re-style the same chart.
  page.document.documentElement.dataset.theme = 'dark';
  page.context.restyleMetricsChart();
  assert.equal(chart.data.datasets[0].backgroundColor, 'rgba(79,209,255,0.80)');
  page.window.PhishGuardI18n.setLang('en');
  assert.deepEqual(Array.from(chart.data.labels), ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC AUC']);
  assert.deepEqual(chart.updates, ['none', 'none']);
  assert.equal(instances.length, 1, 'no second chart');
});

test('Chart.js arriving before the metrics draws the chart when they load', async () => {
  const {Chart, instances} = fakeChartLibrary();
  const page = homepage({Chart, fetch: async () => json({metrics: METRICS})});
  page.elements.set('metricsChart', Object.assign(new FakeElement('canvas'), {getContext: () => ({})}));
  page.context.setupMetricsChartLoader();
  assert.deepEqual(page.head.children, [], 'an already present library is not fetched again');
  assert.equal(instances.length, 0);
  await page.context.loadMetrics();
  assert.equal(instances.length, 1);
  assert.deepEqual(Array.from(instances[0].data.labels), ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC AUC']);
});

test('a Chart.js load or integrity failure keeps the table and throws nothing', async () => {
  for (const outcome of ['error', 'load-without-Chart']) {
    const page = homepage({fetch: async () => json({metrics: METRICS})});
    page.context.setupMetricsChartLoader();
    await page.context.loadMetrics();
    const [script] = page.head.children;
    assert.doesNotThrow(() => (outcome === 'error' ? script.listeners.error() : script.listeners.load()));
    assert.equal(page.read('_chartLibrary'), 'failed');
    assert.equal(page.read('metricsChart'), null);
    assert.match(page.elements.get('metrics-tbody').innerHTML, /Random Forest/);
    assert.doesNotThrow(() => { page.context.restyleMetricsChart(); page.context.relabelMetrics(); });
    assert.equal(page.warnings.length, 1);
    page.context.loadChartLibrary();
    assert.equal(page.head.children.length, 1, 'a failure is not retried in a loop');
  }
});

test('the chart canvas keeps its text alternative', () => {
  assert.match(source('index.html'), /<canvas id="metricsChart" role="img" aria-label="[^"]*table above[^"]*"/);
});

// ── Heading order ────────────────────────────────────────────────────────────
// `start` is the level of the heading the sequence sits under (0: none).
function assertOrdered(levels, label, start = 0) {
  levels.reduce((previous, level) => {
    assert.ok(level <= previous + 1, `${label}: heading jumps from h${previous} to h${level}`);
    return level;
  }, start);
}
const headingLevels = html => [...html.matchAll(/<h([1-6])\b/g)].map(match => Number(match[1]));

test('both pages have ordered headings; the disposable-email card title is an h3 above its h4s', () => {
  const index = source('index.html');
  assertOrdered(headingLevels(index), 'index.html');
  // Result areas are in the markup (hidden until shown), so the scan covers them too.
  assert.match(index, /<h3 class="di-title" data-i18n="di\.title">/);
  const card = index.slice(index.indexOf('id="disposable-info"'), index.indexOf('di-domains'));
  assert.deepEqual(headingLevels(card), [3, 4, 4, 4]);
  // The dialog is its own context and starts at h2.
  const dialog = index.slice(index.indexOf('<dialog'), index.indexOf('</dialog>'));
  assert.deepEqual(headingLevels(dialog), [2]);
  // The workspace: sign-in or cases (each an h1), then h2 panels, h3 sections.
  const cases = source('cases.html');
  const workspace = cases.indexOf('id="workspace"');
  assert.ok(workspace > cases.indexOf('id="login-panel"'));
  assert.deepEqual(headingLevels(cases.slice(0, workspace)), [1]);
  assertOrdered(headingLevels(cases.slice(workspace)), 'cases.html workspace');
  // The heading reset keeps the title's look.
  assert.match(source('style.css'), /\.di-title \{[^}]*font-size: 20px;[^}]*text-wrap: wrap;/);
});

test('rendered image evidence fits the heading outline where it is shown', () => {
  // vision.js is the only script that writes headings: an h3, then h4 per image.
  for (const name of ['app-core.js', 'app-sender.js', 'app-verify.js', 'app-content-render.js', 'app-reports.js', 'app-metrics.js',
    'app-layout.js', 'feedback.js', 'file-intake.js', 'confirm-dialog.js', 'cases.js']) {
    assert.doesNotMatch(source(name), /<h[1-6]\b|createElement\('h[1-6]'\)|node\('h[1-6]'/, name);
  }
  const nodes = [];
  const context = vm.createContext({window: {}, navigator: {languages: ['en-US']}, console, setTimeout, clearTimeout,
    URL: {createObjectURL: () => 'blob:x', revokeObjectURL() {}},
    document: {createElement: tag => { const node = {tag, children: [], textContent: '', append(...n) { this.children.push(...n); }}; nodes.push(node); return node; }}});
  vm.runInContext(source('vision.js'), context);
  const root = {children: [], append(...n) { this.children.push(...n); }, replaceChildren(...n) { this.children = n; }};
  context.window.PhishGuardVision.render(root, VISION_ANALYSIS, {name: 'invoice.png', size: 10, type: 'image/png'});
  const walk = node => [...(/^h[1-6]$/.test(node.tag || '') ? [Number(node.tag[1])] : []), ...(node.children || []).flatMap(walk)];
  const rendered = walk(root);
  assert.equal(rendered[0], 3);
  assert.ok(rendered.filter(level => level === 4).length >= 6, 'an h4 per image and for the enhancement');
  assertOrdered(rendered, 'image evidence', 2);
  // Where it is placed: under an h2 or h3 on both pages.
  for (const page of ['index.html', 'cases.html']) {
    const html = source(page);
    const before = headingLevels(html.slice(0, html.indexOf('id="visual-evidence"')));
    assert.ok(before.at(-1) >= 2, `${page}: image evidence follows h${before.at(-1)}`);
  }
});

// ── Document metadata ────────────────────────────────────────────────────────
const attribute = (tag, name) => tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1];
const metaTags = html => [...html.slice(0, html.indexOf('</head>')).matchAll(/<meta\b[^>]*>/g)].map(match => match[0]);
const metaContent = (html, key, value) => attribute(metaTags(html).find(tag => attribute(tag, key) === value) || '', 'content');

test('the homepage has a description and Open Graph / Twitter metadata; the workspace is not indexed', () => {
  const index = source('index.html');
  const description = metaContent(index, 'name', 'description');
  assert.ok(description && description.length <= 170, description);
  assert.match(description, /heuristic/i, 'no stronger claim than the page makes');
  assert.match(description, /not a guarantee/);
  assert.equal(metaContent(index, 'property', 'og:description'), description);
  assert.equal(metaContent(index, 'property', 'og:title'), index.match(/<title>([^<]+)<\/title>/)[1]);
  assert.equal(metaContent(index, 'property', 'og:type'), 'website');
  assert.equal(metaContent(index, 'property', 'og:site_name'), 'PhishGuard');
  assert.equal(metaContent(index, 'name', 'twitter:card'), 'summary');
  assert.doesNotMatch(index, /og:image/, 'no suitable same-origin image exists');
  assert.equal(metaContent(index, 'name', 'robots'), undefined);
  assert.match(metaTags(index).find(tag => /name="description"/.test(tag)), /data-i18n-attr="content:meta\.description"/);

  const cases = source('cases.html');
  assert.ok(metaContent(cases, 'name', 'description'));
  assert.match(metaTags(cases).find(tag => /name="description"/.test(tag)), /data-i18n-attr="content:cases\.meta\.description"/);
  assert.equal(metaContent(cases, 'name', 'robots'), 'noindex');
});
