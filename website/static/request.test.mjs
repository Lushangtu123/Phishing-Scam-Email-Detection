// Request time limits and cancellation (request.js) and how the homepage uses
// them: timeouts with their own message, the Cancel buttons, late responses.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import {loadPage} from '../tests/fixtures/i18n/scenarios.mjs';

const source = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
const APP_SCRIPTS = ['app-core.js', 'app-theme.js', 'app-layout.js', 'app-config.js', 'app-sender.js', 'app-verify.js',
  'app-content.js', 'app-content-render.js', 'app-sms.js', 'app-reports.js', 'app-metrics.js', 'app.js'];
const TIMEOUT_TEXT = 'The service took too long to respond. Try again.';
const tick = () => new Promise(resolve => setImmediate(resolve));

// A manual clock: setTimeout callbacks run only when advance() passes them.
function fakeClock() {
  let now = 0, nextId = 1;
  const timers = new Map();
  return {
    setTimeout: (fn, ms = 0) => { const id = nextId++; timers.set(id, {fn, at: now + ms}); return id; },
    clearTimeout: id => { timers.delete(id); },
    pending: () => timers.size,
    async advance(ms) {
      const until = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]); now = due[1].at; due[1].fn();
        await tick();
      }
      now = until;
      await tick();
    },
  };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return {promise, resolve, reject};
}

// request.js on its own, as a page loads it.
function loadRequest(overrides = {}) {
  const clock = fakeClock();
  const window = {};
  const context = vm.createContext({window, AbortController, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout, ...overrides});
  vm.runInContext(source('request.js'), context, {filename: 'request.js'});
  return {request: window.PhishGuardRequest, clock};
}

// The homepage scripts with request.js, AbortController and a manual clock.
// `fetch` records each call; tests answer them through the returned list.
function homepage({withRequest = true} = {}) {
  const clock = fakeClock();
  const calls = [];
  const fetch = (url, init) => { const call = {url, init, ...deferred()}; calls.push(call); return call.promise; };
  const warnings = [];
  const page = loadPage(['i18n.js', ...(withRequest ? ['request.js'] : []), ...APP_SCRIPTS], {
    AbortController, fetch, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
    console: {...console, warn: (...args) => warnings.push(args), error: (...args) => warnings.push(args)},
  });
  const read = expression => vm.runInContext(expression, page.context);
  return {...page, clock, calls, warnings, read, el: id => page.document.getElementById(id)};
}
const json = data => ({ok: true, status: 200, json: async () => data});
const SENDER = {email: 'a@example.com', verdict: 'low', label: 'Low Sender Risk', risk_score: 3, risk_indicators: [],
  high_risk_count: 0, med_risk_count: 0, feature_breakdown: [], disposable_status: 'no_known_match'};
const CONTENT = {risk_level: 'low', risk_label: 'Low Risk', risk_score: 5, category_results: [], extra_indicators: []};

// ── request.js ───────────────────────────────────────────────────────────────
test('request.js limits: 45 s for analyses and saves, 15 s for small reads', () => {
  const {request} = loadRequest();
  assert.equal(request.TIMEOUTS.action, 45000);
  assert.equal(request.TIMEOUTS.read, 15000);
  assert.ok(Object.isFrozen(request.TIMEOUTS));
  // The server limits they are measured against.
  const vercel = JSON.parse(readFileSync(new URL('../../vercel.json', import.meta.url), 'utf8'));
  assert.ok(request.TIMEOUTS.action > vercel.functions['app.py'].maxDuration * 1000);
  const verificationDeadline = Number(readFileSync(new URL('../app.py', import.meta.url), 'utf8').match(/^VERIFICATION_TIMEOUT = ([\d.]+)$/m)[1]);
  assert.ok(request.TIMEOUTS.action > verificationDeadline * 1000);
});

test('request.js times out, aborting the fetch signal, and clears its timer on success', async () => {
  const {request, clock} = loadRequest();
  let seen;
  const pending = request.run(signal => { seen = signal; return new Promise(() => {}); }, {timeout: 1000});
  assert.equal(seen.aborted, false, 'work starts synchronously with a live signal');
  let settled = false;
  pending.catch(() => {}).finally(() => { settled = true; });
  await clock.advance(999);
  assert.equal(settled, false);
  await clock.advance(1);
  await assert.rejects(pending, error => error.timedOut === true && error.aborted === false && error.name === 'TimeoutError');
  assert.equal(seen.aborted, true);

  const done = await request.run(async () => 'ok', {timeout: 1000});
  assert.equal(done, 'ok');
  assert.equal(clock.pending(), 0, 'no timer is left behind');
  await assert.rejects(request.run(async () => { throw new Error('network'); }), /network/);
  assert.equal(clock.pending(), 0);
});

test('request.js follows the caller signal, before and during the request', async () => {
  const {request, clock} = loadRequest();
  const outer = new AbortController();
  let seen;
  const pending = request.run(signal => { seen = signal; return new Promise(() => {}); }, {signal: outer.signal});
  outer.abort();
  await assert.rejects(pending, error => error.aborted === true && error.timedOut === false && error.name === 'AbortError');
  assert.equal(seen.aborted, true);
  assert.equal(clock.pending(), 0);

  const early = new AbortController(); early.abort();
  await assert.rejects(request.run(signal => { seen = signal; return new Promise(() => {}); }, {signal: early.signal}),
    error => error.aborted === true);
  assert.equal(seen.aborted, true, 'an already-aborted caller never gets a live request');
});

test('request.js without AbortController runs the request with no limit', async () => {
  const {request, clock} = loadRequest({AbortController: undefined});
  assert.equal(await request.run(async signal => signal ?? 'no signal'), 'no signal');
  assert.equal(clock.pending(), 0);
});

// ── Homepage requests ────────────────────────────────────────────────────────
test('a hung sender analysis times out with its own message and restores the idle form', async () => {
  const page = homepage();
  page.el('email-input').value = 'a@example.com';
  const run = page.context.runEmailAnalysis();
  assert.equal(page.calls.length, 1);
  assert.equal(page.el('analyze-btn').disabled, true);
  assert.equal(page.el('analyze-btn-text').textContent, 'Analyzing…');
  assert.equal(page.el('cancel-sender-analysis').hidden, false, 'Cancel is offered while the request runs');
  await page.clock.advance(44999);
  assert.equal(page.el('analyze-btn').disabled, true, 'still waiting just before the limit');
  await page.clock.advance(1);
  await run;
  assert.equal(page.calls[0].init.signal.aborted, true, 'the fetch is aborted');
  assert.equal(page.el('email-error').textContent, TIMEOUT_TEXT);
  assert.notEqual(TIMEOUT_TEXT, page.read("t('request.error.network')"), 'distinct from the network error');
  assert.equal(page.el('analyze-btn').disabled, false);
  assert.equal(page.el('analyze-btn-text').textContent, 'Analyze');
  assert.equal(page.el('loading-area').classList.contains('hidden'), true);
  assert.equal(page.el('cancel-sender-analysis').hidden, true);
  // A response after the timeout is not rendered.
  page.calls[0].resolve(json(SENDER)); await tick();
  assert.equal(page.el('result-area').classList.contains('hidden'), true);
});

test('Cancel stops a sender analysis without an error, and its late response is ignored', async () => {
  for (const withRequest of [true, false]) {
    const page = homepage({withRequest});
    page.el('email-input').value = 'a@example.com';
    const run = page.context.runEmailAnalysis();
    const signal = page.calls[0].init.signal;
    page.context.cancelEmailAnalysis();
    assert.equal(signal.aborted, true, 'the fetch is aborted');
    assert.equal(page.el('analyze-btn').disabled, false);
    assert.equal(page.el('analyze-btn-text').textContent, 'Analyze');
    assert.equal(page.el('loading-area').classList.contains('hidden'), true);
    assert.equal(page.el('cancel-sender-analysis').hidden, true);
    await page.clock.advance(100);
    assert.equal(page.el('copy-status').textContent, 'Analysis cancelled.', 'a brief neutral status');
    // Without request.js the fake fetch ignores the signal and answers late.
    page.calls[0].resolve(json(SENDER));
    await run;
    await tick();
    assert.equal(page.el('email-error').textContent, '', `no error (request.js: ${withRequest})`);
    assert.equal(page.el('result-area').classList.contains('hidden'), true, 'the late response is not rendered');
    assert.equal(page.read('lastResults.sender'), null);
    // Cancel with nothing in flight does nothing.
    page.el('copy-status').textContent = '';
    page.context.cancelEmailAnalysis();
    await page.clock.advance(100);
    assert.equal(page.el('copy-status').textContent, '');
  }
});

test('a sender analysis still renders normally and leaves no timer running', async () => {
  const page = homepage();
  page.el('email-input').value = 'a@example.com';
  const run = page.context.runEmailAnalysis();
  page.calls[0].resolve(json(SENDER));
  await run;
  assert.equal(page.el('result-area').classList.contains('hidden'), false);
  assert.equal(page.el('cancel-sender-analysis').hidden, true);
  await page.clock.advance(60000);
  assert.equal(page.el('email-error').textContent, '');
});

test('the content Cancel button also covers the server request, and a hung one times out', async () => {
  const page = homepage();
  page.context.setupInputEvents();
  page.el('content-subject').value = 'Hi';
  const run = page.context.runContentAnalysis();
  assert.equal(page.calls[0].url, '/api/analyze-content');
  assert.equal(page.el('cancel-content-scan').hidden, false, 'shown for text analysis, not only image scans');
  assert.equal(page.el('content-analyze-btn').disabled, true);
  page.el('cancel-content-scan').listeners.click();
  assert.equal(page.calls[0].init.signal.aborted, true);
  assert.equal(page.el('cancel-content-scan').hidden, true);
  assert.equal(page.el('content-analyze-btn').disabled, false);
  assert.equal(page.el('content-btn-text').textContent, 'Analyze Content');
  assert.equal(page.el('content-loading-area').classList.contains('hidden'), true);
  page.calls[0].resolve(json(CONTENT));
  await run; await page.clock.advance(100);
  assert.equal(page.el('content-error').textContent, '');
  assert.equal(page.el('content-result-area').classList.contains('hidden'), true, 'the late response is not rendered');
  assert.equal(page.el('copy-status').textContent, 'Analysis cancelled.');

  const hung = page.context.runContentAnalysis();
  await page.clock.advance(45000);
  await hung;
  assert.equal(page.calls[1].init.signal.aborted, true);
  assert.equal(page.el('content-error').textContent, TIMEOUT_TEXT);
  assert.equal(page.el('content-analyze-btn').disabled, false);
  assert.equal(page.el('cancel-content-scan').hidden, true);
});

test('content Cancel during an image scan cancels recognition before any request', async () => {
  const page = homepage();
  let cancelled = 0;
  const scan = deferred();
  page.window.PhishGuardVision = {cancel() { cancelled++; }, render() {}, recognize: () => scan.promise};
  page.context.setupInputEvents();
  vm.runInContext("_visualFile = {name: 'shot.png', type: 'image/png'}; _rawEmailSource = new ArrayBuffer(8)", page.context);
  const run = page.context.runContentAnalysis();
  assert.equal(page.el('cancel-content-scan').hidden, false);
  const before = cancelled;
  page.el('cancel-content-scan').listeners.click();
  assert.equal(cancelled, before + 1);
  scan.resolve({observations: []});
  await run;
  assert.equal(page.calls.length, 0, 'no server request after a cancelled scan');
  assert.equal(page.el('content-analyze-btn').disabled, false);
});

test('an .eml upload request is cancellable too', async () => {
  const page = homepage();
  vm.runInContext("_rawEmailSource = new ArrayBuffer(8)", page.context);
  const run = page.context.runContentAnalysis();
  assert.equal(page.calls[0].url, '/api/analyze-eml');
  assert.equal(page.calls[0].init.headers['Content-Type'], 'message/rfc822');
  page.context.cancelContentAnalysis();
  assert.equal(page.calls[0].init.signal.aborted, true);
  await run;
  assert.equal(page.el('content-error').textContent, '');
});

test('a hung verification times out, shows the error and returns to the Run button', async () => {
  const page = homepage();
  vm.runInContext("_verifyEmail = 'a@example.com'; _emailVerificationEnabled = true", page.context);
  const run = page.context.runVerification();
  assert.equal(page.calls[0].url, '/api/verify-email');
  assert.equal(page.el('verify-loading').classList.contains('hidden'), false);
  await page.clock.advance(45000);
  await run;
  assert.equal(page.calls[0].init.signal.aborted, true);
  assert.equal(page.el('verify-error').textContent, TIMEOUT_TEXT);
  assert.equal(page.el('verify-loading').classList.contains('hidden'), true);
  assert.equal(page.el('verify-idle').classList.contains('hidden'), false);
});

test('a new sender analysis aborts a verification still in flight', async () => {
  const page = homepage();
  vm.runInContext("_verifyEmail = 'a@example.com'; _emailVerificationEnabled = true", page.context);
  const verify = page.context.runVerification();
  const signal = page.calls[0].init.signal;
  page.el('email-input').value = 'b@example.com';
  page.context.runEmailAnalysis();
  assert.equal(signal.aborted, true);
  await verify;
  assert.equal(page.el('verify-error').textContent, '');
});

test('postJSON accepts an external AbortSignal and a timeout override', async () => {
  const page = homepage();
  const controller = new AbortController();
  const aborted = page.context.postJSON('/api/x', {}, {signal: controller.signal});
  controller.abort();
  await assert.rejects(aborted, error => error.aborted === true);
  assert.equal(page.calls[0].init.signal.aborted, true);

  const short = page.context.postJSON('/api/x', {}, {timeout: 500}).then(() => null, error => error);
  await page.clock.advance(499);
  assert.equal(page.calls[1].init.signal.aborted, false);
  await page.clock.advance(1);
  const error = await short;
  assert.equal(error.timedOut, true);
  assert.equal(error.message, TIMEOUT_TEXT);
});

test('the Chinese page shows the Chinese timeout and cancel texts', () => {
  const {DICTIONARY} = loadPage(['i18n-zh.js', 'i18n.js']).window.PhishGuardI18n;
  for (const key of ['request.error.timeout', 'request.cancelled', 'sender.cancel']) {
    assert.ok(DICTIONARY.zh[key] && DICTIONARY.zh[key] !== DICTIONARY.en[key], key);
  }
  assert.equal(DICTIONARY.en['request.error.timeout'], TIMEOUT_TEXT);
});

test('configuration and metrics reads give up after 15 s and fall back as before', async () => {
  const page = homepage();
  const config = page.context.loadPublicConfig();
  const metrics = page.context.loadMetrics();
  assert.deepEqual(page.calls.map(call => call.url), ['/api/config', '/api/metrics']);
  assert.equal(page.calls[0].init.cache, 'no-store');
  await page.clock.advance(14999);
  assert.equal(page.calls[0].init.signal.aborted, false);
  await page.clock.advance(1);
  await Promise.all([config, metrics]);
  assert.ok(page.calls.every(call => call.init.signal.aborted));
  assert.equal(page.read('_emailVerificationEnabled'), false, 'safe configuration defaults');
  assert.match(page.el('metrics-tbody').innerHTML, /Performance metrics are unavailable|unavailable/i);
  assert.equal(page.warnings.length, 2, 'both failures are logged');
});

test('the sender Cancel button sits next to the Analyze button, outside the live region', () => {
  const html = source('index.html');
  const row = html.slice(html.indexOf('<div class="email-input-row">'), html.indexOf('<p id="email-error"'));
  assert.ok(row.indexOf('id="analyze-btn"') < row.indexOf('id="cancel-sender-analysis"'));
  assert.match(row, /<button id="cancel-sender-analysis" type="button" class="btn-ghost btn-cancel" hidden data-action="cancel-email" data-i18n="sender\.cancel">Cancel<\/button>/);
  const area = html.slice(html.indexOf('<div id="loading-area"'), html.indexOf('<!-- Result Area -->'));
  assert.doesNotMatch(area, /<button/, 'the loading status holds no controls');
  assert.match(html, /<button id="cancel-content-scan" type="button"[^>]*hidden[^>]*>Cancel scan<\/button>/);
});
