#!/usr/bin/env node
// Real Chromium, actual application APIs and vendored OCR workers; synthetic data only.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import os from 'node:os';
import {mkdtemp, readFile, mkdir, writeFile, rm} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import net from 'node:net';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const options = {python: 'python3', output: path.resolve(root, '../work/browser-checks')};
for (let i = 2; i < process.argv.length; i++) {
  const flag = process.argv[i];
  if (flag === '--help') {
    console.log('node website/tools/browser-checks/run.mjs [--python /path/to/python] [--playwright-module /path/to/playwright] [--executable-path /path/to/chromium] [--output /path/to/report-directory]');
    process.exit(0);
  }
  const names = {'--python': 'python', '--playwright-module': 'playwright', '--executable-path': 'executable', '--output': 'output'};
  assert(names[flag] && process.argv[i + 1], `Unknown or incomplete option: ${flag}`);
  options[names[flag]] = process.argv[++i];
}
const require = createRequire(import.meta.url);
let chromium;
try { ({chromium} = require(options.playwright || 'playwright')); }
catch { throw new Error('Install Playwright in a local work directory and pass --playwright-module; see this directory\'s README.md.'); }
const fixtureDir = path.join(root, 'website/tests/fixtures/vision');
const manifestPath = path.join(root, 'website/tools/vision-benchmark/synthetic-manifest.json');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const token = 'synthetic-browser-analyst-token-not-a-real-credential';
const children = [];
const temporary = await mkdtemp(path.join(os.tmpdir(), 'phishguard-browser-'));
const summary = {schema_version: 'phishguard-browser-checks/v1', checks: [], limitations: [
  'Synthetic integration controls do not establish real-world detection or OCR accuracy.',
  'Text model, outbound enrichment, sender history and external services are disabled.',
  'Chart.js is served from this site; any external request fails the run.',
]};
let browser;
let failure;

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
// Do not inherit application credentials, cloud storage settings or enrichment switches.
const environment = Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'SYSTEMROOT'].filter(key => process.env[key]).map(key => [key, process.env[key]]));
async function server(args, port, env = {}) {
  const child = spawn(options.python, args, {cwd: path.join(root, 'website'), env: {...environment, ...env}, stdio: ['ignore', 'pipe', 'pipe']});
  children.push(child);
  let logs = '';
  child.stdout.on('data', bytes => {logs = (logs + bytes).slice(-8000);});
  child.stderr.on('data', bytes => {logs = (logs + bytes).slice(-8000);});
  let spawnError;
  child.on('error', error => {spawnError = error;});
  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    if (spawnError || child.exitCode !== null) throw new Error(`Local server failed: ${spawnError?.message || logs}`);
    try { if ((await fetch(url, {signal: AbortSignal.timeout(500)})).ok) return url; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Local server did not become ready: ${logs}`);
}
async function check(name, work) {
  await work();
  summary.checks.push({name, passed: true});
  console.log(`PASS ${name}`);
}
async function responseFor(page, route, work, status = 200) {
  const waiting = page.waitForResponse(response => new URL(response.url()).pathname === route && response.request().method() === 'POST', {timeout: 180000});
  const [response] = await Promise.all([waiting, work()]);
  assert.equal(response.status(), status, `${route} status`);
  return response.json();
}
function validateVisual(data, expectedQR) {
  const observations = data.visual_analysis?.observations;
  assert(observations?.length, 'Actual API must retain image observations');
  assert(observations.every(item => ['processed', 'partial'].includes(item.status)), 'Recognition must produce usable evidence');
  assert.deepEqual([...new Set(observations.flatMap(item => item.qr_payloads || []))].sort(), [...expectedQR].sort(), 'Literal QR payload sets');
}

try {
  await mkdir(options.output, {recursive: true});
  const appPort = await freePort();
  const appURL = await server(['-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', String(appPort)], appPort, {
    APP_ENV: 'test', ENABLE_EMAIL_VERIFICATION: 'false', VERIFICATION_MODE: 'off', CONTENT_MODEL_ENABLED: 'false',
    SENDER_HISTORY_ENABLED: 'false', PHISHGUARD_JEV_ENABLED: 'false', CASE_MANAGEMENT_ENABLED: 'true',
    CASE_STORE: 'sqlite', CASE_DB_PATH: path.join(temporary, 'cases.sqlite3'),
    CASE_ANALYST_TOKEN_HASHES: JSON.stringify({browser_test: createHash('sha256').update(token).digest('hex')}),
  });
  const benchmarkPort = await freePort();
  const benchmarkURL = await server([path.join(root, 'website/tools/vision-benchmark/serve.py'), '--port', String(benchmarkPort)], benchmarkPort);
  browser = await chromium.launch({headless: true, ...(options.executable ? {executablePath: options.executable} : {})});
  summary.browser = browser.version();
  const context = await browser.newContext({viewport: {width: 1280, height: 900}, serviceWorkers: 'block'});
  const pageErrors = [];
  const remoteAttempts = new Set();
  const allowed = new Set([appURL, benchmarkURL]);
  // Abort all external requests, including accidental navigation to extracted links; the page needs none.
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (['http:', 'https:'].includes(url.protocol) && !allowed.has(url.origin)) {
      remoteAttempts.add(url.hostname);
      return route.abort('blockedbyclient');
    }
    return route.continue();
  });
  context.on('page', page => page.on('pageerror', error => pageErrors.push(error.message)));
  const page = await context.newPage();
  await page.goto(appURL);
  await page.waitForLoadState('networkidle');
  await check('public sender form calls the real API and renders its result', async () => {
    await page.locator('#email-input').fill('meeting@example.com');
    const data = await responseFor(page, '/api/analyze-email', () => page.locator('#analyze-btn').click());
    assert.equal(data.email, 'meeting@example.com');
    await page.locator('#result-area').waitFor({state: 'visible'});
    assert((await page.locator('#vb-title').innerText()).length > 0);
  });
  await page.locator('#tab-email-content').click();
  await check('public manual content form calls the real API', async () => {
    await page.locator('#content-subject').fill('Synthetic team meeting');
    await page.locator('#content-body').fill('Please review the team notes before the Thursday meeting.');
    const data = await responseFor(page, '/api/analyze-content', () => page.locator('#content-analyze-btn').click());
    assert(data.risk_level);
    await page.locator('#content-result-area').waitFor({state: 'visible'});
    assert((await page.locator('#crb-title').innerText()).length > 0);
  });
  await check('English and Chinese URL-line confidence passes through real API and UI', async () => {
    summary.url_line_confidence_controls = {};
    for (const [language, filename, expected] of [
      ['eng', 'synthetic-phishing.png', manifest.records.find(row => row.id === 'synthetic-phishing')],
      ['chi_sim', 'synthetic-chinese.png', manifest.records.find(row => row.id === 'synthetic-chinese')],
    ]) {
      await page.locator('#content-ocr-language').selectOption(language);
      await page.locator('#raw-email-file').setInputFiles(path.join(fixtureDir, filename));
      await page.waitForFunction(() => document.getElementById('raw-email-status').textContent.includes('loaded'));
      const posted = page.waitForRequest(request => new URL(request.url()).pathname === '/api/analyze-visual' && request.method() === 'POST');
      const [data, submittedRequest] = await Promise.all([
        responseFor(page, '/api/analyze-visual', () => page.locator('#content-analyze-btn').click()), posted,
      ]);
      validateVisual(data, []);
      const item = data.visual_analysis.observations[0];
      const submitted = JSON.parse(submittedRequest.postData()).observations[0];
      assert.equal(item.ocr_text, submitted.ocr_text, 'Server must preserve the literal worker OCR text');
      assert.equal(item.ocr_url_line_confidence, submitted.ocr_url_line_confidence);
      assert.equal(item.ocr_language, language);
      assert(Number.isFinite(item.ocr_url_line_confidence) && item.ocr_url_line_confidence >= 0 && item.ocr_url_line_confidence <= 100);
      assert(item.ocr_text.length && item.ocr_confidence > 0);
      const label = `URL-like line OCR confidence: ${Math.round(item.ocr_url_line_confidence)}%`;
      await page.waitForFunction(expected => document.getElementById('visual-evidence').textContent.includes(expected), label);
      assert((await page.locator('#visual-evidence').textContent()).includes(item.ocr_text));
      assert.equal(await page.locator('#visual-evidence a').count(), 0);
      summary.url_line_confidence_controls[language] = {page: item.ocr_confidence,
        url_like_line: item.ocr_url_line_confidence, literal_text_match: item.ocr_text === expected.expected_text};
    }
    await page.locator('#content-ocr-language').selectOption('eng');
  });
  await check('public upload invokes real QR/OCR extraction and visual API', async () => {
    await page.locator('#raw-email-file').setInputFiles(path.join(fixtureDir, 'synthetic-qr.png'));
    await page.waitForFunction(() => document.getElementById('raw-email-status').textContent.includes('loaded'));
    const data = await responseFor(page, '/api/analyze-visual', () => page.locator('#content-analyze-btn').click());
    validateVisual(data, ['https://paypa1.example/login']);
    assert.equal(data.visual_analysis.observations[0].ocr_text, '', 'A QR-only image must not contribute invented OCR text');
    await page.locator('#visual-evidence').waitFor({state: 'visible'});
    assert((await page.locator('#visual-evidence').innerText()).includes('https://paypa1.example/login'));
    assert.equal(await page.locator('#visual-evidence a').count(), 0, 'Extracted payloads must stay non-clickable');
    const preview = page.locator('#visual-evidence details.visual-original-preview');
    await preview.locator('summary').click();
    const picture = preview.locator('img');
    await picture.waitFor({state: 'visible'});
    assert.match(await picture.getAttribute('src'), /^blob:/, 'Original preview must use a local object URL');
    await picture.evaluate(img => img.decode());
    assert(await picture.evaluate(img => img.complete && img.naturalWidth > 0), 'Original image must render next to OCR evidence');
  });
  await check('public cancellation stops an actual worker before sending evidence and permits retry', async () => {
    await page.locator('#content-analyze-btn').waitFor({state: 'visible'});
    await page.waitForFunction(() => !document.getElementById('content-analyze-btn').disabled);
    let release;
    const held = new Promise(resolve => {release = resolve;});
    let workerRequested;
    const started = new Promise(resolve => {workerRequested = resolve;});
    let sent = 0;
    const count = request => {if (new URL(request.url()).pathname === '/api/analyze-visual') sent++;};
    page.on('request', count);
    const pattern = '**/vision-worker.mjs?*';
    await page.route(pattern, async route => {workerRequested(); await held; await route.continue().catch(() => {});});
    try {
      await page.locator('#content-analyze-btn').click();
      await Promise.race([started, new Promise((_, reject) => setTimeout(() => reject(new Error('Worker startup not observed')), 10000))]);
      await page.locator('#cancel-content-scan').click();
      await page.waitForFunction(() => !document.getElementById('content-analyze-btn').disabled && document.getElementById('cancel-content-scan').hidden);
      assert.equal(sent, 0, 'Cancelled evidence must not reach analysis API');
    } finally {release(); await page.unroute(pattern);}
    const retry = await responseFor(page, '/api/analyze-visual', () => page.locator('#content-analyze-btn').click());
    validateVisual(retry, ['https://paypa1.example/login']);
    assert.equal(sent, 1, 'Only the new extraction should submit evidence');
    page.off('request', count);
  });
  await check('EML upload parses embedded images in the real browser worker', async () => {
    await page.waitForFunction(() => !document.getElementById('content-analyze-btn').disabled);
    await page.locator('#raw-email-file').setInputFiles(path.join(fixtureDir, 'synthetic-images.eml'));
    await page.waitForFunction(() => document.getElementById('raw-email-status').textContent.includes('loaded'));
    const data = await responseFor(page, '/api/analyze-visual', () => page.locator('#content-analyze-btn').click());
    validateVisual(data, ['https://paypa1.example/login']);
    assert.equal(data.visual_analysis.observations.length, 2);
  });
  await check('stalled OCR startup preserves four QR images and original email through the public API', async () => {
    const matrix = JSON.parse(await readFile(path.join(fixtureDir, 'qr-matrices.json'), 'utf8'))[0];
    const pictures = await page.evaluate(async matrix => {
      const images = [];
      for (let i = 0; i < 4; i++) {
        const canvas = new OffscreenCanvas(240 + i, 240), ctx = canvas.getContext('2d');
        ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#000';
        matrix.forEach((row, y) => row.forEach((on, x) => {if (on) ctx.fillRect(30 + x * 6, 30 + y * 6, 6, 6);}));
        const bytes = new Uint8Array(await (await canvas.convertToBlob({type: 'image/png'})).arrayBuffer());
        images.push(btoa(String.fromCharCode(...bytes)));
      }
      return images;
    }, matrix.matrix);
    const raw = ['MIME-Version: 1.0', 'Subject: Synthetic OCR outage control',
      'Content-Type: multipart/mixed; boundary="ocr-outage"', '',
      '--ocr-outage', 'Content-Type: text/plain', '', 'Urgent account suspended. Enter your password.',
      ...pictures.flatMap((bytes, i) => ['--ocr-outage', 'Content-Type: image/png',
        `Content-Disposition: attachment; filename="qr-${i}.png"`, 'Content-Transfer-Encoding: base64', '', bytes]),
      '--ocr-outage--', ''].join('\r\n');
    let release;
    const held = new Promise(resolve => {release = resolve;});
    let blocked = 0;
    const pattern = '**/static/vendor/vision/core/**';
    const stall = async route => {blocked++; await held; await route.abort().catch(() => {});};
    await context.route(pattern, stall);
    try {
      await page.locator('#raw-email-file').setInputFiles({name: 'ocr-outage.eml', mimeType: 'message/rfc822', buffer: Buffer.from(raw)});
      await page.waitForFunction(() => document.getElementById('raw-email-status').textContent.includes('loaded'));
      const posted = page.waitForRequest(request => new URL(request.url()).pathname === '/api/analyze-visual' && request.method() === 'POST', {timeout: 180000});
      const start = Date.now();
      const [data, submittedRequest] = await Promise.all([
        responseFor(page, '/api/analyze-visual', () => page.locator('#content-analyze-btn').click()), posted,
      ]);
      const elapsed = Date.now() - start;
      assert(blocked > 0, 'The actual local OCR core request must be held pending');
      assert(elapsed < 150000, 'Partial evidence must arrive before the page deadline');
      const submitted = JSON.parse(submittedRequest.postData());
      assert.equal(submitted.eml_base64, Buffer.from(raw).toString('base64'), 'Original MIME bytes must reach the API');
      validateVisual(data, [matrix.text]);
      const observations = data.visual_analysis.observations;
      assert.equal(observations.length, 4);
      assert.equal(new Set(observations.map(item => item.sha256)).size, 4, 'All four distinct images must be inspected');
      for (const item of observations) {
        assert.deepEqual(item.qr_payloads, [matrix.text]);
        assert.equal(item.status, 'partial');
        assert.equal(item.ocr_text, '');
        assert(item.warnings.some(warning => /text recognition.*(failed|skipped)/i.test(warning)));
      }
      assert.equal(data.input_mode, 'raw-email');
      assert(['high', 'critical'].includes(data.risk_level), 'The original credential request must retain its risk');
      assert(data.extra_indicators.some(item => /Direct credential request/.test(item.msg)));
      assert.equal(data.analysis_complete, false);
      await page.waitForFunction(() => document.getElementById('visual-evidence').textContent.includes('Text recognition was skipped'));
      summary.ocr_outage_control = {images_retained: observations.length, exact_qr: true,
        original_email_retained: true, text_coverage_warning: true, blocked_core_requests: blocked, elapsed_ms: elapsed};
    } finally { release(); await context.unroute(pattern, stall); }
  });
  await check('missing CID coverage reaches the public API and UI without discarding QR evidence', async () => {
    const qr = (await readFile(path.join(fixtureDir, 'synthetic-qr.png'))).toString('base64');
    const mail = id => ['MIME-Version: 1.0', 'Subject: Synthetic CID coverage control',
      'Content-Type: multipart/related; boundary="cid-coverage"', '', '--cid-coverage',
      'Content-Type: text/html', '', `<p>Review the image.</p><img src="cid:${id}">`,
      '--cid-coverage', 'Content-Type: image/png', 'Content-ID: <available@example.test>',
      'Content-Transfer-Encoding: base64', '', qr, '--cid-coverage--', ''].join('\r\n');
    const matched = await page.evaluate(async raw => window.PhishGuardVision.recognize(
      new File([raw], 'matched-cid.eml', {type: 'message/rfc822'})), mail('available@example.test'));
    assert.equal(matched.observations.length, 1);
    assert.deepEqual(matched.observations[0].qr_payloads, ['https://paypa1.example/login']);
    assert(!matched.warnings.some(warning => /CID/.test(warning)), 'A supported matching CID should not claim missing coverage');
    const raw = mail('missing@example.test');
    await page.locator('#raw-email-file').setInputFiles({name: 'missing-cid.eml', mimeType: 'message/rfc822', buffer: Buffer.from(raw)});
    await page.waitForFunction(() => document.getElementById('raw-email-status').textContent.includes('loaded'));
    const posted = page.waitForRequest(request => new URL(request.url()).pathname === '/api/analyze-visual' && request.method() === 'POST');
    const [data, request] = await Promise.all([
      responseFor(page, '/api/analyze-visual', () => page.locator('#content-analyze-btn').click()), posted,
    ]);
    const submitted = JSON.parse(request.postData());
    assert.equal(submitted.eml_base64, Buffer.from(raw).toString('base64'));
    assert(submitted.warnings.some(warning => /CID.*incomplete/.test(warning)));
    validateVisual(data, ['https://paypa1.example/login']);
    assert.equal(data.visual_analysis.observations.length, 1);
    assert(data.visual_analysis.warnings.some(warning => /CID.*incomplete/.test(warning)));
    assert.equal(data.input_mode, 'raw-email');
    assert.equal(data.analysis_complete, false);
    await page.waitForFunction(() => /CID.*incomplete/.test(document.getElementById('visual-evidence').textContent));
    // The new warning is coverage metadata, not a client-supplied risk signal.
    const control = await context.request.post(appURL + '/api/analyze-visual', {data: {...submitted, warnings: []}});
    assert.equal(control.status(), 200);
    assert.equal(data.risk_level, (await control.json()).risk_level);
    summary.cid_coverage_control = {matched_without_cid_warning: true, missing_warning_in_api_and_ui: true,
      original_email_retained: true, unrelated_qr_retained: true, coverage_warning_preserves_risk: true};
  });
  await check('real visual API keeps OCR and QR phrases independent', async () => {
    async function analyze(ocr_text, qr_payloads) {
      const response = await context.request.post(appURL + '/api/analyze-visual', {data: {observations: [{
        name: 'source-boundary-control.png', mime_type: 'image/png', source: 'upload', sha256: 'a'.repeat(64),
        status: 'processed', ocr_text, qr_payloads, ocr_confidence: 90, warnings: [],
      }]}});
      assert.equal(response.status(), 200);
      return response.json();
    }
    const isolated = await analyze('', ['enter your password. Urgent account suspended.']);
    const negation = await analyze('Do not', ['enter your password. Urgent account suspended.']);
    assert.equal(negation.risk_level, isolated.risk_level, 'A separate caption cannot negate the QR request');
    assert(['high', 'critical'].includes(negation.risk_level));
    const split = await analyze('Urgent account suspended. Enter your', ['password']);
    assert(!['medium', 'high', 'critical'].includes(split.risk_level), 'Independent sources must not create a credential phrase');
    const complete = await analyze('Urgent account suspended. Enter your password', []);
    assert(['high', 'critical'].includes(complete.risk_level), 'A complete single-source request remains detected');
    const record = negation.visual_analysis.observations[0];
    assert.equal(record.assessment_method, 'independent-source-max');
    assert.equal(record.assessed_source_count, 2);
    assert.equal(record.ocr_text, 'Do not');
    assert.deepEqual(record.qr_payloads, ['enter your password. Urgent account suspended.']);
    summary.visual_source_boundary = {qr_negation_blocked: true, cross_source_phrase_blocked: true,
      single_source_risk_retained: true, original_text_retained: true};
  });
  await check('independent MIME HTML parts cannot hide a later QR image', async () => {
    const qr = (await readFile(path.join(fixtureDir, 'synthetic-qr.png'))).toString('base64');
    const raw = ['MIME-Version: 1.0', 'Content-Type: multipart/alternative; boundary="part-isolation"', '',
      '--part-isolation', 'Content-Type: text/html', '', '<script>unclosed example',
      '--part-isolation', 'Content-Type: text/html', '', `<img src="data:image/png;base64,${qr}">`,
      '--part-isolation--', ''].join('\r\n');
    const evidence = await page.evaluate(async raw => window.PhishGuardVision.recognize(
      new File([raw], 'part-isolation.eml', {type: 'message/rfc822'})), raw);
    assert.equal(evidence.observations.length, 1, 'A separate MIME part must start a fresh HTML parser');
    assert.deepEqual(evidence.observations[0].qr_payloads, ['https://paypa1.example/login']);
    summary.mime_part_isolation = {later_image_retained: true, exact_qr: true};
  });
  await check('HTML resource context excludes inert QR decoys and retains Outlook image candidates', async () => {
    const benign = (await readFile(path.join(fixtureDir, 'synthetic-benign.png'))).toString('base64');
    const qr = (await readFile(path.join(fixtureDir, 'synthetic-qr.png'))).toString('base64');
    const evidence = await page.evaluate(async ({benign, qr}) => {
      const real = `<img src="data:image/png;base64,${benign}">`;
      const decoy = `<img src="data:image/png;base64,${qr}">`;
      const scan = html => window.PhishGuardVision.recognize(new File([
        'MIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n' + html,
      ], 'html-context.eml', {type: 'message/rfc822'}));
      const inert = await scan(`<!--${decoy}--><script>const sample = '${decoy}';</script>` +
        `<template>${decoy}</template><textarea>${decoy}</textarea>` + real);
      const conditional = await scan(`<!--[if mso]>${decoy}<![endif]-->` + real);
      const css = await scan(String.raw`<div style="backg\72 ound:image\2d set('data:image/png;base64,${qr}' 1x)"></div>`);
      const bounded = await scan(real + '<template>'.repeat(20000) + '</template>'.repeat(20000));
      return {inert, conditional, css, bounded};
    }, {benign, qr});
    assert.equal(evidence.inert.observations.length, 1, 'Inert HTML must not supply a QR observation');
    assert.deepEqual(evidence.inert.observations[0].qr_payloads, []);
    assert(evidence.inert.observations[0].ocr_text.includes('meeting'), 'Actual image remains readable');
    assert.equal(evidence.conditional.observations.length, 2);
    assert.deepEqual(evidence.conditional.observations.flatMap(item => item.qr_payloads), ['https://paypa1.example/login']);
    assert(evidence.conditional.warnings.some(warning => /conditional|render/i.test(warning)));
    assert.deepEqual(evidence.css.observations.flatMap(item => item.qr_payloads), ['https://paypa1.example/login']);
    assert(evidence.css.warnings.some(warning => /CSS|render/i.test(warning)));
    assert.equal(evidence.bounded.observations.length, 1);
    assert(evidence.bounded.warnings.some(warning => /nesting limit.*incomplete/i.test(warning)));
    summary.html_image_context_control = {inert_qr_observations: 0, actual_image_retained: true,
      conditional_qr_retained: true, conditional_warning: true, escaped_css_qr_retained: true,
      parser_limit_preserves_prefix: true};
  });
  await check('repeated inline images leave room for a later distinct QR attachment', async () => {
    const logo = (await readFile(path.join(fixtureDir, 'synthetic-benign.png'))).toString('base64');
    const qr = (await readFile(path.join(fixtureDir, 'synthetic-qr.png'))).toString('base64');
    const raw = ['MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="repeated-image-control"', '',
      '--repeated-image-control', 'Content-Type: text/html', '',
      `<img src="data:image/png;base64,${logo}">`.repeat(6),
      '--repeated-image-control', 'Content-Type: image/png',
      'Content-Disposition: attachment; filename="later-qr.png"', 'Content-Transfer-Encoding: base64', '', qr,
      '--repeated-image-control--', ''].join('\r\n');
    const evidence = await page.evaluate(async raw => window.PhishGuardVision.recognize(
      new File([raw], 'repeated-images.eml', {type: 'message/rfc822'})), raw);
    assert.equal(evidence.observations.length, 2, 'Repeated bytes must not consume unique-image slots');
    assert(evidence.observations.every(item => ['processed', 'partial'].includes(item.status)));
    assert.deepEqual(evidence.observations.flatMap(item => item.qr_payloads), ['https://paypa1.example/login']);
    assert.equal(evidence.warnings.length, 0, 'Copies must not produce false coverage-limit warnings');
    summary.repeated_image_control = {image_occurrences: 7, unique_images_inspected: 2, exact_later_qr: true};
  });
  await check('analyst can save and reload an image case through real SQLite APIs', async () => {
    await page.goto(appURL + '/cases');
    await page.waitForLoadState('networkidle');
    await page.locator('#token').fill(token);
    await page.locator('#login-form button').click();
    await page.locator('#workspace').waitFor({state: 'visible'});
    await page.locator('#open-compose').click();
    await page.locator('#eml').setInputFiles(path.join(fixtureDir, 'synthetic-qr.png'));
    const record = await responseFor(page, '/api/cases/visual', () => page.locator('#create-case').click(), 201);
    assert(record.id);
    validateVisual(record.analysis, ['https://paypa1.example/login']);
    await page.locator('#detail').waitFor({state: 'visible'});
    const reload = page.waitForResponse(response => new URL(response.url()).pathname === `/api/cases/${record.id}` && response.request().method() === 'GET');
    await page.locator('#reload-case').click();
    assert.equal((await reload).status(), 200);
    await page.waitForFunction(() => document.getElementById('visual-evidence').textContent.includes('https://paypa1.example/login'));
    const stored = await context.request.get(appURL + `/api/cases/${record.id}?kind=case`, {headers: {Authorization: `Bearer ${token}`}});
    assert.equal(stored.status(), 200);
    validateVisual((await stored.json()).analysis, ['https://paypa1.example/login']);
    assert.equal(await page.evaluate(() => Object.values(localStorage).some(value => value.includes('synthetic-browser-analyst-token'))), false);
    assert.equal(await page.evaluate(() => Object.values(sessionStorage).some(value => value.includes('synthetic-browser-analyst-token'))), false);
  });
  await check('five synthetic images are scored by real OCR and QR workers', async () => {
    await page.goto(benchmarkURL);
    await page.waitForLoadState('networkidle');
    await page.locator('#manifest').setInputFiles(manifestPath);
    await page.locator('#images').setInputFiles(manifest.records.map(record => path.join(fixtureDir, record.filename)));
    await page.locator('#run').click();
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Finished:'), null, {timeout: 300000});
    const report = JSON.parse(await page.locator('#report').innerText());
    await writeFile(path.join(options.output, 'vision-evaluation-report.json'), JSON.stringify(report, null, 2) + '\n');
    summary.vision = report.summary;
    summary.literal_extraction = {
      text_exact: report.records.filter(row => row.text_exact).length,
      text_total: report.records.length,
      text_mismatches: report.records.filter(row => !row.text_exact).length,
      urls_exact: report.records.filter(row => row.urls_scored && row.urls_exact).length,
      urls_total: report.summary.url_scored_count,
      url_mismatches: report.records.filter(row => row.urls_scored && !row.urls_exact).length,
      empty_reference_false_text_count: report.summary.empty_reference_false_text_count,
      status: report.summary.text_exact_rate === 1 && report.summary.url_exact_set_rate === 1 ? 'exact' : 'mismatches_present',
    };
    assert.equal(report.identity.asset_manifest_verified, true);
    assert.equal(report.records.length, manifest.records.length);
    assert(report.records.every(row => ['processed', 'partial'].includes(row.status)), 'All controls must produce usable extraction');
    assert.equal(report.summary.qr_positive_exact_set_rate, 1, 'Both single and multiple QR payload sets must match literally');
    assert.equal(report.summary.qr_extra_payload_count, 0);
    assert.equal(report.summary.empty_reference_false_text_count, 0, 'QR-only controls must not contribute invented OCR text');
    assert.equal(report.by_language.eng.unexpected_han_image_rate, 0);
    const english = report.records.filter(row => row.language === 'eng' && row.reference_characters > 0);
    assert(english.every(row => row.edit_distance / row.reference_characters <= 0.05), 'English literal CER must stay below the documented 5% integration ceiling');
    const chinese = report.records.find(row => row.language === 'chi_sim');
    assert(chinese.actual_characters > 0 && chinese.edit_distance / chinese.reference_characters <= 0.4, 'Chinese literal CER must stay below the documented 40% integration ceiling; this is not an accuracy target');
    console.log(JSON.stringify({literal_text_exact_rate: report.summary.text_exact_rate, literal_url_exact_set_rate: report.summary.url_exact_set_rate, literal_qr_exact_set_rate: report.summary.qr_exact_set_rate, CER: report.summary.character_error_rate}));
  });
  await check('rotated QR masking preserves adjacent and scattered text in the real worker', async () => {
    const matrix = JSON.parse(await readFile(path.join(fixtureDir, 'qr-matrices.json'), 'utf8'))[1];
    const evidence = await page.evaluate(async ({matrix}) => {
      const canvas = new OffscreenCanvas(700, 700), ctx = canvas.getContext('2d');
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, 700, 700);
      ctx.save(); ctx.translate(350, 350); ctx.rotate(Math.PI / 4);
      ctx.fillStyle = '#000';
      const size = matrix.length * 8;
      matrix.forEach((row, y) => row.forEach((on, x) => {if (on) ctx.fillRect(x * 8 - size / 2, y * 8 - size / 2, 8, 8);}));
      ctx.restore();
      ctx.font = '24px Arial'; ctx.fillStyle = '#000';
      // KEEP is inside the QR's bounding box but outside its actual polygon.
      ctx.fillText('KEEP', 195, 215); ctx.fillText('Review notes', 80, 610);
      const buffer = await (await canvas.convertToBlob({type: 'image/png'})).arrayBuffer();
      return new Promise((resolve, reject) => {
        const worker = new Worker('/static/vision-worker.mjs', {type: 'module'});
        const timer = setTimeout(() => {worker.terminate(); reject(new Error('Rotated QR control timed out'));}, 90000);
        worker.onerror = event => {clearTimeout(timer); worker.terminate(); reject(new Error(event.message));};
        worker.onmessage = ({data}) => {
          if (!data.result && !data.error) return;
          clearTimeout(timer); worker.terminate();
          data.error ? reject(new Error(data.error)) : resolve(data.result);
        };
        worker.postMessage({buffer, kind: 'image', name: 'authored-rotated-qr-with-caption.png', language: 'eng'}, [buffer]);
      });
    }, matrix);
    assert.equal(evidence.observations.length, 1);
    const observation = evidence.observations[0];
    assert.deepEqual(observation.qr_payloads, [matrix.text]);
    assert(observation.ocr_text.includes('KEEP'), 'Text inside a rotated QR bounding box must survive polygon masking');
    assert(observation.ocr_text.includes('Review notes'), 'Scattered text must remain readable');
  });
  await check('large screenshots preserve small and large QR codes before OCR resizing', async () => {
    const matrices = JSON.parse(await readFile(path.join(fixtureDir, 'qr-matrices.json'), 'utf8'));
    const evidence = await page.evaluate(async matrices => {
      const canvas = new OffscreenCanvas(4096, 1600), ctx = canvas.getContext('2d');
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#000';
      for (const [index, x, y, module] of [[0, 100, 100, 2], [1, 3000, 1100, 8]]) {
        matrices[index].matrix.forEach((row, dy) => row.forEach((on, dx) => {
          if (on) ctx.fillRect(x + dx * module, y + dy * module, module, module);
        }));
      }
      ctx.font = '48px Arial'; ctx.fillText('Review notes', 100, 500);
      const file = new File([await canvas.convertToBlob({type: 'image/png'})], 'large-qr-control.png', {type: 'image/png'});
      const start = performance.now();
      const result = await window.PhishGuardVision.recognize(file);
      return {...result, elapsed_ms: Math.round(performance.now() - start)};
    }, matrices);
    assert.equal(evidence.observations.length, 1);
    const observation = evidence.observations[0];
    assert.deepEqual([...observation.qr_payloads].sort(), matrices.map(item => item.text).sort(),
      'Both literal QR payloads must survive, including the two-pixel modules');
    assert.equal(observation.ocr_text.trim(), 'Review notes', 'QR masking must preserve caption text without QR noise');
    summary.large_image_qr_control = {width: 4096, height: 1600, expected_qr_count: 2,
      exact_qr_set: true, exact_caption: true, elapsed_ms: evidence.elapsed_ms};
  });
  await check('authored URL lookalikes and dotted non-URLs keep line diagnostics honest', async () => {
    const controls = [];
    for (const font of ['32px Arial', 'bold 32px Georgia']) for (const [id, literal] of [
      ['digit-one', 'https://paypa1.example/login'],
      ['letter-el', 'https://paypal.example/login'],
      ['digit-in-domain', 'https://examp1e.test/login'],
      ['plain-domain', 'https://example.test/login'],
    ]) controls.push({id: `${font}-${id}`, font, literal, expectedURL: true});
    controls.push({id: 'release-number', font: '32px Arial', literal: 'Project Q3.2026 review notes', expectedURL: false});
    controls.push({id: 'ordinary-text', font: '32px Arial', literal: 'Review notes before Thursday', expectedURL: false});
    const rows = await page.evaluate(async controls => {
      const rows = [];
      for (const row of controls) {
        const canvas = new OffscreenCanvas(850, 80), ctx = canvas.getContext('2d');
        ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#000'; ctx.font = row.font; ctx.fillText(row.literal, 15, 52);
        const file = new File([await canvas.convertToBlob({type: 'image/png'})], row.id + '.png', {type: 'image/png'});
        const result = await window.PhishGuardVision.recognize(file);
        const item = result.observations[0];
        rows.push({id: row.id, expectedURL: row.expectedURL, status: item?.status,
          urlLikeLineFound: Number.isFinite(item?.ocr_url_line_confidence),
          literalTextMatch: item?.ocr_text?.trim() === row.literal});
      }
      return rows;
    }, controls);
    assert.equal(rows.length, controls.length);
    assert(rows.every(row => ['processed', 'partial'].includes(row.status)), 'All authored images must have usable extraction');
    assert(rows.filter(row => row.expectedURL).every(row => row.urlLikeLineFound), 'All URL-like controls must receive a diagnostic line score');
    assert(rows.filter(row => !row.expectedURL).every(row => !row.urlLikeLineFound), 'Dotted release numbers and ordinary prose are not URLs');
    summary.authored_url_controls = {count: rows.length, url_like_line_found: rows.filter(row => row.expectedURL && row.urlLikeLineFound).length,
      expected_url_count: rows.filter(row => row.expectedURL).length, non_url_false_line_count: rows.filter(row => !row.expectedURL && row.urlLikeLineFound).length,
      literal_text_match_count: rows.filter(row => row.literalTextMatch).length};
  });
  assert.deepEqual(pageErrors, [], 'No uncaught browser errors');
  assert.equal(remoteAttempts.size, 0, `Unexpected remote request: ${[...remoteAttempts]}`);
  summary.blocked_remote_hosts = [...remoteAttempts];
} catch (error) {
  failure = error;
  summary.failure = error.message;
  console.error(error.stack);
} finally {
  await browser?.close();
  for (const child of children) {
    if (child.exitCode === null) {
      const stopped = new Promise(resolve => child.once('exit', resolve));
      child.kill('SIGTERM');
      await Promise.race([stopped, new Promise(resolve => setTimeout(resolve, 3000))]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
  }
  await rm(temporary, {recursive: true, force: true});
  await mkdir(options.output, {recursive: true});
  summary.integration_passed = !failure;
  await writeFile(path.join(options.output, 'browser-checks-report.json'), JSON.stringify(summary, null, 2) + '\n');
}
if (failure) process.exitCode = 1;
