#!/usr/bin/env node
// Regenerates fixtures/*.json from the real FastAPI backend. Run it only when
// an API response or a quick example changes on purpose, then regenerate the
// baselines (README.md). It starts the Vercel entry point (root app.py) on a
// loopback port with the environment from vercel.json (content model on,
// VERIFICATION_MODE=lite; rate limit raised, host list limited to loopback),
// opens the homepage in Chromium and clicks the same quick examples as the
// spec (scenarios.mjs), recording each /api/ request and response.
//   node website/tools/visual/capture-fixtures.mjs --python /path/to/python [--executable-path /path/to/chromium]
import assert from 'node:assert/strict';
import path from 'node:path';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {chromium} from '@playwright/test';
import {HERE, FIXTURE_DIR, SENDER_EXAMPLES, CONTENT_EXAMPLES, waitForPageReady, runSenderExample, runContentExample} from './scenarios.mjs';

const ROOT = path.resolve(HERE, '../../..');
const options = {python: 'python3'};
for (let i = 2; i < process.argv.length; i++) {
  const names = {'--python': 'python', '--executable-path': 'executable'};
  assert(names[process.argv[i]] && process.argv[i + 1], `Unknown or incomplete option: ${process.argv[i]}`);
  options[names[process.argv[i]]] = process.argv[++i];
}

// Keys whose values vary per request; none exist today, scrubbed if added.
const VOLATILE_KEY = /(^|_)(timestamp|request_id|trace_id|elapsed(_ms)?|duration(_ms)?|latency(_ms)?|(generated|analy[sz]ed|created|checked)_at)$/i;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
function scrub(value, key = '') {
  if (Array.isArray(value)) return value.map(item => scrub(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v, k)]));
  }
  if (VOLATILE_KEY.test(key)) return typeof value === 'number' ? 0 : 'scrubbed';
  if (typeof value === 'string' && ISO_TIME.test(value)) return '2026-05-15T12:00:00Z';
  return value;
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const {port} = server.address();
  await new Promise(resolve => server.close(resolve));
  return port;
}

const vercel = JSON.parse(readFileSync(path.join(ROOT, 'vercel.json'), 'utf8')).env;
const port = await freePort();
const base = `http://127.0.0.1:${port}`;
// Only the vercel.json settings plus PATH/HOME: no credentials or cloud stores are inherited.
const env = {
  ...Object.fromEntries(['PATH', 'HOME', 'TMPDIR', 'SYSTEMROOT'].filter(k => process.env[k]).map(k => [k, process.env[k]])),
  ...vercel, ALLOWED_HOSTS: '127.0.0.1,localhost', RATE_LIMIT_PER_MINUTE: '1000',
  SENDER_HISTORY_ENABLED: 'false', PHISHGUARD_JEV_ENABLED: 'false', CASE_MANAGEMENT_ENABLED: 'false',
};
const backend = spawn(options.python, ['-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', String(port)],
  {cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe']});
let logs = '';
backend.stdout.on('data', chunk => { logs = (logs + chunk).slice(-6000); });
backend.stderr.on('data', chunk => { logs = (logs + chunk).slice(-6000); });
let browser;
try {
  const deadline = Date.now() + 60000;
  for (;;) {
    if (backend.exitCode !== null) throw new Error(`Backend exited:\n${logs}`);
    try { if ((await fetch(`${base}/api/config`, {signal: AbortSignal.timeout(1000)})).ok) break; } catch {}
    if (Date.now() > deadline) throw new Error(`Backend did not start:\n${logs}`);
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  browser = await chromium.launch(options.executable ? {executablePath: options.executable} : {});
  const context = await browser.newContext({viewport: {width: 1280, height: 900}, serviceWorkers: 'block'});
  await context.route(url => url.origin !== base, route => route.abort('blockedbyclient'));
  const page = await context.newPage();
  const recorded = [];
  page.on('response', async response => {
    const url = new URL(response.url());
    if (!url.pathname.startsWith('/api/')) return;
    const request = response.request();
    recorded.push((async () => ({
      method: request.method(), path: url.pathname,
      request: request.postData() ? JSON.parse(request.postData()) : null,
      status: response.status(), body: scrub(await response.json()),
    }))());
  });
  await page.goto(base);
  await waitForPageReady(page);
  for (const email of Object.values(SENDER_EXAMPLES)) await runSenderExample(page, email);
  for (const key of Object.values(CONTENT_EXAMPLES)) await runContentExample(page, key);
  const calls = await Promise.all(recorded);
  const byPath = route => calls.filter(call => call.path === route);
  // Each route was called once per example, in click order.
  const named = [
    ['config', byPath('/api/config'), ['config']],
    ['metrics', byPath('/api/metrics'), ['metrics']],
    ['sender', byPath('/api/analyze-email'), Object.keys(SENDER_EXAMPLES)],
    ['content', byPath('/api/analyze-content'), Object.keys(CONTENT_EXAMPLES)],
  ];
  const fixtures = named.flatMap(([label, found, names]) => {
    assert.equal(found.length, names.length, `${label}: expected ${names.length} recorded call(s), saw ${found.length}`);
    return names.map((name, index) => {
      assert.equal(found[index].status, 200, `${name}: status`);
      return [name, found[index]];
    });
  });
  Object.entries(SENDER_EXAMPLES).forEach(([name, email]) =>
    assert.equal(fixtures.find(([n]) => n === name)[1].request.email, email, `${name}: request`));
  mkdirSync(FIXTURE_DIR, {recursive: true});
  for (const [name, call] of fixtures) {
    writeFileSync(path.join(FIXTURE_DIR, `${name}.json`), JSON.stringify(call, null, 1) + '\n');
    console.log(`wrote fixtures/${name}.json (${call.method} ${call.path})`);
  }
} finally {
  await browser?.close();
  backend.kill();
}
