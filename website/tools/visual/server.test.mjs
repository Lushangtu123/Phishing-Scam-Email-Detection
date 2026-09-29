// node --test website/tools/visual/server.test.mjs (no dependencies)
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {startServer, STATIC_DIR} from './server.mjs';

const server = await startServer(0);
const base = `http://127.0.0.1:${server.address().port}`;
test.after(() => new Promise(resolve => server.close(resolve)));
const get = (route, init) => fetch(base + route, init);
// Sends the path exactly as written (fetch would normalise dot segments).
const raw = route => new Promise((resolve, reject) => {
  http.get({host: '127.0.0.1', port: server.address().port, path: route}, response => {
    let body = '';
    response.on('data', chunk => { body += chunk; });
    response.on('end', () => resolve({status: response.statusCode, body}));
  }).on('error', reject);
});
const page = name => readFile(path.join(STATIC_DIR, name), 'utf8');

test('page routes mirror app.py', async () => {
  for (const [route, file] of [['/', 'index.html'], ['/cases', 'cases.html']]) {
    const response = await get(route);
    assert.equal(response.status, 200, route);
    assert.match(response.headers.get('content-type'), /^text\/html/);
    assert.equal(await response.text(), await page(file));
  }
  const icon = await get('/favicon.ico');
  assert.equal(icon.headers.get('content-type'), 'image/svg+xml');
});

test('static files are served with their types, ignoring cache-busting queries', async () => {
  const css = await get('/static/style.css?v=51');
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type'), /^text\/css/);
  assert.equal(await css.text(), await page('style.css'));
  assert.match((await get('/static/app.js?v=1')).headers.get('content-type'), /^text\/javascript/);
});

test('unknown pages get the 404 page; missing assets and escapes get JSON 404', async () => {
  const missingPage = await get('/no-such-page');
  assert.equal(missingPage.status, 404);
  assert.equal(await missingPage.text(), await page('404.html'));
  for (const route of ['/static/missing.js', '/static/..%2f..%2fapp.py', '/static/../../app.py',
    '/static/%2e%2e/%2e%2e/app.py', '/static/..', '/_vercel/other/script.js']) {
    const response = await raw(route);
    assert.equal(response.status, 404, route);
    assert.deepEqual(JSON.parse(response.body), {detail: 'Not Found'}, route);
  }
});

test('Vercel collectors answer an empty script, as off Vercel', async () => {
  const response = await get('/_vercel/insights/script.js');
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '');
});

test('API calls are never answered: the spec must fulfil them from fixtures', async () => {
  const response = await get('/api/analyze-email', {method: 'POST', body: '{}'});
  assert.equal(response.status, 503);
  assert.match((await response.json()).detail, /No fixture for POST \/api\/analyze-email/);
  assert.equal((await get('/', {method: 'POST'})).status, 405);
});
