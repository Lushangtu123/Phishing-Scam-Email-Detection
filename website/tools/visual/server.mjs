#!/usr/bin/env node
// Serves website/static/ with the page routes of website/app.py, so the
// screenshot tests need no Python backend:
//   /             -> index.html        /cases        -> cases.html
//   /favicon.ico  -> favicon.svg       /static/<p>   -> website/static/<p>
//   /_vercel/{insights,speed-insights}/script.js -> empty script (as off Vercel)
//   other page URLs -> 404.html with status 404; missing /static/ or /_vercel/
//   files -> JSON 404, like app.py.
// /api/* answers 503: the spec fulfils every API call from fixtures/ with
// page.route, so a request reaching this server is a missing fixture.
// Loopback only, read only, no CSP headers (CSP is covered by the backend tests).
// PHISHGUARD_VISUAL_STATIC_DIR serves another copy of website/static instead,
// e.g. a scratch copy with a deliberate style change to see which screenshots fail.
//   node website/tools/visual/server.mjs [--port 4719]
import http from 'node:http';
import path from 'node:path';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';

export const STATIC_DIR = path.resolve(process.env.PHISHGUARD_VISUAL_STATIC_DIR ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), '../../static'));

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon',
  '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8',
  '.gz': 'application/gzip',
};
const PAGES = {'/': 'index.html', '/cases': 'cases.html', '/favicon.ico': 'favicon.svg'};
const VERCEL_COLLECTORS = new Set(['/_vercel/insights/script.js', '/_vercel/speed-insights/script.js']);

function send(res, status, type, body) {
  res.writeHead(status, {'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'});
  res.end(res.req.method === 'HEAD' ? undefined : body);
}
const jsonNotFound = res => send(res, 404, 'application/json', '{"detail":"Not Found"}');

// Resolves /static/<p> inside STATIC_DIR, or null for anything that escapes it.
function staticFile(pathname) {
  let relative;
  try { relative = decodeURIComponent(pathname.slice('/static/'.length)); } catch { return null; }
  const file = path.resolve(STATIC_DIR, relative);
  return file.startsWith(STATIC_DIR + path.sep) ? file : null;
}

async function handle(req, res) {
  // The raw path, without URL normalisation: staticFile() confines every
  // /static/ request, dot segments included, to STATIC_DIR.
  const pathname = req.url.split(/[?#]/, 1)[0];
  if (pathname === '/api' || pathname.startsWith('/api/')) {
    return send(res, 503, 'application/json',
      JSON.stringify({detail: `No fixture for ${req.method} ${pathname}; the visual spec must route every API call.`}));
  }
  if (!['GET', 'HEAD'].includes(req.method)) return send(res, 405, 'application/json', '{"detail":"Method Not Allowed"}');
  if (VERCEL_COLLECTORS.has(pathname)) return send(res, 200, TYPES['.js'], '');
  const file = PAGES[pathname] ? path.join(STATIC_DIR, PAGES[pathname])
    : pathname.startsWith('/static/') ? staticFile(pathname) : undefined;
  if (file) {
    try { return send(res, 200, TYPES[path.extname(file)] || 'application/octet-stream', await readFile(file)); }
    catch { return jsonNotFound(res); }
  }
  if (file === null || pathname === '/static' || pathname.startsWith('/_vercel')) return jsonNotFound(res);
  return send(res, 404, TYPES['.html'], await readFile(path.join(STATIC_DIR, '404.html')));
}

export function startServer(port = 0, host = '127.0.0.1') {
  const server = http.createServer((req, res) => {
    handle(req, res).catch(error => {
      if (!res.headersSent) send(res, 500, 'text/plain; charset=utf-8', String(error?.message || error));
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const index = process.argv.indexOf('--port');
  const port = index > 0 ? Number(process.argv[index + 1]) : 4719;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('--port must be 0-65535');
  const server = await startServer(port);
  console.log(`PhishGuard static pages on http://127.0.0.1:${server.address().port}/`);
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
