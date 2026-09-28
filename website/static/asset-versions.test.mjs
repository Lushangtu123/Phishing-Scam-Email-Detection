import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {checkManifest, updateManifest} from '../tools/asset-versions/asset-versions.mjs';

const staticDir = fileURLToPath(new URL('./', import.meta.url));
const manifest = JSON.parse(readFileSync(new URL('../tools/asset-versions/manifest.json', import.meta.url), 'utf8'));

test('every versioned static file matches its pinned version and hash', () => {
  const problems = checkManifest(staticDir, manifest);
  assert.deepEqual(problems, [], `${problems.join('\n')}\nRun: node website/tools/asset-versions/update.mjs`);
  assert.ok(Object.keys(manifest).includes('app.js') && Object.keys(manifest).includes('vision-worker.mjs'));
});

function fixture(t, files) {
  const dir = mkdtempSync(path.join(tmpdir(), 'asset-versions-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  for (const [name, body] of Object.entries(files)) writeFileSync(path.join(dir, name), body);
  return dir;
}

test('a changed file is bumped everywhere, and a bump inside a versioned file cascades', t => {
  const dir = fixture(t, {
    'index.html': '<script src="/static/b.js?v=3"></script><script src="/static/a.js?v=1"></script>',
    'b.js': 'new Worker("/static/a.js?v=1");',
    'a.js': 'one',
  });
  const pins = {};
  updateManifest(dir, pins);
  assert.deepEqual(checkManifest(dir, pins), []);

  writeFileSync(path.join(dir, 'a.js'), 'two');
  assert.deepEqual(checkManifest(dir, pins), ['a.js changed without a new ?v= (still 1)']);
  const changes = updateManifest(dir, pins);
  assert.deepEqual(changes, ['bumped a.js ?v=1 -> 2', 'bumped b.js ?v=3 -> 4']);
  assert.equal(readFileSync(path.join(dir, 'index.html'), 'utf8'),
    '<script src="/static/b.js?v=4"></script><script src="/static/a.js?v=2"></script>');
  assert.equal(readFileSync(path.join(dir, 'b.js'), 'utf8'), 'new Worker("/static/a.js?v=2");');
  assert.deepEqual(checkManifest(dir, pins), []);
  assert.deepEqual(updateManifest(dir, pins), []);
});

test('non-integer versions, disagreeing references and stale pins are reported', t => {
  const dir = fixture(t, {
    'index.html': '<script src="/static/lib.js?v=4.4.0"></script><script src="/static/x.js?v=1"></script>',
    'other.html': '<script src="/static/x.js?v=2"></script>',
    'lib.js': 'v4', 'x.js': 'x',
  });
  const pins = {'lib.js': {version: '4.4.0', sha256: '0'.repeat(64)}, 'gone.js': {version: '1', sha256: '0'.repeat(64)}};
  assert.deepEqual(checkManifest(dir, pins).sort(), [
    'gone.js is pinned but no longer referenced',
    'lib.js changed without a new ?v= (still 4.4.0)',
    'x.js (referenced by index.html, other.html) is missing from the manifest',
    'x.js is referenced with different versions: 1, 2',
  ]);
  assert.throws(() => updateManifest(dir, pins), /x\.js is referenced with different versions/);
  writeFileSync(path.join(dir, 'other.html'), '<script src="/static/x.js?v=1"></script>');
  assert.throws(() => updateManifest(dir, pins), /lib\.js changed but \?v=4\.4\.0 is not an integer/);
});
