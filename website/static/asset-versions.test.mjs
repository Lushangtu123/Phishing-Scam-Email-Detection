import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {checkManifest, collectReferences, collectRelativeImports, updateManifest} from '../tools/asset-versions/asset-versions.mjs';

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

test('URLs that scripts load at run time are versioned like markup references', () => {
  // i18n-zh.js and Chart.js are inserted by scripts, not by the HTML; a change
  // to either must still bump every script that embeds its URL.
  const references = collectReferences(staticDir);
  assert.deepEqual([...references.get('i18n-zh.js').sources].sort(), ['i18n.js', 'lang-init.js']);
  assert.deepEqual([...references.get('vendor/chart/chart.umd.min.js').sources], ['app-metrics.js']);
  for (const html of ['index.html', 'cases.html']) {
    assert.doesNotMatch(readFileSync(path.join(staticDir, html), 'utf8'), /i18n-zh\.js|chart\.umd/, html);
  }
});

test('a script-embedded URL is bumped with its file, and the embedding script cascades', t => {
  const dir = fixture(t, {
    'index.html': '<script src="/static/lang.js?v=2"></script>',
    'lang.js': "const SOURCES = {zh: '/static/zh.js?v=1'};",
    'zh.js': 'one',
  });
  const pins = {};
  updateManifest(dir, pins);
  writeFileSync(path.join(dir, 'zh.js'), 'two');
  assert.deepEqual(checkManifest(dir, pins), ['zh.js changed without a new ?v= (still 1)']);
  assert.deepEqual(updateManifest(dir, pins), ['bumped zh.js ?v=1 -> 2', 'bumped lang.js ?v=2 -> 3']);
  assert.equal(readFileSync(path.join(dir, 'lang.js'), 'utf8'), "const SOURCES = {zh: '/static/zh.js?v=2'};");
  assert.equal(readFileSync(path.join(dir, 'index.html'), 'utf8'), '<script src="/static/lang.js?v=3"></script>');
});

test('the background shader and the two library modules it imports are versioned; their imports are followed', () => {
  const references = collectReferences(staticDir);
  assert.deepEqual([...references.get('bg-shader.mjs').sources], ['index.html']);
  for (const module of ['vendor/paper-shaders/0.0.81/shader-mount.js', 'vendor/paper-shaders/0.0.81/shaders/mesh-gradient.js'])
    assert.deepEqual([...references.get(module).sources], ['bg-shader.mjs'], module);
  // Their own imports carry no ?v=; the version is in the directory name instead.
  const {imports, problems} = collectRelativeImports(staticDir, references);
  assert.deepEqual(problems, []);
  const library = [...imports.keys()].filter(file => file.startsWith('vendor/paper-shaders/')).sort();
  assert.deepEqual(library, ['vendor/paper-shaders/0.0.81/shader-sizing.js', 'vendor/paper-shaders/0.0.81/shader-utils.js',
    'vendor/paper-shaders/0.0.81/vertex-shader.js']);
  assert.deepEqual([...imports.get('vendor/paper-shaders/0.0.81/vertex-shader.js')], ['vendor/paper-shaders/0.0.81/shader-mount.js']);
  assert.deepEqual([...imports.get('vision-core.mjs')].sort(), ['vision-email.mjs', 'vision-worker.mjs']);
});

test('relative imports of versioned modules are followed: a missing file or a relative ?v= URL is reported', t => {
  const dir = fixture(t, {
    'index.html': '<script type="module" src="/static/entry.mjs?v=1"></script>',
    'entry.mjs': "const load = () => import('/static/lib/main.js?v=2');\nimport './helper.mjs?v=3';",
    'helper.mjs': '',
    'page.js': "const label = 'imported from \"./not-a-module.js\"';",
  });
  mkdirSync(path.join(dir, 'lib'));
  writeFileSync(path.join(dir, 'lib', 'main.js'), 'import {a} from "./dep.js";\nimport {\n} from "../gone.js";');
  writeFileSync(path.join(dir, 'lib', 'dep.js'), 'export const a = 1;');
  const pins = {};
  updateManifest(dir, pins);
  const {imports, problems} = collectRelativeImports(dir);
  assert.deepEqual([...imports.keys()], ['lib/dep.js']);
  assert.deepEqual(problems.sort(), [
    'entry.mjs imports ./helper.mjs?v=3: a relative URL with a query is not pinned; use /static/...?v=',
    'lib/main.js imports ../gone.js, which does not exist',
  ]);
  assert.deepEqual(checkManifest(dir, pins).sort(), problems.sort(), 'checkManifest reports them, so CI fails');
  writeFileSync(path.join(dir, 'gone.js'), '');
  writeFileSync(path.join(dir, 'entry.mjs'), "const load = () => import('/static/lib/main.js?v=2');");
  updateManifest(dir, pins);
  assert.deepEqual(checkManifest(dir, pins), []);
});

test('a file imported without ?v= is pinned under its importer: changing it bumps the importer, and cascades', t => {
  const dir = fixture(t, {
    'index.html': '<script type="module" src="/static/entry.mjs?v=4"></script>',
    'entry.mjs': "const load = () => import('/static/lib/main.js?v=1');",
  });
  mkdirSync(path.join(dir, 'lib'));
  writeFileSync(path.join(dir, 'lib', 'main.js'), 'export {a} from "./dep.js";');
  writeFileSync(path.join(dir, 'lib', 'dep.js'), 'export {b as a} from "./leaf.js";');
  writeFileSync(path.join(dir, 'lib', 'leaf.js'), 'export const b = 1;');
  const pins = {};
  updateManifest(dir, pins);
  assert.deepEqual(Object.keys(pins['lib/main.js'].imports), ['lib/dep.js', 'lib/leaf.js'], 'transitively');
  assert.equal(pins['entry.mjs'].imports, undefined, '/static/ URLs are pinned as assets of their own');
  assert.deepEqual(checkManifest(dir, pins), []);

  writeFileSync(path.join(dir, 'lib', 'leaf.js'), 'export const b = 2;');
  assert.deepEqual(checkManifest(dir, pins), ['lib/main.js imports lib/leaf.js, which changed without a new ?v= on lib/main.js (still 1)']);
  assert.deepEqual(updateManifest(dir, pins), ['bumped lib/main.js ?v=1 -> 2', 'bumped entry.mjs ?v=4 -> 5']);
  assert.equal(readFileSync(path.join(dir, 'entry.mjs'), 'utf8'), "const load = () => import('/static/lib/main.js?v=2');");
  assert.deepEqual(checkManifest(dir, pins), []);

  // A new import is reported until pinned, and pinning it is a change of the module too.
  writeFileSync(path.join(dir, 'lib', 'extra.js'), '');
  writeFileSync(path.join(dir, 'lib', 'dep.js'), 'import "./extra.js";\nexport {b as a} from "./leaf.js";');
  assert.deepEqual(checkManifest(dir, pins).sort(), [
    'lib/main.js imports lib/dep.js, which changed without a new ?v= on lib/main.js (still 2)',
    'lib/main.js imports lib/extra.js, which is not pinned; run update.mjs',
  ]);
  assert.deepEqual(updateManifest(dir, pins), ['bumped lib/main.js ?v=2 -> 3', 'bumped entry.mjs ?v=5 -> 6']);
});

test('a module pinned before imports were tracked gets them pinned without a new version', t => {
  const dir = fixture(t, {'index.html': '<script type="module" src="/static/worker.mjs?v=7"></script>',
    'worker.mjs': "import './core.mjs';", 'core.mjs': ''});
  const pins = {'worker.mjs': {version: '7', sha256: createHash('sha256').update("import './core.mjs';").digest('hex')}};
  assert.deepEqual(checkManifest(dir, pins), ['worker.mjs imports core.mjs, which is not pinned; run update.mjs']);
  assert.deepEqual(updateManifest(dir, pins), ['pinned the imports of worker.mjs']);
  assert.equal(pins['worker.mjs'].version, '7');
  assert.deepEqual(checkManifest(dir, pins), []);
});

test('the pinned imports cover the vision worker and the vendored shader library', () => {
  const library = manifest['vendor/paper-shaders/0.0.81/shader-mount.js'];
  assert.deepEqual(Object.keys(library.imports), ['vendor/paper-shaders/0.0.81/vertex-shader.js']);
  assert.deepEqual(Object.keys(manifest['vendor/paper-shaders/0.0.81/shaders/mesh-gradient.js'].imports),
    ['vendor/paper-shaders/0.0.81/shader-sizing.js', 'vendor/paper-shaders/0.0.81/shader-utils.js']);
  assert.ok(manifest['vision-worker.mjs'].imports['vision-core.mjs'] && manifest['vision-worker.mjs'].imports['vendor/vision/jsQR.js']);
});
