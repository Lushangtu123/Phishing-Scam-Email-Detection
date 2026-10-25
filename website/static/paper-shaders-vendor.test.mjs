// The vendored Paper Shaders files (vendor/paper-shaders/<version>/) are the npm package's
// files, byte for byte, except the one patch recorded in vendored.json and PATCHES.md.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const staticDir = fileURLToPath(new URL('./', import.meta.url));
const vendorDir = path.join(staticDir, 'vendor', 'paper-shaders');
const [versionDir, ...otherVersions] = readdirSync(vendorDir);
const libraryDir = path.join(vendorDir, versionDir);
const record = JSON.parse(readFileSync(path.join(libraryDir, 'vendored.json'), 'utf8'));
const OWN_FILES = ['PATCHES.md', 'vendored.json'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const read = file => readFileSync(path.join(libraryDir, file));
const scripts = Object.keys(record.files).filter(file => file.endsWith('.js'));

function listFiles(dir, prefix = '') {
  return readdirSync(dir, {withFileTypes: true}).flatMap(entry => (entry.isDirectory()
    ? listFiles(path.join(dir, entry.name), `${prefix}${entry.name}/`) : [`${prefix}${entry.name}`]));
}

test('one version is vendored, in a directory named after it, with exactly the recorded files', () => {
  assert.deepEqual(otherVersions, [], 'delete the old version directory after an upgrade');
  assert.equal(record.package, '@paper-design/shaders');
  assert.equal(versionDir, record.version, 'the version is part of every library URL');
  assert.match(record.tarball.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
  assert.deepEqual(listFiles(libraryDir).sort(), [...Object.keys(record.files), ...OWN_FILES].sort());
  assert.ok(record.files.LICENSE && record.files.NOTICE, 'Apache-2.0: the license and notice ship with the code');
});

test('every vendored file matches its recorded hash, and is the upstream file unless patched', () => {
  for (const [file, entry] of Object.entries(record.files)) {
    const bytes = read(file);
    assert.equal(sha256(bytes), entry.sha256, `${file} differs from vendored.json`);
    assert.equal(bytes.length, entry.bytes, file);
    if (!entry.patches) assert.equal(entry.sha256, entry.upstreamSha256, `${file} is not recorded as patched`);
  }
});

test('the patched file is the upstream file plus exactly the recorded patch, which PATCHES.md shows', () => {
  const patched = Object.entries(record.files).filter(([, entry]) => entry.patches);
  assert.deepEqual(patched.map(([file]) => file), ['shader-mount.js']);
  const notes = readFileSync(path.join(libraryDir, 'PATCHES.md'), 'utf8');
  for (const [file, entry] of patched) {
    let text = read(file).toString('utf8');
    assert.match(text, /^\/\* MODIFIED FILE: changed by PhishGuard /, 'Apache-2.0 4(b): a prominent notice at the top');
    for (const {upstream, patched: replacement} of entry.patches) {
      assert.equal(text.split(replacement).length - 1, 1, `the patched text occurs once in ${file}`);
      text = text.replace(replacement, () => upstream);
      // The diff in PATCHES.md shows each changed line.
      for (const line of upstream.split('\n').filter(Boolean)) {
        if (!replacement.includes(line)) assert.ok(notes.includes(`-${line}`), `PATCHES.md shows -${line}`);
      }
      for (const line of replacement.split('\n').filter(Boolean)) {
        if (!upstream.includes(line)) assert.ok(notes.includes(`+${line}`), `PATCHES.md shows +${line}`);
      }
    }
    assert.equal(sha256(Buffer.from(text, 'utf8')), entry.upstreamSha256, `${file} minus the patch is the upstream file`);
  }
});

test('CSP: the vendored scripts and bg-shader.mjs create no <style> element and set no style attribute', () => {
  // The page CSP is style-src 'self' and script-src 'self' (no 'unsafe-eval').
  const forbidden = [
    /createElement\(\s*['"`]style['"`]/i, /<style/i, /\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML/,
    /setAttribute\(\s*['"`]style['"`]/, /\.cssText\b/, /insertRule/, /adoptedStyleSheets/, /new CSSStyleSheet/,
    /\beval\(/, /new Function\b/, /document\.write/,
  ];
  const sources = [...scripts.map(file => [file, read(file).toString('utf8')]),
    ['bg-shader.mjs', readFileSync(path.join(staticDir, 'bg-shader.mjs'), 'utf8')]];
  // Comments (the patch notes mention <style>) are not code.
  const code = source => source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  for (const [file, source] of sources) {
    assert.match(code(source), /\S/, file);
    for (const pattern of forbidden) assert.doesNotMatch(code(source), pattern, `${file}: ${pattern}`);
  }
  // The upstream file did insert one; the check would have caught it.
  const upstream = record.files['shader-mount.js'].patches.map(patch => patch.upstream).join('\n');
  assert.match(upstream, forbidden[0]);
});

test('style.css carries the rules ShaderMount no longer inserts, in the same layer', () => {
  const mount = read('shader-mount.js').toString('utf8');
  const defaultStyle = mount.match(/const defaultStyle = `([\s\S]*?)`;/)[1];
  assert.match(defaultStyle, /^@layer paper-shaders \{/);
  const declarations = [...defaultStyle.matchAll(/([a-z-]+):\s*([^;{}]+);/g)].map(([, property, value]) => `${property}: ${value.trim()}`);
  assert.ok(declarations.length >= 10, declarations.join('\n'));
  const css = readFileSync(path.join(staticDir, 'style.css'), 'utf8');
  const layer = css.match(/@layer paper-shaders \{([\s\S]*?)\n\}/)[1];
  assert.match(layer, /:where\(\[data-paper-shader\]\) \{[^}]*\}/);
  const flat = layer.replace(/\s+/g, ' ');
  for (const declaration of declarations) assert.ok(flat.includes(`${declaration};`), `style.css @layer paper-shaders has ${declaration}`);
});

test('the vendored modules import only each other, and bg-shader.mjs imports the two entry points', () => {
  const RELATIVE = /(?:\bfrom|\bimport)\s*\(?\s*(['"])(\.\.?\/[^'"]*)\1/g;
  const reached = new Set();
  const visit = file => {
    if (reached.has(file)) return;
    reached.add(file);
    for (const [, , specifier] of read(file).toString('utf8').matchAll(RELATIVE)) {
      const target = path.posix.join(path.posix.dirname(file), specifier);
      assert.ok(record.files[target], `${file} imports ${specifier}, which is not vendored`);
      visit(target);
    }
  };
  const loader = readFileSync(path.join(staticDir, 'bg-shader.mjs'), 'utf8');
  const entries = [...loader.matchAll(/'\/static\/vendor\/paper-shaders\/([^/]+)\/([^'?]+)\?v=\d+'/g)];
  assert.deepEqual(entries.map(([, version, file]) => [version, file]),
    [[record.version, 'shader-mount.js'], [record.version, 'shaders/mesh-gradient.js']]);
  entries.forEach(([, , file]) => visit(file));
  assert.deepEqual([...reached].sort(), scripts.sort(), 'every vendored script is reachable, and nothing else is needed');
});
