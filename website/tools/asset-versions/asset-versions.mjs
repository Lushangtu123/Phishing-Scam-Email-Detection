// Versioned static URLs (/static/app.js?v=46) are cached by browsers for a year
// without revalidation, so a file whose bytes change must get a new ?v=. The manifest pins each
// versioned file's version and SHA-256; asset-versions.test.mjs fails when they
// drift and update.mjs bumps integer versions (repeating until stable, since a
// bump inside one versioned file changes that file's own hash). A versioned module's pin also
// covers the files it imports by relative URL (which carry no ?v=), transitively.
import {createHash} from 'node:crypto';
import {existsSync, readdirSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';

const SOURCE = /\.(html|js|mjs|css)$/;
const REFERENCE = /\/static\/([A-Za-z0-9_./-]+)\?v=([A-Za-z0-9.]+)/g;

function sourceFiles(staticDir, dir = staticDir) {
  // Sorted so results do not depend on the filesystem's directory order.
  return readdirSync(dir, {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name)).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(staticDir, full);
    return SOURCE.test(entry.name) && !entry.name.endsWith('.test.mjs') ? [full] : [];
  });
}

export function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

// Map of asset path -> {versions: Set, sources: Set of referencing files}.
export function collectReferences(staticDir) {
  const references = new Map();
  for (const source of sourceFiles(staticDir)) {
    for (const [, asset, version] of readFileSync(source, 'utf8').matchAll(REFERENCE)) {
      const entry = references.get(asset) ?? {versions: new Set(), sources: new Set()};
      entry.versions.add(version);
      entry.sources.add(path.relative(staticDir, source));
      references.set(asset, entry);
    }
  }
  return references;
}

// Relative module imports (`from './x.js'`, `import './x.js'`, `import('./x.js')`) are requested
// without ?v=, so a versioned module's pin covers them too: `imports` holds the SHA-256 of every
// file it reaches that way, and a change to one needs a new ?v= on the module, like a change to
// the module itself. (The server revalidates those files; a vendored library also keeps its
// version in its directory name, vendor/paper-shaders/0.0.81/, so two versions never mix.)
const RELATIVE_IMPORT = /(?:\bfrom|\bimport)\s*\(?\s*(['"])(\.\.?\/[^'"]*)\1/g;

// A versioned asset is a module when it ends in .mjs, or is a .js file referenced from one (import()).
function isModule(asset, sources) {
  return asset.endsWith('.mjs') || (asset.endsWith('.js') && [...sources].some(source => source.endsWith('.mjs')));
}

// The static-relative files one module imports directly, and what is wrong with its imports:
// a missing file, or a relative URL with a query (never pinned: write /static/...?v= instead).
function moduleImports(staticDir, module) {
  const file = path.join(staticDir, module);
  const targets = [];
  const problems = [];
  if (!existsSync(file)) return {targets, problems};
  for (const [, , specifier] of readFileSync(file, 'utf8').matchAll(RELATIVE_IMPORT)) {
    if (/[?#]/.test(specifier)) {
      problems.push(`${module} imports ${specifier}: a relative URL with a query is not pinned; use /static/...?v=`);
      continue;
    }
    const target = path.relative(staticDir, path.join(path.dirname(file), specifier)).split(path.sep).join('/');
    if (target.startsWith('..') || !existsSync(path.join(staticDir, target))) problems.push(`${module} imports ${specifier}, which does not exist`);
    else targets.push(target);
  }
  return {targets, problems};
}

// Every file a module reaches through relative imports, transitively, sorted, with its SHA-256.
export function importClosure(staticDir, module) {
  const reached = new Set();
  const pending = [module];
  while (pending.length) {
    for (const target of moduleImports(staticDir, pending.shift()).targets) {
      if (target === module || reached.has(target)) continue;
      reached.add(target);
      pending.push(target);
    }
  }
  return Object.fromEntries([...reached].sort().map(file => [file, sha256(path.join(staticDir, file))]));
}

// Map of static-relative path -> Set of the modules that import it, following relative imports
// from every versioned module, and the problems found on the way.
export function collectRelativeImports(staticDir, references = collectReferences(staticDir)) {
  const imports = new Map();
  const problems = [];
  const pending = [...references].filter(([asset, {sources}]) => isModule(asset, sources)).map(([asset]) => asset);
  const seen = new Set(pending);
  while (pending.length) {
    const module = pending.shift();
    const found = moduleImports(staticDir, module);
    problems.push(...found.problems);
    for (const target of found.targets) {
      const importers = imports.get(target) ?? new Set();
      importers.add(module);
      imports.set(target, importers);
      if (!seen.has(target)) { seen.add(target); pending.push(target); }
    }
  }
  return {imports, problems};
}

// What the manifest pins for an asset: its hash, and for a module that imports files, theirs.
function pinFor(staticDir, asset, sources) {
  const pin = {sha256: sha256(path.join(staticDir, asset))};
  if (isModule(asset, sources)) {
    const imports = importClosure(staticDir, asset);
    if (Object.keys(imports).length) pin.imports = imports;
  }
  return pin;
}

const sameImports = (a = {}, b = {}) => JSON.stringify(a) === JSON.stringify(b);

// Every problem that makes the manifest disagree with the files, as readable strings.
export function checkManifest(staticDir, manifest) {
  const references = collectReferences(staticDir);
  const problems = [...collectRelativeImports(staticDir, references).problems];
  for (const [asset, {versions, sources}] of references) {
    const pinned = manifest[asset];
    if (versions.size > 1) problems.push(`${asset} is referenced with different versions: ${[...versions].join(', ')}`);
    if (!pinned) { problems.push(`${asset} (referenced by ${[...sources].join(', ')}) is missing from the manifest`); continue; }
    const [version] = versions;
    if (pinned.version !== version) problems.push(`${asset} is referenced as ?v=${version} but pinned as ${pinned.version}`);
    const pin = pinFor(staticDir, asset, sources);
    if (pinned.sha256 !== pin.sha256) problems.push(`${asset} changed without a new ?v= (still ${version})`);
    const was = pinned.imports ?? {}, now = pin.imports ?? {};
    for (const file of new Set([...Object.keys(was), ...Object.keys(now)])) {
      if (!(file in now)) problems.push(`${asset} no longer imports ${file}; run update.mjs`);
      else if (!(file in was)) problems.push(`${asset} imports ${file}, which is not pinned; run update.mjs`);
      else if (was[file] !== now[file]) problems.push(`${asset} imports ${file}, which changed without a new ?v= on ${asset} (still ${version})`);
    }
  }
  for (const asset of Object.keys(manifest))
    if (!references.has(asset)) problems.push(`${asset} is pinned but no longer referenced`);
  return problems;
}

function replaceReference(staticDir, sources, asset, from, to) {
  const pattern = new RegExp(`/static/${asset.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\?v=${from.replace(/\./g, '\\.')}(?![A-Za-z0-9.])`, 'g');
  for (const source of sources) {
    const file = path.join(staticDir, source);
    writeFileSync(file, readFileSync(file, 'utf8').replace(pattern, `/static/${asset}?v=${to}`));
  }
}

// The module or a file it imports differs from its pin. Imports not yet pinned at all are not a
// change (the manifest predates import tracking); they are pinned without a new version.
function changedSince(pinned, pin) {
  return pinned.sha256 !== pin.sha256 || (pinned.imports !== undefined && !sameImports(pinned.imports, pin.imports));
}

// Bring references and the manifest back in line; returns the list of changes made.
export function updateManifest(staticDir, manifest) {
  const changes = [];
  for (let round = 0; round < 20; round++) {
    let changed = false;
    const references = collectReferences(staticDir);
    // Refuse before touching any file, so an error never leaves a half-updated tree.
    // Disagreeing references come first: until they agree there is no version to bump.
    for (const [asset, {versions}] of references)
      if (versions.size > 1) throw new Error(`${asset} is referenced with different versions: ${[...versions].join(', ')}; make them equal first`);
    for (const [asset, {versions, sources}] of references) {
      const [version] = versions;
      const pinned = manifest[asset];
      if (pinned && pinned.version === version && changedSince(pinned, pinFor(staticDir, asset, sources)) && !/^\d+$/.test(version))
        throw new Error(`${asset} changed but ?v=${version} is not an integer; set a new version by hand`);
    }
    for (const [asset, {versions, sources}] of references) {
      const [version] = versions;
      const pin = pinFor(staticDir, asset, sources);
      const pinned = manifest[asset];
      if (!pinned) { manifest[asset] = {version, ...pin}; changes.push(`pinned ${asset} at ?v=${version}`); continue; }
      if (pinned.version === version && !changedSince(pinned, pin)) {
        // A module pinned before imports were tracked: record them without a new version.
        if (!sameImports(pinned.imports, pin.imports)) { manifest[asset] = {version, ...pin}; changes.push(`pinned the imports of ${asset}`); }
        continue;
      }
      if (pinned.version === version) {
        const next = String(Number(version) + 1);
        replaceReference(staticDir, sources, asset, version, next);
        manifest[asset] = {version: next, ...pin};
        changes.push(`bumped ${asset} ?v=${version} -> ${next}`);
        changed = true;
      } else {
        manifest[asset] = {version, ...pin};
        changes.push(`re-pinned ${asset} at ?v=${version}`);
      }
    }
    if (!changed) break;
  }
  const referenced = collectReferences(staticDir);
  for (const asset of Object.keys(manifest))
    if (!referenced.has(asset)) { delete manifest[asset]; changes.push(`unpinned ${asset}`); }
  return changes;
}
