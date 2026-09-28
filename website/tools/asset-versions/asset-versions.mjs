// Versioned static URLs (/static/app.js?v=46) are cached by browsers for a day,
// so a file whose bytes change must get a new ?v=. The manifest pins each
// versioned file's version and SHA-256; asset-versions.test.mjs fails when they
// drift and update.mjs bumps integer versions (repeating until stable, since a
// bump inside one versioned file changes that file's own hash).
import {createHash} from 'node:crypto';
import {readdirSync, readFileSync, writeFileSync} from 'node:fs';
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

// Every problem that makes the manifest disagree with the files, as readable strings.
export function checkManifest(staticDir, manifest) {
  const problems = [];
  const references = collectReferences(staticDir);
  for (const [asset, {versions, sources}] of references) {
    const pinned = manifest[asset];
    if (versions.size > 1) problems.push(`${asset} is referenced with different versions: ${[...versions].join(', ')}`);
    if (!pinned) { problems.push(`${asset} (referenced by ${[...sources].join(', ')}) is missing from the manifest`); continue; }
    const [version] = versions;
    if (pinned.version !== version) problems.push(`${asset} is referenced as ?v=${version} but pinned as ${pinned.version}`);
    if (pinned.sha256 !== sha256(path.join(staticDir, asset)))
      problems.push(`${asset} changed without a new ?v= (still ${version})`);
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
    for (const [asset, {versions}] of references) {
      const [version] = versions;
      const pinned = manifest[asset];
      if (pinned && pinned.version === version && pinned.sha256 !== sha256(path.join(staticDir, asset)) && !/^\d+$/.test(version))
        throw new Error(`${asset} changed but ?v=${version} is not an integer; set a new version by hand`);
    }
    for (const [asset, {versions, sources}] of references) {
      const [version] = versions;
      const hash = sha256(path.join(staticDir, asset));
      const pinned = manifest[asset];
      if (!pinned) { manifest[asset] = {version, sha256: hash}; changes.push(`pinned ${asset} at ?v=${version}`); continue; }
      if (pinned.sha256 === hash && pinned.version === version) continue;
      if (pinned.sha256 !== hash && pinned.version === version) {
        if (!/^\d+$/.test(version)) throw new Error(`${asset} changed but ?v=${version} is not an integer; set a new version by hand`);
        const next = String(Number(version) + 1);
        replaceReference(staticDir, sources, asset, version, next);
        manifest[asset] = {version: next, sha256: hash};
        changes.push(`bumped ${asset} ?v=${version} -> ${next}`);
        changed = true;
      } else {
        manifest[asset] = {version, sha256: hash};
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
