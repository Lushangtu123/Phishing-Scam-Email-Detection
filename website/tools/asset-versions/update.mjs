// After editing a versioned static file, run from the repository root:
//   node website/tools/asset-versions/update.mjs
// It bumps each changed file's integer ?v= wherever it is referenced and
// rewrites manifest.json; review and commit both.
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {updateManifest} from './asset-versions.mjs';

const staticDir = fileURLToPath(new URL('../../static/', import.meta.url));
const manifestFile = new URL('manifest.json', import.meta.url);
const manifest = existsSync(manifestFile) ? JSON.parse(readFileSync(manifestFile, 'utf8')) : {};
const changes = updateManifest(staticDir, manifest);
const sorted = Object.fromEntries(Object.keys(manifest).sort().map(asset => [asset, manifest[asset]]));
writeFileSync(manifestFile, JSON.stringify(sorted, null, 2) + '\n');
console.log(changes.length ? changes.join('\n') : 'Versioned static assets are up to date.');
