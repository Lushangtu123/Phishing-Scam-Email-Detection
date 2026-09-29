#!/usr/bin/env node
// Runs the screenshot tests (README.md).
//   node website/tools/visual/run.mjs [--committed] [--update] [--executable-path /path/to/chromium]
//        [--output DIR] [--force-host] [-- <extra playwright test arguments>]
// --committed  compare with (or, with --update, rewrite) baselines/, the set
//              rendered in the pinned Playwright container; without it the
//              git-ignored baselines-local/ is used.
// --update     rewrite every baseline in the chosen directory.
// --force-host allow --committed --update outside the Playwright container
//              (the result will not match CI; for experiments only).
// Environment: PHISHGUARD_VISUAL_STRICT=1 allows no differing pixel;
// PHISHGUARD_VISUAL_STATIC_DIR serves another copy of website/static.
import {spawnSync} from 'node:child_process';
import {existsSync, readdirSync, readFileSync, rmSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REL = path.relative(process.cwd(), HERE) || '.';
const args = process.argv.slice(2);
const rest = args.includes('--') ? args.splice(args.indexOf('--')).slice(1) : [];
const options = {committed: false, update: false, forceHost: false};
for (let i = 0; i < args.length; i++) {
  const flag = args[i];
  if (flag === '--help') {
    const lines = readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1);
    console.log(lines.slice(0, lines.findIndex(line => !line.startsWith('//'))).map(line => line.slice(3)).join('\n'));
    process.exit(0);
  } else if (flag === '--committed') options.committed = true;
  else if (flag === '--update') options.update = true;
  else if (flag === '--force-host') options.forceHost = true;
  else if ((flag === '--executable-path' || flag === '--output') && args[i + 1]) options[flag.slice(2)] = args[++i];
  else fail(`Unknown or incomplete option: ${flag} (see --help)`);
}

function fail(message, title = 'Visual regression') {
  if (process.env.GITHUB_ACTIONS) console.log(`::error title=${title}::${message.replaceAll('\n', '%0A')}`);
  console.error(`\n${title}: ${message}\n`);
  process.exit(1);
}

const OUTPUT = path.relative(process.cwd(), path.resolve(options.output || path.join(HERE, '.output'))) || '.';
const REGENERATE = `Render the committed baselines in the pinned container:
  GitHub Actions -> "Visual baselines" -> Run workflow (on your branch), download the
  "visual-baselines" artifact and replace ${REL}/baselines/*.png with its PNGs, then commit.
Baselines rendered outside the container (another OS, fonts or Chromium build) will not match CI.`;
const DIFFS = `The expected, actual and diff images of each failure are in the "visual-regression-diffs"
artifact (locally: ${OUTPUT}/report/index.html). If the change is intended:\n${REGENERATE}`;

const pinned = JSON.parse(readFileSync(path.join(HERE, 'package.json'), 'utf8')).devDependencies['@playwright/test'];
const installed = path.join(HERE, 'node_modules/@playwright/test/package.json');
if (!existsSync(installed)) fail(`@playwright/test is not installed. Run: npm ci --prefix ${REL}`);
const version = JSON.parse(readFileSync(installed, 'utf8')).version;
if (version !== pinned) fail(`@playwright/test ${version} is installed but ${pinned} is pinned. Run: npm ci --prefix ${REL}`);

const baselineDir = path.join(HERE, options.committed ? 'baselines' : 'baselines-local');
// The official image keeps its browsers in /ms-playwright.
const inContainer = process.env.PLAYWRIGHT_BROWSERS_PATH === '/ms-playwright';
if (options.committed && options.update && !inContainer && !options.forceHost) {
  fail('Refusing to rewrite the committed baselines outside the Playwright container: they would not match CI.\n' +
    'Use the "Visual baselines" workflow, or run inside mcr.microsoft.com/playwright:v' + pinned + '-noble (README.md).');
}
const pngs = () => (existsSync(baselineDir) ? readdirSync(baselineDir).filter(file => file.endsWith('.png')) : []);
if (options.update) {
  // Start from an empty set so the result holds exactly the current screenshots.
  for (const file of pngs()) rmSync(path.join(baselineDir, file));
} else if (options.committed && !pngs().length) {
  fail(`No committed baselines in ${REL}/baselines/.\n${REGENERATE}`, 'Visual baselines missing');
}

const env = {
  ...process.env,
  PHISHGUARD_VISUAL_BASELINES: options.committed ? 'committed' : 'local',
  ...(options.output ? {PHISHGUARD_VISUAL_OUTPUT: path.resolve(options.output)} : {}),
  ...(options['executable-path'] ? {PHISHGUARD_VISUAL_CHROMIUM: path.resolve(options['executable-path'])} : {}),
};
const cli = path.join(HERE, 'node_modules/@playwright/test/cli.js');
const result = spawnSync(process.execPath, [cli, 'test', '--config', path.join(HERE, 'playwright.config.mjs'),
  ...(options.update ? ['--update-snapshots=all'] : []), ...rest], {cwd: HERE, env, stdio: 'inherit'});
if (result.status !== 0) {
  fail(options.update ? 'Baseline update failed; see the log above.'
    : `Screenshots differ from ${options.committed ? 'the committed' : 'the local'} baselines, or a baseline is missing.\n` +
      (options.committed ? DIFFS : `Local baselines live in ${REL}/baselines-local/; rerun with --update to accept.`));
}
if (options.update) console.log(`\nWrote ${pngs().length} baselines to ${path.relative(process.cwd(), baselineDir)}/`);
