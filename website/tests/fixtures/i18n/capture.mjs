// Regenerates en-snapshot.json from the current homepage scripts in English.
// Run only when English copy changes on purpose:
//   node website/tests/fixtures/i18n/capture.mjs [--pre-i18n]
import {existsSync, writeFileSync} from 'node:fs';
import {runScenarios, runVisionScenario, STATIC_DIR} from './scenarios.mjs';

const APP = ['app-core.js', 'app-theme.js', 'app-layout.js', 'app-config.js', 'app-sender.js', 'app-verify.js',
  'app-content.js', 'app-content-render.js', 'app-reports.js', 'app-metrics.js', 'app.js'];
const withI18n = existsSync(new URL('i18n.js', STATIC_DIR)) && !process.argv.includes('--pre-i18n');
const pre = withI18n ? ['i18n.js'] : [];
const snapshot = {
  app: await runScenarios([...pre, ...APP]),
  vision: runVisionScenario([...pre, 'vision.js']),
};
writeFileSync(new URL('en-snapshot.json', import.meta.url), JSON.stringify(snapshot, null, 1) + '\n');
console.log(`captured ${Object.keys(snapshot.app).length} app scenarios and ${Object.keys(snapshot.vision).length} vision renders` +
  (withI18n ? ' (with i18n.js)' : ' (pre-i18n scripts)'));
