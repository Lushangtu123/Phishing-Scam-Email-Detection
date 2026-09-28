// Regenerates cases-en-snapshot.json: the English rendering of the case
// workspace scripts in cases-scenarios.mjs. The committed snapshot was taken
// from the scripts as they were before cases.js used i18n.js, e.g.
//   mkdir -p /tmp/pre && for f in vision.js file-intake.js confirm-dialog.js cases.js; do
//     git show 23110af:website/static/$f > /tmp/pre/$f; done
//   node website/tests/fixtures/i18n/capture-cases.mjs --from /tmp/pre
// Without --from it captures the current scripts (with i18n.js); do that only
// when English copy changes on purpose.
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {CASE_SCRIPTS, runCaseScenarios} from './cases-scenarios.mjs';

const from = process.argv.indexOf('--from');
const staticDir = from > 0 ? pathToFileURL(process.argv[from + 1].replace(/\/?$/, '/')) : undefined;
const snapshot = await runCaseScenarios(staticDir ? CASE_SCRIPTS : ['i18n.js', ...CASE_SCRIPTS], staticDir ? {staticDir} : {});
writeFileSync(new URL('cases-en-snapshot.json', import.meta.url), JSON.stringify(snapshot, null, 1) + '\n');
console.log(`captured ${Object.keys(snapshot).length} case workspace scenarios` + (staticDir ? ` from ${staticDir.pathname}` : ' (current scripts)'));
