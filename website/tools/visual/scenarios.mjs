// Page flows shared by capture-fixtures.mjs (real backend) and visual.spec.mjs
// (fixtures), so both send exactly the same API requests.
import path from 'node:path';
import {readdirSync, readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_DIR = path.join(HERE, 'fixtures');

// The built-in quick examples whose results are captured.
export const SENDER_EXAMPLES = {
  'sender-high-risk': 'security-alert@paypa1-verify.xyz',
  'sender-low-risk': 'user@gmail.com',
};
export const CONTENT_EXAMPLES = {
  'content-phishing': 'phishing-account',
  'content-legit': 'legit-newsletter',
};

const settle = page => page.evaluate(() => new Promise(resolve =>
  requestAnimationFrame(() => requestAnimationFrame(resolve))));

// Moves the pointer off the page. Otherwise whatever scrolls under its last
// position (a card once a result scrolls into view) may or may not have picked
// up :hover by the time of the capture.
export async function parkPointer(page) {
  await page.mouse.move(-1, -1);
  await settle(page);
}

// Clicks a quick example and fails fast, with a clear message, when the click
// sends no analysis request (seen when motion was not reduced: scroll-reveal
// animations moved the button between mousedown and mouseup).
async function clickAndAwaitRequest(page, locator, route) {
  const sent = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === route,
    {timeout: 10_000});
  sent.catch(() => {});
  await locator.click();
  try {
    await sent;
  } catch (error) {
    throw new Error(`Clicking the example sent no ${route} request`, {cause: error});
  }
}

// After page.goto: translated, config and metrics answered, fonts loaded.
export async function waitForPageReady(page) {
  await page.waitForLoadState('networkidle');
  await page.waitForFunction(() => !document.documentElement.hasAttribute('data-i18n-pending'));
  await page.evaluate(() => document.fonts.ready);
  await parkPointer(page);
}

async function waitForResult(page, area, loading) {
  await page.locator(loading).waitFor({state: 'hidden'});
  await page.locator(area).waitFor({state: 'visible'});
  await page.waitForLoadState('networkidle');
  await page.evaluate(() => document.fonts.ready);
  await parkPointer(page);
}

// Clicks a sender quick example (which fills the input and analyzes it).
export async function runSenderExample(page, email) {
  await clickAndAwaitRequest(page, page.locator(`#panel-email-address [data-action="set-example"][data-arg="${email}"]`),
    '/api/analyze-email');
  await waitForResult(page, '#result-area', '#loading-area');
}

// Opens the content tab and clicks a content quick example.
export async function runContentExample(page, key) {
  await page.locator('#tab-email-content').click();
  await clickAndAwaitRequest(page, page.locator(`[data-action="set-content-example"][data-arg="${key}"]`),
    '/api/analyze-content');
  await waitForResult(page, '#content-result-area', '#content-loading-area');
}

// Every committed fixture: {name, method, path, request, status, body}.
export function loadFixtures() {
  return readdirSync(FIXTURE_DIR).filter(file => file.endsWith('.json')).sort()
    .map(file => ({name: file.slice(0, -5), ...JSON.parse(readFileSync(path.join(FIXTURE_DIR, file), 'utf8'))}));
}
