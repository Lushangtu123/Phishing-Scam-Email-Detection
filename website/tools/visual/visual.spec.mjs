// Screenshot tests for the homepage and its analysis results (README.md).
// Every /api/ call is answered from fixtures/ (captured from the real backend
// by capture-fixtures.mjs); any other origin is blocked.
import {isDeepStrictEqual} from 'node:util';
import path from 'node:path';
import {test, expect} from '@playwright/test';
import {HERE, loadFixtures, SENDER_EXAMPLES, CONTENT_EXAMPLES, waitForPageReady, parkPointer, runSenderExample,
  runContentExample} from './scenarios.mjs';

const FIXTURES = loadFixtures();
const FIXED_NOW = new Date('2026-05-15T12:00:00Z');
const VIEWPORTS = {1280: {width: 1280, height: 900}, 390: {width: 390, height: 844}};
const RESULT_STYLES = [path.join(HERE, 'screenshot.css'), path.join(HERE, 'hide-navbar.css')];

let problems;
test.beforeEach(async ({context, page, baseURL}) => {
  problems = [];
  const origin = new URL(baseURL).origin;
  await context.route(() => true, async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) {
      problems.push(`external request blocked: ${url.origin}`);
      return route.abort('blockedbyclient');
    }
    if (!url.pathname.startsWith('/api/')) return route.fallback();
    const text = request.postData();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }  // e.g. a raw .eml upload
    const fixture = FIXTURES.find(item => item.method === request.method() && item.path === url.pathname &&
      isDeepStrictEqual(item.request, body));
    if (!fixture) {
      problems.push(`no fixture for ${request.method()} ${url.pathname} ${JSON.stringify(body)?.slice(0, 120)} ` +
        '(re-run capture-fixtures.mjs after changing an example)');
      return route.fulfill({status: 599, json: {detail: 'missing visual fixture'}});
    }
    return route.fulfill({status: fixture.status, json: fixture.body, headers: {'Cache-Control': 'no-store'}});
  });
  page.on('pageerror', error => problems.push(`page error: ${error.message}`));
});
test.afterEach(() => {
  expect(problems, 'unexpected requests or page errors').toEqual([]);
});

// Fresh context per test (so empty storage), then an explicit theme and
// language, a fixed clock, and a page that has finished loading.
async function open(page, {theme = 'light', lang = 'en', url = '/'} = {}) {
  await page.addInitScript(({theme, lang}) => {
    try {
      localStorage.clear();
      localStorage.setItem('phishguard-theme', theme);
      localStorage.setItem('phishguard-lang', lang);
    } catch {}
  }, {theme, lang});
  await page.clock.setFixedTime(FIXED_NOW);
  await page.goto(url);
  await waitForPageReady(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await expect(page.locator('html')).toHaveAttribute('lang', lang === 'zh' ? 'zh-CN' : 'en');
  // Count-ups, the score ring and scroll reveals only settle at once with reduced motion.
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches), 'reduced motion').toBe(true);
}

for (const width of [1280, 390]) {
  for (const theme of ['light', 'dark']) {
    test.describe(`${width}px ${theme}`, () => {
      test.use({viewport: VIEWPORTS[width], colorScheme: theme});

      test('navbar and hero', async ({page}) => {
        await open(page, {theme});
        await expect(page).toHaveScreenshot(`top-${theme}-${width}.png`);
      });

      test('sender result, high-risk example', async ({page}) => {
        await open(page, {theme});
        await runSenderExample(page, SENDER_EXAMPLES['sender-high-risk']);
        await expect(page.locator('#result-area')).toHaveScreenshot(
          `sender-high-risk-en-${theme}-${width}.png`, {stylePath: RESULT_STYLES});
      });

      test('content result, phishing example', async ({page}) => {
        await open(page, {theme});
        await runContentExample(page, CONTENT_EXAMPLES['content-phishing']);
        await expect(page.locator('#content-result-area')).toHaveScreenshot(
          `content-phishing-${theme}-${width}.png`, {stylePath: RESULT_STYLES});
      });
    });
  }
}

test.describe('390px light', () => {
  test.use({viewport: VIEWPORTS[390], colorScheme: 'light'});

  test('mobile section menu opened', async ({page}) => {
    await open(page);
    await page.locator('#nav-menu-toggle').click();
    await expect(page.locator('#nav-menu-toggle')).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#nav-links')).toBeVisible();
    await parkPointer(page);
    await expect(page).toHaveScreenshot('mobile-menu-open-light-390.png');
  });

  test('sender result in Chinese, high-risk example', async ({page}) => {
    await open(page, {lang: 'zh'});
    await expect(page.locator('#analyze-btn-text')).not.toHaveText('Analyze');
    await runSenderExample(page, SENDER_EXAMPLES['sender-high-risk']);
    await expect(page.locator('#result-area')).toHaveScreenshot(
      'sender-high-risk-zh-light-390.png', {stylePath: RESULT_STYLES});
  });
});

test.describe('1280px light', () => {
  test.use({viewport: VIEWPORTS[1280], colorScheme: 'light'});

  test('sender result, low-risk example', async ({page}) => {
    await open(page);
    await runSenderExample(page, SENDER_EXAMPLES['sender-low-risk']);
    await expect(page.locator('#result-area')).toHaveScreenshot(
      'sender-low-risk-en-light-1280.png', {stylePath: RESULT_STYLES});
  });

  test('content result, legitimate example', async ({page}) => {
    await open(page);
    await runContentExample(page, CONTENT_EXAMPLES['content-legit']);
    await expect(page.locator('#content-result-area')).toHaveScreenshot(
      'content-legit-light-1280.png', {stylePath: RESULT_STYLES});
  });

  test('404 page', async ({page}) => {
    await open(page, {url: '/no-such-page'});
    await expect(page).toHaveScreenshot('not-found-light-1280.png');
  });
});
