// Screenshot tests for the homepage. Run through run.mjs (README.md), which
// sets the environment variables read here.
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {defineConfig} from '@playwright/test';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// Committed baselines are rendered in the pinned Playwright container only;
// any other machine compares against its own, git-ignored baselines-local/.
const BASELINES = process.env.PHISHGUARD_VISUAL_BASELINES === 'committed' ? 'baselines' : 'baselines-local';
const OUTPUT = path.resolve(process.env.PHISHGUARD_VISUAL_OUTPUT || path.join(HERE, '.output'));
const PORT = Number(process.env.PHISHGUARD_VISUAL_PORT || 4719);
const EXECUTABLE = process.env.PHISHGUARD_VISUAL_CHROMIUM || undefined;

export default defineConfig({
  testDir: HERE,
  testMatch: 'visual.spec.mjs',
  snapshotPathTemplate: `{testDir}/${BASELINES}/{arg}{ext}`,
  outputDir: path.join(OUTPUT, 'test-results'),
  reporter: [['list'], ['html', {outputFolder: path.join(OUTPUT, 'report'), open: 'never'}]],
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // A flaky screenshot is a defect in the stabilisation, not something to retry away.
  retries: 0,
  // CI never writes baselines; update mode passes --update-snapshots=all explicitly.
  updateSnapshots: process.env.CI ? 'none' : 'missing',
  timeout: 60_000,
  expect: {
    timeout: 15_000,
    toHaveScreenshot: {
      // Per pixel, threshold ignores colour noise far below what an eye sees
      // (a shadow under a blurred backdrop varies by 1/255 run to run). At most
      // 0.1% of pixels may then differ; a padding or wrap change moves whole
      // rows of text and exceeds that many times over (README.md).
      // PHISHGUARD_VISUAL_STRICT=1 allows none, for checking stabilisation.
      maxDiffPixelRatio: process.env.PHISHGUARD_VISUAL_STRICT === '1' ? 0 : 0.001,
      threshold: 0.2,
      animations: 'disabled',
      caret: 'hide',
      scale: 'css',
      stylePath: path.join(HERE, 'screenshot.css'),
    },
  },
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    browserName: 'chromium',
    headless: true,
    deviceScaleFactor: 1,
    // Not a Playwright Test option of its own: it must go through contextOptions.
    contextOptions: {reducedMotion: 'reduce'},
    locale: 'en-US',
    timezoneId: 'UTC',
    serviceWorkers: 'block',
    launchOptions: EXECUTABLE ? {executablePath: EXECUTABLE} : {},
  },
  webServer: {
    command: `node server.mjs --port ${PORT}`,
    cwd: HERE,
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: false,
    timeout: 15_000,
  },
});
