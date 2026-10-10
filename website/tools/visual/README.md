# Visual regression tests

Screenshot tests for the homepage, so a CSS or markup change that breaks layout
fails CI. They use Playwright's `toHaveScreenshot` (`@playwright/test` 1.63.0,
pinned in `package.json` and `package-lock.json`).

## What is captured (17 screenshots)

| Screenshot | Widths | Themes |
|---|---|---|
| Top of the page: navbar and hero (viewport) | 1280, 390 | light, dark |
| Sender result `#result-area`, high-risk example `security-alert@paypa1-verify.xyz` | 1280, 390 | light, dark |
| Content result `#content-result-area`, "Account suspension phish" example | 1280, 390 | light, dark |
| The same sender result in Chinese (`zh`), to catch overflow | 390 | light |
| Section menu opened (viewport) | 390 | light |
| Sender result, low-risk example `user@gmail.com` | 1280 | light |
| Content result, "Legitimate newsletter" example | 1280 | light |
| 404 page (viewport) | 1280 | light |

Result screenshots are of the result element only (the whole element, even
when it is taller than the viewport), so a change elsewhere on the page does not
fail them.

## Files

- `visual.spec.mjs`: the tests. Not named `*.test.mjs`, and outside
  `website/static/`, so `node --test website/static/*.test.mjs` never picks it up.
- `playwright.config.mjs`: viewport, scale, motion, locale, time zone, tolerance.
- `run.mjs`: the entry point used locally and by both workflows.
- `server.mjs`: serves `website/static/` with the page routes of `app.py`
  (`/`, `/cases`, `/favicon.ico`, `/static/*`, the Vercel collector scripts, the
  HTML 404 page). `/api/*` answers 503. `server.test.mjs` tests it (CI `test` job).
- `scenarios.mjs`: the page flows (open, click a quick example, wait), shared
  by the spec and the fixture capture.
- `fixtures/*.json`: API responses. Every `/api/` request is fulfilled from these
  with `page.route`, matched on method, path and the exact JSON body. An
  unmatched request, any request to another origin, or a page error fails the test.
- `capture-fixtures.mjs`: regenerates the fixtures from the real backend.
- `screenshot.css`, `hide-navbar.css`: styles Playwright injects only while
  capturing.
- `baselines/`: the committed baselines, rendered in the Playwright container.
  Empty (`.gitkeep`) until the first run of the **Visual baselines** workflow.
- `baselines-local/`, `.output/` (report, actual/expected/diff images): local only,
  git-ignored.

## Why the baselines come from a container

Text rasterisation depends on the installed fonts, FreeType and Chromium
build, so screenshots taken on a laptop or on a plain GitHub runner differ from
each other by thousands of pixels without any page change. The CI job and the
baseline workflow therefore both run in the same pinned image,
`mcr.microsoft.com/playwright:v1.63.0-noble`, with the same `@playwright/test`
version, and only baselines rendered there are committed. `run.mjs --committed
--update` refuses to run outside that image (it checks
`PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`). Any other machine compares against
its own `baselines-local/`.

When upgrading Playwright, change the version in `package.json` (then
`npm install --prefix website/tools/visual` to update the lockfile), the image
tag in `.github/workflows/ci.yml` (`visual` job) and in
`.github/workflows/visual-baselines.yml`, then regenerate the baselines.

## No Python backend

The visual job serves the static files with `server.mjs` and answers the API
from fixtures. This keeps the job fast and independent of the Python
environment, and it makes the result fixed. With a live backend, a change to
scoring text or to the model would show up as a visual failure. Those changes
are covered by the backend tests and the i18n snapshot tests. CSP headers are
not sent here; `website/tests/test_app_security.py` covers the CSP.

The fixtures were captured with the environment in `vercel.json`: production
profile, content model on, `VERIFICATION_MODE=lite`. That is what the public
page shows, including the ML model card and the verification notice. The
responses contain no timestamps or request ids. The capture script still
replaces any value under a time- or id-like key, and any ISO timestamp, in case
one is added later.

## Making the screenshots stable

- Each test gets a fresh browser context, so storage starts empty. An init script
  then clears `localStorage` and sets `phishguard-theme` and `phishguard-lang`
  explicitly. The context also emulates the matching `prefers-color-scheme`.
- Viewport 1280×900 or 390×844, device scale factor 1, locale `en-US`, time zone
  UTC, `Date` fixed at 2026-05-15T12:00:00Z (`page.clock.setFixedTime`), service
  workers blocked.
- `prefers-reduced-motion: reduce` (through `contextOptions`: it is not a
  Playwright Test option of its own, and a top-level `reducedMotion` is silently
  ignored). With it the page skips count-ups, scroll reveals and smooth
  scrolling, and most CSS animations. The spec asserts that the page really
  sees reduced motion. Without it, count-ups were caught mid-way ("29" instead
  of "30") and a scroll reveal once moved a button between mousedown and mouseup.
- While capturing: `animations: 'disabled'` (finite animations and transitions,
  such as the score ring, jump to their end; infinite ones reset), `caret:
  'hide'`, and `screenshot.css` hides the three decorative background blobs.
  Result screenshots also hide the sticky navbar (`visibility`, so the layout is
  kept), which would otherwise be drawn over the top of a tall element.
- The spec waits for `networkidle`, the Chinese dictionary (`data-i18n-pending`
  cleared), `document.fonts.ready`, the result shown and the loading state
  hidden, and two animation frames. The pointer is then moved off the page.
  Otherwise whichever card scrolls under the last click position may or may not
  have `:hover` at capture time; this was seen on a content card.
- `toHaveScreenshot` also retakes the screenshot until two in a row are identical.
- Nothing is masked. The benchmark chart (Chart.js) is outside every captured
  area, so it is neither drawn into nor masked from any screenshot.

## Tolerance

`threshold: 0.2` (Playwright's default per-pixel colour distance) and
`maxDiffPixelRatio: 0.001` (at most 0.1% of an image's pixels may differ).

Measured over repeated runs on one machine, 15 of the 17 PNGs were
byte-identical. In the other two, one band of pixels differed by 1/255: the
shadow of the content input card under its `backdrop-filter`, where it overlaps
the top of the content result. The per-pixel threshold ignores this, so three
runs with `PHISHGUARD_VISUAL_STRICT=1` (no differing pixel allowed) all passed.
The pixel budget only absorbs rare anti-aliasing noise. Layout changes exceed it
many times over:

| Deliberate change (scratch copy of `website/static`) | Result |
|---|---|
| `.col-card` padding 22px → 20px | all 11 result screenshots fail; the 6 page screenshots (no result cards) pass |
| `.verdict-banner` side padding 30px → 34px | the three 1280 px sender results fail (4,283–5,624 px, about 5× the budget); at 390 px the banner is a centred column, so nothing moves and the screenshots rightly pass |
| Light-theme `.level-high` label colour `#9a3412` → `#b91c1c` | not detected: a colour-only change to small text is below the per-pixel threshold. The label colours are covered by the contrast tests in `website/static/app.test.mjs`. |

## Run locally

Node 20 or newer. From the repository root:

```sh
npm ci --prefix website/tools/visual
# Playwright's own Chromium (or pass --executable-path to an existing Chromium/headless shell):
node website/tools/visual/node_modules/@playwright/test/cli.js install chromium
node website/tools/visual/run.mjs --update   # first run: writes baselines-local/
node website/tools/visual/run.mjs            # later runs: compare with baselines-local/
```

The report with expected, actual and diff images is
`website/tools/visual/.output/report/index.html`. Options (`--help`):
`--executable-path` (an existing Chromium), `--output DIR`, and `--` followed
by Playwright arguments, such as `-- --grep "content result"`.
`PHISHGUARD_VISUAL_STRICT=1` allows no differing pixel, to check stabilisation
changes. `PHISHGUARD_VISUAL_STATIC_DIR=/path/to/copy` serves a copy of
`website/static`, for example to try a style change without touching the tree.

To compare with the committed baselines exactly as CI does, run the same image:

```sh
docker run --rm --ipc=host -v "$PWD":/work -w /work mcr.microsoft.com/playwright:v1.63.0-noble \
  sh -c 'npm ci --prefix website/tools/visual && node website/tools/visual/run.mjs --committed'
```

## Update the baselines

After an intended visual change, or to create the first set:

1. Push the branch.
2. On GitHub, open Actions → **Visual baselines** → **Run workflow**, and choose
   the branch. It takes no inputs. GitHub lists a `workflow_dispatch` workflow
   only once the file is on the default branch; from then on it can run on any
   branch. From the command line:
   `gh workflow run visual-baselines.yml --ref <branch>`.
3. Download the **visual-baselines** artifact (17 PNGs, at the artifact root)
   into `website/tools/visual/baselines/`, replacing the old set:
   `rm -f website/tools/visual/baselines/*.png && gh run download <run-id> -n visual-baselines -D website/tools/visual/baselines`.
   Check the images, or the **visual-baselines-report** artifact, then commit.
   If you can reach GitHub over git but not its artifact storage, run the
   workflow with `push_branch` checked (`gh workflow run visual-baselines.yml
   --ref <branch> -f push_branch=true`); it also commits the PNGs to the
   `visual-baselines-update` branch, from which you can
   `git fetch origin visual-baselines-update` and
   `git checkout FETCH_HEAD -- website/tools/visual/baselines`.

When the CI job fails, the **visual-regression-diffs** artifact holds the HTML
report and the expected, actual and diff images of each failed screenshot. The
job log shows what to do next. If `baselines/` is empty, the job fails at once
with the steps above.

## Update the fixtures

Only needed when an API response or a quick example changes on purpose.
Afterwards, regenerate the baselines.

```sh
node website/tools/visual/capture-fixtures.mjs --python /path/to/venv/bin/python [--executable-path /path/to/chromium]
```

The script starts the Vercel entry point (root `app.py`) with the environment
from `vercel.json`, loopback only and with the rate limit raised. It clicks the
same quick examples as the spec and writes `fixtures/*.json`. It inherits only
`PATH`, `HOME`, `TMPDIR` and `SYSTEMROOT` from the environment.
