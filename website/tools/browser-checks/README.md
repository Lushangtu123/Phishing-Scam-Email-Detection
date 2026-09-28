# Real browser integration checks

This script starts the actual FastAPI application and existing image benchmark
on temporary loopback ports, launches headless Chromium, and exercises the shipped
pages and vendored module workers. It uses no API response mocks, personal mail,
cloud credentials or remote uploads. Its temporary SQLite database is deleted and
both servers and the browser are stopped in `finally`.

The fifteen checks cover sender analysis, manual message analysis, English and Chinese
image URL-line confidence displayed through the real API/UI, image upload,
local-only original-image preview beside the OCR result,
worker cancellation followed by a successful retry, EML embedded-image extraction,
six repeated inline images followed by a different QR attachment,
inert HTML QR decoys versus Outlook/CSS image candidates and bounded parsing,
independent HTML MIME parts and separate OCR/QR phrase assessment,
analyst image-case creation and reload, all five existing synthetic benchmark
images, an additional authored rotated QR with adjacent and scattered text, and
ten browser-authored font/text controls for URL lookalikes and non-URL prose,
and a 4,096 × 1,600 screenshot with two-pixel and eight-pixel QR modules beside
ordinary caption text.
Case creation uses a synthetic token generated only for this run's local
server. The script verifies that the token is absent from browser storage.

## Run from the repository root

Prerequisites: Node.js 20 or newer, Python with the project's development
requirements installed, Playwright 1.62.1, and its Chromium browser. Use a local
virtual environment and browser dependency directory rather than a global install:

The Playwright pin is the version read from the installed package used in the
local Chromium validation; its browser identity is recorded separately in each
report. A locally supplied Chromium can differ from Playwright's packaged browser.

```sh
python3 -m venv ../work/browser-venv
../work/browser-venv/bin/python -m pip install -r requirements-dev.txt
npm install --prefix ../work/browser-deps --no-save --package-lock=false playwright@1.62.1
PLAYWRIGHT_BROWSERS_PATH="$PWD/../work/browser-binaries" node ../work/browser-deps/node_modules/playwright/cli.js install chromium
PLAYWRIGHT_BROWSERS_PATH="$PWD/../work/browser-binaries" node website/tools/browser-checks/run.mjs \
  --python "$PWD/../work/browser-venv/bin/python" \
  --playwright-module "$PWD/../work/browser-deps/node_modules/playwright" \
  --output "$PWD/../work/browser-checks"
```

When a compatible Chromium is already available, pass its full executable path
using `--executable-path`; no browser download is required. `--playwright-module`
can point to an existing Playwright package. Use `--help` for all options.
The script creates its own backend and has no option to write to a deployed
service or use a real analyst credential. Run on a machine that permits local
server sockets and headless browser processes.

The command exits nonzero on a failed check. It writes
`browser-checks-report.json` and `vision-evaluation-report.json` under `--output`.
`browser-checks-report.json` separates `integration_passed` from the literal
extraction mismatch counts. The image report includes the actual browser identity, source and resource hashes,
per-record statuses and literal metrics. Reports exclude raw recognized text,
URLs, QR payloads and access tokens. The browser report includes only the
synthetic English/Chinese page and URL-like line confidence numbers, boolean
literal-text matches, and aggregate counts for the ten authored controls.
These confidence values are diagnostic, not safety scores.
Existing fixtures contain synthetic data
only. The default report directory is `../work/browser-checks`, outside the
repository. Keep generated reports in `work/` and attach them as CI artifacts when
running the command in a browser-enabled job.

## What passing means

The hard integration gates require usable extraction for every image, exact
single- and multiple-QR payload sets with zero unexpected payloads, zero OCR text
on the two QR-only controls, preservation of the rotated QR's adjacent caption
and scattered text, recovery of the later QR despite repeated earlier images,
exclusion of QR decoys in inert HTML while preserving conditional/CSS candidates, no unexpected
cross-source credential phrases or negation, recovery of a QR after a separate
MIME part with unclosed markup, no unexpected
Han characters on English controls, and literal CER at most 5% on each English
text control and 40% on the Chinese text control. CER preserves punctuation,
case and whitespace. The Chinese ceiling preserves the current limited
synthetic behavior; it is deliberately not a production acceptance target.

Exact text and OCR URL sets are scored separately against the unchanged,
human-transcribed manifest. They are **not replaced with OCR-derived answers** or
normalized to manufacture matches. The report's `literal_extraction.status`
explicitly distinguishes exact output from remaining mismatches, even when all
integration checks pass. QR-only images also count false OCR text.

On the initial Chromium 148 run, all seven integration checks passed, QR exact
sets were 5/5 (including empty reference sets), text exact matches were 0/5,
and OCR URL exact sets were 1/3. CER was 45/238 (18.9%) overall: 1/71 on the
English meeting image, 4/116 on the English phishing image and 18/51 on the
Chinese image; the two QR-only images produced 22 spurious OCR characters.
Whitespace errors and OCR URL errors remain defects to investigate. A passing
browser check does not certify literal OCR accuracy, model accuracy or real mail
safety. Do not raise ceilings or alter ground truth just to pass a regression.

After masking successfully decoded QR quadrilaterals in the OCR copy, the same
unchanged five-image manifest scored 23/238 edits (9.66% CER), text exact 2/5,
OCR URL exact 1/3 and QR exact sets 5/5. Both QR-only controls emitted zero OCR
characters, down from 22. The three text controls retain their original errors
(1/71, 4/116 and 18/51). A separate browser-authored 45-degree QR control verifies
that its literal payload, a caption inside the bounding box but outside the QR
polygon, and scattered text all survive. Only decoded polygons are masked;
undecodable regions remain visible to OCR. Original bytes, resource versions,
language selection, sparse-text segmentation and literal scoring are unchanged.
These are synthetic regression results, not real-world accuracy estimates.

The large-screenshot control initially lost its smaller QR because the worker
reduced the entire image to 2,000 pixels before QR decoding. The worker now decodes
and masks QR polygons at original resolution, then reduces the masked copy for
OCR. The same control changes from one of two exact QR payloads to both, while
retaining the exact `Review notes` caption without QR noise. File, pixel, image,
QR-count and job-time limits still apply; the decoded bitmap is checked against
the pixel limits and released before OCR. The report records elapsed time as a
diagnostic rather than a portable performance guarantee.

The next Chromium 148 run added URL-line diagnostics without changing OCR text,
QR extraction or risk scoring. The synthetic English phishing image had 92%
overall OCR confidence but 48% on its misread URL-like line; the Chinese image
had 92% overall and 80% on its malformed URL-like line. Both line values are
reported to the user for character-by-character checking. Neither value
confirms a URL, and a missed URL-like line produces no line score. Literal URL
accuracy remained 1/3 and CER remained 23/238. The nine checks passed locally.

The additional Chromium 148 stress check draws ten separate images in-browser:
`1`/`l` and plain/digit-containing addresses in Arial and Georgia, plus two
non-URL text controls. The worker returned a URL-like line score for all eight
address controls and none for the two non-URL controls; eight of the ten literal
OCR strings matched their authored text. The non-URL dotted release number
`Q3.2026` initially triggered a false URL-like score; it now has none. These
controls add a small regression set, not a claim of general URL recognition or
calibrated confidence. The existing five-image manifest and its reference labels
remain unchanged. The current ten browser checks passed locally.

The text model, mailbox verification, retained sender history and external
opinions are disabled in this runner. Browser network requests are restricted to
the two local origins; the existing chart CDN is blocked, and chart rendering is
outside these checks. No recognized link is opened. This is an optional integration
command for CI environments with Playwright and Chromium installed; Node's VM
unit tests remain useful but cannot replace it.

## Optional GitHub Actions run

The separate **Synthetic browser integration** workflow in
`.github/workflows/browser-checks.yml` runs only through `workflow_dispatch`.
After the workflow is available on GitHub, select it in the Actions tab and use
**Run workflow**. It does not run automatically for pushes or pull requests and
does not deploy anything.

The job uses Python 3.12, Node 22 and Playwright 1.62.1, installing browser packages
and reports only in the runner's temporary directory. It uses the same synthetic
fixtures and isolated local APIs as the command above. Both report JSON files are
uploaded for 14 days, including when a browser check fails, and tracked source
changes fail the job. No dataset, access token or private credential is supplied
through workflow inputs or secrets. Artifact upload uses the officially documented
[actions/upload-artifact v7](https://github.com/actions/upload-artifact#usage).

This manual workflow is a reproducible synthetic integration run. Its green
status is not a real-data release evaluation, and the uploaded reports retain
the literal OCR mismatch counts separately from integration success.
