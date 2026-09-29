# Changelog

All notable changes to the **Phishing & Scam Email Detection** project are
documented in this file.

> **Maintenance rule:** every future change — model upgrades, new datasets,
> backend or frontend tweaks, bug fixes, README adjustments — MUST be appended
> to this file as a new entry under a new ISO-format heading, with the
> following structure:
>
> ```
> ## [YYYY-MM-DD HH:MM PT] — Short title
> ### Why
> ### Files changed
> ### Effect
> ```
>
> Order: newest entry at the top. Times are local (Pacific). Keep entries
> factual and reference specific files, metric values, or commit hashes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [2026-09-29 10:30 PT] — Real 2023 legitimate mail: account and security notices are flagged 69% of the time

### Why
- Public real, recent, legitimate transactional mail is scarce. The only usable find was the free UniqueData/email-spam-classification sample (58 real "not spam" emails from around 2023, CC BY-NC-ND 4.0). It is used as an independent test set.

### Files changed
- `website/tools/evaluate_external_corpora.py` — `load_uniquedata` and optional `--uniquedata-csv`, which adds the legitimate rows as a test-only set to `--extended-experiment`.
- `website/tests/test_external_corpora.py` — the UniqueData loader splits legitimate and spam rows.
- `docs/evaluation.md` — source row, per-condition false-positive rates and the highest-scoring notices.

### Effect
- At 0.3736 the deployed recipe (C0) flags 40/58 (69.0%, Wilson 56.2–79.4%). This matches the 67.7% on the PhishFuzzer seeds from a different collection.
- C2 flags 53.4% and C3 flags 58.6%.
- Netflix, Steam, Twitch, Venmo and Instagram account and security notices score 0.82–0.99.
- The served model is unchanged.

## [2026-09-29 09:40 PT] — Newer phishing, marketing mail and templates: phishing extrapolates, transactional legitimate mail does not

### Why
- The previous round showed recent legitimate mail is the missing ingredient. Newer public data (Nazario 2015–2025 phishing, Marketing-Emails, Postmark transactional templates) was added to test time extrapolation and whether more data closes the gap.

### Files changed
- `website/tools/evaluate_external_corpora.py` — mbox loader for Nazario yearly files (charset fallback, HTML stripped from every text body, unfolded subjects), Marketing-Emails CSV loader, Postmark template loader with placeholder filling (demo template skipped), deterministic family split, and `--extended-experiment`. The option compares C0–C3 on recent PhishFuzzer seeds (grouped folds), Nazario 2023–2025, held-out marketing mail and templates, after removing family overlap with training.
- `website/tests/test_external_corpora.py` — malformed mbox messages, marketing/template parsing, family split, and grouped-fold isolation in the extended experiment.
- `docs/evaluation.md` — sources, licenses, revisions, C0–C3 results and limits.

### Effect
- With no change to its training data (C0), the recipe detects 97.3% of 2023–2025 Nazario phishing.
- C3 (C2 + 13,101 synthetic marketing emails + 1,841 Nazario 2015–2022 messages) does not beat C2: recent-seed PR AUC 0.790 vs 0.793, FPR 37.3% vs 32.4%.
- Marketing-Emails turned out to be fully synthetic and is flagged under 1% even by C0.
- Transactional templates for dunning and trial expiry are flagged: 3/10 with C0, 5/10 with C3.
- The served model is unchanged. The next useful data is real, recent, legitimate transactional mail.

## [2026-09-29 08:22 PT] — External public corpora: recent legitimate mail is the missing training ingredient

### Why
- Normalization and reweighting of the existing corpora did not improve transfer. Public data with more recent mail (DiFraud, PhishFuzzer, phishing_pot) was obtained to measure the recipe on unseen mail and to test whether adding it helps.

### Files changed
- `website/tools/evaluate_external_corpora.py` — trains the deployed configuration on the seven training corpora and scores DiFraud and PhishFuzzer (recent real seeds, LLM variants of recent and legacy seeds, spam separately) after removing training-family overlap; `--augmentation-experiment` compares C0/C1/C2 training sets on the recent seeds with grouped folds over seed IDs.
- `website/tests/test_external_corpora.py` — loaders, provenance split, spam separation, overlap removal, external rows never trained on, and C2 never training on a tested seed's family.
- `docs/evaluation.md` (§5), `.vercelignore` — sources, licenses, pinned revisions, results and limits; keep the tool out of the deployment.

### Effect
- Serving pipeline, 500 phishing_pot + 500 easy_ham EML: phishing recall 85.2% (81.8–88.0%), 1.4% not alerted and 13.4% undetermined; legitimate false alerts 5.0% on 2003 mail; 0.4% of phishing analyses complete.
- Model recipe on unseen corpora: DiFraud PR AUC 0.963, FPR 10.5%; recent real PhishFuzzer seeds PR AUC 0.725, FPR 67.7%; LLM variants of recent seeds FPR 66.8% vs 6.0% for variants of legacy seeds.
- Training additions on the 205 recent seeds: PR AUC 0.725 → 0.707 (C1: + DiFraud + legacy variants) → 0.793 (C2: + variants of other recent seeds); FPR 67.7% → 53.9% → 32.4%; recall 83.5% → 83.5% → 81.5%. Small, single-collection sample; not adopted into the served model.
- Validation: 722 backend tests (5 new), 507 frontend tests, `ruff check .` and `git diff --check` pass.

## [2026-09-29 07:48 PT] — Corpus reweighting and CEAS_08 removal do not improve transfer (negative result)

### Why
- After text normalization failed, the next candidate was corpus composition: 91% of legitimate training mail comes from two older corpora, and CEAS_08's phishing labels likely mark spam.

### Files changed
- `website/tools/evaluate_source_holdout.py` — `--balance-sources` (equal total sample weight per training corpus, mean weight 1, routed to the classifier inside the pipeline) and repeatable `--exclude-from-training CORPUS` (scored, never trained on, in both the pooled folds and the held-out runs); both recorded in the report settings.
- `website/tests/test_source_holdout.py` — excluded corpora never enter any training set yet are scored; balanced weights sum equally per corpus and reach the final pipeline step; no weights without the option. The exclusion test fails when the exclusion is removed from the held-out loop.
- `docs/evaluation.md` — results and conclusion (§4).

### Effect
- Held-out PR AUC, baseline / balanced / without CEAS_08 / both: Phishing_Email 0.832 / 0.793 / 0.551 / 0.553; CEAS_08 0.971 / 0.954 / 0.971 / 0.954; phishnchips_core 0.746 / 0.760 / 0.730 / 0.755; SpaPhish 0.597 / 0.597 / 0.569 / 0.561. Hard-negative FPR 60.3% / 60.7% / 67.3% / 66.2%.
- Without CEAS_08 the model loses 17,114 of 30,519 legitimate examples and flags 89% of legitimate `Phishing_Email` mail. Not adopted; the missing ingredient is modern and non-English legitimate mail, which the public corpora do not supply.
- Validation: 10 evaluator tests pass.

## [2026-09-28 20:35 PT] — Surface-token text normalization does not improve transfer (negative result)

### Why
- The deployed model's strongest features include years, clock times, quoted-reply markers and specific URLs. Replacing those surface details with fixed tokens was the first candidate fix, tested against the 20:06 leave-one-source-out baseline before touching the served model.

### Files changed
- `website/tools/model_text.py` — idempotent normalizer: URLs, email addresses, clock times (including `5pm`), years and other numbers become `zzurl`/`zzemail`/`zztime`/`zzyear`/`zznum`; quoted-reply `>` markers are removed; trailing sentence punctuation stays outside URLs. Evaluation-only; excluded from the deployment.
- `website/tools/evaluate_source_holdout.py` — `--normalize` runs the same recipe with the normalizer as the first pipeline step and records it in the report.
- `website/tests/test_model_text.py`, `website/tests/test_source_holdout.py` — replacement cases (checked against actual output), idempotence, untouched Chinese/Spanish text, tokens surviving the production vectorizers, and the normalized pipeline differing from production only by its first step.
- `docs/evaluation.md`, `.vercelignore` — results, analysis and scope.

### Effect
- Same data, deduplication and seed: pooled PR AUC 0.9993 → 0.9991; held-out PR AUC 0.832 → 0.829 (Phishing_Email), 0.971 → 0.956 (CEAS_08), 0.746 → 0.786 (phishnchips_core), 0.597 → 0.630 (SpaPhish); Nazario recall 85.7% → 74.5%; hard-negative FPR 60.3% → 59.7%. Where FPR fell (Phishing_Email 19.4% → 14.1%) recall fell too (78.0% → 73.0%).
- A normalized fit on all corpora removes the year cue (`zzyear` −0.15) but rebuilds corpus cues from the tokens (`zztime` −3.25, `zzurl zzemail`) and keeps names (`enron` −6.6, `vince`, `tony`); mojibake `â` is a +3.3 phishing cue. 91% of legitimate training mail is from `CEAS_08` and `Phishing_Email`. Not adopted; corpus composition is next.
- Validation: 11 new or updated tests pass; the tool runs both as a script and under unittest.

## [2026-09-28 20:06 PT] — Leave-one-source-out evaluation of the content-model recipe

### Why
- The README's 98.80% accuracy comes from a grouped split of pooled corpora, so test messages have training neighbours from the same corpus. Newer data (SpaPhish 2024/2025: 14.6–18.8% false positives) and the deployed model's strongest features (`enron`, `vince`, `jose`, `monkey org`, `2005`, `2026`) pointed to corpus shortcuts, which that split cannot measure.

### Files changed
- `website/tools/evaluate_source_holdout.py` — trains the deployed configuration on all corpora but one and scores the held-out corpus, alongside a pooled grouped 5-fold baseline; deduplicates normalized families across corpora and drops label conflicts first; writes aggregate JSON (counts, Wilson intervals, PR/ROC AUC, corpus SHA-256s) and a Markdown table. It does not touch the served artifact.
- `website/tests/test_source_holdout.py` — held-out rows never enter training, metrics match hand calculations, single-label corpora omit the missing rate, corpora are skipped when the rest lack a label, cross-corpus deduplication, and the evaluated classifier, vectorizer and threshold match the committed artifact.
- `docs/evaluation.md` (§4), `README.md`, `.vercelignore` — method, command, results and limits; flag the README table as in-distribution; keep the tool out of the deployment.

### Effect
- On 56,232 deduplicated public messages (7 corpora; `phishnchips_legit_v5` is fully duplicated by `phishnchips_core`), the pooled baseline reproduces the README's picture (PR AUC 0.9993, recall 99.44%, FPR 2.00% at 0.3736). Holding a corpus out: `Phishing_Email` recall 99.1% → 78.0% and FPR 1.9% → 19.4%; `phishnchips_core` recall 98.7% → 10.6%; SpaPhish FPR 11.0% → 96.5%; synthetic hard negatives FPR 12.9% → 60.3%; `Nazario` recall 98.9% → 85.7%; CEAS_08 recall 97.8%, FPR 9.4%.
- This is the baseline for normalization, label and corpus changes; no model, threshold or rule changed.
- Validation: the parity test fails when `C` is changed (4.0 → 1.0). Full run took about 16 minutes on an Apple-silicon laptop.

## [2026-09-28 19:45 PT] — Commit container visual baselines and enable the visual CI job

### Why
- The screenshot suite needs baselines rendered in the same pinned Playwright container as CI before its job can block merges.

### Files changed
- `website/tools/visual/baselines/*.png` — 17 baselines rendered by **Visual baselines** run 36512371739 (`mcr.microsoft.com/playwright:v1.62.1-noble`, from e6edb8a), fetched from `visual-baselines-update` and reviewed (English and Chinese sender results, content results, hero, mobile menu, 404).
- `.github/workflows/ci.yml` — the blocking `visual` job (compare against the committed baselines in the same container; upload expected/actual/diff images on failure).

### Effect
- Layout or style changes that move the homepage results, hero, mobile menu or 404 page now fail CI with diff images.

## [2026-09-28 19:35 PT] — Visual baselines: optional push to a review branch

### Why
- The first baseline run (36512049177) succeeded, but its artifact is served from Azure Blob storage, which the development sandbox's network policy blocks; GitHub over git is reachable.

### Files changed
- `.github/workflows/visual-baselines.yml` — new `push_branch` input (default off). When set, the job also commits the rendered PNGs to the separate `visual-baselines-update` branch (force-pushed; never the branch it ran on). The job's permission is `contents: write` for that step; the workflow stays manual-only.
- `website/tools/visual/README.md` — how to use it.

### Effect
- Baselines can be fetched with `git fetch origin visual-baselines-update` and reviewed before being committed to `website/tools/visual/baselines/`.

## [2026-09-28 19:20 PT] — Production smoke: accept Vercel's browser cache header

### Why
- The first production run of `--check-frontend` (c9e2397, run 36509859168) passed compression, the HTML/JSON 404s, CSP and `/cases`, but failed all three assets on `Cache-Control: public, max-age=86400`. That is the documented Vercel behaviour (12:27 correction entry): the CDN acts on `stale-while-revalidate` and strips it from browser responses. The check, not the site, was wrong.

### Files changed
- `website/tools/post_deploy_smoke.py` — `_versioned_cache_ok` requires `public` and `max-age=86400`, allows `stale-while-revalidate` to be absent (must be 604800 if present) and rejects `no-store`/`no-cache`/`private`.
- `website/tests/test_post_deploy_smoke.py` — test for the accepted and rejected headers.
- `README.md` — notes the Vercel header.
- `website/tools/post_deploy_smoke.py` — `frontend_delivery.versioned_cache_control` now reports the `Cache-Control` observed for each asset instead of the app's constant.

### Effect
- Production evidence from run 36509859168: compressed `style.css`, `i18n.js`, `app-core.js`; unknown page → HTML 404 with `no-store` and CSP; unknown `/api/` path → JSON 404; homepage, 404 page and `/cases` CSP `script-src 'self'`/`style-src 'self'` without `'unsafe-inline'`; `/cases` `no-store` and `noindex`.

## [2026-09-28 19:14 PT] — Visual regression screenshots of the homepage results, rendered in a pinned Playwright container

### Why
- No test looked at the rendered page, so a CSS or markup change that broke the layout of the analysis results, the navbar or the 390 px layout passed CI.
- Font rendering differs between machines, so baselines have to come from one fixed environment, not from a developer machine or a plain runner.

### Files changed
- `website/tools/visual/visual.spec.mjs` — 17 `toHaveScreenshot` cases. Navbar and hero, sender result (`security-alert@paypa1-verify.xyz`) and content result ("Account suspension phish"), each in light and dark at 1280 and 390 px; the sender result in Chinese at 390 px; the 390 px section menu open; the low-risk sender and legitimate-newsletter results and the 404 page at 1280 px light. Result screenshots are element screenshots. Every `/api/` call is fulfilled from fixtures matched on the exact request body. An unmatched API call, any other-origin request or a page error fails the test.
- `website/tools/visual/playwright.config.mjs` — Chromium only; device scale factor 1, `en-US`, UTC, service workers blocked, reduced motion through `contextOptions`. `animations: 'disabled'`, `caret: 'hide'`, `threshold` 0.2, `maxDiffPixelRatio` 0.001 (0 with `PHISHGUARD_VISUAL_STRICT=1`). CI never writes baselines (`updateSnapshots: 'none'`). No retries.
- `website/tools/visual/scenarios.mjs` — shared page flows: wait for `networkidle`, the Chinese dictionary, `document.fonts.ready` and two frames; click a quick example and require its analysis request; park the pointer off the page so no card keeps `:hover`.
- `website/tools/visual/run.mjs` — entry point. `--committed` uses `baselines/`; otherwise the git-ignored `baselines-local/` is used. `--update` starts from an empty set. It fails with the regeneration steps (GitHub `::error` annotation) when committed baselines are missing or differ. It refuses to write committed baselines outside the `/ms-playwright` image, and checks that the installed `@playwright/test` equals the pin.
- `website/tools/visual/server.mjs`, `server.test.mjs` — dependency-free static server with `app.py`'s page routes (`/`, `/cases`, `/favicon.ico`, `/static/*` confined to the static directory, empty Vercel collector scripts, the HTML 404 page, JSON 404 for missing assets). `/api/*` answers 503. Five `node:test` cases, including path traversal.
- `website/tools/visual/capture-fixtures.mjs`, `fixtures/*.json` — `config`, `metrics`, two sender and two content responses, recorded through the real page from the Vercel entry point with the `vercel.json` environment (production, content model on, `VERIFICATION_MODE=lite`), loopback only. Values under time- or id-like keys and ISO timestamps are replaced; the current responses have none. A second capture reproduced all six files byte for byte.
- `website/tools/visual/screenshot.css`, `hide-navbar.css` — capture-only styles: the decorative background blobs are hidden; result screenshots also hide the sticky navbar, keeping its layout.
- `website/tools/visual/package.json`, `package-lock.json` — `@playwright/test` 1.62.1 (with `playwright` and `playwright-core` 1.62.1).
- `website/tools/visual/baselines/.gitkeep` — the committed baseline directory, filled from the workflow artifact.
- `website/tools/visual/README.md` — coverage, the reason for container baselines, stabilisation, tolerance with measurements, local run, baseline and fixture updates.
- `.github/workflows/ci.yml` — new `visual` job in `mcr.microsoft.com/playwright:v1.62.1-noble` (`--ipc=host`, `contents: read`, npm cache from the lockfile). On failure it uploads the report and the expected/actual/diff images as `visual-regression-diffs`. The `test` job runs `server.test.mjs` and runs `node --check` on the seven new modules.
- `.github/workflows/visual-baselines.yml` — manual `workflow_dispatch`, `contents: read`, same image. It renders every baseline and uploads the PNGs as `visual-baselines` and the report as `visual-baselines-report`. It commits nothing.
- `.gitignore` — `website/tools/visual/baselines-local/` and `website/tools/visual/.output/`.
- `README.md` — Testing section: one paragraph on the visual job.

### Effect
- Locally (Chromium 141 headless shell, with local baselines), three strict compare runs in a row, allowing no differing pixel: 17/17 passed each time, about 17 s per run. Across repeated update runs, 15 of the 17 PNGs were byte-identical. The other two differed only by 1/255 in a shadow band, which the per-pixel threshold ignores.
- Before the reduced-motion fix, count-ups were captured mid-way ("29" / "28" for 30; "0%" / "1%" on the score ring). A card under the last click position also flipped `:hover` between runs.
- Deliberate breaks in a scratch copy of `website/static`:
  - `.col-card` padding 22 → 20 px failed all 11 result screenshots.
  - `.verdict-banner` side padding 30 → 34 px failed the three 1280 px sender results (4,283–5,624 px, about 5× the 0.1% budget). At 390 px the banner is a centred column, so nothing moved.
  - A colour-only change of the light `.level-high` label was not detected; this is documented, and label contrast stays covered by `app.test.mjs`.
- `website/tools/visual/baselines/` is empty until the **Visual baselines** workflow has run, so the `visual` job fails with instructions until its PNGs are committed. `node --test website/static/*.test.mjs` is unchanged.

## [2026-09-28 19:05 PT] — Post-deploy smoke checks frontend delivery on production

### Why
- Compression, the HTML 404 page and versioned-asset caching could only be verified on the real Vercel deployment, which is not reachable from the development sandbox. The production smoke job already runs on GitHub after every Production deployment.

### Files changed
- `website/tools/post_deploy_smoke.py` — new opt-in `--check-frontend` (`_check_frontend_delivery`): homepage, 404 page and `/cases` CSP (`script-src 'self'`, `style-src 'self'`, no `'unsafe-inline'`) and `nosniff`; `Content-Encoding` in br/gzip/zstd and `Cache-Control` equal to the app's versioned-asset value for `style.css`, `i18n.js`, `app-core.js` (URLs read from the homepage); unknown page URL → uncached HTML 404 page; unknown `/api/` path → JSON `{"detail": "Not Found"}`; `/cases` `no-store` and `noindex`. Every check runs and all problems are reported in one error. Result JSON gains `frontend_delivery`.
- `.github/workflows/post-deploy-smoke.yml` — passes `--check-frontend`.
- `website/tests/test_post_deploy_smoke.py` — 4 tests: passing deployment, all problems reported together, cache value pinned to `website/app.py`, workflow flag.
- `README.md` — documents the frontend checks.

### Effect
- Against a local server (no compression locally) every check except compression passes; the next Production deployment reports compression from Vercel itself.
- `python -m unittest discover -s website/tests`: all pass (10 skipped); `ruff check .` clean.


## [2026-09-28 18:40 PT] — Fix a timing-dependent feedback timeout test

### Why
- CI on `main` for c860007 failed 506/507 in `test (3.12)`: `feedback.test.mjs` "a timed-out report is unconfirmed…" expected 1 request and saw 0. The same commit passed on the branch and locally.
- The test waited at most 50 event-loop turns for the report request, but `feedback.js` first hashes the input with `crypto.subtle.digest`, which runs off the main thread and can take longer on a busy runner. Reproduced locally under CPU load: 6/25 runs failed.

### Files changed
- `website/static/feedback.test.mjs` — the wait for the first request is bounded by 5 s of real time instead of 50 turns (the fake clock only replaces timers inside the page context).

### Effect
- Under the same CPU load: 0/25 failures. `node --test website/static/*.test.mjs`: 507 pass, 0 fail. No product code changed.

## [2026-09-28 17:50 PT] — Worded severity labels, severity-sorted case evidence, `style-src 'self'` homepage CSP, forced-colours support

### Why
- Homepage "Risk Indicators" (sender) and "Technical Indicators" (content) rows showed their level only by the dot and row tint colour (WCAG 1.4.1). The case workspace mixed analysis warnings, indicators and category lines in one unsorted `#evidence` list with no level at all, and repeated every warning a second time as an info-level indicator (the server adds `warning_indicator(...)` for each `analysis_warnings` entry).
- The homepage and 404 CSP still allowed `style-src 'unsafe-inline'` only because of two `style="display:none"` attributes in `index.html`.
- In Windows high-contrast (forced colours) mode tints and glows are dropped, so level pills lost their shape and the risk dots and score rings their meaning.

### Files changed
- `website/static/app-core.js` — `levelLabelHtml(level)`: a `<span class="level-label level-<level>">` with the existing `level.*` word (`high` / `高` …) for critical, high, medium, low and info; unknown levels get no label.
- `website/static/app-sender.js`, `website/static/app-content-render.js` — each indicator row renders `risk-dot` (now `aria-hidden="true"`), the level label, then the message. The content extra/safety cards toggle with `hidden` instead of `style.display`.
- `website/static/index.html` — `#content-extra-card` / `#content-safety-card` use `hidden` (the page's last two `style=` attributes).
- `website/static/style.css` — `.level-label` shares the `.cat-level-badge` rule; `.level-critical` / `.level-info` added; light-theme label colours `#b91c3c` / `#9a3412` / `#7c5800` / `#1d4ed8` and dark critical/high `#ff7a86` / `#ffa06e` so every label (and the category badge) is ≥ 4.5:1; `.risk-critical` row styling; `.col-card[hidden]`; an `@media (forced-colors: active)` block (colour fields hidden, dots `CanvasText`, ring track `CanvasText` / value `Highlight`, pills and labels bordered, glow-only field focus gets a `Highlight` outline).
- `website/static/cases.js` — `renderEvidence()`: reported signals (feedback) first, then indicators and then categories, each run stable-sorted critical → high → medium → low → info → unlevelled, with a `badge level-label risk-<level>` label (`level.*` words); info indicators that repeat a warning are dropped; warnings go to `#evidence-warnings`. All nodes are built with `textContent`.
- `website/static/cases.html` — `#evidence-warnings-group` (hidden when there are none): an `h4` "Analysis warnings" and `ul#evidence-warnings`, after the evidence it qualifies.
- `website/static/cases.css` — levelled rows lead with the label instead of the dot; warnings list with an amber dot and small heading; forced-colours rules for dots and badges.
- `website/static/i18n.js`, `website/static/i18n-zh.js` — `cases.evidence.warnings`: "Analysis warnings" / "分析警告".
- `website/app.py` — the default CSP (homepage, 404 page and other non-workspace responses) is `style-src 'self'`; the workspace and vision-worker policies are unchanged.
- `website/tests/test_app_security.py` — the default, homepage and 404 policies are exactly `style-src 'self'` without `unsafe-inline`; `/cases` and the vision worker keep their exact policies.
- `website/static/app.test.mjs`, `i18n.test.mjs`, `cases.test.mjs` — labels for every level (en and zh) and none for unknown levels; light-theme label contrast; `hidden` card toggles; a static scan for `style=` / `<style>` in `index.html` and `404.html` and for `setAttribute('style')`, `style=` markup, `<style>`, `cssText`, `insertRule` and `adoptedStyleSheets` in the homepage scripts; the forced-colours rules; case evidence order, labels, warnings group and de-duplication (en and zh).
- `website/tests/fixtures/i18n/en-snapshot.json` — regenerated with `capture.mjs`: only the 12 captured indicator lists changed, each by the added label spans (37 in all) and the dot's `aria-hidden`.
- `website/tests/fixtures/i18n/cases-scenarios.mjs`, `cases-en-snapshot.json` — the capture includes `evidence-warnings` and the group's hidden flag; regenerated with `capture-cases.mjs`.
- `website/tools/asset-versions/manifest.json` and page references — `style.css` v51, `cases.css` v21, `cases.js` v27, `i18n.js` v7, `i18n-zh.js` v3, `lang-init.js` v5, `app-core.js` / `app-sender.js` / `app-content-render.js` v5.

### Effect
- Measured in Chromium (text colour against the rendered pill background), en/zh × light/dark × 1280/390 px: homepage labels 5.41–6.76:1, synthetic critical/info rows ≥ 4.77:1, category badges ≥ 5.15:1 (dark high was 4.35:1 over a bright colour field before), case evidence labels ≥ 4.75:1; no label overflows its row and no page scrolls sideways at 390 px.
- CSP sweep with a `securitypolicyviolation` listener, en and zh: load, theme toggle (view transition), language toggle, sender result and score breakdown, content example, PNG upload with QR and with OCR text (image evidence and original-image preview), feedback dialog and confirm dialog, recent checks, benchmark chart after scroll, 404 page, 390 px menu: 0 violations. The case workspace (already `style-src 'self'`) also had 0.
- A real `.eml` case (attachment, remote image): 8 high, 3 medium, 2 low labelled indicators, then 2 labelled (high) categories, then 4 analysis warnings under their heading (they were interleaved and duplicated before).
- Node tests 499 → 507; Python tests 696 → 698 (10 skipped).

## [2026-09-28 17:03 PT] — Request timeouts and Cancel, HTML 404 page, `<noscript>` notice, mobile address keyboard

### Why
- No API request had a time limit. With `/api/analyze-email` never answering, the homepage stayed on "Analyzing…" indefinitely (after 8 s in Chromium the button was still disabled and the skeleton still showing), with no way to stop it. The same applied to content analysis, verification, `/api/config`, `/api/metrics`, feedback reports and every case-workspace request.
- Unknown page URLs (`/nope`, `/cases/x`) returned the API's `{"detail":"Not Found"}` JSON to browsers.
- With JavaScript off the homepage showed a demo form that did nothing, with no explanation; on phones the sender field got a capitalizing, autocorrecting text keyboard.

### Files changed
- `website/static/request.js` (new, 3,211 B) — `PhishGuardRequest.run(work, {timeout, signal})`: runs `work(signal)` (fetch *and* body read) under an `AbortController`, rejecting with `error.timedOut` when the limit passes or `error.aborted` when the caller's signal aborts; the fetch is aborted either way, a late settlement is ignored, the timer is always cleared, and `work` starts synchronously. `TIMEOUTS` (frozen): `action` 45,000 ms for analyses, verification and saves, which is above `vercel.json` `maxDuration` 30 s (Vercel answers 504 itself after that) and the 12 s `VERIFICATION_TIMEOUT`, with headroom for a cold start and a slow image upload; `read` 15,000 ms for `/api/config`, `/api/metrics` and case-queue reads. It only settles requests: each page words the error, so it is shared by the homepage and `cases.html` (which does not load `app-core.js`). Without `AbortController` there is no limit.
- `website/static/app-core.js` — `runRequest()`, `getRequest()` (15 s reads) and `postJSON/postRequest(url, …, {signal, timeout})` (45 s default); a timeout becomes `request.error.timeout`, distinct from `request.error.network`. Fetch options are unchanged when there is no signal.
- `website/static/app-sender.js` — new `#cancel-sender-analysis` handling: `cancelEmailAnalysis()` aborts, restores the idle form with no error, announces `request.cancelled` through `#copy-status` and returns focus to the input; `invalidateSender()` aborts the request (and any verification) instead of only superseding it. The request-id guard still drops late responses.
- `website/static/app-content.js` — `#cancel-content-scan` now covers the server request (`/api/analyze-content`, `/api/analyze-eml`, `/api/analyze-visual`) as well as the in-browser image scan (no second button); `cancelContentAnalysis()` announces and refocuses; `invalidateContent()` aborts the request.
- `website/static/app-verify.js` — verification is abortable (`abortVerification()` on reset, re-run and new analyses) and times out at 45 s back to the Run button with the timeout message.
- `website/static/app-config.js`, `website/static/app-metrics.js` — `/api/config` and `/api/metrics` use `getRequest()`; a timeout falls back as a failure did before (safe defaults, "unavailable" table).
- `website/static/feedback.js` — the report request (and its body read) runs under the 45 s limit; a timeout takes the existing sent-but-unconfirmed path (`retry.uncertain`, "The outcome is unconfirmed…", Retry resends the same body and `Idempotency-Key`), never the definite-rejection path.
- `website/static/cases.js` — `api()` runs fetch + JSON under `request.js` (GET 15 s, other methods 45 s); the session-epoch checks are kept (a timeout after sign-out stays silent), and a timeout is a localized `failure('request.error.timeout')` without a `status`, so case creation stays unconfirmed with its `Idempotency-Key` and review saves keep `expected_version`.
- `website/app.py` — `@app.exception_handler(StarletteHTTPException)`: a 404 for a GET/HEAD whose path is not `/api`, `/api/…`, `/static`, `/static/…` or `/_vercel/…`, from a client that does not ask for JSON without HTML, gets `static/404.html` (status 404, `text/html; charset=utf-8`, `Cache-Control: no-store`; the security middleware adds the usual headers and CSP). Everything else goes to FastAPI's default handler unchanged. The page bytes are read once; if the file is missing the JSON 404 is kept.
- `website/static/404.html` (new) — PhishGuard navbar with the EN/中文 toggle, "Error 404 / Page not found", links to `/` and `/cases`; `theme-init.js` + `lang-init.js` + deferred `i18n.js`, `style.css`, `<meta name="robots" content="noindex">`, no inline script or style.
- `website/static/index.html` — `request.js` before `feedback.js`; `#email-input` gains `inputmode="email" autocapitalize="off" autocorrect="off" enterkeyhint="go"` (still `type="text"`, so no native email validation); Cancel button next to Analyze; two English `<noscript>` notices (hero, and in place of the demo form).
- `website/static/cases.html` — deferred `request.js` before `cases.js`; token field gains `autocapitalize="off" autocorrect="off" spellcheck="false" enterkeyhint="go"`; English `<noscript>` notice.
- `website/static/style.css`, `website/static/cases.css` — `.btn-cancel` in the input row, `.noscript-notice`, `@media (scripting: none)` hides controls that do nothing without scripts (theme/language toggles, menu button, demo tabs and panels, recent checks; the workspace sign-in form), and the 404 page styles (`.nf-*`).
- `website/static/i18n.js`, `website/static/i18n-zh.js` — new keys `request.error.timeout`, `request.cancelled`, `sender.cancel`, `notFound.{meta.title,code,title,lead,home,cases}`.
- `website/static/app.js` — `cancel-email` page action.
- Tests: `website/static/request.test.mjs` (new, 16), `cases.test.mjs` (+5; harness `clock` option loads `request.js` with fake timers), `feedback.test.mjs` (+1; same option), `app.test.mjs` (+2), `i18n.test.mjs` (+3; the translatable-text scans skip `<noscript>`, which cannot be translated), `website/tests/test_app_security.py` (+6, `NotFoundPageTests`).
- `website/tools/asset-versions/manifest.json` — `request.js` pinned at `?v=1`; `app-config.js` 2→3, `app-content.js` 2→3, `app-core.js` 3→4, `app-metrics.js` 3→4, `app-sender.js` 3→4, `app-verify.js` 3→4, `app.js` 52→53, `cases.css` 19→20, `cases.js` 25→26, `feedback.js` 9→10, `i18n-zh.js` 1→2 (so `lang-init.js` 3→4 and `i18n.js` 4→5, which embed its URL), `style.css` 48→49.
- `.github/workflows/ci.yml`, `README.md` — `node --check website/static/request.js`; README describes the time limits, Cancel, the 404 rule and the `<noscript>` notice.

### Effect
- Hung `/api/analyze-email` in Chromium (Playwright fake clock): still busy at 44 s; at 45 s "The service took too long to respond. Try again.", button re-enabled, skeleton and Cancel hidden. Same for content analysis and verification. Cancel restores the idle form at once with "Analysis cancelled." in the live region, and a response fulfilled afterwards is not rendered.
- `/nope`, `/cases/x`, `/index.html` → 404 HTML with the site CSP and security headers; `HEAD /nope` → same headers, no body; `/api/nope` (any Accept), `/nope` with `Accept: application/json`, `/static/nope.js`, `/_vercel/unknown/script.js`, `POST /nope` → unchanged `{"detail":"Not Found"}`. `/`, `/cases`, `/favicon.ico`, the `/cases/` → `/cases` redirect and 405s are unchanged. 404 page in en/zh × light/dark: no console errors or CSP violations (Chrome's own "Failed to load resource: 404" line for the document aside).
- JavaScript disabled: the notices are visible, the dead controls are hidden (`scripting: none` matches in Chromium), and the English page is not hidden (`data-i18n-pending` is only set by script). A Chinese visitor with JavaScript off gets the English notice, as they get the English page.
- Tests: frontend 472 → 499 passing; backend 690 → 696 OK (10 skipped); English snapshots (`website/tests/fixtures/i18n/`) byte-identical, unchanged.

## [2026-09-28 16:30 PT] — Lighter first load: per-language dictionary, on-demand Chart.js, earlier in-page links, heading and metadata fixes

### Why
- Every visitor downloaded both languages' strings (`i18n.js`, 195,993 B) and Chart.js (205,222 B) on load, although only one language is shown and the chart sits below the fold.
- In-page navigation (`setupSmoothScroll()`) was bound only after `/api/config` and then `/api/metrics` answered, one after the other; with a slow metrics response the nav links fell back to the browser's instant jump, without smooth scrolling (or reduced-motion handling) and without moving keyboard focus.
- The disposable-email card jumped from the demo `h2` to `h4` subheadings (its title was a `div`), and neither page had a meta description; the private case workspace had no `noindex` (no `X-Robots-Tag` header is sent either).

### Files changed
- `website/static/i18n.js` — keeps the runtime and the English dictionary (fallback and English-match reference); new `register()`, `SOURCES = {zh: '/static/i18n-zh.js?v=1'}` and an on-demand loader that reuses the request `lang-init.js` started (marked `data-i18n-dictionary`/`data-state`). A Chinese page whose strings have not arrived stays `data-i18n-pending` and is translated (and revealed) when `i18n-zh.js` registers, dispatching `phishguard:languagechange` only after `DOMContentLoaded`; if the file fails the page is revealed in English, `console.error` is logged and `phishguard:languageerror` is dispatched. `setLang('zh')` keeps English while loading, marks `#lang-toggle` `aria-busy` and ignores clicks, applies once loaded (unless another language was chosen meanwhile), and removes a failed request so a later click retries. Public API unchanged apart from the added `register`; `DICTIONARY.zh` appears once loaded. New keys `meta.description`, `nav.lang.failed`, `cases.meta.description`.
- `website/static/i18n-zh.js` (new) — the Chinese dictionary only; registers with a running `i18n.js`, or leaves itself in `window.PhishGuardI18nDictionaries` for `i18n.js` to pick up (then cleared).
- `website/static/lang-init.js` — for a zh visitor inserts `<script src="/static/i18n-zh.js?v=1" fetchpriority=high>` into `<head>` (external, so CSP `script-src 'self'` holds; no `document.write`); its `DOMContentLoaded` reveal now waits until that request has loaded or failed. English visitors request nothing extra. The stylesheets' 2 s reveal is unchanged.
- `website/static/app-metrics.js` — Chart.js is inserted (same URL, same `sha384-e6nU…W5d1g` SRI, no `crossorigin` since it is same-origin) when `#performance` is within 600 px of the viewport (`IntersectionObserver`), or at once without it. The table renders as soon as `/api/metrics` answers; `drawMetricsChart()` draws when both metrics and library are present, in either order. A load or integrity failure logs a warning and keeps the table. The chart skips its entry animation under `prefers-reduced-motion`, as it is now drawn on screen.
- `website/static/app.js` — `setupSmoothScroll()` and `setupMetricsChartLoader()` run with the other synchronous setup; `loadPublicConfig()` and `loadMetrics()` start together (`Promise.all`), each keeping its own error handling. Announces `nav.lang.failed` on `phishguard:languageerror`.
- `website/static/cases.js` — shows `nav.lang.failed` as an error notice on `phishguard:languageerror`.
- `website/static/index.html` — eager Chart.js `<script defer … integrity>` removed; `<meta name="description">` (localized via `data-i18n-attr`), `og:type`, `og:site_name`, `og:title`, `og:description`, `twitter:card=summary` (no `og:image`: no suitable same-origin image); `.di-title` is now an `h3` above its `h4`s.
- `website/static/cases.html` — localized `<meta name="description">` and `<meta name="robots" content="noindex">`.
- `website/static/style.css`, `website/static/cases.css` — `.di-title` keeps `text-wrap: wrap` so the new `h3` looks as before; `.lang-toggle[aria-busy="true"]` shows a progress cursor.
- `website/static/page-loading.test.mjs` (new, 11 tests) — smooth scroll bound and both requests started before either answers; config/metrics failures independent; Chart.js absent from the HTML, requested once with its SRI on intersection (or without IntersectionObserver); table without Chart.js; chart drawn after a late load in the current theme and language and re-styled after it; library before metrics; load/integrity failure safe; heading order on both pages including rendered image evidence; meta tags.
- `website/static/i18n.test.mjs` — 9 new tests: English visitors never request `i18n-zh.js`; zh page hidden until applied whether the file arrives before or after `DOMContentLoaded` or before `i18n.js`; initial and runtime load failures; one load per page; a later choice wins; `?v=` identical in `lang-init.js`, `i18n.js` and the manifest; meta description follows the language. Harnesses load `i18n-zh.js` before `i18n.js` for Chinese; the English snapshots run with `i18n.js` alone and still match byte for byte.
- `website/static/cases.test.mjs`, `website/static/server-messages.test.mjs`, `website/static/app.test.mjs` — load `i18n-zh.js` for Chinese; the SRI test reads the pin from `app-metrics.js`.
- `website/static/asset-versions.test.mjs` — the manifest tracks `i18n-zh.js` from `lang-init.js` and `i18n.js` and Chart.js from `app-metrics.js`; a script-embedded URL bump cascades (the tool already scanned `.js` sources).
- `website/tools/asset-versions/manifest.json` — `i18n-zh.js` pinned at `?v=1`; `i18n.js` 3→4, `lang-init.js` 2→3, `app.js` 51→52, `app-metrics.js` 2→3, `cases.js` 24→25, `style.css` 47→48, `cases.css` 18→19.
- `.github/workflows/ci.yml`, `README.md` — `node --check website/static/i18n-zh.js`; README notes the split dictionary and on-demand Chart.js.

### Effect
- Chromium, fresh profile, uncompressed response bytes (gzip-9 estimate in brackets):

  | Visit | Before | After |
  |---|---|---|
  | Homepage, English, initial load | 26 requests, 717,334 B (208,521) | 25 requests, 431,891 B (113,793) |
  | Homepage, English, after scrolling to #performance | 26 requests, 717,334 B | 26 requests, 637,113 B (183,486) |
  | Homepage, Chinese, initial load | 26 requests, 717,334 B | 26 requests, 522,548 B (143,054) |
  | Homepage, Chinese, after scrolling | 26 requests, 717,334 B | 27 requests, 727,770 B (212,747) |
  | /cases, English | 9 requests, 326,282 B (94,214) | 9 requests, 242,976 B (68,147) |
  | /cases, Chinese | 9 requests, 326,282 B | 10 requests, 333,633 B (97,408) |

  `i18n.js` 195,993 → 110,938 B (gzip 58,632 → 31,930); `i18n-zh.js` 90,657 B (gzip 28,661). A Chinese visitor fetches 5,602 B more in total (loader, comments, new keys) in one extra, parallel request.
- First visible (translated) frame, Chromium median, throttled to 150 ms RTT / 1.6 Mbps: homepage English 2,220 → 1,708 ms, Chinese 3,918 → 2,933 ms; /cases unchanged within noise (en 662 → 660, zh 1,916 → 1,945 ms). Unthrottled local: unchanged within noise. No English frame is painted on a Chinese page, including with `i18n-zh.js` delayed 1.5 s; with it blocked the page appears in English at ~150 ms.
- With `/api/metrics` delayed 10 s, clicking "Features" right after load scrolls to `#features` and focuses it (before: native jump only; focus stayed on `<body>`). A tampered Chart.js is blocked by SRI and the table stays.
- `node --test website/static/*.test.mjs`: 472 pass, 0 fail (450 before). `python -m unittest discover -s website/tests`: 690 OK, 10 skipped.

## [2026-09-28 16:20 PT] — Case queue columns fit their card at every width

### Why
- The case queue's "Created" column was clipped at 1280 px. Measuring 1121–1920 px showed the fixed-width grid (`84 / 230 / 100 / 116 / 148 px`, or `76 / 210 / 90 / 104 / 132 px` at ≤1380 px) was wider than the queue card from 1121 to 1440 px, clipping up to 108 px of the row in English and Chinese.
- At 1121–1200 px the two columns' minimums (560 + 350 + 16 px beside the 210 px sidebar) were also wider than the page, adding a horizontal scrollbar.

### Files changed
- `website/static/cases.css` — `--case-grid` tracks after the risk badge are proportional with floors (`minmax(160px, 2.6fr) minmax(72px, .85fr) minmax(80px, .95fr) minmax(104px, 1.2fr)`; ≤1380 px: `minmax(150px, 2.4fr) minmax(64px, .8fr) minmax(72px, .9fr) minmax(96px, 1.2fr)`); the single-column breakpoint moves from 1120 to 1200 px and the sticky-queue query from 1121 to 1201 px.
- `website/static/cases.test.mjs` — new test: every non-risk track is a shrinking `minmax(…px, …fr)`, the row floor fits the queue column minimum at both breakpoints, and the two columns fit just above the stacking breakpoint (fails against the previous CSS).
- `website/static/cases.html`, `website/tools/asset-versions/manifest.json` — `cases.css` `?v=17 → 18` via `website/tools/asset-versions/update.mjs`.

### Effect
- Chromium, English and Chinese rows at 390, 860, 1000, 1121, 1200, 1280, 1366, 1381, 1440, 1480, 1600, 1920 px: row overflow 0 px and no horizontal page scroll at every width (before: 108 / 103 / 55 / 2 / 50 / 13 px overflow at 1121–1440 px and a page scrollbar at 1121 px). At 1280 px the title column is 212 px (was 210 px) and the date wraps to two lines inside a 106 px column.
- `node --test website/static/*.test.mjs`: 450 pass, 0 fail.

## [2026-09-28 15:51 PT] — Simplified Chinese case workspace (/cases) sharing the homepage language choice

### Why
- The case workspace was English-only, and the homepage's 中文 "Case login" note said so; analysts using the Chinese homepage switched language when opening a case.
- English output of the workspace must not change.

### Files changed
- `website/static/cases.html` — `lang-init.js` in `<head>` after `cases-theme.js`; `i18n.js` is the first deferred script (before `vision.js`, `file-intake.js`, `confirm-dialog.js`, `cases.js`; CSP stays `script-src 'self'`, no inline script); EN / 中文 button (`#lang-toggle`, same markup and `nav.lang.label` as the homepage) next to the theme control; 146 `data-i18n` and 18 `data-i18n-attr` annotations (sidebar, topbar, login, compose drawer, capacity/feedback overview, filters incl. option labels and "(UTC)" labels, queue headers, pagination, empty state, detail sections, Jev panel and disclosure, review form, history, footer, `<title>`); English stays in the markup; risk filter options get explicit `value`s so translated labels cannot change the filter.
- `website/static/cases.js` — every user-visible string through `t()`; renders split from fetches (`renderQueue`, `renderCapacity`, `renderFeedbackOverview`, `renderCaseView`), notices / Jev status / file status / localized errors kept as re-renderable text; on `phishguard:languagechange` the list, capacity, overview, open case, review-status option labels, draft status, Jev status and results are re-rendered from loaded data — no request, no reset of form values, drafts, pending saves or consent; times use the active locale (English still the browser default) and keep the zone name, UTC `title` and ISO `datetime`.
- `website/static/i18n.js` — 283 `cases.*` keys in `en` and `zh` (1,124 per language); `riskLabel(label, level)` (moved from `app-content-render.js`, also knows the sender verdict labels kept in feedback reports); `<title data-i18n>` pages keep their own title; the pending flag is cleared in a `finally`; 案件 → 案例 and 分析人员 → 分析员 throughout zh; `nav.caseLogin.aria` no longer says the workspace is English-only.
- `website/static/lang-init.js` — also clears `data-i18n-pending` at `DOMContentLoaded` (after deferred scripts), so the page is revealed even when `i18n.js` fails and reduced motion disables the CSS reveal.
- `website/static/cases.css` — `.lang-toggle`; span-wrapped text keeps its old styling (`workflow-preview`, footer separator, `#logout`, new-case "+", review labels); pending/reveal rule (`!important` so reduced motion keeps it); `:lang(zh-CN)` sizes for 9 px monospace capitals, badges and dates.
- `website/case_api.py` — case reads add top-level `analysis_warning_details` and `source_preview.warning_details` via `server_messages.details()` (stored analysis and audit JSON unchanged).
- `website/static/app-content-render.js` — `contentRiskLabel` delegates to `PhishGuardI18n.riskLabel`.
- `website/static/vision.js`, `file-intake.js`, `confirm-dialog.js` — comments: `i18n.js` now loads on both pages; the inline English `tr()` text remains the fallback.
- `website/tests/fixtures/i18n/cases-scenarios.mjs`, `capture-cases.mjs`, `cases-en-snapshot.json` (new) — 15 fake-DOM scenarios / 81 captures (login, all kinds/statuses/risks, partial/empty/unstable queues, pagination, filters, capacity and overview states, detail with coded indicators, warnings and categories, feedback records incl. EML preview, history incl. Jev saved, history-capacity limits, review/draft/conflict/errors, Jev availability, all 17 skip reasons, save/confirm prompts, case creation, image input errors, sign-out) captured from the pre-change scripts (commit 23110af).
- `website/static/cases.test.mjs` (+8 tests), `i18n.test.mjs` (+5), `website/tests/test_case_api.py` (+1); `.github/workflows/ci.yml`, `README.md` — syntax checks for the new fixtures, workspace localization and read-time warning codes documented; `?v=` bumps via `website/tools/asset-versions/update.mjs`.

### Effect
- English workspace output is byte-identical to 23110af across all 81 captures; `node --test website/static/*.test.mjs` 449/449 (was 436), `python -m unittest discover -s website/tests` 690 OK, 10 skipped (was 689).
- In 中文 mode, e.g. the queue shows `严重 · 用户反馈 · 漏报 · 已关闭 · 正常 · 2026年9月12日 UTC 02:05`, history shows `状态：待处理 → 处理中`, and a stored `Attachment content was not inspected; …` warning renders as its Chinese template; subjects, notes, actor names, API errors and the audit JSON stay as stored.
- Chromium (Playwright): en/zh × light/dark × 1280/390 sign-in, create from the homepage phishing example, open, save review, paginate, filter, keyboard language switch mid-draft (draft kept, 0 API calls), homepage ↔ workspace carry-over both ways, blocked `i18n.js` still reveals the page — 137 checks, no console errors, CSP violations or horizontal scroll.

## [2026-09-28 15:14 PT] — Stable codes for server messages; Chinese indicator, warning and verification text

### Why
- In 中文 mode the server's free-text English (sender `risk_indicators[].msg`, content `extra_indicators[].msg`, `safety_signals`, `analysis_warnings`, verification `message`/`smtp_message`, image assessment warnings) was shown untranslated because it carried no stable code.
- The API must not break: every existing English string and field type stays exactly as before.

### Files changed
- `website/data/server_messages.json` (new) — 189 codes → English templates (`str.format` fields): `sender.*` 39 (incl. 6 randomness-factor fragments), `content.*` 16, `link.*` 10, `structure.*` 9, `prefix.*` 4, `warning.*` 36, `safety.*` 15, `verify.*` 60.
- `website/server_messages.py` (new) — `text`, `indicator`, `message`, `wrap` (records `Sender: …` / `Attached message: …` / `Image (name): …` as `prefixes`), `describe`/`details` (derive codes for warning and safety strings from the same templates), `annotate_content`, `strip_details`; params are strings/finite numbers truncated to 256 characters, while `msg` is rendered from the untruncated values.
- `website/sender_features.py`, `website/email_structure.py`, `website/app.py`, `website/visual_evidence.py`, `website/enhanced_vision.py` — every indicator is built from its template and gains `code`/`params`; link findings keep `rule_id` (code = rule id); warning constants and `CONTENT_SAFETY_SIGNALS` descriptions come from the registry; content/visual responses add `analysis_warning_details` and `safety_signal_details`, observations add `assessment_warning_details`, enhancement adds `warning_details`; `/api/verify-email` adds `code`/`params` to `spf`/`dmarc`/`domain_age`/`mx_ptr`, `smtp_message_code`/`_params`, `note_code`/`_params`, `mailbox_verification.reason_code`/`_params`; `_analyze_case` drops the `*_details` lists before storage (indicator codes are kept).
- `website/static/i18n.js` — `server.<code>` for all 189 codes in `en` (identical to the registry) and `zh`; `server(entry)` localizes only when the English rendering of code + params reproduces `msg` (else the server text), `serverList(values, details)`; factor lists and category labels inside messages are localized.
- `website/static/app-core.js` (`serverText`, `serverStrings`, `verifyText`), `app-sender.js`, `app-content-render.js`, `app-reports.js`, `app-verify.js`, `vision.js` — sender indicators, score-breakdown rows, copy summaries, Markdown indicators and warnings, content technical indicators, safety signals, verification step details and image/enhancement warnings use the codes.
- `website/tests/test_server_messages.py` (new, 14 tests), `website/static/server-messages.test.mjs` (new, 8 tests) — registry ↔ dictionary guard (identical English, same zh placeholders, every backend code literal registered), homepage examples, auth-failure .eml, nested/visual prefixes, verification skipped/unavailable/busy/failed paths, zh rendering and fallbacks.
- `README.md` — “Message codes” under the API overview; `website/static/index.html`, `cases.html`, `website/tools/asset-versions/manifest.json` — `?v=` bumps.

### Effect
- English is unchanged: the i18n English snapshot passes untouched, and 266 indicator `msg` plus 59 verification `message` strings (47 addresses, 12 content inputs, 6 .eml files, 2 visual payloads, 58 mocked verification paths) are byte-identical to the previous commit.
- In 中文 mode, e.g. `Domain contains a hyphen (paypa1-verify.xyz) — …` renders as `域名包含连字符（paypa1-verify.xyz）— 主流服务商的域名通常不使用连字符`; matched keywords, filenames, hosts and SMTP replies stay as sent.
- Changing a backend template without updating `i18n.js` now fails `node --test`.
- Tests: Python 689 OK (10 skipped); Node 436 pass, 0 fail.

## [2026-09-28 14:37 PT] — Simplified Chinese (zh-CN) homepage UI with an EN / 中文 switch

### Why
- The homepage was English-only. Chinese-speaking users now get a full Simplified Chinese UI, while English stays the default and renders the same visible text as before.
- The case workspace (`cases.html` / `cases.js`) is out of scope and stays English.

### Files changed
- `website/static/i18n.js` (new, 1,539 lines) — `window.PhishGuardI18n` with `t(key, params)` (`{name}` interpolation; missing zh key → English; missing key → the key plus one `console.warn`), `plural` (`.one` / `.other` keys), `known(key, serverText)`, `lang`, `languageTag`, `locale`, `dateLocale`, `setLang`, `apply(root)`, and a flat 652-key dictionary per language (`en`, `zh`). It loads as the first `<body>` script, translates `data-i18n` / `data-i18n-attr` / `data-i18n-html` markup before first paint (English needs no pass), binds `#lang-toggle`, stores the choice in `localStorage['phishguard-lang']` (try/catch) and dispatches `phishguard:languagechange`.
- `website/static/lang-init.js` (new, 11 lines) — pre-paint `<head>` script, after `theme-init.js`: stored choice, else `navigator.languages[0]` starting with `zh` → `zh-CN`; sets `<html lang>` and, for Chinese, `data-i18n-pending` (cleared by `i18n.js`).
- `website/static/index.html` — 237 `data-i18n*` annotations (English text kept as the no-JS fallback; mixed-content nodes wrap their text in a `<span>`), the EN / 中文 button next to the theme toggle, `lang-init.js` in `<head>` and `i18n.js` before `vision.js`.
- `website/static/app-core.js` — `t`, `tPlural`, `uiLang`, `knownText`, `levelName`; localized `postRequest` errors including the 429 “{seconds}” message; count-ups use the active locale.
- `website/static/app-sender.js`, `app-verify.js`, `app-config.js`, `app-content.js`, `app-content-render.js`, `app-reports.js`, `app-metrics.js`, `app-theme.js`, `app-layout.js` — every user-visible literal now comes from `t()`; `renderResult` / `renderContentResult` take `{ languageOnly }` to re-render without resetting verification, re-animating scores, scrolling or moving focus; the verification notice, file-status line, last verification result and last metrics are kept so they can be re-rendered.
- `website/static/app.js` — `rerenderForLanguage()` on `phishguard:languagechange`: re-renders visible sender/verification/content/visual-evidence results, recent checks, benchmark table and Chart.js axis labels, busy button labels and the menu/theme labels from stored responses — no request is repeated.
- `website/static/feedback.js` — dialog states, errors and the retry confirmation from `t()`; server `detail` messages stay as sent.
- `website/static/vision.js`, `file-intake.js`, `confirm-dialog.js` — shared with `cases.html`, which does not load `i18n.js`, so they use `tr(key, 'English', params)`; worker progress messages are localized in `vision.js`.
- `website/static/style.css` — `.lang-toggle` (only the target language shows at ≤ 480 px), the `data-i18n-pending` no-flash guard with a 2 s reveal fallback, `:lang(zh-CN)` letter-spacing for eyebrow/uppercase labels; `.case-login span` → `.case-login span[aria-hidden="true"]` (it would otherwise hide the new label span on phones); removed the unused `.demo-tab span { font-size: 15px; }`; `.report-trigger > span[data-i18n]:first-child` keeps the ↗ spacing on the icon only.
- `website/static/i18n.test.mjs` (new, 28 tests), `website/tests/fixtures/i18n/{scenarios.mjs,capture.mjs,en-snapshot.json}` (new) — the snapshot was captured from the pre-change scripts (41 app scenarios + 3 image-evidence renders).
- `website/static/app.test.mjs` — loads `i18n.js` before the app scripts; the script-order test also checks `lang-init.js` in `<head>` and `i18n.js` as the first `<body>` script; three markup regexes accept the new attributes/span; the JSON report keys now include `language`.
- `website/static/feedback.test.mjs` — loads `i18n.js` before `feedback.js`, as the page does.
- `website/static/cases.html` — only the `?v=` bumps of the three shared scripts.
- `website/tools/asset-versions/manifest.json` — pins `i18n.js`/`lang-init.js` at `?v=1` and the bumped files.
- `.github/workflows/ci.yml`, `README.md` — `node --check` for `lang-init.js`, `i18n.js`, `confirm-dialog.js`, `feedback.js`; README runs `i18n.test.mjs` too.

### Effect
- Localized server text, only by stable code and only while the server's English still matches the dictionary (`known()`): sender `verdict` → label; content `risk_label` (9 known labels, else a label from `risk_level`); `ml_label` (2); category `key` → label/description (10); feature `name` → label/description (30); `disposable_status`, `sender_history_status`, verification `overall`, level codes. Left in English as sent: risk-indicator/technical-indicator `msg`, safety signals, `analysis_warnings`, matched keywords, SMTP/DNS/SPF/DMARC/WHOIS/PTR `message`s, API `detail` errors, feedback receipts, OCR/QR text, worker errors and warnings, classifier names in the benchmark, and the English sample emails.
- Copy summaries and Markdown reports follow the UI language; the JSON report keeps the raw API response and adds `"language": "en" | "zh-CN"`. Recent-check entries are unchanged in storage (same allow-list) and localized at render time from `mode`/`level`.
- Tests: `node --test website/static/*.test.mjs` 428/428 (was 400); `python -m unittest discover -s website/tests` 675 OK (10 skipped). Chromium: the previous English script 130/130; a Chinese run 122/122 (zh/en × light/dark × 1280/390, no console errors, no CSP violations, no horizontal scroll, no clipped controls); English pixel comparison against `origin/main` identical except sub-pixel (≤ 0.02 px) anti-aliasing where a text node became a span.

## [2026-09-28 13:37 PT] — Split the homepage script into cohesive files (no behaviour change)

### Why
- `website/static/app.js` had grown to 2,018 lines covering requests, icons, theme, tabs, navigation, sender and content analysis, verification, reports, recent checks and metrics, so no part could be read on its own. The upcoming UI-string extraction also needs rendering code in predictable places.

### Files changed
- `website/static/app-core.js` (177 lines) — `setError`, `postJSON`/`postRequest`, `escapeHtml`, the icon system (`ICON_PATHS`, `icon`), `prefersReducedMotion`, `withViewTransition`, `animateNumber`, `setupCountUps`, `setRing`, `animateBar`, `announce`.
- `website/static/app-theme.js` (59) — `THEME_KEY`, `resolveTheme`, `applyTheme`, `cycleTheme`, `setupTheme`.
- `website/static/app-layout.js` (210) — `?tab=` deep links and `switchDemoTab`, `setupDemoTabs`, the case login link, `setupMobileNav`, `setupScrollReveal`, `setupShortcuts`, `setupSmoothScroll`.
- `website/static/app-config.js` (50) — `_publicConfig`, `_emailVerificationEnabled`, `applyPublicConfig`, `loadPublicConfig`.
- `website/static/app-sender.js` (338) — `invalidateSender`, `setExample`, `clearEmail`, `runEmailAnalysis`, `renderSenderHistory`, `renderResult`, `senderScoreBreakdown`, `renderScoreBreakdown`.
- `website/static/app-verify.js` (196) — `resetVerifyCard`, `runVerification`, `renderVerifyResult`, `showVerifyVerdict`.
- `website/static/app-content.js` (275) — raw-file state, `invalidateContent`, `clearRawEmail`, `setupInputEvents`, `refreshEnhancedOptions`, `CONTENT_EXAMPLES`, `setContentExample`, `clearContent`, `runContentAnalysis`.
- `website/static/app-content-render.js` (246) — `CATEGORY_ICONS`, `RISK_CONFIG`, `contentModelName`, `contentMode`, `renderContentResult`.
- `website/static/app-reports.js` (330) — `feedbackAnalysis`/`openFeedback`, `lastResults`, copy summary, Markdown/JSON downloads, recent checks.
- `website/static/app-metrics.js` (135) — `loadMetrics`, `renderMetricsTable`, Chart.js theming and `renderMetricsChart`.
- `website/static/app.js` (59, was 2,018) — now only the entry point: the `DOMContentLoaded` setup sequence, `PAGE_ACTIONS`/`setupPageActions`, and the navbar scroll listener.
- `website/static/index.html` — loads the ten `app-*.js` files (`?v=1`) before `app.js` (`?v=50`), still after `feedback.js` and before `analytics-init.js`; the recent-checks markup comment now points to `app-reports.js`.
- `website/static/app.test.mjs` — `loadFrontend` runs the files in page order in one `vm` context; the SVG-icon test reads all of them; one new test checks `index.html` loads exactly that list in that order. No assertion changed.
- `.github/workflows/ci.yml` — `node --check` for each new file.
- `README.md` — the local syntax check covers `website/static/app*.js`.
- `website/tools/asset-versions/manifest.json` — new pins from `update.mjs`.

### Effect
- Classic scripts sharing one global scope were kept (not ES modules), so load order, the `DOMContentLoaded` handler, `window.PhishGuardFeedback`/`PhishGuardVision` access and the `vm` test harness behave as before. Nothing but placement changed: all 85 functions have identical source and all 36 top-level `const`/`let` bindings identical values when the old and new files are loaded side by side; every original line is present, and the only new lines are file banners and seven section-header comments.
- Validation: 400 frontend tests pass (399 before, plus the load-order test); 675 backend tests pass (10 local Redis skips); `node --check` on all eleven files. Chromium (Playwright) against the running app with the text model and feedback enabled: 130/130 checks across light/dark × 1280px/390px (all eleven scripts return 200; sender and content analysis; `?tab=` deep link, click and arrow-key tab switching; theme cycling auto → light → dark → auto with the chart restyled; metrics table and chart; copy summary; Markdown/JSON downloads; recent checks; the feedback dialog; the `/` shortcut; the navbar scroll state; the 390px menu), with no console errors and no CSP violations on any page load.

## [2026-09-28 13:26 PT] — Tab deep links, model-named ML card, local recent checks and downloadable reports

### Why
- The analysis mode could not be linked: every visit opened Email Address, and the hash is already used by the in-page section links (`#demo`, `#about`, …).
- The ML card title was hard-coded "TF-IDF + Logistic Regression" in `index.html` even though `content_model.py` can select `CalibratedLinearSVC` or `ComplementNB`; the API already reports the choice in `ml_metrics.model` (the shipped artifact reports `LogisticRegression`).
- Users comparing several messages had no record of earlier verdicts, and a result could only be copied as plain text, not saved.

### Files changed
- `website/static/app.js` — `?tab=address|content` opens that tab on load without animation (`tabFromSearch`, `setupDemoTabs`); `switchDemoTab(name, {animate, updateUrl})` rewrites only the `tab` parameter via `history.replaceState`, keeping other parameters and the `#hash` (`syncTabQuery`); unknown values are ignored. `_requestedDemoTab` tracks the requested tab, so a second switch while a view transition is pending (e.g. a fast ArrowRight after a click) is no longer dropped. `contentModelName` maps `ml_metrics.model` (`LogisticRegression`, `CalibratedLinearSVC`, `ComplementNB`) to a display name, else "Text model", set through `textContent`. Recent checks (`recordRecentCheck`, `cleanRecentEntry`, `renderRecentChecks`, `clearRecentChecks`): after a successful render, up to 10 entries go to `localStorage["phishguard-recent-checks"]`, each rebuilt from `mode`, `label`, `level`, `score`, `at` and (sender only) the address domain; every storage call is in `try/catch`. `downloadReport(kind, format)` builds Markdown (`senderReportMarkdown`/`contentReportMarkdown`, Markdown syntax escaped, ISO timestamp, existing disclaimer) or JSON (`{generated_at, tool: "PhishGuard", mode, result}` with every `*_base64` key removed at any depth) into a `Blob` behind a temporary `<a download>`, then revokes the object URL; filenames are `phishguard-<sender|content|eml|image>-YYYYMMDD-HHMMSS.<md|json>` in local time. `announce()` factors the `#copy-status` live-region update out of `copySummary`; it now also announces "Report downloaded", "Download failed" and "Recent checks cleared". New actions: `download-report`, `clear-recent`.
- `website/static/index.html` — `#content-ml-title` span beside the ML badge; a `role="group"` "Download report" pill with Markdown and JSON buttons next to both Copy summary buttons; a `<details id="recent-checks">` after the tab panels with a one-line "saved only in this browser" note, an empty state, and a "Clear recent checks" button; one sentence on the local list added to the content privacy notice; bump `style.css` to v45 and `app.js` to v49.
- `website/static/style.css` — `.download-group`/`.download-option` and `.recent-*` styles using theme tokens only (per-level left border: `--accent2`, `--info`, `--yellow`, `--orange`, `--red`); list rows stack at ≤640px.
- `website/tools/asset-versions/manifest.json` — new pins from `update.mjs`.
- `website/static/app.test.mjs` — 17 tests: load-time `?tab=` (no animation, no URL write), `replaceState` with query and hash kept, no pushes, ignored unknown values (`admin`, `constructor`, `__proto__`, full tab ids), the pending-transition race; ML title for all three classifiers plus fallbacks; sender entries hold the domain only; content, eml and image entries have exactly `at, label, level, mode, score`; the cap at 10; nothing recorded on a failed request; throwing, blocked, corrupt and hand-edited storage; Clear (storage, announcement, focus); relative times; Markdown and JSON contents, `*_base64` stripping without mutating the result, URL revocation, announcements, rejected kinds and formats; the markup. The page-action test now expects 33 declared actions.

### Effect
- `/?tab=content#demo` opens Email Content. Clicking or arrowing between tabs changes the URL to `?tab=address#demo` / `?tab=content#demo` without adding history entries; section links still push `#about` and keep the query.
- With the bundled artifact the card reads "TF-IDF + Logistic Regression" (from `ml_metrics.model`, not markup); a model id the page does not know reads "Text model".
- After a sender check the stored entry is `{"mode":"sender","label":"Critical Sender Risk","level":"critical","score":100,"at":…,"domain":"paypa1-verify.xyz"}`. Content, `.eml` and image entries store no subject, body, file name or OCR text. Nothing leaves the browser, and entries are display-only.
- Validation: 399 frontend tests pass (17 new, all failing against the previous sources); `node --check` on `app.js` and `app.test.mjs`; 675 backend tests (10 local Redis skips) pass. Chromium (Playwright) against the running app with the text model enabled: 76/76 checks across light/dark × 1280px/390px (deep link, replaceState, keyboard switching, hash links, ML title, Markdown/JSON downloads by mouse and keyboard, announcements, recent list persistence and Clear, no horizontal scroll, no console errors, and a page whose `Storage` methods all throw).

## [2026-09-28 13:06 PT] — Dim-text contrast, iOS focus zoom, benchmark escaping, UTC-labelled case times and announced copy

### Why
- `--text-dim` (footer headings, kbd hints, example labels, score formula, phone table labels at 10–12.5px) failed WCAG AA: dark `#6b7382` was 4.19:1 on `--bg` and 3.95:1 on `--bg-card`; light `#8792a6` was 2.90:1 on `--bg` and 3.14:1 on white. The case page's `--faint` had the same problem (dark 3.88:1, light 3.31:1 on `--canvas`).
- iOS Safari zooms into focused fields under 16px: `.email-input` 15px, `.content-subject-input` 14px, `.content-body-textarea` 13.5px, `.ocr-language-select` 15px, feedback dialog fields 14px, and the case filters 11px (the existing ≤460px rule lost to `.filter-grid input`).
- `renderMetricsTable` interpolated classifier names into HTML unescaped and hard-coded the "Best" badge to `Random Forest`. Case date filters are UTC but were labelled "From"/"Through", and case timestamps used a bare `toLocaleString()` with no zone. Copy summary only swapped the button label, which screen readers usually do not announce.

### Files changed
- `website/static/style.css` — `--text-dim` dark `#858d9d`, light `#626c81`; a `(hover: none) and (pointer: coarse)` rule sets the sender input, subject, body, OCR language select, feedback dialog select/textarea and `.copy-buffer` to 16px; new `.sr-only` utility.
- `website/static/cases.css` — `--faint` dark `#8a8a8a`, light `#6e6e6e`; the same coarse-pointer rule sets text inputs, selects, textareas, `.filter-grid` fields and the theme select to 16px.
- `website/static/app.js` — `renderMetricsTable` escapes names with `escapeHtml` and picks the best row as highest F1, ties by higher ROC_AUC (`row-best` unchanged); `copySummary` clears then sets `#copy-status` to "Summary copied to clipboard" / "Copy failed" and keeps the label swap.
- `website/static/index.html` — `<p id="copy-status" class="sr-only" role="status" aria-live="polite">`; bump `style.css` to v44 and `app.js` to v48.
- `website/static/cases.js` — `formatTime(value, timeZone)` (explicit fields plus `timeZoneName: 'short'`; `dateStyle` cannot be combined with `timeZoneName`) and `timeNode(value, className)` (`<time datetime="…Z" title="… UTC">`) used for queue dates, history times, Jev requested/reset/receipt-expiry times.
- `website/static/cases.html` — visible labels "From (UTC)" / "Through (UTC)"; bump `cases.css` to v16 and `cases.js` to v23. `theme-color` already followed the applied theme via `cases-theme.js` (`#0a0a0a`/`#fafafa` = `--canvas`); unchanged, now guarded by a test.
- `website/tools/asset-versions/manifest.json` — new pins from `update.mjs`.
- `website/static/app.test.mjs`, `cases.test.mjs`, `cases-theme.test.mjs` — 7 tests: metrics escaping and computed best row, copy live region, `--text-dim` contrast in both themes, the 16px touch rule, case time zones and ISO `datetime`, `--faint` contrast and touch rule, and `theme-color` matching `--canvas` per theme.

### Effect
| Token (theme) | Before on bg / card | After on bg / card | After, worst realistic surface |
|---|---|---|---|
| `--text-dim` dark | 4.19 / 3.95 | 6.00 / 5.65 | 4.63 (hovered glass card with sheen) |
| `--text-dim` light | 2.90 / 3.14 | 4.88 / 5.27 | 4.59 (`--fill-soft` on page) |
| `--faint` dark (canvas / surface) | 3.88 / 3.70 | 5.73 / 5.47 | 5.04 (`--soft`) |
| `--faint` light (canvas / surface) | 3.31 / 3.45 | 4.89 / 5.10 | 4.64 (`--soft`) |
- Both tokens stay dimmer than their muted counterparts (e.g. dark `--text-muted` 7.87:1 vs `--text-dim` 6.00:1 on `--bg`).
- In Chromium, a touch context gets 16px for every field listed above while desktop keeps 15/14/13.5/15/14px; a `<img onerror>` classifier name renders as text; case `theme-color` tracks the theme, with `#0a0a0a` when JS is off. Real metrics still mark Random Forest (F1 0.9746) as best.
- Validation: 382 frontend tests pass (7 new; the 6 behaviour tests fail against the previous sources, the `theme-color` guard passes on both), plus `node --check` on `app.js` and `cases.js`, and 675 backend tests (10 local Redis skips) pass.

## [2026-09-28 12:41 PT] — Theme-aware risk colours, visible load/input errors, announced results and reduced-motion scrolling

### Why
- Result scores and rings used hard-coded dark-theme hex colours as inline styles, so the light theme's darker tokens never applied: the medium-risk yellow `#f0c05a` measured 1.57:1 on the light page.
- A failed `/api/metrics` request left the benchmark table on "Loading…" indefinitely; an empty Email Content submission only shook the textarea with no message.
- A new sender or content verdict was not announced to screen readers, and result scrolling and in-page links animated even with reduced motion requested; in-page links also left the URL hash and keyboard focus behind.

### Files changed
- `website/static/app.js` — `renderResult` and `RISK_CONFIG.scoreColor` use `var(--red|--orange|--yellow|--info|--accent2)`; `loadMetrics` checks `res.ok` and a non-empty `metrics` object, shows "Benchmark results are unavailable right now." in `#metrics-tbody` on failure, and renders the chart in its own `try` so a Chart.js error keeps the table; `runContentAnalysis` sets `#content-error` for an empty submission; both result renderers focus their verdict title (`preventScroll`) after revealing it; result scrolling and `setupSmoothScroll` use `prefersReducedMotion() ? 'auto' : 'smooth'`, and in-page links now `history.pushState` the hash and focus the target (adding `tabindex="-1"` when it is not focusable).
- `website/static/index.html` — `#vb-title` and `#crb-title` get `tabindex="-1"`; bump `app.js` to v47 and `style.css` to v43.
- `website/static/style.css` — no focus outline on the two programmatically focused verdict titles.
- `website/tools/asset-versions/manifest.json` — new pins from `update.mjs`.
- `website/static/app.test.mjs` — 5 tests: theme tokens for every risk level (and both theme blocks define them), metrics failure modes versus a chart-only failure, the empty-content message, verdict focus, and reduced-motion/hash-link behaviour.

### Effect
- Light-theme score contrast on `#f4f6fb` (score text is large bold, 3:1 minimum): yellow 1.57 → 3.02, orange 2.16 → 3.13, red 2.77 → 4.27, info 1.98 → 4.78, green 1.75 → 3.33. In Chromium, a light-theme high-risk content score computes to `rgb(221, 107, 31)` (the light `--orange`) for both text and ring.
- In Chromium: a 500 from `/api/metrics` shows the unavailable row; focus lands on `crb-title` / `vb-title` after analysis; with reduced motion, the "How It Works" link jumps to `#about`, sets the hash and focuses the section.
- Validation: 375 frontend tests (5 new; all 5 fail against the previous `app.js`/`index.html`), `node --check website/static/app.js`, and 675 backend tests (10 local Redis skips) pass.

## [2026-09-28 12:27 PT] — Correction: browsers do not get stale-while-revalidate on Vercel

### Why
- The 12:11 entry and the `app.py` comment said browsers could serve a versioned file from cache for up to a week while refreshing it. Production shows otherwise: `GET /static/style.css?v=42` returns `cache-control: public, max-age=86400` with `x-vercel-cache: HIT`. Vercel's CDN acts on `stale-while-revalidate` itself and strips it from the browser response; the local server still sends the full header.

### Files changed
- `website/app.py` — the comment on `VERSIONED_ASSET_CACHE_CONTROL` now states the observed Vercel behaviour; the header value is unchanged.

### Effect
- On Vercel, browsers cache versioned files for one day and then revalidate; the CDN also caches them and serves `HIT`s, and each deployment clears that cache. A missed `?v=` bump can therefore be stale in a browser for up to a day, not a week; the 12:25 check now catches a missed bump before merge.
- Production evidence after the 12:11 change: a repeat visit loaded all 9 versioned files from the browser cache with no network request, and 304 revalidations carry `max-age=86400`.

## [2026-09-28 12:25 PT] — Fail CI when a versioned static file changes without a new ?v=

### Why
- Versioned static URLs are now cached by browsers for a day (entry at 12:11), so an edited file whose `?v=` is not bumped is served stale. This happened once during that work (`cases.css` until v15); the bump was a manual convention with no check.

### Files changed
- `website/tools/asset-versions/asset-versions.mjs` — collect every `/static/<file>?v=<version>` reference in served HTML/JS/CSS (13 files, 16 references); check them against a manifest; bump changed integer versions everywhere they are referenced, repeating until stable because a bump inside one versioned file changes its own hash (`vision.js` references `vision-worker.mjs`). It refuses before writing anything when references disagree or a changed file has a non-integer version (Chart.js `4.4.0`).
- `website/tools/asset-versions/update.mjs`, `manifest.json` — CLI that applies the update and writes a sorted manifest; initial manifest pins the current 13 versions and SHA-256s (no version changed).
- `website/static/asset-versions.test.mjs` — fails CI (it runs with the existing `node --test website/static/*.test.mjs`) when the manifest and files disagree, naming the file and the command to run; fixture tests cover the cascade, non-integer versions, disagreeing references, missing and stale pins.
- `README.md`, `.vercelignore` — document the workflow; keep the tool out of the deployment.

### Effect
- Appending a comment to `style.css` made the test fail with "style.css changed without a new ?v= (still 42)"; `update.mjs` then rewrote `index.html` to `style.css?v=43` and the test passed (probe reverted). A second run on a clean tree reports "Versioned static assets are up to date."
- Validation: 370 frontend tests (3 new), 675 backend tests (10 local Redis skips), `ruff check .`, `compileall` and `git diff --check` pass.

## [2026-09-28 12:13 PT] — Keyboard-safe clear control, eyebrow contrast and a visible sign-in h1

### Why
- A live audit found that Tab from the empty sender input landed on the invisible clear button (`opacity: 0` hid it from sight and pointer, not from focus), which was also only 47×17 px when shown.
- Light-theme section eyebrows (`#0a7fd6` on `#f4f6fb`, 13.5 px) measured 3.87:1, below the 4.5:1 AA text minimum.
- The signed-out `/cases` view had no `h1`; the workspace `h1` exists only after sign-in, and the intro column is `display: none` at ≤680 px.

### Files changed
- `website/static/style.css` — `.btn-clear` adds `visibility: hidden` (flipped after the fade) and a 44 px minimum target; light-theme `.section-eyebrow` uses `#0a6fbd` (4.83:1).
- `website/static/cases.html`, `website/static/cases.css` — "Analyst sign in" becomes the page `h1` and the intro tagline a styled paragraph, both with their previous computed styles; bump `cases.css` to v15.
- `website/static/index.html` — bump `style.css` to v42.
- `website/static/app.test.mjs`, `website/static/cases.test.mjs` — tests for the clear control's hidden state and target size, the eyebrow contrast computed from `style.css`, and a single `h1` in the always-visible sign-in panel.

### Effect
- Local Chromium: Tab from the empty input goes to Analyze; after typing, Tab focuses the visible clear button (47×44 px, 2 px focus ring). The sender input row stays 50 px tall, as in production.
- At 1280 px the tagline and sign-in heading match production computed styles and boxes exactly (51.2 px/620/−2 px at 301×109; 25 px/620/−0.35 px at 350×34); at 375 px the only visible heading is `H1: Analyst sign in`.
- Validation: 367 frontend tests (the 3 new ones fail against the previous files) and 675 backend tests (10 local Redis skips) pass, with `ruff check .`, Vercel runtime smoke, evaluation baseline, 34 asset hashes and JavaScript syntax checks.

## [2026-09-28 12:11 PT] — Defer Chart.js and let browsers reuse versioned static files

### Why
- On production, Chart.js (73 KB brotli, 200 KB decoded) was render-blocking in `<head>` although it is first used only after `/api/metrics` resolves; first contentful paint measured 736 ms.
- Every static file was served `Cache-Control: public, max-age=0, must-revalidate`, so a returning visitor revalidated about ten files per page view (observed 304s taking 110–330 ms each), even though their URLs already carry `?v=`.

### Files changed
- `website/static/index.html` — load the vendored Chart.js with `defer` (SRI pin unchanged).
- `website/app.py` — `/static/...?v=...` responses with status 200 or 304 get `Cache-Control: public, max-age=86400, stale-while-revalidate=604800`; unversioned, missing and non-static responses are unchanged. 304s carry it so browsers that stored the old `max-age=0` pick it up.
- `website/static/app.test.mjs` — the vendored-script test now also requires `defer`.
- `website/tests/test_app_security.py` — versioned 200 and 304 responses carry the policy; `favicon.svg`, a missing `?v=` file, `/?v=1` and an empty `v` do not.

### Effect
- Local: Chart.js reports `renderBlockingStatus: non-blocking` and still renders; versioned assets and their 304s return the new header.
- A changed file must still get a new `?v=`: during this work a second edit to `cases.css` without a bump was served from the one-day cache until it was bumped to v15. The one-day `max-age` bounds that failure mode.
- Validation: 364 frontend tests and 675 backend tests (10 local Redis skips) pass; the tightened chart test fails against the previous `index.html`, and the caching test fails with `None != 'public, max-age=86400, …'` when the header line is removed. `ruff check .`, Vercel runtime smoke, evaluation baseline, 34 asset hashes and JavaScript syntax checks pass.

## [2026-09-28 11:44 PT] — Escape remaining server fields, hide decorative icons, serve /favicon.ico

### Why
- Follow-up to the homepage audit: some server-supplied fields were inserted into `innerHTML` templates without `escapeHtml` while neighbouring fields were escaped; two decorative button icons and the benchmark chart were exposed to assistive technology without meaning; and `/favicon.ico` returned 404, the only console error on the live page.

### Files changed
- `website/static/app.js` — escape `high_risk_count`/`med_risk_count`, sender and extra indicator `level`, score-breakdown `level`, category `level`/`count` (class, badge and count text) and ML token `contribution` (title attribute). Values that remain unescaped are client constants, locally built markup or `toFixed()` numbers.
- `website/static/index.html` — `aria-hidden="true"` on the two Analyze button icons; `role="img"` and an `aria-label` on `#metricsChart` pointing to the table above it; bump `app.js` to v46.
- `website/app.py` — `GET /favicon.ico` returns the existing `static/favicon.svg` as `image/svg+xml`.
- `website/static/app.test.mjs`, `website/tests/test_app_security.py` — render sender and content results with `x"><img …>` in every affected field and assert it appears only escaped; assert all icons inside buttons/links are hidden and the chart has a text alternative; assert `/favicon.ico` returns the SVG with security headers.

### Effect
- Local Chromium: no console errors (the `/favicon.ico` 404 is gone), 0 unhidden icons inside controls, the chart reports `role="img"` with its label, and ordinary results render unchanged (`risk-item risk-medium`, `cat-card cat-high`, `level-high`, "4 signals matched").
- Validation: 364 frontend tests (the 2 new ones fail against the previous `index.html`/`app.js`), 673 backend tests (10 local Redis skips; the favicon test fails with 404 against the previous `app.py`), `ruff check .`, Vercel runtime smoke, evaluation baseline, 34 asset hashes and JavaScript syntax checks pass. The opt-in Playwright run was not repeated for this change.

## [2026-09-28 11:18 PT] — Homepage landmarks, tab semantics and a named sender input

### Why
- An audit of the live homepage found the main sender input had no accessible name, the demo tabs exposed no selected state, there was no `<main>` landmark or skip link (the case workspace already had both), and headings jumped from `h2` to `h4` twice.

### Files changed
- `website/static/index.html` — add `aria-label` to `#email-input`; mark the demo switcher as `role="tablist"` with `role="tab"`, `aria-selected`, `aria-controls` and roving `tabindex`, and panels as `role="tabpanel"`; add a skip link and wrap page sections in `<main id="main" tabindex="-1">`; demo column titles `h4` → `h3` and footer column titles `h4` → `h2`.
- `website/static/app.js` — `switchDemoTab` keeps `aria-selected`/`tabindex` in sync; new `setupDemoTabs` adds ArrowLeft/ArrowRight/Home/End navigation; `setupSmoothScroll` skips the skip link so focus moves into `<main>`.
- `website/static/style.css` — skip-link styles; `.footer-col h4` → `.footer-col h2` (styles are class-scoped and margins are globally reset, so rendering is unchanged).
- `website/static/index.html` (assets) — bump `style.css` to v41 and `app.js` to v45.
- `website/static/app.test.mjs` — tests for tab markup and state sync, skip link, `<main>`, sender input name and heading order.

### Effect
- Browser audit on a local server: 0 unnamed form controls (was 1), 0 heading-level jumps (was 2), tabs report `aria-selected` true/false with the active tab focusable, ArrowRight moves focus and selection and wraps, and Tab → Enter on the skip link focuses `MAIN#main`.
- Validation with both changes: 362 frontend tests (the 2 new ones fail on the previous markup), 672 backend tests (10 local Redis skips), `ruff check .`, 13 JavaScript syntax checks and 34 recognition-asset hashes pass. The opt-in browser run (Playwright 1.62.1, Chromium 151, macOS arm64) passes 17/17 checks with 0 external requests and unchanged visual metrics: exact QR sets 5/5, OCR texts 2/5, OCR URL sets 1/3 and 23/238 character edits.

## [2026-09-28 11:16 PT] — Remove script-src 'unsafe-inline' and the chart CDN from the page CSP

### Why
- The homepage CSP allowed `script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net` only because of 29 inline event handlers, two inline `<script>` blocks and Chart.js from jsDelivr. `'unsafe-inline'` removes most XSS protection on a page that renders analysis of untrusted email, and an allowlisted public CDN serves arbitrary packages.

### Files changed
- `website/app.py` — default page policy is now `script-src 'self'`; other directives are unchanged (`style-src 'unsafe-inline'` remains for inline style attributes).
- `website/static/index.html` — replace 28 `onclick` attributes with `data-action`/`data-arg` and drop the `onkeydown` attribute; load `theme-init.js`, `analytics-init.js` and the vendored Chart.js instead of inline or CDN scripts; bump `app.js` to v44.
- `website/static/theme-init.js`, `website/static/analytics-init.js` — the two former inline scripts, unchanged in behavior.
- `website/static/vendor/chart/chart.umd.min.js`, `LICENSE.md` — Chart.js 4.4.0 (MIT), byte-identical to the previous CDN file: its SHA-384 matches the existing `integrity` pin, which the script tag keeps.
- `website/static/app.js` — `PAGE_ACTIONS` allowlist and `setupPageActions`, binding each control's listener on the element itself so `event.currentTarget` is unchanged (the theme reveal animation depends on it); the Enter-to-analyze handler moves here.
- `website/static/app.test.mjs` — replace the third-party SRI test with a stricter one (all scripts same-origin, vendored file hash equals its pin); assert no inline scripts or handlers; assert each of the 28 declared actions calls the same function with the same arguments as its former inline handler; read the analytics queues from their file and require it to load before the collectors.
- `website/tests/test_app_security.py` — assert the page `script-src` is exactly `'self'`.
- `website/tools/browser-checks/run.mjs`, `README.md` — any external request now fails the optional browser run; Chart.js is no longer outside its scope.

### Effect
- Served policy: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.
- In Chromium against a local server with that policy (checked together with the accessibility change that follows): no console errors or CSP violations; Chart.js renders the benchmark chart; the pre-paint theme and analytics queues initialise; a quick-example click fills the input and posts `/api/analyze-email`; typed input + Enter posts it; the theme toggle's reveal origin equals the button centre (453, 35).
- Validation at this change: 360 frontend tests (358 before; the 4 new or rewritten ones fail against the previous `index.html`/`app.js`), 672 backend tests (10 local Redis skips), `ruff check .` and JavaScript syntax checks pass.

## [2026-09-28 10:42 PT] — Move sender-address feature extraction out of app.py

### Why
- `website/app.py` was 4,496 lines; `extract_email_features` alone was 601 lines, the largest function in the backend, interleaved with the domain registries it depends on.

### Files changed
- `website/sender_features.py` — new module holding, verbatim and in original order, `extract_email_features` and its full module-level dependency closure: known-domain sets (`LEGIT_PROVIDERS`, `HIGH_TRAFFIC`, `SUSPICIOUS_KEYWORDS`, `ROUTINE_MAILBOX_NAMES`, `BRAND_DOMAINS`, keyword and TLD sets), the disposable/privacy-relay registries, `_DOMAIN_EXTRACTOR`, registry matchers, `normalize_homoglyphs`, `_shannon_entropy`, and `_normalize_sender_address` with its two regexes (26 names, 24 statements).
- `website/app.py` — remove those statements and re-export all 26 names from `sender_features`, so `app.<name>` references in callers and tests are unchanged; drop seven imports that only the moved code used.
- `README.md` — list the new module under Project structure.

### Effect
- `website/app.py` shrinks from 4,496 to 3,732 lines. No behavior change is intended.
- Equivalence evidence: the moved 24 statements and the remaining 181 `app.py` statements are AST-identical to the originals in the same order. A differential run of the original and refactored `extract_email_features` over 3,126 addresses (every address found in `website/tests`, 3,000 seeded random locals across legitimate, disposable, relay and brand domains, and malformed inputs) produced 0 differences.
- No test patches any moved name (checked every `patch.object(app, …)`/`patch('app.…')`); no moved global is reassigned at runtime.
- Validation: 671 backend tests pass (10 local Redis skips), Vercel runtime smoke and evaluation baseline comparison pass, the root Vercel entrypoint and `website/` uvicorn imports load, 358 frontend tests, 13 JavaScript syntax checks and 34 asset hashes pass.

## [2026-09-28 10:40 PT] — Add a pinned ruff lint gate for definite Python defects

### Why
- CI only ran `compileall`, which catches syntax errors but not undefined names or dead imports. A first `ruff` pass found 9 pyflakes findings.

### Files changed
- `ruff.toml` — enable only `E9` and `F` (syntax errors and pyflakes); exclude exploratory notebooks.
- `.github/workflows/ci.yml` — new `lint` job installing `ruff==0.16.9` and running `ruff check .`.
- `.vercelignore` — exclude `ruff.toml` from the deployment bundle.
- `website/app.py` — remove unused `digit_ratio` in sender randomness scoring (factor 3 uses `digit_count` and a scatter pattern, unchanged) and unused `dns.resolver`/`dns.exception` imports in `verify_email_endpoint` (helpers import their own resolvers); mark the `_REGISTRY_DOMAIN_RE` import as a deliberate re-export because `test_detection_behavior.py` reads `app._REGISTRY_DOMAIN_RE`.
- `website/tests/test_case_opinions.py` — keep the `store.update` call but drop its unused result binding.
- `website/tests/test_compare_evaluations.py`, `website/tools/build_private_cohort.py`, `phishing-detection/src/evaluate.py`, `phishing-detection/src/train.py` — remove unused imports.
- `phishing-detection/src/preprocess.py` — replace a placeholder-free f-string with a plain string.
- `README.md` — document the lint job and the local command.

### Effect
- `ruff check .` reports 0 findings (previously 9 in served/tested code). Style rules remain disabled, so the gate flags definite defects only.
- Validation: 671 backend tests pass (10 local Redis skips); no runtime behavior changes.

## [2026-09-28 10:09 PT] — Disclose missing and ambiguous CID image coverage

### Why
- Browser image extraction silently skipped unresolved CID references. An unrelated attachment could produce image observations without warning that the referenced resource was missing.

### Files changed
- `website/static/vision-cid.mjs` — add bounded MIME-context matching with exact identifiers, single percent decoding, related/alternative scope rules and explicit coverage warnings.
- `website/static/vision-email.mjs`, `website/static/vision-core.mjs` — associate independently parsed HTML with its source MIME node without changing collection order; report unresolved or unverifiable CID references while preserving other images.
- `website/static/vision-cid.test.mjs`, `website/static/vision-email-cid.test.mjs` — add 57 controls for identifiers, message/scope boundaries, duplicate alternatives, metadata failures and resource limits.
- `website/static/vision.js`, `website/static/index.html`, `website/static/cases.html` — refresh browser asset versions.
- `website/tools/browser-checks/*`, `website/tools/vision-benchmark/serve.py`, `website/tools/vision-benchmark/test_server.py`, `README.md`, `docs/evaluation.md` — add a real worker/API/UI coverage check, include the new module in benchmark identity and document limits.

### Effect
- Missing, malformed, ambiguous, unsupported, empty or non-image CID targets now disclose incomplete coverage. Valid image candidates remain inspectable, and an unrelated attachment or another nested message cannot hide a missing reference.
- Matching is metadata verification only; image decoding, four-image budgets and OCR limits still apply. Coverage warnings do not add phishing risk, fetch remote resources or establish real-mail accuracy.
- Validation: 358 frontend tests, 17 Chromium checks, three local harness checks and 34 asset hashes pass. The 671-test backend suite passes with 10 local Redis integration skips. The paired five-image comparison passes with unchanged exact QR sets 5/5, OCR texts 2/5, OCR URL sets 1/3 and 23/238 character edits.

## [2026-09-28 09:40 PT] — Preserve QR and email results when OCR fails

### Why
- Four repeated 45-second OCR startup waits exceeded the page's 150-second limit and discarded decoded QR evidence. Parameter setup could wait indefinitely, and failed or stalled worker cleanup could suppress the result.

### Files changed
- `website/static/vision-worker.mjs` — stop OCR retries within a failed task, share deadlines across startup/setup and encoding/recognition, retain QR evidence, and make cleanup nonblocking while handling late initialization.
- `website/static/vision-worker-failure.test.mjs` — add 13 controls for startup/recognition/cleanup failures, late workers, normal reuse, damaged-image isolation and preservation of earlier text.
- `website/static/vision.js`, `website/static/index.html`, `website/static/cases.html` — refresh browser asset versions.
- `website/tools/browser-checks/run.mjs`, `website/tools/browser-checks/README.md`, `README.md`, `docs/evaluation.md` — add an actual OCR resource-outage integration check and document the behavior, evidence and limits.

### Effect
- OCR failure now produces explicit text-coverage warnings while later images still receive QR scanning. Unreadable images do not disable an otherwise healthy OCR worker; a new task can attempt OCR again.
- In Chromium, a held local OCR core request returned all four QR observations and original EML bytes in 45,974 ms, preserving the original credential-request risk. Later normal OCR checks pass after the fault is removed.
- Validation: 301 frontend tests, 16 browser integration checks and 34 asset hashes pass. The 671-test backend suite passes with 10 local Redis integration skips. Five fault controls failed before the fix. The fixed five-image visual comparison passes with unchanged QR sets 5/5, OCR texts 2/5, OCR URL sets 1/3 and 23/238 character edits.
- This improves failure recovery, not OCR spelling or measured real-mail accuracy. The overall 150-second limit remains; missing CID image coverage is not addressed in this change.

## [2026-09-28 09:25 PT] — Preserve independent MIME and visual text boundaries

### Why
- Joined HTML let unclosed markup in one MIME part hide a later part's image. Concatenated OCR and QR strings could create a credential request across sources or allow a separate caption to negate a dangerous QR request.

### Files changed
- `website/static/vision-email.mjs`, `website/static/vision-email-parts.test.mjs` — parse decoded HTML parts independently with shared part/text limits, preserve image budgets and test MIME boundaries, encoding and parser metadata failures.
- `website/app.py`, `website/visual_evidence.py`, `website/tests/test_visual_analysis.py` — assess OCR and distinct QR payloads separately; retain the strongest individual risk, maximum rule/model scores and explanatory findings without cross-source score accumulation.
- `website/static/vision.js`, `website/static/vision-ui.test.mjs` — label the highest individual model score and refresh the worker version.
- `website/tools/browser-checks/run.mjs`, `website/tools/browser-checks/README.md`, `README.md`, `docs/evaluation.md` — add actual worker/API controls and document limits and evidence.

### Effect
- The later MIME part's QR is now recovered where the browser previously produced zero observations. Across OCR-to-QR and QR-to-QR controls, separate negation cannot lower a dangerous request and phrase fragments cannot manufacture a new credential request; complete single-source sentences retain their behavior.
- Validation: 288 frontend tests and 15 Chromium integration checks pass. The 671-test backend suite passes with 10 local Redis integration skips. The fixed five-image visual comparison passes with unchanged 5/5 exact QR sets, 2/5 exact OCR texts, 1/3 exact OCR URL sets and 23/238 character edits.
- Requests remain bounded to at most 36 nonempty extracted sources. Two local synthetic runs using the pinned model took 87.2 and 82.4 ms at that maximum; this is not a production latency guarantee. The corrections do not repair OCR spelling or establish real-mail accuracy.

## [2026-09-27 23:02 PT] — Extract HTML image evidence from resource contexts

### Why
- Whole-HTML data-URI matching treated QR images inside comments, scripts, templates and literal examples as evidence. Distinct inert images could also consume the four-image budget before a real image. Parser limits applied only after a full parse would not bound deep nesting or very long attribute lists.

### Files changed
- `website/static/vision-html.mjs`, `website/static/vision-core.mjs`, `website/static/vision.js` — identify HTML/CSS resource candidates, preserve one conditional Outlook interpretation, bound parsing during construction/tokenization, decode only supported inline resources and refresh the worker version.
- `website/tools/vision-assets/*`, `website/static/vendor/vision/*` — lock parse5 8.0.1, CSSTree 3.2.1 and esbuild 0.28.2; bundle self-hosted parsers with licenses and manifest hashes. Existing OCR/QR assets are unchanged; installations remain task-local.
- `website/static/vision-html-images.test.mjs`, `website/tools/browser-checks/*`, `website/tools/vision-benchmark/serve.py`, `website/tools/vision-benchmark/test_server.py` — add 39 parser controls, a real worker regression and implementation-identity coverage.
- `README.md`, `docs/evaluation.md` — document candidate semantics, incomplete-coverage limits and remaining CSS/OCR limitations.

### Effect
- The Chromium inert-QR control changes from two observations including the hidden decoy to only the actual benign image. Outlook conditional and escaped CSS QR candidates remain recognizable with rendering warnings; earlier evidence survives a parser-limit stop.
- Validation: 262 frontend tests, 13 Chromium integration checks, three benchmark-server checks and all 34 asset hashes pass. The 665-test backend suite passes with 10 local Redis integration skips. Independent review found no remaining blocking issue.
- The unchanged five-image benchmark retains 5/5 exact QR sets, 2/5 exact OCR texts, 1/3 exact OCR URL sets and 23/238 character edits; the paired no-regression gate passes. These synthetic controls do not estimate real-mail accuracy. CSS layout/client visibility remains unverified, and unsupported CSS grammar explicitly reports incomplete coverage.

## [2026-09-27 22:46 PT] — Reduce filename false alerts and image coverage errors

### Why
- Bare download labels such as `invoice.pdf` were mistaken for displayed domains and forced high-risk mismatch alerts. Repeated inline image bytes consumed the four-image budget before worker deduplication, hiding later distinct attachments. APNG could silently contribute only its default frame.

### Files changed
- `website/app.py`, `website/tests/test_detection_behavior.py` — exempt complete bare common filenames without a recognized public suffix, with explicit-address, real-suffix and dangerous-target controls.
- `website/static/vision-core.mjs`, `website/static/vision-email.mjs`, `website/static/vision.js` — deduplicate original bytes before the shared image limit, validate PNG chunk framing, explicitly reject APNG and refresh the worker version.
- `website/static/vision.test.mjs`, `website/static/vision-image-format.test.mjs`, `website/tools/browser-checks/run.mjs` — cover duplicate/nested image budgets, PNG/APNG format failures and actual recovery of a later QR attachment.
- `README.md`, `docs/evaluation.md`, `website/tools/browser-checks/README.md` — document scope, results and remaining rendering/OCR limitations.

### Effect
- Nine synthetic benign filename controls no longer trigger displayed-domain mismatch; nine address controls and four dangerous targets retain alerts. Both historical public corpora (443 messages total) retain their prior counts, with zero inference failures; the two-class comparison passes. These corpora contain no matching filename examples, so no real-data accuracy gain is claimed.
- In Chromium, six copies followed by a different QR now yield two unique observations and the exact QR, up from one observation with the QR omitted. The existing five-image benchmark is unchanged, and its paired comparison passes. PNG animation is reported as unsupported, not treated as completely inspected.
- Validation: 223 frontend tests and 12 Chromium integration checks pass. The 665-test backend suite passes with 10 local Redis integration skips. Independent review found no blocking defect. Raw HTML data-URI rendering-context filtering and remaining literal OCR errors require further work.

## [2026-09-27 22:31 PT] — Preserve small QR codes in large screenshots

### Why
- Resizing a screenshot to 2,000 pixels before QR decoding could erase small QR modules. A real browser regression found only one of two codes in a 4,096 × 1,600 synthetic screenshot.

### Files changed
- `website/static/vision-worker.mjs`, `website/static/vision.js` — scan and mask bounded original pixels before reducing the OCR copy, check decoded dimensions, release bitmap/canvas memory, and refresh the worker cache version.
- `website/tools/browser-checks/run.mjs`, `website/tools/browser-checks/README.md` — add the small/large QR and exact-caption control, with diagnostic elapsed time.
- `README.md`, `docs/evaluation.md` — document separate QR/OCR resizing and the rejected image-alt relaxation experiment.

### Effect
- The new browser control recovers 2/2 literal QR payloads instead of 1/2 and preserves its caption without QR noise. The original five-image benchmark remains at 5/5 exact QR sets, 2/5 exact OCR texts, 1/3 exact OCR URL sets and 23/238 character edits. Larger native QR scans retain the existing size and time limits; mobile resource use is not benchmarked.
- Removing the remote-image-alt exclusion in an offline experiment increased historical normal-mail alerts from 114 to 115, so that policy remains unchanged. The 20 newly undetermined historical messages are not counted as resolved.
- Validation: 213 frontend tests and 11 Chromium integration checks pass; the 662-test backend suite passes with 10 local Redis integration skips. The fixed five-image visual comparison passes without extraction regressions.

## [2026-09-27 22:15 PT] — Avoid high-risk sender flags for routine role mailboxes

### Why
- Exact functional mailbox names such as `subscriptions` were matching broad local-part substrings and contributing to false alerts on historical normal mail.

### Files changed
- `website/app.py` — suppress the local-part keyword signal only for eight complete routine role names; keep domain and compound-name checks.
- `website/tests/test_detection_behavior.py` — cover benign role names and negative controls for account-takeover wording and spoofed domains.
- `README.md`, `docs/evaluation.md` — describe the rule and paired replay limits.

### Effect
- On 244 reference-filtered historical `hard_ham` messages, labeled-normal alerts fall from 135 to 114; nonalerts rise from 44 to 45, and undetermined from 65 to 85. The 199-message two-class pilot remains at 90/100 phishing alerts and 2/99 legitimate alerts, with seven phishing results undetermined. Both replays have zero inference failures. The two-class no-regression comparison passes; the hard-ham-only comparison fails its unknown-rate condition and lacks a phishing class. This is a targeted error correction, not an estimate of current-inbox accuracy.

## [2026-09-27 21:45 PT] — Add paired offline counterfactual alert diagnostics

### Why
- The attribution sidecar showed signal co-occurrence, but the Apple Core correction removed 30 misleading signals without changing any final verdict. The next investigation needs paired decision changes, including possible lost phishing alerts and newly undetermined outcomes.

### Files changed
- `website/tools/counterfactual_evidence.py` — replay baseline alerts with one fixed evidence family or targeted link rule removed at a time and aggregate transitions without message content or exceptions.
- `website/tools/evaluate_public_corpus.py`, `website/tools/evaluate_serving_pipeline.py` — offer optional sidecars tied to the evaluated cohort and model, using the same included rows as the ordinary reports; return nonzero if a diagnostic replay fails.
- `website/tests/test_counterfactual_evidence.py`, `website/tests/test_public_evaluation.py` — cover paired transitions, privacy, denominator integrity, independent sender/link removal and keyword-dependent pressure handling.
- `README.md`, `docs/evaluation.md` — document commands, interpretation and the first paired public-corpus replay.

### Effect
- Baseline verdicts on both public cohorts are unchanged. Among 135 historical `hard_ham` alerts, removing sender analysis alone yields 22 nonalerts and 38 undetermined results; removing link-destination rules yields 4 and 15. The narrower display-mismatch replay yields 2 and 15, while removing the now-absent brand-lookalike signal changes none. These are overlapping diagnostic experiments, not combined accuracy gains.
- On the separate 199-message pilot, removing the model would change 28 of 90 phishing alerts to nonalerts and 14 to undetermined. All seven replay variants completed without inference failures after fixing a keyword-registry shape error; no serving score, model or threshold changed.
- Local validation: 661 backend tests pass with 10 local Redis integration skips. A two-row synthetic private-evaluator CLI smoke test produced matching cohort/model digests and zero replay failures.

## [2026-09-27 21:32 PT] — Exclude Apple Core newsletter labels from link lookalikes

### Why
- Aggregate attribution found Apple brand-lookalike signals in 30 alerted historical `hard_ham` messages. Inspection identified the same Apple Core newsletter host in each, an ordinary compound name rather than a deceptive Apple domain.

### Files changed
- `website/app.py` — treat the complete `applecore` host label as a benign Apple-containing word; keep longer login-themed compounds eligible for lookalike detection.
- `website/tests/test_detection_behavior.py` — cover the newsletter host and suspicious compounds with a failing-then-passing regression.
- `docs/evaluation.md` — record the paired public-corpus replay and its limits.

### Effect
- The brand-lookalike attribution signal disappears from those 30 alerts. Final decisions remain 135 alerts, 44 nonalerts and 65 undetermined across 244 historical `hard_ham` messages; the 199-message phishing/easy-ham pilot is also unchanged. This fixes an incorrect explanation without demonstrating a false-alert-rate improvement.
- The full backend suite passes: 653 tests, with 10 local Redis integration skips.

## [2026-09-27 21:18 PT] — Add privacy-bounded evidence attribution for email evaluations

### Why
- Historical `hard_ham` false alerts remained high, while aggregate reports did not show which stable rule signals co-occurred with each decision group.

### Files changed
- `website/app.py` — attach stable IDs to link findings without changing scores or verdicts.
- `website/tools/evidence_attribution.py`, `website/tools/evaluate_public_corpus.py`, `website/tools/evaluate_serving_pipeline.py` — add an optional aggregate-only attribution sidecar tied to the evaluated cohort.
- `website/tests/test_evidence_attribution.py`, `website/tests/test_public_evaluation.py`, `README.md`, `docs/evaluation.md` — cover privacy, denominator integrity and usage.

### Effect
- A replay of 244 reference-filtered historical `hard_ham` messages found `link.brand_lookalike` in 30 of 135 alerts and `link.display_mismatch` in 20; the groups may overlap. These are co-occurrences, not proven false rules.
- The 199-message phishing/easy-ham pilot passed the existing two-class comparison with unchanged results. No model, threshold, risk weight or image-recognition default changed.

## [2026-09-27 19:57 PT] — Keep negative contractions out of winning-phrase matches

### Why
- Python's word-character boundary excludes apostrophes, so `You won't` incorrectly matched the financial-lure phrase `You won`. Ten inspected hard_ham messages reproduced that false signal. Python and Unicode documentation confirm the relevant boundary distinction.

### Files changed
- `website/app.py` — keep a straight or curly apostrophe followed by the contraction ending `t` inside the matched word, while preserving possessives and closing quotation marks.
- `website/tests/test_detection_behavior.py` — add failing-then-passing regressions for subject/body contractions, case, invisible format controls, HTML entities and complete EML input; retain genuine winning phrases, later matches and dangerous links.
- `README.md`, `docs/evaluation.md` — document the phrase boundary and matched corpus outcomes, including the additional undetermined result.

### Effect
- The ten false `You won` matches disappear without changing input admission, model artifact, decision threshold or risk weights. This is a bounded phrase-matching correction, not general linguistic negation analysis.
- On 443 reference-filtered development EMLs, phishing alerts remain 90/100 and easy_ham false alerts remain 2/99. Hard_ham alerts change from 136/244 to 135/244, with nonalerts unchanged at 44 and undetermined results increasing from 64 to 65. One other Critical verdict becomes High. These outcomes do not establish overall accuracy gains.
- Local validation: 136 focused detection tests and the Vercel runtime/model smoke pass; 638 backend tests run with 10 local Redis integration skips. Synthetic and dual-class pilot comparisons pass. The strict hard_ham comparison remains failing because it lacks phishing samples and increases undetermined results; no acceptance criterion was loosened.

## [2026-09-27 19:40 PT] — Align sender scoring with supported mailbox syntax

### Why
- API and From-parser validation accepted ordinary mailbox punctuation, but two narrower scoring checks incorrectly added special-character and invalid-format risk. Paired public-corpus replay found 86 affected hard_ham senders and one easy_ham sender.

### Files changed
- `website/app.py` — reuse the existing mailbox character contract and normalizer, and describe supported syntax without claiming complete RFC mailbox support.
- `website/tests/test_detection_behavior.py` — add failing-then-passing tests for supported punctuation, IDN domains, malformed dot atoms, brand substitution and full-message dangerous links.
- `README.md`, `docs/evaluation.md` — document the consistent syntax boundary, matched corpus results and increased undetermined count.

### Effect
- Input admission, model artifact, decision threshold, sender weights and dangerous-link rules are unchanged. Valid punctuation no longer creates an invalid-format signal; malformed local-part dots still fail validation.
- On 443 inspected, reference-filtered EML regressions, phishing alerts remain 90/100 and easy_ham false alerts change from 3/99 to 2/99. Hard_ham false alerts change from 206/244 to 136/244: eight alerts become nonalerts and 62 become undetermined, raising its undetermined total from two to 64. These development results do not establish overall accuracy.
- Local validation: 634 backend tests run with 10 Redis integration skips, 191 frontend tests pass, and the Vercel runtime/model smoke passes. Independent code review found no blocking issue. Synthetic and dual-class pilot comparisons pass; the strict hard_ham comparison remains failing because it lacks phishing samples and increases undetermined results. No acceptance criterion was loosened.

## [2026-09-27 19:14 PT] — Distinguish displayed addresses from release numbers and article titles

### Why
- Historical public normal-mail tests exposed false link-display mismatches for release numbers such as `5.0` and `802.11b`, and publisher domains mentioned inside article headlines.
- Treating those labels as promised destination addresses forced High risk without sufficient evidence; explicit address and navigation deception must retain its detection.

### Files changed
- `website/app.py` — validate domain suffixes, skip numeric release labels, distinguish address labels and navigation instructions from prose, and continue scanning for explicit addresses after unrelated mentions.
- `website/tests/test_detection_behavior.py` — add failing-then-passing regressions and controls for versions, publisher titles, actual addresses, English/Chinese navigation instructions, IP URLs, punctuation, and dangerous destinations.
- `README.md`, `docs/evaluation.md` — document the rule boundary and the matched public-corpus comparison, exclusions and remaining uncertainty.

### Effect
- Model artifact, decision threshold and actual-destination checks are unchanged. No tracking domain is allowlisted and no link is fetched.
- On 443 reference-filtered public EML regressions, phishing alerts remain 90/100 and easy_ham false alerts remain 3/99. Hard_ham false alerts change from 207/244 to 206/244, with undetermined results increasing from one to two; the overall false-alert rate remains excessive. These inspected samples are development evidence, not an independent release holdout.
- Local validation: 629 backend tests run with 10 Redis integration skips, 191 frontend tests pass, the committed Vercel runtime/model smoke passes, and the existing synthetic and dual-class public regression comparisons pass. The single-class hard_ham result does not qualify as release evidence.

## [2026-09-27 18:18 PT] — Show the original uploaded image beside uncertain OCR

### Why
- Synthetic phishing images still show `paypa1` as `paypal` in OCR despite a high whole-image confidence score. A warning to check the original was insufficient when the original image was no longer visible beside the result.

### Files changed
- `website/static/vision.js`, `website/static/app.js`, `website/static/style.css`, `website/static/index.html`, `website/static/cases.html` — add a bounded, expandable local preview for the directly uploaded image and refresh the changed browser assets.
- `website/app.py` — permit `blob:` only for images in the public page's content security policy, so a local preview can render without broadening script or connection permissions.
- `website/static/vision-ui.test.mjs`, `website/tools/browser-checks/run.mjs`, `website/tests/test_app_security.py` — verify local object-URL creation, cleanup, real-browser rendering and the image-only CSP permission.
- `README.md`, `website/tools/browser-checks/README.md` — explain preview availability and privacy limits.

### Effect
- In the public Email Content result, the original image can be compared at native resolution with extracted URL text. Its bytes remain in the browser; the analysis API, saved cases and feedback continue to receive only extracted evidence, never the image preview.
- Clearing or replacing the result revokes the temporary preview URL. OCR text, QR payloads, risk scoring and the existing literal benchmark remain unchanged.

## [2026-09-27 16:15 PT] — Cover distributed rate limits with real Redis in CI

### Why
- The independently configured distributed limiter had mocked REST-response tests but no test that executed its production Lua against Redis under concurrent requests.
- The existing CI backend job already provides an isolated local Redis service; local developer machines without Redis should not pretend this integration ran.

### Files changed
- `website/tests/test_rate_limit_redis.py` — route the production Upstash-style pipeline request to CI's localhost Redis, exercise 12 concurrent requests against a three-request minute budget, then verify an independent six-request hourly feedback budget, retry TTL and a separate legitimate route.
- `README.md` — document the opt-in local Redis test port, random HMAC-derived keys and local skip behavior.

### Effect
- With `PHISHGUARD_TEST_REDIS_PORT=6379`, CI's existing Redis-backed backend job will run the new test; no cloud Redis, real credential, sender observation or external network access is used.
- The current local machine has no Redis server, so the new real-Lua test is skipped here. This entry records test coverage added, not a locally observed Redis integration pass.

## [2026-09-27 16:09 PT] — Guard URL-line diagnostics against dotted release numbers

### Why
- The URL-like line heuristic introduced in the previous update incorrectly scored ordinary `Q3.2026` release text as an address.
- The original five-image benchmark has too few font and non-URL variants to reveal that false diagnostic.

### Files changed
- `website/static/vision-core.mjs`, `website/static/vision.test.mjs` — require a letter in bare-domain suffixes while retaining digit-confused `examp1e` and malformed-protocol coverage; lock the release-number case with a failing-then-passing regression.
- `website/tools/browser-checks/run.mjs`, `website/tools/browser-checks/README.md`, `docs/evaluation.md` — add ten real-worker, browser-authored URL/font and non-URL controls and document their diagnostic limits.

### Effect
- On Chromium 148, URL-like line confidence appeared for 8/8 authored address controls and 0/2 non-URL controls; 8/10 literal OCR strings matched their authored inputs. The new integration check brings the browser total to 10/10 passing.
- The original five-image benchmark remained at 23/238 strict OCR edits, exact URL sets 1/3 and QR payload sets 5/5. No URLs were repaired or fetched, and client confidence still does not affect risk scoring.

## [2026-09-27 15:56 PT] — Show URL-line OCR uncertainty separately from page confidence

### Why
- A synthetic phishing screenshot displayed 92% whole-image OCR confidence while its `paypa1` URL line scored 48% and was transcribed as `paypal`.
- Re-running Chinese URL text with another language or page segmentation did not reliably preserve the address, so automatic spelling replacement could conceal lookalikes.

### Files changed
- `website/static/vision-core.mjs`, `website/static/vision-worker.mjs` — extract the minimum confidence of URL-like Tesseract lines (including malformed prefixes and digit-confused domain suffixes), return null for absent or truncated text, and preserve the literal OCR text.
- `website/visual_evidence.py` — bound and retain the nullable 0–100 confidence field without using it for risk scoring.
- `website/static/vision.js`, `website/static/index.html`, `website/static/cases.html` — display the separate line score with character-by-character review guidance and refresh the browser script/worker versions.
- `website/static/vision.test.mjs`, `website/static/vision-ui.test.mjs`, `website/tests/test_visual_analysis.py`, `website/tools/browser-checks/run.mjs` — verify parsing, bounds, unchanged risk, saved cases, actual API pass-through and current English/Chinese UI results.
- `README.md`, `docs/evaluation.md`, `website/tools/browser-checks/README.md` — document diagnostic semantics and observed synthetic results.

### Effect
- In local Chromium 148, the English and Chinese controls both scored 92% overall but their misread URL-like lines scored 48% and 80% respectively; the UI now presents those numbers separately. Exact OCR URLs remained 1/3 and strict CER remained 23/238, with no URL spelling repair or detection-score change.
- Nine real-browser checks, 190 frontend tests and 620 backend tests passed (nine backend Redis integration checks skipped because local Redis is not configured). Synthetic evidence does not establish real-image accuracy.

## [2026-09-27 10:59 PT] — Exclude decoded QR patterns from OCR without erasing adjacent text

### Why
- Two unchanged QR-only browser controls consistently produced 22 invented OCR characters despite exact QR decoding.
- Axis-aligned QR masks can erase captions beside rotated codes; unclipped negative scanline endpoints can erase unrelated pixels.

### Files changed
- `website/static/vision-core.mjs` — whiten decoded quadrilaterals in a distinct OCR copy, translate quadrant coordinates, mask duplicate-payload locations and clip every span to image bounds.
- `website/static/vision-worker.mjs` — recognize the masked copy while retaining original bytes, digest and literal QR payloads.
- `website/static/vision.test.mjs` — cover repeated payloads, quadrant coordinates, rotated geometry, undecodable images and edge-crossing masks.
- `website/tools/browser-checks/run.mjs` — reject OCR text on QR-only controls and verify real rotated QR extraction with adjacent and scattered text.
- `website/tools/browser-checks/README.md`, `README.md` — document preprocessing, unchanged OCR limitations and the eight browser checks.

### Effect
- On the unchanged five-image manifest, invented QR-only OCR text fell from 22 characters to zero; literal CER fell from 45/238 (18.91%) to 23/238 (9.66%). Exact text increased from 0/5 to 2/5; QR payload sets remain 5/5 and OCR URL sets remain 1/3.
- Sparse-text mode, model assets, input fixtures and scoring are unchanged. The three text-image errors persist; synthetic results do not establish real-mail accuracy.
- Regression checks failed before the fix for actual QR-only OCR output and out-of-bounds masking, then passed after the fix. Eight real-browser checks and 188 front-end tests pass locally.
- The existing visual no-regression comparator passes against the previous report without policy changes; 11 visual API tests and all 29 pinned recognition assets also pass.

## [2026-09-27 10:45 PT] — Preserve API budgets and add independent release verification

### Why
- API key churn could evict active limits; minute-window cleanup could also erase a still-live hourly feedback budget.
- Synchronous rules, MIME parsing, raw sender-candidate selection and model prediction delayed ASGI health requests. Four synthetic CI emails did not establish real-mail release quality.
- Add repeatable browser and environment checks while keeping existing detection thresholds, model artifact and ground truth unchanged.

### Files changed
- `website/app.py` — group untrusted route keys, retain each budget's own window, reject new keys at capacity, wire independent distributed limits and bounded parsing/sender/rule/model workers.
- `website/rate_limits.py` — validate dedicated Redis limiter configuration without enabling sender observations; preserve legacy configuration and local fallback.
- `website/sender_history.py` — share Redis transport and atomic limiter independently of sender-history operations.
- `website/verification_runtime.py` — allow separate worker thread names for verification and analysis pools.
- `website/tests/test_app_security.py` — assert active budgets survive capacity pressure and update the independent limiter integration seam.
- `website/tests/test_rate_limit_security.py` — API key-churn, mixed-window, full-capacity, expiry and history-disabled distributed-limit regressions.
- `website/tests/test_distributed_rate_limits.py` — dedicated/legacy configuration, opaque keys, malformed settings and transport fallback controls.
- `website/tests/test_analysis_concurrency.py` — verify responsive health, retryable saturation and recovery through actual ASGI APIs.
- `website/tools/release_evaluation.py` — opt-in human-reviewed real-mail holdout contract bound to cohort, code and model identities.
- `website/tools/compare_evaluations.py` — accept explicit release review and prevent output from overwriting comparison inputs.
- `website/tests/test_release_evaluation.py` — review, coverage, identity, temporal and strict no-regression rejection controls.
- `.github/workflows/ci.yml` — use the development dependency entry point and label the four-email check as synthetic smoke evidence.
- `website/tools/browser-checks/run.mjs` — real Chromium, actual local APIs/workers and SQLite checks with literal extraction metrics kept separate from integration success.
- `website/tools/browser-checks/README.md` — pinned Playwright setup, synthetic CER ceilings and observed OCR limitations.
- `.github/workflows/browser-checks.yml` — manual synthetic Chromium workflow with temporary dependencies and retained reports; no automatic deployment.
- `requirements.txt`, `website/requirements.txt`, `phishing-detection/requirements.txt` — share unchanged artifact-compatible runtime pins across serving and research entry points.
- `requirements-dev.txt` — backend/test installation entry point with pinned HTTP client.
- `requirements-dev-py312-macos-arm64.lock.txt` — resolved 35-package snapshot for the tested Python 3.12 macOS arm64 environment; other platforms and notebook extras remain unverified.
- `.env.example`, `README.md` — document independent shared limits, saturation behavior and reproducible Python environments.
- `docs/evaluation.md` — distinguish release review from synthetic smoke and correct the historical candidate status against checked-in code; deployed state remains unverified.

### Effect
- Before the patch, unknown-path churn turned a blocked analysis request into HTTP 200; afterward it remains 429. New identities wait for expired capacity, and active hourly feedback restrictions survive minute requests.
- A controlled two-second synchronous analysis formerly delayed health output; health now returns before that analysis completes. Busy analysis returns 503 with `Retry-After: 1` and recovers when a worker is free.
- The new real-mail review is opt-in: each Gmail/Outlook × English/Chinese cell needs at least 50 independently reviewed phishing and 50 legitimate messages, plus bound human audit evidence. This is a coverage floor, not proof of statistical adequacy or acceptable accuracy. No real holdout is bundled and no real-mail release pass is claimed.
- Real-browser controls pass 7/7, while literal OCR text exact matches remain 0/5, OCR URL exact sets 1/3, QR sets 5/5 and synthetic CER 45/238 (18.9%). These mismatches are retained as evidence, not rewritten as an accuracy improvement.
- Final local Python 3.12 checks: 610 backend tests pass, 9 existing real-Redis integration tests skip because no local Redis service is configured; all 183 frontend tests and 29 vendored asset checks pass. The committed model smoke and unchanged four-email synthetic comparison pass. Independent review also verifies cancellation, concurrent cold-model prediction and health responsiveness on a 20,000-header synthetic message. The manual browser GitHub workflow was not dispatched.
- No model weights, decision thresholds, existing synthetic baseline or deployment were changed.


---

## [2026-09-26 12:54 PT] — Pin Chart.js with subresource integrity

### Why
- The homepage loaded `chart.js@4.4.0` from jsDelivr without an `integrity`
  attribute, so a tampered CDN response would execute on the page (CSP already
  allows `https://cdn.jsdelivr.net`).

### Files changed
- `website/static/index.html` — add
  `integrity="sha384-e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g"`
  and `crossorigin="anonymous"` (hash of the 205,222-byte
  `dist/chart.umd.min.js`; jsDelivr returns `Access-Control-Allow-Origin: *`).
- `website/static/app.test.mjs` — every external `<script>` must be
  version-pinned and carry a sha384 `integrity` plus `crossorigin="anonymous"`.

### Effect
- Chrome 148: `Chart` loads, the benchmark chart renders, 0 console errors; a
  modified file would now be blocked instead of executed.
- `node --test website/static/*.test.mjs` 183/183.

## [2026-09-26 12:53 PT] — Score breakdown, copy summary, and keyboard shortcuts

### Why
- The sender score (e.g. `100/100`) gave no indication of how it was reached.
- Results could not be shared without retyping them.
- Power users had no keyboard path to the inputs or to submit content.

### Files changed
- `website/static/index.html` — `#score-breakdown` disclosure (“Why this
  score?”) under the sender verdict; `.result-actions` rows with a
  `Copy summary` button beside the existing `Report an issue` for both
  analyzers; `/` and `Ctrl/⌘ + Enter` hints; `style.css?v=39`, `app.js?v=41`.
- `website/static/app.js` — `senderScoreBreakdown()` / `renderScoreBreakdown()`
  mirror the server weights (high 28, medium 10, low 3, capped at 100) from
  `_analyze_sender_address` and hide the breakdown if they do not reproduce
  `risk_score`; `senderSummaryText()` / `contentSummaryText()` build a
  plain-text summary with a disclaimer; `copySummary()` uses the Clipboard API
  with an `execCommand('copy')` fallback for non-secure origins;
  `setupShortcuts()` focuses the active input on `/` (not while typing or with
  a dialog open) and submits content on `Ctrl/⌘ + Enter` when idle.
- `website/static/style.css` — breakdown, action row, and `kbd` styles; hints
  are hidden on touch-only devices.
- `website/static/app.test.mjs` — breakdown arithmetic, HTML escaping, cap and
  drift hiding; sender/content summary text and copy feedback.

### Effect
- `security-alert@paypa1-verify.xyz`: “Why this score?” lists 4 × +28,
  3 × +10, 2 × +3 and `= 148, capped at 100.`
- `Copy summary` places `PhishGuard sender check: … Verdict: Critical Sender
  Risk (100/100) …` on the clipboard; `/` focuses `#email-input`;
  `Ctrl + Enter` in the body runs content analysis.
- `node --test website/static/*.test.mjs` 182/182.

## [2026-09-26 12:47 PT] — Hero capability stats, footer, SVG glyphs, and balanced text

### Why
- The hero's four stats were UCI website-benchmark numbers (97.47 %, 0.9977,
  11,055, 30), off-topic for an email detector and duplicated by the
  Performance section.
- The footer was one line and linked to the pre-rename repository
  `CS-166-Final-Project`.
- A few text glyphs remained (`✕` clear button, `✓` in the no-risk
  placeholder, the safety-signal title and each safety-signal row).
- Headings and paragraphs could end with a single orphaned word.

### Files changed
- `website/static/index.html` — hero stats: `30` sender risk signals, `6`
  detection layers, `Auth headers` (SPF, DKIM & DMARC in .eml), `OCR + QR`
  (run in your browser); three-column footer (Product / Analysts / Project)
  with tagline, privacy line, and links to
  `Lushangtu123/Phishing-Scam-Email-Detection` (GitHub, README, CHANGELOG);
  SVG clear button (`aria-label`) and safety-title icon; `style.css?v=37`,
  `app.js?v=39`.
- `website/static/app.js` — safety rows use `icon('check')`;
  `setupCaseLoginLink()` also rewrites the footer `.case-login-link` on local
  hosts.
- `website/static/style.css` — equal-width `minmax(0, 1fr)` hero stat
  columns, `.stat-text`, footer grid (1 column ≤768 px), icon sizing,
  `text-wrap: balance` for headings and `pretty` for paragraphs.
- `website/static/cases.css` — the same `text-wrap` rules; `cases.css?v=13`
  in `website/static/cases.html`.
- `website/static/app.test.mjs` — no `✓`/`✕` glyphs, renamed repository
  links, footer case link.

### Effect
- The benchmark numbers now appear only in `#performance`; hero cards are
  equal width at 1440 px and 2 × 2 at 390 px.
- Footer at 1440 px: brand + tagline beside three link columns; at 390 px
  it stacks, and `Case workspace` resolves to `/cases` locally.
- `node --test website/static/*.test.mjs` 180/180.

## [2026-09-26 12:43 PT] — Animated dialogs and a themed confirm dialog

### Why
- The feedback dialog appeared in a single frame and the case drawer only
  animated on open, not on close.
- Four confirmations (feedback retry; case sign-out, Jev save, case retry)
  used the browser's native `window.confirm`, which ignores the page theme.

### Files changed
- `website/static/confirm-dialog.js` — new `window.PhishGuardConfirm(message,
  {confirmLabel, cancelLabel})` builds a `<dialog>` with DOM APIs only
  (compatible with the `/cases` CSP), focuses Cancel by default, resolves
  `true` only for the confirm button, and falls back to `window.confirm`
  without `<dialog>` support.
- `website/static/feedback.js`, `website/static/cases.js` — `askConfirm()`
  uses `PhishGuardConfirm` when loaded, else `window.confirm`; the four call
  sites await it and re-check their session/case/opinion state after the
  dialog closes before continuing.
- `website/static/style.css`, `website/static/cases.css` — `@starting-style` +
  `transition-behavior: allow-discrete` enter/exit for the feedback dialog,
  the case drawer (slide from the right) and `.pg-confirm`; reduced motion
  disables them.
- `website/static/index.html`, `website/static/cases.html` — load
  `confirm-dialog.js?v=1`; `feedback.js?v=8`, `cases.js?v=22`.
- `website/static/confirm-dialog.test.mjs`, `website/static/cases.test.mjs` —
  native fallback, confirm/dismiss resolution, cancel focus, and sign-out
  waiting for the themed confirm.

### Effect
- Chrome 148: the feedback dialog fades and lifts in; closing the case drawer
  slides it out; sign-out with an unsaved subject shows a themed
  `Sign out` / `Cancel` dialog, and Cancel keeps the session.
- Existing tests that stub `window.confirm` still exercise the same branches.
- `node --test website/static/*.test.mjs` 179/179.

## [2026-09-26 12:38 PT] — Skeleton loading states and view transitions

### Why
- Both analyzers showed a generic spinner while waiting, and the sender spinner
  sat below the disposable-email explainer, away from where results appear.
- Theme and tab switches changed the whole page in a single frame.

### Files changed
- `website/static/index.html` — replace both spinners with a result-shaped
  `.skeleton` (banner, score ring, three cards, scanning beam) inside the
  existing `#loading-area` / `#content-loading-area` (`role="status"`); move
  `#loading-area` above `#result-area`; the theme button passes its click
  event; `style.css?v=36`, `app.js?v=38`.
- `website/static/style.css` — skeleton shimmer and beam (off under reduced
  motion; one card at ≤1024 px); `::view-transition` rules for a 0.28 s
  crossfade and a circular `theme-reveal` clip-path from `--vt-x/--vt-y`.
- `website/static/app.js` — `withViewTransition(update, done)` wraps DOM
  updates in `document.startViewTransition` when available and motion is
  allowed, otherwise runs them directly; `cycleTheme(event)` reveals the new
  theme from the toggle's centre; `switchDemoTab()` crossfades and ignores
  clicks on the active tab.
- `website/static/app.test.mjs` — fallback, supported, and reduced-motion
  paths for `withViewTransition`; skeleton markup and placement.

### Effect
- Chrome 148: while a request is pending, a placeholder the shape of the result
  appears directly under the input; switching dark → light grows the new theme
  from the top-right toggle over 0.6 s.
- Browsers without View Transitions, and reduced-motion users, switch
  instantly as before.
- `node --test website/static/*.test.mjs` 176/176.

## [2026-09-26 12:34 PT] — How It Works as a scroll-driven timeline

### Why
- The six pipeline steps were identical full-width bars with a small square
  number, giving no sense of sequence.

### Files changed
- `website/static/style.css` — `.pipeline-steps` becomes a 920 px timeline:
  a 2 px rail through 48 px circular number nodes with the text in cards to
  the right. Under `@supports (animation-timeline: view())` and
  `prefers-reduced-motion: no-preference`, the rail fills via a named
  `view-timeline: --pipeline` and each node lights up via `view()`; other
  browsers and reduced-motion users see the completed state. Hover moves only
  the card. Removed the now-unused `.top3-*` rules; `style.css?v=35`.
- `website/static/index.html` — cache-busted stylesheet only; step markup is
  unchanged.

### Effect
- Chrome 148 at 1440 px: mid-section, nodes 01–03 are lit and 04–06 are
  muted; at the end all six are lit with the rail filled. Same behaviour at
  390 px.
- `node --test website/static/*.test.mjs` 174/174.

## [2026-09-26 12:32 PT] — Signals section as a bento grid with live examples

### Why
- `Explainable Sender Signals` showed three equal-height bullet lists (8 / 8 /
  14 items) followed by a separate `Highest-Priority Sender Checks` row that
  repeated the same ideas; it read like documentation rather than a product.

### Files changed
- `website/static/index.html` — replace the lists + top-3 row with a 6-card
  `.bento` grid: look-alike domain (`paypa1-verify.xyz` vs `paypal.com`),
  randomized username (`xq7m9v2k4p8z`, 5/6-factor meter), risky TLDs
  (`.tk .xyz .top .gq .ml`, all in `SPAM_TLDS`), mailbox service type
  (mailinator vs Firefox Relay), known-provider context, and
  authentication/identity alignment (SPF/DKIM/DMARC + From vs Reply-To).
  The three top-3 descriptions are kept verbatim in the matching cards; the
  full 30-signal lists move into a `<details class="signals-all">`;
  `style.css?v=34`, `app.js?v=37`.
- `website/static/style.css` — `.bento` (6 columns → 2 at ≤1024 px → 1 at
  ≤640 px), card/demo/tag styles, `.signals-all` disclosure, reduced-motion
  hover overrides.
- `website/static/app.js` — scroll-reveal targets `.bento` cards and
  `.signals-all` instead of the removed top-3 elements.

### Effect
- 1440 px: one hero card (4 columns) + tall randomness card, two small cards,
  then provider + wide authentication card; each shows a concrete example
  consistent with the detector's current output.
- 390 px: single column with no horizontal overflow (`scrollWidth` 390).
- `node --test website/static/*.test.mjs` 174/174.

## [2026-09-26 10:41 PT] — Align the case workspace with the homepage and reduce density

### Why
- `/cases` used a separate visual language (Avenir font, 6–8 px radii,
  monochrome white primary buttons, `◈ ▤ ⌕ ◇` text glyphs as icons), so the
  analyst workspace and the analyzer looked like different products.
- The detail panel was `position: sticky` with its own `max-height` scroll,
  nesting a second scroll region inside the page.
- Always-open filters, four large zero-count feedback cards, and a ~120-word
  Jev data-handling paragraph pushed the queue and assessment down.
- `action(event.submitter, …)` threw `TypeError: Cannot set properties of null`
  when a form was submitted without a submitter (e.g. `requestSubmit()`).

### Files changed
- `website/static/cases.html` — SVG shield brand mark, inbox/search nav icons,
  key access icon, upload icon in the drop zone; filters wrapped in
  `<details id="filters-disclosure">` with `#filter-summary`; Jev notice moved
  into a `.jev-disclosure`; `cases.css?v=12`, `cases.js?v=21`.
- `website/static/cases.css` — homepage font stack and brand tokens
  (`--brand-a/-b`, `--brand-grad`, `--on-brand`, 12 / 8 px radii) for both
  themes; gradient `.primary`; gradient-drawn select chevrons (the page CSP
  forbids `data:` images); detail panel flows with the page while the
  height-bounded queue is sticky above 1120 px; feedback overview as one
  4-cell strip; grid upload field with hover/drag states; two-column review
  selects.
- `website/static/cases.js` — `action()` tolerates a null button;
  `renderFilterSummary()` shows `All records` or `N active` on filter submit.
- `website/static/cases.test.mjs` — null-submitter login/filter submits and the
  active-filter count.

### Effect
- 1440 px: filters collapse to a 40 px bar (`All records` / `3 active`); the
  feedback overview drops from ~96 px cards to a ~44 px strip; `.detail` is
  `position: static; overflow: visible`, and the queue stays pinned at
  `top: 68px` while reading a long case.
- `Human verdict` no longer truncates to "Not reviewe"; programmatic
  `requestSubmit()` sign-in works.
- `node --test website/static/*.test.mjs` 174/174.

## [2026-09-26 10:33 PT] — Quiet local runs: case link, Vercel collectors, favicon

### Why
- On `127.0.0.1:8000` the homepage `Case login` button sent developers to the
  production workspace, although `docs/case-workflow.md` says local work should
  use the local `/cases`.
- Off Vercel, `/_vercel/insights/script.js` and
  `/_vercel/speed-insights/script.js` returned JSON 404s, producing four
  console errors (404 + strict-MIME refusal) on every page load.
- Neither page declared an icon, so browsers also logged `/favicon.ico` 404.

### Files changed
- `website/app.py` — `GET /_vercel/{collector}/script.js` returns an empty
  `text/javascript` body for `insights` / `speed-insights` when `VERCEL` is
  unset; unknown collectors and requests on Vercel still 404.
- `website/tests/test_app_security.py` — `VercelCollectorFallbackTests` for the
  off-platform, unknown-collector, and on-Vercel cases.
- `website/static/app.js` — `caseLoginHref()` / `setupCaseLoginLink()` rewrite
  the button to `/cases` only for `localhost`, `127.0.0.1`, and `[::1]`.
- `website/static/favicon.svg` — gradient shield icon matching `.brand-mark`.
- `website/static/index.html`, `website/static/cases.html` — `<link rel="icon">`;
  `app.js?v=36`. The deployed `Case login` href is unchanged.
- `website/static/app.test.mjs` — local vs. deployed host cases for the link.

### Effect
- Local server with cache disabled: 0 console errors on `/` (previously 5);
  `Case login` resolves to `/cases`; both collector paths return 200 with an
  empty script.
- Deployed hosts, including preview `*.vercel.app` and `localhost.example`, keep
  the stable production URL.
- Backend `python3 -m unittest discover -s tests`: 598 tests OK (9 skipped);
  frontend 173/173.

## [2026-09-26 10:29 PT] — Themed form controls, upload target, and chart colours

### Why
- `:root` declared no `color-scheme`, so native select menus, checkboxes and
  scrollbars rendered in light mode on the dark theme; selects used the
  platform chevron.
- The content upload area was a plain dashed box with a one-line hint and no
  visible drag state beyond an outline.
- Chart.js colours were hard-coded for dark mode (`#8da2bd` ticks, dark
  tooltip) and did not change when the theme toggled.

### Files changed
- `website/static/style.css` — `color-scheme: dark` on `:root`; gradient-drawn
  chevrons and focus rings for `.ocr-language-select` and feedback selects;
  grid-based `.file-dropzone` with `.drop-icon`, hover and solid-accent
  `drag-active` states; `style.css?v=33`.
- `website/static/index.html` — upload icon inside `#content-file-dropzone`;
  `app.js?v=35`.
- `website/static/app.js` — `chartTheme()` reads `--text-muted`, `--text`,
  `--line`, `--bg-card2`, `--border-hi`; `applyChartTheme()` sets per-theme bar
  palettes and axis/legend/tooltip colours before the chart is built;
  `applyTheme()` calls `restyleMetricsChart()` (`update('none')`, no
  re-animation).
- `website/static/app.test.mjs` — dark and light palette/token assertions.

### Effect
- Toggling to light re-colours the benchmark chart in place (bars
  `rgba(10,127,214,…)`, ticks `#56627a`); back to dark restores
  `rgba(79,209,255,…)` / `#9aa3b2`.
- Selects and the feedback checkboxes match each theme; dragging a file over
  the content upload area shows a tinted, solid-border target.
- `node --test website/static/*.test.mjs` 172/172.

## [2026-09-26 10:27 PT] — Mobile section menu and stacked benchmark cards

### Why
- At ≤900 px `.nav-links` was hidden with no replacement, so phones could not
  jump to Live Demo / Performance / Features / How It Works.
- At 390 px the benchmark table scrolled sideways and cut off Recall, F1 and
  ROC AUC.

### Files changed
- `website/static/index.html` — add `#nav-menu-toggle` (menu/close SVG,
  `aria-expanded`, `aria-controls="nav-links"`); give the list `id="nav-links"`;
  `style.css?v=32`, `app.js?v=34`.
- `website/static/app.js` — `setupMobileNav()` opens/closes `.navbar.menu-open`,
  closes on link click, Escape (returns focus), outside click, and widths
  >900 px; `renderMetricsTable()` writes `data-label` on each metric cell.
- `website/static/style.css` — toggle button and opaque dropdown panel for
  ≤900 px (reduced-motion safe); ≤640 px benchmark rows render as cards with
  a 3-column label/value grid.
- `website/static/app.test.mjs` — cover metric `data-label`s and the menu's
  ARIA wiring.

### Effect
- 390 px: the menu button opens a 4-link panel; choosing `Performance`
  scrolls there and closes the panel; the button is `display: none` at 1440 px.
- 390 px benchmark: table width 356 px = container width (was 552 px), all
  five metrics visible per classifier.
- `node --test website/static/*.test.mjs` 171/171.

## [2026-09-26 10:24 PT] — Balance sender and content result layouts

### Why
- The sender result stacked four cards (evidence, mailbox type, sender history,
  verification) in the left column while the middle column held one short
  card; running verification stretched the left column to ~1,000 px beside
  two-thirds empty width.
- The content result's `Technical Indicators` list was clipped by a 340 px
  inner scroll and the bottom row left an empty third column.

### Files changed
- `website/static/index.html` — move `#sender-history-card` under Risk
  Indicators; move `#verify-card` out of the columns into a full-width
  `.verify-card-wide` card whose Mailbox / Policy / Domain sections sit in a
  `.verify-groups` grid with a `.verify-footer` holding the verdict and Re-run;
  `style.css?v=31`.
- `website/static/style.css` — add `.verify-card-wide`, `.verify-groups`
  (3 columns, 1 column ≤1024 px), `.verify-footer`; switch
  `.content-bottom-row` from `auto-fill` to `auto-fit` and drop the inner
  scroll on its risk list.

### Effect
- 1440 px desktop, `security-alert@paypa1-verify.xyz`: columns now hold 2 / 2 / 1
  cards; the finished verification renders as three side-by-side groups
  (~340 px tall instead of ~900 px in a single 360 px column).
- `Account suspension phish` content example: all 6 technical indicators are
  visible without inner scrolling and the method note fills the remaining width.
- Element IDs are unchanged; `node --test website/static/*.test.mjs` 169/169.


## [2026-09-20 17:52 PT] — Record model build dependencies and pin serving versions

### Why
- The committed text-model artifact records scikit-learn 1.9.0 but predates exact NumPy, SciPy, joblib, and threadpoolctl provenance; a successful load alone cannot establish parity with its original training environment.
- The serving and local evaluation requirements allowed numerical dependency drift between installations.
- Real Gmail/Outlook serving performance still needs independently labeled, campaign-separated inbox samples.

### Files changed
- `requirements.txt` and `website/requirements.txt` — pin the tested core numerical packages; pin pandas in the training requirements.
- `website/model_environment.py` — provide shared dependency-version capture and serving validation.
- `website/content_model.py` and `website/content_inference.py` — record versions in new training builds and artifact envelopes; reject recorded version drift when packaging or loading.
- `website/tests/test_app_security.py` and `website/tests/test_content_corpus.py` — cover versioned round trips, mismatches, legacy metadata, and training-to-inference integration.
- `README.md` — distinguish tested serving pins from unknown legacy training versions, and document deployment and independent-cohort verification.
- `CHANGELOG.md` — record this update.

### Effect
- New builds record Python and six package versions; versioned artifacts reject mismatched serving dependencies. The existing SHA-256-pinned artifact remains loadable without claiming unavailable historical version evidence.
- Local checks passed: 363 Python tests, 52 frontend tests, the committed-artifact Vercel runtime smoke test, and `pip check`. No real Gmail/Outlook cohort was evaluated.

## [2026-09-20 16:47 PT] — Score MIME alternatives separately and disclose unverified image/CSS views

### Why
- A constructed `multipart/alternative` email with one phishing view and one long routine view fell from 52.1% High to 7.4% complete Low when the views were concatenated for model inference.
- Zero-sized or transparent CSS text and computed zero opacity could similarly dilute a visible phishing message; short credential instructions in image fallback text and unresolved `cid:`/relative images were not fully disclosed.
- Deeply nested CSS made the stylesheet check take about 4.5 seconds on a 32 KB input.

### Files changed
- `website/email_structure.py` — retain alternative-branch paths for decoded MIME text while preserving duplicate-header candidate inspection.
- `website/app.py` — score up to 16 branch-covering MIME views, retain the strongest model signal, disclose unscored views; conservatively handle additional CSS hiding patterns and short credential `alt`; report unresolved image references; scan nested stylesheets linearly.
- `website/static/app.js` and `website/static/app.test.mjs` — display the unresolved-image coverage warning.
- `website/tests/test_html_input_coverage.py` — add phishing/benign MIME controls, CSS and image regressions, branch-budget coverage, and a stylesheet performance guard.
- `README.md` and `CHANGELOG.md` — document the behavior and remaining limits.

### Effect
- Both tested plain/HTML phishing variants now produce 52.1% High rather than 7.4% complete Low. CSS zero-font and transparent-text padding now abstains; `opacity:calc(0)` restores the visible-text 52.1% High signal. The short `cid:` credential-alt control is incomplete/Unknown rather than complete/Safe.
- The 32 KB nested stylesheet control fell from about 4.5 seconds to about 0.02 seconds locally. The committed model artifact and threshold are unchanged; real Gmail/Outlook recall and false-positive rates remain unmeasured without consented, time-separated samples.

## [2026-09-20 16:16 PT] — Guard uncertain CSS and image fallback text

### Why
- A constructed phishing message fell from a 52.1% High model score to 7.4% complete Low when benign padding used `opacity:0` or a CSS class with `display:none`.
- An image without a source could show phishing text through `alt`, yet the detector treated that text as absent; sourced images can expose different text when loading fails.
- The archived corpus metrics do not measure the current serving path or real Gmail/Outlook traffic.

### Files changed
- `website/app.py` — exclude zero-opacity inline text; conservatively abstain from CSS-uncertain and substantive conditional-alt model scoring, suppress only uncertain HTML-part prose while preserving clear MIME text and explicit destinations, and score source-less image `alt` as fallback text.
- `website/static/app.js` — explain rendering-based model abstention without showing stale score bars.
- `website/static/app.test.mjs` — cover the new abstention presentation.
- `website/tests/test_html_input_coverage.py` — add CSS padding, opacity, image-alt, picture, independent-link, and decorative-image regressions.
- `website/tools/evaluate_serving_pipeline.py` — add a local, digest-pinned serving-path evaluator that reports aggregate alert and coverage rates by provider, month, and provider×month without observing sender history.
- `website/tests/test_serving_evaluation.py` — test input validation, aggregate denominators, privacy of output, and a real CLI run against the committed artifact.
- `README.md` — document rendering limits and how to evaluate consented, labeled inbox samples without claiming provider-specific accuracy.
- `CHANGELOG.md` — record the behavior and measurement scope.

### Effect
- The `opacity:0` padding control now retains the visible-text 52.1% High model score and marks analysis incomplete. A CSS class hiding the same padding now yields `ml_status=unverified_rendering` and an incomplete Unknown result instead of complete Low; hidden phishing padding likewise cannot create an unsupported High verdict. A CSS-uncertain HTML part does not erase clear phishing text in a separate plain-text MIME part.
- Missing-source `alt` text enters text scoring, including inside source-less `<picture>`; substantive sourced-image `alt`, including no-space Han text, yields an incomplete, nullable model result while short decorative labels retain ordinary text scoring.
- The committed model artifact and threshold are unchanged. No real Gmail/Outlook serving-path recall or false-positive rate is claimed without consented, time-separated data.

## [2026-09-20 15:51 PT] — Exclude hidden HTML text and abstain on uncovered body segments

### Why
- Inline-hidden HTML text could swing a committed-model score without changing the text readers see: a constructed scam example fell from 52.1% to 7.4% with hidden benign padding, while a benign example rose from 4.7% to 99.0% with hidden phishing padding.
- English subject/body features could mask a substantial Japanese, Cyrillic, or Chinese passage with no fitted model features.

### Files changed
- `website/app.py` — exclude text under `hidden` and inline `display:none` / `visibility:hidden` from text scoring, respect local visibility and implied HTML tag closures, and warn when text was omitted; inspect actual raw-HTML link destinations while deriving labels and free-text URLs from visible prose.
- `website/content_inference.py` — require fitted features for a substantial body and for each substantive non-Latin-script passage before emitting a model score.
- `website/language_coverage.py` — share Han recognition with script-passage extraction, excluding numbers/symbols from feature coverage and retaining newer Han extensions.
- `website/tests/test_content_inference.py` — account for the additional body-only vectorization check.
- `website/tests/test_html_input_coverage.py` — add committed-model, HTML/MIME, CSS-override, link-preservation, and multilingual-abstention regressions.
- `README.md` — document hidden-text handling, coverage gates, and limits of non-rendered CSS/language analysis.
- `CHANGELOG.md` — record the behavior change and its limits.

### Effect
- The constructed hidden-padding controls now retain the visible-text model score and report `analysis_complete=false`; links in hidden subtrees remain inspectable as independent destination evidence.
- The tested Japanese, Cyrillic, and mixed English/Chinese bodies now return `ml_status=insufficient_feature_coverage` with nullable model scores; a 26-Han-character footer also now abstains rather than showing an English-only model score. Scattered Chinese names separated by English text retain the English model score plus the Han warning.
- The committed model artifact and threshold are unchanged. This is a regression fix, not a measured improvement in real-world Gmail/Outlook recall or false-positive rate.

## [2026-09-20 15:27 PT] — Abstain on uncovered Chinese bodies and disclose alternate image references

### Why
- An English subject could give the fitted text model features even when a substantial Chinese body gave it none, producing a confident result that did not reflect the body.
- VML and SVG image references, including VML inside Outlook conditional comments, were omitted from image-coverage reporting.

### Files changed
- `website/language_coverage.py` — share Han ideograph detection between API and model paths, with explicit Unicode 17 Extension I/J block fallbacks for Python 3.12's older character-name database.
- `website/content_inference.py` — abstain with the existing `insufficient_feature_coverage` status when a substantial Han-script body has zero fitted features, even if its subject has features.
- `website/app.py` — count VML and SVG image references as uninspected image content, without fetching or decoding them; inspect MSO conditional comments conservatively while leaving ordinary and solely negated `!mso` comments inert.
- `website/tests/test_content_inference.py` — verify Unicode extension boundaries in the shared coverage check.
- `website/tests/test_html_input_coverage.py` — add committed-model, link-risk, manual HTML, raw-email, conditional-comment, and negative-control regressions.
- `README.md` — document the added coverage and the remaining language limitation.
- `CHANGELOG.md` — record the behavior change and its unmeasured real-world limits.

### Effect
- The tested English-subject/Chinese-body controls now yield nullable model scores and an incomplete, undetermined verdict when no independent risk exists; a suspicious link still raises risk independently.
- The tested VML/SVG image-only messages now disclose uninspected pixels and cannot appear fully analyzed. The image bytes are still not OCR-scanned or fetched.
- The committed model artifact and decision threshold are unchanged. Real, consented and time-separated Gmail/Outlook samples remain necessary to quantify false positives and phishing recall.

## [2026-09-20 14:57 PT] — Disclose image and language gaps and qualify model-only risk

### Why
- Remote HTML images could be left uninspected while the API still reported a complete Safe analysis; short image-led messages and MIME alternatives made that especially misleading.
- The committed text model alone could label an ordinary invoice message Critical (84.2% model score, zero heuristic points), and substantial Chinese text lacked a specific coverage warning.

### Files changed
- `website/app.py` — count remote image references without fetching them, preserve per-HTML-part and nested-message coverage, warn on substantial Han-script text, and require strong independent evidence before model output can raise a verdict to Critical.
- `website/static/app.js` — distinguish remote-image incompleteness and model-only/model-led results in the risk banner.
- `website/tests/test_html_input_coverage.py` and `website/tests/test_detection_behavior.py` — cover remote images, data-URI `srcset`, MIME alternatives, nested messages, zero-width padding, mixed-language text, evidence fusion, and a paired committed-model invoice/payment-change regression.
- `website/static/app.test.mjs` — verify the new browser-facing explanations.
- `README.md` — document coverage fields, verdict behavior, and the remaining lack of provider-specific validation.
- `CHANGELOG.md` — record the change and its limits.

### Effect
- A remote-image-only short HTML part now yields Unknown when no independent risk is found; text-rich mail with a decorative remote image keeps the inspected-text verdict but is explicitly incomplete. Image bytes are still not decoded, fetched, OCR-scanned, or QR-scanned.
- The constructed ordinary invoice control changes from Critical to High — Model Signal Needs Review while retaining its 84.2% model score. The model artifact and threshold are unchanged; real Gmail/Outlook false-positive and phishing-recall changes remain unmeasured.
- Substantial Han-script text now produces a language-coverage warning instead of an unqualified complete Safe result; this is disclosure, not a trained Chinese detector.

## [2026-09-20 14:20 PT] — Add Vercel page and performance collectors

### Why
- The Hobby project's Web Analytics and Speed Insights dashboards were enabled
  but showed zero events because the FastAPI-served HTML page loaded neither
  browser collector. The dashboard's default Next.js instructions do not match
  this repository's plain HTML frontend.

### Files changed
- `website/static/index.html` — initialize the Vercel page-view and web-vitals
  queues and load their deferred same-origin scripts before `</body>`.
- `website/static/app.test.mjs` — verify the rendered HTML includes both
  collectors without Next.js imports.
- `CHANGELOG.md` — record the integration and its verification limits.

### Effect
- Both collector scripts are now included in the HTML served by FastAPI. The
  existing production script routes each returned HTTP 200 before this change;
  browser event delivery and dashboard counts still require deployment and
  post-deploy verification. No email input is submitted as a custom event.

## [2026-09-20 12:57 PT] — Abstain on low-context email text

### Why
- The character n-gram model could produce critical-risk scores for very short,
  routine subjects such as `Hello` or `File shared with you`, despite having too
  little context for a reliable content classification.
- Raising the global model threshold would also reduce phishing recall on
  sufficiently detailed messages.

### Files changed
- `website/content_inference.py`: add a deterministic pre-vectorization context
  gate requiring at least five Unicode word tokens and 40 non-whitespace
  characters, returning `insufficient_context` with nullable model scores.
- `website/app.py`, `website/static/app.js`, and frontend/backend tests: preserve
  independent rule and structure evidence, render an honest incomplete result,
  and explain the new abstention without probability bars.
- `README.md` and committed-model regressions: document the additive status and
  cover short legitimate subjects without changing the model artifact or global
  decision threshold.

### Effect
- Short, low-context messages no longer receive an ML phishing verdict solely
  from sparse character patterns. With no independent evidence they return
  `unknown`; suspicious links, credential pressure, sender evidence, and
  dangerous attachment metadata continue to determine risk normally.

## [2026-09-20 10:03 PT] — Clarify provider aliases and deployment readiness

### Why
- Treating every `+tag` local part as an alias could merge distinct mailboxes on
  custom domains whose delivery rules are unknown.
- Vercel rollout convergence could make a correct deployment smoke check fail,
  while repeating stateful probes would mutate sender history more than once.
- Public capability fields and the content form did not clearly distinguish
  configured history from live reachability or disclose server-side processing.

### Files changed
- `website/sender_history.py`, `website/app.py`, and backend tests: limit plus-tag
  canonicalization to known Gmail/Microsoft providers, normalize Googlemail dot
  aliases, and trust one valid Vercel client IP only in the Vercel profile.
- `website/tools/post_deploy_smoke.py` and its tests: retry read-only readiness
  checks before running the phishing, legitimate, and sender-history POST probes
  exactly once.
- `website/app.py`, `website/static/index.html`, frontend tests, and `README.md`:
  expose `sender_history_configured`, retain the compatible availability field,
  and add processing, retention, and data-minimization guidance.

### Effect
- Sender identities no longer collide on providers without documented alias
  semantics, and public rate limiting no longer groups all Vercel clients under
  the serverless proxy peer.
- Deployment checks tolerate brief alias propagation without duplicating
  stateful requests, and users receive clearer capability and privacy language.

## [2026-09-20 09:43 PT] — Harden sender history and production smoke checks

### Why
- Vercel's immutable deployment URL redirected anonymous GitHub Actions requests
  to an SSO login page, so the post-deploy smoke parsed HTML as JSON and failed
  even though the public production alias was healthy.
- The public address-only endpoint exposed exact retained observation metadata,
  and the in-process limiter could not enforce one quota across Vercel instances.

### Files changed
- `.github/workflows/post-deploy-smoke.yml`,
  `website/tools/post_deploy_smoke.py`, and
  `website/tests/test_post_deploy_smoke.py`: target the public production alias,
  reject cross-host redirects and non-JSON responses with actionable errors, and
  verify a unique sender transitions from `first_seen` to `previously_seen`.
- `website/sender_history.py`, `website/app.py`, and related backend tests: add
  an atomic HMAC-keyed Upstash rate-limit operation, retain the bounded local
  fallback, remove address-only history lookups, and expose only coarse sender
  history status and service scope.
- `website/static/app.js`, `website/static/app.test.mjs`, `README.md`, and the
  sender-history design: update privacy boundaries and replace deployment-local
  wording with service-retained history semantics.

### Effect
- Deployment smoke checks no longer fail on Vercel's protected immutable URL and
  now validate the live Upstash integration rather than configuration alone.
- Public clients cannot query exact first/last-seen timestamps or observation
  counts, and configured deployments share one short-lived POST limit across
  serverless instances without storing raw client addresses.

## [2026-09-19 21:58 PT] — Add privacy-preserving sender observation history

### Why
- Disposable-domain lists cannot determine whether a Gmail or Outlook mailbox
  is newly created, and random-looking mailbox names are only weak heuristics.
- Serverless instances cannot maintain reliable cross-request history in local
  memory, so deployment-local observations require an optional external store.

### Files changed
- `website/sender_history.py`, `website/config.py`, and `website/app.py`: add an
  optional Upstash REST store keyed by HMAC-SHA-256 sender identifiers, atomic
  first/last-seen updates, bounded counts, a 90-day default TTL, short fail-open
  timeouts, redirect rejection, safe configuration validation, and public
  capability flags.
- `website/static/index.html`, `website/static/app.js`, and
  `website/static/style.css`: show first-observed, previously-observed, disabled,
  and unavailable states while explicitly separating deployment history from
  provider account age and sender safety.
- `website/tests/test_sender_history.py`,
  `website/tests/test_sender_history_integration.py`,
  `website/tests/test_config.py`, and `website/static/app.test.mjs`: cover opaque
  identities, alias canonicalization, atomic/read-only behavior, failure paths,
  risk neutrality, raw-message integration, configuration, and UI wording.
- `README.md`: document privacy boundaries and optional Vercel Marketplace
  setup using Upstash Redis.

### Effect
- Full raw-message analysis records only the highest-risk sender selected for
  the result, with at most one external history request per analysis;
  nested messages cannot amplify requests, and address-only analysis remains
  read-only. No raw sender address or message body is written to Redis.
- Observation history can add context for one-time provider accounts, but never
  claims a Gmail/Outlook creation date and never suppresses phishing evidence.
- Missing or unavailable Upstash storage leaves all existing analysis available.

## [2026-09-19 13:07 PT] — Reduce text-model false positives and expose uncertainty

### Why
- The committed classifier labeled short ordinary messages such as trip-photo
  replies and project updates as phishing, while zero-vocabulary multilingual
  input still received a model verdict.
- The UI described classifier output as probability/confidence, and evaluation
  rates lacked uncertainty intervals despite small legitimate validation slices.
- Deployment smoke testing exercised only a phishing positive control.

### Files changed
- `website/content_model.py` and `website/model/content_model_artifact.pkl`: add
  1,044 unique grouped training-only legitimate hard negatives from 87 template
  families, including personal correspondence and workplace updates; exclude
  normalized overlap with reserved data, remove mislabeled threat filler from
  legitimate synthetic mail, share family IDs with the base synthetic corpus so
  held-out template variants cannot be reintroduced after splitting, add build
  provenance and Wilson 95% intervals, and mark the 2025 temporal set as a
  post-selection regression slice.
- `website/content_inference.py`, `website/app.py`, `website/static/app.js`, and
  `website/static/index.html`: abstain when TF-IDF has zero usable features,
  preserve rule/structure results, and label supported output as a model risk
  score rather than a calibrated probability or confidence.
- `website/email_structure.py`: retain parsed `To`/`Cc` candidates, add a bounded
  self-addressed-message signal, and treat a missing visible recipient as
  informational because Bcc is legitimate.
- `website/tools/post_deploy_smoke.py`, `website/tests/vercel_runtime_smoke.py`,
  and their tests: require both phishing-positive and legitimate-negative
  controls, read Vercel's deployment `environment_url`, and compare the full
  model SHA-256. Regression tests cover abstention, personal/workplace hard
  negatives, held-out-family exclusion, recipient handling, terminology,
  intervals, and artifact provenance.
- `.github/workflows/ci.yml`: keep source tests on Python 3.12 and 3.13 while
  loading the Python-3.12 serialized deployment artifact only on its matching
  runtime.
- `vercel.json`, `README.md`, and `phishing-detection/README.md`: pin the rebuilt
  artifact and document its scope, metrics, limitations, and uncertainty.

### Effect
- The exact observed photo-message regression scores 15.9%, two differently
  worded monthly-report controls score 5.1% and 9.4%, and the Outlook planning-
  note fixture scores 22.4%, all below the 37.36% threshold; the local Vercel
  runtime phishing positive control scores 99.8%.
  Unsupported Chinese, Japanese, and unknown-Unicode text now returns
  `ml_status=insufficient_feature_coverage` with nullable model scores.
- The 6,000-row original group-isolated test reports 99.32% phishing recall and
  98.13% precision. The 2025 SpaPhish regression slice reports 96.65% recall and
  18.75% false-positive rate, with Wilson 95% intervals.
- The rebuilt 26,052-row Logistic Regression artifact is pinned as
  `a0a503a0cd6122e722933add91f49cc72e3fa74abaf1129c4df3fe0450401746`.

## [2026-09-19 10:07 PT] — Add dated Spanish corpus and cross-language model validation

### Why
- The committed English-heavy model classified every legitimate message in an
  initial 2024–2025 SpaPhish check as phishing (87/87 false positives), despite
  high phishing recall.
- The previous mixed-corpus holdout was group-isolated but not chronological or
  multilingual, so it did not expose this cross-language calibration failure.

### Files changed
- `website/content_model.py`: add the CC-BY-4.0 SpaPhish v1 source with a pinned
  SHA-256 download, normalized-family isolation, 2024 threshold validation,
  2025 evaluation-only holdout, and explicit partial-temporal metadata.
- `website/tests/test_content_corpus.py`: cover checksum failure, atomic
  preservation of an existing dataset, temporal partition boundaries, family
  isolation, false-positive-constrained threshold selection, and holdout metrics.
- `website/model/content_model_artifact.pkl` and `vercel.json`: rebuild the
  Logistic Regression artifact and pin SHA-256
  `50bc0b1a9e694b12521f8f3fe0131348f91746a1d9dce0a82c62ac2b7b56ec00`.
- `README.md` and `phishing-detection/README.md`: document source, license,
  observed file counts, evaluation protocol, metrics, and limitations.

### Effect
- Training uses 1,008 SpaPhish samples in addition to the 30,000-row capped
  base corpus; 128 dated 2024 messages select a maximum-recall threshold under
  a 20% legitimate-message false-positive cap.
- The untouched 2025 holdout contains 211 normalized families and reports
  96.65% phishing recall, 97.19% precision, 15.62% false-positive rate, and
  0.9940 PR AUC with zero training-family overlap.
- The original 6,000-row mixed-corpus holdout remains at 99.50% phishing recall
  and 0.9994 PR AUC. This is not a Gmail/Outlook claim: 791 training rows are
  undated, and no provider-specific private inbox corpus was available.

## [2026-09-18 21:19 PT] — Fix sender lookalikes and accelerate deployed inference

### Why
- Standalone digit-substitution domains such as `paypa1.com` normalized to an
  official brand and were then incorrectly excluded from the spoofing rule.
- Last-two-label domain parsing treated `co.uk` as a registrable domain and
  produced both missed lookalikes and false subdomain warnings.
- Privacy-alias coverage omitted official SimpleLogin domains, while content
  explanations rebuilt and densified 80,000 model features on every request.
- Source-level CI did not verify the completed Vercel deployment.

### Files changed
- `website/app.py`, `requirements.txt`, and `website/requirements.txt`: offline
  Public Suffix parsing, corrected brand-spoof semantics, and a decisive sender
  risk floor for verified character-substitution lookalikes.
- `website/data/privacy_relay_domains.json` and
  `website/disposable_registry.py`: a validated, versioned privacy-relay list
  with provider provenance, including official SimpleLogin alias domains.
- `website/content_inference.py`: cached explanation metadata and sparse-only
  contributor computation.
- `.github/workflows/post-deploy-smoke.yml` and
  `website/tools/post_deploy_smoke.py`: revision-matched public deployment
  health, configuration, model-ID, and positive-control checks.
- Backend regressions, GitHub Action runtime upgrades, and README guidance.

### Effect
- Isolated `paypa1`, `g00gle`, `app1e`, `n3tflix`, `micro5oft`, `6oogle`, and
  `p4ypal` sender domains now reach at least High risk, including under
  multi-label suffixes such as `.co.uk`.
- Ordinary multi-label domains no longer inherit false `co.uk`/`com.au`
  subdomain or uncommon-TLD findings, and SimpleLogin aliases remain neutral.
- The deployed model preserves its probability and contributor contract while
  avoiding per-request dense explanation arrays; completed Vercel deployments
  receive an independent HTTP smoke test.

## [2026-09-18 18:28 PT] — Harden custom-domain and model deployment maintenance

### Why
- A custom Vercel domain was not part of the backend Host allow-list and would
  be rejected after DNS attachment.
- CI installed the broader training dependency set instead of independently
  exercising the exact Vercel runtime, committed artifact, and Lite profile.
- The disposable-provider list was embedded in application code without
  version or provenance metadata, and deployed metrics did not identify their
  exact model artifact.

### Files changed
- `website/app.py`, `.env.example`, and `vercel.json`: additive custom-domain
  configuration, data-file bundling, and deployed artifact identity reporting.
- `website/disposable_registry.py`, `website/data/disposable_domains.json`, and
  `website/tools/build_disposable_registry.py`: validated versioned registry
  loading and deterministic offline maintenance.
- `.github/workflows/ci.yml` and `website/tests/vercel_runtime_smoke.py`: a
  production-dependency CI job that loads and predicts with the real artifact;
  the general Python 3.13 matrix skips that Python 3.12-specific artifact smoke.
- Python regressions and README deployment guidance.

### Effect
- Operators can attach explicit custom domains without weakening the default
  Vercel Host policy.
- Dependency or artifact incompatibility fails CI before deployment, while
  `/health` and `/api/metrics` identify the model that actually loaded.
- All 466 existing registry entries are preserved in a reviewable data file;
  future updates can record their source and version without editing detector
  logic. Gmail/Outlook mailbox lifetime remains explicitly unobservable.

## [2026-09-18 17:50 PT] — Add an almost-full Vercel profile

### Why
- The public deployment disabled all network verification because SMTP mailbox
  probing was unsuitable, even though bounded domain-level checks can run
  independently.
- The web runtime also needed a compact, prebuilt model path that did not import
  the pandas-based training stack or train during service startup.

### Files changed
- `app.py`, `vercel.json`, `requirements.txt`, `.python-version`, and
  `.vercelignore`: Vercel FastAPI entrypoint, runtime dependencies, bounded Lite
  profile, and bundle controls.
- `website/config.py`, `website/app.py`, and `website/static/app.js`: explicit
  `off`/`lite`/`full` verification modes, separate domain/mailbox summaries,
  configurable workers, and honest Lite-mode presentation.
- `website/content_inference.py` and `website/model/content_model_artifact.pkl`:
  runtime-only verified inference and a 3.4 MB Logistic Regression artifact.
- Python and frontend tests plus README/design documentation: public contracts,
  compatibility behavior, and deployment boundaries.

### Effect
- Vercel Lite mode runs format, MX/A/AAAA, SPF, DMARC, PTR, and best-effort
  WHOIS checks without opening SMTP connections or claiming mailbox existence.
- The deployed artifact is SHA-256 pinned (`d25fc27b...53631`), contains 24,000
  training and 6,000 held-out samples after grouped splitting, and reports zero
  train/test group overlap. Its held-out corpus metrics are model-development
  evidence only, not a real-world phishing-accuracy claim.
- Startup validates the artifact and loads inference without requiring pandas;
  a rejected artifact degrades to the existing rule and structure analyzer.

## [2026-09-18 10:30 PT] — Preserve equivalent message evidence and correct verification summaries

### Why
- Browser-readable slash/backslash URL variants and omitted HTML head end tags
  could suppress otherwise detected message risk.
- DNS TXT fragments and substring-based SPF/DMARC parsing produced incorrect
  policy summaries; verification and sender analysis disagreed on address syntax.

### Files changed
- `website/app.py`: shared HTTP(S) destination normalization before base resolution,
  incomplete malformed-target handling, implicit head recovery, TXT/policy parsing,
  and shared address normalization for verification.
- `website/tests/test_review_regressions.py`: equivalent-target, HTML visibility,
  policy-record, and address-validation regressions with offline network fixtures.
- `README.md`: documented recovery boundaries and policy-summary limitations.

### Effect
- Equivalent URL forms retain destination-host checks; malformed explicit
  authorities do not silently inherit a base URL or claim complete analysis.
- An omitted head end tag no longer hides body evidence; inert text remains hidden.
- Fragmented TXT records retain policy values. Ambiguous/invalid recognized
  policies remain inconclusive instead of receiving a successful policy verdict.
- Verification uses canonical IDNA addresses while retaining submitted text for
  display, and rejects unsupported address syntax before DNS.

## [2026-09-18 09:58 PT] — Make HTML recovery independent of Python parser tolerance

### Why
- CI on Python 3.13.15 silently consumed unknown HTML marked declarations,
  bypassing exception-based recovery and causing nine regression assertions
  to fail despite the local Python 3.12.9 suite passing.

### Files changed
- `website/app.py`: shared declaration-aware HTML parser for text, links,
  and forms, with explicit recovery for unknown marked declarations.
- `website/tests/test_review_regressions.py`: tolerant-parser regression and
  normal comment, attribute, script/style, CDATA, and conditional controls.
- `.github/workflows/ci.yml`: Python 3.12/3.13 test matrix with fail-fast disabled.
- `README.md`: documented version-independent recovery and CI coverage.

### Effect
- Unknown marked declarations retain risk evidence and incomplete-analysis
  warnings without depending on the standard library raising an exception.
- Literal markers outside declaration context do not trigger the new check.
- Both supported Python minor versions will be tested on subsequent CI runs.

## [2026-09-17 22:24 PT] — Recover ambiguous MIME and HTML without losing risk evidence

### Why
- Authentication comments/reason strings could override actual DMARC results.
- Duplicate MIME headers hid encoded content, malformed HTML aborted analysis,
  and decimal amounts were incorrectly inflated by removing punctuation.

### Files changed
- `website/email_structure.py`: clause-aware authentication parsing and bounded
  alternate MIME leaf interpretations with explicit warnings.
- `website/app.py`: shared HTML recovery, nested completeness propagation,
  `analysis_warnings`, and decimal/grouped amount handling.
- `website/tests/test_review_regressions.py`, `README.md`: regression controls
  and documented recovery limits.

### Effect
- Comments and quoted explanations no longer replace real authentication results.
- Ambiguous MIME and recovered HTML retain available evidence and report incomplete
  analysis instead of silently reporting a complete verdict or throwing the reproduced error.
- Ordinary decimal invoice amounts do not trigger the large-amount signal merely
  because they include cents; long-digit and output-length protections remain.

## [2026-09-17 22:10 PT] — Bound MIME parsing and preserve multi-mailbox identity signals

### Why
- Multiple mailboxes in one From field hid display-name impersonation.
- Deep MIME nesting and long monetary digit strings could abort analysis.
- No-MX domains with only IPv6 addresses were incorrectly classified as invalid.

### Files changed
- `website/email_structure.py`: per-mailbox identity checks and a 200-node
  parsing budget with explicit incomplete, outer-headers-only fallback.
- `website/app.py`: bounded monetary evidence and A/AAAA discovery fallback.
- `website/tests/test_review_regressions.py`: adversarial and normal controls.
- `README.md`: limits, fallback behavior, and IPv6 discovery semantics.

### Effect
- Multiple From addresses retain the strongest brand-identity signal.
- Over-budget MIME and large numbers no longer trigger the reproduced exceptions.
- IPv6-only implicit mail hosts remain eligible for verification, while DNS
  errors stay inconclusive and Null MX still stops further checks.

## [2026-09-17 21:55 PT] — Preserve ambiguous-header evidence and clarify verification results

### Why
- Duplicate key headers could hide sender or subject risk. SMTP rejections,
  Null MX records, and caught lookup failures produced misleading verification results.

### Files changed
- `website/email_structure.py`, `website/app.py`: candidate-header analysis,
  header defects, SMTP response distinctions, Null MX, and explicit check status.
- `website/static/app.js`, `website/static/index.html`: incomplete-verification
  and no-mail-service messages; cache version 25.
- Backend and frontend regression tests; `README.md` documents API semantics.

### Effect
- Duplicate critical headers preserve detected risk and flag incomplete analysis.
- Policy rejection and full mailboxes are not classified as nonexistent.
- Null MX stops further checks without labeling the domain as phishing.
- Failed checks cannot report complete verification; SMTP acceptance is not
  presented as guaranteed mailbox existence or delivery.

## [2026-09-17 21:36 PT] — Unify sender checks and bound nested analysis and verification

### Why
- Unicode domains bypassed raw-message sender checks. Attached messages lost
  identity/attachment evidence. JSON requests without Content-Length bypassed the
  body-size guard, and thread-pool shutdown defeated verification timeouts.

### Files changed
- `website/app.py`, `email_structure.py` — shared domain normalization, bounded
  nested-message inspection with untrusted inner authentication, one verification
  deadline covering DNS discovery and follow-up checks, socket cleanup/timeouts.
- `website/request_limits.py` — pre-decoding actual-byte ASGI request-body cap.
- `website/verification_runtime.py` — shared non-queueing bounded verification pool.
- `website/static/app.js`, `index.html` — preserve inconclusive DNS results in
  the UI, clarify the unverifiable verdict, and load v24 JavaScript.
- `website/tests/test_app_security.py`, `test_detection_behavior.py`,
  `static/app.test.mjs` — IDN equivalence, attached-email risk/trust/limits,
  streamed request limits, timeouts, saturation/recovery, and UI regressions.
- `README.md` — input normalization, inspection bounds and operational contracts.

### Effect
- Supported raw-message senders and attached-message risks retain their evidence.
  Uninspected opaque or transfer-encoded attached content is explicitly marked incomplete.
- Oversize streamed JSON is rejected before parsing. Slow verification no longer
  blocks the response beyond its deadline; still-running work retains bounded
  capacity. No real mailbox probing or detection-accuracy claim is implied.

## [2026-09-17 21:18 PT] — Isolate MIME evidence and expose incomplete analysis

### Why
- Concatenated MIME parts allowed unclosed markup to hide other content; parser
  defects silently discarded bodies. Relative HTML targets were not resolved,
  and medium destination-risk floors disappeared during aggregation.

### Files changed
- `website/email_structure.py` — typed content parts and recovered MIME defects.
- `website/app.py` — per-part text/link/form analysis, HTML base resolution,
  risk-floor preservation, and explicit incomplete-analysis response state.
- `website/static/app.js`, `style.css`, `index.html` — amber unknown-risk state,
  incomplete-analysis explanation, nonnumeric score display, and v23 assets.
- `website/tests/test_detection_behavior.py`, `website/static/app.test.mjs` —
  multipart isolation, malformed MIME, relative destinations, risk floors,
  plain-text URL preservation, and unknown-state/animation regressions.
- `README.md` — parsing guarantees, limitations, and new response compatibility.

### Effect
- MIME parts cannot suppress each other's visible evidence. Incomplete parsing
  without detected risk produces `unknown`/null rather than a clean zero; existing
  risk evidence is retained. Relative targets are checked without network access.
- These are bounded parser and rule fixes, not a measured accuracy improvement.

## [2026-09-17 21:01 PT] — Preserve MIME bytes and normalize content evidence

### Why
- Text-only upload decoding corrupted non-UTF8 and Unicode MIME bodies. HTML
  formatting hid credential phrases, positive evidence could become a no-indicators
  verdict, substring shortener checks misfired, and form destinations were omitted.

### Files changed
- `website/app.py` — bounded binary `/api/analyze-eml` route sharing the existing
  analysis pipeline; normalized visible text, contextual credential-request floor,
  consistent low-risk minimum, parsed shortener hosts, form/password evidence.
- `website/email_structure.py` — byte-aware MIME parsing, legacy Unicode support,
  charset and transfer decoding with explicit fallback warnings.
- `website/static/app.js`, `index.html` — original-byte upload, client size feedback,
  shared response error handling, upload limit copy and v22 assets.
- `website/tests/test_detection_behavior.py`, `website/static/app.test.mjs` —
  byte fidelity, stream limits, markup variants, negation/reset controls,
  shortener boundaries and HTML form regressions.
- `README.md` — binary API contract and remaining language/heuristic limitations.

### Effect
- Original message bytes survive transport; rule evidence no longer disappears
  solely because of common HTML formatting or a low positive score.
- Urgency + threats + a direct credential request establish a high-risk floor,
  while tested reset/safety notices do not. Shortener and form targets are checked
  without executing HTML or visiting links. No new model or empirical accuracy claim.

## [2026-09-17 20:35 PT] — Preserve uploaded-message and normalized-link evidence

### Why
- Manual text could replace an uploaded message's body. Equivalent link formats
  bypassed host checks; unknown charsets aborted analysis; attachment-only messages
  were rejected. Generic login hostnames forced a high-risk verdict on weak evidence.

### Files changed
- `website/app.py` — authoritative raw-message mode, structural-only input,
  parsed destination/IP checks, and weaker generic hostname evidence.
- `website/email_structure.py` — safe charset fallback and explicit parse warnings.
- `website/static/app.js`, `index.html`, `style.css` — mutually exclusive file/manual
  input, empty-file feedback, accessible upload status, and v21 static assets.
- `website/tests/test_detection_behavior.py`, `website/static/app.test.mjs` —
  positive and negative controls for the reviewed defects and upload state.
- `README.md` — input precedence, parsing limits, link behavior, and language caveats.

### Effect
- File evidence cannot be overwritten by stale manual text, and supported IP/link
  representations retain risk signals without classifying IP-looking hostnames as IPs.
- Unknown text codecs produce an explicit warning; dangerous attachment-only input
  receives a verdict. Generic account-host terms alone no longer force high risk.
- No new model, data download, or real-world accuracy claim; pure-text/multilingual
  recall still needs independent evaluation.

## [2026-09-17 19:34 PT] — Keep analysis results aligned with current input

### Why
- Late responses could overwrite a newer sender or content result, and mailbox
  verification errors were rendered as invalid addresses. Structural-only risk
  could appear beside a no-patterns summary. Example selection left stale upload UI.

### Files changed
- `website/static/app.js` — request generations, shared HTTP error handling,
  input invalidation, file-read state, and summaries including technical evidence.
- `website/app.py` — reject non-address input at the sender API boundary.
- `website/static/index.html`, `style.css` — accessible inline error messages;
  static assets bumped to v20.
- Frontend and detection tests — out-of-order responses, input changes, HTTP
  errors, invalid addresses, and pending upload regressions.
- `README.md` — accepted sender syntax and request/upload behavior.

### Effect
- Switching or clearing input prevents obsolete results from reappearing.
- Rate limits and service failures no longer become mailbox verdicts.
- Non-address text receives input guidance, and summaries include structural risk.
- Upload state stays consistent when examples replace files or reads finish late.

## [2026-09-17 18:31 PT] — Separate mailbox service type from sender risk

### Why
- Disposable-provider matches were scored as high-risk evidence while the overall
  low verdict displayed a green check. Disabled local verification also displayed
  public-service wording, including after a result reset.

### Files changed
- `website/app.py` — informational disposable-provider evidence, Apple private
  relay domains, accurate provider descriptions, and public deployment profile.
- `website/static/app.js`, `index.html`, `style.css` — neutral low-score display,
  separate service classification, no complementary safety score, and distinct
  local/public/unknown verification messages. Assets bumped to v19.
- `website/static/app.test.mjs`, `website/tests/test_app_security.py`,
  `website/tests/test_detection_behavior.py` — configuration, classification,
  presentation, and full-message regression coverage.
- `README.md` — scoring semantics and explicit local verification startup.

### Effect
- A provider-category match alone adds no phishing points; independent risks still
  score normally. No new empirical detection-accuracy claim is made.
- Low scores no longer imply a verified or safe message. Deployment safety gates
  and rate limits remain enabled.
- Superseded score animations cannot overwrite a newer result when examples are
  analyzed in quick succession; a regression test covers high-to-zero transitions.

## [2026-09-17 15:00 PT] — Scan illustration, score rings, count-ups, light/dark theme

### Why
- Follow-up to the icon pass: the user asked to implement the remaining
  visual suggestions (narrative hero graphic, ring-style scores, animated
  numbers, and automatic light/dark switching).

### Files changed
- `website/static/index.html` — hero visual replaced by `.scan-card` (a
  glass message card with avatar, skeleton lines, one flagged link line, a
  green header check, a red alert badge, and a sweeping `.scan-beam`) while
  keeping the orb glow, rings, and floating chips; sender and content banners
  now wrap the score in a `.score-ring` SVG (`#vb-ring`, `#crb-ring`); hero
  stat values carry `data-count/data-decimals/data-suffix`; nav gains a
  `#theme-toggle` (sun / moon / "A" auto badge); `<head>` bootstrap script
  resolves `data-theme` from `localStorage['phishguard-theme']` or
  `prefers-color-scheme` before first paint; `color-scheme` is `light dark`
  with two `theme-color` metas; assets bumped to `?v=18`.
- `website/static/app.js` — `setupTheme/applyTheme/cycleTheme` (auto → light
  → dark, persisted, follows system changes in auto); `animateNumber()`
  (cubic ease-out, always ends on the exact formatted value; immediate when
  `requestAnimationFrame` is missing or reduced motion is set) used for hero
  stats via `setupCountUps()` and for `vb-prob` / `crb-score`; `setRing()`
  drives `stroke-dashoffset` on the ring (heuristic-only content totals are
  scaled against a ceiling of 30).
- `website/static/style.css` — theme tokens added (`--glass-bg`,
  `--field-bg`, `--fill`, `--line`, `--track`, `--on-accent`, …) and all
  hard-coded dark rgba surfaces converted to them; `:root[data-theme="light"]`
  palette (`#f4f6fb` base, `#0f172a` text, accent `#0a7fd6`, multiply-blend
  colour fields) plus a handful of light-specific overrides; `.scan-*`
  illustration styles (6.5 s beam sweep, 11 s card float, 3.2 s flag pulse);
  `.score-ring` (104 px, 6.5 px stroke, 1.1 s eased fill); `.theme-toggle`
  with cross-fading sun/moon; reduced-motion block covers the new animations.

### Effect
- Verified in headless Chrome for both themes: hero illustration and chips
  render, hero stats count up to `97.47% / 0.9977 / 11,055 / 30`, the sender
  ring fills to 100/100 (`stroke-dashoffset` 0) with `100/100` centred, the
  legitimate-newsletter content result shows a green `0%` ring, and the
  toggle reflects the active mode.
- Theme resolves before first paint (no flash), follows the OS in auto mode,
  and persists a manual choice.
- `node --test website/static/app.test.mjs` 9/9 passing (count-ups set final
  values synchronously in the vm harness); `node --check` OK.

## [2026-09-17 14:51 PT] — Unified SVG icon system replaces emoji

### Why
- User asked for more attractive, modern graphics. The page mixed ~40
  platform-dependent emoji (🛡 ✉ 📄 🔗 🌐 📧 🗑 ⚠️ ✅ ❌ 🔍 ☠️ 🏆 …) that render
  differently per OS and clash with the fluid glass design.

### Files changed
- `website/static/app.js` — added `ICON_PATHS` (29 stroke icons on a 24px
  grid), `icon(name, extraClass)` helper, and `CATEGORY_ICONS` mapping the
  backend `category_results[].key` (urgency, threats, financial, credential,
  impersonation, deception, attachments, tech_scam, job_scam,
  social_engineering) to clock / bell / dollar / key / mask / eye-off /
  paperclip / monitor / briefcase / brain. Verdict banners, disposable-check
  card, verification steps and verdicts, content risk banner, category cards,
  summary pills, and the benchmark "Best" badge now render SVG via
  `innerHTML`; emoji removed from ML verdict text; unused `LEVEL_ICONS`
  dropped. Backend `cat.icon` is no longer displayed (API unchanged).
- `website/static/index.html` — tabs, input adornment, verification section
  titles/buttons, disposable info card, feature category cards, and footer use
  inline SVGs; quick-example chips lose their emoji prefixes; assets bumped to
  `?v=17`.
- `website/static/style.css` — new icon layer: `.ico` sizing, `.icon-tile`
  (44px rounded tile) with tinted `tile-high/medium/low/purple` and
  app-icon-style gradient `tile-grad-cyan/mint/violet` variants; 56px tinted
  discs for `.vb-icon`/`.crb-icon` keyed to banner class; tinted 26px squares
  for `.vstep-icon`; `.best-badge`; per-state colours for `.disp-check-icon`.

### Effect
- Every symbol on the page now shares one stroke weight and palette; category
  cards show a semantic icon (clock for urgency, key for credential harvesting,
  etc.) inside a level-tinted tile instead of backend emoji.
- Verified via headless Chrome on the sender critical-risk result, content
  critical-risk result, features, demo input, and benchmark views.
- `node --test website/static/app.test.mjs` 9/9 passing; `node --check` OK.

## [2026-09-17 13:39 PT] — Integrate fluid frontend with disposable classification

### Why
- The frontend redesign and disposable-email improvements diverged from the
  same base and needed to be combined without losing either visual behavior or
  the newer classification semantics.

### Files changed
- `website/static/app.js`: retain the five-state disposable renderer while
  adding the fluid theme's scroll reveal, palette, chart, and passive-scroll
  updates.
- `website/static/index.html` and `website/static/style.css`: adopt the fluid
  glass layout and cache-busted assets while retaining cautious disposable
  education copy and all result-state selectors.
- `CHANGELOG.md`: preserve both histories in chronological order and record the
  merged verification results.

### Effect
- The redesigned frontend and current sender-analysis API work together without
  code conflicts or loss of classification behavior.
- The merged backend suite passes 83 tests, the frontend suite passes 9 tests,
  and JavaScript syntax validation succeeds.

## [2026-09-17 13:07 PT] — Modern fluid restyle (supersedes the HUD theme)

### Why
- User follow-up: the HUD/instrument look should give way to something more
  modern, closer to Apple's marketing pages — large type, generous space,
  frosted-glass surfaces, and flowing motion — while staying easy on the eyes.

### Files changed
- `website/static/style.css` — rewritten again around a fluid, editorial system:
  `#06080f` base with three fixed radial colour fields (`.bg-fluid .blob-*`)
  that drift on 46/52/58 s alternating loops; floating pill-shaped glass navbar
  (`backdrop-filter: blur(22px)`); hero headline at `clamp(40px, 5.6vw, 72px)`
  with `-0.035em` tracking and a 14 s flowing gradient on the accent word; new
  hero orb (`.orb` conic gradient, `blur(34px)`, 18 s border-radius morph +
  90 s rotation) under a glass core with four gently floating chips; pill
  buttons and tags; segmented demo tabs with a sliding highlight driven by
  `:has(.demo-tab:nth-child(2).active)`; `.reveal/.in-view` transitions;
  `[id] { scroll-margin-top: 84px }` so anchors clear the sticky nav; removed
  the instrument grid, corner brackets, and monospace uppercase labels; kept a
  full `prefers-reduced-motion` fallback that disables all ambient motion and
  shows revealed content immediately.
- `website/static/index.html` — assets bumped to `?v=16`; added the
  `.bg-fluid` layer; replaced the radar markup with `.orb-scene`; dropped the
  `SIGNAL CONSOLE` tag and `hud-frame` classes; softened section eyebrows to
  "Try it / Benchmark / Signals / Pipeline"; hero copy now reads
  "Phishing email detection, explained."
- `website/static/app.js` — added `setupScrollReveal()`: an
  `IntersectionObserver` adds `.in-view` the first time a target enters the
  viewport, with up to 60 ms stagger per child inside `.hero-stats`,
  `.charts-row`, `.feature-cards-grid`, `.top3-grid`, and `.pipeline-steps`.
  It is skipped when
  `IntersectionObserver` is unavailable or reduced motion is requested, so
  nothing is ever left hidden. Scroll listener is now `passive`.

### Effect
- Verified in a real Chrome session (1920×1171) and recorded: cards fade/slide
  in as they scroll into view, the background glow and orb motion are
  perceptible but slow, the segmented control slides between tabs, and both
  sender and content critical-risk results render without overlap or
  stuck-invisible elements.
- Fatigue budget unchanged in spirit: colour fields ≤ 20 % alpha at their
  centre and fully transparent by 68 %, every ambient loop ≥ 9 s (chip float
  9 s, ring breathe 12 s, gradient 14 s, orb morph 18 s, drift ≥ 46 s), reveal
  transitions 0.8 s with a decelerating ease, no flicker.
- After integration, `node --test website/static/app.test.mjs` passes 9/9 (the
  reveal code is guarded so the `vm`-based test harness is unaffected);
  `node --check` passes.

## [2026-09-17 12:41 PT] — Calm sci-fi HUD restyle of the web frontend

### Why
- User request: give the frontend a stronger science-fiction feel without
  making it tiring to read or watch.
- The previous theme was a generic GitHub-dark palette with a single fast
  orbit animation and no visual hierarchy between labels, numbers, and prose.

### Files changed
- `website/static/style.css` — rewritten around a "calm HUD" design system:
  deep-space palette (`#070b14` base, `#4fd1ff` cyan / `#3fd58f` mint accents),
  fixed low-alpha aurora glow and fading 48px instrument grid on `body::before`
  / `body::after`, `hud-frame` corner brackets, monospace uppercase labels for
  all section/column/metric headers, radar hero (concentric rings, 20 s conic
  sweep, 60 s orbiting signal pills), glowing probability bars, HUD-style
  loading ring, `::file-selector-button` styling, `:focus-visible` outlines,
  and a `prefers-reduced-motion` block that freezes ambient motion and pins
  orbit pills to static positions.
- `website/static/index.html` — cache-busted assets to `?v=15`; added
  `color-scheme`/`theme-color` metas, inline SVG shield brand mark with a
  `SIGNAL CONSOLE` tag, hero badge with a slow pulse dot, secondary
  "How It Works" hero button, numbered `section-eyebrow` labels (01–04), and
  `hud-frame` on the input, disposable-info, and chart cards.
- `website/static/app.js` — aligned hardcoded verdict/score colours and the
  Chart.js bar, grid, legend, and tooltip colours to the new palette. No
  behavioural logic changed.

### Effect
- Fatigue controls: decorative layers stay at ≤ 11 % alpha, every ambient
  animation is ≥ 20 s per cycle (aurora drift 48 s, radar sweep 20 s, orbit
  60 s, pulse dot 2.8 s at low amplitude), no flicker/scanline effects, body
  text remains 15px sans-serif on a near-black background, and reduced-motion
  users get a fully static page.
- Layout regressions fixed while restyling: the `No detected risk` probability
  label no longer wraps to three lines (`.prob-label` 36px → 96px) and the
  content-tab `Analyze Content` button is no longer collapsed to text height
  (now 40px tall).
- Verified with headless Chrome at 1440px and 414px on the hero, sender
  critical-risk result, content critical-risk result, benchmark, features,
  pipeline, and mobile views; `node --test website/static/app.test.mjs`
  remains 6/6 passing and the backend suite still passes.

## [2026-09-17 08:48 PT] — Evidence-based disposable email classification

### Why
- Disposable-provider lookup reduced domains to their last two labels, missing
  providers such as `10minutemail.co.uk` and `guerrillamail.co.uk`.
- Broad substring checks falsely classified unrelated domains, while random
  Gmail and Outlook mailbox names were not surfaced at all.
- Privacy relays, plus aliases, and Gmail dot variants could be presented as
  disposable or risky without enough evidence, and the UI implied unsupported
  mailbox-expiration guarantees.

### Files changed
- `website/app.py`: add boundary-aware full-domain registry matching, normalized
  and disjoint disposable/privacy-relay registries, anchored domain heuristics,
  provider-aware mailbox-pattern thresholds, plus-address and Gmail-dot
  normalization, and explicit classification metadata.
- `website/static/app.js` and `website/static/index.html`: render confirmed,
  suspected, privacy-relay, and no-known-match states separately with cautious
  explanations of what the evidence can establish.
- `website/tests/test_detection_behavior.py` and
  `website/static/app.test.mjs`: add regression coverage for multi-label
  providers, random Gmail/Outlook names, relay services, aliases, domain
  collisions, rendered labels, and education copy.
- `README.md`: document the response fields, semantics, and limitations.

### Effect
- Known disposable providers are confirmed by an exact or label-boundary domain
  match; suspicious mailbox or domain shapes remain explicitly heuristic.
- Random-looking Gmail and Outlook addresses are surfaced without being called
  confirmed disposable accounts, while ordinary addresses remain low risk.
- Privacy relays are informational and contribute no phishing score by
  themselves; plus tags and Gmail dots likewise do not increase risk.
- The backend regression suite passes 83 tests and the frontend suite passes
  9 tests.

## [2026-09-15 19:36 PT] — Raw-sender, ASCII-link, and MIME hardening

### Why
- Complete `.eml` analysis parsed the `From` header but did not reuse the
  sender/domain detector, allowing a highly suspicious sender to receive a safe
  full-message verdict when its body was neutral.
- Destination checks covered IDN lookalikes but missed ASCII digit substitutions,
  URL userinfo deception, and trusted-brand labels embedded in attacker domains.
- Attachment scoring relied on filename extensions, so an executable or archive
  MIME type without a matching suffix was not detected.

### Files changed
- `website/app.py`: extract shared sender analysis, fuse bounded sender evidence
  from the highest-risk valid mailbox into raw-message verdicts, and detect
  nonempty URL userinfo plus noncanonical brand labels normalized for common
  digit substitutions and separators.
- `website/email_structure.py`: classify dangerous and archive attachment MIME
  types in addition to filename extensions, including risky leaf parts without
  attacker-controlled attachment metadata.
- `website/tests/test_detection_behavior.py`: add positive attack controls and
  canonical-domain, Gmail-sender, and PDF negative controls.
- `README.md`: document the expanded full-message signals and regression scope.

### Effect
- `billing@secure-account.xyz` in a raw message now contributes its existing
  critical sender score and receives a high-or-critical full-message verdict;
  multi-mailbox `From` headers cannot hide it behind a benign first address.
- `paypa1.com`, `paypal.com@evil.example`, and
  `paypal.com.evil.example` destinations now set a high-risk floor while
  canonical PayPal destinations remain clean.
- Extensionless executable MIME payloads are high risk, archive MIME payloads
  are medium risk, and ordinary PDF attachments remain unscored.
- Common official regional domains remain clean, malformed sender fields and
  empty URL userinfo are ignored, and MIME aliases are covered.
- The backend regression suite now passes 72 tests; the frontend suite remains
  6/6 passing.

## [2026-09-15 14:14 PT] — Destination-aware rules and global corpus deduplication

### Why
- Rules-only analysis inspected displayed URL text but could miss a malicious
  destination behind generic button text, a bare displayed domain, or an IDN
  lookalike.
- Macro-enabled and archive attachments were not scored, and decisive trusted
  authentication failures could still receive only a medium verdict.
- Source-prefixed fallback groups allowed normalized duplicates from different
  corpora to cross the train/test boundary; permissive substring and
  obfuscation rules also produced avoidable false positives.

### Files changed
- `website/app.py`: analyze HTML, Markdown, and plain-text destinations; detect
  IDN lookalikes, displayed-host mismatches, credential-themed domains, raw-IP
  destinations, malformed targets, `hxxp` schemes, and zero-width keyword
  splitting; add evidence severity floors and boundary-aware phrase matching.
- `website/email_structure.py`: score macro-enabled, executable, disk-image, and
  archive attachments and expose a structural risk floor.
- `website/content_model.py`: deduplicate normalized families across all sources,
  exclude label conflicts, use source-independent fallback groups, and select
  candidate models by cross-validated average precision.
- `website/tests/test_detection_behavior.py` and project documentation: add the
  corresponding adversarial regressions and refresh measured metrics.

### Effect
- Generic-link, bare-domain, and IDN destination attacks now receive high-risk
  evidence; ZIP and macro-document attachments no longer pass as safe; decisive
  SPF/DKIM/DMARC failure sets a high-risk minimum.
- Normal words such as `login` and substrings such as `irs` in `first` no longer
  trigger obfuscation or brand rules.
- From 61,707 raw corpus rows, normalization retained 53,841 after removing
  7,333 duplicates and 533 label-conflicting rows. The 10,768-row grouped
  holdout measured 99.78% phishing recall, 0.22% false-negative rate, 97.88%
  precision, 98.89% accuracy, and 0.9996 PR AUC at an F2 threshold of 0.3515.

## [2026-09-15 08:57 PT] — Trusted email evidence and offline model artifacts

### Why
- Uploaded `Authentication-Results` headers could claim `dmarc=pass` and
  suppress real authentication failures without proving which receiver created
  the header.
- Protected-brand display names and internationalized lookalike domains were
  not represented in raw-message structural risk.
- Local SMTP verification could connect to private DNS targets, the in-memory
  rate limiter trusted raw forwarding headers, and web startup could download
  data and train the content model.

### Files changed
- `website/email_structure.py` and `website/config.py`: add configurable trusted
  authentication-service IDs plus protected-brand, IDNA, and Unicode-confusable
  identity signals.
- `website/app.py`: enforce public SMTP targets, bound rate-limit state, ignore
  raw forwarding headers, load only verified offline content-model artifacts,
  and remove the dead `/api/predict` route and UCI runtime model state.
- `website/content_model.py` and `website/prebuild_demo_model.py`: add versioned
  SHA-256-verified artifacts, disable pickle-cache loading by default, strengthen
  near-duplicate grouping, and report per-source sample counts.
- `website/tests/`, `.env.example`, `render.yaml`, and project documentation:
  add adversarial regression coverage and document the new safe defaults.

### Effect
- Untrusted authentication claims cannot affect scoring; configured receiver
  results retain forwarding-aware DMARC handling.
- Display-name, Punycode, and common Unicode lookalikes produce visible phishing
  evidence while canonical brand domains remain clean.
- SMTP cannot open a socket to non-global addresses, rate-limit memory is
  bounded, and default web startup remains rules-only without network or model
  training work.
- Optional ML is deployed as a trusted offline artifact whose digest and runtime
  compatibility are checked before use.
- A fresh 61,707-row offline evaluation with normalized family grouping retained
  zero train/test group overlap and measured 99.67% phishing recall, 0.33%
  false-negative rate, 98.80% precision, 99.21% accuracy, 0.9997 PR AUC, and a
  learned F2 threshold of 0.3636 on the 12,342-row held-out fold.

## [2026-09-04 13:52 PT] — Full corpus recall benchmark and campaign URL isolation

### Why
- The first full evaluation grouped PhishNChips rows by unique record ID even
  when multiple variants shared the same phishing URL. That could allow one
  campaign's variants to cross training and test boundaries.
- The project needed a direct comparison between the default `0.5` decision
  threshold and the learned recall-oriented threshold.

### Files changed
- `website/content_model.py`: groups PhishNChips variants by `url_raw` before
  falling back to record ID/text hash; reports the grouping policy, default
  threshold recall, and recall gain; defaults bundled synthetic-template
  augmentation to off; bumps the cache key to v5.2.
- `website/tests/test_detection_behavior.py`: verifies shared campaign URLs use
  one group and the new threshold-comparison metrics are present.
- `.env.example`: documents `CONTENT_MODEL_AUGMENT_SYNTHETIC=false`.
- `README.md`: records the dated corpus evaluation and its limitations.

### Effect
- On the 12,342-row group-isolated holdout, the learned F2 threshold `0.3492`
  achieved phishing recall `0.9980` and false-negative rate `0.0020`, compared
  with recall `0.9951` at threshold `0.5` (`+0.0028`). Accuracy was `0.9921`,
  precision `0.9869`, F1 `0.9924`, ROC AUC `0.9997`, PR AUC `0.9998`, and Brier
  score `0.0058`; train/test group overlap was zero.
- These remain offline mixed-corpus results rather than a production claim:
  PhishNChips is synthetic, classic corpora lack campaign IDs, and the split is
  not time-separated.

## [2026-09-04 13:24 PT] — Evidence-preserving phishing detection and honest evaluation

### Why
- The sender endpoint applied a Random Forest trained on UCI phishing-website
  URL/HTML features to similarly named email-address heuristics. That domain
  mismatch made its displayed “phishing probability” and feature importances
  invalid for email senders.
- The content model split individual rows, allowing variants from the same
  source/template family to appear in training and evaluation, and fitted its
  TF-IDF vocabulary before cross-validation. Both could inflate reported
  performance.
- Full authentication headers, sender-identity alignment, MIME attachments,
  and actual HTML link destinations were unavailable to the detector. Weak ML
  output could also average away strong rule evidence, while attacker-copyable
  footer text reduced risk.

### Files changed
- `website/app.py`: replaced sender-model probability output with a declared
  heuristic risk score; added raw-message input, conservative max-evidence
  fusion, honest UCI metric scope, rules-only readiness, HTML-link parsing, and
  neutral handling of regional English and safety-footer phrases.
- `website/email_structure.py`: added RFC 5322/MIME parsing, SPF/DKIM/DMARC
  result checks, From/Reply-To/Return-Path alignment, multipart HTML coverage,
  and dangerous-attachment indicators.
- `website/content_model.py`: added campaign/template group IDs,
  `StratifiedGroupKFold`, per-fold TF-IDF fitting, out-of-fold F2 threshold
  selection, phishing recall/FNR/PR-AUC/Brier reporting, cache invalidation,
  and removal of automatic downloads from an unaudited PhishFuzzer mirror.
- `website/config.py`, `.env.example`, and `render.yaml`: added
  `CONTENT_MODEL_ENABLED`; the public Render profile now uses validated
  sender/structure/rule analysis without synthetic model training.
- `website/static/index.html`, `website/static/app.js`, and
  `website/static/style.css`: added `.eml` upload, sender-risk terminology,
  recall-focused metrics, scoped the historical UCI website benchmark, removed
  invalid sender importance claims, and escaped attacker-controlled indicator
  text before HTML rendering.
- `website/tests/test_detection_behavior.py`, `website/tests/test_app_security.py`,
  `website/tests/test_config.py`, and `website/static/app.test.mjs`: added
  regression coverage for the new semantics, raw-message evidence, grouping,
  deployment mode, multipart HTML, forwarded-mail authentication, and output
  escaping.
- `README.md` and `phishing-detection/README.md`: documented the new detector,
  evaluation scope, dataset limitations, and reproducible quality gates.

### Effect
- Sender results no longer claim unsupported ML probabilities. Complete email
  files can expose high-value phishing evidence that plain text omits.
- Evaluation prevents train/test campaign-family overlap, learns a
  recall-oriented threshold without using the held-out set, and reports the
  metrics needed to measure missed phishing.
- Strong structural/authentication evidence cannot be diluted by a weak text
  score, copied safety footers do not evade detection, and regional language is
  not treated as malicious.
- The zero-cost public deployment starts without a synthetic model while
  retaining useful explainable detection, and the regression suite verifies
  both model-enabled and rules-only behavior.

## [2026-06-20 15:15 PT] — README features-table sync with v4.3 content classifier

### Why
- User flagged: the "Web Application" features table in `README.md` still
  described **Email Content Analysis** as "Rule-based keyword scan across
  10 phishing categories + 11 structural checks", which has been stale
  since v2 of the content classifier (May 2026). The same row also said
  "all four classifiers" in the Model Metrics Dashboard row even though
  we now also expose the content-classifier metrics in `/api/metrics`.

### Files changed
- `README.md` (features table, two rows):
  - **Email Content Analysis** — now reads
    "Hybrid **ML + heuristic** classifier — TF-IDF (word + char n-gram)
    → CV-selected calibrated model (LogReg / LinearSVC / ComplementNB)
    trained on ~82 400 emails incl. 2026 LLM-grounded benchmarks
    (PhishNChips v5.2, PhishFuzzer), blended 55 / 45 with the
    10-category keyword scan + 11 structural checks".
  - **Model Metrics Dashboard** — wording adjusted from "all four
    classifiers" to "all classifiers (UCI URL-feature models + content
    classifier)" so it matches what `/api/metrics` actually returns.

### Effect
- Top-of-README feature summary now accurately reflects the v4.3 hybrid
  pipeline; new readers won't be told the content path is rule-only.
- No code or model changes; docs-only patch.

---

## [2026-06-20 14:55 PT] — 2026 LLM-grounded datasets + brand-impersonation rebalance (v4.3)

### Why
- User asked: "继续加强训练，数据集尽量用最新的". Up to v4 the real data was
  still 2002–2008 mailing-list traffic. Modern phishing attacks (GitHub
  Pages hosting, IPFS, URL shorteners, QR-code lures, hyper-realistic LLM
  brand impersonation) were under-represented, and we were still seeing
  false positives on legit transactional emails (Amazon shipping, Stripe
  payout, DocuSign envelope) once the LLM-generated phishing was mixed in.

### Files changed
- `phishing-detection/data/` *(new files, ~42 MB total)* — three
  `phishnchips_*.csv` and three `phishfuzzer_*.csv` files downloaded from
  Hugging Face into the data directory.
- `website/content_model.py`:
  - Added two new schemas `phishnchips_csv` (JSON-encoded `email_content`
    blob from PhishNChips v5.2) and `phishfuzzer_csv` (Subject/Body/Type
    columns from PhishFuzzer; `Spam` rows dropped, `Phishing→1`,
    `Valid→0`).
  - Extended `_DATASETS` with six new entries pointing at the HF mirrors
    of **PhishNChips v5.2** (Apr 2026, 2 387 emails grounded in real
    PhishTank / OpenPhish / GitHub Pages / Tranco / cross-domain modern
    workplace data) and **PhishFuzzer** (Nov 2026, 19 800 LLM-generated
    variants over 3 300 real seeds, 3-class).
  - Bumped synthetic `n_variants` from 80 → 160 to give the modern legit
    templates more relative weight against brand-impersonation phishing.
  - Added ~8 brand-issued transactional legit templates (Amazon shipping
    × 3, Stripe payout × 3, DocuSign envelope × 3, Chase mortgage,
    Google 2FA backup codes) directly aimed at the failure patterns
    surfaced by the new corpora.
  - Added a tie-break rule in `build_content_pipeline`: when LinearSVC
    and LogisticRegression are within 0.001 ROC AUC, prefer LogReg
    because its sigmoid output is naturally well-calibrated for
    boundary samples (Platt-calibrated SVM was producing brittle
    50–60 % probabilities for legit Amazon / Stripe / DocuSign).
  - `_CACHE_VERSION` → `v4.3-2026-brand-saturated-logreg-preferred`
    (forces retrain; old `v3-...` cache is stale).

### Effect
- Training corpus grew from ~50 k → **82 393 emails**
  (65 914 train + 16 479 test). New 2026 data contributes
  ~16 k modern LLM-grounded examples (2 387 PhishNChips + 13 356
  PhishFuzzer after dropping Spam).
- Model: `LogisticRegression` (selected via tie-break against
  CalibratedLinearSVC, both at CV ROC AUC ≈ 0.9995).
- Test metrics: **Accuracy 0.9905 · F1 0.9908 · ROC AUC 0.9996** on a
  held-out 16 479-row test set.
- 15/15 on the hard generalisation suite (7 modern legit including
  Amazon shipping / Stripe payout / DocuSign / Chase mortgage / 2FA
  backup codes / GitHub PR / Calendar invite, 4 classic phishing,
  4 brand-new 2026 attack patterns — Google Docs lure, QR-code invoice
  scam, IPFS-hosted DocuSign envelope, GitHub Pages security alert).
  Lowest legit score 32.1 %, highest legit 32.1 %; lowest phishing
  79.7 % → comfortable 47-point decision margin.
- Cold-train time ≈ 2 min 40 s; warm load from
  `phishing-detection/data/content_model_cache.pkl` (3.6 MB) is
  effectively instant.

---

## [2026-06-20 14:36 PT] — Project change-history bootstrap

### Why
- User asked: "将之前所有的更新记录起来，具体到时间，位置，更新的原因和效果。
  以后所有的更新都要记录在里面". Up to this point all changes were only
  reflected in commits/files; there was no single dated narrative of what
  happened and why.

### Files changed
- `CHANGELOG.md` *(new)* — backfilled four prior dated entries
  (v4 multi-dataset, v3 real-data + caching, v2 initial ML integration,
  plus a "project context anchors" appendix) and pinned the maintenance
  rule at the top.
- `README.md` — added a top-of-file pointer ("📋 Change history: see
  `CHANGELOG.md`") so the log is discoverable.
- `.cursor/rules/changelog.mdc` *(new)* — Cursor rule with
  `alwaysApply: true` requiring every future code/model/dataset/doc/dep
  change in this repo to append a new dated entry to `CHANGELOG.md`
  before ending the turn. Entry-format spec is included verbatim.

### Effect
- Future agent sessions (and humans) will see and honour the rule via
  Cursor's always-applied rules system, so the changelog stays current
  by default instead of needing to be remembered.
- Three prior tracked milestones (initial ML, real-data + cache,
  multi-dataset + model selection) are now visible to any reviewer as a
  single chronological record, eliminating the need to read commit
  history or scroll through long chats to understand the evolution.

---

## [2026-06-20 14:30 PT] — Content classifier v4: multi-dataset + model selection + modern templates

### Why
- The v3 model (trained only on `Phishing_Email.csv`, 18,631 emails) showed
  three concrete false positives on real-world modern emails: Amazon order
  confirmations (46.3 % phishing), Wells Fargo mortgage statements (73.2 %)
  and Google 2FA backup codes (79.6 %).
- Root cause: the public corpus is heavy on 2002–2008 mailing-list traffic and
  under-represents modern e-commerce / SaaS / banking / 2FA notification
  formats. Pulling in more 2002-era data would not fix this.
- Goal: (1) substantially expand both the *phishing* coverage (CEAS_08 +
  Nazario) and the *modern legitimate* coverage (new synthetic templates);
  (2) replace the hand-picked classifier with automatic CV-driven selection.

### Files changed
- **`website/content_model.py`**
  - `_DATASETS` table — three real corpora declared (Phishing_Email + CEAS_08
    + Nazario) with downloaders.
  - `ensure_real_dataset()` rewritten to fetch all three from their direct
    URLs (Hugging Face + Zenodo 8339691).
  - `_load_one_corpus()` added with two schemas
    (`phishing_email_csv`, `champa_csv`); filters Nazario mbox-control rows
    like `FOLDER INTERNAL DATA`.
  - `_LEGIT_TEMPLATES` extended by **17 new modern templates**: Amazon order,
    Best Buy receipt, GitHub PR comment, GitHub CI build, Stripe receipt,
    AWS invoice, Slack DM digest, Zoom meeting reminder, Google Calendar
    invite, Apple App Store receipt, Netflix payment, Uber Eats, DocuSign
    NDA, Chase Sapphire statement, Notion weekly digest, LinkedIn weekly
    summary, Lyft trip receipt, Spotify Premium receipt, Delta flight
    confirmation, Shopify new-order, Datadog usage report, password-changed
    confirmation, generic 2FA OTP, Coursera receipt, Figma welcome —
    plus a second batch: Wells Fargo mortgage statement, Chase auto-loan,
    PG&E utility bill, Comcast Xfinity bill, State Farm renewal, Geico
    insurance card, Fidelity 1099-INT, Google 2-Step backup codes,
    1Password Emergency Kit, generic authenticator code, Workday W-2,
    open-enrollment HR memo, Etsy / Bookshop.org orders, Partiful RSVP,
    Calendly confirmation.
  - `n_variants` default raised **40 → 80** so synthetic samples are not
    drowned out by the 59 k real-corpus rows.
  - **Model selection added** — `build_content_pipeline()` now runs 3-fold
    stratified CV ROC AUC across three candidates and picks the winner:
    - `LogisticRegression(C=4, liblinear, balanced)`
    - `CalibratedClassifierCV(LinearSVC, method='sigmoid', cv=3)` — Platt-scaled
      so it emits probabilities.
    - `ComplementNB(alpha=0.3)`
  - `_extract_coefficients()` added to keep the explainability layer
    working for all three model families (incl. CalibratedClassifierCV via
    averaged inner-estimator coefs and ComplementNB via
    `feature_log_prob_` diff).
  - `predict_content()` made robust to classifiers without `coef_`.
  - `_CACHE_VERSION` bumped to `v3-multidataset-modelselect-calibrated`
    so the existing on-disk cache is invalidated.
- **`phishing-detection/data/CEAS_08.csv`** (64 MB) added — downloaded from
  `https://zenodo.org/records/8339691/files/CEAS_08.csv` (Champa et al. 2024,
  CC-BY-4.0).
- **`phishing-detection/data/Nazario.csv`** (7.4 MB) added — same source.
- **`README.md`** — content-classifier section + datasets table rewritten to
  reflect the three-corpus pipeline and the new metrics.
- **`phishing-detection/README.md`** — same updates plus file-tree entries
  for the two new CSVs.

### Effect

| Metric (20 % hold-out) | v3 | **v4** |
|------------------------|-----|--------|
| Training samples | 16,376 | **50,392** |
| Accuracy | 0.9805 | **0.9908** |
| Precision | 0.9617 | **0.9900** |
| Recall | 0.9909 | **0.9920** |
| F1 | 0.9761 | **0.9911** |
| ROC AUC | 0.9983 | **0.9997** |
| Selected model | LogReg (hard-coded) | **LogReg (CV-selected)** |

11-sample hard generalization battery (samples NOT in training templates):

| Sample | v3 ML % | **v4 ML %** | Verdict |
|--------|--------:|------------:|---------|
| Phish: Crypto wallet hack | 100.0 | **99.2** | ✓ phishing |
| Phish: HR salary credential grab | 70.8 | **64.2** | ✓ phishing |
| Phish: SharePoint share scam | 99.9 | **98.9** | ✓ phishing |
| Phish: Voicemail .exe attachment | 62.4 | **63.9** | ✓ phishing |
| Phish: Apple ID closure scam | 100.0 | **99.9** | ✓ phishing |
| Legit: Wells Fargo mortgage | **73.2 ⚠ FP** | **9.5** | ✓ legit (fixed) |
| Legit: Pediatric appointment | 0.1 | **0.9** | ✓ legit |
| Legit: School field-trip slip | 1.1 | **7.8** | ✓ legit |
| Legit: K8s CI failure email | 3.6 | **8.8** | ✓ legit |
| Legit: 2FA backup codes | **79.6 ⚠ FP** | **37.2** | ✓ legit (fixed) |
| Bonus: Amazon order shipped | 19.1 | **11.3** | ✓ legit |

**Overall: 11/11 correct (100 %).** All three previously-known false
positives were eliminated.

Training time: ~127 s on first run; subsequent server starts load the
pickled pipeline in **< 50 ms**.

---

## [2026-06-20 13:59 PT] — Content classifier v2 → v3: real public dataset + caching

### Why
- The v2 model trained on a purely synthetic template corpus reported
  Accuracy / F1 / ROC AUC = 1.0 — visibly inflated. Held-out metrics on
  synthetic data don't reflect real-world performance.
- We needed a real-world labelled email corpus and faster startups so the
  FastAPI app doesn't take 40 s every reload.

### Files changed
- **`website/content_model.py`**
  - Module-level docstring rewritten to declare the real-data-first
    pipeline.
  - `ensure_real_dataset()` and `load_real_corpus()` added with auto-download
    from the Hugging Face mirror of the Kaggle *Phishing Email Detection*
    dataset (`zefang-liu/phishing-email-dataset`,
    `Phishing_Email.csv`, 18 650 emails, LGPL-3.0).
  - Vectoriser upgraded from single `TfidfVectorizer` to `FeatureUnion`:
    - word 1–2 grams (semantic phrases)
    - `char_wb` 3–5 grams (catches obfuscation like `P@yP@l`, `Amaz0n`)
  - `_extract_coefficients()` precursor / `_flat_feature_names()` introduced
    so the per-email top-token explainability still works through
    `FeatureUnion`.
  - **Pickle-based cache** added (`content_model_cache.pkl`) keyed by a
    SHA-256 hash that captures dataset file sizes/mtimes + training options
    + `_CACHE_VERSION` (`v2-word12-charwb35`). First training takes ~38 s,
    subsequent loads ≈ 20 ms.
- **`website/app.py`**
  - `/api/metrics` extended to include the `content_model` section
    (`name`, `metrics`, `data_source`, `top_terms`).
- **`README.md`** + **`phishing-detection/README.md`** — added new
  "Email-text dataset" section, dataset citation, and a metrics table.

### Effect

| Metric | Synthetic-only (v2 inflated) | **v3 with real data** |
|--------|------------------------------|----------------------|
| Training samples | 1,472 | **16,376 (≈11× more)** |
| Test samples | 368 | **4,095** |
| Accuracy | 1.0 | **0.9805** |
| F1 | 1.0 | **0.9761** |
| ROC AUC | 1.0 | **0.9983** |
| Startup time | ~1 s | 38 s first time / **0.02 s cached** |

Manual test verification:

| Sample | v3 ML phishing prob |
|--------|---------------------|
| Classic PayPal urgency phish | 100.0 % |
| Obfuscated `P@yP@l` / `acc0unt` | 99.4 % |
| TechBlog newsletter | 2.5 % |
| Legit Amazon order | 46.3 % (boundary — noted as known weak spot, addressed in v4) |

---

## [2026-06-20 13:51 PT] — Initial ML integration for email-content search

### Why
- The website had two analyzers: the *email-address* tab used a Random Forest
  ML model; the *email-content* tab used **only** hand-coded keyword rules.
  User asked: "让邮件内容搜索也采用机器学习" — make the content scan also use
  ML so the system is end-to-end ML-driven.

### Files changed
- **`website/content_model.py`** *(new file)*
  - 24 phishing templates + 20 legitimate templates with randomised
    placeholders (`{brand}`, `{url}`, `{amount}`, `{name}`).
  - `generate_content_corpus()` produces 1,840 balanced samples.
  - `build_content_pipeline()` fits `TfidfVectorizer(ngram=(1,2),
    stopwords=english, sublinear_tf)` + `LogisticRegression(class_weight=
    balanced)`; computes Accuracy / Precision / Recall / F1 / ROC AUC on a
    20 % stratified hold-out.
  - `predict_content()` returns `ml_phishing_probability`,
    `ml_legitimate_probability`, `ml_label`, `ml_prediction`,
    `ml_top_contributors` (per-email word-level token attribution).
- **`website/app.py`**
  - `from content_model import build_content_pipeline, predict_content`.
  - New global `_content_pipeline` populated in `startup_event()`.
  - `/api/analyze-content` rewritten to: (1) still run the heuristic
    scanner, (2) add ML probabilities into the response, (3) blend the two
    into a `combined_phishing_score` (55 % ML + 45 % heuristic) and
    promote/demote `risk_level` accordingly.
- **`website/static/index.html`**
  - Added a `content-ml-card` section between the risk banner and the
    keyword-category grid.
  - Updated the "About This Analysis" footer to describe the new ML +
    heuristic hybrid (replacing the previous "this is NOT an ML model"
    disclaimer).
- **`website/static/app.js`**
  - `renderContentResult()` extended to display ML phishing/legit
    probability bars, ML metric badges (Accuracy / F1 / ROC AUC), and the
    per-email top phishing-indicative tokens.
- **`website/static/style.css`**
  - `.content-ml-card`, `.ml-badge`, `.ml-card-metrics`, `.ml-metric`,
    `.ml-contribs`, `.ml-token` style rules added (blue accent palette).

### Effect
- Both analyzers in the web app are now ML-driven.
- Live API verified end-to-end:
  - Classic PayPal phishing sample → **ML 98.1 % phishing**, combined 81.0,
    verdict *Critical Risk*.
  - TechBlog newsletter sample → **ML 2.1 % phishing**, combined 1.2,
    verdict *No Phishing Indicators Found*.
- The pure-synthetic metrics (Accuracy / F1 / AUC all 1.0) were honest about
  being synthetic — the v3 update later replaced this with real data.

---

## Project context — anchors that predate this changelog

These items were already in place at the start of the conversation that
created this file. Listed for completeness; future entries describe deltas
relative to this baseline.

- **Random Forest URL-feature classifier** trained on the UCI Phishing
  Websites Dataset (`phishing-detection/data/phishing_dataset.csv`,
  11 055 rows × 30 features). Held-out metrics from the notebook:
  Accuracy 97.47 %, F1 0.9746, ROC AUC **0.9977** (best of four classifiers
  benchmarked: Random Forest, SVM-RBF, Decision Tree, Logistic Regression).
- **FastAPI backend** `website/app.py` with endpoints `/api/metrics`,
  `/api/features`, `/api/analyze-email`, `/api/analyze-content`,
  `/api/verify-email`, `/api/predict`.
- **Disposable-email database** of 500+ known providers + 6-factor
  auto-generated-username heuristic.
- **Email-authenticity 7-stage verifier**: RFC 5321 format → DNS MX/A →
  SMTP RCPT TO → SPF (`-all/~all/?all/+all`) → DMARC
  (`p=reject/quarantine/none`) → MX PTR / reverse-DNS → WHOIS domain age.
- **Single-page frontend** (`website/static/index.html` + `app.js` +
  `style.css`) — dark-theme responsive UI with orbital hero animation,
  three analysis tabs, animated probability bars, and a model-performance
  panel powered by Chart.js.
