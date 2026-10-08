# SMS Scam Detection Implementation Plan

> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a rule-based SMS mode to PhishGuard: a separate module and endpoint behind a feature
flag, reusing the plain-text email rules, calibrated on public data and the owner's first batch of
texts, and launched only if the owner's held-out batch meets the gate fixed in advance.

**Architecture:** `website/sms_analysis.py` holds pure functions (sender kinds, brand claims, SMS
rules, verdict). `website/app.py` adds the request model, the endpoint and the domain-age lookup.
The front end adds a third tab that reuses the existing result components.

**Tech Stack:** Python 3.12, FastAPI, plain JavaScript, `unittest`, Node's built-in test runner.

**Spec:** `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md`

## Global Constraints

- No email result may change. The shared scoring helper is checked against the served pipeline before and after.
- Add no runtime dependency (`tldextract` is already one).
- Texts are not retained; reports and evaluation outputs hold counts only.
- Every change gets its own CHANGELOG entry, and the full test suites run before each commit.
- Public datasets are downloaded only after their licences are checked and the owner agrees.

## Scope

- **In:** sender kinds, brand claims, the four SMS rules, the reused plain-text and link rules,
  `POST /api/analyze-sms`, `SMS_ANALYSIS_ENABLED`, the "SMS" tab, `website/tools/evaluate_sms.py`,
  tests, documentation.
- **Out:** screenshot (OCR) input, the text model, number reputation, official SMS short codes in
  the registries, cases and sender history for texts, new registry names (Amazon).

---

### Task 1: Branch and baseline

- [ ] Start from `main` once Lushangtu123/Phishing-Scam-Email-Detection#11 is merged; until then,
  stack the branch `sms-scam-detection` on #11, whose link rules the SMS mode reuses.
- [ ] Run `.venv/bin/python -m unittest discover -s website/tests` and
  `node --test website/static/*.test.mjs` as the baseline.

### Task 2: Shared scoring for the reused rules

**Files:** `website/app.py`, tests beside the existing content-rule tests.

- [ ] Move the points and floors of the keyword categories, `_fine_lure` and `_delivery_lure` out of
  `analyze_email_content` into small shared helpers, so both modes use one set of weights.
- [ ] Run `website/tools/evaluate_serving_pipeline.py` on the Nazario and genuine-mail cohorts before
  and after; the counts must be identical.

### Task 3: `website/sms_analysis.py`, test first

**Files:** `website/sms_analysis.py`, `website/tests/test_sms_analysis.py`.

- [ ] `classify_sender`: the ten kinds of the spec, full-width digits, zero-width characters,
  `+86`/`0086`/`+1` prefixes.
- [ ] `claimed_brand`: signatures (`【…】`, `[…]`) and the name a text opens with, from both
  registries; a later mention is not a claim.
- [ ] Links without a scheme, accepted when `tldextract` finds a public suffix.
- [ ] Rules: `sms.sender_mismatch`, `sms.sender_mismatch_weak`, `sms.link_off_brand`,
  `sms.reopen_to_activate`, `sms.fine_lure`, `sms.delivery_lure`, plus the reused rules.
- [ ] `app.analyze_sms`: the verdict through `fuse_content_risk` with no model reading; `unknown`
  when no rule fires.

### Task 4: Edge cases and risks

- [ ] Test that a personal text mentioning a brand is not a claim, that "Reply Y to confirm your
  appointment" does not fire, that a matching official number never lowers the score, that a
  forged official number is left to the content and link rules, that an empty or unreadable sender
  is `none`, and that text over 2,000 characters is rejected.

### Task 5: Endpoint and flag

**Files:** `website/config.py`, `website/app.py`, `website/tests/test_config.py`, a new endpoint test.

- [ ] `SMS_ANALYSIS_ENABLED`, off by default.
- [ ] `SmsRequest` and `POST /api/analyze-sms`: validation with localised 400 messages, the existing
  rate limits and security headers, the registration date of up to five link domains, 404 when off.
- [ ] `/api/config` reports the flag.

### Task 6: Messages and evidence codes

**Files:** `website/data/server_messages.json`, `website/static/i18n.js`,
`website/static/i18n-zh.js`, `website/tools/evidence_attribution.py`.

- [ ] Add every new code in English and Chinese, and to `_RULE_IDS`.
- [ ] Run `test_server_messages.py`, `test_evidence_attribution.py` and `i18n.test.mjs`.

### Task 7: The SMS tab

**Files:** `website/static/index.html`, a new `website/static/app-sms.js`,
`website/static/app-layout.js`, Node tests, visual baselines.

- [ ] A third tab and panel: sender field, text field with a count, Ctrl/⌘ + Enter, the privacy
  notice, synthetic examples; hidden when the flag is off.
- [ ] Results through the components of `app-content-render.js`, plus the "Sender" card.
- [ ] New `?v=` versions for changed files; check the tabs at 375 px; update the visual baselines.

### Task 8: Evaluation tool

**Files:** `website/tools/evaluate_sms.py`, `website/tests/test_evaluate_sms.py`.

- [ ] Verdict counts per cohort and label, and how often each rule fires on genuine texts.
- [ ] A test that no text or number reaches the report.

### Task 9: Calibration

- [ ] Check the licences of the Mishra and Soni SMS phishing dataset and the UCI SMS Spam
  Collection, and download them only with the owner's agreement.
- [ ] The owner prepares two batches of texts from both numbers as private JSONL outside the repository.
- [ ] Calibrate weights and Chinese phrases on the public data and the first batch.
- [ ] Record the launch gate in `docs/evaluation.md` before the held-out run.

### Task 10: Measure and launch

- [ ] Score the held-out batch once. If it meets the gate, turn on `SMS_ANALYSIS_ENABLED` in Vercel;
  otherwise keep it off.
- [ ] Record the results in `docs/evaluation.md`; update `docs/detection-design.md`, `docs/api.md`
  and the README; one CHANGELOG entry per change.

## Open questions

- When will #11 be merged? Until it is, the work stacks on it.
- How many texts can each batch hold? The 4% gate needs about 50 genuine texts per region per batch.
- Is a public Chinese SMS dataset with a clear licence worth looking for? Both planned public sets are English.
