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

Older entries are archived by month in [docs/changelog/](docs/changelog/): [September 2026](docs/changelog/2026-09.md), [June 2026](docs/changelog/2026-06.md).

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [2026-10-21 13:05 PT] — Candidate phishing groups from headers, version 2

### Why
- **The calibration plan needs countable phishing families.** v1 (`split_by_family.py`) merges phishing on an organisational sender domain. On the 3,657 phishing_pot messages added after `49f63777`, one such key held 2,114 messages from 1,800 distinct addresses inside a 2,266-message group (headers only, counts only). That key may cause false merges; neither its identity nor campaign membership is established.
- **Approved and authorized.** The owner approved the v2 design on 2026-10-21 (K = 20, P = 0.5, 256 KiB header limit, cross-field links kept, template hubs reported only, a separate tool, `owner-01` confirms domains), with two added rules. The owner authorized the implementation on synthetic inputs only, up to PR and CI, not merged.

### Files changed
- `website/tools/phishing_candidate_groups_v2.py` (new):
  - copies follow a trusted manifest, and files are read up to the first blank line;
  - v1's keys are kept, with thread links added;
  - a confirmed diffuse domain no longer merges on its own;
  - the report holds counts only, and flagged domains go to a private list.
- `website/tests/test_phishing_candidate_groups_v2.py` (new, 23 tests, synthetic).
- `docs/superpowers/specs/2026-10-21-phishing-candidate-groups-v2.md` (new): the approved design in English.
- `docs/evaluation.md`: "Candidate phishing groups, version 2 (2026-10-21)".

### Effect
- **Unchanged.** `split_by_family.py`, its tests, the v1 ledger, the served analysis, the model, the rules and the thresholds.
- **Acceptance criteria.** S1–S13 are met on synthetic inputs. All 19 planted defects make tests fail, and 346 of 349 executable lines are covered. There are 0 network attempts.
- **Not done.** No real mail was read: the tool has not been run on phishing_pot, and no domain has been confirmed.

## [2026-10-20 23:09 PT] — certifi 2026.10.19: a security exception to the cooling period

### Why
- **The advisory.** GHSA-6q48-6c7w-9gw2 (critical, published 2026-10-20): certifi bundled emSign root CAs whose intermediate CA keys were compromised. The deployment lock held the affected 2026.7.22, reached through tldextract → requests.
- **The patched versions.** The maintainer's advisory lists 2026.10.18 as patched. GitHub's advisory recommends 2026.10.19, which also restores roots that were not affected.
- **The cooling period.** 2026.10.19 was uploaded on 2026-10-20 at 02:24 UTC, under the 7 days the project requires. The owner approved an exception for certifi alone on 2026-10-20. Every other package keeps the period, scikit-learn included.

### Files changed
- `pyproject.toml`: `exclude-newer-package = { certifi = "2026-10-20T03:00:00Z" }`. The global `exclude-newer` stays at 2026-10-03.
- `uv.lock` (uv 0.12.23, `uv lock --upgrade-package certifi`): certifi 2026.7.22 → 2026.10.19 and the per-package cutoff; nothing else changes.
- `requirements-dev-py312-macos-arm64.lock.txt`: certifi 2026.10.19, with a note.
- `docs/deployment.md`: the exception, how it was verified, and what is still open.

### Effect
- **Verified.**
  - The lock's sdist and wheel hashes equal PyPI's (`035c1e85…`, `42d35340…`).
  - `uv lock --check` passes, and `uv pip check` passes on the development environment (40 packages).
  - The Vercel runtime smoke test passes.
  - The unit suite, compileall, ruff and the frontend tests pass (see the PR).
- **Still open.** This replaces only certifi's own trust store. The app's outbound HTTPS uses the standard library's `urllib` and the system trust store. Two things are not verified:
  - whether Vercel's runtime points `SSL_CERT_FILE` at certifi;
  - whether the system store trusts the affected roots.
- **Next round.** Pillow (optional vision service only) waits for the next upgrade round.

## [2026-10-20 20:29 PT] — Reviews in the public evaluator

### Why
- A draft of criteria for a calibration experiment counts the work a person does on legitimate mail as alerts, reviews and Unknown. The draft is kept outside the repository and is not approved.
- Only the serving evaluator reported reviews. The public evaluator dropped the review mark, so its reports could not give that count, and a missing count must not be read as zero.
- The owner authorized this implementation on 2026-10-20, on synthetic inputs only, up to PR and CI. It is not merged.

### Files changed
- `website/tools/evaluate_public_corpus.py`:
  - each analysis's `model_only_review` mark is kept in memory (`_review`);
  - `plan_counts` reports per label `alerted`, `reviewed`, `passed` and `undetermined`, by the serving evaluator's `_plan_counts`, and on legitimate mail also `attention` and `attention_with_undetermined`;
  - `plan_scoring_sha256` versions them on their own; `scoring_sha256` is unchanged.
- `website/tests/test_public_plan_counts.py` (new, 5 tests, synthetic).
- `docs/evaluation.md`: "Reviews in the public evaluator (2026-10-20)".

### Effect
- **Checks.** Same counts as the serving evaluator on 11 synthetic analysis results. Failures are counted as Unknown, never as reviewed.
- **Golden replay.** `343af04` against `69b7e61`: 19 captured `evaluate_corpus` calls and two command-line runs are byte-identical outside the new fields and the pre-listed run metadata.
- **CI and tests.** The CI synthetic baseline passes unchanged. All 6 planted defects fail the tests, and all 17 added statement lines are covered.
- **What to expect.** By the source code, the served option A does not set the review mark (only option C does, on original messages), so a public cohort's `reviewed` should be 0 today. This is an inference from the source, not a measurement: this change was measured on synthetic inputs only, and no public cohort was rerun.
- **Unchanged.** No served analysis, model, rule or threshold changes.

## [2026-10-20 13:46 PT] — P1/P2 pairing tool: fixes after the review of 7a4bb93

### Why
- A technical review of `7a4bb93` (PR #83) found five problems and held the merge:
  - argument errors echoed their values;
  - extraction errors left the in-process entry with their own message;
  - the report could overwrite an original;
  - a file named twice was read twice;
  - criterion 6 had no comparison with the pinned commit.
- The entry below claimed criteria 3, 6 and 8 as met. That said more than had been shown at `7a4bb93`. It stays as it was; this entry corrects it.
- Still authorized for synthetic inputs only, up to tests, PR and CI. Not merged; no real mail, 1a measurement, download or key collection.

### Files changed
- `website/tools/evaluate_paired_modes.py`:
  - one snapshot per file, by device and inode;
  - a single exception boundary: every failure leaves as `PairedRunError` with a fixed message and no cause or context;
  - argument errors in one fixed line (exit status 2), with abbreviations off;
  - the report path refused, before the model loads, if it names the input or any original through the same path, an alias, a symbolic link or a hard link;
  - from the command line, each set report carries its mode's run metadata, so its sidecars name the evaluated commit (they named none).
- `website/tests/test_paired_modes.py`: 5 new tests, 19 in all, synthetic only.
- `docs/evaluation.md`: a dated correction section after the original results table, which is kept. `docs/data-and-model.md`: the read-once and output rules.

### Effect
- **Criterion 6 against the pinned commit.** The branch's tool and `evaluate_serving_pipeline.py` at `52b091c9f131495aa5746d736ea30a85df7ba888` both ran from the command line, on the ten synthetic sources, with the committed model and the network guard (0 attempts). The four set-and-mode reports (4, 4, 2 and 1 evaluated rows) are byte-identical outside the run metadata that names a checkout. The sidecars are identical except their evaluated commit.
- **Planted defects.** All 19 made tests fail: criterion 11's eleven, run again, and eight for the fixes.
- **Unit suite.** 1,465 tests pass (15 skipped); the 532 frontend tests pass.
- **Not changed.** The long-token timing stays a separate case. No serving module, model, rule or threshold changes.

## [2026-10-20 10:39 PT] — P1/P2 pairing tool, on synthetic inputs

### Why
- The owner approved the step 1 criteria (#80) and the pairing design (#82) on 2026-10-20. The implementation is authorized for synthetic inputs only, up to tests, PR and CI, not merged.
- Not authorized: real mail, the 1a measurement, downloads and key collection.
- The design's acceptance criteria were fixed before the implementation. Its golden comparisons use the pinned commit `52b091c9f131495aa5746d736ea30a85df7ba888`.

### Files changed
- `website/tools/evaluate_paired_modes.py` (new):
  - each original is read once into a trusted snapshot after validation, holdout refusal and cleaning;
  - duplicates are decided by the smallest source digest;
  - sources fall into pairs, P1 only, P2 only and neither, with counts, reasons and set digests only (`null` with an unhashed member);
  - empty sets get no evaluator call;
  - errors are position-free;
  - the 3 × 3 decision table stays in the private report.
- `website/tools/evaluate_serving_pipeline.py`: `evaluate_records(snapshots=…)`, an in-process entry for bytes already read. It refuses snapshots for rows without `eml_path`, and a list that does not match the rows. `_read_eml` keeps its check in `_checked_eml`.
- `website/tests/test_paired_modes.py` (new, 14 tests, all synthetic).
- `docs/superpowers/specs/2026-10-20-false-alert-diagnosis-criteria.md`, `docs/superpowers/specs/2026-10-20-p1-p2-pairing-design.md`: status lines record the owner's approval, its date and scope.
- `docs/evaluation.md`: results. `docs/data-and-model.md`: the tool.

### Effect
- **Criteria.** Design criteria 1–10 are met on synthetic inputs, and all 11 planted defects made tests fail.
- **Existing entry unchanged.** Without snapshots, `evaluate_records` on the 1,713 archived unit-suite inputs gives byte-identical results to the pinned commit: 2,227 evaluations, including 23 expected errors.
- **Found, not changed.** A plain-text `.eml` with one 55,000-character token takes the served analysis about 10 seconds.
- **Unit suite.** 1,460 tests pass (15 skipped).
- **Unchanged.** No serving module, model, rule or threshold changes. No real mail was read.

## [2026-10-20 10:10 PT] — Design: pairing P1 and P2 in memory

### Why
- Step 1 compares the owner's downloads read as `.eml` (P1) and as pasted text (P2), on the messages both modes actually analyse, paired by source. Since #81, reports give reason counts only, so the pairing must happen in memory within one run, and only aggregates may leave it.
- Design and acceptance criteria only. Two technical reviews' blockers are resolved; the last review judged the design ready for approval. Approving it and authorizing the implementation are the owner's own decisions: nothing is implemented, and no mail is read.

### Files changed
- `docs/superpowers/specs/2026-10-20-p1-p2-pairing-design.md` (new). It covers:
  - **Shape.** A thin new tool that reuses the existing evaluation logic.
  - **Reading.** The input is cleaned first, then each original is read once into a trusted snapshot. A source over 3 MiB gets no digest.
  - **Duplicates.** Stable representatives: the smallest source digest, never input order.
  - **Four sets by source.** Only counts and set digests leave the process; a "neither" set with an unhashed member has a `null` digest and an unhashed count.
  - **Conservation.** Over the validated input records, duplicate copies included.
  - **Prepared rows.** An in-process-only entry, with its protections and regression tests.
  - **Empty sets and errors.** Empty sets get zero counts and no evaluator call. Errors are position-free.
  - **The 3 × 3 decision table.** In the private report only.
  - **Criteria.** Eleven acceptance criteria, including a golden comparison at a pinned full commit SHA; the last lists eleven planted defects.

### Effect
- No code, rule, model or evaluation changes.

## [2026-10-20 09:32 PT] — Pasted cohorts without truncation or ARC lookups

### Why
- Step 1 of the false-alert diagnosis needs P2: the owner's original messages analysed as pasted text. The existing helper, `evaluate_local_review.pasted()`, had three faults:
  - it cut subjects to 500 and bodies to 50,000 characters without saying so;
  - it read messages with default ARC verification, so extracting a Google-sealed message could look up keys in DNS;
  - it kept only label, provider and date, so a `cohort_role: holdout` marker would be lost.
- The serving evaluator had no pasted mode. The criteria were fixed at `39cc7d7`, before the implementation.

### Files changed
- `website/tools/pasted_cohort.py` (new):
  - extraction with `arc_result=None`;
  - subjects over 500 characters, bodies over 50,000, and empty sources or sources over 3 MiB are excluded with a fixed reason, never truncated;
  - every non-content field is kept.
- `website/tools/evaluate_serving_pipeline.py`:
  - `--paste` (refused with a recorded mailbox) and `evaluate_records(paste=True)`;
  - exclusions counted by reason only;
  - `input_mode` in the configuration.
- `website/tools/compare_evaluations.py`: the input accounting adds pasted exclusions, and both reports must agree on `input_mode` and `paste_exclusions`.
- **Fixed after a technical review of `9ac7bec`:**
  - input rows go through `pasted_cohort.from_input()`, which drops internal fields, so a JSONL `_eml_bytes` can no longer replace the file `eml_path` names;
  - one size check covers files, bytes and strings, a string by its UTF-8 bytes;
  - a pasted report with exclusions passes the comparator against itself;
  - excluded rows' line numbers are no longer written.
- `website/tools/evaluate_local_review.py`: uses the shared extraction and reports `paste_exclusions`; `MAX_PASTE_SOURCE_BYTES` stays as an alias for `evaluate_llm_labeler.py`.
- `website/tests/test_pasted_cohort.py` (new, 10 tests). `website/tests/test_evaluate_local_review.py`: its over-limit test now expects exclusion instead of truncation.
- `docs/evaluation.md`: criteria and results. `docs/data-and-model.md`: the `--paste` mode.

### Effect
- **Limits.** 500/50,000 characters are kept and 501/50,001 excluded; a file over the 60,000-byte `.eml` limit whose text fits is kept whole.
- **No lookups.** Extracting a Google-sealed synthetic message records no outbound attempt, in process or from the command line; with default ARC verification the same message does attempt one.
- **Holdout.** Holdout rows stay refused in pasted mode.
- **Planted defects, rerun on the final code:**
  - restored truncation: 8 failures;
  - restored default ARC: 3;
  - internal fields kept: 1;
  - string limit skipped: 1;
  - comparator ignoring exclusions: 1.
- **Exclusion digests.** An excluded row's digest covers its reason and a little metadata, not the source file; the originals' version rests on the separately pinned input.
- **Unit suite.** 1,446 tests pass (15 skipped).
- **Unchanged.** Serving modules, model, rules and thresholds. No real mail was extracted or evaluated.
- **Not changed, found in passing.** `evaluate_llm_labeler.py` also reads messages with default ARC verification.

## [2026-10-20 09:07 PT] — Draft criteria: step 1, diagnosing false alerts on development data

### Why
- The diagnostic tools are complete (#76, #77) and the evaluators run without registry lookups (#78). The next step is to find which evidence the alerts on legitimate development mail are sensitive to, and what removing it would cost on phishing.
- The criteria must be fixed in writing before anything runs. This is a draft for the owner's approval: no mail is read, nothing is downloaded and nothing is measured.

### Files changed
- `docs/superpowers/specs/2026-10-20-false-alert-diagnosis-criteria.md` (new, draft, revised after a technical review). It covers:
  - **Pinned configuration.** One commit, model and input versions for the whole batch.
  - **Phase 1a only.** Inputs where ARC does not run: `.eml` with the mailbox recorded, and pasted text. Mail without a mailbox waits for offline ARC; no ARC-off run.
  - **Cohorts.** Expected counts with raw, deduplicated, excluded and successful counts reported. P1 and P2 are each validated, deduplicated and filtered, then paired by source message; only the actual intersection is compared (79 pairs and 13 pasted-only messages are expected, not certain). P3 is out.
  - **Failed replays.** `analysis_failed` is kept apart, never merged or dropped; transitions plus failures equal the baseline's alerts, and a family with unresolved failures is not routed.
  - **Phishing losses.** Alert-to-non-alert and alert-to-undetermined are reported separately.
  - **Undetermined results.** Only their co-occurring signals are reported, since the counterfactual tool replays alerts only.
  - **Routing lines.** Exploratory and always with n/N: 50% sensitivity to the outermost fusion's model probability; 30% for a rule family; "no main removal path located yet"; and 20% undetermined, out of all inputs.
  - **Network guard.** It covers every step that reads mail, including text extraction.
- **A finding the draft records.** `evaluate_local_review.pasted()`, the existing way to make pasted cohorts, silently truncates subjects and bodies and verifies ARC while extracting text. The criteria therefore require a separately approved extraction change before the batch.

### Effect
- No code, rule, model or evaluation changes.

## [2026-10-20 08:30 PT] — Design: offline ARC verification for evaluations

### Why
- After the evaluators stopped their RDAP and other service calls, ARC verification is the only remaining path to the network. For a Google-sealed raw message with no trusted result and no mailbox, it looks up the seal's public key in DNS.
- The zero-outbound result therefore covers only inputs without ARC seals. Live lookups also reveal when such a message is evaluated, and make results depend on DNS at the time.
- Design only, at the owner's request: nothing is implemented, no key is collected, and no mail is read or measured.

### Files changed
- `docs/superpowers/specs/2026-10-20-offline-arc-verification-design.md` (new). It covers:
  - **Snapshot.** A versioned, hashed snapshot of public keys. The expected whole-file hash sits in the external frozen configuration, and real snapshots stay outside the repository.
  - **Verification.** A snapshot mode for the evaluators only, with real `dkim.arc_verify` verification. A missing key is `unverified` and never falls back to live DNS; a withdrawn key (`p=` empty) fails.
  - **Isolation.** No key crosses between snapshots or between snapshot and live caches.
  - **Counting.** One primary ARC outcome per baseline input; replays are counted apart.
  - **Meaning.** A snapshot result reflects the snapshot's key state only. A key withdrawn after it can still verify in snapshot mode while live DNS refuses, so the two modes may differ, and bridging equality holds only where the key responses match.
  - **Criteria.** Eight criteria with six planted defects, fixed before any implementation.
  - **Settled choices.** The owner adopted four as this round's design choices: where a real snapshot lives, where selectors come from, when to collect, and snapshot mode for the frozen plan. A frozen snapshot is never overwritten; a later one is a new version with its own configuration. Settling the selector-source rule does not authorize reading any particular private or holdout mail.

### Effect
- No code, rule, model or evaluation changes.

## [2026-10-19 20:50 PT] — Evaluators without registry lookups, with their services recorded

### Why
- **RDAP inherited.** Both evaluators started from `vercel.json`, which has set `RDAP_LOOKUPS=true` since 2026-10-02 (`13c6da8`), and neither turned it off. A run therefore asked registries' RDAP servers about the registrable domains of the evaluated mail's sender and links, never addresses or URL paths, and those answers could differ between runs.
- **Wrong record.** The public evaluator recorded `network_services_enabled: false` regardless.
- **History.** Whether any earlier run on private mail looked domains up is not established. Only runs after 2026-10-02 could have, and it has to be checked against each run's date and configuration.
- The criteria were fixed at `0f59ced`, before the implementation, and must hold before the false-alert diagnosis of development data.

### Files changed
- `website/tools/evaluate_serving_pipeline.py`:
  - `OFFLINE_ENVIRONMENT` turns RDAP, sender history, Jev and the local review off;
  - `evaluation_environment()` builds the run's environment;
  - `external_services()` records the effective settings, including ARC key lookups for known sealers, which stay as served;
  - the configuration validator accepts the new keys.
- `website/tools/evaluate_public_corpus.py`: `public_evaluation_environment()` with the same services off. The report records the effective settings instead of a constant.
- `website/tests/network_guard.py` (new): refuses and records every connection, datagram and name lookup, in-process or from a child process's start (`sitecustomize`).
- `website/tests/test_evaluator_network.py` (new, 7 tests): environments, recorded settings, in-process runs (baseline, identity, all families, attribution) and command-line runs of both evaluators, with a positive control for each guard.
- `website/tests/fixtures/evaluation/baseline.json`: regenerated; see Effect.
- `docs/evaluation.md`: criteria and results. `docs/data-and-model.md`: the evaluators' services.

### Effect
- No outbound attempt in either evaluator, in process or as a command, on inputs with `.com` and `.net` sender and link domains. With RDAP on, the same in-process runs do attempt lookups.
- Zero outbound calls were verified only for this round's synthetic inputs, which carry no ARC seal. Mail with a seal can still trigger DNS lookups of ARC keys, so the evaluators are not yet fully offline.
- **Recorded settings.** RDAP, sender history, Jev and the local review are off. `network_services_enabled` stays `true` because ARC verification may still look up `google.com` signing keys for sealed messages without a mailbox. That is a separate decision.
- **Planted defects.** RDAP left on failed 4 tests; a constant `network_services_enabled` failed 3.
- **Comparisons.** `compare_evaluations.py` treats reports from before and after this change as having different configurations.
- **CI baseline regenerated.** `website/tests/fixtures/evaluation/baseline.json` (synthetic, 2026-09-21) was regenerated with this evaluator, because the CI comparison against it failed with "Incomparable configuration". Only its `reproducibility` block changed; every metric, count and cohort digest is identical.
- **Unchanged.** Serving modules and `vercel.json` (production keeps RDAP).
- **Unit suite.** 1,429 tests pass (15 skipped).

## [2026-10-19 20:39 PT] — Correction to the tools v2 entry: D was partly verified, E deviates; follow-up tests

### Why
- The entry of 2026-10-19 20:16 and the results in `docs/evaluation.md` said more than was shown. A Codex technical review found two overstatements:
  - **D:** in attached messages, only text requests had points and floor checked; shortened links in attachments were not checked either.
  - **E:** `requested_question` changed outside the criterion's list.
- The original criteria and results stay. This entry corrects them and records the follow-up tests apart.

### Files changed
- `docs/evaluation.md`: a correction and a follow-up section under "Counterfactual and attribution tools, version 2". The original table is unchanged.
- `website/tests/test_counterfactual_families.py`, 7 more tests:
  - **D:** lures, HTML tricks, weak cues and intent rules in an attached message; a shortened link in an attachment. Each checks points, floor and aggregation by maximum.
  - **E:** `requested_question` against the existing conditions of `_apply_requested_answer` on 4 account notices and 2 controls; an attached notice's result is unchanged.

### Effect
- **Correction to the 20:16 entry:**
  - D was partly verified at `d7bf89a`.
  - E deviates from its list as written. A Codex technical review judged the `requested_question` change a reasonable derived change. That is not the owner's acceptance, and it is separate from D12.
- **Follow-up results:** all 7 tests pass.
- **Planted defects:**
  - a mixed-script cue at 2 points instead of 3: 3 failures;
  - attached messages also fused without the model probability: 1 failure;
  - `requested_question` always true in this family: 14 failures, counting subtests;
  - "always false" passes, as it should: without a model probability in the outermost fusion the question cannot hold.
- No tool, rule or serving code changed.

## [2026-10-19 20:16 PT] — Counterfactual and attribution tools, version 2

### Why
- A coverage check on the unit suite's 1,713 synthetic inputs (archived outside the repository) found that the diagnostic tools missed most of the strong rules. No counterfactual family removed the text requests, lures, password forms, hidden padding, attachment text or weak cues, and attribution counted only twelve link rule IDs.
- The replays also ignored the baseline's mailbox setting and intent rules, kept attached messages' structure evidence and skipped attachment link rules.
- The tools must be complete before the false-alert diagnosis of development data, which has its own criteria. Criteria A–H were fixed at `803b08f`, before the implementation.

### Files changed
- `website/tools/counterfactual_evidence.py`:
  - **Analyzer and identity.** Replays run through the evaluation's own analyzer. Each alert is first replayed with no intervention, which must reproduce the baseline byte for byte, or the tool stops.
  - **Six new families:** `text_requests`, `lures`, `html_tricks`, `weak_cues`, `intent_rules` (only when rules are on) and `outer_fusion_without_model_probability`. Each removes its evidence where it is found, with its points and floor.
  - **Fixes:** `message_structure` clears attached messages at every depth; single link rules also match by code.
  - **Sidecar:** `counterfactual-evidence/v2`, with the tool file's SHA-256 and the evaluated commit.
- `website/tools/evidence_attribution.py`:
  - every content and link finding by code, from a fixed list of 60 codes, once per input;
  - unknown codes only as `code.unrecognized`, which marks coverage incomplete;
  - `link.ipfs_gateway` added to the rule IDs;
  - sidecar `evidence-attribution/v2`.
- `website/tools/evaluate_serving_pipeline.py`, `website/tools/evaluate_public_corpus.py`: pass their analyzer to the replays; the public evaluator's own hash includes the attribution tool.
- `website/tests/test_counterfactual_families.py` (new, 19 tests). Also `test_counterfactual_evidence.py` (fakes answer the identity replay), `test_evidence_attribution.py` (+3) and `test_public_evaluation.py` (+1 command-line test).
- `docs/evaluation.md`: the criteria (committed first) and the results. `docs/data-and-model.md`: the sidecars' description.

### Effect
- **No serving change.** With RDAP off, the 1,713 baselines are byte-identical on `main` and the branch.
- **Identity.** It holds for all 1,713 inputs under two sets of settings.
- **Version 1 families.** They differ only on the 14 inputs whose attached messages carry structure evidence. No decision changed.
- **Coverage.** All 26 codes that no family removed are now removed wherever they appear.
- **Outer fusion family.** It changed only the fusion results, plus `requested_question` in 12 inputs. That key follows from the fusion basis but is not on the criterion's list; it is reported, not added afterwards.
- **Planted defects.** Three were planted, and each failed tests.
- **Statement coverage.** 202/208 and 80/87; only version 1 error branches were missed.
- **Unit suite.** 1,422 tests pass (15 skipped).
- **Found, not changed.** Both evaluators keep `vercel.json`'s `RDAP_LOOKUPS=true`, so a run looks up the evaluated mail's sender and link domains at registries' RDAP servers, and those answers vary between runs. It needs a decision before any run on private mail.

## [2026-10-19 17:41 PT] — Data licenses: what each data source states, with revisions and attribution

### Why
- Using PhishGuard in one company's analyst-assisted investigations needs the data's licenses checked alongside the evaluation. The owner asked for an inventory of every training and evaluation source.
- Read only: license pages, dataset cards, `LICENSE` files and the metadata APIs of Hugging Face, Zenodo, Mendeley Data and GitHub. No dataset was downloaded. The conclusions are for the owner or legal counsel.

### Files changed
- `docs/data-licenses.md` (new). For each source: revision, stated license, commercial use as stated, attribution, and what is uncertain. Covers:
  - the 7 corpus files of the served model, plus its 1,044 project-written hard negatives;
  - the 6 reference files shipped in `website/data/`;
  - the UCI benchmark shown on the site;
  - 12 evaluation-only sources.

  Also an attribution section and 8 open questions.
- `docs/evaluation.md`: PhishFuzzer's license cell (2026-09-29 table) corrected. CC BY 4.0 is the arXiv license of the paper; the dataset has none.
- `docs/data-and-model.md`, `README.md`: link to the new page.

### Effect
- **Served model** (artifact `a0a503a0…1746`):
  - **Revisions:** each training file's SHA-256 matches the source at a fixed revision: Hugging Face `34085a03` and `89afcc39`, Mendeley SpaPhish version 1/2, Zenodo 8339691 by MD5.
  - **Commercial use is unclear.** In PhishNChips `core_emails.csv` (2,000 rows), 66 rows carry OpenPhish URLs permitted for academic research only, and 662 Tranco domains are used under academic-use norms. `Phishing_Email.csv` is LGPL-3.0. CEAS 2008's own terms were not found.
- **Repository and deployment:** the repository is public with no `LICENSE`. It and the deployment bundle hold a copy of the Spamhaus DROP lists (1,783 networks), whose terms grant no license.
- **Evaluation sources:**
  - **Not allowed commercially, or no license:** phishing_pot (CC BY-NC 4.0), UniqueData (CC BY-NC-ND 4.0), PhishFuzzer (no license), SpamAssassin easy_ham (no license; copyright with the senders).
  - **No recorded origin:** DataCon 2023 day 1 and the trec06c sample.
- No code, model, rule or verdict changed.

## [2026-10-15 08:55 PT] — Design: PhishGuard's own DKIM verification; checklist: can the holdout meet D10 and D11

### Why
- The owner agreed an order of work: the independent evaluation first; DKIM self-verification designed alongside it; enterprise context last.
- This step is design and preparation only. Nothing is implemented, enabled or scored.

### Files changed
- `docs/superpowers/specs/2026-10-15-dkim-self-verification-design.md`:
  - **What it checks:** the uploaded raw bytes' own DKIM signatures (dkimpy, already pinned), through a guarded, bounded DNS resolver.
  - **What it reports:** "no signature", "pass", "fail" and "could not be checked", kept apart, with relaxed and strict alignment to `From`, as a separate evidence type beside `mailbox`, `server` and `arc`.
  - **Wording:** it names the evidence ("PhishGuard verified the DKIM signature of example.com"), never "verified email".
  - **Phase 1:** information only, off by default. Its effect on `authenticated_sender` is a later, separately evaluated decision.
  - **Freeze:** kept apart from the 2026-10-13 plan's baseline.
  - **Criteria:** five, fixed before any implementation.
- `docs/superpowers/specs/2026-10-15-holdout-feasibility-checklist.md`:
  - **Targets:** D10 (400 messages over the four provider-language cells, 30 authenticated phishing, the decisive subset) and D11 (behaviours and control types), with family rules and sources.
  - **What may be counted:** counts, sources and families, and authentication from the frozen structure analysis. No candidate output is looked at.
  - **Decision points:** D10 and D11 met; D10 met but not D11 (split in writing before the first scoring, thresholds unchanged); D10 not met; D12 not met.
  - **A report template.**

### Effect
- No code or served behaviour changes. The plan stays unfrozen, and no holdout row is scored, until D12 records a real, confirmed independent reviewer.

## [2026-10-15 08:12 PT] — Text rules read Cyrillic or Greek look-alikes inside Latin words as Latin, and report them

### Why
- The owner asked whether a Cyrillic а in place of a Latin a is caught. In domains and display names it was. Inside body words it got past the rules: with the served model, an uploaded `.eml` asking to reply with a password was Critical in Latin letters and **Low** with Cyrillic а.

### Files changed
- `website/content_rules.py`:
  - **New helpers:** `_mixed_script_words` and `_fold_mixed_script`, using the look-alike map the domain checks already use.
  - **What counts:** a word is a run of Latin, Cyrillic or Greek letters, with invisible format controls inside it. It counts when it has at least 3 letters, a Latin letter, a look-alike, and nothing else.
  - **Where it applies:** `_text_rule_findings` (email, hidden text requests, SMS) and attachment text read such words as Latin.
  - **The new finding** `content.mixed_script_words` (Medium, 3 points) reports them.
- `website/app.py` — the mail lure rules read their text and button labels the same way. The new finding joins the impersonation tactics of the mail-type note.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the finding's text in English and Chinese. Asset versions: `i18n.js` v151, `i18n-zh.js` v75, `lang-init.js` v78.
- `website/tests/test_mixed_script_words.py` (7 tests).
  - **Controls:** text wholly in Cyrillic or Greek, symbols such as `μg` and `TGF-β`, Chinese beside a Greek letter, a two-letter fragment, and a Russian word with a stray Latin letter.
  - **Paths:** requests, the mailbox lure and its button, attachments, SMS and an uploaded `.eml`.
- `docs/evaluation.md` — the criteria, fixed before the first run and committed first; both runs; the tightening; the results.

### Effect
- **First run:** the criteria passed, but 4 of 36,567 legitimate public rows got the finding, none of them a disguised Latin word. The definition was tightened after looking at those 4 development rows.
- **Results after tightening:**
  - **Public corpora:** 0 of 36,567 legitimate rows get the finding. Of 38,545 phishing rows, 30 get it, and 16 change level (1 newly alerted).
  - **Golden replay:** 8 of 4,802 items change, all of them with mixed-script words. Everything else is byte-identical to `main`.
  - **Planted bugs:** disabling the mapping, or the detection, fails 8 tests each.
- **Not changed:**
  - the text model's input;
  - words wholly in look-alike letters;
  - SMS-only rules.

## [2026-10-14 20:51 PT] — Evaluation: human-written and LLM-rewritten mail through the served pipeline

### Why
- The owner asked whether AI-written scams get past the project. Before changing anything, the served pipeline (rules, fusion, abstention and the served model) was measured on PhishFuzzer's human seeds and their own LLM rewrites. The earlier comparison (2026-09-29) scored the model recipe alone.

### Files changed
- `docs/evaluation.md`, section 5 — the criteria (fixed before the run), the counts by era and label, the results against the criteria, an exploratory per-seed check, the reading and its limits.

### Effect
- **Detection is not lower for LLM-rewritten phishing:**
  - recent seeds 85.4% and their variants 90.0%;
  - legacy seeds 99.1% and their variants 98.4%.
- **False alerts rise for legacy-style legitimate mail:**
  - seeds 2.1% (21 of 998) and their variants 7.3% (437 of 5,988), with non-overlapping 95% intervals;
  - per seed: 210 seeds with a flagged variant only, against 12 the other way.
- **Recent-style legitimate mail:** 61.8% with the seeds and 70.9% with their variants, with overlapping intervals ("no difference shown"). It is flagged far more than either effect.
- **Scope:**
  - development data, counts only;
  - no code or served behaviour changes;
  - the PhishFuzzer seed file was downloaded with the owner's approval to the git-ignored `.evaluation-data/`;
  - scripts and outputs are archived outside the repository.

## [2026-10-14 16:55 PT] — Case sign-out: a failed sign-out no longer promises an end "within 30 minutes"

### Why
- **The finding (P3):** the owner's security re-review of `51e9c9d` found that when the case storage could not end a session, `DELETE /api/cases/session` answered 503 with "the session ends on its own within 30 minutes".
- **Why that is wrong:** the 30 minutes is an idle limit that slides with each request. Whoever holds the session ID can keep it alive until 8 hours after sign-in, and the review showed it still valid at minute 31 with use.
- **A second point:** a 503 may also mean that the session was removed but the answer failed.

### Files changed
- `website/case_api.py` — the 503 says the sign-out could not be confirmed, in the owner's words: "Case storage is unavailable, so sign-out could not be confirmed. The session may still be active. An active session expires after 30 minutes without use or 8 hours after sign-in, whichever comes first." The status stays 503, and the page's handling is unchanged: it does not show this answer, and drops its session either way.
- `website/tests/test_case_sessions.py` — the failure is injected before anything is deleted (`CaseUnavailable` and `sqlite3.OperationalError`). The test checks:
  - 503, the exact message and `no-store`;
  - the session is still stored and still valid: with use it outlives 30 minutes, and after 30 minutes without use it ends (401).
- `docs/case-workflow.md` — what the sign-out API answers when storage is unavailable. It notes that this is the API's answer, and that how the page shows or handles a failed sign-out is a separate design task.
- `website/static/cases.test.mjs` — the boundary test's synthetic 503 carries the new message.

### Effect
- **Only the 503 message changes,** and only when storage cannot record a sign-out.
- **Planted bug:** with the old message restored, the new test fails for both failures.
- **Separate design task (not changed):** confirming revocation on the page, handling a failed sign-out, and background revocation (ASVS 7.2.4 server side).

## [2026-10-14 15:52 PT] — Case sessions: a damaged session record no longer passes the identity check

### Why
- **The finding:** the owner's security re-review of `096279c` (P2) found that a session record stored as "an analyst who is not configured, with an empty credential" was granted access by every case endpoint, with both session stores (Redis and SQLite).
- **The cause:** `identity()` looked up the analyst's configured digest with a default of `''` and compared it with the stored credential. `hmac.compare_digest('', '')` is true.
- **Reach:** the record has to be written wrongly, damaged or tampered with, and its session ID known. Sign-in cannot create it.
- **The rule:** a server that meets an abnormal identity must refuse it.

### Files changed
- `website/case_api.py`, `identity()`: before comparing, the stored analyst must be text and configured now, and the stored credential must be text and a SHA-256 hex digest (64 lowercase hex characters, as `CASE_ANALYST_TOKEN_HASHES` requires). Otherwise the session is closed and the request gets the same 401 as a rotated credential. A storage fault still gives 503.
- `website/tests/test_case_sessions.py`:
  - **Damaged records, through the real API:** `/api/cases/me` and `/api/cases`, on SQLite and on Redis (the production Lua, local Redis in CI). Each must give 401 and leave no record. The records:
    - the review's counterexample (an unknown analyst, empty credential);
    - an unknown analyst with a well-formed digest;
    - a configured analyst with an empty, uppercase or short credential;
    - on SQLite, a BLOB credential.
  - **Intact sessions** keep 200.
  - **A storage fault** while reading the session gives 503, not 401, and leaves the session in place.
  - The existing API tests' setup is shared with the Redis API class; the tests themselves are unchanged.

### Effect
- **Behaviour:** only damaged session records are affected. Sign-in, normal sessions, expiry, sign-out and credential rotation behave as before.
- **Planted bug:** with the old comparison restored, the counterexample gets 200 on both stores and both endpoints, so the new test fails. Before the fix, the SQLite BLOB credential raised an exception. The other damaged records were already refused.
- **Local run:** all 26 session and Redis tests pass against Redis 7.4.7 (the owner's cached image, pinned by digest).
- **Not changed (deferred):** validating records in `CaseSessions.resume()` itself, and server-side revocation at sign-out or re-authentication (ASVS 7.2.4).

## [2026-10-14 12:50 PT] — Correction: the re-authentication test shows a sign-out request, not a revocation (ASVS 7.2.4)

### Why
- The owner's review of #68 found that its test and its entry below (2026-10-14 12:09) claimed more than the test shows. The entry says the sign-out DELETE "ends the first session on the server", and names a planted bug "sign-out not ending the session".
- The test only checks that the page **sends** the DELETE and drops the old session before signing in again:
  - `endSession()` neither waits for nor checks the answer;
  - the harness answered every sign-out with 204.
  - With the DELETE answered 503, or never finishing, the test still passed. So it does not show that the server revoked the session.
- The entry is corrected here, not edited. The owner chose tests and docs only, with no change of behaviour.

### Files changed
- `website/static/cases.test.mjs`:
  - **The #68 test:** its title and comments now say what it checks: the page has sent its sign-out and dropped the old session, or the server refused it. Its assertions are unchanged.
  - **A new test for when the sign-out fails (503) or never finishes:** the page sends it once, signs out anyway, and from then on sends only the new session. Nothing confirms the server revoked the old one.
- `website/tests/fixtures/i18n/cases-scenarios.mjs` — a handler may now answer sign-outs itself (`handlesSignOut`); otherwise they still get 204.

### Effect
- **No change of behaviour.** Correctly read, the #68 entry's planted bug is "sign-out not sending its DELETE".
- **Planted bugs:** two each fail the new test: sign-out sending no DELETE, and the old session kept after the sign-out. Frontend tests: 532 of 532.
- **7.2.4 stays partly verified.** The page drops the old session when it signs out, but whether the server has revoked it is not checked: after a failed or unfinished sign-out, the old session may stay valid until its 30-minute idle or 8-hour limit. Guaranteeing revocation needs a server-side design, not made here.

## [2026-10-14 12:09 PT] — Case page: a test that re-authentication follows the end of the current session (ASVS 7.2.4)

### Why
- The owner's local security re-review of `d09a740` recorded ASVS 5.0.0 7.2.4 (a new session on re-authentication, and the current one terminated) as only partly verified. The case page already re-authenticates only once its session has ended or been refused, but no test fixed that. The owner chose a test only, with no change of behaviour.

### Files changed
- `website/static/cases.test.mjs` — one test, run with and without unsaved work:
  - no sign-in form is shown while a session is live;
  - after sign-out, the DELETE that ends the first session on the server comes before the second sign-in, and the first session is never sent again;
  - after the server refuses the session (401), the next sign-in follows that refusal, and every later request carries only the new session.

### Effect
- **No change of behaviour.**
- **Planted bugs:** three each fail the test: sign-out not ending the session, the sign-in form left visible, and the new session not adopted after a refusal. A fourth planted change (keeping a non-empty old token) cannot occur in this flow and does not fail the test.
- **Still open, unchanged:** the server does not end an earlier session at sign-in. Separate tabs keep separate sessions, and a client outside the page that keeps an old session keeps it until its 30-minute idle or 8-hour limit.

## [2026-10-14 10:37 PT] — Intent rules: an experimental evaluation wiring, off by default (默认关闭的实验性评估接入)

### Why
- Part 2 of the 2026-10-13 evaluation plan, step 1 of three that the owner authorizes one at a time. The draft credential-handover and payment-redirection rules are wired into the content analysis **off by default**, so the evaluator's `--intent-rules` (#66) can run them. Steps 2 and 3 (a golden replay with the rules off; the rules on for the development cases with the served model) are not part of this change, and no rule is turned on in production.

### Files changed
- `website/intent_rules.py` — the draft rules, English and Chinese. The patterns are the version the owner reviewed (SHA-256 `23ff83fd…`) and are not changed here.
- `website/app.py`:
  - `INTENT_RULES` is `intent_rules.ENABLED` itself, so the evaluator's switch is what the rules read. It is empty by default.
  - `IMPLEMENTED_INTENT_RULES` names both rules.
  - `analyze_email_content` calls `intent_findings` after the lure rules, on the same renderings with their labelled links. Each matching rule counts once, with 3 points and a Medium floor.
  - Text that styles may hide is not read; this coverage limit is documented.
  - No request field, query parameter, setting or environment variable sets the switch.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`:
  - `content.intent.credential_handover` and `content.intent.payment_redirection`, in English and Chinese. Without them, every hit raised `KeyError`.
  - Asset versions: `i18n.js` v149, `i18n-zh.js` v74, `lang-init.js` v77, and the HTML references to them.
- `website/tests/test_intent_rules_wiring.py` (6 tests, committed fixtures only):
  - off by default on all 78 fixtures, and no request, query or environment variable turns a rule on;
  - one hit adds 3 points, a Medium floor and nothing else; hidden text is not read;
  - the switch is restored after a failed analysis, and stays within its task or thread.
- `website/tests/test_intent_rule_evaluation.py` — now checks that both rules are implemented behind the rules' own switch. A build without a rule still refuses it.
- `docs/evaluation.md`:
  - the criteria section's preamble is corrected: D8 is judged on the public corpora, and D6, D7 and D9 on the holdout;
  - the results of criteria 1 and 3, and the wiring with its coverage limit;
  - the evaluator section updated.

### Effect
- **No change in service:** the switch is empty there.
- **Development numbers, counts only:**
  - Criterion 1: 45 of 45 positives and 0 of 30 controls, after a first run of 27 of 45 that failed. The rules were written on these fixtures, so this is a check, not evidence.
  - Criterion 3: of 36,567 legitimate public rows, 12 match the credential rule and 0 the payment rule (the bound is 36). None of the 12 is a real request for a secret or a mislabel; no exception was added.
- Five planted bugs each fail at least one test: switch on by default, 4 points, a separate evaluator switch, findings counted twice, switch not restored.
- Criterion 4, a golden replay with the rules off (step 2): of 4,790 inputs, all are byte-identical to `main` `6d5a613`. These are the unit suite's 1,545 content-analysis calls and 523 raw messages, the 78 fixtures (twice), and 2,043 public-corpus rows, all with the served model. A planted bug (the rules on by default) changes 178. Statement coverage of the changed code is 100%.
- Criterion 2, the rules on with the served model, pasted (step 3): both assessment misses go from Low to Medium, and #60's reproduction stays Critical. Development positives alert 45 of 45 (31 with the rules off), and none of the 30 controls changes level. All four development criteria pass; none of this is evidence of detection.

## [2026-10-13 21:51 PT] — Serving evaluator: an intent-rule switch that refuses unimplemented rules, and the D6/D7/D9 counts

### Why
- Step 2 of the 2026-10-13 evaluation plan asks for an evaluator option that runs a named configuration (option, credential rule on or off, payment rule on or off), plus per-configuration and deduplicated counts. The rules themselves are still under review, so the switch must not run them or pretend they ran.

### Files changed
- `website/tools/evaluate_serving_pipeline.py`:
  - `--intent-rules none|credential|payment|both`, recorded in the configuration. Any value but `none` is refused unless `app.IMPLEMENTED_INTENT_RULES` names the rule. That set does not exist yet, so every rule is refused, before the model loads or a message is read.
  - With a rule on, `analyze_record` analyses each message again with no rule, and keeps that level beside the result.
  - Optional row tags `behaviour` and `control_type`, validated and added to the duplicate check (untagged rows keep their digests).
  - A new `intent_rules` report block, per rule and language: legitimate matches and matches per control type (D6), new alerts (D7), tagged phishing alerted and added (D9). Combined counts take each message once.
- `website/tests/test_intent_rule_evaluation.py` (6 tests, synthetic results and a stand-in analysis).
- `docs/evaluation.md` — the switch, the tags and the block.

### Effect
- No served behaviour changes, and `app.py` is untouched. A replay with the served model is byte-identical to `main` (`b29cab5`) on five synthetic messages under both mailbox settings: 2 reports and 8 per-message results. A planted bug changes 1 of the 8. No rule, intent fixture, real mail or holdout was run.

## [2026-10-13 20:49 PT] — Split imported mail into development and holdout by family, from headers only

### Why
- Step 3 of the 2026-10-13 evaluation plan: fresh mail must be divided into development and holdout cohorts so that no family is in both (D11) and no one reads holdout content. Until now that step had no tool, and exports stayed unsplit.

### Files changed
- `website/tools/split_by_family.py` — reads only each `.eml`'s header block (From, Reply-To, Subject, topmost Received):
  - **Families:** legitimate mail by sending organisation; phishing by campaign (shared sender, Reply-To or subject template). Families merge transitively, also across runs.
  - **Assignment:** a family goes to development if any of its messages was seen, was received on or before 2026-10-14 by the provider's Received header, or has no such header. Other families are drawn for holdout from a secret in the ledger. A holdout family contributes at most 3 messages. A family never moves from development to holdout.
  - **Output:** two separate private directories outside the repository; a hashed ledger beside the holdout; counts only on stdout.
- `website/tests/test_split_by_family.py` (8 tests, synthetic messages only).
- `docs/evaluation.md` — the tool, its limits (the landing host is in the body and is not read), and the collection steps updated.

### Effect
- The owner can split exports collected after 2026-10-14 without opening them. Five planted bugs each fail at least one test: a cap of 5, no subject templates, the body read as headers, earlier development roles ignored, undated mail treated as fresh. No real mail was read or split.

## [2026-10-13 19:02 PT] — Synthetic fixtures for the intent rules, a baseline, and mail-collection steps

### Why
- Steps 3–4 of the 2026-10-13 evaluation plan: the two intent rules (credential handover, payment redirection) need synthetic development and regression data before they are written, and the owner needs written steps to collect fresh mail while the holdout stays sealed.

### Files changed
- `website/tests/fixtures/intent_rules/development.jsonl` (75 rows, 36 families, English and Chinese: positives and the plan's six control types, every required scenario in both languages) and `regression.jsonl` (the assessment's two misses and #60's reproduction). Reserved domains only.
- `website/tools/intent_fixture_baseline.py` — counts today's results on the fixtures as pasted text (counts only).
- `website/tests/test_intent_fixtures.py` (6 tests) — shape, one set/language/behaviour/kind per family (it caught two mixed families, now split), scenario coverage in both languages, quoted warnings as controls and quoted instructions as positives, reserved domains.
- `docs/evaluation.md` — the fixtures, the baseline and the collection steps.

### Effect
- Baseline before the rules, served model: English positives alert 27 of 30, but only 2 with a rule finding; English controls draw 14 false alerts of 20 (10 model-only); Chinese payment positives and all Chinese controls are Unknown; both assessment misses still miss. Nothing reads or scores real or holdout mail.

## [2026-10-13 16:12 PT] — Serving evaluator: plan options A/B/C, mailbox settings and a sealed holdout

### Why
- Step 2 of the 2026-10-13 evaluation plan (#62): compare the three labels for model-only alerts on original messages by running the full pipeline per option, score real downloads with and without their mailbox chosen, and keep the holdout sealed until the plan is frozen (its reviewer, D12, is not yet assigned).

### Files changed
- `website/app.py` — `MODEL_ONLY_OPTION` (a ContextVar, default "A", the served behaviour; no request can set it) and `_apply_model_only_option`, run after every other step: B raises an unauthenticated model-only note to Medium, C marks it for review (`model_only_review`, still Low); a note that was lowered to a verified sender or abstained to Unknown is left alone.
- `website/tools/evaluate_serving_pipeline.py` — `--option`, `--mailbox-setting none|recorded` (passes the row's provider to `analyze_raw_email(mailbox_provider=...)`, which the evaluator never did), `--frozen-plan-commit` (checked in git: the plan at that commit must record its reviewer); rows marked `cohort_role: holdout` are refused before analysis otherwise; a `model_only_plan` block with alerts, reviews, false passes and Unknown per label, attention on legitimate mail, authenticated phishing and its decisive subset. The configuration's two new keys are optional, so earlier reports still validate.
- `website/tools/build_private_cohort.py` — each row carries its `cohort_role`.
- `website/static/i18n.js`, `i18n-zh.js` — a translation for C's label (the frontend tests require one for every label `app.py` can send), with the asset versions bumped.
- `website/tests/test_model_only_options.py` (new, 11 tests); `docs/evaluation.md` — usage.

### Effect
- Served behaviour unchanged: with the served model, the full content analysis of the 518 raw messages the unit tests parse is byte-identical to `main` (44 are model-only); a planted default of B changes 16, so the replay detects it. No holdout exists yet; nothing was scored.

## [2026-10-13 16:06 PT] — Evaluation plan for model-only alerts and intent rules: D1–D11 locked, reviewer pending

### Why
- The 2026-10-13 review questioned showing an original message as Low when only the text model alerts, a rule that keys on the input path rather than authentication, and asked for intent-based rules (credential handover, payment redirection) instead of keyword patches for the two reproduced misses. AGENTS.md requires criteria in writing before any measurement.

### Files changed
- `docs/superpowers/specs/2026-10-13-model-only-and-intent-rules-evaluation-plan.md` (new) — three options for model-only alerts on original messages (A current Low note, B Medium unless the sender is authenticated, C an explicit review state), scored by running the full pipeline per option (no offline reconstruction), with abstention kept exactly; two intent rules with controls and required tests; metrics that keep alerts, reviews, false passes and Unknown apart; authenticated phishing and its decisive subset reported separately; one pre-registered holdout comparison over 12 configurations (A/B/C × no rule, credential only, payment only, both), each rule accepted for English and Chinese together, the deployed combination checked per message; fresh mail after 2026-10-14, at least 400 unique real downloads, public samples kept as an unverified cohort; thresholds on observed counts with Wilson intervals; "insufficient evidence" when a minimum is not met. Revised twice after review.

### Effect
- D1–D11 are locked at this commit. D12, the independent reviewer, is to be determined and not yet assigned (`reviewer-01` is a reserved ID), so the plan is not frozen and no holdout may be scored. Tooling, synthetic regression and development data, and new-mail collection may proceed; holdout mail stays isolated, unused for tuning and unscored. Nothing was measured.

## [2026-10-13 15:35 PT] — Case workspace: the access token only signs in; short-lived, revocable sessions

### Why
- Every case request carried the analyst's long-lived access token, checked against its configured SHA-256. Sign-out only cleared the page: after it, the same token still read `/api/cases/me` (200). There was no idle or absolute expiry and nothing to revoke (ASVS 7.2.2, 7.2.4, 7.4.1; 7.3.1, 7.3.2 at L2; finding A-01 of the 2026-10-13 assessment). The owner chose in-memory session IDs (no cookie, so no CSRF surface), 30 idle minutes / 8 hours, and keeping unsaved work across an expiry.

### Files changed
- `website/case_sessions.py` (new) — `CaseSessions`: `open`, `resume` (renews the idle time) and `close`. A session is `secrets.token_urlsafe(32)`; only its SHA-256 is stored, with the analyst and the credential digest it signed in with. Upstash: one key per session under `phishguard:sessions:v1:<workspace>:<environment>:`, Lua on Redis's own clock, expiring at the idle time and never past 8 hours. SQLite: a `case_sessions` table in the case database.
- `website/case_api.py` — `POST /api/cases/session` takes the access token and returns `{actor, session, idle_seconds, expires_at}`; `DELETE /api/cases/session` ends a session (204, also if already ended). Every other case route takes only a session; one whose analyst's hash was replaced or removed since sign-in ends at its next request. The access token alone now gets 401 from case routes.
- `website/static/cases.js` — signs in through the session endpoint and keeps only the session; sign-out and leaving the page end it on the server (`keepalive`). A 401 with unsaved work keeps the work and asks to sign in again: the same analyst continues, another analyst starts cleared. `cases.html`, `i18n.js`, `i18n-zh.js` — the sign-in help (the token still stays valid across releases until its hash is replaced) and two session messages.
- `website/tools/verify_case_login.py` — signs in at `/api/cases/session` and signs out at once; `website/tools/browser-checks/run.mjs` — in Chromium, the access token is refused for a case read, a session reads it, and the page's sign-out returns 204.
- Tests: `website/tests/test_case_sessions.py` (new: 11 SQLite/API tests, 4 Redis tests for CI), `test_case_api.py` (the helper signs in once per service), `test_verify_case_login.py`, `vercel_runtime_smoke.py`, `website/static/cases.test.mjs` (3 new), `website/tests/fixtures/i18n/cases-scenarios.mjs` (sign-ins answered by the harness unless a test handles them), `cases-en-snapshot.json` (regenerated: only the "sign out prompts" scenario gains default Jev flags; every visible string is unchanged).
- `docs/case-workflow.md`, `docs/api.md` — sessions, expiry and revocation.

### Effect
- Local server in Chromium: sign-in 201 and every later request on the session; no token or session in localStorage, sessionStorage or cookies; sign-out sends `DELETE` (204) and the server's session table goes from 1 row to 0; leaving the page does the same.
- Tests: sign-out revokes; 30 idle minutes end a session while activity keeps it; an active session still ends at 8 hours; replacing or removing an analyst's hash ends their sessions only; the database holds the digest, not the session or token; Preview and Production sessions are separate. Backend 1,350 tests pass (14 skipped: 10 earlier and the 4 Redis tests, which run in CI), frontend 530.

## [2026-10-13 15:11 PT] — source-map-js 1.2.1 → 1.2.2 in the recognition-asset build lock

### Why
- [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q) (CVE-2026-93749, high): crafted indexed source maps can stall the event loop in source-map-js below 1.2.2. It entered `website/tools/vision-assets/package-lock.json` through css-tree, a build-time dependency (reported by the 2026-10-13 ASVS assessment).

### Files changed
- `website/tools/vision-assets/package-lock.json` — source-map-js 1.2.2 (published 2026-09-30, past the seven-day cooling period), updated with `npm update source-map-js --package-lock-only --before=2026-10-06`; only its version, URL and integrity changed, and the integrity matches the registry's.

### Effect
- Rebuilt with 1.2.2 in a task-local directory: the 34 served assets are byte-identical (`verify.mjs` passes, `manifest.json` unchanged), and none contains source-map code (no `SourceMapConsumer`, `SourceMapGenerator`, `SourceNode` or `source-map-js`). The vulnerable version was never served; only the build environment changes.

## [2026-10-13 15:11 PT] — Security headers on unexpected 500s, and HSTS from the application

### Why
- An exception no handler caught got Starlette's 500, sent outside the middleware that adds the security headers: no CSP, `nosniff` or `X-Frame-Options` (ASVS 3.4.4/3.4.6; no exception text leaked). The application sent no `Strict-Transport-Security`; production had Vercel's own `max-age=63072000; includeSubDomains; preload`, but the application did not assert it (ASVS 3.4.1).

### Files changed
- `website/app.py` — `unexpected_error`, an `Exception` handler: the same `Internal Server Error` body, now with the security headers and `Cache-Control: no-store`; Starlette still logs the exception.
- `website/http_policy.py`, `vercel.json` — `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (Vercel's value) on every response and on `/static`.
- `website/tests/test_app_security.py`, `test_vercel_static_headers.py` — a synthetic failing route returns 500 with every security header and no exception text; pages and API send HSTS; the CDN and the middleware still agree.

### Effect
- A synthetic RuntimeError: 500 without the headers on `main`, with them here. Browsers ignore HSTS over plain HTTP, so local development is unaffected.

## [2026-10-13 15:11 PT] — Uploads that are plainly not email are refused (415)

### Why
- A Windows program or a PNG uploaded to `/api/analyze-eml` as `message/rfc822` was parsed as an empty message and shown as **Low** with only a decoding warning (ASVS 5.2.2).

### Files changed
- `website/email_structure.py` — `not_an_email`: a known signature at the start (Windows or ELF program, PNG, JPEG, GIF, WebP, PDF, zip/Office, Outlook `.msg`/OLE, gzip, 7z, RAR) or a NUL byte among the headers.
- `website/app.py` — `_parse_raw_email` refuses those with 415 ("This file is not an email message; it looks like …"), covering the `.eml`, JSON `raw_email`, visual and case paths.
- `website/tests/test_app_security.py` — 9 kinds refused; plain, BOM, mbox `From ` line, header-less text and binary-body messages still analyzed; JSON `raw_email` checked the same way. `docs/api.md` — the rule.

### Effect
- The 518 raw messages the unit tests analyze and the repository's `.eml` file: none refused.

## [2026-10-13 15:11 PT] — Spelled-out code lengths count as a one-time-code request

### Why
- "Please send us the **six digit** verification code…" did not match the one-time-code request rule, which knew only `6 digit`. Uploaded as an `.eml` from a personal Gmail address it rested on the text model alone and was shown as Low; with `6 digit` it was Critical (2026-10-13 ASVS assessment).

### Files changed
- `website/content_rules.py` — `_CODE_MODIFIER` takes `three` to `ten` before `digit`.
- `docs/evaluation.md` — "Spelled-out code lengths": criteria committed before the run (b93fd45), and the results.
- `website/tests/test_sensitive_requests.py` — 3 requests match, 4 controls do not.

### Effect
- All four criteria pass: 3 of 3 requests match (0 at the baseline); 0 of 4 controls; 0 of 36,567 legitimate public rows match, none new; the reproduction `.eml` goes from Low to Critical while a benign code notice stays Low. The text model's alert on an unauthenticated `.eml` without a rule is still shown as Low, a policy this does not change. Backend 1,335 tests pass (10 skipped), frontend 527.

## [2026-10-13 14:09 PT] — CI: read-only jobs, no stored token, and the baseline push split off

### Why
- `ci.yml` declared permissions only for its `visual` job; the others relied on the repository's default (read today). Every `actions/checkout` left the job's token in `.git/config`, where `npm ci`, pip installs and the browser could read it. The Visual baselines job held `contents: write` for its whole run, though only its optional push needs it, while it installs npm packages and runs Chromium.

### Files changed
- `.github/workflows/ci.yml` — top-level `permissions: contents: read`; every checkout `persist-credentials: false`.
- `.github/workflows/browser-checks.yml`, `post-deploy-smoke.yml` — checkouts `persist-credentials: false`.
- `.github/workflows/visual-baselines.yml` — the render job is read-only with no stored token; the push to `visual-baselines-update` is a separate `push` job (`needs: baselines`, `if: inputs.push_branch`), the only one with `contents: write`, which downloads the artifact (`actions/download-artifact` v8.0.1, pinned; v8.0.2 of 2026-10-07 held back by the seven-day cooling period) and runs only git.
- `website/tools/visual/README.md` — the `push_branch` input and the separate push job.

### Effect
- No job that installs or runs third-party code holds a write token, and none keeps its token on disk. Checked: the four workflow files parse, and only `visual-baselines.yml`'s `push` job has `contents: write`.

## [2026-10-13 14:09 PT] — Homepage CSP: workers same-origin, no frames, no `<base>`, forms to this site

### Why
- The policy on the homepage, 404 page and API responses (and `/static` on Vercel) left `worker-src`, `frame-src` and `form-action` unset and allowed `base-uri 'self'`, looser than `/cases`.

### Files changed
- `website/http_policy.py`, `vercel.json` — adds `worker-src 'self'; frame-src 'none'; base-uri 'none'; form-action 'self'`. The pages use only `/static/vision-worker.mjs` as a worker, frame nothing, have no `<base>`, and their only form is a `<dialog>` form, which does not navigate.
- `website/tests/test_app_security.py` — the pinned policy.

### Effect
- In Chromium against the local server: the policy is served; the vision worker starts; a blob: worker is refused (`worker-src`); loading the page and running a sender and a content analysis report no violation.

## [2026-10-13 14:09 PT] — ARC verified before analysis: slow DNS no longer holds an analysis worker

### Why
- The analysis thread called `arc_sealed_results`, which waited up to 5 s for the ARC threads (#56). With 0.3 s DNS lookups an analysis worker was held 0.64 s by one message.

### Files changed
- `website/email_structure.py` — `start_arc_verification` (pre-check, then the verification on the ARC threads, as a future); `arc_sealed_results` waits on it as before for direct callers; `analyze_raw_email(arc_result=...)` takes an answer the caller already has.
- `website/app.py` — `_parse_raw_email` for the `.eml`, content, visual and case paths: without a mailbox or trusted Authentication-Results IDs (when ARC is what may authenticate the message) it starts the check and waits on the event loop, then analyzes with the answer; otherwise as before.
- `website/tests/test_arc_sealed_results.py` — 4 tests: the lookups run on ARC threads and the analysis thread never calls `arc_sealed_results`; a changed message gets no trust; a mailbox choice makes no lookup; a slow chain stops at its deadline.

### Effect
- One sealed message with 0.3 s lookups: the request takes 0.64 s on `main` and here, but the analysis worker is held 0.64 s on `main` and 0.03 s here. The 518 raw messages the unit tests parse give identical structures. Backend 1,320 tests pass (10 skipped), frontend 527.

## [2026-10-13 14:00 PT] — One CSS budget per request, attached messages included

### Why
- `_run_analysis` handed work to the analysis pool without the caller's context, so every `analyze_email_content` call, one per attached message (up to 20, three levels deep), started its own 4,000,000-step CSS budget (#56).

### Files changed
- `website/app.py` — `_run_analysis` runs the function in `contextvars.copy_context()`; `_analyze_content` opens `shared_cascade_budget()` around the analysis (`_analyze_content_within_budget`), so an attached message's analysis uses the outer one.
- `website/tests/test_analysis_budgets.py` — `RequestBudgetTests` (2).

### Effect
- A message attaching 3 HTML messages creates 1 budget; on `main`, one per message analyzed. A pool thread now sees the request's context variables (checked with a marker variable).

## [2026-10-13 14:00 PT] — PDF text decoded only as far as the limit; CMap text and string bytes budgeted

### Why
- `pdf_text` checked its 20,000-character limit only after a whole `Tj` string was decoded: one string of 50,000 codes, each mapped to 200 characters, became 10,000,000 characters first. A CMap code could map to text of any length, and a literal string, however long, counted as one token.

### Files changed
- `website/email_structure.py` — `show()` decodes codes one at a time and stops at twice the text limit (past it no further text is read), without first listing every code; a CMap destination is cut at 512 bytes (`_MAX_PDF_CMAP_TARGET_BYTES`, the PDF limit), and the characters codes map to are charged to a second font budget, 1,000,000 per message (`_MAX_PDF_FONT_TEXT_CHARS`); `_pdf_tokens` charges each byte of a literal string as it reads it (stopping when the budget is spent) and each byte of a hex string.
- `website/tests/test_analysis_budgets.py` — `PdfTextMemoryTests` (5).

### Effect
- The 50,000-code string reads the same 20,000 characters with under 5 MiB peak memory. 4,096 range codes of 256 characters: 1,048,576 characters mapped on `main`, now `_PdfResourceLimit` (text unread, links kept, warning). A 5,000-byte string under a 1,000-step budget stops reading at 1,000.

## [2026-10-13 14:00 PT] — CSS var(): each reference costs a step, and repeated expansions are remembered

### Why
- `_substitute_variables` charged the budget by the length a var() produced, after following it: references that expand to nothing cost nothing. 8 references per level, 7 levels (615 bytes) took 5.85 s, 12 per level over 60 s, with no "analysis incomplete".

### Files changed
- `website/html_visibility.py` — one step per var() before it is followed; `_with_custom_properties` passes a memo per custom-property set, so each (value, depth) is expanded once (the depth limit is unchanged).
- `website/tests/test_analysis_budgets.py` — 2 tests: an empty expansion with no budget left raises; the same value expands to `x` one level down and past depth 8 seven levels down, with and without memo hits.

### Effect
- The 615-byte case: 5.85 s → under 0.01 s; 12 per level: over 60 s → under 0.01 s; 30 per level, 8 levels (2.3 KB): 0.01 s. Same readings as the narrow variant.
- No change for benign input: the 1,467 HTML inputs the unit tests render, 2,671 public-corpus HTML bodies and the 518 raw messages the unit tests parse give byte-identical results on `main` and this branch. The depth test fails with a planted bug (memo keyed without depth), which the replays alone did not catch. All 6 defect tests fail on `main`, the 2 controls pass on both; backend 1,325 tests pass (10 skipped), frontend 527.

## [2026-10-13 13:28 PT] — PDF attachments share one inflate and token budget per message

### Why
- After #56 only font entries were shared. Each PDF still had its own 4 MB inflate limit (twice: links and text) and its own 300,000 content-stream tokens: a 55 KB message with 76 PDFs of 476 bytes took 7.5 s, with no warning.

### Files changed
- `website/email_structure.py` — `_PdfMessageBudget` (font entries 200,000, inflated bytes 8 MB, tokens 300,000), shared by every PDF of one `analyze_raw_email` call (`_shared_pdf_budget`); `pdf_link_targets`, `_pdf_objects` and `pdf_text` take at most their per-document limit or what the message has left. A read cut short by the message's budget keeps what was read and adds `warning.attachment_resource_limit`; a document read alone, or one PDF at its own limits, is unchanged.
- `website/data/server_messages.json`, `website/static/i18n.js`, `i18n-zh.js` — the warning now covers all three limits ("…not all of its text or links were checked. Analysis is incomplete.").
- `website/tests/test_analysis_budgets.py` — `PdfMessageBudgetTests` (4).

### Effect
- 76 token-heavy PDFs: 7.54 s → 0.15 s; 10 PDFs inflating 4 MB each: 0.38 s → 0.06 s; both now report the analysis incomplete. The first PDF's text and every PDF's links read so far are kept.
- The 2 defect tests fail on `main`, the 2 controls (one PDF at 300,000 tokens or 4 MB; a PDF read alone twice) pass on both. Replaying the 518 raw messages the unit tests analyze: 515 identical to `main`; the 3 that differ are the budget tests' own messages (two new, one with the reworded warning). Backend 1,316 tests pass (10 skipped), frontend 527.

## [2026-10-13 11:15 PT] — Sender history only in signed-in case workspaces, one namespace each

### Why
- With sender history enabled (it is in Production), every public raw-email analysis read and wrote one service-wide "first observed / observed before" record keyed by the From address. From is unauthenticated: a forged message could ask whether anyone had submitted mail from an address, and change the answer the next user saw.

### Files changed
- `website/sender_history.py` — `sender_history_key(address, secret, workspace)` mixes the workspace into the HMAC and uses `sender-history:v2:`; `lookup` and `observe` require a workspace. The old service-wide `v1` records are no longer read and expire with their retention.
- `website/app.py` — public analysis (`/api/analyze-content`, `/api/analyze-eml`, visual, address-only) neither reads nor writes history and reports `sender_history_status: "workspace_required"` (`"disabled"`/`"unavailable"` when the store is off). `_analyze_case` observes the selected sender in its workspace (`history_workspace`).
- `website/case_api.py` — `CaseService.history_workspace` is `<VERCEL_ENV>:cases:<CASE_WORKSPACE>` (SQLite: the database path); case creation passes it, after the analyst token check and the idempotency replay check.
- `website/static/app-sender.js`, `i18n.js`, `i18n-zh.js`, `index.html` — a "Kept only in the case workspace" row for `workspace_required`; the privacy notice says public analysis does not read or record sender history and a pseudonymous observation is kept only when an analyst saves a case.
- `website/tools/visual/fixtures/sender-high-risk.json`, `sender-low-risk.json` — `sender_history_status` set by hand to `workspace_required`, what Production returns for an address-only check (the capture script runs with history off, which would now show "not enabled"); the sender screenshots show the new row.
- `website/tools/visual/baselines/` — 8 of 17 images re-rendered by the Visual baselines workflow (run 38445974508) and reviewed: the 6 sender results are 22 px taller (the history row's new text wraps one more line; checked in English at 1280 px and Chinese at 390 px, no overflow); the 2 content results at 390 px have identical text drawn a fraction of a pixel lower (the longer privacy notice above them gains a line; 1.3% of pixels differ by more than 16/255, none by a whole-pixel shift). The other 9 are unchanged (the mobile menu differs in 4 pixels by 4/255, left as is).
- `website/tools/post_deploy_smoke.py` — the history probe is one anonymous POST that must return `workspace_required` (was two expecting `first_seen` then `previously_seen`); five POSTs in all.
- `docs/deployment.md`, `docs/testing.md` — the same.
- `website/tests/test_sender_history*.py`, `test_post_deploy_smoke.py`, `website/static/app.test.mjs` (the new row; 527 frontend tests) — the new contract: two public analyses of one From make 0 store calls; a case saved by an authenticated analyst makes 1 (`("alice@example.com", "local:cases-sqlite:…")`), its replay 0 and an anonymous attempt is refused (401); keys differ by workspace.

### Effect
- Production after deployment: the homepage sender card shows "Kept only in the case workspace" instead of first/previously observed. History starts empty in each case workspace. Risk scores never used history, so verdicts do not change.

## [2026-10-13 11:10 PT] — ARC verification: exact sealer check, DNS-time whitelist, 10 lookups / 4 s on its own threads

### Why
- The pre-check that limits key lookups to Google read `d=` with a regex: an `x-d=google.com;` tag passed it while dkimpy then looked up the key at the real `d=evil.example`, telling the message's author that it was analyzed.
- dkimpy verifies every ARC set (RFC 8617 allows 50), two key lookups each, 2 s per lookup, on the analysis thread: a 20-set chain made 40 lookups.

### Files changed
- `website/email_structure.py` — `_arc_sealers` reads every ARC-Seal and ARC-Message-Signature with dkimpy's own `rfc822_parse` and `parse_tag_value` (a duplicate or unreadable tag means no lookup); `_guarded_arc_dns` answers only `<selector>._domainkey.<known sealer>`, at most `_ARC_MAX_LOOKUPS = 10` times and until `_ARC_VERIFY_SECONDS = 4.0`, each lookup within the time left; verification runs on a two-thread `BoundedExecutor` (`_arc_pool`) and is skipped, untrusted, when both are busy.
- `website/tests/test_analysis_budgets.py` — `ArcLookupTests` (6).

### Effect
- On `main` vs this branch: the decoy tag made 1 lookup at `evil.example` vs 0; the 20-set chain 40 lookups vs 10; 0.3 s lookups stop at the deadline (0.8 s in the test, under 2.5 s in all). The final checks are unchanged: the existing 7 ARC tests (valid Google seal trusted, altered message or other sealers not) pass.

## [2026-10-13 11:05 PT] — PDF fonts: shared CMaps and descendant fonts expand once, 200,000 entries per message

### Why
- Each font expanded its ToUnicode CMap and `/W` widths again, even when 30 fonts referenced one: a 3,391-byte PDF peaked at 388 MiB and took 27 s (tracemalloc on); 30 distinct CMaps in 6,300 bytes, 253 MiB and 23 s. Many PDF attachments each had their own limit.

### Files changed
- `website/email_structure.py` — `_pdf_fonts` caches CMaps by object number and `_pdf_widths` caches descendant fonts (`_pdf_cid_widths`); every expanded entry is charged to `_MAX_PDF_FONT_ENTRIES = 200_000`, shared by all PDFs of one `analyze_raw_email` call; past it `_PdfResourceLimit` leaves the text unread, keeps the attachment's links and adds `warning.attachment_resource_limit`.
- `website/data/server_messages.json`, `website/static/i18n.js`, `i18n-zh.js` — the warning ("…its links were checked but its text was not. Analysis is incomplete.").
- `website/tests/test_analysis_budgets.py` — `PdfFontBudgetTests` (3).

### Effect
- 1, 8, 30 or 200 fonts sharing one CMap: 13.5 MiB and under 1 s each (was 13.5 / 104 / 388 MiB). 30 distinct CMaps stop at 25 MiB and 2.5 s. 10 attachments of one such PDF: links kept on all 10, text read on 3, warning shown.

## [2026-10-13 11:00 PT] — CSS rendering: memoized selector matching and a 4,000,000-step budget, past it "analysis incomplete"

### Why
- Selector matching backtracked exponentially: `q div div div div div div span` over 40 nested divs (521 bytes) took 16.9 s, the `~` form 16.4 s. Neither combinators nor var() expansion had a total limit; with memoization alone, 20 KB of nested `<b>` still took 429 s, and per-link-label passes 30 s.

### Files changed
- `website/html_visibility.py` — `_TextCollector._matches` remembers each (compound, element) it tried; matching steps, var() characters and "maybe" rules checked are charged to `_CascadeBudget` (`_MAX_CASCADE_OPERATIONS = 4_000_000`), shared through `shared_cascade_budget()` by one message's parts and link labels; one var() value may grow to `_MAX_VARIABLE_EXPANSION = 16_384` characters. Past either, the rendering views are dropped as for an unmodelled stylesheet and the part gets the stylesheet warning plus `warning.css_budget`.
- `website/app.py` (`analyze_email_content`), `website/link_analysis.py` (`_extract_links`) — run under one shared budget.
- `website/data/server_messages.json`, `website/static/i18n.js`, `i18n-zh.js` — `warning.css_budget`.
- `website/tests/test_analysis_budgets.py` — `CascadeBudgetTests` (7).

### Effect
- 521-byte selector traps: 16.9 s → under 0.01 s, still resolved. 20 KB and 56 KB traps: 429 s and 50 s → 1.3 s, reported incomplete. 60 KB of styled link labels: 30 s → 1.7 s. Budget used by legitimate mail: at most 262 in the unit tests, 24 in the public corpus, 266,000 for a synthetic 31 KB newsletter (120 descendant rules, @media and dark mode, var() colours).
- No change for benign input: text, warnings, readings and link labels are byte-identical to `main` for 2,671 public-corpus HTML bodies and the 1,463 HTML inputs the unit tests render (a planted matching bug changes the second hash). All 11 defect tests run against `main` fail there (the 429 s and 30 s cases were timed separately) and the 2 control tests pass on both; all 16 pass here; backend 1,312 tests pass (10 skipped), frontend 526.

## [2026-10-12 14:31 PT] — AGENTS.md: the project's working rules for coding agents

### Why
- Since 2026-10-12 `main` requires a pull request and six passing checks, and direct pushes, which Codex had used (227 commits since September), are rejected. The other working rules (the 7-day dependency cooling period, private data, release checks, pre-registered criteria, refactor verification) lived only in agents' private notes and the changelog.

### Files changed
- `AGENTS.md` — new: branches, pull requests and releases (protected `main`, merge only on the owner's word with `--match-head-commit`, production checks, `preview-*` branches, teammates' branches kept); the checks to run before a PR; the CHANGELOG rule; the cooling period, including pinned actions and image digests; the owner's private data; measurements with criteria fixed beforehand; how a refactor shows it changes no behaviour.

### Effect
- No code change. Every command, file and setting it names was checked against the repository and the live ruleset.

## [2026-10-12 13:54 PT] — `_visible_content_text`'s HTML reader moved to module level (630 → 110 lines)

### Why
- `html_visibility._visible_content_text` was the longest function in the backend (630 lines) because it defined its 520-line HTML reader class, `TextCollector`, inside itself, and so rebuilt the class on every call.

### Files changed
- `website/html_visibility.py` — the class is `_TextCollector` at module level, just above the function, unchanged apart from one level less indentation; the function (110 lines) creates it as before.

### Effect
- No behaviour change, shown three ways:
  - The class reads no variable of the enclosing function (its only free name was `__class__`, for `super()`), and nothing changes class-level state (`head_elements` is only read; the parent `_AnalysisHTMLParser` holds only constants), so one class at import behaves as one per call.
  - Syntax trees: with docstrings normalised (`inspect.cleandoc`; three multi-line docstrings lose four spaces of indentation), the class, the rest of the function and the module's other 81 definitions are identical to `main`.
  - Golden replay: 7,663 calls (1,663 from the unit tests and 3,000 public HTML bodies, each called two ways) return the same text, warnings, structure statistics and readings on `main` and this branch. They reach 352 of the class's 386 statements (91%); one planted bug changed 1 result, another, in a rare table branch, changed none, so the syntax-tree check carries the proof.
- Backend tests 1,293 pass (10 skipped); frontend 526; `ruff check` passes. The class still has four methods over 60 lines (`handle_starttag` 143).

## [2026-10-12 13:46 PT] — Split `extract_email_features` (545 → 70 lines), outputs unchanged

### Why
- `sender_features.extract_email_features` was one 545-line function: address parsing, the 30 features, semantic domain signals, a 150-line random-username heuristic that rebuilt three name lists on every call, and the disposable classification. It was the second-longest function in the backend.

### Files changed
- `website/sender_features.py` — the function runs its stages through helpers: `_parse_sender_address` (a frozen `_SenderAddress`), `_match_registries` (`_RegistryMatches`), `_is_known_domain`, `_domain_structure_features` (features 1-13), `_keyword_and_brand_features` (14-24), `_summary_features` (25-30; `iframe` still counts the -1 values set before it), `_semantic_domain_indicators`, and `_flag_random_username` with `_is_real_name` and `_randomness_factors`. The first-name, last-name and common-word lists are module-level frozensets, built once. Statements, comments, the order of features and indicators, and the later switch of the four username features are kept; the module docstring no longer claims that `app` re-exports these names.

### Effect
- No behaviour change. Golden replay: 42,308 inputs (every call of the unit tests, 40,000 sender strings sampled from the public corpora in `phishing-detection/data` with seed 20261012, 2,095 synthetic addresses, and 36 official brand domains that reach the embedded-brand branch) give byte-identical results on `main` and this branch under hash seeds 0, 1 and 2, with the order of feature keys and indicators compared. The inputs reached 252 of the function's 255 statements; of the other three, one is unreachable (`continue` after a `find` of a substring) and two run but are traced on a neighbouring line.
- The replay catches planted bugs: `>= 0.4` for the digit ratio changes 65 results, a threshold of 3 changes 160, and moving the semantic signals before features 25-30 changes all of them.
- Backend tests 1,293 pass (10 skipped); frontend 526; `ruff check` passes.

## [2026-10-12 13:27 PT] — CI hardening: Redis from apt, actions and the Playwright image pinned

### Why
- On 2026-10-12 the main-branch `test (3.12)` job failed before any test ran: pulling the Redis service image from Amazon ECR Public returned "Data limit exceeded", so Vercel held #51 back from production until the job was rerun. Docker Hub had failed the same way on 2026-10-09.
- The workflows used floating tags (`actions/checkout@v7`, the Playwright image `v1.63.0-noble`), so a moved tag would run new code in CI unseen. Two of them had already moved to releases under 7 days old: `setup-node` v7 to v7.1.0 (2026-10-08) and `upload-artifact` v7 to v7.0.2 (2026-10-07), outside the owner's 7-day cooling period.

### Files changed
- `.github/workflows/ci.yml` — the test job installs `redis-server` from Ubuntu's packages and waits for `PONG`, instead of a Redis service container.
- `.github/workflows/*.yml` — every action pinned to a commit SHA with its release in a comment: `checkout` v7.0.1, `setup-python` v7.0.0, `setup-node` v7.0.0, `upload-artifact` v7.0.1 (the last two are the releases before the uncooled ones); the Playwright container pinned to its digest (`v1.63.0-noble@sha256:eff16c30…`).

### Effect
- The integration tests no longer depend on a container registry's pull limit.
- A tag moved upstream changes nothing until a pin is edited here. `setup-node` v7.1.0 and `upload-artifact` v7.0.2 can join the 2026-10-16 dependency round.
- Repository settings the same day (not files): Dependabot alerts enabled; the "Protect main" ruleset now requires a pull request and the six CI checks from GitHub Actions, so direct pushes to `main` are rejected.

## [2026-10-12 10:55 PT] — Homepage scripts deferred: English first paint 40% sooner on a slow phone

### Why
- On a throttled phone (Lighthouse's mobile preset: 150 ms RTT, 1.6 Mbps, CPU 4x) the production homepage first painted at 1,176 ms, together with DOMContentLoaded (1,197 ms): over HTTP/2 the 19 parser-blocking scripts at the end of `<body>` are fetched at high priority beside `style.css`, and the page cannot paint before the stylesheet. (An earlier reading of 1.46 s on a fast connection came from a background browser tab, which does not paint; unthrottled, production paints at 300 ms.)

### Files changed
- `website/static/index.html` — the 19 `<body>` scripts are `defer`, in the same order; `compat.js`, `theme-init.js` and `lang-init.js` in `<head>` stay blocking.
- `website/static/i18n.js` — whether page scripts have rendered is a flag set on DOMContentLoaded, not `document.readyState !== 'loading'`: a deferred script runs while readyState is already `interactive` but before that event, so a Chinese dictionary arriving in that gap would have re-rendered scripts that had not rendered yet.
- `website/static/i18n.test.mjs` — a deferred i18n.js with readyState `interactive`: a dictionary before DOMContentLoaded announces no change, one after it does (fails on the previous `i18n.js`).
- `website/static/app.test.mjs` — the script-order test accepts `defer` and requires it on every `<body>` script.
- `website/static/lang-init.js` — comment only.
- `website/static/404.html`, `website/static/cases.html`, `website/tools/asset-versions/manifest.json` — versions.

### Effect
- Measured locally behind an HTTP/2, Brotli proxy (which reproduces production's first paint coinciding with DOMContentLoaded), median of 9 fresh loads on the throttled phone: English first paint 1,036 → 620 ms and LCP 1,092 → 648 ms; DOMContentLoaded unchanged.
- A Chinese page is about 5% slower to appear (first paint 1,296 → 1,368 ms): it stays hidden until the Chinese strings (`i18n-zh.js`) arrive, at about 1.2 s either way, and deferred scripts share bandwidth with them. Preloading `i18n.js` for Chinese pages did not help and was not kept.
- Browser check: English and Chinese pages load, analyse and switch language with no console errors. Frontend tests: 526 pass.

## [2026-10-12 04:51 PT] — Gemma 4 and Mistral Small 3.2 measured as second teachers: neither pair passes

### Why
- After `gpt-oss:20b` failed as the second teacher, the owner chose to try two other model families with `qwen3.8:27b-mxfp8`. The criteria were written before the models were downloaded and match the earlier ones: at floor 90, at most 4 of 890 phishing messages accepted as legitimate and at most 15 of the owner's 92 genuine messages sent to a person.

### Files changed
- `docs/evaluation.md` — new section "Two more second teachers: Gemma 4 and Mistral Small 3.2 (2026-10-12)".
- `docs/llm-teacher.md` — the result after the gpt-oss paragraph.

### Effect
- Qwen + `gemma4:26b-a4b-it-q8_0` accepted 6 of 890 phishing messages (fails, limit 4) and sent 14 of 92 genuine messages to a person (passes). Qwen + `mistral-small3.2:24b` accepted 1 (passes) and sent 67 (fails). `label_with_llm.py` keeps Qwen alone.
- Gemma 4 alone read only 3 of the owner's 92 genuine messages as phishing (Qwen 10) but accepted 14 phishing messages (Qwen 9).
- The candidate models were deleted after the measurement, as the owner asked, together with `gpt-oss:20b`. Reports hold counts only and stay outside the repository.

## [2026-10-11 12:42 PT] — Two local teachers measured: agreement fails the review-load criterion

### Why
- The owner asked to train with two teachers: `qwen3.8:27b-mxfp8` and `gpt-oss:20b`, a label only when both agree. The two-teacher measurement prepared on 2026-10-08 had not run, and its pass criteria were fixed then: at floor 90, at most 4 of 890 phishing messages accepted as legitimate and at most 15 of the owner's 92 genuine messages sent to a person.
- A six-message check showed the tool alternating models per message made Ollama swap them on the GPU: Qwen's median rose from 2.5 s to 25.7 s, about 9 hours for the full run.

### Files changed
- `website/tools/evaluate_llm_labeler.py` — `label_cohort` runs one model through a cohort, then the next, and pairs the readings afterwards; the readings and counts are the same.
- `website/tests/test_evaluate_llm_labeler.py` — the stub records the order of model calls; two models over four rows are asked 4 + 4, not alternately (fails on the previous code).
- `docs/evaluation.md` — new section "Two local teachers and their agreement (2026-10-11)".
- `docs/llm-teacher.md` — the result under "The teacher, measured".

### Effect
- Agreement accepted 4 of 890 phishing messages as legitimate (Qwen alone 9; criterion 1 passes) but sent 56 of the owner's 92 genuine messages to a person (Qwen alone 10; criterion 2 fails): gpt-oss read 53 of them as phishing. `label_with_llm.py` keeps Qwen alone. The report holds counts only and stays outside the repository; 2 h 13 min on an Apple M2 Max.
- Qwen reproduced the 2026-10-06 counts exactly (10 of 92, 9 of 890).
- No served behaviour changes. Backend tests for the tool: 4 pass.

## [2026-10-11 09:29 PT] — Year-long cache for versioned assets; larger footer tap targets

### Why
- Versioned static files (`/static/…?v=N`) were cached by browsers for one day, so a visitor returning a day later revalidated 20+ files. The day was a safety margin for a missed `?v=` bump, but `asset-versions.test.mjs` already fails CI when a file's bytes change without a new version, and no versioned URL is built at runtime.
- On a phone the nine footer links were 22px tall, under the 24px minimum target size of WCAG 2.5.8.

### Files changed
- `vercel.json`, `website/http_policy.py`, `website/tools/post_deploy_smoke.py`: versioned assets get `Cache-Control: public, max-age=31536000, immutable` (was `public, max-age=86400, stale-while-revalidate=604800`). The smoke check requires `public` and the year-long `max-age`; `immutable` may be absent, in case the CDN strips it as it strips `stale-while-revalidate`.
- `website/tests/test_post_deploy_smoke.py`: the accepted and rejected headers follow the new value.
- `website/tools/asset-versions/asset-versions.mjs`, `docs/deployment.md`: comments and docs say a year.
- `website/static/style.css`: footer links get 5px vertical padding in place of the column's 10px gap (32px targets); the heading margin and a -5px column margin keep every footer text position where it was.
- `website/static/index.html`, `website/static/404.html`, `website/tools/asset-versions/manifest.json`: stylesheet version.

### Effect
- Returning visitors reuse versioned files for a year without a request; a deployment that changes a file changes its URL.
- Footer links are 32.4px tall. A layout comparison against the previous stylesheet finds every footer text position and the footer height unchanged at 375px and 1280px, in English and Chinese.
- Tests: 525 frontend, 1293 backend (10 skipped) pass; `ruff check` passes.

## [2026-10-11 09:04 PT] — Sender result: evidence chips on one line again

### Why
- Phase B (#47) moved the sender result's evidence chips (`.pill`) from 11.5px to 12px. In the narrow Heuristic Evidence column the three chips then needed 365px of 349px, and "3 medium-risk" wrapped to a second line.

### Files changed
- `website/static/style.css`: `.pill` uses `--text-2xs` (11px) and 10px side padding (was 12px and 11px), like the other compact badges such as the HIGH/MEDIUM labels beside it. `.pill` is used only for these three chips.
- `website/tools/visual/baselines/sender-*.png`: regenerated (6 shots).
- `website/static/index.html`, `website/static/404.html`, `website/tools/asset-versions/manifest.json`: stylesheet version.

### Effect
- The chips fit on one line at 1280px: 339 of 349px in English, 244px in Chinese. The desktop high-risk sender result is 35px shorter; the other 11 visual shots are pixel-identical. With two-digit counts the row can still wrap, cleanly. Frontend tests: 525 pass.

## [2026-10-11 08:49 PT] — Frontend phase B: design tokens

### Why
- The layout review counted 34 font sizes, 21 border radii, 33 box shadows and 274 hard-coded colours in `style.css`. Values that differ by half a pixel look like mistakes, and a theme colour copied as `rgba(255,92,108,…)` in 20 places cannot be changed in one.

### Files changed
- `website/static/style.css`: step 1 (no visual change) turns 189 theme-colour tints into channel tokens, e.g. `rgba(var(--red-rgb),0.08)`; the tokens are defined once so a tint is the same in both themes, as before. Step 2 adds a type scale (`--text-2xs` 11px … `--text-7xl` 44px, 13 steps; half-pixel sizes round up), `--radius-2xs` (6px) and `--radius-xs` (10px) beside the existing 14/20/28px radii, `--pill` on thin bars, and `--focus-ring` for the five identical field focus rings. Kept literal on purpose: the fluid hero `clamp()` sizes, the 16px iOS anti-zoom rule for fields, the 8.5px badge that fits its 13px circle, and the one-off theme-specific elevation shadows.
- `website/static/app.test.mjs`, `website/static/page-loading.test.mjs`: assert the tokens where they asserted pixel sizes.
- `website/tools/visual/baselines/*.png`: regenerated (17 shots).
- `website/static/index.html`, `website/static/404.html`, `website/tools/asset-versions/manifest.json`: stylesheet version.

### Effect
- Font sizes go from 34 values to 13 steps plus 4 deliberate exceptions; pixel radii from 15 values to 2 new tokens. Remaining literal `rgba()` colours: 30 (white and black overlays and three one-offs).
- Step 1 was checked by comparing computed styles of every element and pseudo-element (17 colour properties, light and dark, all details open) against the old stylesheet: 0 differences in 4,164; changing `--red-rgb` as a control changes 37.
- Step 2 is a small visible change: text that was 12.5/13.5 px is now 13/14 px, so result pages are 3-61 px taller and rewrap slightly; on the sender result the third heuristic-evidence chip wraps to a second line. Frontend tests: 525 pass.

## [2026-10-11 08:28 PT] — Result pages, phase C: verdict first

### Why
- The layout review found the sender result hard to read: three equal columns, two of them small scroll boxes, mostly 11.5-13 px text. The verdict was clear; the reasons behind it were not.

### Files changed
- `website/static/index.html`, `app-core.js`, `app-sender.js`, `app-content-render.js` — both verdict banners list **Key findings**: the three strongest indicators (critical, then high, then medium, in the server's order), above the full lists; hidden when none qualifies. The sender result puts every risk indicator in a wide column beside the score, mailbox-type and history cards, and folds the 30-signal breakdown into a "Most Relevant Sender Signals" card (two columns when opened).
- `website/static/style.css` — no scroll boxes inside cards (`.risk-list`, `.feature-breakdown`); indicator, signal and detail text 13-14 px; banner icons align to the top.
- `website/static/i18n.js`, `website/static/i18n-zh.js` — `result.keyFindings` ("Key findings" / "关键发现").
- `website/static/app.test.mjs` — the findings' order, limit, cut-off and escaping.
- Versioned assets bumped.

### Effect
- Checked in the browser at 1280 and 390 px, light and dark, English and Chinese: the critical sender example shows three high findings under its verdict and all nine indicators without scrolling; the phishing content example shows its three strongest technical findings; a legitimate example shows none. No console errors. Frontend tests 525 pass (the new test fails if the ranking is removed); backend 1293 OK.
- `website/tools/visual/baselines/` — regenerated (Visual baselines run 38151410816): the ten result shots grow (findings, full lists) and were checked by eye at both widths, light and dark, English and Chinese; the navbar, menu and 404 shots are unchanged; the legitimate content shot differs by 0.025% of pixels (its banner icon now aligns to the top).

## [2026-10-11 08:02 PT] — Homepage layout, phase A: focus, collapsible extras, phone fixes

### Why
- A layout review (desktop, phone, dark mode): the archived UCI website benchmark, unrelated to this product, was the section right after the demo; the disposable-email guide filled a large card under the demo; on phones the brand and the case login touched in the bar, and quick examples stacked one per line.

### Files changed
- `website/static/index.html` — the benchmark section moves to the end of the page (nav order follows: Live Demo, Features, How It Works, Performance) and its results sit in a `<details>` behind "Show the archived results"; the disposable-email guide is a `<details>` whose header (still an h3) is the summary; the section menu gains a case-login item for phones.
- `website/static/style.css` — styles for both disclosures (the existing chevron pattern), phones: quick examples in one sideways-scrolling row that fades at its edge (no scroll snapping: re-snapping when the viewport resized moved the page, which put the off-screen skip link into the 390 px result screenshots), the case login in the menu instead of the bar, a smaller guide header.
- `website/static/app-layout.js` — a link into a collapsed section (`#disposable-info` from the footer or a sender result) opens it, as does loading the page with that hash.
- `website/static/i18n.js`, `website/static/i18n-zh.js` — `perf.toggle` ("Show the archived results" / "查看归档结果").
- Versioned assets bumped (`tools/asset-versions/update.mjs`), so `404.html`, `cases.html` and `lang-init.js` change only in their `?v=`.

### Effect
- Checked in the browser at 1280 px and 375 px, light and dark, English and Chinese: both disclosures start closed; the footer link and a `#disposable-info` URL open the guide; the benchmark table and Chart.js chart render once opened (the chart, loaded while collapsed, resizes); the phone bar holds brand, language, theme and menu with no horizontal overflow; the menu lists the case login under a divider; the examples row is 30 px tall. No console errors. Frontend tests 524 pass; backend 1293 OK.
- `website/tools/visual/baselines/` — regenerated by the Visual baselines workflow (run 38150209621) in the pinned Playwright 1.63.0 container. Clear changes only in the navbar shots (`top-*`, the moved nav item and the phone bar) and the opened phone menu; the other 11 differ by at most 0.8% of pixels, none strongly (rendering noise since the 1.63.0 container).

## [2026-10-10 23:14 PT] — Train a local candidate on a reviewed private mailbox

### Why
- Most false alerts come from the text model, trained on genuine mail from 2002-2008; the owner's own recent mail is the missing data (docs/llm-teacher.md). The training pipeline could not read a reviewed mailbox yet.
- The owner chose to keep any model trained on private mail on this computer only (2026-10-10): its vocabulary keeps words from that mail, and `/api/metrics` publishes the served model's `top_terms`.

### Files changed
- `website/content_model.py` — `build_content_pipeline(private_corpus=…)` (and `CONTENT_MODEL_PRIVATE_CORPUS`) reads `labelled.csv` from `tools/label_with_llm.py`. Its rows are deduplicated and join the training side after the split, as the synthetic hard negatives do, without held-out or already present families. A private build skips the pickle cache, marks the model `private_training`, and records only counts and the corpus's SHA-256. The corpus and the saved artifact must be outside the repository. `load_content_pipeline_artifact(…, allow_private=False)` refuses a private model.
- `website/content_inference.py`, `website/app.py` — the serving loader refuses a private model unless allowed; the app allows it only when `APP_ENV=development`, so a demo or production server rejects it.
- `website/prebuild_demo_model.py` — `--private-corpus`.
- `website/tools/evaluate_serving_pipeline.py` — `--artifact` and `--artifact-sha256` evaluate a local candidate (private allowed) on the same input as the served model; `compare_evaluations.py` compares the two reports.
- `website/tests/test_private_training.py` (new) — 7 tests on synthetic private rows.
- `docs/llm-teacher.md` — step 4 with the commands and the local-only rule.

### Effect
- No change to the served model or to analysis. With synthetic private rows: the private rows reach the training side only (the test side keeps its size), the model card holds no private text, nothing is cached, saving inside the repository and loading in demo or production are refused, and a development server and `--artifact` evaluations load the model. End to end, the CLI refused its default in-repository output, built a candidate outside it, and both models were evaluated and compared on the same input. Backend unittest 1293 tests OK; frontend 524 pass; Vercel runtime smoke passes.

## [2026-10-10 22:42 PT] — Ignore Claude Code's local settings

### Why
- `.claude/` holds local launch configurations with this machine's paths; it showed as untracked in every `git status`.

### Files changed
- `.gitignore` — `.claude/` beside the other editor directories.

### Effect
- `git status` is clean; nothing tracked changes.

## [2026-10-10 22:26 PT] — Lock every package Vercel installs with uv.lock

### Why
- Only direct dependencies were pinned: Vercel resolved transitive packages afresh on each build, so the 7-day cooling period did not reach them, and production could change without a commit.
- Vercel's Python builder installs a committed `uv.lock` with `uv sync --frozen --no-dev` (`packages/python/src/install.ts` and `uv.ts` in vercel/vercel), which never compares the lock with `pyproject.toml`.
- Correction to the 2026-10-09 22:51 entry: that upgrade wrote the uncooled resolution (fastapi 0.143.0, pydantic 2.14.0, dnspython 2.9.0, tldextract 5.4.0, phonenumberslite 9.0.41, opentelemetry-api 1.45.1, filelock 4.1.0) into `requirements-dev-py312-macos-arm64.lock.txt`, not the cooled one its entry described. No install or test reads that file.

### Files changed
- `uv.lock` (new) — 36 packages resolved by uv 0.12.23 from `pyproject.toml`; the direct pins are unchanged.
- `pyproject.toml` — `[tool.uv] exclude-newer = "2026-10-03T00:00:00Z"`: the cooling-period cutoff for every package, recorded in the lock.
- `.github/workflows/ci.yml` — `vercel-runtime` installs uv 0.12.23, runs `uv lock --check`, installs with `uv sync --frozen --no-dev` as Vercel does, and smoke-tests that environment (`uv pip check` included).
- `website/tests/test_vercel_static_headers.py` — `uv.lock` must hold the pinned versions and the same `exclude-newer`.
- `requirements-dev-py312-macos-arm64.lock.txt` — re-resolved with `uv pip install --exclude-newer` at the same cutoff; its serving packages equal `uv.lock` (filelock 4.0.9).
- `docs/deployment.md` — the lock and the upgrade procedure.

### Effect
- Production installs exactly the locked versions. A lock that no longer matches `pyproject.toml` fails CI (checked: changing a pin without `uv lock` makes `uv lock --check` exit 1, and the new test fails on a locked version that differs from its pin).
- With the locked set: backend unittest 1286 tests OK, the Vercel runtime smoke and the synthetic evaluation comparison pass, `uv pip check` is clean. Render and local installs still use `requirements*.txt`.

## [2026-10-10 21:52 PT] — Deploy only main and preview-* branches on Vercel

### Why
- On 2026-10-10 the Hobby plan's 100 deployments a day ran out ("Deployment rate limited"), mostly on preview deployments of pull request branches, so #39's production deployment did not happen until the next day's merge.
- An Ignored Build Step does not help: Vercel counts a canceled build as a full deployment.

### Files changed
- `vercel.json` — `git.deploymentEnabled`: `"**": false`, `"main": true`, `"preview-*": true`. Vercel deploys a branch when any matching rule is true, so `main` and `preview-*` deploy and other branches create no deployment.
- `docs/deployment.md` — the policy, and when to name a branch `preview-*` (dependency upgrades, `vercel.json`, `pyproject.toml`, `.vercelignore`).
- `website/tests/test_vercel_static_headers.py` — pins the rules and checks which example branches deploy.

### Effect
- Pull request branches stop using the deployment quota; production deployments of `main` and the post-deploy smoke are unchanged. CI's `vercel-runtime` job still smoke-tests the Vercel profile on every pull request. This branch is itself named `preview-…`, so its preview checks that Vercel accepts the new `vercel.json`.

## [2026-10-10 21:15 PT] — Archive the changelog by month

### Why
- `CHANGELOG.md` had grown to 6,072 lines; every entry is inserted at its top, and finding history meant scrolling through three months.

### Files changed
- `docs/changelog/2026-09.md` (123 entries) and `docs/changelog/2026-06.md` (6 entries) — the September and June entries, moved unchanged and in order.
- `CHANGELOG.md` — keeps October (2,693 lines) and links the archives above the "Format is loosely based on…" line, so new entries still go directly under it.
- `.cursor/rules/changelog.mdc` — rule 7: when a month ends, move its entries to `docs/changelog/YYYY-MM.md`; moving is not deleting history.
- `website/tools/post_deploy_smoke.py` — a comment that cited a September entry names its archive (comment only).

### Effect
- History is unchanged: the three files' entries, concatenated, are byte-identical to the previous `CHANGELOG.md`. `docs/` is outside the Vercel bundle (`.vercelignore`), as `CHANGELOG.md` already was.

## [2026-10-10 15:00 PT] — Remove the structure verdict, which no response used

### Why
- `_analyze_content` set a level with `_apply_structure_verdict` after the structure, attachment and sender evidence (a Medium floor at any score), unlike `_content_verdict` (Medium only up to a score of 8). The question was whether that difference was intended. It never mattered: `fuse_content_risk` sets `risk_level` and `risk_label` on every response afterwards, and nothing in between reads them.
- Replaying the 3,780 captured `_analyze_content` inputs and corpus messages with both ladders replaced by a constant left every response identical, with the text model off and on.

### Files changed
- `website/app.py` — `_apply_structure_verdict` and its call removed. `_content_verdict` stays: `analyze_email_content` returns its level to direct callers and tests.

### Effect
- No behaviour change: the golden replay of 7,321 inputs is identical with the model off, on and with stubbed RDAP dates, and so are the 124 `analyze_sms` outputs. Backend unittest 1284 tests OK; frontend 524 pass.

## [2026-10-10 14:40 PT] — Move the content rules out of app.py

### Why
- The content rules were the last large area inside `website/app.py` (3,996 lines). Their dependency closure (108 definitions: `CONTENT_RULES` and the Chinese keywords, the request patterns, the mailbox, delivery, fine, account-hold, file-share and subsidy lures, presentation cues, attachment-text rules, `_text_rule_findings`, registration-date findings) uses no app state.

### Files changed
- `website/content_rules.py` (new, 1,364 lines) — those definitions moved verbatim, with the three import-time statements that build them (merging the Chinese keywords into `CONTENT_RULES`, adding three patterns to `_SENSITIVE_REQUEST_EN`). It imports nothing from `app.py`.
- `website/app.py` (3,996 → 2,684 lines) — imports back the 23 names its own code calls; drops 20 imports only the rules used.
- 19 files in `website/tests/` and `website/tools/counterfactual_evidence.py` — use `content_rules.X` (and `html_visibility._AnalysisHTMLParser`, `email_structure.OFFICIAL_SERVICE_NUMBERS`) instead of reaching them through `app`. `evaluate_jev.py` keeps taking its helpers from `app`, which its test pins.
- `website/static/i18n.test.mjs` — the check that the category labels match the backend reads `CONTENT_RULES` from `content_rules.py`.
- `README.md` — project structure.

### Effect
- No behaviour change: an AST comparison with `main` shows the 111 moved statements and the 138 remaining ones unchanged and in order. The golden replay of 7,321 email inputs is identical with the model off, on and with stubbed RDAP dates, and every `analyze_sms` call the tests make (118, plus 6 synthetic texts) gives identical output. A planted bug in `content_rules.py` changes 73-83 email and 8 SMS outputs. Backend unittest 1284 tests OK.

## [2026-10-10 14:17 PT] — Tests use the modules that define what they test; app.py stops re-exporting

### Why
- `app.py` imported 79 names it never used, only so that tests could reach them as `app.X`: the HTML/CSS reader's internals, sender registries, link and HTTP helpers, and `socket`, `smtplib` and `HTMLParser`. The module boundaries from the split existed only on paper, and every move risked a test reaching a name through the wrong module.

### Files changed
- `website/app.py` — the nine `noqa: F401` re-export imports become plain imports of what `app.py` uses (79 names dropped, 3,996 lines).
- 24 files in `website/tests/` — `app.X` (and two `getattr(app, ...)`) become `html_visibility.X`, `sender_features.X`, `disposable_registry.REGISTRY_DOMAIN_RE`, `link_analysis.X`, `http_policy.X`, `domain_verification.X`, `socket` or `smtplib`, each importing its module. Patches on `app` stay: they patch what `app.py` itself calls.

### Effect
- No behaviour change in the served code: only imports were removed. Every `app.X`, `getattr(app, …)`, `patch.object(app, …)`, aliased and `from app import` reference in the tests and tools still resolves. Backend unittest 1284 tests OK; `ruff`, `compileall` and `vercel_runtime_smoke.py` pass.

## [2026-10-10 14:10 PT] — One test file for the official-brand registry additions

### Why
- The registry additions were tested in four files, three of them named by date (`test_registry_additions_2026_10_05/06/07.py`) with identical helpers.
- The thirteen dated `test_review_*.py` files stay: each is the regression suite of one code review, and its docstring names the review's commit and topics, which a topic name would lose.

### Files changed
- `website/tests/test_registry_additions.py` — the four files' six classes, one per batch (`Additions20261002Tests` … `Additions20261007ChineseSecondBatchTests`), with one copy of `GMAIL_PASS` and `received`. The Chinese batches pass their message as `body=ZH_CODE` instead of relying on a different default.
- `website/tests/test_registry_additions_2026_10_05.py`, `…_10_06.py`, `…_10_07.py` — removed.
- `docs/evaluation.md` — its pointer to the 10-06 file names the merged file.

### Effect
- 30 of the 32 test methods are AST-identical to the originals; the other two differ only by `body=ZH_CODE`. 32 registry tests and the full suite of 1284 pass.

## [2026-10-10 13:58 PT] — Split _analyze_content, part 2: model, fusion, verified sender, abstention

### Why
- Last of four PRs breaking `analyze_email_content` and `_analyze_content` into named steps, behaviour unchanged.

### Files changed
- `website/app.py` — new `_apply_content_model` (async), `_fuse_content_result`, `_apply_verified_sender`, `_add_registration_dates` (async) and `_apply_abstention`. Each body is the original block, cut verbatim at the same indentation. `_analyze_content` goes from 189 to 58 lines and reads as its steps in order. All stay in `app.py`, so patches on `app` (`_content_pipeline`, `predict_content`, `SETTINGS`) still apply.

### Effect
- No behaviour change: the golden replay of 7,321 inputs against `main` is identical with the text model off, on, and with stubbed RDAP dates. Planting two bugs in the new helpers changes 65 outputs. Backend unittest 1284 tests OK.
- Across the four PRs: `analyze_email_content` 460 → 167 lines, `_analyze_content` 390 → 58.

## [2026-10-10 13:43 PT] — Split _analyze_content, part 1: input, structure, attachments, sender, attached messages

### Why
- Third of four PRs breaking `analyze_email_content` and `_analyze_content` into named steps, behaviour unchanged.

### Files changed
- `website/app.py` — new `_resolve_content_input`, `_add_structure_evidence`, `_add_attachment_links`, `_add_attachment_text`, `_add_sender_evidence`, `_apply_structure_verdict`, `_merge_nested_messages` (with `_add_nested_coverage` for its three repeated image-count merges) and `_ensure_image_warnings` (its three repeated blocks as one loop). `_analyze_content` goes from 390 to 189 lines. The structure verdict keeps its own rules (a Medium floor holds at any score), separate from `_content_verdict`; its docstring says how they differ. All stay in `app.py`.

### Effect
- No behaviour change: the golden replay of 7,321 inputs against `main` is identical with the text model off, on, and with stubbed RDAP dates. Planting two bugs in the new helpers changes 159 outputs. Backend unittest 1284 tests OK.

## [2026-10-10 13:29 PT] — Split analyze_email_content, part 2: links, readings, lures and verdict

### Why
- Second of four PRs breaking `analyze_email_content` and `_analyze_content` into named steps, behaviour unchanged.

### Files changed
- `website/app.py` — new `_collect_links`, `_reading_links` (was a nested closure), `_rule_readings`, `_riskiest_rules`, `_lure_findings` (was a nested closure), `_hidden_text_findings`, `_content_verdict` and `_FLOOR_RANK`. `analyze_email_content` goes from 314 to 186 lines. The short scoring checks (shortener, password form, question marks, URL count and the like) stay inline, in order. All stay in `app.py`.

### Effect
- No behaviour change: the golden replay of 7,321 inputs against `main` is identical with the text model off, on, and with stubbed RDAP dates. Planting two bugs in the new helpers changes 328 outputs. Backend unittest 1284 tests OK.

## [2026-10-10 13:14 PT] — Split analyze_email_content, part 1: reading the parts

### Why
- `analyze_email_content` (460 lines) and `_analyze_content` (390 lines) are where detection changes are hardest. The owner chose to break them into named steps, behaviour unchanged, over four PRs. This is the first.
- Each part's reading was a 12-element tuple read back by position (`parsed[7:10]`, `parsed[11]`).

### Files changed
- `website/app.py` — new `_PartReading` (a NamedTuple naming those 12 fields), `_plain_part`, `_read_html_part` (was the nested `visible_html`), `_read_parts`, `_build_model_views` (the MIME-alternative view enumeration) and `_image_coverage`. `analyze_email_content` calls them and goes from 460 to 314 lines. All stay in `app.py`, so patches on `app` still apply.

### Effect
- No behaviour change. A local golden comparison replays 7,321 inputs through `main` and this branch: every `analyze_email_content` and `_analyze_content` call the test suite makes (1,734 and 1,506), 474 synthetic variants for branches those miss (attachment shorteners, structure score thresholds, attached messages with unresolved images, more MIME alternatives than the view budget, a small link-label budget), and 300 messages from each of six public corpora. Outputs are identical with the text model off, on, and with stubbed RDAP dates; together these runs reach every statement of both functions. Planting two bugs in the new helpers changes 71 outputs. Backend unittest 1284 tests OK.

## [2026-10-10 12:27 PT] — Move stateless HTTP policy out of app.py

### Why
- Third step of splitting `website/app.py`. The HTTP middleware and routes cannot move: they read and write `app` module state (`_rate_limit_buckets`, `_rate_limit_store` set by the lifespan, `RATE_LIMIT_PER_MINUTE`, `INDEX_PAGE`, `_not_found_page_body`) that tests patch on `app`. Only the stateless policy moves.

### Files changed
- `website/http_policy.py` (new, 184 lines) — 14 definitions moved verbatim: `_build_allowed_hosts`, `_RateLimitBucket`, `_RATE_LIMIT_PATHS`, `_rate_limit_key`, `_record_rate_limit_hit`, `SECURITY_HEADERS`, `WORKER_SCRIPT_PATHS`, `WORKER_CONTENT_SECURITY_POLICY`, `VERSIONED_ASSET_CACHE_CONTROL`, `_with_security_headers`, `_revalidated_file`, `_NOT_FOUND_JSON_PREFIXES`, `_NOT_FOUND_JSON_PATHS`, `_wants_not_found_page`.
- `website/app.py` (4,047 → 3,893 lines) — imports them back; drops the now-unused `ipaddress` import. Middleware, routes, the lifespan and the shared state stay.
- `website/tests/test_post_deploy_smoke.py`, `website/tools/post_deploy_smoke.py` — the test that pins the smoke tool's cache header to the app's constant reads `http_policy.py`; the tool's comment names it.
- `README.md` — project structure.

### Effect
- No behaviour change: an AST comparison with `main` shows the 14 moved statements and the 221 remaining ones unchanged and in order. Backend unittest 1284 tests OK (10 Redis skips); `vercel_runtime_smoke.py` and `ruff` pass. Planting two bugs in `http_policy.py` fails 35 tests. Through the app: security headers, hash ETag and 304, the HTML and JSON 404s, the worker CSP, the versioned cache header and the per-minute 429 all behave as before.

## [2026-10-10 12:13 PT] — Move link analysis out of app.py

### Why
- Second step of splitting `website/app.py`, one area per PR: link extraction and destination checks, which email and text messages share.

### Files changed
- `website/link_analysis.py` (new, 536 lines) — 27 definitions moved verbatim: `_extract_links`, `_analyze_link_destinations`, `_visible_link_host`, `_label_uses_brand_lookalike`, shortener/IP/IPFS/free-hosting checks, `_link_hosts` and their constants. They depend on nothing left in `app.py`.
- `website/app.py` (4,526 → 4,047 lines) — imports them back for callers and tests; drops the imports only the moved code used (`escape_html`, `tldextract`, `_BRAND_SITE_LABELS`, `_confusable_skeleton`).
- `website/tools/counterfactual_evidence.py` — the `link_display_mismatch` and `link_brand_lookalike` replays patch `_visible_link_host` and `_label_uses_brand_lookalike` on `link_analysis`, where they are now called; a patch on `app` no longer reached them (`test_specific_link_rule_replay_keeps_other_link_rules` caught it).
- `README.md` — project structure.

### Effect
- No behaviour change: an AST comparison with `main` shows the 27 moved statements and the 235 remaining ones unchanged and in order. Backend unittest 1284 tests OK (10 Redis skips); `vercel_runtime_smoke.py`, the synthetic evaluation comparison and `ruff` pass. Planting two bugs in `link_analysis.py` fails 13 tests.

## [2026-10-10 11:35 PT] — Move the domain checks out of app.py

### Why
- `website/app.py` had grown to 4,922 lines. The owner chose to split it one area per PR, starting with the least coupled one: the `/api/verify-email` checks.

### Files changed
- `website/domain_verification.py` (new, 417 lines) — `_verify_message`, `_resolve_public_smtp_addresses`, `_smtp_probe`, `_check_spf`, `_check_dmarc`, `_check_domain_age`, `_check_mx_ptr`, `_lookup_mail_domain` and `_summarize_verification`, moved verbatim.
- `website/app.py` (4,922 → 4,526 lines) — imports them back, so `app._smtp_probe` and the rest still work and tests that patch them on `app` still reach the endpoint. The endpoint, `VERIFICATION_TIMEOUT`, the worker pool and `VerifyRequest` stay. `socket` and `smtplib` stay imported for tests that use `app.socket` and `app.smtplib`.
- `README.md` — project structure.

### Effect
- No behaviour change: the moved block is byte-identical (`cmp` against `main`); backend unittest 1284 tests OK (10 Redis skips); `vercel_runtime_smoke.py` and `ruff` pass. Planting three bugs in `domain_verification.py` fails 7 tests, so the suite exercises the new module. A Lite-mode `/api/verify-email` call with real DNS returns a complete domain result.

## [2026-10-09 22:51 PT] — Upgrade FastAPI, uvicorn and Playwright (7-day cooling period)

### Why
- Dependency refresh. The owner chose to take only releases published at least 7 days earlier (on or before 2026-10-02), so fastapi 0.143.0, pydantic 2.14.0, dnspython 2.9.0, tldextract 5.4.0, phonenumberslite 9.0.41 and Playwright 1.64.0 (all 2026-10-03 to 10-09) wait for a later round.
- scikit-learn stays 1.9.0: the committed artifact was pickled with 1.9.0 and the loaders reject another patch version (`test_artifact_loaders_reject_different_sklearn_patch`), so 1.9.1 needs a rebuilt and re-evaluated model.

### Files changed
- `requirements.txt`, `pyproject.toml` — fastapi 0.141.1 → 0.142.2, uvicorn 0.52.4 → 0.54.0.
- `requirements-dev-py312-macos-arm64.lock.txt` — re-resolved in a fresh CPython 3.12.9 venv with transitive packages held to the same cutoff: adds `opentelemetry-api==1.45.0` (Apache-2.0, now required by FastAPI; API only, no SDK or exporter, so nothing is sent), `filelock` back to 4.0.4.
- `website/tools/visual/package.json`, `package-lock.json` — `@playwright/test` 1.62.1 → 1.63.0 (upstream dropped the optional `fsevents`).
- `.github/workflows/ci.yml`, `visual-baselines.yml` — container `mcr.microsoft.com/playwright:v1.63.0-noble`; `browser-checks.yml` installs `playwright@1.63.0`.
- `website/tools/visual/README.md`, `website/tools/browser-checks/README.md` — the version mentions.

### Effect
- In the fresh venv: `pip check` clean; backend unittest 1284 tests OK (10 Redis skips); `vercel_runtime_smoke.py` passes with the committed model (sha256:a0a503a0cd61); the synthetic evaluation still passes `compare_evaluations.py` against `baseline.json`; uvicorn serves `/health`, `/api/analyze-sms` and `/api/analyze-content` with no server errors.
- Only direct pins are fixed: CI and Vercel still resolve transitive packages to their newest releases.

## [2026-10-09 22:10 PT] — CI syntax-checks every tracked script

### Why
- The "Check JavaScript syntax" step listed 38 files by hand and had missed six: `app-sms.js`, `compat.js`, `analytics-init.js`, `theme-init.js`, `vision-cid.mjs` and `vision-html.mjs`.

### Files changed
- `.github/workflows/ci.yml` — the step runs `node --check` on every tracked `.js` and `.mjs` file outside `website/static/vendor/`.
- `docs/testing.md` — the local commands use the same check and `node --test website/static/*.test.mjs`, as CI does, instead of five named test files.

### Effect
- 73 files are checked (38 before), all passing on Node 23. Appending `function (` to `app-sms.js` makes the step fail (negative control).

## [2026-10-09 22:10 PT] — Refresh the development lock snapshot

### Why
- `requirements-dev-py312-macos-arm64.lock.txt` lacked `phonenumberslite==9.0.40`, which the SMS mode added to `requirements.txt`.

### Files changed
- `requirements-dev-py312-macos-arm64.lock.txt` — re-resolved from `requirements-dev.txt` in a fresh CPython 3.12.9 venv (pip 24.3.1).

### Effect
- Adds `phonenumberslite==9.0.40`; transitive `charset-normalizer` 3.5.1 → 3.5.2 and `filelock` 4.0.4 → 4.1.0. Direct pins are unchanged. `pip check` is clean and the backend unittest suite passes in that venv.

## [2026-10-09 22:10 PT] — Document the text-message mode

### Why
- The SMS mode has run in production as a test since 2026-10-08, but the README, the API overview and the deployment settings did not mention it.

### Files changed
- `README.md` — the mode in the introduction, "What it checks", "Limitations" (gate status: Chinese scams 64.9% against 70%) and the project structure (`sms_analysis.py`).
- `docs/api.md` — `POST /api/analyze-sms`: request bounds, the 404 when off, the response fields (`sender_kind`, `claimed_brand`, `official_channels`, `domain_registrations`), the `unknown` level and SMS feedback.
- `docs/deployment.md` — `SMS_ANALYSIS_ENABLED` in the settings table.

### Effect
- Documentation only; no behaviour changes.

## [2026-10-09 14:50 PT] — CI pulls Redis from Amazon ECR Public

### Why
- The test jobs of PR #26 failed twice before any test ran: GitHub's runners hit Docker Hub's unauthenticated pull limit ("toomanyrequests") and then timeouts while pulling the `redis:7-alpine` service image.

### Files changed
- `.github/workflows/ci.yml` — the Redis service uses `public.ecr.aws/docker/library/redis:7-alpine`, the same official image mirrored on Amazon ECR Public.

### Effect
- The test jobs no longer depend on Docker Hub's anonymous limit. No code or test changes.

## [2026-10-09 14:16 PT] — Report an issue on text message results

### Why
- Validating the SMS mode further needs real misjudgements, and a text message result had no "Report an issue" button: production mistakes could not reach the analysts' queue as they do for email checks.

### Files changed
- `website/feedback_api.py` — `/api/feedback` accepts `input_mode: sms`. With consent the report keeps the sender (at most 256 UTF-8 bytes) and the text (8,000); analysts see them as the report's body. Consent to private evaluation stays limited to email content and email files.
- `website/static/feedback.js`, `website/static/app-sms.js`, `website/static/index.html` — a "Report an issue" button on the text message result (shown when feedback is enabled), the report's analysis summary (rule codes with dots written as underscores, no 0–100 score), and the context cleared when the input changes; static asset versions bumped.
- `website/tests/test_feedback_api.py`, `website/static/app.test.mjs` — a consented SMS report stored for review, a source-free one, and rejected fields, evaluation consent and sizes; the button and the analysis summary; the page's 43 actions.

### Effect
- Readers can tell the analysts that a text was misjudged, with or without the text itself. Checked locally with feedback storage on: the dialog hides the evaluation consent and the report is saved (201).

## [2026-10-09 11:45 PT] — Downloadable reports for text message checks

### Why
- The owner asked whether text message results appear in a report. They did not: only the email address and email content checks could be downloaded, and the recent-checks list keeps only the verdict.

### Files changed
- `website/static/app-reports.js` — `smsReportMarkdown`: verdict, the sender's kind, the organisation it claims, the email/foreign-sender note, categories, findings and how to verify through official channels; `downloadReport` and `buildReport` accept `sms` (Markdown and JSON). Like the API response, the report holds neither the sender's number nor the text.
- `website/static/index.html` — Markdown and JSON download buttons on the text message result.
- `website/static/app-sms.js`, `website/static/i18n.js`, `website/static/i18n-zh.js` — report labels in English and Chinese; "How to verify" on a text result says "this text" instead of "this email" (`sms.verify.channel`); static asset versions bumped.
- `website/static/app.test.mjs` — the SMS report's Markdown and JSON, nothing downloaded before a result, the labelled download group, and the page's 42 actions.

### Effect
- A text message check can be saved as `phishguard-sms-<time>.md` or `.json`, built in the browser; nothing is sent anywhere.

## [2026-10-09 10:54 PT] — SMS mode: a note on email and foreign senders

### Why
- The owner asked how well the number checks work. In the owner's 211 labelled texts, 26 of 35 scams and none of 176 genuine texts came from an email address or a foreign number, yet the number rules decided no alert. Scoring such senders (+2) was measured and not adopted: it would have caught no more of the owner's scams, and its false alarms on friends' iMessages and services abroad cannot be measured.

### Files changed
- `website/static/app-sms.js`, `website/static/index.html` — a note under "Sender" when it is an email address or a foreign number; no points.
- `website/static/i18n.js`, `website/static/i18n-zh.js` — the note in English and Chinese; static asset versions bumped.
- `website/static/app.test.mjs` — the note shows for an email sender and not for a short code.
- `docs/evaluation.md` — "SMS mode: the sender's kind as evidence": the counts, the tried change and a gap seen (English prize texts with a link stay Low).

### Effect
- No score or verdict changes. Readers see why an email or foreign sender is worth a second look.

## [2026-10-09 10:23 PT] — The Text Message tab on older phone browsers

### Why
- The owner could not see the SMS test on a phone browser. The tab starts hidden and is shown by the configuration request, which ran after thirteen setup steps. On older phone browsers (iOS Safari before 15.4, older Android WebViews and in-app browsers) a setup step throws, because `Object.hasOwn` (every translation lookup), `matchMedia(...).addEventListener` (theme) or `crypto.randomUUID` is missing, or `feedback.js` does not parse (`||=`). The email tabs, plain HTML, still showed; the Text Message tab never did.

### Files changed
- `website/static/compat.js` (new, ES5) — polyfills `Object.hasOwn`, `MediaQueryList.addEventListener` and `crypto.randomUUID` where missing; the first script of `index.html`, `cases.html` and `404.html`.
- `website/static/app.js` — each setup step runs on its own (`runSetupSteps`), so one failing step no longer stops the others or the configuration.
- `website/static/feedback.js` — the one `||=` written out, so the file parses before Safari 14 and Chrome 85.
- `website/static/app.test.mjs`, `cases.test.mjs`, `i18n.test.mjs` — an older browser without these APIs gets them from compat.js; compat.js is first on every page and ES5; a failing step does not stop the rest; script counts include compat.js. Static asset versions bumped.

### Effect
- On modern browsers nothing changes (checked at phone width locally: compat.js first, Text Message tab shown, no console errors). On older ones the page setup and the Text Message tab no longer depend on these newer APIs. Optional chaining (`?.`) still needs iOS 13.4 or Chrome 80.

## [2026-10-09 10:03 PT] — SMS mode: Chinese rules from the IMC 2025 Chinese reports

### Why
- The 42 Chinese reports, sealed and scored once at 0 of 42, were read to learn what the Chinese rules miss. They are development data from now on.

### Files changed
- `website/sms_analysis.py`:
  - `sms.loan_offer` (new, +4, at least Medium): a loan or credit line "approved" to claim through a link;
  - `sms.account_lure` also covers ETC and phone-line suspensions; `sms.account_threat` also covers Chinese new-device alerts and "确认您的帐户";
  - `sms.parcel_problem` covers parcels held by customs with a number to call; `sms.authority_threat` needs 您, covers court "execution" threats, and its warning filter looks for warning phrasing rather than the word 诈骗;
  - `sms.stock_group` covers free stock-tip services; "飞机@" counts as a private messenger; more traditional characters are read as simplified.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the loan message; the stock message names tip services; static asset versions bumped.
- `website/tests/test_sms_analysis.py` — each new branch firing and not firing (a genuine Apple notice, a 微众银行 bill, a China Mobile balance warning, a question about court enforcement).
- `docs/evaluation.md`, `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — what the reports showed, and the rule table.
- `CHANGELOG.md`, `docs/evaluation.md` — corrects the IMC English development count of the entry below to 1,977 (24.8%): the earlier figure predated the toll-free fix in the same commit.

### Effect
- IMC Chinese reports 0 → 13 of 42 (in-sample; about a third are not scams).
- No change on the full 707,396 Chinese normal texts (41 flagged), the owner's normal texts, the public ham or the IMC English development half; FBS development half financial fraud 18 → 20.

## [2026-10-09 01:30 PT] — SMS mode: the wording rules on the sealed IMC halves and the full Chinese corpus

### Why
- The rules of `2f751a0` were committed before the sealed IMC English half and the 42 Chinese reports were scored, once, and before the full Chinese normal corpus was rerun.

### Files changed
- `docs/evaluation.md` — "SMS mode: wording rules from public scam reports, and Chinese false alarms": the two datasets, their split, seal and preprocessing, results per scam type, false alarms, and the gate.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — "Launch status" update.

### Effect
- IMC English sealed half: 364 → 1,913 of 7,982 at Medium or above (4.6% → 24.0%); the development half moved the same way (24.8%).
- IMC Chinese, sealed: still 0 of 42. The Chinese scam side of the gate is not met; the mode stays a test.
- Chinese normal texts flagged: 288 → 41 of 707,396. The owner's normal texts and the public ham stay at 0.

## [2026-10-09 01:17 PT] — SMS mode: wording rules from public scam reports, and fewer false alarms on Chinese chat

### Why
- The owner asked to raise accuracy. Two downloads (owner-approved) showed the gaps: the IMC 2025 smishing reports (Agarwal et al., CC-BY-4.0) were 4.4% at Medium or above once their link placeholders became neutral links, because the SMS mode leaned on links; and a 720K-text Chinese corpus (hrwhisper/SpamMessage) showed 288 of 707,396 normal texts flagged, mostly by `sms.split_words`.

### Files changed
- `website/sms_analysis.py`:
  - six rules, each +4 and at least Medium, written on the IMC development half and known Chinese scripts: `sms.account_threat` (block, suspend or KYC/PAN, new-device or changed-details alerts, points to redeem), `sms.utility_cutoff`, `sms.refund_lure`, `sms.family_new_number`, `sms.parcel_problem` (English and Chinese), `sms.authority_threat` (embassy, customs, police; anti-fraud warnings left out);
  - a callback counts only when the number is not a toll-free or service line ("1-800-…" no longer reads as a Chinese mobile);
  - `sms.split_words` needs a break that splits a lure word (佣.金, 微|信), so chat's "~", "···" and foreign names' "·" no longer fire;
  - `sms.gambling_promo` counts 赌场/赌城/网赌 instead of any 赌 and skips news and warnings; `sms.stock_group` needs an invitation to join and a promotional hook.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the six messages in English and Chinese; static asset versions bumped.
- `website/tests/test_sms_analysis.py` — each new rule firing and not firing (Chase, Apple, PG&E, GOV.UK, IRS, USPS, 顺丰, 公安部 anti-fraud texts), and the stricter split-words rule.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — the rule table gains the six.

### Effect
- IMC English development half at Medium or above: 349 → 1,977 of 7,987 (bank 50 → 1,321, government 22 → 135, "hey mum" 0 → 21 of 30). Mishra and Soni smishing 324 → 343 of 562.
- Chinese normal texts flagged: of the 93 the new rules' predecessors still flagged in the full corpus, 41 remain (mostly part-time and rebate spam labelled normal).
- No change on the owner's normal texts (0) or the public ham (0), or on the FBS development half. The sealed IMC halves are scored once on this commit.

## [2026-10-09 00:44 PT] — SMS mode: the Chinese rules on the sealed half of the FBS texts

### Why
- The six Chinese rules were committed (`316eefb`) before the sealed test half of the FBS texts was scored; the result decides where the Chinese side of the launch gate stands.

### Files changed
- `docs/evaluation.md` — "SMS mode: Chinese scam rules from public fake-base-station texts": the dataset, its preprocessing and limits, the split, seal and analysis plan, development and test results per category, controls, and the owner's held-out Chinese scams.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — "Launch status" update.

### Effect
- Sealed test half, scored once: 1,328 of 2,046 Chinese scam texts at Medium or above (64.9%): bank phishing 89.3%, gambling 51.4%, other fraud 36.3%, financial fraud 27.4%. Texts whose template is not in the development half: 65.5%.
- The owner's held-out Chinese scams: 3 of 6. The gate's 70% is not met, so the SMS mode stays a test. No normal text changed.

## [2026-10-09 00:41 PT] — SMS mode: six Chinese scam rules from public fake-base-station texts

### Why
- The owner's Messages hold only 9 Chinese scam templates, too few to calibrate or judge the gate, and the current rules caught almost none of the public FBS spam texts (CCS 2020; 4 of 2,049 in the development half). The owner chose to download its fraud and gambling categories.

### Files changed
- `website/sms_analysis.py` — six rules, each +4 and at least Medium, reading a view of the text with traditional and look-alike characters made plain:
  - `sms.account_lure`: bank points, security token, card limit or real-name records, with a link outside the official domains or a mobile number;
  - `sms.gambling_promo`: gambling terms with sign-up, deposit, rebate, payout or bonus offers, and a link or contact;
  - `sms.prize_link`: being picked for a large prize, with a link to claim it;
  - `sms.flight_compensation`: a cancelled flight, compensation and a number to call;
  - `sms.stock_group`: stock tips and a group to join;
  - `sms.album_link`: photos or "you're in the news" with a link.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the six messages in English and Chinese; static asset versions bumped.
- `website/tests/test_sms_analysis.py` — each rule firing and not firing (genuine bank, telecom, airline, lottery and fund texts).
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — the rule table gains these six and the three from the owner's calibration.

### Effect
- FBS development half at Medium or above: bank phishing 4 of 891 → 805, gambling 4 of 799 → 413, other fraud 0 of 292 → 143, financial fraud 0 of 63 → 18.
- No normal text changes: the owner's US and Chinese normal texts stay 0 at Medium or above, as do the public 4,834 ham texts; no new rule fires on any of them. The sealed test half is scored once on this commit.

## [2026-10-08 23:34 PT] — SMS mode: batch 3 supplement of the owner's texts

### Why
- Batch 3 left the US normal texts short of the gate's 50, and Chinese scams were too few to judge. Codex found 48 more texts in the Messages window and the owner labelled them.

### Files changed
- `docs/evaluation.md` — "SMS mode: the owner's texts": the supplement (39 US and 7 Chinese normal texts, 2 Chinese promotion scams), its single scoring on `3e936ce`, the check of the owner's full 160-template review, and the gate with the supplement.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — "Launch status": where the gate stands.

### Effect
- Normal texts meet the gate in both regions: US 0 of 69 and Chinese 0 of 52 at Medium or above. US scams 11 of 12.
- Chinese scams do not (2 of 5): the gambling and off-platform gift promotions get no finding. The mode stays a test. No rule changed.

## [2026-10-08 21:26 PT] — Official domains of the five protected brands

### Why
- `link.brand_lookalike` scored links to the protected brands' own other domains High: Apple's `apple.co` in the owner's third batch of texts, and Google, Amazon, Microsoft and PayPal country or service domains in public legitimate mail.

### Files changed
- `website/email_structure.py` — `_PROTECTED_BRAND_DOMAINS` holds each brand's domains from its own published lists (Google's 187 search domains, Amazon's stores, Microsoft 365 sign-in domains, apple.co, apple.news and Apple service domains, paypal.me and paypalobjects.com) and the brands' top-level domains (.apple, .amazon, .google, .microsoft). `amazonaws.com` and `onmicrosoft.com` stay out.
- `website/tests/test_protected_brand_domains.py` (new) — official hosts are not lookalikes in mail or texts, lookalikes built on them and shared hosts stay High, and display names from the brands' own domains are not impersonation.
- `docs/evaluation.md` — "Official domains of the five protected brands": sources, before/after counts and the `amazonaws.com` variant.

### Effect
- No alert count changed in the owner's genuine downloads, the new brand emails, PhishFuzzer or Nazario 2023–24, and no phishing message lost evidence.
- Public legitimate messages linking these domains: PhishNChips 19 alerts → 0, CEAS-08 4 → 1 (the one left links `amazonaws.com`).
- The owner's batch 3 of texts: the one genuine text at High (`apple.co`) is no longer flagged.

## [2026-10-08 21:06 PT] — SMS mode: corrected senders and a third batch of the owner's texts

### Why
- The owner found that the three China Mobile texts of batch 2 come from 1065813919, a China Mobile SMS port, which Codex had recorded as an ordinary +86 number. The owner also labelled a full review with 75 more genuine templates.

### Files changed
- `docs/evaluation.md`:
  - batch 2 rescored with the corrected senders: Chinese normal texts 0 of 9;
  - batch 3 (45 Chinese and 30 US genuine texts, scored once): 0 and 1 at Medium or above, the one a genuine `apple.co` link that `link.brand_lookalike` flags;
  - the official domains that rule misses, and the held-out totals against the gate.

### Effect
- No code changes. Held out, Chinese normal texts pass (0 of 54). US normal texts do not yet (one High, 30 texts), and Chinese scams are too few. The mode stays a test.

## [2026-10-08 20:45 PT] — SMS mode: batch 2 of the owner's texts, scored once

### Why
- The sealed batch 2 (24 templates) was scored once against the rules committed in `4adbae8`.

### Files changed
- `docs/evaluation.md` — "SMS mode: the owner's texts (2026-10-09)": the data, the split, both batches against the gate, and the limits; counts only.

### Effect
- US scams 11 of 12 (92%) and Chinese scams 2 of 3 at Medium or above.
- 3 of 9 Chinese normal texts alerted, all China Mobile texts whose sender was recorded only as "other Chinese number" and scored with a landline stand-in. Whether they are real false alerts waits for the owner to check the sender. The gate is not met, and the mode stays a test.

## [2026-10-08 20:44 PT] — SMS rules calibrated on the owner's first batch

### Why
- The owner labelled 85 deidentified text templates from macOS Messages (53 normal, 32 scam). They were split into batch 1 (61: the 36 already counted and half of the new ones, seed 166, stratified by label and language) and a sealed batch 2 (24).
- On batch 1, before these changes:
  - the gate's US criteria held: 0 of 33 normal texts at Medium or above, and 10 of 14 scams (71%);
  - the Chinese ones did not: 1 of 11 normal texts at Medium (9%), and 0 of 3 scams.
- The owner allowed reading only the six scams batch 1 still missed. Their wording guided the rules below, so batch 1's results after the change are in-sample; batch 2 is the test.

### Files changed
- `website/sms_analysis.py`:
  - Chinese service numbers with an extension (100xx, 95xxx, 96xxx, 12xxx plus up to four digits, such as 1008611) are short codes. A genuine China Mobile text from a 7-digit number was a sender mismatch.
  - `sms.external_contact_lure`: easy money (rebates, commissions, part-time pay, sure returns, gambling, refunds) and a private messenger (WeChat, QQ, WhatsApp, Telegram); a business's WeCom is left out.
  - `sms.split_words`: four or more Chinese words broken up with symbols ("佣.金", "微|信"); the rules read the text joined again.
  - `sms.job_offer`: a job with pay or hours, and a short link, a messenger or "send a message to this number".
  - Each rule is +4, at least Medium.
- `website/app.py` — the SMS parcel lure also reads a parcel with an action to take (confirm, set, update, reschedule…) and a link that is neither official nor a known tracker.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the three messages; asset versions bumped.
- `website/tests/test_sms_analysis.py` — synthetic texts for each change, including genuine ones that must not fire: WeCom coupons, a bank's maturity notice, a WhatsApp help line, a flight route with hyphens, a name with a middle dot, a job alert on indeed.com, a recruiter asking for a reply.

### Effect
- Batch 1, in-sample: 14 of 14 US and 3 of 3 Chinese scams at Medium or above; 0 of 33 US and 0 of 11 Chinese normal texts.
- Public Mishra and Soni data: still 0 of 4,834 normal texts; smishing 57.6%.
- Batch 2 is scored once, after this commit.

## [2026-10-08 19:48 PT] — SMS mode on in production as a test, before the launch gate

### Why
- The owner chose to put the SMS mode online now and update it after calibration on their own texts, instead of waiting for the launch gate.

### Files changed
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — "Launch status": the decision, and that the gate, calibration and known gaps still apply.
- Vercel (not in the repository): `SMS_ANALYSIS_ENABLED=true` for the Production environment.

### Effect
- After the next production deployment the "Text Message" tab and `/api/analyze-sms` are live. Chinese wording is uncalibrated, and genuine loyalty texts or US businesses texting from 10-digit numbers may be flagged (see the spec's known gaps).

## [2026-10-08 19:43 PT] — Export texts from macOS Messages for the SMS launch gate

### Why
- The SMS mode launches only after the owner's own texts meet the gate, and copying them by hand is the obstacle. The owner asked for a local script that reads the Messages database.

### Files changed
- `website/tools/export_sms_from_messages.py` — new:
  - `extract` opens `~/Library/Messages/chat.db` read-only. It exports only one-way conversations (one other party, never answered), so personal chats and group chats are left out, and reads the text from `attributedBody` where newer macOS keeps it.
  - It masks verification codes, card tails, the owner's numbers (`--own-number`) and email local parts. A personal sender becomes an example number of the same kind and country, so the SMS mode classifies it the same way.
  - Identical masked texts are kept once with a count, and rows are split into batch 1 and a held-out batch 2 per region (seed 166). It writes `review.csv` outside the repository and prints counts only.
  - `finish` requires every row to be labelled `scam`, `legitimate` or `skip`, then writes `batch1.jsonl` and `batch2.jsonl` for `evaluate_sms.py` and names the batches short of 50 legitimate texts.
- `website/tests/test_export_sms_from_messages.py` — new, on a synthetic `chat.db`: one-way conversations only, the database unchanged, masking, `attributedBody`, `--since`, duplicates, batches, labels, and an output inside the repository refused.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — the tool in the data section.

### Effect
- No change to the site. Terminal needs Full Disk Access to read `chat.db`; the owner reads every row before labelling, as masking cannot find names.

## [2026-10-08 19:19 PT] — Restore the missing 2026-09-17 scroll-reveal entry

### Why
- The entry for the scroll-reveal easing fix (commit `cfb334b`) was written but never committed to `main`. It sat on two unmerged Cursor branches, `cursor/changelog-scroll-reveal-542f` (draft PR #4, closed 2026-10-08) and `cursor/sci-fi-frontend-refresh-542f`, with the same text.

### Files changed
- `CHANGELOG.md` — "Smoother scroll reveal in 'How It Works'" restored in its chronological position (2026-09-17 13:32 PT), from draft PR #4's version, which says it was missed.

### Effect
- No code changes; the history of `cfb334b` is complete.

## [2026-10-08 19:19 PT] — Cursor Cloud Agent environment

### Why
- Draft PR #9 (closed 2026-10-08) added a development environment for Cursor's Cloud Agents and was never merged. The repository already uses Cursor (`.cursor/rules/changelog.mdc`).

### Files changed
- `.cursor/environment.json` — from PR #9 unchanged: create `.venv`, install `website/requirements.txt` (which includes the serving pins), and run the app with uvicorn on port 8000.

### Effect
- No change to the site or CI.

## [2026-10-08 19:19 PT] — Scroll reveal replays on every pass

### Why
- On 2026-09-17 the owner reported that the fade/slide-in played only the first time content scrolled into view; scrolling back showed nothing. Draft PR #5 fixed it on the old single `app.js` and was never merged (closed 2026-10-08). The homepage script has since been split, so the change is ported rather than merged.

### Files changed
- `website/static/app-layout.js` — `setupScrollReveal` keeps observing every target (`threshold: 0`). An element that fully leaves the viewport drops `.in-view`, `.settled` and `.from-above`; on re-entry it plays again with the per-batch stagger. An element entering across the top edge gets `.from-above`. `animationend` adds `.settled` instead of removing the classes.
- `website/static/style.css` — `.reveal.in-view.from-above` uses `reveal-in-down` (an 18px drift down), and `.reveal.in-view.settled` drops the animation fill so hover transforms work.
- `website/static/app.test.mjs` — new: entering from below, settling, resetting on leaving, and re-entering from above; nothing is unobserved.
- Asset versions bumped.

### Effect
- Content fades in each time it scrolls into view, from the side it arrives on. With reduced motion, or without IntersectionObserver, nothing is hidden, as before.

## [2026-10-08 16:12 PT] — The homepage revalidates by content

### Why
- Testing a preview deployment, a browser that had visited before kept the previous deployment's homepage. It loaded `i18n.js?v=111` while the new page names `?v=115`, so it showed raw dictionary keys and untranslated messages.
- Starlette's `FileResponse` derives its ETag from the file's modification time and size, and Vercel gives every deployed file the same time (`Last-Modified: Sat, 20 Oct 2018 01:46:40 GMT`). A deployment that changes only `?v=` numbers of the same length keeps the ETag, and the browser's revalidation is answered 304. This defeats the `?v=` asset versioning for returning visitors, in production too.

### Files changed
- `website/app.py` — `_revalidated_file`: the homepage and the favicon get an ETag from the SHA-256 of their bytes and `Cache-Control: no-cache`, with no `Last-Modified`. A matching `If-None-Match` (weak or strong) gets 304. `/cases` is unchanged: it is `no-store` and never reused.
- `website/tests/test_html_etag.py` — new: the ETag is the page's hash; revalidation; two pages of the same size and time, which `FileResponse` gives one ETag, get different ones, and a browser holding the old one receives the new page; the favicon.

### Effect
- After each deployment, returning visitors revalidate the homepage and get the new page with its new asset versions. An unchanged page still costs only a 304.
- Checked on a local server: 200 with the hash ETag, 304 with it, 200 and the full page with a stale one.

## [2026-10-08 16:04 PT] — SMS: premium-rate numbers from libphonenumber

### Why
- The owner asked whether phone-number tools (PhoneInfoga, numint, Ignorant, caller-ID apps) would help. Their privacy-safe core is Google's libphonenumber. Their online parts send numbers to third parties or probe a person's accounts, which the SMS mode does not do. Premium-rate numbers, a fact of each numbering plan, give a callback signal that is not tied to old British prefixes.

### Files changed
- `requirements.txt`, `pyproject.toml` — `phonenumberslite==9.0.40` (Apache-2.0, offline metadata only, released 2026-09-24).
- `website/sms_analysis.py` — international and North American senders typed by libphonenumber, with a `premium_rate` kind; `sms.premium_callback` for a request to call or text a premium-rate number.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`, `website/static/i18n.test.mjs` — the message and the sender kind; asset versions bumped.
- `website/tests/test_sms_analysis.py` — premium numbers and other numbers; the Ofcom drama range `+44 7700 900…` is no valid number.
- `docs/evaluation.md`, `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — results and limits.

### Effect
- Mishra and Soni test half: smishing at Medium or above 136 → 156 of 281 (55.5%), spam 21 → 43 of 235, normal texts still 0 of 2,417.
- VoIP numbers are still not recognised in the US.

## [2026-10-08 15:54 PT] — SMS calibration on public data: prize callbacks, IP links, the signed brand

### Why
- The public baseline caught 4 of 562 smishing texts. The missed ones were mostly prize scams asking for a call or text to a number. A genuine USPS text scored Low because the impersonation category counted the brand it signed as.

### Files changed
- `website/sms_analysis.py`:
  - `sms.prize_callback`: prize or award wording with a request to call, text or dial a number, +4, at least Medium.
  - IPv4 hosts after an explicit scheme are links.
  - `sms_findings` returns the claimed organisation's names.
- `website/app.py` — `_discount_claimed_brand`: in a text, the organisation it signs as is no impersonation keyword; other brands still count.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the `sms.prize_callback` message; asset versions bumped.
- `website/tests/test_sms_analysis.py`, `website/tests/test_evaluate_sms.py` — the new rule with "won't" and appointment texts, the discount, IP links.
- `docs/evaluation.md` — "SMS mode: a prize-callback rule, calibrated on public data": rules from the development half, test half scored once. `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — the rule, the discount and their limits.

### Effect
- On the sealed test half of the Mishra and Soni dataset: smishing at Medium or above 2 → 136 of 281 (0.7% → 48.4%), spam 0 → 21 of 235, normal texts unchanged at 0 of 2,417.
- The genuine USPS example now gives "No Known Scam Signs Found".
- Still behind the flag. The owner's texts decide the launch.

## [2026-10-08 15:40 PT] — SMS mode: public-data baseline

### Why
- Task 9 of the SMS plan starts with a baseline on public data. The owner chose the Mishra and Soni SMS phishing dataset (CC BY 4.0) and not the UCI collection, with which it shares 4,753 texts.

### Files changed
- `docs/evaluation.md` — "SMS mode: public-data baseline (2026-10-08)": 0 of 4,834 normal texts and 4 of 562 smishing texts at Medium or above, and what the missed texts have in common.

### Effect
- No code changes. The data stays outside the repository. The baseline shows that recall, not false alerts, is the gap, and that the public texts are older prize scams with premium-rate numbers rather than today's link scams.

## [2026-10-08 15:36 PT] — SMS evaluation tool

### Why
- Task 8 of the SMS plan: a counts-only measurement for calibration and the launch gate.

### Files changed
- `website/tools/evaluate_sms.py` — new: reads JSONL cohorts of labelled texts (region `cn` or `us`, optional sender, text, label `scam` or `legitimate`), runs `app.analyze_sms` with no network, and reports verdicts by cohort, label and region, the share at Medium or above, and how often each rule or keyword category fires on legitimate texts. A malformed row is reported by line number only.
- `website/tests/test_evaluate_sms.py` — new: counts, shares, rules on legitimate texts, no text or sender in the report, row validation.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — a known gap found while testing it.

### Effect
- No change to the site. On the tool's synthetic test texts, a genuine USPS delivery text scores Low because the impersonation category is a list of brand names; calibration decides whether texts discount the claimed brand's own name.

## [2026-10-08 15:33 PT] — The SMS tab

### Why
- Task 7 of the SMS plan: a homepage tab for the SMS analysis, shown only when the server enables it.

### Files changed
- `website/static/index.html` — a third tab, "Text Message", hidden by default, and its panel: sender and text fields (64 and 2,000 characters, with a count), the privacy notice, three synthetic examples (an unpaid-toll text, a fake Chinese bank text, a genuine USPS delivery text), and a result area with the banner, matched categories, a sender card (the sender's kind, the claimed organisation and a reminder that a matching number can be forged), the organisation's official channels and the findings.
- `website/static/app-sms.js` — new: shows the tab when `/api/config` reports `sms_analysis_enabled` (and then follows a `?tab=sms` link), posts to `/api/analyze-sms` with cancellation, renders the result with the content tab's helpers, re-renders on a language switch and records verdict-only recent checks.
- `website/static/app.js`, `app-config.js`, `app-layout.js`, `app-reports.js` — the SMS actions, the configuration hook, `?tab=sms` and arrow keys that skip a hidden tab, and the `sms` recent-check mode.
- `website/static/style.css` — a hidden tab stays hidden, the sliding highlight divides in thirds when three tabs show, and the tabs tighten at 560 px and drop icons at 420 px.
- `website/static/i18n.js`, `website/static/i18n-zh.js` — English and Chinese strings for the tab, the ten sender kinds and three risk labels: "No Known Scam Signs Found", and High and Critical labels for texts, since the email ones say "钓鱼邮件". `website/app.py` uses them.
- `website/static/*.test.mjs` — `app-sms.js` in the page-script lists; the page actions, tab semantics, the hidden-by-default tab and the rendered result; the `sms.kind.*` key family. Asset versions bumped.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — the text labels.

### Effect
- In production nothing changes until `SMS_ANALYSIS_ENABLED` is set: the tab stays hidden, so the visual baselines are unchanged.
- Checked on a local server with the flag on: the fake bank example gives "High Risk — Likely a Scam Text" with four findings and ICBC's official channels, in English and Chinese; at 375 px the three tabs fit on one line in both languages, with no horizontal scroll.

## [2026-10-08 15:20 PT] — SMS endpoint behind SMS_ANALYSIS_ENABLED

### Why
- Task 5 of the SMS plan: an endpoint for the SMS analysis, off until the launch gate passes.

### Files changed
- `website/config.py` — `sms_analysis_enabled` from `SMS_ANALYSIS_ENABLED`, false by default.
- `website/app.py` — `SmsRequest` (sender up to 64 characters, text up to 2,000) and `POST /api/analyze-sms`: 404 when off, 400 for an empty text, the analysis on the analysis workers, then the registration dates of up to five link domains when RDAP lookups are on (context only, as for email). The sender is never echoed. The path is rate-limited and its bodies are capped at 16,000 bytes. `/api/config` reports `sms_analysis_enabled`.
- `website/tests/test_sms_endpoint.py` — new: the flag, validation, the response, link-domain ages with a stubbed lookup, and the rate limit.
- `website/tests/test_app_security.py` — the public configuration now includes `sms_analysis_enabled`.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — over-long fields get 422 from the request model, as on the other analysis endpoints.

### Effect
- No change for visitors: the flag is off and the page has no SMS tab yet.

## [2026-10-08 15:17 PT] — SMS analysis: sender kinds, brand claims and text-message rules

### Why
- Tasks 2–4 of the SMS plan: the analysis behind the SMS mode, before its endpoint and tab.

### Files changed
- `website/sms_analysis.py` — new: `classify_sender` (ten kinds, `+86`/`0086`/`+1`, full-width digits, zero-width characters), `claimed_brand` (a signature or the name a text opens with; Chinese organisations by their Chinese names only; `sender_only` services left out), `text_links` (links with or without a scheme, bare hosts only with a known public suffix), and the rules `sms.sender_mismatch`, `sms.sender_mismatch_weak`, `sms.link_off_brand` and `sms.reopen_to_activate`.
- `website/app.py` — `analyze_sms` combines them with the shared plain-text rules (`_text_rule_findings`), the link rules, short links and the fine and delivery lures (`sms.fine_lure`, `sms.delivery_lure`), scored by `fuse_content_risk` with no model; no finding gives `unknown`, never safe. `_lure_points` and `_delivery_wording` are now shared by the email and SMS lures.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the six `sms.*` messages in English and Chinese; asset versions bumped.
- `website/tests/test_sms_analysis.py` — new; `website/tests/test_server_messages.py` — the `sms.` family.
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md`, `docs/superpowers/plans/2026-10-08-sms-scam-detection.md` — brought in line: `app.analyze_sms` composes, because on Vercel the module named `app` is the root entrypoint; claims by opening name, not "within 20 characters" (which counted "我用工行转你了"); the `other_number` kind; separate weak-mismatch and lure codes, since the Chinese email lure messages say "邮件".

### Effect
- No email result changes: the served pipeline gave identical signals on the six usual cohorts before and after (genuine downloads with and without a mailbox, new brand emails with and without, PhishFuzzer recent seeds, Nazario 2023–24).
- Not reachable yet: no endpoint or tab. A Chinese bank-scam text without email-style wording ("账户已冻结…输入密码和验证码") reaches only Low through its link findings; Chinese SMS phrases come from data in calibration.

## [2026-10-08 15:03 PT] — Implementation plan for SMS scam detection

### Why
- The owner approved the SMS design and asked for its implementation plan.

### Files changed
- `docs/superpowers/plans/2026-10-08-sms-scam-detection.md` — new: ten tasks from the branch and baseline through shared scoring, the SMS module, edge cases, the endpoint and flag, messages, the tab, the evaluation tool, calibration and the held-out launch decision.

### Effect
- No code changes.

## [2026-10-08 14:59 PT] — Design for SMS scam detection

### Why
- Scam text messages are increasingly common, and the owner asked for an SMS mode that judges a text from its sender and wording. The owner chose China and the US as regions, pasted text with an optional sender as input, a separate module and endpoint, and the owner's texts plus public datasets as test data.

### Files changed
- `docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md` — new: sender kinds, brand claims, the sender-mismatch, off-brand-link, reopen-to-activate and SMS delivery rules, the reused plain-text rules, an `unknown` verdict when no rule fires, the `SMS_ANALYSIS_ENABLED` flag, and a launch gate fixed before the held-out run.

### Effect
- No code changes. Implementation follows an implementation plan, after Lushangtu123/Phishing-Scam-Email-Detection#11 is merged.

## [2026-10-08 10:40 PT] — Measure several local teachers and their agreement

### Why
- A second teacher from another model family should make errors that do not coincide with Qwen's, so a label both give is safer. Measuring that needs each message put to both models.
- gpt-oss ignores `"think": false` and reasons anyway. On two synthetic messages it read a shipping notice as phishing (90) in 5.2 s; with `"think": "low"` it read both correctly in 0.8 s each.

### Files changed
- `website/tools/evaluate_llm_labeler.py` — `--model` may be repeated. The report then gives each model's counts and their agreement as one teacher: the verdict all give, at the lowest of their confidences; a disagreement goes to a person. `--think MODEL=LEVEL` sets a reasoning level. Each floor also reports `legitimate_to_person`. One model still writes the schema-1 report.
- `website/local_review.py` — `LocalReviewSettings.think`, default `False`, so the served review is unchanged.
- `website/tests/test_evaluate_llm_labeler.py`, `website/tests/test_local_review.py` — agreement counts, argument checks, and the forwarded reasoning level.

### Effect
- No served behaviour changes. The measurement of `gpt-oss:20b` beside `qwen3.8:27b-mxfp8` has not run yet.

## [2026-10-08 10:02 PT] — Merge main into the review follow-ups: CDN notes in docs/deployment.md

### Why
- Main gained the two static-file entries below while this branch had shortened the README and moved its deployment section to `docs/deployment.md` (2026-10-05 17:35 PT), so the merge conflicted in `README.md` and here.

### Files changed
- `docs/deployment.md` — main's paragraph on CDN-served static files and the `pyproject.toml` dependencies, unchanged, where it stood in the old README's "Vercel Hobby deployment" section.
- `README.md` — the short README, with `pyproject.toml` in the project structure.
- `website/tests/test_vercel_static_headers.py` — the docstring points to `docs/deployment.md`.
- `CHANGELOG.md` — the entries of both sides, newest first.

### Effect
- No behaviour change. The two entries below that name `README.md` describe text that now lives in `docs/deployment.md`.

## [2026-10-08 09:45 PT] — Vercel installs dependencies from pyproject.toml

### Why
- The preview deployment of the previous entry failed: once a `pyproject.toml` exists, Vercel's Python builder runs `uv lock` on it, which stopped with "No `project` table found". The previous entry's claim that dependencies stay in `requirements.txt` for Vercel was wrong.

### Files changed
- `pyproject.toml` — a `[project]` table (`requires-python = "~=3.12.0"`, as `.python-version`) listing the serving pins of `requirements.txt`, beside the CDN setting.
- `website/tests/test_vercel_static_headers.py` — the two dependency lists must name the same pins, and the Python requirement must match `.python-version`.
- `README.md` — how Vercel installs dependencies now.

### Effect
- Vercel installs the same direct pins as before, through uv instead of pip; local and CI installs still read `requirements.txt`. To be confirmed on the preview deployment.

## [2026-10-08 09:40 PT] — Serve static files from Vercel's CDN

### Why
- The owner asked why the page loads slowly. Warm, the whole page loads in 0.17 s (22 files, 127 KB). Cold, each `/static` file took 0.8–2.2 s, one after another: Vercel keeps `app.mount("/static", StaticFiles(...))` in the Python Function when the app has top-level middleware, so every CDN cache miss (after a deployment, in a new region, after a day, after idle time) woke the Function.

### Files changed
- `pyproject.toml` — new, Vercel settings only: `[tool.vercel.fastapi.static] cdn = true` promotes `/static` to the CDN despite the middleware. Dependencies stay in `requirements.txt`.
- `vercel.json` — `headers` gives CDN-served `/static` files what the middleware gave them: the security headers, the page Content-Security-Policy (the vision worker scripts keep their own) and, for `?v=` URLs, the versioned-asset Cache-Control. No two rules set the same header, as Vercel does not document which would win.
- `website/app.py` — the security headers and the worker policy are named constants (`SECURITY_HEADERS`, `WORKER_SCRIPT_PATHS`, `WORKER_CONTENT_SECURITY_POLICY`); behaviour unchanged.
- `website/tests/test_vercel_static_headers.py` — new: for nine static URLs the `vercel.json` headers equal the middleware's, no header is set twice, other paths get none, and the CDN setting stays on.
- `README.md` — the static-file delivery and why the headers live in two places.

### Effect
- On Vercel, static files no longer wake the Function. The homepage and API requests still run in it, as do static files missing from the build.
- Browser caching is unchanged (one day for versioned files): with the CDN serving them, expiry no longer reaches the Function, and the short lifetime keeps the margin against a missed `?v=` bump.
- To be confirmed on the preview deployment before merging: the build installs dependencies as before, `/static` responses come from the CDN with these headers, and the page and analysis work.

## [2026-10-08 09:26 PT] — Links to free development and storage addresses

### Why
- The previous entry left out a signal for any link to a free hosting service until it was measured on recent legitimate mail. The owner chose public developer lists: 24,264 messages of 15 `lists.apache.org` archives from 2026-07 to 2026-09 had no such link, nor did any of 60,601 legitimate messages in all, while 99 of 787 Nazario 2023–24 phishing messages did, 83 of them on development, storage or tunnel addresses.

### Files changed
- `website/app.py` — `link.dev_hosting`: a link to Cloudflare R2 or Workers dev URLs, Glitch, Cyclic, Replit, Cloudflare or ngrok tunnels, 000webhost or Azure storage web endpoints adds 4 points and a Medium floor. Site builders and app hosting (Wix, Vercel, Netlify, Cloudflare Pages, Firebase) stay out of it; there only a site named after a registered organization counts.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the message in English and Chinese; asset versions bumped.
- `website/tools/evidence_attribution.py` — the rule is a recognized signal.
- `website/tests/test_link_brand_free_host.py` — the services flagged, site builders and app hosting not flagged alone, one finding per message, and a brand on a development address.
- `website/tests/test_file_share_elsewhere.py` — the fake WeTransfer notice whose button leads to a `workers.dev` address is now Critical (High before), with the new finding.
- `docs/detection-design.md`, `docs/evaluation.md` — the rule and the measurement.

### Effect
- No count changed on `.eml` cohorts; 83 Nazario 2023–24 messages carry the finding, and 21 of their alerts are now corroborated by it rather than led by the model.
- Nazario 2023–24 pasted as text: 752 → 753 alerts of 787. No legitimate cohort changed.
- Recent consumer and small-business mail was not measured.

## [2026-10-08 09:12 PT] — Links to a site named after an organization on a free hosting service

### Why
- Asked whether Cloudflare's Clef models help with phishing domains: Clef classifies a domain by fetching and rendering the site, which PhishGuard never does, so the useful change was in the link rules. `link.brand_lookalike` covers only five brands, and extending it to every registered organization would have flagged 9 of the owner's 92 genuine messages (the organizations' own other domains) for few new catches. The real lookalikes sat on free hosting services.

### Files changed
- `website/email_structure.py` — `BRAND_SITE_LABELS`: the domain labels of organizations matched by display name, without common words, the five protected brands or shared-service subdomains.
- `website/app.py` — `link.brand_on_free_host`: a link to a site on one of 35 free hosting or site-builder services (Cloudflare Pages, Workers and R2, Vercel, Netlify, Glitch, Firebase, Wix and others) whose name is built on such a label; 4 points, no floor, once per message. Code and blog hosts (`github.io`, `blogspot.com`) and names with "clone" are left out. The finding counts as impersonation evidence.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the message in English and Chinese; asset versions bumped (`index.html`, `cases.html`, `404.html`, `lang-init.js`, manifest).
- `website/tools/evidence_attribution.py` — the rule is a recognized signal.
- `website/tests/test_link_brand_free_host.py` — new: lookalike sites from real phishing, digit-for-letter and pinyin names, the weight, and the sites not flagged.
- `docs/detection-design.md`, `docs/evaluation.md` — the rule, the rejected extension and the data.

### Effect
- No alert, undetermined or not-alerted count changed on the owner's genuine mail, the new brand emails, Nazario 2023–24 or PhishFuzzer's recent seeds. Three Nazario 2023–24 phishing messages (Wells Fargo on cyclic.app, Docusign on glitch.me) now carry the finding; all were already alerts.
- Not added: a link to any free hosting service as a signal. 99 of 787 Nazario 2023–24 messages had one and none of 36,337 legitimate messages in the local corpora did, but those corpora are mostly from 2008 or earlier, and small businesses and developers use these services.

## [2026-10-08 08:52 PT] — Thirteen more Chinese services added to the official registry

### Why
- The owner asked to continue with the remaining Chinese services on the list of common sites.

### Files changed
- `website/data/official_brands_cn.json` — 快手, 小红书, 菜鸟, 百度, 货拉拉, 德邦快递, 芒果TV, 酷狗音乐, 蜜雪冰城, 叮咚买菜 and 瑞幸咖啡 by name, and 微博 and 知乎 as `sender_only` services, with their published hotlines. Each domain is named by a service, complaint or report mailbox on the organization's own page, read in a browser on 2026-10-07.
- `website/tests/test_registry_additions_2026_10_07.py` — the second Chinese batch: names from other domains, their own domains, the words and services left out (装修快手, 菜鸟教程, 德邦证券, 某某官方微博), verified own mail and the hotlines.
- `docs/evaluation.md` — the services, what was left out and why, and the measurement.

### Effect
- No count or signal changed on the usual cohorts, and none of the owner's mail comes from or names these services; the tests show the new findings.
- Not added: 哈啰 and 得物 (their pages could not be read from here), 喜马拉雅, 豆瓣 and 高德 (phone numbers or forms only), 大众点评, 优酷, 盒马 and 网易云音乐 (mailboxes on another or a shared domain), 钉钉, 飞书, 闲鱼 and BOSS直聘 (they relay other users' messages), 网易163邮箱 and 189.cn (public mailbox services), and 肯德基中国, 饿了么, 华为 and 苏宁易购 (no official mailbox found or read).

## [2026-10-07 11:33 PT] — Ten Chinese services added to the official registry

### Why
- The owner asked to continue with the Chinese services on the list of 460 common sites, about 40 of which the registry lacked.

### Files changed
- `website/data/official_brands_cn.json` — 携程, 去哪儿网, 同程旅行, 美团, 抖音, 哔哩哔哩, 爱奇艺 and 小米账号 by name, and 滴滴出行 and 唯品会 as `sender_only` services, with seven official hotlines. Each domain is named by a service, complaint or report mailbox on the organization's own page, read in a browser.
- `website/tests/test_registry_additions_2026_10_07.py` — new: the Chinese names from other domains, their own domains, the words left out (周末去哪儿, 小米, 滴滴出行), verified own mail, the official channels and the hotlines.
- `docs/evaluation.md` — the services, the gaps and the measurement.

### Effect
- No count or signal changed on the usual cohorts, and none of the owner's mail comes from or names these services; the cohorts are English, so the tests show the new findings.
- A message asking the reader to call one of the seven hotlines (95010, 95117, 95711 and four 400 numbers) is no longer taken for a callback lure.
- Not added: 饿了么 (no official mailbox found) and 华为 (no page names its account mail domain); the list's other Chinese services are not checked yet.

## [2026-10-06 21:32 PT] — Thirteen more organizations added to the official registry

### Why
- A second batch from the owner's list of 460 common sites, in the same four groups (banks and insurers, delivery and shopping, travel, subscriptions and software).

### Files changed
- `website/data/official_brands_intl.json` — Fidelity Investments, Discover, 1Password, Bitwarden, Hilton Honors and Emirates by name, and State Farm, Chime, Uber, Lyft, Qatar Airways, British Airways and Target as `sender_only` services. Each domain is named as a sending domain or a report address on the organization's own page, read in a browser on 2026-10-06. 1Password's community and custom invitation mail and Bitwarden's no-reply address are relays.
- `website/tests/test_registry_additions_2026_10_06.py` — the second batch: names from other domains, their own domains, the names left out (Fidelity Bank, Discover Weekly, Paris Hilton, Emirates NBD), verified own mail, the relays, and shared or unlisted domains kept unofficial.
- `docs/evaluation.md` — the batch, what was left out and why, and the measurement.

### Effect
- No alert, undetermined or not-alerted count changed in the owner's 79 genuine `.eml` messages, the new brand emails, Nazario 2023–24 or PhishFuzzer's recent seeds. One Nazario message showing "Fidelity Investments" from another domain now carries an impersonation finding (fusion model-led to corroborated). None of the owner's 87 exported Gmail messages comes from or names these organizations.
- Left out: Wise (a report form only), Temu (merchant messages go through it), and DoorDash, HBO Max, Disney+, Hulu, SHEIN, Samsung, United Airlines, Southwest, Ryanair, Home Depot, Costco, Instacart, Starbucks and Nike (no page names their sending domains or a report address).

## [2026-10-06 14:35 PT] — Fifteen organizations added to the official registry

### Why
- The owner supplied a list of 460 common sites with their official website domains. A website domain is not a sending domain (`docs/official-registry.md`), so the list was not imported; it supplied candidates in the four groups the owner chose: banks and insurers, delivery and shopping, travel, and subscriptions and games.

### Files changed
- `website/data/official_brands_intl.json` — RBC, TD (as TD Canada Trust), Scotiabank, CIBC, BMO, DPD UK, Evri, Air Canada, Delta, Blizzard and Roblox by name, and American Airlines, OpenAI, Nintendo and Riot Games as `sender_only` services. Each domain is named as a sending domain or a report address on the organization's own page, read in a browser on 2026-10-06. OpenAI's invite address is a relay.
- `website/tests/test_registry_additions_2026_10_06.py` — new: the names from other domains, their own domains, the names left out (RBC Bearings, BMO Stadium, TD Bank, the American Airlines credit union), verified own mail, OpenAI's invites as relays, shared senders kept unofficial, and the official channels.
- `docs/official-registry.md` — narrower names or a `sender_only` entry when other organizations' mail carries a name, and a website list as a source of candidates only.
- `docs/evaluation.md` — the additions, what was left out and why, and the measurement.

### Effect
- No alert, undetermined or signal count changed in the owner's 79 genuine `.eml` messages (with and without a mailbox), the new brand emails, Nazario 2023–24 or PhishFuzzer's recent seeds. None of them, and none of the owner's 87 exported Gmail messages, comes from or names these organizations.
- Mail that shows these names from other domains now carries an impersonation finding, and their own authenticated mail is a verified official sender.
- Left out: U.S. Bank (its pages now give only a phone number), Walmart, Best Buy and eBay (they relay seller or member messages), Marriott and PlayStation (no page names their sending domains).

## [2026-10-06 14:01 PT] — The owner's review of the first teacher queue

### Why
- The first labelling run queued one message for the owner: a community digest Gmail had filed in Spam, which the teacher read as legitimate (95).

### Files changed
- `docs/llm-teacher.md`, `docs/evaluation.md` — the owner's label.

### Effect
- The owner labelled it legitimate, as the teacher had. All 18 new messages of the Gmail export are training rows, all legitimate; the training loader reads all 18. They stay outside the repository.
- Provider spam still goes to a person: one message does not show that Gmail's Spam label can be skipped.

## [2026-10-06 11:00 PT] — A local language model as a labelling teacher

### Why
- The text model's genuine training mail is mostly from 2002–2008, and the owner's recent mail is the missing ingredient. Labelling thousands of messages by hand is the obstacle, so a local model could propose labels for a person to check before a candidate model is trained on them.

### Files changed
- `website/tools/evaluate_llm_labeler.py` — new: asks a local model (loopback only) about each labelled message of consented cohorts and reports, counts only, its readings by confidence band and the precision, recall and coverage of labels accepted at floors 50, 80 and 90.
- `website/tools/label_with_llm.py` — new: labels an mbox or a directory of `.eml` files into a directory outside the repository. Legitimate readings at or above the floor become training rows in the CEAS_08/Nazario column layout. Every phishing reading, reading below the floor, unanswered message, Takeout message labelled Spam and message a `--review` manifest lists goes to a review queue. `merge` rebuilds the training file with the person's labels, `label` refuses a queue a person has started, and `--exclude` keeps evaluation messages out.
- `website/tests/test_evaluate_llm_labeler.py`, `website/tests/test_label_with_llm.py` — both tools against a stub model: counts and floors, no message text in the report, loopback only, the queue, the merge, spam and listed messages, evaluation messages and the output location.
- `website/tests/test_artifact_provenance.py` — new: fails if the committed text model names a training source outside the public corpora, since a TF-IDF vocabulary keeps words from its training mail.
- `website/tests/test_evaluate_local_review.py` — closes the stub server's socket.
- `docs/llm-teacher.md` — new: the rules (a person decides every phishing label; the teacher never labels evaluation messages; private mail and models trained on it stay out of Git; replace the served model only on a measured gain; the licence), the steps, the owner's mailbox and the measurement.
- `docs/evaluation.md` — the measurement. `README.md` — links the new page.

### Effect
- `qwen3.8:27b-mxfp8` on 1,095 labelled messages: 10 of the owner's 92 genuine messages read as phishing, all at 90 or more, so phishing labels must come from a person. Legitimate readings at 90 or more missed 9 of 890 phishing messages (1.0%). 97% of readings are at 90 or more, so the floor is no safeguard. 5.1 s a message on an M2 Max.
- The owner's Gmail export of 87 messages: 69 are evaluation messages and were skipped. 17 messages are labelled legitimate and 1, which Gmail had filed in Spam and the teacher read as legitimate, waits for the owner. The outputs are outside the repository.
- No change to the served page or model.

## [2026-10-05 23:46 PT] — Compare four Qwen models as local reviewers

### Why
- The rollout plan asks whether a smaller model, which a modest host could serve, reviews model-driven alerts as well as the 27B one measured on 2026-10-04.

### Files changed
- `website/tools/evaluate_local_review.py` — a pasted cohort reads source files up to the browser's 3 MiB limit, not the 60,000-byte `.eml` limit, since pasting has no upload limit of its own.
- `website/tests/test_evaluate_local_review.py` — that limit, both ways.
- `docs/evaluation.md`, `docs/llm-review-rollout.md` — the comparison and what it means for serving the review.

### Effect
- Shadow mode, same cohorts, alerts that each model would lower (owner's 35 pasted false alerts / pasted Nazario phishing alerts of 752 / mean seconds): `qwen3.5:4b-mlx` 16 / 87 / 0.8; `qwen3.5:9b` 11 / 17 / 1.7; `qwen3.8:27b-mlx` 25 / 14 / 3.6; `qwen3.8:27b-mxfp8` 32 / 9 / 4.2. No model lowered a Nazario `.eml` alert. `qwq:32b` timed out on 3 of 4 reviews.
- The small models do not hold up; the 8-bit 27B build is the candidate reviewer, at 32 GB and up to 27.5 s per review.
- No verdict changes: the review stays off by default.

## [2026-10-05 21:04 PT] — Shadow mode and a comparison tool for the local language-model review

### Why
- After the 2026-10-05 compromise, pasted text keeps its model-only alerts, which the local Qwen review lowered from 35 to 9 on the owner's genuine mail. The owner asked to prepare the review for the served page without changing the privacy promise yet: measure first, in shadow mode, and compare smaller models that a modest host could serve.

### Files changed
- `website/local_review.py`, `website/app.py` — `LOCAL_LLM_REVIEW_SHADOW=true` runs the review as usual, but a legitimate reading only records that it would lower the alert (`content.local_review_shadow`); the verdict is unchanged. Still development-only and loopback-only.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — the shadow message in English and Chinese; asset versions bumped.
- `website/tools/evaluate_local_review.py` (new) — runs the serving pipeline over consented cohorts once per Ollama model, in shadow mode, with `--paste` for the pasted path, and writes counts only (alerts, would lower, kept, unavailable, skipped, response times), with model and prompt digests.
- `website/tests/test_local_review.py`, `website/tests/test_evaluate_local_review.py` (new) — the setting, shadow readings, per-cohort counts with a stub server, and loopback-only URLs.
- `docs/llm-review-rollout.md` (new) — the gates before the review runs for visitors (independent holdout, a servable model, privacy, prompt injection), the steps, rollback and the comparison procedure; `docs/optional-features.md`, `docs/deployment.md`, `README.md` link it.

### Effect
- No verdict changes: the review stays off by default, and shadow mode never changes a result.

## [2026-10-05 17:52 PT] — Keep model-only alerts on pasted text; a note only in original messages

### Why
- Making every model-only score a note (entry "Show a text-model signal alone as a note, not an alert", above) cost 25 to 56 points of phishing recall on pasted public corpora, far more than the 2026-09-29 `.eml` figure. The owner chose a compromise: a note only where the message's headers were read.

### Files changed
- `website/app.py` — `fuse_content_risk(raw_message=)`: a model-only score is a Low note in an original message and a Medium alert ("Model Signal Needs Review") otherwise; `_analyze_content` decides from the parsed message (after `raw_email` is parsed), and `_analyze_visual` passes it to the text read from an uploaded `.eml`'s images.
- `website/static/i18n.js`, `website/static/i18n-zh.js`, `website/static/app-content-render.js` — both labels again; the model-only line explains an alert or a note by the result's level; asset versions bumped.
- `website/static/app.test.mjs`, `website/tests/fixtures/i18n/scenarios.mjs`, `website/tests/fixtures/i18n/en-snapshot.json` — the original model-only tests and snapshot are back, with an added `.eml` note scenario (20 snapshot lines added, none changed).
- `website/tests/test_local_review.py`, `test_requested_notice.py`, `test_presentation_cues.py` — the original files, plus tests that an original message's note is neither asked about nor reviewed; `test_detection_behavior.py`, `test_risk_precision.py`, `test_html_input_coverage.py` — pasted expectations restored, the note tested for raw messages.
- `README.md`, `docs/detection-design.md`, `docs/evaluation.md` — the rule by input path and its measurement.

### Effect
- Pasted public corpora (9,263 messages): every alert, undetermined and other count equals the original code's.
- Raw messages rebuilt from the CSVs: Nazario alerts 1,544 → 1,529 of 1,563; CEAS-08 legitimate false alerts 85 → 83 of 1,497. The owner's genuine `.eml` cohort is not measured.

## [2026-10-05 17:35 PT] — Short README; details moved to docs/

### Why
- The README had grown to 2,068 lines that mixed a user guide, the API, design reasoning and evaluation logs; its project tree still used the old `CS-166-Final-Project/` name and listed 8 of 30 modules, and five sections sat after the footer.

### Files changed
- `README.md` — rewritten (167 lines): what PhishGuard checks, how a verdict is made (diagram), measured results by input path with their caveats, limitations, quick start, testing, the full project tree and a documentation index.
- `docs/detection-design.md`, `docs/api.md`, `docs/deployment.md`, `docs/data-and-model.md`, `docs/testing.md`, `docs/optional-features.md` (new) — the former README sections, moved verbatim: headings shift one level where a section became a page, relative links were rewritten to resolve from `docs/`, and the three sections that sat at the wrong level after the footer were fixed.
- `docs/evaluation.md`, `website/tools/evaluate_source_holdout.py` — references to README sections now name the new pages.
- `progress_report.md`, `phishing-detection/README.md` — a note that they are the historical report and the archived course benchmark.

### Effect
- Documentation only. Every non-blank line of the old README is in the new pages except the old introduction and project tree, which the new README replaces; every relative link and anchor in README and `docs/` resolves. The quick-start commands were run: the rules-only and model-enabled servers both answered `/health`.

## [2026-10-05 17:21 PT] — Move the HTML/CSS visibility reader out of app.py

### Why
- `website/app.py` held 7,866 lines, about 40% of them a hand-written CSS cascade, colour and visibility reader that eleven reviews in three days kept patching. Separating it lets that code be read, reviewed and tested on its own, and leaves `app.py` with the API, rules and fusion.

### Files changed
- `website/html_visibility.py` (new) — 3,178 lines moved verbatim from `app.py`, in their original order: the HTML parser base and Outlook conditional comments, the CSS cascade, colour, gradient and math readers, `_visible_content_text`, and three pure helpers it needs (`_strip_invisible_format_controls`, `_parse_link_target`, `_unescape_css`).
- `website/app.py` — imports what it uses from the new module, and re-exports, marked as such, the internals tests reach through `app.`; unused imports removed. 7,866 → 4,691 lines.
- `website/tests/test_review_2026_10_02_third.py` — patches `_MAX_VIEW_ANCHORS` where it now lives; a patch on `app` would no longer reach it.
- `README.md` — the module in the project tree.

### Effect
- No behavior change: every line removed from `app.py` is in the new module unchanged, all 1,163 Python and 515 frontend tests pass, and the full analysis JSON of 9,263 local corpus messages and 371 HTML inputs taken from the test suite is byte-identical before and after (with `PYTHONHASHSEED` fixed: `content.obfuscation` joins a set of brand names, so its order already varied between processes).

## [2026-10-05 17:15 PT] — Say plainly that the text model does not read Chinese mail

### Why
- The page is bilingual and the registry lists 39 Chinese organizations, but the text model was trained without Chinese mail: on 611 unlabelled DataCon 2023 Chinese messages, 349 (57%) end undetermined. The old warning ("language-specific phishing checks are limited") did not tell a reader why, or which checks still apply.

### Files changed
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — `warning.han_text` now says the text model was not trained on Chinese mail, so only the rule checks are reliable, in English and Chinese; asset versions bumped.
- `README.md` — which checks still read Chinese mail, and that its detection quality is unmeasured.

### Effect
- Wording only: verdicts, scores and the warning's code are unchanged.

## [2026-10-05 17:15 PT] — Review checklist and evidence gate for the official-brand registry

### Why
- A trusted DMARC pass on a registry domain makes a verified official sender, which the text model and weak rules cannot raise above Low, so each official domain is a trust anchor. The registry's own notes say some domains came "from prior knowledge" and still need confirmation (`jpmorganchase.com`, `square.com`, `squareup.com`), and entries are often added after a single incident.

### Files changed
- `docs/official-registry.md` (new) — what an entry does, the evidence a domain needs, relay and shared-domain checks, display names, measurement and a six-monthly recheck.
- `website/tests/test_registry_evidence.py` (new) — every official domain needs recorded evidence (`domain_sources`, a statement page on the domain, or an official contact address there); the 79 domains without any are listed and the list may only shrink; `domain_sources` must be HTTPS pages.
- `README.md` — links the checklist.

### Effect
- No verdict changes. Adding a domain without evidence now fails CI, and so does confirming a listed domain without taking it off the list.
- 79 official domains in 48 entries are pending confirmation (36 international, 43 Chinese).

## [2026-10-05 17:13 PT] — Read hidden text with the strongest request and lure rules

### Why
- Eleven reviews from 2026-10-01 to 10-03 each found a style the CSS reader misjudged (a gradient, `calc()`, `clamp()`, `atan2()`, `color-mix()`, a custom property's case, print-only CSS), so that a visible callback scam read as hidden text and came out Safe or Low. Matching every browser and mail client has no end; the rules should not depend on it.

### Files changed
- `website/app.py` — `_visible_content_text` adds an `all_text` reading (never a model rendering) where styles may hide text. `analyze_email_content` runs the request rules (credential, callback, subsidy, sensitive requests) and the lure rules on it, with each link's whole label (`_extract_links(hidden_labels=True)`); a finding only that reading makes is listed as "In text the message may hide: …" at Medium level. `_analyze_content` adds its Medium floor (3 points) after the model's renderings are chosen, so it never lets the model score hidden text. The lure checks share one helper, `lure_findings`.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — `prefix.hidden_text` in English and Chinese; asset versions bumped.
- `website/tests/test_hidden_text_rules.py` (new) — no tested style (the reviews' and the common hiding methods, in a stylesheet, inline and print-only) clears a callback request; marking, severity, no duplicates, keyword score and the model unchanged. `website/tests/hidden_findings.py` (new) — shown and hidden finding codes for tests.
- `website/tests/test_review_2026_10_01_fourth.py`, `test_review_2026_10_02.py`, `test_review_2026_10_02_second.py`, `test_review_2026_10_02_third.py`, `test_review_2026_10_02_fifth.py` — visibility controls compare the findings in what the message shows, and the hidden ones now also expect the marked finding.
- `website/tests/test_html_input_coverage.py` — hidden phishing padding is a Medium hidden-text finding; the model still abstains.
- `README.md`, `docs/evaluation.md` — the rule and its measurement.

### Effect
- A scam request or lure in text the reader may not see is now a Medium alert instead of Safe, Low or Unknown; what the message shows keeps its High findings.
- Local public corpora (9,263 pasted messages): no alert count changed, and no message had a hidden-text finding. These corpora are plain text; the effect on real HTML mail, including false alerts on genuine HTML newsletters, is unmeasured until the owner's `.eml` cohorts are run.

## [2026-10-05 16:59 PT] — Show a text-model signal alone as a note, not an alert

### Why
- After the 2026-10-05 project review, the owner chose to stop alerting on a text-model score that no rule, sender, link or structure evidence supports (`fusion_basis=model_only`) until a consented, independent holdout supports more. Uncorroborated model scores were about half of the false alerts on real account notices (2026-09-29).

### Files changed
- `website/app.py` — `fuse_content_risk`: `model_only` is **Low Risk — Text Model Signal Only** instead of a Medium alert; on its own the model counts at most 29% in `combined_phishing_score`, while `ml_phishing_probability` keeps its reading. `_fused_decision` keeps the rendering-view and earlier-abstention checks keyed on "alert or note", so hidden text still cannot add or remove a model signal. A verified official sender keeps its own Low label.
- `website/static/i18n.js`, `website/static/i18n-zh.js` — `content.riskLabel.lowModel` replaces `mediumModel`; the model-only line says it is a note, not an alert. Asset versions bumped (`website/tools/asset-versions/manifest.json` and the page references).
- `website/static/app.test.mjs`, `website/tests/fixtures/i18n/scenarios.mjs`, `website/tests/fixtures/i18n/en-snapshot.json` — the note in the page; the snapshot was regenerated with `capture.mjs` and only the model-only scenario changed.
- `website/tests/test_detection_behavior.py`, `test_presentation_cues.py`, `test_risk_precision.py`, `test_html_input_coverage.py`, `test_rendering_views.py`, `test_local_review.py`, `test_requested_notice.py` — expectations for the note; the local-review and "did you do this yourself?" tests now use model-led alerts, which still reach them.
- `README.md`, `docs/evaluation.md` — the rule and its measurement.

### Effect
- A model-only result no longer alerts, asks whether the reader did it, or goes to the local review. Model-led alerts (the model with keyword categories or presentation cues) are unchanged.
- Local public corpora, pasted subject and body, committed artifact (table in `docs/evaluation.md`): phishing alerts Nazario 1,506 → 1,112 of 1,561, PhishNChips 993 → 435 of 1,000, PhishFuzzer LLM variants 1,308 → 1,258 of 1,344; false alerts PhishFuzzer legitimate 194 → 122 of 1,392, CEAS-08 27 → 19 of 1,496, Phishing_Email 22 → 8 of 1,470, PhishNChips 31 → 19 of 1,000.
- Caution: pasted text loses far more phishing alerts than the 2026-09-29 `.eml` measurement (Nazario 2023–25, 91.8% → 89.0%), because nothing in it can corroborate the model. Most of these corpora are in the model's training pool. Measure the owner's genuine and Nazario `.eml` cohorts with `evaluate_serving_pipeline.py` before deploying.

## [2026-10-05 15:26 PT] — Add six organizations to the official registry

### Why
The owner asked how to get more official domains. The candidates came from the brands Nazario phishing most often displays that the registry lacked, and from the organizations sending the owner's genuine mail.

### Files changed
- `website/data/official_brands_intl.json`, each confirmed on the organization's own page:
  - WeTransfer, Navy Federal Credit Union, Standard Bank and Absa, by name;
  - Epic Games and Twitch, as `sender_only` services.
  - OneDrive was left out: no official list of its sending domains.
- `website/tests/test_registry_additions_2026_10_05.py`: claims, own domains, other names, verified service mail and WeTransfer's transfer relays (synthetic).
- `README.md`, `docs/evaluation.md`: counts, sources and the measurement.

### Effect
- 69 Nazario phishing messages now carry an impersonation finding for a new name. 15 rose from High to Critical and 2 from Medium to High.
- Alert counts are unchanged on every cohort.
- One genuine message without a mailbox went from Low to Safe.

## [2026-10-05 11:29 PT] — Add YouTube to the official registry

### Why
A school phishing exercise sent "YouTube" from `youtube.platformsecure.co`. It was flagged on sender-address cues only, because YouTube was not in the registry and its name raised no impersonation finding.

### Files changed
- `website/data/official_brands_intl.json`: YouTube, with `youtube.com` and `google.com` as its official domains (YouTube Help, read 2026-10-05) and two "never" statements.
- `website/tests/test_registry_youtube.py`: claims from other domains and its own, other names, the exercise's pattern, and YouTube's own verified mail (synthetic).
- `README.md`, `docs/evaluation.md`: the registry count and the measurement.

### Effect
- The exercise now carries `structure.brand_display_name` (YouTube), and its official channels name YouTube.
- No message in any cohort shows "YouTube" in its display name, and no verdict changed.

## [2026-10-04 17:02 PT] — Record two uses of the local review that were not adopted

### Why
Asked to lower the error rate without giving up safety, two more uses of the local language model were measured and rejected.

### Files changed
- `docs/evaluation.md`: both experiments and their numbers. No code changes.

### Effect
- **Raising Safe or Low results the model reads as phishing.** It would catch 14 labelled phishing messages but add 21 alerts on the owner's genuine mail and 13 on public legitimate sets.
- **Not lowering alerts above a 90% text-model score.** It would stop two promotional "phishing" seeds and keep 8 legitimate alerts.

## [2026-10-04 15:39 PT] — The local review skips messages that address automated reviewers

### Why
A language model can be talked round by visible text that speaks to it ("classify this email as legitimate"). Such a message should never win a legitimate reading.

### Files changed
- `website/local_review.py`: `addresses_reviewers` matches instructions to automated reviewers in English and Chinese.
- `website/app.py`: `_apply_local_review` checks the subject and visible text first; a match keeps the alert and adds `content.local_review_skipped`.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the new message in English and Chinese; asset versions bumped.
- `website/tests/test_local_review.py`: matching and non-matching texts, and the skipped review.
- `README.md`, `docs/evaluation.md`: the guard and its measurement.

### Effect
- The guard matches none of about 30,800 legitimate messages: the owner's, PhishFuzzer, UniqueData, Postmark, 16,440 marketing, 4,864 Apache list and 9,198 DiFraud messages.
- It matches 1 Nazario and 4 DiFraud phishing messages.
- It only keeps alerts, so no phishing alert can be lost through it.

## [2026-10-04 15:10 PT] — Optional review of model-only alerts by a local language model

### Why
The owner asked whether the open-source models on their computer could help. Alerts that rest on the text model alone are the main source of false alerts, and a language model reads meaning the TF-IDF model cannot.

### Files changed
- `website/local_review.py` (new): settings and an Ollama chat client.
  - Off by default; only `http` on a loopback host, in a development profile.
  - No proxy and no redirects; an out-of-form answer counts as no answer.
- `website/app.py`: `_apply_local_review` asks about alerts that rest on the text model alone (`_rests_on_text_model`), before the "Did you do this yourself?" question. A legitimate reading at the minimum confidence lowers the alert to Low.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: four result messages and the new Low label, in English and Chinese; asset versions bumped.
- `website/tests/test_local_review.py`: settings, the client against a stub server, and the analysis (synthetic).
- `README.md`, `docs/evaluation.md`: how to turn it on, the pilot and the end-to-end measurement.

### Effect
- Off by default: no verdict changes unless `LOCAL_LLM_REVIEW_ENABLED=true` in development.
- With Qwen3.8 27B through Ollama, review off → on:
  - genuine downloads: alerts 35 → 9 pasted and 24 → 11 without a mailbox; 3 with a mailbox, unchanged;
  - PhishFuzzer legitimate seeds 63 → 21, UniqueData 39 → 29, Postmark 3 → 0;
  - Nazario 3,445 → 3,444 (the corpus's own introduction), PhishFuzzer recent phishing 88 → 85, DataCon unchanged.

## [2026-10-04 12:10 PT] — Presentation cues give way to a legitimate model reading

### Why
The owner's 11 new brand emails were all Low as `.eml`. Pasted, one Quora digest still reached Medium on rule points while the model scored it 6%. Two of its six points came from exclamation marks and the number of links, cues that genuine notices share.

### Files changed
- `website/app.py`:
  - the rule findings and the message analysis count points from presentation cues (`_PRESENTATION_CUES`) apart;
  - `fuse_content_risk` leaves them out when the model reads the text as legitimate;
  - the content analysis keeps them whenever any view or rendering reaches the threshold.
- `website/tests/test_presentation_cues.py`: fusion and message tests (synthetic).
- `README.md`, `docs/evaluation.md`: the rule and the measurements.

### Effect
- Genuine downloads: alerts fall from 25 to 24 without a mailbox and from 37 to 35 pasted. The 11 new emails, pasted, fall from 4 to 3.
- No level changes on Nazario (3,466), DataCon (611), PhishFuzzer recent seeds (205), UniqueData (58) or Postmark (10).
- With the model off, or with no model reading, the rules score as before.

## [2026-10-03 04:30 PT] — Record candidate models scored in the serving pipeline

### Why
The owner asked for an offline evaluation of a candidate content model trained on public data, before any decision to replace the served one. It also checks section 5's C2 result (recent-seed LLM variants halving false positives on PhishFuzzer seeds) on legitimate mail from other sources.

### Files changed
- `docs/evaluation.md`: method, results and conclusion of the comparison. No code or model changes.

### Effect
Against a baseline trained the same way (M0r), neither candidate lowers false alerts on legitimate mail from other sources:
- M1r (+ DiFraud and legacy-seed LLM variants): genuine pasted false alerts 33 → 56, Postmark 2 → 9.
- M2r (+ recent-seed variants too):
  - within one alert on the genuine `.eml` and UniqueData cohorts;
  - six more genuine messages undetermined;
  - genuine pasted 33 → 36, Postmark 2 → 6.

The served model is unchanged.

## [2026-10-03 03:30 PT] — Fix the review of 362eb8f: a bad url() drops its background

### Why
The read-only review of main at 362eb8f (2026-10-02) found one P2. `url()` arguments were barely checked: only whitespace inside an unquoted address was. `url(a"b")`, `url(a(b))`, two strings or two strings with a comma between them were read as valid images, and `_background_uncertain` skipped every `url()`. Browsers read them as bad URLs and drop the declaration. So `background: black; background: url(a"b") text` keeps the black background under white text, but here it replaced it, and its `text` clip made the white page the backdrop. The callback alert was lost, and the verdict was Unknown (not Safe).

### Files changed
- `website/app.py`: `_CSS_URL` reads a `url()` as CSS tokenizes it: an unquoted address with no whitespace, quote, bracket, control character or lone backslash (escapes allowed), or one quoted string, either with optional whitespace around. Any other `url()` invalidates its background declaration.
- `website/tests/test_review_2026_10_02_seventh.py`: 3 tests (bad and valid URLs, and the background before a bad one staying).
- `README.md`, `docs/evaluation.md`.

### Effect
- **Review samples.** `url-bad-quote`, `url-nested`, `url-two-strings` and `url-comma` are High in HTML and EML, like `url-control`.
- **Real declarations.** Of 176 background declarations with `url()` in real HTML (Nazario 130, the genuine downloads 19, DataCon 27), none changes validity. Of the 5,977 values tested so far, none changes.
- **Same served model, main (ff94d10) against this change:** no per-message change on Nazario, the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public templates; pasted cohort counts identical.
- Tests: 1,118 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-03 02:30 PT] — A model score below its threshold no longer makes an alert

### Why
The fusion turned any model probability of 30% or more into a Medium "Suspicious Content" alert. That included probabilities below the model's own 0.3736 decision threshold, which was chosen within a 20% false-positive budget on validation data. Below it the model reads the text as legitimate. The owner chose to align the fusion with the threshold (the trade-off is in the 01:30 entry).

### Files changed
- `website/app.py`: in `fuse_content_risk`, a model probability below the threshold may raise the verdict to Low, never to an alert on its own. Rule evidence still counts on its own terms. The combined score still shows the probability.
- `website/tests/test_detection_behavior.py`: probabilities of 30%, 35% and 37.35% stay Low; with five rule points, Medium.
- `website/tests/test_risk_precision.py`: a probability 0.00002 below the threshold is now Low, not Medium. The unrounded comparison it checks is unchanged.
- `README.md`, `docs/evaluation.md`.

### Effect
Same served model, main (3701d1c) against this change:

| Cohort | Alerts before | After |
|---|---:|---:|
| 92 genuine downloads, no mailbox | 27 | 25 |
| 92 genuine downloads, mailbox chosen | 3 | 3 |
| 92 genuine downloads, pasted | 45 | 37 |
| PhishFuzzer legitimate seeds | 72 | 63 |
| UniqueData legitimate | 42 | 39 |
| Postmark templates | 4 | 3 |
| Nazario phishing | 3,445 | 3,445 (no per-message change) |
| PhishFuzzer phishing seeds | 90 | 88 |

- **DataCon 2023 day 1.** Two Medium messages become Low: a predatory journal's call for papers and an editing-service advertisement. One undetermined message becomes Low.
- **Public HTML templates.** Four undetermined templates become Low: their renderings now agree.
- Tests: 1,115 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-03 01:30 PT] — Read plain-text file-sharing lures, and where false alerts come from

### Why
- **A missed lure.** One Nazario message stayed Medium only through a low model score: "Signed revised agreements has been sent using Dropbox file viewer. Press Here sign in with your email to view the message. http://janiceli.ca/camp/dropbox".
  - The file-sharing rule did not know "has been sent using Dropbox".
  - Its link was a bare address in plain text, with no label to read the action from.
- **False alerts on legitimate mail** were profiled before changing anything. They are almost all model-driven: no rule floor, and often no Medium finding at all.
  - 92 genuine downloads, pasted: 45 alerts, 27 of them with no Medium finding.
  - PhishFuzzer legitimate seeds: 72 alerts, 59 with none.
  - UniqueData legitimate: 42 alerts, 37 with none.

  The six genuine downloads with a High floor without a mailbox come from address keywords: two from `accountprotection.microsoft.com`, four from `notice.aliexpress.com`. They stay alerts through the model even without the keywords, so relaxing those findings would gain nothing and cost Nazario alerts (2 to 8 in the variants tried). They are left as they are.

### Files changed
- `website/app.py`: file-sharing notices include "has been sent / shared / uploaded using / via / through / on" a named service. A bare address with no label takes the 120 characters before it in the text as its label, for this rule only.
- `website/tests/test_file_share_plain_links.py`: 3 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- **The lure.** Nazario 2016 #342 rises from Medium to High (`link.file_share_elsewhere`).
- **Legitimate text.** The new wording matches none of the PhishFuzzer legitimate texts, DIFraud genuine, marketing mail or UniqueData legitimate.
- **Same served model, main (362eb8f) against this change:**
  - Nazario 3,466: one Medium → High; nothing else changes (3,445 alerts, 16 undetermined, 5 Safe or Low);
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Tests: 1,114 passed, 10 skipped; all frontend test files 514 passed.

### Not changed (a decision for the owner)
The fusion turns any model probability of 30% or more into a Medium "Suspicious Content" alert. That includes probabilities below the model's own 37.4% decision threshold, whose selection already set the false-positive budget. Counting the model only at its threshold would change alerts as follows (this change included):

| Cohort | Now | Aligned |
|---|---:|---:|
| Genuine downloads, no mailbox / pasted | 27 / 45 | 25 / 37 |
| Genuine downloads, mailbox chosen | 3 | 3 |
| PhishFuzzer legitimate / UniqueData / Postmark | 72 / 42 / 4 | 63 / 39 / 3 |
| Nazario phishing | 3,445 | 3,445 (2 Safe or Low → undetermined) |
| PhishFuzzer phishing | 90 | 88 |

## [2026-10-03 00:30 PT] — Fix the recheck of 9162549: words that are no colours, uncertainty through the whole cascade

### Why
An offline recheck of main at 9162549 (2026-10-02) found one P1 left from the last fix. It turned a visible callback scam from High to Safe:
- **Gradients kept on an unknown stop.** `background: black; background: linear-gradient((min(atan2(0px, 3rem))/ 3grad), black, black) text` hid white text. Two more such values come from the stored verdicts: `(12.5 + 3ms + …)` and `12.5grad-calc(banana - 1x)`. Both Chromium builds drop all three, so the black background stays under the white text.
- **The cause.** `_color_class` called any word holding `calc(`, `min(` or the like *anywhere* an uncomputed colour, so these words became gradient stops of unknown colour. The gradient was then kept. It was not marked uncertain, and its `text` clip restored the white page as the backdrop.
- **The same gap elsewhere.** It held for any colour or image this reader cannot check:
  - a `color-mix()` background or stop;
  - a `-moz-linear-gradient()` or `image-set()` under a `text` clip.

### Files changed
- `website/app.py`:
  - **Colour words.** A colour this reader cannot compute must be one (`_UNRESOLVED_COLOR`):
    - `color-mix()`, `light-dark()` and substitutions;
    - a colour function with math inside;
    - relative colour syntax.

    Any other word that merely holds a math function is invalid.
  - **Uncertainty.** `_background_uncertain` also holds for an uncomputed colour (as a background or a stop) and for any image function whose arguments are not checked (prefixed gradients, `image-set()`, `cross-fade()`, `element()`). The cascade therefore leaves the backdrop unknown there.
- `website/tests/test_review_2026_10_02_sixth.py`: 5 tests; on 9162549 they give 11 failures. One replays stored values that a Chromium build drops behind a background in contrast with the text: every tenth value, plus the recheck's three; `PHISHGUARD_FULL_CASCADE=1` checks all 1,208. Each value is tried with and without a `text` clip, and the text must be read.
- `README.md`, `docs/evaluation.md`.

### Effect
- **Recheck samples.** `fixture-gap-0`, `-1` and `-2` are High in HTML and EML, like `fallback-control`.
- **Cascade replay** (offline): 1,208 dropped values × 3 cascades.
  - This change hides none.
  - On 9162549, exactly the recheck's three are hidden.
- **Offline verdicts.** Of 5,977 values tested so far, the recheck's three change from accepted to dropped, and both builds drop them. None changes the other way, and the fixture's checks still hold.
- **Same served model, main (9162549) against this change:**
  - Nazario 3,466: no per-message change (3,445 alerts, 16 undetermined, 5 Safe or Low);
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Tests: 1,111 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 23:30 PT] — Fix the review of 3351c72: unknown clips, percentage bases, bracketed none, backgrounds browsers may drop

### Why
The read-only review of main at 3351c72 (2026-10-02) found four P1 issues, all reproduced here. Each turned a visible callback scam from High to Safe:
- **S1.** `background-clip: env(no-such-env, text)` was an unknown clip, yet black text over a black gradient was read as hidden. Chromium falls back to `text`, so the gradient paints only inside the glyphs and the text shows on the white page.
- **S2.** A percentage folded into any unit: `calc((1s + 1%) * 1px / 1s)` became a length once the time cancelled, and the gradient was read as solid black. Chromium drops it.
- **R1.** `clamp((none), 10px, none)` was read like `clamp(none, 10px, none)`. Only a bare `none` is a missing bound; Chromium drops the bracketed form.
- **R2.** A shorthand this reader keeps but browsers may drop replaced the black background before it, and its `text` clip then left the white page as the backdrop. `background: black; background: linear-gradient(sqrt(4px), black, black) text` hid white text that Chromium shows on black.

The review's other probes were checked against its Chromium 154 results. `atan2(calc(1px * 1px), calc(1px * 1px))` is accepted (black on black). Three percentage cancellations are dropped (white on white). All four stay hidden, as Chromium shows them. A conic stop mixing an angle and a percentage, under a `text` clip, is accepted by Chromium 154 and dropped by 148: either may hold.

### Files changed
- `website/app.py`:
  - **Percentage basis (S2).** A math type now carries the basis its percentages resolved against. A sum folds a percentage only into a length or an angle, never into a time or another unit. Two bases in one value are invalid, and the result must be its basis (`calc((1px + 1%) / 1px * 1deg)` is invalid).
  - **none (R1).** `(none)` in brackets is invalid; only a bare `none` is a bound of `clamp()`.
  - **Backgrounds browsers may keep or drop (R2).** `_background_uncertain` names a value holding a substitution function, a math function this reader cannot type, or a conic stop mixing an angle and a percentage. Wherever the background, clip, size or repeat in effect is such a value, the backdrop is unknown: its own colours and the background it replaced are both possible.
  - **Unknown clips (S1).** A clip this reader cannot resolve leaves the backdrop unknown too.
- `website/tests/test_review_2026_10_02_fifth.py`: 7 tests; on 3351c72 they give 10 failures and 6 errors.
- `README.md`, `docs/evaluation.md`.

### Effect
- **Review samples.** `clip-env`, `time-percent-cancel`, `clamp-paren-stop`, `clamp-paren-angle`, `clip-invalid-math` and `clip-version-math` are High in HTML and EML. The four probes Chromium hides stay hidden. The earlier samples (`atan-*`, `clamp-*`, `math0`–`math4`, the link budget, recipient pre-fill) keep their results.
- **Offline checks** (no browser launched this round):
  - the 1,916 Chromium 154 and 148 verdicts in the fixture still hold: nothing either build accepts is dropped, and whatever a build drops but this reader keeps has unknown colours;
  - 5,977 values tested so far: one changes from accepted to dropped, and both builds drop it; none changes the other way.
- **Nesting.** 124 deeply nested inputs still return a result through both endpoints.
- **Same served model, main (3351c72) against this change:**
  - Nazario 3,466: no per-message change (3,445 alerts, 16 undetermined, 5 Safe or Low);
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Tests: 1,106 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 22:30 PT] — Fix the review of e02355e: atan2() percentages, clamp() bounds, deep math, checked against two Chromium builds

### Why
The read-only review of main at e02355e (2026-10-02) found two P1 and one P2 issue in the math typing added there, all reproduced here:
- **R1 (P1).** `atan2(1deg, 1%)` and `atan2(1deg, calc(1deg + 1%))` were typed as angles. Chromium 154 drops both, yet the gradient was read as solid black: a visible callback scam became Safe.
- **R2 (P1).** `clamp(none, 10px, none)` and `clamp(0px, 10px, none)` were rejected. Chromium 154 accepts them, so the valid black gradient was dropped and white text on it read as white on the white page, hence hidden: Safe.
- **S1 (P2).** `calc()` nested 250 deep raised `RecursionError`: both analysis endpoints returned 500 for a 1.8 kB message.
- **Also found**, comparing every value with Chrome 154 (the user's installed browser, headless, with a scratch profile) and Chromium 148:
  - Browsers accept a declaration holding `env()` when they parse it, as with `var()`. `background: black env(safe-area-inset-top) 0` was dropped, so white text on it read as hidden.
  - Units multiply and divide by their powers: `calc(1px * 1px / 1px)` is a length and `calc(10em / 1% * 1vw)` a length-percentage. Both were rejected.
  - Chrome 154 accepts an angle mixed with a percentage in a conic stop; 148 does not.

R2 shows that dropping a valid background hides text just as accepting an invalid one does. So neither may happen where this reader is unsure.

### Files changed
- `website/app.py`:
  - **Types by powers.** `_css_math_type` gives each value powers of length, angle, percentage and other units, which multiply and divide. Sums need equal powers or fold a percentage into the other side's base. A percentage anywhere is remembered: where the value takes none (a direction, a conic `from`), it is invalid.
  - **atan2() (R1).** An angle or length mixed with a percentage is invalid; two percentages resolve against the place's basis.
  - **clamp() (R2).** Either bound may be `none`; the value may not.
  - **Unknown, not invalid**, where this reader cannot be sure. The background is kept, but its colours count as unknown, so it hides nothing:
    - `sqrt()`, `pow()`, `exp()` and `log()` of a dimension (Chromium accepts `sqrt(1vw)` and rejects `sqrt(4px)`);
    - a percentage inside a trigonometric function;
    - functions this reader does not model (`progress()`, `sibling-index()`);
    - an angle mixed with a percentage in a conic stop.
  - **Substitution functions.** `var()`, `env()`, `attr()`, `if()` and `inherit()` make a background valid when parsed, with unknown colours (`_CSS_SUBSTITUTION`), in the shorthand and in the clip, size and repeat longhands. `_background_parts` also leaves the colours unknown wherever an untyped math function stands.
  - **Depth (S1).** Math nested past 32 levels is left unknown (`_CSS_MATH_DEPTH`); a `RecursionError` there is caught the same way.
- `website/tests/test_review_2026_10_02_fourth.py`: 13 tests. Three of them check every value of `website/tests/fixtures/css/background_browser_verdicts.json` (1,916 values with both builds' `CSS.supports`):
  - nothing either build accepts is dropped;
  - whatever a build drops but this reader keeps has unknown colours;
  - agreement stays above 80% (the fixture holds every generated disagreement).
- `website/tests/test_review_2026_10_02_third.py`: `calc(10% + 1deg)` in a conic stop leaves the colours unknown instead of being dropped.
- `README.md`, `docs/evaluation.md`.

### Effect
- **Review samples.** `atan-mixed`, `atan-mixed-nested`, `clamp-none` and `clamp-max-none` are High in HTML and EML, like their controls. The 250-deep sample returns a result: 200 from both endpoints, with no exception.
- **Browsers.** 5,545 values were compared: the 1,045 hand-written ones of the last rounds and this one, and 4,500 generated math expressions in eight positions. The result agrees with Chrome 154 on 94%. Neither build accepts a value this reader drops, and every value a build drops but this reader keeps leaves its colours unknown. On 553 public values the two `-moz-` and `-o-` gradients remain the only disagreements.
- **Nesting.** 124 deeply nested inputs return a result through both endpoints within 5 seconds each: `calc()` to 3,000 levels, `var()` fallback chains, `:not()`, `@media`, `color-mix()`, 10,000 nested `<div>` elements.
- **Same served model, main (e02355e) against this change:**
  - Nazario 3,466: no per-message change (3,445 alerts, 16 undetermined, 5 Safe or Low);
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Tests: 1,099 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 21:30 PT] — Fix the review of 9abbad5: CSS math types, gradient coverage, RDAP queue, link budget, subscription links

### Why
The read-only review of main at 9abbad5 (2026-10-02) found two P1 and two P2 issues, all reproduced here:
- **S1 (P1).** Any `calc()`, `min()`, `max()` or `clamp()` counted as a valid value anywhere in a gradient. `linear-gradient(calc(1px), black, black)` (a length as the direction), `black calc(1deg)` in a linear stop, `calc(banana)` and `conic-gradient(from calc(1px), …)` are rejected by Chromium, yet were read as solid black. A visible callback scam was then hidden: Safe, while the white control is High.
- **S2 (P2).** Cancelling an RDAP lookup released its admission slot at once, but its work item stayed in the pool's queue until a worker reached it. Twenty messages of five domains, with the workers blocked, left 92 queued items; only 8 fetches ran.
- **R1 (P1).** At exactly 200 links the per-view labels were dropped for the whole message (`len(anchors) < 200` was false although nothing overflowed). This brought back the old whole-label match: "Releasedecoy messages", and the mailbox lure fell from High to Low.
- **R2 (P2).** The recipient-prefilled rule skipped any link whose URL contained "preferences", "unsubscribe" and the like anywhere: `?email=…&preferences=0` turned Medium into Low.
- **Also found.** The same S1 class holds for gradients that do not cover the box. `linear-gradient(black, black) no-repeat 0 0 / 1px 1px`, a zero size, `repeat-x`, `space`, or the same through `background-size` and `background-repeat` paint a tile or nothing, yet were read as a solid black backdrop. Chromium screenshots show the text on white.

### Files changed
- `website/app.py`:
  - **Math types (S1).** `_css_math_type` parses math functions as CSS Values 4 types them:
    - sums need matching types (lengths with percentages, angles alone), with whitespace around `+` and `-`;
    - products need a number on one side, and a quotient of like types is a number (`10px / 2px`);
    - `min()`, `max()`, `clamp()`, `round()`, `mod()`, `rem()`, `abs()`, `sign()`, `hypot()`, trigonometric and exponential functions each take their own argument types and counts.

    `_css_quantity` returns the result type, and each place takes its own: a linear direction or conic `from` an angle; linear and radial stops a length or percentage; conic stops an angle or percentage (Chromium rejects them mixed); a circle's radius a length. A function this reader cannot type (`env()`, `var()` inside) is accepted but leaves the gradient's colours unknown. `_css_words` ends a word at a function's closing bracket, as CSS tokenizes (`url(a.png)no-repeat`).
  - **Coverage.** A one-colour gradient is a solid backdrop only where its tiles cover the box: repeated on both axes at a size above zero (`_background_covers`). `background-size` and `background-repeat` are cascaded with the colours, validated layer by layer, and reset by the shorthand.
  - **Link budget (R1).** Per-view labels are kept up to 5,000 links (`_MAX_VIEW_ANCHORS`), more than a 60,000-byte upload can hold. If a message does go past it, the labels already read stay. The rest are matched by their plain label, and the rendering counts as unresolved, so the result is never Safe or Low on that alone.
  - **Subscription links (R2).** `_subscription_link` exempts a link by its label, its path, or Mailchimp's `list-manage.com`. A word in the query, fragment or host no longer counts.
- `website/domain_age.py` (S2): each admitted lookup keeps its slot until its work item leaves the queue and ends (`_admitted`). A lookup no message waits for is skipped without a request when the pool reaches it, or taken up again if another message asks for the domain first. Futures are no longer cancelled.
- `website/tests/test_review_2026_10_02_third.py`: 15 tests. `test_review_2026_10_02_second.py`: the RDAP test checks the admitted count.
- `README.md`, `docs/evaluation.md`.

### Effect
- **Review samples.** `math1`–`math4`, `anchors199` and `anchors200` are High in HTML and EML. `prefill_exempt` is Medium as an EML, like `prefill_normal`; pasted HTML has no recipients to compare. The RDAP probe ends with 8 queued items instead of 92, 16 admitted, and 8 fetches.
- **Chromium `CSS.supports`.** All 709 crafted values agree: the 305 earlier ones, 378 math values in seven positions, and 26 `background-size` and `background-repeat` values. 551 of 553 public values agree, as before.
- **Coverage, by screenshot.** The four partial gradients show their text on white, and a 10-px repeated tile hides it, as read.
- **Same served model, main (9abbad5) against this change:**
  - Nazario 3,466: no per-message change (3,445 alerts, 16 undetermined, 5 Safe or Low);
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- A 50,000-character body of 2,000 links takes 0.4 s with either budget.
- Tests: 1,085 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 20:30 PT] — Flag hidden-text salting, mailbox lures in attachments, and attachment names ending in a dot

### Why
Six of the 27 Nazario messages still undetermined, Safe or Low had a concrete lure the rules missed:
- **Hidden-text salting.** Two "Sorry we missed you! Schedule your next delivery date" and "Your package could not be delivered" lures put white 8-px Wikipedia paragraphs on the white page. The views already left the padding out, but nothing named it, and the short visible text scored low.
- **Attachment names.** A voicemail lure attached `vm_20220526_6316080857.htm.`, a page that redirects to a phishing site. Windows drops the trailing dot and opens it as a web page, but `PurePath` read no extension, so it was not a dangerous attachment.
- **Mailbox lures in attachments.** "Your email account mailbox requires immediate update … reactivation of your web-mail account" sat in a Word file under an empty body. Mailbox rules read only the body and its button labels.
- **File-sharing wording.** "Remittance Document Shared With You … a file located in Google Drive was shared with you", with an Open button on keap.app, did not match the notice wording.
- **Account hold.** An AMEX lure said "to regain full access to your account … log in", with no restricted or suspended.

### Files changed
- `website/app.py`:
  - `content.hidden_padding` (Medium; score 3; Medium floor) names 200 letters or more in their background's colour. The view pass now reports the count (`same_colour_letters`). 15 of 3,466 Nazario messages have that much; none of the 92 genuine downloads, DataCon 2023 day 1 or the 87 public templates hides any.
  - `content.attachment_mailbox_lure` (High; the credential tactic): a mailbox lure in Word or PDF attachment text, with an attachment link off the sender's domain to an unlisted host. With no button labels to read, only the mailbox itself counts (`_ATTACHMENT_MAILBOX_LURE`: mailbox, email account, inbox, webmail); "this email" beside "pending" does not.
  - Mailbox states add "requires (immediate) update, upgrade, verification or validation" and "reactivation".
  - File-sharing notices add "Document Shared With You" and "a file … was shared with you".
  - The account-hold states add "regain full access" and "restore full access". Genuine resets say "regain access to your account", so that alone does not count: it added a password-reset email among the PhishFuzzer legitimate texts.
- `website/email_structure.py`: an attachment's extension is read after dropping trailing dots and spaces.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the two findings. Asset versions bumped.
- `website/tests/test_salting_and_attachment_lures.py`: 8 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (48aa40d) against this change:
  - Nazario 3,466: alerts 3,439 → 3,445; undetermined 20 → 16; Safe or Low 7 → 5. The six → High; 8 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Findings on Nazario: `content.hidden_padding` 15, `content.attachment_mailbox_lure` 2; `content.mailbox_lure` 761 → 778, `content.account_hold_lure` 436 → 441, `link.file_share_elsewhere` 106 → 108, `structure.dangerous_attachment` 190 → 191.
- Wording hits on legitimate text are unchanged: the new mailbox states, file-sharing notices and account-hold states add none on the genuine downloads, PhishFuzzer and UniqueData legitimate sets, DIFraud genuine, Apache lists or marketing mail. The attachment mailbox wording, read in message bodies, appears in 13 of 6,702 PhishFuzzer legitimate texts and 5 of 9,198 DIFraud genuine ones (quarantine digests, mail-server discussions). In attachments it also needs an unlisted link.
- Tests: 1,070 passed, 10 skipped; all frontend test files 514 passed.

### Not changed
- A 300-character window for the callback rule would catch a Microsoft Defender invoice scam whose "didn't make this purchase" is 270 characters from the number. It also matched three DIFraud genuine texts (an order-cancellation policy, a legal disclaimer), so the window stays at 200.
- Digits for letters in display names ("D1sc0ver C4rd.") would add one registry claim in Nazario, on a message already High, so they are not read.

## [2026-10-02 19:30 PT] — Fix the review of ca047e5: gradient grammar, link labels per view, RDAP admission, Received trust

### Why
The read-only review of main at ca047e5 (2026-10-02) found two P1 and two P2 issues, all reproduced here:
- **S1 (P1).** Gradients browsers reject were still read as solid backgrounds, so a visible callback scam was treated as hidden: Safe, where a white background gives High. The probes:
  - `linear-gradient(to circle, black, black)` and `to left right`;
  - a linear stop at an angle (`black 1deg`) and a conic stop at a length (`black 10px`);
  - a trailing or doubled colour hint (`linear-gradient(black, 10px)`, `black 1px, 2px, 3px, black`);
  - a negative background size (`black -1px / -2px`).
- **S2 (P2).** RDAP lookups had no admission bound. The pool's queue was unbounded, the deadline cancelled nothing, and a domain already in flight was submitted again. Four messages of five blocked lookups left 8 running and 12 queued, and all 20 ran after the deadline.
- **S3 (P2).** `_sending_server` crossed the receiving boundary on the peer's own name. `from mail.google.com (attacker.example. [185.220.101.1]) by mx.google.com` let a forged line below report 8.8.8.8 as the verified sending server.
- **R1 (P1).** A link's label in each view was matched from the anchor's whole text. With `.decoy{display:none}`, `Release<span class="decoy">decoy</span> messages` read "Releasedecoy messages" in every view, so the mailbox lure was missed: Safe, where the control and an inline-hidden decoy are High.
- **Exploration.** The fine rule's government exemption accepted any `go.` second level, so a toll lure linking to `local-test.go.to` (a name anyone may register) was Safe.
- **Also found.**
  - `background: black text` is valid, as the review notes, but `text` clips the background to the glyphs. The black text then shows on the white canvas; it was read as hidden (Safe).
  - Gradient text (`background-clip: text` with transparent text) was likewise read as hidden.
  - Chromium rejects unitless numbers in the background shorthand, even in quirks mode, and stops written position first (`10px black`). Both were accepted.

### Files changed
- `website/app.py`:
  - **Gradient grammar (S1).** `_gradient_stops` checks each gradient type's first argument (`_gradient_setup_valid`) and its stops, following CSS Images 4:
    - first argument: a linear angle, or `to` with sides on two axes; a radial shape, extent or sizes, with an `at` position; a conic `from` angle, with an `at` position; any of them with an `in <colour space> [<method> hue]` clause at either end;
    - stops: the colour first, then up to two lengths or percentages (angles or percentages for conic);
    - colour hints: only between two colour stops.
    
    `_css_quantity` classifies values as lengths, angles or percentages. `_background_valid` rejects a negative size and a second `text` box. `_css_length` no longer accepts unitless numbers.
  - **background-clip.** `background-clip`, `-webkit-background-clip` and `text` in the shorthand are cascaded with the colours (`_background_clip`). A background clipped to the text is no backdrop, and transparent text over one that paints counts as visible. A clip anywhere in the message turns on the colour cascade.
  - **Link labels per view (R1).** The view pass records each actionable link's label in every rendering view (`anchors`, up to 200 links). `reading_links` gives each reading the labels its view shows; beyond 200 links it falls back to the old matching.
  - **Government hosts.** `_government_host` reads the Public Suffix List and accepts:
    - `.gov` and `.mil`;
    - a suffix with a government label (`gov.uk`, `go.jp`, `gc.ca`, `nsw.gov.au`);
    - `admin.ch` and `bund.de`.
- `website/domain_age.py` (S2):
  - at most 16 lookups are admitted at once (`MAX_PENDING_LOOKUPS`);
  - one future per domain is shared by every message that asks for it;
  - cached dates are answered without the pool;
  - a lookup no message waits for any more is cancelled before it starts.
- `website/email_structure.py` (S3):
  - a peer is the service's own server only when the receiving server recorded an address in the service's mail networks (`_MAILBOX_NETWORKS`: Google's mail netblocks; Exchange Online's ranges);
  - the receiving server's recorded address is read before an address in the peer's name.
- `website/tests/test_review_2026_10_02_second.py`: 16 tests; on e806393 they give 37 failures and 16 errors.
- `README.md`, `docs/evaluation.md`.

### Effect
- **Review samples.** All are High in HTML and EML:
  - `css_01`–`css_09` (`css_08`, `black text`, included);
  - `decoy_label`;
  - `fine_gov`;
  - seven `background-clip` probes that Chromium shows. Transparent clipped text with no background stays hidden, as Chromium shows it.
- **S2 probe.** Once every call has returned, 8 lookups are running and the queued ones are cancelled. Releasing the fetcher runs 8 fetches, not 20. Five concurrent messages asking for one domain make one fetch.
- **S3 probe.** The sending server is 185.220.101.1, as with the control.
- **Chromium `CSS.supports`.** All 305 crafted values agree (the earlier 76, plus 229 gradient, size and clip probes). 551 of 553 public values agree; the exceptions are the `-moz-` and `-o-` gradients, as before.
- **Same served model, main (e806393) against this change:**
  - Nazario 3,466: no per-message change (3,439 alerts, 20 undetermined, 7 Safe or Low);
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts;
  - the sending server is unchanged for all 92 genuine downloads, with and without a mailbox.
- **Timing.** The 92 genuine `.eml` files took 14.5 s against 12.8 s, and Nazario 145.8 s against 142.6 s. These runs went alongside other evaluations.
- **Tests.** 1,062 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 18:30 PT] — Read account-hold lures in the message body

### Why
- Three undetermined English Nazario messages put an account-hold lure in the body, each linking off the sender's domain:
  - Chase: "your online account has been temporarily suspended … login below to verify";
  - J.P. Morgan Chase: "we had to suspend your online banking … Verify now";
  - The New York Times: "your billing information … needs to be updated … Verify Payment Information".
- The wording was read only in attachments.

### Files changed
- `website/app.py`: `content.account_hold_lure` (Medium; score 3; Medium floor; the credential tactic) applies the attachment rule's wording (`_account_hold_lure`) to every rendering view of the body. It needs a link to a host that is neither the sender's nor listed (`_account_hold_link`).
  - Medium, not High: 2 of the 92 genuine downloads use the wording and are told apart only by their links, which go to the service's own or an official domain.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped.
- `website/tests/test_account_hold_body.py`: 2 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (eb82c61) against this change:
  - Nazario 3,466: alerts 3,436 → 3,439 (the three → High); 1 Medium → High; 82 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- The finding fires on 429 Nazario messages and on no genuine download, Apache list message or template.
- Tests: 1,046 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 17:30 PT] — Flag links that carry the recipient's own address

### Why
- 1,324 of 3,466 Nazario messages link to a site that is neither the sender's nor listed, with the recipient's address in the URL. Forms seen include `?email=jose@monkey.org`, `#jose@monkey.org` and base64.
- Phishing kits pre-fill their sign-in page this way, so it looks like the reader's own account.
- Eight such messages were still undetermined, most in English or Chinese: a FlowAccount document, an SF Express e-invoice and parcel notice, invoice and purchase-order lures, and a garbled mailbox notice.

### Files changed
- `website/app.py`: `link.recipient_prefilled` (Medium; score 3; Medium floor; the credential tactic) fires when:
  - a link leaves the sender's domain for an unlisted host;
  - its path, query or fragment carries a To or Cc address, as written, URL-encoded or in base64.
  
  Unsubscribe and preference links and `mailto:` links are left out. `analyze_email_content` now takes the recipients.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped.
- `website/tests/test_recipient_prefilled_link.py`: 3 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (ca047e5) against this change:
  - Nazario 3,466: alerts 3,428 → 3,436 (8 undetermined → 5 High, 3 Medium); 11 Medium → High; 62 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts, which have no recipients.
- The pattern fires on none of the 92 genuine downloads (real marketing and account mail to these addresses) or 5,055 Apache list messages.
- Tests: 1,044 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 16:30 PT] — Flag display names that show the recipient's own domain

### Why
- 485 of 3,466 Nazario messages put the recipient's own domain in the From display name ("monkey.org", "monkey.org Delivery System", "警报|讯息传递。monkey.org") while sending from an unrelated domain, posing as the recipient's mail or IT team. Four were still undetermined.
- No check compared the display name with the recipients.

### Files changed
- `website/email_structure.py`: `structure.recipient_domain_display` (Medium; score 3; Medium floor; the impersonation tactic) fires when a From display name shows the organizational domain of a To or Cc recipient and the From address is on another domain. Left out:
  - mail providers' domains (gmail.com, outlook.com);
  - display names with "via" (relays naming the person they carry);
  - mail from registered services' own domains.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped. `website/app.py`: the impersonation tactic lists it.
- `website/tests/test_recipient_domain_display.py`: 2 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (1c9fe4b) against this change:
  - Nazario 3,466: alerts 3,424 → 3,428 (4 undetermined → 3 Medium, 1 High); 2 Medium → High; 5 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- None of the 5,055 Apache list messages (sent to an organization's lists) or DataCon's 611 messages fires.
- The 92 genuine downloads were all received at consumer mailboxes, which the rule leaves out, so they test nothing here. Mail received at company domains is untested.
- Tests: 1,041 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 15:30 PT] — Add Alibaba.com to the official registry

### Why
- Two undetermined Nazario messages were fake Alibaba.com inquiries ("Alibaba Trade Center", "Alibaba trade Centre"). They mixed a real alibaba.com link with "Reply Now" and document buttons on attacker sites.
- Alibaba.com's own seller site lists fake inquiries among the three kinds of spam its users receive.

### Files changed
- `website/data/official_brands_intl.json`: Alibaba.com, 39 → 40 brands with display names.
  - **Domain:** `alibaba.com`.
  - **Display names:** "Alibaba.com", and "Alibaba Trade" for the trade-centre names fake inquiries use.
  - **Left out:** "Alibaba" alone, because Alibaba Cloud, AliExpress and 1688 send from other domains.
  - **Source:** the quote was read in a browser on seller.alibaba.com.
- The New York Times (one undetermined message) was not added: both its help centre and its search results were out of reach, so its domains could not be confirmed on its own pages.
- `website/tests/test_registry_additions.py`: 1 test.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (98917f2) against this change:
  - Nazario 3,466: alerts 3,422 → 3,424 (the two inquiries → 1 Critical, 1 High); 5 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Tests: 1,039 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 14:30 PT] — Flag unpaid fine and toll lures

### Why
- Three Nazario messages forged Spain's Ministerio del Interior: "Multa no pagada", "Tienes una multa pendiente", with a link to an Azure cloud app. Two were undetermined.
- Unpaid toll and traffic-fine lures (E-ZPass-style tolls, 12123 traffic violations, "ETC 已失效") are a common family today, and no rule read them.

### Files changed
- `website/app.py`: `content.fine_lure` (High; the payment tactic) fires when:
  - the text speaks of an unpaid fine or toll in English, Spanish, Portuguese, Italian, French, German or Chinese (`_FINE_LURE`);
  - the message links to a host that is neither the sender's, a listed official one, nor a government's (`_GOVERNMENT_HOST`: `.gov`, `gob.es`, `gouv.fr` and the like).
  
  Every link destination counts, labelled or not, as for the link checks. The rule runs in every rendering view.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped.
- `website/tests/test_fine_lure.py`: 3 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (12a5b65) against this change:
  - Nazario 3,466: alerts 3,420 → 3,422 (the two undetermined → High); 1 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- The wording appears in none of the genuine downloads, the 5,055 Apache list messages, 9,198 genuine DIFraud messages or 16,440 marketing emails. Only three Nazario messages carry it.
- Tests: 1,038 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 13:30 PT] — Add seven impersonated brands to the official registry

### Why
- 18 undetermined Nazario messages showed a brand the registry did not list, from an unrelated domain:
  - Tinder (7);
  - USAA (4 with readable text, and the PDF lures);
  - Fifth Third Bank (2);
  - PNC Alerts, Charles Schwab (written with zero-width characters), MetaMask, 三井住友銀行 (1 each).
- A simulated registry match moved all of them to High or Critical.

### Files changed
- `website/data/official_brands_intl.json`: seven entries, 32 → 39 brands with display names. Each domain was confirmed on the organization's own page, and each quote was read there in a browser on 2026-10-02:
  - **USAA:** `usaa.com`; how-to-tell-it's-USAA page; abuse@usaa.com.
  - **Fifth Third Bank:** `53.com`; phishing page, DMARC statement; phishing@53.com.
  - **PNC Bank:** `pnc.com`; "we will never ask you to click a link from a text"; abuse@pnc.com.
  - **Charles Schwab:** `schwab.com`; SchwabSafe.
  - **MetaMask:** `metamask.io`, `metamask.discoursemail.com`, and its card partner's `cl-cards.com`, all as its page lists them.
  - **Tinder:** `tinder.com`, `gotinder.com`. The privacy policy names dpobrazil@gotinder.com; it was read through a fetch tool because the browser declined the site, and no quote was taken.
  - **三井住友銀行:** `smbc.co.jp`; "メールや電話でログイン情報を求めることは絶対にありません".
- Shared names are left out: "Schwab" alone (Schwab Charitable) and "SMBC" alone (SMBC Nikko, SMBC Card).
- `website/tests/test_registry_additions.py`: 3 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (deaea6d) against this change:
  - Nazario 3,466: alerts 3,402 → 3,420 (18 undetermined → 14 High, 4 Critical); 4 Medium → High; 143 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Tests: 1,035 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 12:30 PT] — Read brand names in display names as they look

### Why
- Two undetermined Nazario messages named a registered brand with lookalike letters:
  - "Βank oϝ Αmerica", with a Greek capital beta and alpha and a digamma;
  - "PayPaI", with a capital I for l and an image-only body.
- The registry match read display names without the confusable table, and the table had only lowercase Greek and Cyrillic letters. Casefolding turns Β into β, which looks nothing like b.

### Files changed
- `website/email_structure.py`:
  - **Capitals.** `_CONFUSABLE_CAPITALS` maps Greek and Cyrillic capitals drawn like Latin ones (Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ Ϝ; А В Е К М Н О Р С Т У Х Ѕ І Ј Ԛ Ԝ) before casefolding. `_CONFUSABLE_TRANSLATION` gains ѕ, һ, ԁ, ԛ, ԝ and ϝ.
  - **Registry matching.** `_folded_display_name` applies both tables, so registry names match lookalike spellings.
  - **Capital I for l.** `_display_name_claims` and the protected-brand check also read a capital I after a lowercase letter as l (`_capital_i_as_l`). The name as written is always checked too, so "LinkedIn" keeps its I.
- `website/tests/test_display_name_lookalikes.py`: 4 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (13c6da8) against this change:
  - Nazario 3,466: alerts 3,400 → 3,402 (the two above → High); 20 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Tests: 1,032 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 11:30 PT] — Look up domain registration dates through RDAP

### Why
- Newly registered domains are a common phishing signal. The owner asked for registration dates via RDAP and chose:
  - to check the sender's domain and the link domains;
  - to evaluate on public data only;
  - to commit a snapshot of IANA's bootstrap.
- RDAP sends a registrable domain to that top-level domain's registry, a third party, so the lookups are off unless a deployment enables them, and the page says so.

### Files changed
- `website/domain_age.py` (new):
  - bootstrap loading and validation;
  - the RDAP server of a top-level domain (longest suffix);
  - bounded lookups: https only (also on redirect), 256 KB, a 2-second timeout and 3 seconds per message, up to five domains;
  - a cache (a day for answers, an hour for failures);
  - an asynchronous variant that holds no analysis worker while waiting.
- `website/tools/update_rdap_bootstrap.py` (new): downloads https://data.iana.org/rdap/dns.json and keeps the https servers. Excluded from the deployment.
- `website/data/rdap_bootstrap.json` (new): fetched 2026-10-02 17:30 UTC (IANA publication 2026-09-30), 54.6 KB, 590 services covering 1,201 top-level domains.
- `website/config.py`: `RDAP_LOOKUPS`, off by default. `vercel.json`: on for the Vercel profile.
- `website/app.py`:
  - `_registration_candidates` takes the From domain, then link domains, as registrable domains only. It skips official brands, mail providers, file-sharing services, shared-suffix hosts and IP addresses.
  - `_registration_findings` names domains registered less than 90 days ago (`sender.recently_registered`, `link.recently_registered`, info level, no points). The dates are in `domain_registrations`.
  - `rdap_lookups_enabled` is in `/api/config` and the health payload.
- `website/email_structure.py`: `registrable_domain` (private suffixes included).
- `website/static/index.html`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the privacy notice says which domains go to which service. `website/data/server_messages.json`: the two findings. Asset versions bumped.
- `website/tests/test_domain_age.py`: 10 tests with fake fetchers. `website/tests/test_app_security.py`: the public config lists the new flag.
- `README.md`, `docs/evaluation.md`.

### Effect
- **Public data only, real RDAP lookups, age at the time each message was sent:**
  - Nazario 2023–25 sender domains: 4 of 67 with a known date were under 90 days old (3 under 30);
  - Nazario link domains: none of 72;
  - Apache list mail: no domain under 90 days among 80 with known dates.
  - The rest had no RDAP service (52 Nazario, 36 Apache), were not found (96 Nazario, mostly deleted since; 3 Apache) or were re-registered after sending (13 Nazario, 1 Apache).
- **Weak on historical mail, so context only.** In live use the domains are still registered when the message is analysed.
- **No verdict change** on any cohort (lookups are off locally).
- Tests: 1,028 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 10:30 PT] — Show the sending server's address and check it against Tor exit and Spamhaus DROP lists

### Why
- Asked whether the sender's IP, and their use of a VPN, can be seen. The sender's own device is not recorded by Gmail or Outlook.com. The server that handed the message to the reader's mail service is recorded in that service's own `Received` lines, and it can be compared with public lists.
- The owner chose downloaded lists over online lookups, limited to Tor exits and blocklists, kept as a checked-in snapshot refreshed by hand. A VPN cannot be detected reliably, so it is not claimed.

### Files changed
- `website/ip_reputation.py` (new): schema, validation, and lookups for the snapshot (Tor exit addresses; Spamhaus DROP networks by bisection). It is never fetched at runtime.
- `website/tools/update_ip_reputation.py` (new): downloads the Tor Project bulk exit list (CC0) and Spamhaus DROP v4/v6 (free with credit; copyright and dates kept). It checks each list before writing atomically. Excluded from the deployment in `.vercelignore`.
- `website/data/ip_reputation.json` (new): fetched 2026-10-02 16:50 UTC, 117 KB. It holds 1,383 Tor exit addresses (IPv4) and 1,783 DROP networks (91 IPv6), DROP list of 2026-09-30.
- `website/email_structure.py`:
  - `_sending_server` reads `Received` lines from the top while the receiving service wrote them (Gmail's `mx.google.com` and `2002:…` hops, Outlook's Exchange Online servers) and takes the first public address from outside the service.
  - With a chosen mailbox the address is verified; otherwise the service is recognised from the topmost line and the address is unverified.
  - The address, and `X-Originating-IP` (sender-written), are compared with the lists. New fields and findings: `sending_server`, `structure.sending_server[_unverified]`, `structure.sending_server_tor`, `structure.sending_server_drop`, `structure.originating_ip_tor`, `structure.originating_ip_drop`. All are info level and add no points.
- `website/app.py`: returns `sending_server` in `message_structure`.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the six findings. Asset versions bumped.
- `website/tests/test_ip_reputation.py`: 10 tests (no network).
- `README.md`, `docs/evaluation.md`.

### Effect
- **Sending server found:**
  - Nazario: 3,455 of 3,466 (unverified, as Nazario's mailbox is neither Gmail nor Outlook);
  - the 92 genuine downloads: all 92, verified with their mailbox chosen;
  - DataCon 2023 day 1: 584 of 611.
- **List matches.** Today's lists match no message on Tor. On Spamhaus DROP they match:
  - 12 Nazario sending servers and 1 Nazario `X-Originating-IP`;
  - 3 DataCon messages;
  - none of the genuine downloads.
- **No verdict change**, per message, on any cohort: the findings are context only.
- Tests: 1,018 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 09:30 PT] — Fix the review of 06dfbb7: gradient stops, lure views, platform senders, PDF fonts

### Why
The read-only review of main at 06dfbb7 (2026-10-02) found three P1 and two P2 issues, all reproduced here:
- **S1 (P1).** `linear-gradient(black 0%, color-mix(in srgb, white, white) 0%)`, a valid gradient that is white behind the text, was read as solid black. The unresolved `color-mix()` stop was dropped, so a visible callback scam was treated as hidden: Safe, previously High.
- **R1 (P1).** The mailbox, delivery, file-sharing and published-document rules read only the text and link labels no style can hide. `@media print { .attack { display: none } }` made a lure the screen shows Safe or Low.
- **R2 (P1).** An unauthenticated `From: …@google.com` made a Google Docs link "the sender's own", so a mailbox lure linking there became Safe.
- **R3 (P2).** PDF font resources were merged by name across pages: two pages each defining `/F1` gave page 2 the first page's ToUnicode map, garbling a callback.
- **R4 (P2).** A malformed font (`/Widths [.]`, a ToUnicode range past its byte capacity) raised out of `analyze_raw_email`, so no result was produced.
- **Also found.** The review's other probes showed that backgrounds browsers reject were still applied: `linear-gradient(banana, black)`, `left left black`, `repeat repeat repeat black`, `none none black`. A line break inside a value (`color: rgb(255,\n255,255)`) dropped the declaration.

### Files changed
- `website/app.py`:
  - **Gradients.** `_gradient_stops` keeps an unresolved stop as unknown, so the gradient is never taken as one colour. It reports a gradient browsers reject, which drops the declaration.
  - **Background validity.** `_background_valid` follows the background layer grammar: one image, repeat, attachment, colour and position, two boxes at most; a well-formed position; the size directly after it; no whitespace inside an unquoted `url()`. Checked against Chromium's `CSS.supports`: all 76 crafted values agree, and 551 of 553 values from public templates and Nazario. The two exceptions are `-moz-` and `-o-` gradients, read as images of unknown colour.
  - **Whitespace.** `_style_values` reads any run of whitespace in a value as one space.
  - **Lure rules (R1).** The four button-based lure rules run on every reading (each rendering view, images off too), with the link labels that reading shows.
  - **Published content (R2).** `_unlisted_off_sender_host` checks user-publishable locations before the sender-domain exemption. `_user_content_location` decodes the path (`/%64ocument/`).
- `website/email_structure.py`:
  - **Font scoping (R3).** Each content stream uses the fonts of its own page (with `/Parent` inheritance) or form.
  - **Unmapped codes.** A simple font's codes missing from its ToUnicode map are read in the standard encoding.
  - **Malformed fonts (R4).** Widths and codes use the full number syntax and are bounded, and CMap ranges past their byte capacity are cut. A PDF or Word attachment that still fails to parse adds `warning.attachment_unreadable`, and the rest of the message is analysed.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the new warning. Asset versions bumped.
- `website/tests/test_review_2026_10_02.py`: 12 tests; on 06dfbb7 they give 24 failures and 4 errors.
- `README.md`, `docs/evaluation.md`.

### Effect
- **Review samples.** Every finding sample is High in HTML and EML, as are the invalid-background probes and the `/%64ocument/` path. `linear-gradient(black)` stays hidden: Chromium paints it black.
- **Same served model, 06dfbb7 against this change:**
  - Nazario 3,466: alerts 3,400 → 3,400; one High → Critical, a file-sharing lure shown only in one rendering view; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- **Not changed.** The sender-domain exemption for other links still trusts an unauthenticated From. An attacker who owns the link's domain can make it pass DMARC as well. Without a chosen mailbox, requiring authentication would remove the exemption from genuine schools' and providers' own notices.
- Tests: 1,008 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 08:30 PT] — Flag delivery lures that ask for a fee or a corrected address

### Why
- Five undetermined Nazario messages were parcel lures:
  - Fastway and South African Post Office fakes: "R 25.00 shipping cost have not been paid", "Confirm the shipping fee 50 ZAR";
  - FedEx and DHL fakes: "unable to locate you due to a mix up in your address", "incorrect address details … update your shipping address".
- Each button led to an unrelated host, and no rule read delivery wording.

### Files changed
- `website/app.py`: `content.delivery_lure` (High; the payment tactic) fires on a delivery notice that:
  - asks for an unpaid shipping, customs or redelivery fee, or says the address is wrong and asks the reader to correct it;
  - has a Pay, Confirm, Update, Continue or Click here button on a host that is not the sender's or an official carrier's;
  - links to no retailers' tracking platform (`_DELIVERY_TRACKING_DOMAINS`: Narvar, AfterShip, Route, ParcelPanel, 17TRACK, Shopify).
  
  "Sorry we missed you, reschedule" alone does not count, because genuine retailers send it.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped.
- `website/tests/test_delivery_lure.py`: 3 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (902bca6) against this change:
  - Nazario 3,466: alerts 3,395 → 3,400 (5 undetermined → 4 Critical, 1 High); 13 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- The wording appears in 26 Nazario messages. It appears in none of:
  - the 92 genuine downloads;
  - 5,055 Apache list messages;
  - 9,198 genuine DIFraud messages;
  - 16,440 marketing emails.
  
  These sets hold few genuine delivery notices, so retailers' fee or address notices are covered by synthetic tests only.
- Tests: 996 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 07:30 PT] — Close gaps in the mailbox-lure rule

### Why
- Sixteen undetermined Nazario messages were mailbox-credential lures the rule should have read. Four reasons:
  - **The reader's address.** It sat inside the threatening sentence ("квота jose@monkey.org перевищена", "كلمة السر … لـ jose@monkey.org تنتهي"), and its dots ended the sentence window.
  - **Password expiry.** "The current password for … expired today", "Your account … password expires today".
  - **Missing wording.** "Unable to send and receive messages", "out of date", and "new version update of your webmail box" were not listed.
  - **Unlisted button labels.** "더 많은 공간을 추가" (add more space), "移除限制" (remove restriction), "Оновіть …" (Ukrainian "update"), "استخدام كلمة المرور الحالية" (use current password), "Read Delayed Messages", and "Cᴏɴғɪʀᴍ ᴀᴄᴄᴏᴜɴᴛ" written in small capitals.

### Files changed
- `website/app.py`, in the mailbox-lure rule (`_mailbox_lure`):
  - email addresses in the text become a neutral word before matching (`_MAIL_ADDRESS`);
  - new threats: the mail account's password expiring, mail that cannot be sent or received, and a mailbox that is out of date or due for a new version;
  - new labels: 추가, 移除, онов-, استخدام, and "read … messages" (not "Read more");
  - labels in small capitals are read as letters (`_SMALL_CAPITALS`).
  
  The link condition is unchanged: off the sender's domain, not a mail provider's sign-in, not official.
- `website/tests/test_mailbox_lure_gaps.py`: 4 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, 1f58e25 against this change:
  - Nazario 3,466: alerts 3,384 → 3,395 (11 undetermined → 6 Critical, 5 High); 3 Medium raised; 66 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Five of the sixteen remain: garbled or obfuscated wording, a link on the sender's own domain, or the lure inside a Word attachment.
- Tests: 993 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 06:30 PT] — Flag file-sharing notices whose button leaves the service

### Why
- Nine undetermined Nazario messages copied a file-sharing notice: WeTransfer's "sent you some files … expires on", OneDrive's "shared a file with you", Dropbox's file-request mail.
- Their Download, Open or View button led to an unrelated host: Cloud Foundry and Workers apps, compromised sites, a SendGrid click link.
- The service was named only in the text or the display name, and no brand rule covers WeTransfer or OneDrive.

### Files changed
- `website/app.py`: `link.file_share_elsewhere` (High; the impersonation tactic) fires when all three hold:
  - the text or the sender's display name names WeTransfer, OneDrive, SharePoint, Dropbox, Google Drive or DocuSign;
  - the text reads as a sharing notice ("sent you some files", "shared a file with you", "files … will be deleted", "download your files");
  - a link labelled Download, Open, View, Get, Access, Review or Preview leads to a host that is not one of the listed services' domains (`_FILE_SHARE_SERVICES`: we.tl, 1drv.ms, SharePoint, aka.ms, Dropbox Sign's hellosign.com among them), the sender's domain, or an official one.
  
  The finding names the service and the host.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped.
- `website/tests/test_file_share_elsewhere.py`: 4 tests, including genuine-style WeTransfer, OneDrive, SharePoint, Google Drive, Dropbox Sign and company-portal notices.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (38d77b5) against this change:
  - Nazario 3,466: alerts 3,375 → 3,384 (9 undetermined → 8 Critical, 1 High); 45 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- No genuine set holds a sharing notice to test against. The wording alone appears in none of these:
  - the 92 genuine downloads;
  - 5,055 Apache list messages;
  - 9,198 genuine DIFraud messages;
  - 16,440 marketing emails.
  
  Genuine notices from the six services are covered by synthetic tests only.
- Tests: 989 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 05:30 PT] — Catch brand names written with a capital I for l

### Why
- Eight undetermined Nazario messages wrote a brand or lure word with a capital I for a lowercase l: "Trust WaIIet" (five crypto scams), "PayPaI", "AppIe ltunes", "WeIIs Fargo". Many fonts draw I and l alike.
- The obfuscation check knew digit and symbol swaps (`P@yP@l`, `Amaz0n`) but not this one, and never read the sender's display name, where three of the eight carried it.

### Files changed
- `website/app.py`:
  - `_letter_swaps` finds words written with I for l after the first letter ("WaIIet", "PayPaI"), or l for an initial i ("ltunes", "lnvoice").
  - Only words that become one of `_LETTER_SWAP_WORDS` count: imitated brands (PayPal, Apple, iCloud, iTunes, Netflix, Wells, Wallet, Outlook) and lure words (mail, login, billing, delivery, invoice, failed). So "LinkedIn", "McIntyre" and all-capital words never match.
  - `_detect_obfuscation` reports these through the existing `content.obfuscation` finding (High, +3, the impersonation tactic).
  - The From display name is now checked too, once per message.
- `website/tests/test_letter_swaps.py`: 6 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (c221517) against this change:
  - Nazario 3,466: alerts 3,368 → 3,375 (7 undetermined → High); 13 High → Critical; none fell. "PayPaI" with no readable body stays undetermined;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Such a word appears in sender, subject or text of 58 Nazario messages and 22 DIFraud fraud messages. It appears in none of:
  - the 92 genuine downloads;
  - 9,198 genuine DIFraud messages;
  - 16,440 marketing emails;
  - 5,055 Apache list messages;
  - the UniqueData legitimate messages;
  - the templates.
- Tests: 985 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 04:30 PT] — Flag account-hold lures in PDF and Word attachments

### Why
- 18 undetermined Nazario messages had an empty body and a PDF holding the whole lure. Most imitated USAA ("your online account has been temporarily restricted", "your payment has been put on hold"); one imitated American Express.
- Each PDF linked to an unrelated site. The text model never reads attachments, and attachment text was checked only for callbacks, secrets and subsidy lures, so nothing fired.

### Files changed
- `website/app.py`:
  - `content.attachment_account_lure` (High; the credential tactic) fires when a Word or PDF attachment:
    - says the reader's account, access or a payment is restricted, suspended, on hold, compromised or expired (`_ACCOUNT_HOLD`, after joining the PDF's broken lines);
    - asks them to verify, update, confirm, log on or sign on within the surrounding 700 characters;
    - links to a host that is neither the sender's domain nor an official one. The finding names the host.
  - Left out: an expired card (genuine payment reminders), wording negated right before the state ("has not been compromised"), and PDFs linking only to the sender's or an official domain.
  - `_unlisted_off_sender_host`: the destination test the mailbox-lure rule already used, now shared by both rules.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped.
- `website/tests/test_attachment_account_lure.py`: 5 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (dc8d420) against this change:
  - Nazario 3,466: alerts 3,350 → 3,368 (18 undetermined → High); 5 Medium → High and 29 High → Critical; none fell;
  - no verdict change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts, which have no attachments.
- None of the genuine downloads has attachment text, so the risk was measured on message text instead. Without the link condition, the wording matches:
  - 2 of 9,198 genuine DIFraud messages;
  - none of 16,440 marketing emails;
  - 1,408 of 6,074 DIFraud fraud messages.
  
  With the link condition, it fires on none of the 92 genuine downloads, 5,055 Apache list messages, 10 templates or 58 UniqueData legitimate messages.
- Tests: 979 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 03:30 PT] — Flag account and payment buttons that lead to published documents and forms

### Why
- Eight undetermined Nazario messages were fake Amazon Prime renewals. Their "Update Information" button opened a Google Drawing, and the trusted domain kept every link check quiet.
- The mailbox-lure rule had the same hole: a lure linking to Microsoft Forms or a Google Form was exempt as a provider's or an official domain.

### Files changed
- `website/app.py`:
  - `_USER_CONTENT_LOCATIONS` lists where anyone can publish on a trusted platform: Google Docs, Drawings, Forms, Slides, Sheets, Sites and Drive files; Apps Script pages; Firebase and Cloud Storage; Microsoft Forms; OneDrive; Dropbox shares; Notion and Canva pages; Tencent Docs, Kdocs, Shimo; SharePoint sites and shares.
  - `link.user_content_action` (High; the credential tactic) fires when an account or payment button leads to such a location (`_ACCOUNT_ACTION`: log in, verify or confirm your account, identity or payment, update your information or payment, unlock, restore or reactivate an account, keep your password). "Confirm attendance", "View document" and company SharePoint sites do not count.
  - The mailbox-lure rule no longer exempts these locations.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding. Asset versions bumped.
- `website/tests/test_user_content_buttons.py`: 3 tests.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (8bfe1a5) against this change:
  - Nazario 3,466: alerts 3,342 → 3,350 (the eight Prime renewals: 6 Critical, 2 High); 11 more alerts rose to Critical, none fell;
  - no verdict, mail-type or question change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 or the 87 public HTML templates;
  - counts identical on the pasted cohorts.
- Genuine evidence is thin: none of the 92 downloads or 87 templates links to such a location at all.
- Tests: 974 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 02:30 PT] — Read the text of PDF attachments

### Why
- Callback phishing often hides in a PDF "invoice" ("If you did not authorize this charge, call 1-888-…") under a body of one line.
- PDF attachments were read only for link annotations, while Word attachments had their text checked since 2026-10-01.

### Files changed
- `website/email_structure.py`: `pdf_text` and its helpers read the text of a PDF's content streams:
  - text-showing operators, decoded through each font's ToUnicode map;
  - compressed object streams are expanded;
  - glyphs are joined by the widths the font gives (`/Widths`, or `/W` for composite fonts), so text placed glyph by glyph keeps its words;
  - bounded in objects (5,000), tokens (300,000), CMap entries and output (20,000 characters). Images and scripts are never read.
  - PDF attachments get `extracted_text`; the attachment stays `metadata_only`.
- `website/app.py`: Word and PDF attachment text get the same check: callback numbers, requests for codes or secrets, and subsidy lures, never keyword categories. Findings are prefixed by their source.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: "PDF attachment: …". Asset versions bumped.
- `website/tests/test_pdf_attachment_text.py`: 6 tests, covering:
  - text operators, word spacing, glyph widths, a ToUnicode font in an object stream and the output bound;
  - a callback invoice PDF (High) and a genuine invoice with a phone number (no finding).
- `README.md`, `docs/evaluation.md`.

### Effect
- Nazario's 120 PDF attachments: 113 yield text, 1–20 ms each. The largest takes 0.87 s, within the bounds.
- Nazario's Amazon "invoice" PDF with a callback number moves from High to Critical.
- Same served model, main (6f71feb) against this change: no other verdict, mail-type or question change, per message, on:
  - the 92 genuine downloads (with and without a mailbox), which hold no PDF;
  - DataCon 2023 day 1 (98 PDFs, 51 with text, none matching);
  - the 87 public HTML templates;
  - Nazario.

  Counts identical on the pasted cohorts.
- Tests: 971 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 01:30 PT] — Catch mailbox lures in English and other languages

### Why
- Of 139 Nazario phishing messages that did not alert, about 20 were English mailbox lures, all undetermined. Examples:
  - "Your 14 important incoming emails are stuck on the email server… Retrieve 14 Emails", linking to `recoverphrase131.web.app`;
  - "username authentication will expire";
  - "Incoming Messages On Hold".
- About ten more were the same lure in Korean, Russian, Ukrainian, Japanese, Arabic or French.
- The model scored them only in renderings it could not score before, so it kept abstaining, and no rule fired.
- The Chinese rule's structure applies to them: the lure wording plus an action link leaving the sender's domain for an unlisted one.

### Files changed
- `website/app.py`: `_MAILBOX_LURE_OTHER` and `_MAILBOX_ACTION_OTHER` extend `content.mailbox_lure`:
  - English: a mailbox, inbox, mail server or incoming mail that is full, over quota, blocked, held, stuck, undelivered, expiring, suspended or closing, in one sentence. "Verify your email address" does not count: genuine sign-ups begin that way, often through a mailing service's tracking domain;
  - Korean, Russian, Ukrainian, Japanese, Arabic, French, Portuguese and Spanish equivalents;
  - action labels in those languages.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the finding names full, blocked, expiring and held mail too. Asset versions bumped.
- `website/tests/test_chinese_lures.py`: lures in six languages, and genuine notices (sign-up confirmation through SendGrid, provider storage notices, newsletter boilerplate).
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (1c49f5a) against this change:
  - Nazario 3,466: alerts 3,327 → 3,342, undetermined 132 → 117. Of the 15 newly caught, 12 are Critical and 3 High. 432 alerts rose to Critical, and none fell;
  - DataCon 2023 day 1: one undetermined lure → High;
  - no verdict, mail-type or question change, per message, on the 92 genuine downloads (with and without a mailbox) and the 87 public HTML templates;
  - counts identical on the pasted genuine text, PhishFuzzer recent, UniqueData and Postmark.
- Genuine evidence is thin: the rule needs a labelled link, so only HTML mail can match. That means 179 messages (the 92 downloads and the 87 templates), none of which match. The plain-text corpora (Apache lists, Marketing-Emails, DiFraud) and 2005-era trec06c have almost no labelled links.
- Analysis time: Nazario 128.4 → 129.2 s.
- Tests: 965 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-02 00:30 PT] — Fix three findings from the review at 0f17def, and the colour bypasses it probed

### Why
- A read-only review at 0f17def reproduced three ways to bring a callback scam to Low or Safe, in HTML and `.eml`:
  - S1 (P1): custom property names were lowercased inside values. `var(--ZERO,16px)` missed `--ZERO`, took the 16px fallback, and read 0px padding as visible: Low, complete.
  - S2 (P1), a regression of a2605bc: an invalid `background: banana black`, which browsers drop, was read as a black background. Visible black scam text was removed from the views: Safe. The reverse (`background: white; background: garbage black` on white text) read hidden padding as visible.
  - R1 (P1): the colour pre-check blended a translucent background only with the white canvas. Translucent white over red (`#ff8080`) never reached the colour pass: Low, complete.
- Beside the findings:
  - an unrelated stylesheet emptied link labels, which turned the Chinese mailbox-lure rule off: High → Unknown;
  - three of the review's probes showed colour bypasses: six colour-only `@media` contexts pushed the stylesheet past the condition limit, which then dropped colours; a one-colour gradient counted as an unknown image; and `color(srgb 1 1 1)` was an unknown colour.

### Files changed
- `website/app.py`:
  - `_style_values` keeps the case of `--name` tokens in values.
  - `_background_valid` checks a `background` shorthand (and `background-image`) before it is used. Each layer may hold only images, positions, sizes, repeats, attachments and boxes, and only the last layer one colour. An invalid one is dropped whole.
  - `_colours_may_match`: a translucent background opens the colour pass.
  - The mailbox-lure rule reads the link labels that the text no style can hide shows.
  - Over the condition limit, @media contexts that only set colours, other than dark mode, become "maybe" rules. These can make text possibly invisible, never certain.
  - `_gradient_stops` and `_background_parts`: a gradient whose stops are all one opaque colour paints that colour.
  - `_wide_gamut_rgb`: `lab()`, `lch()`, `oklab()`, `oklch()` and `color()` (srgb, srgb-linear, display-p3, a98-rgb, prophoto-rgb, rec2020, xyz) are converted to sRGB as CSS Color 4 does.
- Tests:
  - `website/tests/test_review_2026_10_01_fourth.py`: 9 tests, all failing on 0f17def;
  - `website/tests/test_same_colour_text.py`: tests of the old behaviour updated.
- `README.md`, `docs/evaluation.md`.

### Effect
- The review's 17 fixtures, served model, HTML and `.eml`:
  - High (callback): the three findings (std_varcase_css, bg_invalid, bg_invalid_overrides, std_bg_invalid, nested_alpha), and three probes (bg_gradient, bg_unsupported_colour, colour_condition_limit);
  - High (credential): lure_style;
  - bg_image_fallback (white text over a background image) stays Low: the image is unknown;
  - bg_blend_gate stays undetermined: all its text is the colour of its background;
  - the six controls stay High.
- Same served model, main (0f17def) against this change: no verdict, mail-type or question change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 (611), the 87 public HTML templates or Nazario 3,466. Counts are identical on the pasted genuine text, PhishFuzzer recent, UniqueData and Postmark.
- Analysis time: the 92 genuine downloads 10.5 → 10.6 s; Nazario 127.6 → 128.5 s.
- Tests: 963 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-01 23:30 PT] — Catch Chinese mailbox-upgrade lures and words split by symbols; read stylesheets after @import

### Why
- Of DataCon 2023 day 1 (611 Chinese messages), 452 were undetermined. About 103 were mailbox-credential phishing:
  - "邮箱系统在线升级 … 点此登录完成本次升级", whose sign-in link went to a lookalike domain (`qiyeyouxiangbazx.com`), stitched onto a recycled genuine Aliyun notice;
  - quota and suspension notices linking to `.top`, `.ink` or IP hosts.
- The rules scored them 0, and the model cannot read Chinese.
- Subsidy lures split their key words with brackets ("《财 政》补〉贴", "个人劳动（补贴））"). The keyword matcher skipped only spaces inside a Chinese phrase.
- A stylesheet starting with `@import url(…);` was unmodelled: the import was read as part of the next rule's selector, which then looked like an @-rule that hides (AliExpress notices).

### Files changed
- `website/app.py`:
  - `_HAN_FILLER` and `_han_compact`: spaces, brackets, quotes and symbols between Chinese characters are skipped by the keyword matcher and the subsidy rule. Sentence punctuation is kept.
  - `content.mailbox_lure` (High; the credential tactic) fires on three conditions together:
    - the text puts a mailbox or account term next to upgrade, migration, quota, suspension or closure in one sentence;
    - a link is labelled with the action (登录, 升级, 点此…);
    - that link's registered domain is not the sender's, not a mail provider's sign-in (`_CONSUMER_MAILBOX_DOMAINS`, Microsoft 365) and not an official brand domain.
  - `analyze_email_content` takes the message's sender for this check.
  - The stylesheet compiler ends a top-level statement at its semicolon (`@import`, `@charset`, `@namespace`).
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the new finding. Asset versions bumped.
- Tests:
  - `website/tests/test_chinese_lures.py`: 7 tests, all failing on a2605bc;
  - `website/tests/test_rendering_views.py`: statement at-rules.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, main (a2605bc) against this change:
  - DataCon 2023 day 1 (611): alerts 136 → 237. The 101 new alerts are all mailbox-upgrade lures moving from undetermined to High.
  - Nazario 3,466: alerts 3,320 → 3,327 and undetermined 139 → 132 (seven Chinese mailbox lures). Nine Chinese mailbox lures that already alerted rose a level; none fell.
  - No verdict, mail-type or question change, per message, on the 92 genuine downloads (with and without a mailbox) and the 87 public HTML templates.
  - Counts identical on the pasted genuine text, PhishFuzzer recent, UniqueData and Postmark.
- trec06c (local, 2005 Chinese mail): the mailbox-lure and subsidy rules fire on none of 21,766 genuine messages or 42,854 spam, and the matcher adds no keyword match.
- The `@import` fix changed no verdict; the AliExpress stylesheets are modelled again.
- Analysis time: the 92 genuine downloads 10.3 → 10.6 s; Nazario 127.5 → 128.3 s.
- Tests: 954 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-01 23:00 PT] — Treat text the colour of its background as possibly invisible

### Why
- Hidden-text salting with padding in the colour of its background got through. On 5dc7c3d a callback scam with its padding in white on white was Low, presented as a complete analysis with no warning. So were these variants:
  - near white (`#fafafa`), or a colour from a stylesheet or `var()`;
  - the colour of a coloured background;
  - the legacy `bgcolor` and `<font color>` attributes.
- The same technique also splits keywords: single white letters between words, so `#YourwPaymentbof1569.85` does not read as "Your Payment of". Nazario 2021 #66 does exactly this.

### Files changed
- `website/app.py`:
  - Colours:
    - `_colour_rgba` parses CSS colours (named, hex, `rgb()`, `hsl()`, `hwb()`, alpha);
    - `_legacy_colour` parses HTML colour attributes as browsers do (`bgcolor="fff"` is `#0f0f0f`);
    - `_background_parts` reads `background` and `background-color`;
    - `_same_colour` compares contrast: below 1.1 is the same colour. The 148 named colours were taken from pandas' CSS4 table and checked against pydantic and npm's `color-name`.
  - The view pass cascades the text colour and the background (`_COLOUR_PROPERTIES`). This includes presentational attributes and the link colour (`_colour_hints`), and translucent backgrounds. Text the colour of its backdrop is possibly invisible, like a tiny font.
  - The backdrop is unknown, and such text counts as readable, in three cases:
    - under a background image or an Outlook VML shape;
    - in `prefers-color-scheme: dark` views (the canvas and default text colour);
    - in Outlook's dark mode, where all colours are unknown because the client recolours them.
  - `_colours_may_match` opens the view pass only when some text colour may match some background or the canvas. When colour was the only reason and no text matches, the views are dropped, so nothing changes.
  - Fewer than 200 letters in their background's colour (`_SAME_COLOUR_MODEL_LETTERS`, a preheader) stay in the model's views and raise no warning. The text rules still read the message without them.
  - Rules this reader cannot match:
    - one aimed at a class, id or attribute that could only give text its background's colour makes it possibly invisible, not undecidable;
    - each such rule's declarations apply together.
  - `:link` and `:any-link` match a link with a destination; rules with `:visited` are skipped.
  - When colour rules add more conditions than are modelled, the views are rendered without colours.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the warning names text the same color as its background. Asset versions bumped (`website/tools/asset-versions/manifest.json`, the HTML pages, `lang-init.js`).
- `website/tests/test_same_colour_text.py`: 12 tests. On 5dc7c3d, 10 fail, all 12 salting techniques among them; the two controls pass.
- `README.md`, `docs/evaluation.md`.

### Effect
- Served model, synthetic callback scam with padding between its halves:
  - six same-colour techniques: Low (complete) → High (callback), now marked incomplete with the warning;
  - the callback split by white letters: High → High with the callback found;
  - white on a blue cell, and visible padding: Low, unchanged.
- Same served model, main (5dc7c3d) against this change:
  - no verdict, mail-type or question change, per message, on the 92 genuine downloads (with and without a mailbox), DataCon 2023 day 1 (611) or the 87 public HTML templates;
  - counts identical on the pasted genuine text, PhishFuzzer recent, UniqueData and Postmark;
  - Nazario 3,466: alerts 3,320 → 3,320; Low or Safe 9 → 7 (two missed phishing messages now undetermined); seven alerts rose a level, and one fell from High to Medium, where the model abstains because its reading depends on hidden text.
- The 39 fixtures of the review at 8f6aca6: unchanged, in HTML and `.eml`.
- Analysis time, single-threaded on an Apple M2 Max: the 92 genuine downloads 9.6 → 10.1 s; Nazario 113.6 → 126.5 s.
- Tests: 946 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-01 22:00 PT] — Fix four findings from the review at 8f6aca6

### Why
- A read-only review at 8f6aca6 reproduced four ways to keep a callback scam Low or Safe with its padding hidden, in HTML and `.eml` alike:
  - S1 (P1): CSS variables were read globally, not per element.
    - `.absent{--z:16px}` made `.pad{font-size:var(--z)}` readable inside a `font-size:0` wrapper, though no element had `--z`.
    - An inline `--z:0px;font-size:var(--z)` was not read at all.
  - S2 (P1): selectors on elements the document lacks are dropped. The scan that decides this read attribute values raw, so `class="p&#97;d"` (which is `pad`) dropped `.pad{display:none}`. Ids too.
  - R1 (P1): `<style>` and `<script>` were left out of the element tree.
    - `p + p{display:none}` matched across a `<style>` and hid the scam.
    - `style + .pad` and `script + .pad` hid nothing.
  - R2 (P1): a 1px font or opacity 0.05 in a stylesheet did not open the views that leave such text out, unlike the same style inline. The result was Low, as a complete analysis with no warning.
- Found while fixing these:
  - rules on `html`, `:root` or `body` were dropped when the document leaves those elements implied. Browsers apply them to everything (`body{font-size:0}`);
  - an unknown pseudo-element in a selector list (`.attack, p::unknown{display:none}`) skipped the list instead of making it undecidable: Safe;
  - `position` inline with `left:-9999px` in a rule, or the reverse, did not open the geometry views;
  - `:root{--z:transparent}.pad{color:var(--z)}` was Low as a complete analysis (the review's probe `vars_gate`).

### Files changed
- `website/app.py`:
  - Custom properties:
    - `_style_values` keeps `--name` declarations;
    - `_with_custom_properties` cascades and inherits them per element, from rules and inline styles. It substitutes `var()` (`_substitute_variables`: nested, with fallbacks) in size, colour, opacity and box values, and `_variable_class` classifies the result;
    - a `var()` with no value and no fallback unsets its declaration, as in browsers;
    - these replace `_custom_properties` and `_with_variables`;
    - a rule this reader cannot match that may set a custom property `var()` reads leaves the text it reaches undecidable.
  - `_parse_selector`:
    - `:root`, and `html` or `body` absent from the document, apply to the root, with `:root`'s pseudo-class specificity;
    - unknown and vendor-prefixed pseudo-elements are "maybe".
  - `_document_features` reads elements with the same HTML parser as the text: character references decoded, the first of a repeated attribute kept.
  - The view pass records `<style>`, `<script>`, `<template>` and `<noframes>` as siblings.
  - Gates for the geometry and typography views:
    - `_box_may_hide` is one gate for inline and stylesheet box values. It includes an off-screen offset or a clip rectangle on its own, and any `var()` box value;
    - the stylesheet gate also opens on tiny fonts, faint opacity and `var()` values;
    - the typography gate opens on tiny fonts and `var()` too.
- Tests:
  - `website/tests/test_review_2026_10_01_third.py`: 19 tests. 17 fail on 8f6aca6; the other two are controls;
  - `website/tests/test_review_2026_10_01_second.py` reads custom properties per element.
- `README.md`, `docs/evaluation.md`.

### Effect
- The review's fixtures, served model, HTML and `.eml`:
  - High (callback), from Low or Safe: scoped and inline variables; entity-encoded class and id; the three `<style>` and `<script>` sibling cases; a stylesheet 1px font or opacity 0.05, with or without an unrelated hiding rule; the unknown pseudo-element list;
  - `vars_gate`: Low → High (callback), still a complete analysis;
  - `root_hide` (`html{font-size:0}`, so no text is visible): Low → Unknown;
  - `body_style` stays Low: its padding inherits a readable size, as the reviewer's browser shows;
  - the other 25 of the 39 fixtures are unchanged.
- Found-while-fixing cases, served model: root rules (`body`, `html`, `:root` font size, `body` transparent colour) Low or Unknown → High (callback); split offsets Low → High (callback).
- Same served model, main (c195630) against this change: no verdict, mail-type or question change, per message, on:
  - the 92 genuine downloads, with and without a mailbox;
  - DataCon 2023 day 1 (611);
  - the 87 public HTML templates;
  - Nazario 3,466.

  Counts are also identical on the pasted genuine text, PhishFuzzer recent, UniqueData and Postmark.
- Analysis time, single-threaded on an Apple M2 Max: the 92 genuine downloads 9.3 → 9.5 s; Nazario 110.8 → 112.3 s.
- Tests: 934 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-01 21:00 PT] — Treat tiny, faint, clipped, off-screen and Outlook-hidden text as possibly invisible

### Why
- Hidden-text salting: phishing hides benign padding beside the scam, so a text model reads it as normal mail. On `57f7f35`, a callback scam came out Low with its padding hidden by any of ten techniques:
  - a zero-height box that clips: inline, in a stylesheet, or split across both;
  - a 1px font, or opacity 0.05;
  - an absolute position at -9999px, or `text-indent:-9999px`;
  - `clip: rect(0 0 0 0)`, or `transform: scale(0)`;
  - `mso-hide:all` (Outlook).
- Found while measuring this: a rule whose selector matched an earlier rule's, apart from a mail-client prefix, lost its client. The hook became an independent condition, doubling the views and leaving some stylesheets unmodelled.
- Text rules spent most of the analysis time recompiling keyword patterns: there are more keywords than Python's regex cache holds.

### Files changed
- `website/app.py`:
  - Box geometry, `mso-hide`, near-zero opacity and tiny fonts:
    - `_geometry_hidden`, `_zero_box`, `_css_pixels`, `_absolute_pixels`, `_opacity_number` and `_hiding_value` read box geometry;
    - `_font_size_class` returns `'tiny'` below 3px, and opacity below 0.1 is `'faint'`;
    - the view pass cascades these properties when the document or stylesheet uses them, and leaves such text out of each view (and `mso-hide:all` text out of the Outlook view).
  - `warning.possibly_invisible_text`:
    - the text rules read the message both with such text and without it, in each view;
    - the model views must agree;
    - it does not make a view "newly scored".
  - Text rules read every computed view, the Outlook view included, for every HTML part.
  - Mail clients are collected from the rules, not from shared patterns.
  - `_keyword_pattern` caches compiled keyword patterns, and identical rule readings are scored once.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the new warning. Asset versions bumped (`website/tools/asset-versions/manifest.json`, the HTML pages, `lang-init.js`).
- Tests:
  - `website/tests/test_hidden_text_salting.py`: 5 tests;
  - `website/tests/test_review_2026_10_01_second.py`: the shared-selector client.
- `README.md`, `docs/evaluation.md`.

### Effect
- All ten salting techniques: Low → High (callback). Padding left visible is still read as written.
- Same served model, `57f7f35` against this change:
  - no verdict or mail-type change on: the 92 genuine downloads (with and without a mailbox), their pasted text, PhishFuzzer recent, UniqueData, Postmark, DataCon 2023 day 1 (611) and the 87 public HTML templates;
  - Nazario 3,466: alerts 3,320 → 3,320, with two messages trading High and Critical.
- Analysis time, single-threaded on an Apple M2 Max:
  - the 92 genuine downloads 14.9 → 9.3 s;
  - Nazario 180 → 111 s;
  - backend tests 44 → 35 s.
- Tests: 915 passed, 10 skipped; all frontend test files 514 passed.

## [2026-10-01 20:00 PT] — Render HTML views with exact selector matching and the CSS cascade

### Why
- A read-only review at 1d9206d reproduced four ways to bring a callback scam to Low or Safe:
  - S1 (P1): font-size math functions.
    - A number was mixed with lengths: `max(16px,1)` was read as visible, where browsers drop it.
    - A valid negative argument was rejected: `max(-1px,0px)` computes to a zero size.
  - R1 (P1): `.wrap span{display:none}` was approximated as hiding all of `.wrap`. That removed the scam text beside the span from every view.
  - R2 (P1): all interaction states shared one switch. Two checkboxes, or a hover and a focus, need four combinations.
  - R3 (P1): image fallback text reached the model views but not the text rules.
- The earlier fixes approximated CSS with class tokens, and each approximation could be turned against the reader. This change renders the views with the cascade instead.
- While checking the change, five more cases where a browser and the reader disagree on whether CSS applies turned up:
  - a selector list with one selector the reader cannot read (browsers drop the whole rule);
  - `@layer`;
  - `<style media="print">`;
  - `<style type="text/plain">`;
  - content a browser moves out of a table.

### Files changed
- `website/app.py`:
  - `_stylesheet_cascade` replaces `_stylesheet_hidden_targets`:
    - `_parse_selector` splits each selector into compounds and combinators;
    - mail-client hooks and interaction states are conditions;
    - rules the reader cannot match exactly are "maybe";
    - views are combinations of up to five conditions, each in at most one client (64 views at most);
    - each view holds the winning declaration per pattern and property.
  - The view pass of `_visible_content_text` matches selectors element by element, siblings included:
    - it computes display, visibility, opacity, font size and colour per view, from the stylesheet and inline cascade;
    - content a browser moves out of a table inherits from outside it;
    - text a "maybe" rule could change is unresolved, and the text rules read it too.
  - `_font_size_class` type-checks `min()`/`max()`/`clamp()` arguments and computes their signs.
  - `_with_variables` resolves `var(--x)` from the custom properties the stylesheet defines.
  - `<style>` media and type attributes are applied.
  - Images-off readings put the alt text in place. They feed the model views and, for floor findings only, the text rules.
- Tests:
  - `website/tests/test_review_2026_10_01_second.py`: 13 new tests;
  - `test_rendering_views.py`, `test_rendering_template_patterns.py`, `test_review_2026_09_30.py`, `test_review_2026_09_30_second.py` and `test_review_2026_10_01.py`: assertions on removed internals now check the rendered text;
  - `website/tests/vercel_runtime_smoke.py`: the unmodelled-stylesheet control now uses CSS nesting, since `div{display:none}` is modelled exactly.
- `README.md`, `docs/evaluation.md`.

### Effect
- All review inputs are High (callback):
  - S1 with a unitless, zero or negative argument;
  - R1;
  - R2, with checkboxes and with hover and focus;
  - R3, with and without hidden padding.
- The five additional cases are High, except `@layer`, which is undetermined.
- Same served model, `1d9206d` against this change:
  - no verdict or mail-type change on: the 92 genuine downloads (with and without a mailbox), their pasted text, PhishFuzzer recent, UniqueData, Postmark, DataCon 2023 day 1 (611) and the 87 public HTML templates;
  - Nazario 2015–25: alerts 3,319 → 3,320, undetermined 138 → 137, Safe or Low 9 → 9.
- Analysis time, single-threaded on an Apple M2 Max: the 92 genuine downloads (two analyses each) 10.5 → 14.7 s; Nazario 163 → 175 s.
- Tests: 909 passed, 10 skipped; frontend 116 passed.

## [2026-10-01 19:00 PT] — Read common mail-template CSS instead of leaving genuine HTML undetermined

### Why
- With a mailbox chosen, 10 of the 92 genuine downloads ended undetermined; without one, 15. All were blocked by HTML rendering uncertainty:
  - Google and LinkedIn templates hide a tag inside a class (`.desktop_hide table`, `.inline-button table`). A hiding selector without its own class or id left the whole stylesheet unmodelled.
  - A Cloudflare template's Office settings block ends `<!` and `[endif]` on separate lines (a formatter's wrap). The conditional was not closed.
  - Descriptive image alt text (three words or more) made every view unresolved, though only short instructions ("Enter password") are beyond the model.
  - An MJML mobile menu, shown when its checkbox is ticked, was read as an ambiguous cascade.

### Files changed
- `website/app.py`:
  - `_hidden_selector_targets`: a subject without tokens is reached through the nearest compound with tokens, when a descendant or child combinator follows that compound. The element's whole content counts as possibly hidden. A rule that shows counts only its subject's own tokens.
  - `_stylesheet_hidden_targets`: interaction states (`:checked`, `:hover`, `:focus`, `:active`, `:target`) are one more context, and they are removed before selectors are compared.
  - `_expand_mso_comments` accepts whitespace inside `<![endif]`.
  - Image alt text:
    - descriptive fallback text of linked images becomes an "images off" rendering that the model scores;
    - fallback instructions stay unresolved;
    - `warning.image_alt_fallback` stops blocking once every view agrees.
- Tests:
  - `website/tests/test_rendering_template_patterns.py`: 7 tests, including padding hidden through an ancestor (still High, callback) and a shown child that does not show its hidden parent;
  - `website/tests/test_rendering_views.py`: the `:hover` rule in the fixture is now its own view.
- `README.md`, `docs/evaluation.md`.

### Effect
- Same served model, `bb24745` against this change:

| Cohort | Alerts / undetermined / Safe or Low before | After |
|---|---|---|
| 92 genuine downloads, mailbox chosen | 3 / 10 / 79 | 3 / 6 / 83 |
| 92 genuine downloads, no mailbox | 27 / 15 / 50 | 27 / 9 / 56 |
| Nazario 2015–25 phishing (3,466) | 3,318 / 139 / 9 | 3,319 / 138 / 9 |
| 87 public HTML templates | — | one welcome template undetermined → Low |
| DataCon 2023 day 1 (611) | — | one Lookfantastic sales mail undetermined → Low (advertising) |

- Unchanged: the pasted genuine text, PhishFuzzer recent, UniqueData and Postmark.
- Still undetermined with a mailbox (6):
  - LinkedIn ×2 and AliExpress ×2 now render fully, but the model alerts only on the new view (47–68%). They keep the earlier abstention.
  - Cloudflare ×1 and Adobe ×1 score at the threshold (36–37% against 37.4%).
- Tests: 888 passed, 10 skipped.

## [2026-10-01 18:00 PT] — Fix five findings from the review at b84c605

### Why
- A read-only review at b84c605 reproduced five ways to bring a phishing message down to Low, or to let a reader's answer do so, on the served model:
  - S1 (P1): CSS functions with bad arguments (`rgb(nope)`, `max(16px,garbage)`) were read as valid. Hidden padding inside a transparent or zero-size wrapper then counted as visible text and diluted a callback scam to Low.
  - S2 (P1): a repeated `@media` condition was merged into one context, losing source order. No view showed the callback with both padding blocks hidden.
  - R1 (P2): "yes" lowered an alert carrying a High shortened-link indicator, which adds to the score without setting a floor.
  - R2 (P2): an order number made a delivery notice count as the reader's own action.
  - R3 (P2): the answer was applied after the completeness check, so an unreadable MIME branch could still end Low.
- While fixing S1, the same root cause turned up in one more form: an unknown `display`, `visibility` or `opacity` value replaced an earlier hiding one (`display:none;display:garbage`), with the same Low result.

### Files changed
- `website/app.py`:
  - Colours (`_color_class`): every argument of each colour function is checked. An invalid colour is dropped, a missing or negative alpha is transparent, and CSS system colours are known.
  - Font sizes (`_font_size_class`): every `min()`, `max()` and `clamp()` argument must be a length, and unknown units are invalid.
  - `_style_values` drops invalid colour and size declarations, so an earlier one stays. An unknown display, visibility or opacity value replaces nothing and marks the text unresolved.
  - `_stylesheet_hidden_targets` replays the rules of each view in source order. A repeated context keeps each of its positions, `!important` beats a later normal rule, and display and visibility are separate properties. Text is unresolved inside a class that different compound selectors hide and show, or inside an element whose classes are hidden and shown in one view.
  - The own-action question:
    - `_rests_on_text_model` blocks it on any Medium or higher indicator, presentation cues aside;
    - `_NOT_OWN_ACTION_NOTICE` excludes deliveries, payments, refunds, invoices, statements, renewals and memberships wherever the text mentions them;
    - the answer is applied before the completeness check.
- Tests:
  - `website/tests/test_review_2026_10_01.py`: 13 tests built from the review fixtures, plus the display, visibility and opacity variant.
  - `website/tests/test_rendering_views.py`: the fixture's base `.mobile` rule now comes before its `@media` rule. In the old order, the later base rule wins under CSS, which leaves a single view.
- `README.md`, `docs/evaluation.md`: the rules and their measurement.

### Effect
- All five review inputs:
  - S1 colour and size, and S2: High (callback);
  - R1 and R2: not asked, and "yes" keeps High;
  - R3: "yes" gives unknown.
- No verdict changed on the 92 genuine downloads (with and without a mailbox), their pasted text, Nazario 3,466, PhishFuzzer recent, UniqueData or Postmark.
- The own-action question, if every asked reader answers "yes":

| Cohort | Asked (before → after) | Alerts after "yes" (before → after) |
|---|---|---|
| Nazario .eml (phishing) | 180 → 8 | 3,138 → 3,310 |
| PhishFuzzer recent phishing, pasted | 6 → 4 | 84 → 86 |
| Genuine .eml, no mailbox | 17 → 16 | 10 → 11 (unknown 15 → 20) |
| Genuine .eml, mailbox chosen | 3 → 2 | 0 → 1 (unknown 10 → 12) |
| Genuine pasted | 29 → 29 | 16 → 16 |
| PhishFuzzer recent legit, pasted | 14 → 10 | 58 → 62 |
| UniqueData legit, pasted | 16 → 12 | 26 → 30 |

- Tests: 881 passed, 10 skipped.

## [2026-10-01 17:00 PT] — Ask about the reader's own actions, not only account codes

### Why
- Many remaining model-driven false alerts on pasted genuine mail were notices of the reader's own actions that the account-code pattern missed: "signed-in", Steam Guard codes, new accounts, order confirmations, job applications and support tickets.

### Files changed
- `website/app.py`:
  - `_ACCOUNT_NOTICE` covers sign-ins, guard and launch codes, new or linked accounts, orders and purchases, job applications and support requests, in English and Chinese;
  - deliveries, payments received, memberships and statements are excluded;
  - the "yes" label is "Low Risk — Confirmed as Your Own Action".
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: the question ("Are you sure you did this yourself just now?", "No, or not sure"), the label and both notes. Asset versions bumped.
- Tests:
  - `website/tests/test_requested_notice.py`: own actions asked; deliveries, received payments, memberships and statements not;
  - `website/static/app.test.mjs`: the new wording.
- `README.md`, `docs/evaluation.md`: the scope and its measurement.

### Effect
- If every asked reader answers "yes":
  - genuine `.eml` alerts 27 → 10, pasted 45 → 16;
  - UniqueData 42 → 26.
- Nazario messages asked rise from 127 to 180, mostly fake orders and unusual sign-ins. A truthful "no" keeps them alerting.

## [2026-10-01 16:00 PT] — Ask where an .eml came from, and whether an account notice was requested

### Why
- Outlook.com downloads cannot be verified cryptographically: every DKIM body hash fails after "Download as EML". So 27 genuine downloads kept alerting unless the reader found the mailbox menu.
- Most model-driven false alerts on genuine mail are account notices, and only the reader knows whether they requested one.

### Files changed
- `website/app.py`:
  - `requested` on `ContentRequest` (and `?requested=` on `/api/analyze-eml`);
  - `_ACCOUNT_NOTICE` (English and Chinese);
  - `_apply_requested_answer` sets `requested_question` for a model-driven alert on an account notice. On "yes" it lowers the result to "Low Risk — Requested Account Notice"; on "no" it keeps the alert with `content.unrequested_notice`.
- `website/visual_evidence.py`: `requested` on `VisualRequest`.
- `website/static/app-content.js`:
  - the detected-mailbox hint becomes a question (Yes / No, or not sure), asked before analysis;
  - menu choices answer it, and a new file is asked again;
  - the requested answer is sent and reset when the text changes.
- `website/static/app-content-render.js`, `index.html`, `style.css`, `i18n.js`, `i18n-zh.js`: the requested question under the banner, the new risk label and messages. Asset versions bumped.
- Tests:
  - `website/tests/test_requested_notice.py`: asking, yes and no, independent evidence never answered away, other mail not asked, endpoint validation;
  - `website/static/app.test.mjs`: both questions; two existing tests now answer the mailbox question.
- `README.md`, `docs/evaluation.md`: the questions and their measurement.

### Effect
- Without an answer, every verdict is unchanged.
- With "yes" to the mailbox question, the 92 genuine downloads alert 3 times.
- With "yes" to the requested question:
  - genuine `.eml` alerts 27 → 14, pasted 45 → 21;
  - UniqueData 42 → 38.
- 127 Nazario phishing messages would be asked. A truthful "no" keeps them alerting.

## [2026-10-01 15:00 PT] — Trust Gmail's ARC-sealed checks without a mailbox choice

### Why
- Without a mailbox choice, 43 of 92 genuine downloads alerted; with it, 3.
- All 52 Gmail downloads carry an ARC chain sealed by Google, and all of them verify. That proves Gmail received the message and recorded its own checks, which a forwarded attachment cannot fake.
- Benign-notice wording was measured first and rejected: it appears in few genuine alerts and in more phishing.

### Files changed
- `website/email_structure.py`:
  - `arc_sealed_results` verifies the chain with `dkimpy`, only when every seal and message signature comes from `ARC_SEALERS` (`google.com`). Any other sealer is never looked up.
  - `_arc_dns_txt` looks up keys with a 2-second timeout and caches them for an hour.
  - With no mailbox, the sealed `ARC-Authentication-Results` are trusted for the outer message only.
  - `authentication_source` and `structure.arc_sealed_results` say so.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: `structure.arc_sealed_results`. Asset versions bumped.
- `requirements.txt`, `requirements-dev-py312-macos-arm64.lock.txt`: `dkimpy==1.1.8`, `authres==1.2.0`.
- `website/tests/test_arc_sealed_results.py`, `website/tests/arc_test_keys.py`: run-time signed messages with a throwaway key and mocked DNS, covering:
  - a valid seal;
  - tampering and lookup failure;
  - foreign sealers never looked up;
  - mismatched results;
  - a chosen mailbox;
  - attached messages.
- `README.md`, `docs/evaluation.md`: the rule and the measurement.

### Effect
- 92 genuine downloads without a mailbox: 43 / 34 / 15 → 27 / 15 / 50 (alerts / undetermined / Safe or Low). The Gmail downloads now match the mailbox choice: 0 / 7 / 45.
- Outlook.com downloads, Nazario, PhishFuzzer, UniqueData, Postmark, Apache and the HTML templates are unchanged.

## [2026-10-01 14:00 PT] — Fix five findings from the second review at 06f4522

### Why
- An independent review reproduced five issues with synthetic fixtures:
  - S1: an invalid inline colour cleared an inherited transparent colour, so hidden padding diluted a visible callback scam to Low. This was a regression from the inline-style change. A `font-size:initial` variant was also Low.
  - S2: media conditions were viewed one at a time, never together.
  - R1: a zero-width character in "GitHub" passed the other-organization check.
  - R2: two sales words turned a link disguised as `accounts.google.com` into advertising. This was a regression from the tracked-link rule.
  - R3: `reason=header.from=…` or a repeated `header.from` could name the DMARC identity.

### Files changed
- `website/app.py`:
  - `_color_state`, `_font_size_state`, `_UNCOMPUTED` and `_NAMED_COLORS` follow CSS: invalid colours inherit; `initial` restores; `min()`/`max()`/`clamp()` over plain lengths are computed; other uncomputable values are unresolved.
  - `_stylesheet_hidden_targets` makes a view for every combination of up to five media contexts (`_MAX_MEDIA_CONTEXTS`), applied in source order.
  - `_tracked_sales_links` lets only neutral shown hosts yield to advertising.
- `website/email_structure.py`:
  - `_clause_properties` and `_single_property` parse DMARC and DKIM clauses as ordered properties, and conflicting identities name none;
  - `_folded_display_name` is shared by both display-name checks.
- Tests:
  - `website/tests/test_review_2026_09_30_second.py` covers all five findings and the computed size functions;
  - updated media and mail-type tests.
- `README.md`, `docs/evaluation.md`: the rules and the results.

### Effect
- All five fixtures now give the expected results (High, Medium or phishing, as listed in the evaluation).
- Genuine downloads, templates, Nazario, DataCon, PhishFuzzer and trec06c: no verdict or mail-type change.

## [2026-10-01 13:00 PT] — Call tracked-link sales mail advertising, not phishing

### Why
- 48 DataCon 2023 sales messages were called phishing on a disguised link alone: predatory conferences, journals, editing services and lead-generation tools sent through click trackers or bare IPs.

### Files changed
- `website/app.py`:
  - academic solicitation terms join `_ADVERTISING_TERMS`;
  - `_advertising` is split out, with a `strict` mode;
  - `_mail_type` calls a message advertising when `deceptive_link` is its only tactic and it has two distinct sales terms and no scam wording.
- `website/tests/test_mail_type.py`: that rule, with one term plus an unsubscribe footer still phishing, and other findings still phishing.
- `README.md`, `docs/evaluation.md`: the rule and its measurement.

### Effect
- Labelled cohorts:
  - spam called advertising 69 → 91;
  - phishing called advertising unchanged at 16;
  - legitimate called advertising 10 → 12 (journal and conference mail).
- DataCon 2023 day 1: 31 solicitations moved from phishing to advertising.
- Nazario labels and every verdict unchanged.

## [2026-10-01 12:00 PT] — Add a mail-type note: phishing or scam, or advertising

### Why
- A risk level alone does not say what kind of unwanted mail a message is. Advertising that the text model flags looked the same as phishing.

### Files changed
- `website/app.py`:
  - `_mail_type` returns `{"type": "phishing", "tactics": [...]}` for an alert with a concrete scam finding, `{"type": "advertising"}` for sales wording with no scam wording, or `None`;
  - `_advertising_terms` and `_SCAM_CATEGORIES` support it;
  - the result carries `mail_type`, and the verdict is unchanged.
- `website/email_structure.py`: `bulk_mail` (`List-Unsubscribe` or a bulk/list `Precedence`).
- `website/static/index.html`, `app-content-render.js`, `style.css`, `i18n.js`, `i18n-zh.js`: the note under the result banner, in English and Chinese. Asset versions bumped.
- Tests:
  - `website/tests/test_mail_type.py`: tactics, advertising, scam wording never advertising, ordinary mail, opt-out and bulk header, model-only alerts;
  - `website/static/app.test.mjs`: rendering.
- `README.md`, `docs/evaluation.md`: the rule and its measurement.

### Effect
- Genuine downloads:
  - no message called phishing; 1 called advertising;
  - no verdict changed on 4,261 messages.
- Nazario: 1,118 phishing messages are named with their tactics, and none is called advertising.
- DataCon 2023 day 1: 122 called advertising and 106 phishing.

## [2026-10-01 11:00 PT] — Read Word attachments; flag subsidy and tax-refund lures

### Why
- In 2023 Chinese phishing (DataCon 2023, day 1) the lure often sits in a Word attachment, with a one-line body or none ("个人劳动补贴" notices). Nothing read the attachment, so these messages stayed undetermined.

### Files changed
- `website/email_structure.py`:
  - `docx_text_and_links` reads `word/document.xml` text and external hyperlinks. It is bounded in archive size, entry count and decompressed bytes, and never opens macros, embedded objects or images.
  - .docx attachments get `extracted_text` and `extracted_links`.
- `website/app.py`:
  - Word attachment links get the destination checks, prefixed `prefix.docx_attachment`.
  - Attachment text is checked only for callback numbers, sensitive requests and subsidy lures (`_attachment_text_findings`, prefixed `prefix.docx_text`).
  - `_subsidy_lure` needs a subsidy or refund term together with claim pressure, in the body or an attachment.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js`: `content.subsidy_lure`, `prefix.docx_attachment`, `prefix.docx_text`. Asset versions bumped.
- `website/tests/test_docx_attachments.py`:
  - extraction, macros and other parts ignored, malformed input, decompression bombs, entry and text bounds;
  - subsidy lures against genuine allowance notices;
  - attachment lures, callbacks and links;
  - ordinary business wording scoring nothing;
  - .docx-named generic types.
- `README.md`, `docs/evaluation.md`: the rule and the measurement.

### Effect
- DataCon 2023 day 1: alerts 86 → 136. The 50 new alerts are all subsidy campaigns, and sales mail is unchanged.
- Genuine downloads, public templates and Nazario: unchanged.

## [2026-10-01 10:00 PT] — Record the English text-model experiments

### Why
- English false alerts in pasted-text mode come almost entirely from the text model.
- Two evaluation-only fixes were measured, and neither met its bar.

### Files changed
- `docs/evaluation.md`: two experiments.
  - Retraining with DiFraud, PhishFuzzer legacy-seed LLM variants and account hard negatives raised ROC AUC by 0.01–0.04 but only shifted the threshold.
  - A `bge-small-en-v1.5` embedding model with logistic regression, trained on the same 26,052 rows, failed all four pre-registered criteria and ranked phishing worse on every set.

### Effect
- No code or model change; the served artifact is unchanged.
- The evaluation record states the limit: modern legitimate training data is missing, and the `.eml` with its mailbox chosen is the accurate path.

## [2026-10-01 09:00 PT] — Say when an alert rests mainly on the text model

### Why
- In pasted-text mode, English false alarms come almost entirely from the TF-IDF + logistic-regression text model: 42 of 58 real legitimate UniqueData messages and 72 of 102 recent legitimate PhishFuzzer seeds alert, while the rules alone would alert on about one. With a raw `.eml` and the mailbox chosen, 3 of 92 genuine emails alert.
- The result already showed "Model Signal Needs Review" and a tip to upload the `.eml`, but did not tell the reader that the judgement came mainly from the model, and the tip was hidden for a model-driven alert on an `.eml` whose mailbox had been chosen or was not recognized.

### Files changed
- `website/static/app-content-render.js` — `renderAccuracyTip` picks `content.tip.uploadModel` or `content.tip.chooseModel` when `fusion_basis` is `model_only` or `model_led` on a Medium/High/Critical result, and shows `content.tip.modelEml` for such a result on an `.eml` with nothing left to choose.
- `website/static/i18n.js`, `website/static/i18n-zh.js` — the three strings in English and Chinese.
- `website/static/app.test.mjs` — pasted text, the Outlook.com rerun offer and the chosen-mailbox case for model-driven alerts; a corroborated alert on a chosen mailbox still shows no tip.
- `website/static/index.html`, `404.html`, `cases.html`, `lang-init.js`, `website/tools/asset-versions/manifest.json` — asset versions bumped by `website/tools/asset-versions/update.mjs`.
- `README.md` — the tip description.

### Effect
- Display only: verdicts, scores, labels and the API response are unchanged.
- Model-driven alerts now state that the text model raised them and that the original `.eml` with its mailbox is much more accurate; corroborated or rule-driven alerts keep the earlier tip text.

## [2026-10-01 08:00 PT] — Add Chinese phrasing to the content keyword rules

### Why
- The keyword categories had no Chinese phrases, and the model does not cover Chinese text.
- 17 undetermined Nazario phishing messages carried Chinese mailbox-credential lures that nothing read.
- The keyword matcher's word boundaries also stopped Chinese phrases matching inside running text.

### Files changed
- `website/app.py`:
  - `_CONTENT_RULES_ZH` adds 82 simplified and traditional phrases to the urgency, threats, credential and deception categories;
  - `_keyword_matches` matches Chinese phrases without word boundaries and skips whitespace inside them.
- `website/tests/test_chinese_content_rules.py` — matching inside running text and across inserted spaces, English boundaries unchanged, simplified and traditional lures, and ordinary Chinese notices (codes, shipping, bills, "we will never ask for your password", membership renewal) matching nothing.
- `README.md`, `docs/evaluation.md` — the rule and its limits.

### Effect
- Nazario 2015–25 phishing: 3,316 → 3,318 alerts; top-header-trusted run 2,032 → 2,036.
- Genuine downloads and public templates unchanged.
- Not yet measured on genuine Chinese mail, so each phrase adds one point and no combination rule raises a verdict; that waits for 163 and QQ samples.

## [2026-10-01 07:00 PT] — Score text that inline zero-size wrappers do not hide; read obfuscated callback numbers

### Why
- 53 of the 168 undetermined Nazario phishing messages carried the inline-CSS warning. Any inline zero `font-size` or transparent color marked the message uncertain and passed that on to every descendant, even when a child restored the size, as in the `font-size:0` layout wrappers of HTML mail.
- Scoring those messages exposed three PayPal payment callback scams. Their lure, "Don't recognize this seller, … contact PayPal at I(888) 673-593I", missed the callback rule on the wording and on a letter written for a digit, so the verified-sender rule lowered the model's alert to Low.

### Files changed
- `website/app.py`:
  - `_style_values` is split out of `_inline_visibility`;
  - `_inline_text_state` reports zero size, transparent colour and uncertain opacity per inline style;
  - the text collector tracks the inherited state per element, lets a positive absolute size or a visible colour restore it, and raises `warning.inline_css_visibility` only when visible text is emitted under it;
  - the callback rule accepts "don't/do not recognize", and reads I, l, | and O as digits where they touch a number (`_PHONE_LOOKALIKE`), quoting the number as written.
- `website/tests/test_html_input_coverage.py` — restored wrappers, relative sizes, transparent parents, image text, and zero-size padding beside restored text.
- `website/tests/test_sensitive_requests.py` — "don't recognize", obfuscated numbers, vanity numbers, and the quoted number.
- `README.md`, `docs/evaluation.md` — the rules, the measurements and the unregistered PayPal number.

### Effect
- Nazario 2015–25 phishing: 3,289 → 3,316 alerts (undetermined 168 → 141). Top-header-trusted run: 2,011 → 2,032.
- 92 genuine downloads: one undetermined → Low with and without a mailbox; no new alerts. Public HTML templates unchanged.
- Callback rule: no new flags on 1,930 genuine or public legitimate messages; 62 → 71 on Nazario.

## [2026-10-01 06:00 PT] — Align routing headers by registrable domain

### Why
- `structure.routing_mismatch` accepted only exact or parent/child domains, so a Return-Path on `gaia.bounces.google.com` for mail from `accounts.google.com` was a mismatch.
- It flagged 22% of the 92 genuine downloads and 22% of 3,466 Nazario phishing messages: no separation at all.

### Files changed
- `website/email_structure.py` — `_same_registrable_domain`, using the bundled Public Suffix List with private suffixes (`github.io` users stay distinct); Reply-To and Return-Path align with From when either relation holds.
- `website/tests/test_routing_mismatch.py` — sibling hosts align; other organizations, sending services, `github.io` users and a foreign Reply-To still differ.
- `README.md`, `docs/evaluation.md` — the rule, its measurement, and why the link-count rule was left unchanged.

### Effect
- The finding appears on 4 of 92 genuine downloads (was 20) and 765 of 3,466 Nazario messages (was 777).
- No verdict changed in any cohort. Raising or removing the link-count threshold was measured and rejected: it lost 6–9 Nazario alerts and saved at most one genuine one.

## [2026-10-01 05:00 PT] — Stop scoring address shape on a service's own domain without a mailbox

### Why
- Without a mailbox choice, 56 of 92 genuine downloads alerted. Most of those alerts came from sender-address findings, not the model: 21 from rules alone and 22 from both, versus 11 from the model alone.
- Relaxing those findings for every sender lost 28–48 Nazario phishing alerts. On a registry service's own domain the address is the same for genuine and spoofed mail, so address shape adds nothing there; only authentication does.

### Files changed
- `website/email_structure.py` — `service_domain_sender`: a From on a `sender_only` service's own domain, with no trusted DMARC result, no decisive authentication failure and no platform-relay sign.
- `website/app.py` — `_relax_authenticated_sender` takes the info code; such senders get the address-shape relaxation with `sender.service_domain`.
- `website/data/server_messages.json`, `website/static/i18n.js`, `website/static/i18n-zh.js` — `sender.service_domain` says the sender is not proven and suggests choosing the mailbox. Asset versions bumped.
- `website/tests/test_service_domain_sender.py` — named vs. not (payment brand, lookalike, generic name, relay address, relay subject, DMARC failure, verified sender); scoring.
- `README.md`, `docs/evaluation.md` — the rule and the variant measurements.

### Effect
- 92 genuine downloads without a mailbox: alerts 56 → 43 (undetermined 25 → 35, clean 11 → 14).
- With a mailbox, 3,466 Nazario phishing and 2,122 top-header-trusted Nazario: unchanged.

## [2026-10-01 04:00 PT] — Add LinkedIn to the service registry

### Why
- Six LinkedIn messages in the 92-message genuine export were undetermined.

### Files changed
- `website/data/official_brands_intl.json` — LinkedIn as a `sender_only` service (`linkedin.com`), sourced from its help center "Phishing content" (read 2026-10-01).
  - It also records the "will never ask you for your password" statement and `phishing@linkedin.com`.
  - `messages-noreply@linkedin.com`, which carries member messages, is a relay address.
  - The review note records why AliExpress was left out.
- `website/tests/test_verified_official_sender.py`, `website/tests/test_review_2026_09_30.py` — a LinkedIn PIN is verified; member-message mail is a relay.
- `README.md`, `docs/evaluation.md` — 27 services and the measurement.

### Effect
- 92 genuine downloads: undetermined 15 → 11; alerts unchanged at 3.
- 11 Nazario phishing messages with LinkedIn in From: none verified, all still alert.

## [2026-10-01 03:00 PT] — Nudge readers toward an uploaded .eml with its mailbox chosen

### Why
- The same model and inputs on `7e9e904` and `19f6235`:
  - with the mailbox chosen, genuine false alerts fell from 50 to 3 of 92;
  - without it, they stayed at 56 of 92.
- The verified-sender, authenticated-sender and relay rules all need the mail service's own check, so most readers never got the improvement.

### Files changed
- `website/static/app-content.js`:
  - `detectMailboxService()` reads the topmost Authentication-Results authserv-id of an uploaded `.eml` (`mx.google.com` → Gmail, `mx.microsoft.com` → Outlook.com), byte by byte and never failing the upload.
  - A hint under "Downloaded from" suggests the choice with a "Use …" button but never makes it: a received `.eml` attachment can carry a forged top header.
  - The rerun and guide buttons are wired up.
- `website/static/app-content-render.js`:
  - `renderAccuracyTip()` shows "A more reliable result" for alerting or undetermined results.
  - For pasted text or screenshots it gives the upload advice and a button that opens the `.eml` guide.
  - For an `.eml` with a recognized service and no choice, it offers "Choose … and analyze again".
  - The input context is kept outside the API result, so reports are unchanged.
- `website/static/app.js` — the hint follows a language switch.
- `website/static/index.html`, `style.css` — the hint and a tip card outside the result area (hidden by default, so result screenshots are unchanged).
- `website/static/i18n.js`, `website/static/i18n-zh.js` — English and Chinese text. Asset versions were bumped.
- `website/static/app.test.mjs` covers:
  - the hint suggests without choosing, and not for another service;
  - the upload tip and guide for pasted text;
  - the rerun button sends `mailbox`;
  - no tip for a clean result.
- `README.md`, `docs/evaluation.md` — the before/after comparison and the guidance.

### Effect
- Guidance only; scoring is unchanged.
- Checked in a browser in English and Chinese: the upload hint for a Gmail-topped file, the upload tip with the guide button, and the rerun button.

## [2026-10-01 02:00 PT] — Fix six issues from an independent review

### Why
- An independent read-only review of `ec3d752` reproduced six issues with synthetic inputs. All reproduced on the then-current main:
  - S1: a CSS string `content:"/*"` hid the following hide rule;
  - S2: mutually exclusive `@media` views were never scored;
  - R1: PayPal invoice content was capped by the verified sender;
  - R2: `notifications@github.com` counted as GitHub's own mail;
  - R3: DMARC `header.from` could be read from a comment, a quoted reason or another clause;
  - R4: "GitHub" from `githubdocuments.com` relaxed address checks.

### Files changed
- `website/app.py`:
  - `_strip_css_comments()` is quote-aware and shared by both stylesheet scanners; an unclosed string is unmodelled.
  - `_stylesheet_hidden_targets()` returns the union of targets and one view per `@media` or other at-rule context (base hides, minus what the context shows, plus what it hides), up to eight contexts.
  - TextCollector elements carry the targets that can reach them; each context gets its own reading (`media_N`).
  - The model agreement check uses every reading except `hidden`.
  - Text rules move into `_text_rule_findings()` and run on the certainly visible text and on each context's view; the riskiest reading counts. Indicator order is unchanged.
  - The registered-service Low exception no longer applies when the main content is an uninspected remote image.
- `website/email_structure.py`:
  - `_dmarc_header_from()` reads `header.from` from the DMARC clause itself, after comments and quoted strings are removed. Several differing DMARC clauses give none.
  - `relay_addresses` (fnmatch patterns) and invoice, money-request and seller-dispute subjects mark relays.
  - `_claims_other_organization()` stops a display name that names another registered organization from matching.
- `website/data/official_brands_intl.json` — `relay_addresses` for GitHub (`notifications@github.com`), Google (Drive, Docs, Groups and Calendar sharing addresses) and Docusign (`dse*@docusign.net`), with a note.
- `website/tests/test_review_2026_09_30.py` — regression tests for all six. `website/tests/test_rendering_views.py` follows the new target structure.
- `README.md`, `docs/evaluation.md` — rules and measurement.

### Effect
- Every synthetic review input now alerts or stays undetermined instead of Safe or Low.
- Unchanged against main on:
  - 92 genuine downloads;
  - 87 public HTML templates;
  - 3,466 Nazario phishing messages;
  - the 2,122 Nazario messages with the top header trusted.

## [2026-10-01 01:00 PT] — Let text rules read the certainly visible text of uncertain HTML

### Why
- 125 of the 195 Nazario phishing messages that did not alert had HTML whose rendering the model could not resolve.
- In those, the text rules also saw an empty string for any CSS-uncertain part, so visible scams scored nothing.

### Files changed
- `website/app.py`:
  - The rendering-view pass also collects certainly visible text: outside elements a stylesheet or uncertain inline style may hide, with Outlook branches kept.
  - This text is available whenever every hiding rule's targets are known, even if the model's renderings stay unresolved.
  - Text rules score it for CSS-uncertain parts instead of an empty string.
- `website/tests/test_html_input_coverage.py` — four padding tests now assert the protected outcome instead of model abstention: an alert, an incomplete analysis, and no model score below the visible text's own.
- `README.md`, `docs/evaluation.md` — rule and measurement.

### Effect
- Nazario 2015–25 phishing without a mailbox: alerts 3,271 → 3,289, undetermined 186 → 168. No alert lost.
- Own genuine downloads (72) and 87 public HTML templates: unchanged.

## [2026-10-01 00:00 PT] — Add nine more service senders

### Why
- 18 of 72 genuine downloads were still undetermined, all from services outside the registry.

### Files changed
- `website/data/official_brands_intl.json` — `sender_only` entries, each with its sources:
  - from official pages: Vimeo (`vimeo.com`), Box (`box.com`), Reddit (`reddit.com`, `redditmail.com`, `redditforcommunity.com`), Pinterest (`pinterest.com`), Steam (`steampowered.com`), Zoom (`zoom.us`);
  - from the homepage or help center only: Notion (`notion.com`, `notion.so`), Netlify (`netlify.com`), Quora (`quora.com`).
  - Reddit and Quora "will never" statements read on their help centers.
  - A registry note records why Cloudflare and Adobe were left out: reported authenticated phishing through `notify.cloudflare.com`; no official Adobe sending-domain page, and widely abused share and sign notices.
- `website/email_structure.py` — the relay subject pattern also matches "inviting you" (Zoom meeting invitations).
- `website/tests/test_verified_official_sender.py` — a Zoom invitation is a relay; Reddit (`redditmail.com`) and Steam account mail are verified.
- `README.md`, `docs/evaluation.md` — 26 services, the exclusions and the measurement.

### Effect
- Own genuine downloads (72): undetermined 18 → 3, Safe or Low 53 → 68, alerts unchanged at 1.
- The three left are the Cloudflare and Adobe messages excluded on purpose.
- Nazario with the top header trusted: unchanged.
