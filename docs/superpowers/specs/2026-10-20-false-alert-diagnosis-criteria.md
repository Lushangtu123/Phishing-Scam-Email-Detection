# Criteria: step 1, diagnosing false alerts on development data

**Status: approved by the owner on 2026-10-20.** Drafted the same day at the owner's request and
revised after technical reviews.

- **What the approval covers:** these criteria. It is not an authorization to run.
- **Still separate decisions, none of them authorized yet:**
  - reading or extracting real mail;
  - the phase 1a measurement;
  - each public download.
- **Fixed before the first run.** A later change is a new, dated version of this file, with its
  reason.

## The question

On development mail, three things:

1. **Legitimate alerts.** Which removable evidence are the alerts on legitimate mail sensitive to?
   What does removing that evidence cost on phishing?
2. **Undetermined results.** Which signals co-occur with them? An undetermined result counts as
   analyst work, not as a correct non-alert.
3. **The next step.** Which one to propose: data for the model, a rule to review on fresh data, or
   nothing located yet.

## Not the question

- **No error rates.** This gives no false-alert or miss rate for real mail flow. The cohorts are
  small, partly public, and in places in the training data.
- **No changes.** Nothing here changes a rule, a weight, a threshold or the model. A change
  suggested by these counts gets its own criteria and fresh data.
- **No holdout.** No holdout mail, and no mail received after the 2026-10-14 cut-off.
- **No causes for undetermined results.** The counterfactual tool replays only alerted inputs
  (`counterfactual_evidence.py:259`). For undetermined results, only co-occurring signals are
  reported; their cause is not tested.

## Configuration (fixed once, before the first run, for the whole batch)

- **Pinned before the first run:** the full commit SHA, the model's SHA-256, and each cohort's
  input version (file SHA-256). Every cohort runs with the same commit and model. If either changes,
  every cohort reruns.
- **Tools:**
  - counterfactual families: `counterfactual-evidence/v2`, 12 families (the intent rules are off);
  - attribution: `evidence-attribution/v2`. Its code coverage must read `all_recognized`. If it
    does not, the batch stops, and the code list is extended under its own approval.
- **Evaluators.** `evaluate_serving_pipeline.py` for the owner's mail and `evaluate_public_corpus.py`
  for public corpora. Both run without RDAP, sender history, Jev or the local review (#78), and each
  report records the effective settings.
- **Model.** The committed artifact (`sha256:a0a503a0…`). Model-only option A, as served. Intent
  rules off, as served. `PYTHONHASHSEED=0`.
- **Network.** Every step that reads mail runs under the guard of `website/tests/network_guard.py`
  (`sitecustomize` with a log file): extracting P2's text, each evaluation, and both sidecars. A
  recorded attempt voids the step, and the attempt is reported.

## ARC and the mailbox setting

ARC verification still looks up Google's keys in DNS. This happens for a raw message with no
trusted result and no chosen mailbox. Evaluations of private mail make no live DNS lookups, and
offline ARC (design of 2026-10-20) is not implemented. So:

- **Phase 1a (this batch):** only inputs where ARC does not run:
  - the owner's `.eml` with the mailbox recorded, since a chosen mailbox skips ARC;
  - pasted text, which has no headers. Its text is extracted with ARC verification off (see P2).
- **Phase 1b (later):** `.eml` without a mailbox, private and public. It runs only after offline
  ARC passes its own criteria.
- **No ARC-off run in this batch.** Turning ARC off may change both the alert and the
  undetermined proportions, in a direction not measured. A verified seal can authenticate a
  sender, but its sealed results can also carry trusted authentication failures, so the effect is
  not one-way.

## Cohorts (development only)

Counts are **expected**. The report gives, for every cohort:

- the raw count;
- the count after deduplication;
- the exclusions, by reason;
- the successful analyses.

Labels come from the records already confirmed; none is inferred again.

**The owner's mail.** Consented, received before 2026-10-14, never marked holdout. Only counts leave
the owner's machine.

| Id | Cohort | Mode | Expected rows |
|---|---|---|---|
| P1 | The 92 genuine downloads of 2026-09-30 (Gmail and Outlook account and service notices, all legitimate) | `.eml`, mailbox recorded | 79 (13 are over the 60,000-byte `.eml` limit) |
| P2 | The same 92 | pasted: subject and visible text | 92 |

- **Comparing the two modes.** P2 is extracted from the same 92 originals as P1. Each mode is
  validated, deduplicated and filtered for exclusions on its own. The two are then paired by
  source message, and only the actual intersection is compared. The messages in P2 alone are
  reported separately, never pooled into the comparison. 79 pairs and 13 extra messages are the
  expected counts, not a certain result.
- **How P2's text is extracted:**
  - from the P1 originals;
  - with ARC verification off (`arc_result=None`), since extraction needs no authentication;
  - under the network guard.

  A subject over 500 characters or a body over 50,000 is **excluded and counted, never
  truncated**. A source file is read up to a fixed limit. Every row keeps its metadata, so a
  holdout marker cannot be lost in the conversion: label, provider, date and, where present,
  `cohort_role`. The existing `evaluate_local_review.pasted()` truncates silently and verifies ARC,
  so it cannot be used as it is. The needed change is a tool change, approved and tested before the
  batch.
- **Not this batch:** the development side of the 2026-10-13 split (P3).

**Public corpora.** Labels are upstream's, and some sources are in the training data. Licenses and
revisions are as in `docs/data-licenses.md`; use is personal and non-commercial. Each download
needs its own approval, naming the file, source and size.

| Id | Cohort | Label | Mode | Expected rows |
|---|---|---|---|---|
| L1 | PhishFuzzer recent seeds, `Valid` (on disk) | legitimate | pasted | 102 |
| L2 | UniqueData "not spam" | legitimate | pasted | 58 (57 after its exact duplicate) |
| L3 | Marketing-Emails held-out split (fully synthetic) | legitimate | pasted | 3,339 |
| L4 | Postmark transactional templates | legitimate | pasted | 10 |
| L5 | Apache list archives, 2025 (notifications, discussion, announcements) | legitimate | pasted | 1,770 |
| F1 | PhishFuzzer recent seeds, `Phishing` (on disk) | phishing | pasted | 103 |
| F2 | Nazario 2023–2025 | phishing | pasted | 1,303 |

**Left out:**

- **DataCon 2023 and trec06c:** their origin is not recorded.
- **phishing_pot and SpamAssassin easy_ham:** they are `.eml` without a mailbox, so phase 1b.
- **Anything received after 2026-10-14, and any holdout row.** The serving evaluator refuses
  holdout rows on its own, and a check before the run confirms that every `received_at` is before
  2026-10-14.

## What is counted (per cohort, counts only, always as n/N)

1. **Decisions:** alerted, not alerted and undetermined, out of all analysed inputs, with Wilson 95%
   intervals.
2. **Legitimate alerts under each family's removal:** how many become non-alerts, how many become
   undetermined, how many stay alerts.
3. **Phishing alerts under each family's removal (F1, F2):** both kinds of loss, reported
   separately: alert to non-alert, and alert to undetermined.
4. **Signals by decision and label:** from the attribution sidecar. They co-occur with a decision;
   they are not causes.
5. **Undetermined results:** their co-occurring signals, such as uninspected images, an unscored
   model or rendering warnings. Co-occurrence only.

Overlapping removals are not added together. An alert that several families each turn into a
non-alert counts under each of them.

**Failed replays.** The counterfactual tool counts a replay that raises as `analysis_failed`.

- **Kept apart.** Failures are reported separately. They are never merged into "undetermined" or
  into a successful removal, and never dropped.
- **The sum must hold.** For each family and label, the transitions plus the failures equal the
  baseline's alerts.
- **Failures block routing.** While a family has unresolved failures in a cohort, that family is
  not routed in that cohort.

**Undetermined signals.** Only the fixed signals the attribution tool already records are reported
for undetermined results. What they cannot tell apart stays unlocated.

## Exploratory routing lines (fixed now; routing only, never acceptance)

Every line is reported with its n/N.

| Line | Applies to | Meaning | Next step to propose |
|---|---|---|---|
| `outer_fusion_without_model_probability` turns ≥ 50% of the legitimate alerts into non-alerts | Legitimate cohorts with ≥ 20 alerts | These alerts are sensitive to the model's probability in the outermost fusion. It is not the model's whole contribution, and it does not show that more data is the only remedy | Targeted modern legitimate data for the model, as one option, under its own criteria |
| A rule family turns ≥ 30% of the legitimate alerts into non-alerts | Legitimate cohorts with ≥ 20 alerts | These alerts are sensitive to removing that family | Review that family on fresh data. Report next to it both kinds of phishing loss in F1 and F2 |
| No family reaches 30% | Legitimate cohorts with ≥ 20 alerts | **No main removal path located yet.** It may come from differences within the cohort, from redundant evidence, or from coverage gaps. It does not show that several kinds of evidence jointly support the alerts | Report it as unlocated. No tool extension in this batch |
| Undetermined results are ≥ 20% of **all inputs** of the cohort | Every cohort, whatever its number of alerts | Analyst work concentrates there | Name the main co-occurring signals as the area to look at next (images, rendering, unscored text). The cause is not tested |

- **Below 20 alerts,** the removal counts of a legitimate cohort are reported and not routed. Its
  undetermined line still applies.
- **Undetermined is not resolved.** An alert that a removal turns into an undetermined result is
  not resolved by it; those are reported apart.
- **Nothing is changed on this data.** A rule or model change proposed from these counts needs
  fresh data and its own criteria. If it lands before the 2026-10-13 plan is frozen, it becomes
  part of that plan's baseline or candidates, as that plan says.

## Privacy and handling

- **Where private outputs live.** Reports and sidecars for the owner's mail stay beside the private
  data, outside the repository.
- **What leaves the machine.** Chat, the archive summaries and `docs/evaluation.md` get counts only.
  No message text, address, subject or per-message result.
- **Per-message rows.** None are written anywhere. Both sidecars are aggregate by design.
- **Public corpora.** Downloaded only with approval, to the git-ignored `.evaluation-data/`, at the
  pinned revisions.

## Reporting

- **Layout.** One table per cohort, with private and public, and pasted and `.eml`, kept apart.
  Each states its mailbox setting, ARC handling and n/N. Cohorts under 30 rows are flagged.
- **The P1/P2 comparison** uses the actual pairs only. The pasted-only messages are listed apart.
- **Results against these criteria,** including every routing line not reached and every
  unlocated case.
- **Archive.** The criteria copy, the pinned configuration, the commands, the cohort digests, the
  network logs and the outputs, in a new archive folder.

## Order

1. The owner approves these criteria.
2. **The P2 extraction change** (no ARC, no truncation, counted exclusions), with tests, approved
   separately. Then the configuration is pinned.
3. Each public download is approved separately: L2–L5 and F2.
4. Phase 1a runs, and is reported against these criteria.
5. Phase 1b waits for offline ARC.

## Positions taken in this revision (following the review of 2026-10-20)

| Question | Position |
|---|---|
| Routing lines | 50%, 30% and 20%, and 20 alerts, kept as exploratory lines, always with n/N; read as above |
| P3 | Not in this batch |
| ARC | Phase 1a now, phase 1b after offline ARC; no ARC-off run |
| Counting how many families each turn an alert into a non-alert (0, 1, 2 or more) | Not added. The families overlap, so such a count says how many single removals clear an alert, not how many independent pieces of evidence there are. Unlocated cases are reported as such |
