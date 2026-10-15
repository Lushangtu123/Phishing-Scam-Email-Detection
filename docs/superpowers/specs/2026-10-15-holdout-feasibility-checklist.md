# Checklist: can the holdout meet D10 and D11?

**Purpose.** For the 2026-10-13 evaluation plan
([plan](2026-10-13-model-only-and-intent-rules-evaluation-plan.md)): decide, before the plan is
frozen, whether the fresh holdout can meet **both D10 and D11**. The check counts messages,
sources and families only.

- **No candidate outputs.** It never looks at what any candidate does with a holdout message:
  the options A/B/C, the intent rules, the model's scores, risk levels or rule findings.
- **Preparation only, approved 2026-10-15.** The plan is not frozen until D12 records a real,
  confirmed independent reviewer, and no holdout row is scored before then.

## Dates

- **2026-10-14 is the cut-off**, not an end date.
  - Only mail received after it counts as fresh.
  - The receipt date comes from the provider's own record (the topmost `Received` header, as
    `split_by_family.py` reads it), not from the `Date` header.
- **Collection continues** until the targets below are met.
- **Each feasibility check is dated.** Its counts are kept with the date and the split ledger's
  hash.

## Targets

| Target | Minimum | Countable before freezing? |
|---|---|---|
| **D10 provider cells** | At least **50 unique messages per class** (legitimate, phishing) in each of Gmail-English, Gmail-Chinese, Outlook-English and Outlook-Chinese: **at least 400** | Yes: provider, language and label |
| **D10 authenticated phishing** | At least **30** messages from at least **10** families | Yes: authentication comes from the headers, through the structure analysis at the frozen baseline commit |
| **D10 decisive subset** | At least **10** from at least **5** families: authenticated by a non-official domain *and* model-only under A | **Only its first half.** "Model-only under A" is a candidate output, known only by scoring. Before freezing, only "authenticated by a non-official domain" is counted, which is an upper bound |
| **D11 credential handover** (holdout phishing tagged by the owner) | English **40** from **15** families; Chinese **20** from **8** | Yes: owner's tags |
| **D11 payment redirection** | English **30** from **10** families; Chinese **15** from **6** | Yes: owner's tags |
| **D11 control types** (legitimate) | Each of the six types: password reset, code notice, supplier change by a known channel, payroll confirmation, unchanged invoice, quoted warning. English **20** from **10** organisations; Chinese **10** | Yes: owner's tags |

**Family rules (D11, enforced by `split_by_family.py`).**

- A family is never split between development and holdout.
- A family contributes at most **3** holdout messages, so each family minimum also needs at
  least a third as many holdout families as messages.

**Sources.**

- **Real downloads**, the only source for the D10 cells and for authenticated phishing:
  - the owner's Gmail and Outlook;
  - a dedicated test mailbox;
  - phishing the owner receives.
- **Public samples** form a separate "provenance unverified" cohort:
  - scored with no mailbox only;
  - never counted toward the D10 cells or the authenticated cohort;
  - downloaded only with the owner's approval.

## What may be counted, and how

1. **Holdout rows per cell, and families.** `split_by_family.py` already prints the holdout cells
   (provider, language, label), counts only. The ledger holds family membership as keyed hashes.
2. **Labels and behaviour tags.** These are the owner's labels and tags, kept beside the private
   rows. Only their counts per tag, language and family are read.
3. **Authentication.** Whether a holdout message is authenticated, and whether that domain is
   official:
   - comes from `analyze_raw_email` at the frozen baseline commit, with the recorded mailbox
     setting;
   - with any future DKIM self-verification **off**;
   - read from the structure fields only (`authenticated_sender`, `verified_official_sender`).

   This is not a candidate output, but it must use the frozen code.

**Not looked at:**

- anything `_analyze_content` returns for a holdout row: levels, scores, findings, the
  model-only note, option labels or intent-rule matches;
- message text, beyond what the owner's own labelling needs. Labelling and tagging are the
  owner's; the reviewer checks them later under D12.

## Decision points (recorded in writing before the first scoring)

1. **D10 and D11 both met.** With D12 recorded, the plan is frozen and the holdout is scored
   once for all 12 configurations.
2. **D10 met, D11 not.** The plan already allows splitting:
   - Part 1, the model-only options, is scored on this holdout.
   - Part 2, the intent rules, uses a **new cut-off and a separate holdout**.
   - The split is written into the plan before the first scoring, and every acceptance threshold
     stays as it is.
3. **D10 not met.** Collection continues. Nothing is scored on a partial holdout.
4. **D12 is not met while no real, confirmed independent reviewer is recorded.** Until then the
   plan is not frozen and no holdout row is scored, whatever the counts say.

## Feasibility report (counts only)

| Field | Content |
|---|---|
| Date, split ledger SHA-256, baseline commit | |
| D10 cells | 4 cells × 2 classes: unique holdout messages, families |
| Authenticated phishing | messages, families; of which by a non-official domain (upper bound for the decisive subset) |
| D11 behaviours | per behaviour and language: tagged holdout phishing, families |
| D11 control types | per type and language: tagged holdout legitimate, organisations |
| Shortfalls | each target not met, and by how much |
| Decision point reached | 1–4 above |

## Tooling gaps (not built; each needs its own approval)

A count-only tool that would produce this report from the split output and the owner's tag file:

- running only the structure analysis for authentication;
- printing no message text and no candidate output.

Until it exists, the report is filled from `split_by_family.py`'s counts and a count of the owner's
tag file.
