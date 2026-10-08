# Data, text model and benchmarks

## Data and evaluation scope

For the local public-corpus pilot, browser OCR/QR benchmarks, and reproducible
baseline comparison, see [the evaluation workflow](evaluation.md). These tools
include owned CI controls and explicit data/label limitations; public raw mail and
private screenshots stay outside Git and Vercel deployments.

### UCI website benchmark

The notebook uses the [UCI Phishing Websites dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites):
11,055 rows with 30 URL, domain, and HTML features. Historical results shown in
the UI are explicitly labeled as a **website benchmark**, not email accuracy.

### Email-text corpora

The optional content model can load:

| Local file | Source/type | Automatic download |
|---|---|---:|
| `Phishing_Email.csv` | Public phishing-email mirror | Yes |
| `CEAS_08.csv` | CEAS 2008 via Zenodo | Yes |
| `Nazario.csv` | Nazario corpus via Zenodo | Yes |
| `phishnchips_*.csv` | Modern synthetic benchmark data | Yes |
| `SpaPhish.csv` | Human-annotated Spanish email corpus via Mendeley Data | Yes, SHA-256 pinned |
| `phishfuzzer_{train,val,test}.csv` | Optional local three-class export | No |

Synthetic benchmark and template data can improve coverage but do not establish
real-world effectiveness. Report metrics only with the exact `data_source`,
`split_strategy`, threshold, and false-negative rate returned by the trained
pipeline. SpaPhish provides a dated cross-language slice, but it is not a Gmail
or Outlook inbox sample and 791 training rows lack dates. A future production
evaluation still needs a strictly dated, organization- and provider-
representative holdout.

### Observed email-text evaluation — 2026-09-19

The committed Logistic Regression artifact sampled 30,000 rows from the globally
deduplicated legacy and PhishNChips pool, reserved 6,000 group-isolated rows for
the original mixed-corpus test, and then added 1,008 SpaPhish training rows plus
1,044 unique grouped synthetic legitimate hard negatives. The hard negatives span 87
transactional, workplace, and personal-correspondence template families and are
added only after the original split; 37 normalized families already present in
reserved data were excluded. SpaPhish normalized families are assigned
to their latest dated partition: 2024 supplies 128 threshold-validation messages
and 2025 supplies 211 post-selection regression-slice messages. The published
CSV is pinned to SHA-256
`fdd74842d0a19fd4332bd91f90b0bcb06e045ceb2b599051b4598b65055a9cc5`.

| Metric | Result |
|---|---:|
| Training rows | 26,052 |
| Original mixed-corpus held-out rows | 6,000 |
| Original held-out accuracy | 98.80% |
| Original held-out precision | 98.13% |
| Original held-out phishing recall | 99.32% |
| Original held-out false-negative rate | 0.68% |
| Original held-out PR AUC | 0.9994 |
| Original held-out Brier score | 0.0095 |
| Training-fold F2 threshold | 0.4352 |
| Effective threshold after 2024 validation | 0.3736 |
| Train/test group overlap | 0 |
| 2024 validation phishing recall | 86.30% (95% CI 76.59%–92.39%) |
| 2024 validation false-positive rate | 14.55% (95% CI 7.56%–26.16%) |
| 2025 SpaPhish holdout rows | 211 (179 phishing / 32 legitimate) |
| 2025 holdout accuracy | 94.31% |
| 2025 holdout precision | 96.65% |
| 2025 holdout phishing recall | 96.65% (95% CI 92.88%–98.45%) |
| 2025 holdout false-negative rate | 3.35% |
| 2025 holdout false-positive rate | 18.75% (95% CI 8.89%–35.31%) |
| 2025 holdout PR AUC | 0.9942 |
| 2025 holdout family overlap | 0 |

The 2025 labels are not used for model selection or threshold tuning, but the
slice has now been repeatedly inspected and is described as a regression slice,
not a permanently untouched holdout. The temporal guarantee remains partial
because 791 SpaPhish training rows have no usable date. These are offline corpus
results, not Gmail/Outlook production claims. PhishNChips and the added hard
negatives are synthetic, provider-specific drift remains unmeasured, and
image-only lures, QR codes, and attachment contents remain outside this
evaluation. The committed artifact is identified by SHA-256
`a0a503a0cd6122e722933add91f49cc72e3fa74abaf1129c4df3fe0450401746`.
Its metrics include the build seed, cache-policy version, training options, and
SHA-256 digest of every local source corpus used for reproducibility checks.

The mixed-corpus rows above are in-distribution: test messages have training
neighbours from the same corpora. A leave-one-source-out run of the same training
recipe ([evaluation §4](evaluation.md#4-leave-one-source-out-model-evaluation))
finds much weaker transfer to unseen corpora, for example 10.6% recall on modern
synthetic phishing and a 96.5% false-positive rate on Spanish legitimate mail
when those corpora are excluded from training.

To measure the **current serving pipeline** on consented, labeled inbox mail,
use `website/tools/evaluate_serving_pipeline.py` with a local JSONL file kept
outside version control. Each line must provide `provider` (`gmail` or
`outlook`), `received_at` (`YYYY-MM-DD`), `label` (`phishing` or `legitimate`),
and either `eml_path` (an absolute path to a local original `.eml` file),
`raw_email` (Unicode text), or `subject`/`body`. Do not mix `eml_path` with text
fields. The `.eml` route preserves MIME bytes and uses the same 60,000-byte limit
as the upload API; keep the JSONL and referenced files outside version control.
An optional, manually verified
`language` field accepts a lowercase two- or three-letter code such as `en`,
`es`, or `zh`; omitted language is reported as `unlabeled`. Do not infer the
language from the model prediction. Run from the repository root with
the pinned Python 3.12 environment:

```bash
.venv/bin/python website/tools/evaluate_serving_pipeline.py --input /absolute/path/to/consented-mail.jsonl
```

Add `--attribution-output /absolute/private/path/attribution.json` to write a
separate, optional aggregate diagnostic. It counts fixed content-category and
link-rule IDs, sender/structure signals, model state and uninspected-image
coverage by human label and final decision. It writes no per-message rows,
matched terms, addresses, URLs or indicator prose. Counts indicate which signals
occurred together with a decision, **not** which signal caused it; the existing
scoring, thresholds and comparison policy are unchanged. Keep the diagnostic
beside the private input, outside version control. The public-corpus evaluator
supports the same option; compare its normal report as before.

Add `--counterfactual-output /absolute/private/path/counterfactual.json` to
either evaluator to replay baseline alerts with one evidence family or targeted
link rule removed at a time. The aggregate transitions show which removals
would change an alert to a nonalert or an undetermined result, alongside the
effect on detected phishing messages. The sidecar contains fixed family names
and counts, not individual messages; overlapping transitions cannot be added
together. See
[the evaluation procedure](evaluation.md#offline-counterfactual-alert-diagnostics).

Exact repeats are excluded from metrics by default (`--duplicate-policy drop`).
Use `--duplicate-policy error` to reject a cohort containing any exact duplicate.
Identity is based on effective message content within its input mode: original
bytes for `eml_path`, exact Unicode for `raw_email`, or the subject/body pair.
File paths, ignored fields, and row order are not identity. The same content
with conflicting labels, providers, received dates, or language labels is rejected
with row numbers; the evaluator does not silently pick one annotation.
This conservative policy requires resolving ambiguous repeated content before
comparing groups. It does not detect near-duplicate templates, campaigns, or the
same message supplied through different input modes, nor establish independence
from training data.

The `input_integrity` section reports input/evaluated/duplicate row counts,
the selected duplicate policy, and warnings for excluded repeats.
`dataset_sha256` uses the versioned `phishguard-evaluation-input-v1` scheme:
SHA-256 over a sorted multiset of record digests covering effective content,
input mode, label, provider, received date, and language (default `unlabeled`).
Repeated records remain in the input fingerprint even when excluded from metrics.
Reordering rows or moving an unchanged `.eml` does not change the digest; changing
its bytes or annotations does. Each `.eml` is read once per input row and the same
byte snapshot is hashed and analyzed. No paths, message content, or per-message
fingerprints appear in the report. The aggregate digest identifies data; it is
not an anonymization guarantee. Wilson intervals still require representative,
independent samples beyond this exact-duplicate check.

The evaluator uses the committed Vercel profile and ignores ambient application
environment variables. Authentication service IDs default to an empty trust list.
Only for mail whose receiving system's header-handling boundary has been verified,
add `--trusted-authserv-id mx.example` (repeat the flag for multiple IDs).
This makes the trust decision explicit; the flag does not authenticate the header.
External sender-history observation remains disabled.

The command loads the digest-verified committed artifact and uses the same
local analysis path as the API, with external sender-history observation
disabled. `eml_path` uses the byte-preserving message parser; `raw_email` uses
the legacy Unicode parser and cannot restore bytes lost during earlier decoding.
It prints aggregate counts and rates overall, by provider, by
language, by received month, by provider×language, and by provider×month;
message bodies and sender addresses are not included in the report. Medium,
High, and Critical are counted as alerts, while Unknown is undetermined and
remains in the phishing-recall denominator. Each group reports phishing and
legitimate denominators alongside two-sided Wilson 95% intervals for recall,
false-alert rate, unknown rate, complete rate, and model-available rate. A
label-specific rate and interval are null when that group has no examples of
the label. Small groups produce wide intervals, so avoid interpreting a point
estimate alone as provider or language performance.
The `reproducibility` section records the effective trust IDs and history policy,
Git commit and dirty state, source/registry digest, deployment-profile digest,
Python version, platform, and core inference/parser package versions. The source
digest includes local edits, so a dirty working tree is not represented solely by
its last commit. Git fields may be null in an exported source tree without Git.
This metadata describes the evaluation run, not the original training environment
or the configuration of a separately deployed service.
Keep the output local: a small provider×month or provider×language cell can
still disclose sensitive cohort information if published. The report marks
temporal isolation `not_verified`: dates alone do not prove training-family
separation. No real Gmail/Outlook cohort is committed or measured here, so the
offline table above must not be presented as provider-specific serving recall.
For a future independent cohort, obtain consent and labels before inspecting
model outputs. Keep a private campaign/family identifier and labeling record
outside the repository, exclude training-family overlap, and reserve a later
campaign-separated sample that is not used for threshold selection. Run this
tool only after that split is fixed; its Wilson intervals describe message
counts and do not correct for repeated messages within a campaign.

The included public Render profile still keeps the optional text model disabled
until a representative, versioned artifact is supplied through a trusted build
process. Rules and message-structure analysis remain available without it.


## Historical benchmark results

These values come from the UCI **website** notebook and are preserved for course
reproducibility only:

| Classifier | Accuracy | F1 | ROC AUC |
|---|---:|---:|---:|
| Random Forest | 0.9747 | 0.9746 | 0.9977 |
| SVM (RBF) | 0.9516 | 0.9515 | 0.9893 |
| Decision Tree | 0.9480 | 0.9480 | 0.9865 |
| Logistic Regression | 0.9285 | 0.9284 | 0.9808 |

Do not use these numbers to describe sender-address or full-email detection.
