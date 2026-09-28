# Reproducible evaluation for a personal project

## Reviewed user feedback draft

Contradictory review reasons and verdicts are excluded from draft export and
counted as `inconsistent_review`. The private cohort builder applies the same
rule to older drafts: false alert requires legitimate, missed threat requires
phishing, and insufficient evidence requires uncertain. Resolve the original
human review and regenerate the draft before evaluation; labels are never
silently corrected by these tools.

The workspace feedback overview summarizes retained report reviews. It is not an
evaluation cohort: duplicate reports may be counted, reporting is self-selected,
and there is no denominator of all analyzed messages. Do not present those counts
as model-wide false-positive or false-negative rates.

Each public report dialog owns its pending request and retry key. Closing or
replacing a dialog invalidates work still preparing the request; a response from
an older dialog cannot change a new report. Once a request has been sent,
closing the dialog cannot undo server retention. Retrying an unchanged report
in the same dialog reuses the exact payload and key. Keep the dialog open after
a network error to retry safely; reopening starts a separate report.

The public **Report an issue** flow now has a separate, optional consent for
private evaluation of retained content or original EML. Only a report with both
source-retention and evaluation consent, a closed analyst review with structured
reason and evidence basis, and a human `phishing` or `legitimate` verdict can
enter a curation draft. Older reports,
source-free reports, images, sender-only reports, legacy unstructured reviews,
reporter-only evidence, open reviews and uncertain verdicts are excluded.
Reports with the same retained message and conflicting human labels are excluded
together; matching duplicates count once. Each exported row preserves the union
of all eligible duplicates' `case_reviewer_ids` and their `source_case_ids`.
An analyst who reviewed any of those duplicates cannot be the independent
reviewer. Regenerate older drafts from the private archive before using this check.

New feedback uses `source_schema: 2`: a missing subject stays empty in the
retained message, while the queue receives a separate report title. Exported
rows preserve this marker. Older records with subjects exactly matching generated
titles such as `User feedback · false_positive` are ambiguous: the title may
have been injected by the old handler, or may genuinely belong to the email.
The exporter excludes them and counts `ambiguous_legacy_subject`; the cohort
builder also rejects such rows in existing drafts without schema 2. Verify the
original email and re-submit/review it through the corrected flow before evaluation.
Do not simply strip the title or add the schema marker to an old draft. Other
legacy messages remain eligible under the existing consent and review checks.

First make and verify a private archive using the commands in
[case-workflow.md](case-workflow.md#storage-limits-and-responsibility), then run:

```sh
.venv/bin/python website/tools/export_reviewed_feedback.py \
  --archive /absolute/private/path/cases-archive.json \
  --output /absolute/private/path/reviewed-feedback-draft.jsonl
```

The draft is an owner-only local file outside Git. It contains original message
text or base64-encoded EML bytes, a human verdict, timestamps, the reported
risk and model ID; it omits analyst notes. Treat it as sensitive. It is **not yet an evaluation
cohort**: user reports are selected by perceived errors, provider and email
arrival date are unknown, the analyst verdict still needs independent label
review, and training/campaign overlap has not been checked. A separate local
cohort builder accepts a second reviewer's annotations and enforces that their
ID differs from every analyst who reviewed that case. It also checks dates,
provider, language, message fingerprints and family separation across
development and holdout inputs. The identities and labels are self-attested;
the tool cannot prove independence, consent or training-set isolation.

Create a private owner-only annotations JSONL outside Git. Each selected draft
record needs one line like this, with independently verified values:

```json
{"id":"00000000-0000-4000-8000-000000000001","label":"legitimate","provider":"gmail","received_at":"2026-09-21","language":"en","family_id":"campaign-1","cohort_role":"holdout","independent_reviewer":"reviewer-b"}
```

Then run:

```sh
.venv/bin/python website/tools/build_private_cohort.py \
  --draft /absolute/private/path/reviewed-feedback-draft.jsonl \
  --annotations /absolute/private/path/annotations.jsonl \
  --output-dir /absolute/private/path/cohort
.venv/bin/python website/tools/evaluate_serving_pipeline.py \
  --input /absolute/private/path/cohort/holdout.jsonl
```

The builder writes new owner-only `development.jsonl`, `holdout.jsonl`, EML
files and a lineage record. Annotations may select a subset of the draft, but
one family cannot be split across roles; conflicting independent labels stop
the build for manual resolution. `received_at` must come from verified provider
or organization evidence, not an untrusted mail `Date` header. Keep the
holdout untouched while developing rules and review training overlap before
claiming independent performance. Never copy private inputs into public fixtures.

The first goal is to measure changes honestly with a small, repeatable local
workflow. These tools do not certify enterprise readiness, train a new model,
change production thresholds, or require a paid service. Start with owned controls,
then public research data, then consented and independently labeled inbox samples.

## 1. Public email research pilot

Use the existing Python 3.12 environment and committed model. From the repository
root, explicitly download a seeded, fixed-version pilot:

```sh
.venv/bin/python website/tools/prepare_public_pilot.py --output .evaluation-data/public-pilot --count 100 --seed 42
.venv/bin/python website/tools/evaluate_public_corpus.py --manifest .evaluation-data/public-pilot/manifest.json --output .evaluation-data/public-pilot/report.json
```

The downloader preserves existing directories, checks the SpamAssassin archive
SHA-256 and each Git blob, never executes email content or follows its links, and
writes original EML bytes to a gitignored, deployment-excluded directory. Only this
preparation command needs network access. Evaluation uses the committed Vercel
profile with history, external verification, cases and trusted-authserver overrides
disabled, ignoring ambient app configuration.

The initial pilot uses 100 [phishing_pot](https://github.com/rf-peixoto/phishing_pot)
messages at commit `49f63777126b0bdb9eb1f6e770a5c3f9df2b0306` and 100 historical
[SpamAssassin easy_ham](https://spamassassin.apache.org/old/publiccorpus/readme.html)
messages. The former has a CC-BY-NC-4.0 license and repository collection labels,
which can include scam/spam and need human review. The latter retains sender
copyright and is a historical research corpus. Keep raw messages local; these
sources are not a commercial redistribution package. Size eligibility is at most
60,000 bytes per EML, excluding 1,025 phishing repository messages and 2 easy_ham
messages in the pinned inventories. Sampling is balanced and seeded; it does not
represent production prevalence. Do not interpret precision on this pilot as inbox
precision.

### Bring another corpus

Create a manifest with `schema_version: 1`, a relative `records` JSONL path,
`exploratory_only: true`, and `sources`. Each source requires `id`, `url`, a fixed
`revision`, `license`, and `label_basis`. Each JSONL row requires `id`, `source_id`,
`label` (`phishing` or `legitimate`) and either a relative `eml_path` or `subject`
and `body`. `content_sha256` can verify raw EML bytes or canonical subject/body JSON.
Provider, language and `received_at` are optional. Unknown values remain unknown;
provider is not guessed from sender addresses and arrival time is not guessed from
an untrusted Date header. Do not put private data in source metadata or record IDs.

The evaluator snapshots bounded files and validates the full cohort before
analysis. Exact duplicates are excluded, conflicting labels fail, and normalized
text templates are reported. An optional `--reference-manifest PATH` uses the same
format to exclude exact and heuristic template overlap with supplied reference
records. A clean comparison does **not** prove that the full model training corpus
is independent: its original files are not available in this checkout. There is no
claim of temporal isolation. Retain these qualifiers when publishing results.

Aggregate reports include recall, false-alert rate, undetermined rate, complete
analysis and model availability, 95% Wilson intervals, source/language/provider/month
groups, explicit exclusions and failures, actual included-cohort hashes, scoring
hashes, code/model hashes and package versions. Inference failures remain in the
undetermined denominator and cause a nonzero exit. An empty post-filter cohort also
fails. Reports omit original email text and file paths.

For a separate, non-causal signal breakdown, add
`--attribution-output /absolute/private/path/attribution.json` to either
evaluator. The sidecar is tied to the main report's evaluated-cohort and model
digests. It counts one occurrence per message for each allowlisted content
category, link rule ID, sender/structure signal, model/fusion state, and image
coverage within the label × decision groups. Unknown rule IDs are grouped as
`unrecognized`; no raw indicator messages, matched words, addresses, URLs or
per-message rows are copied. A diagnostic count is an association, not a
counterfactual contribution to the final verdict. Do not tune weights on an
inspected development set or use this sidecar as a release gate.

Keep the stricter existing `evaluate_serving_pipeline.py` for consented Gmail and
Outlook data with known provider and arrival date. Public corpus labels must not be
passed off as provider-specific real-world testing.

### Displayed-link rule regression, 2026-09-27

The public samples were inspected to diagnose false alerts, so subsequent results
on them are development regressions, not an untouched holdout. Before comparison,
decoded message views were conservatively checked against 63,054 rows from the
seven public training-source files, verified against artifact provenance hashes.
One easy_ham and three hard_ham messages matched normalized families/templates
and were excluded. This heuristic check does not establish complete training or
campaign independence.

Against baseline `d7fac9359fbcbe55785ef0891412ad4fe926ce2c`, the address-label fix
keeps the committed model and threshold unchanged. The same original EML bytes
produce the following results; Medium, High and Critical all count as alerts:

| Cohort | Baseline | Updated |
| --- | --- | --- |
| 100 phishing_pot messages | 90 alerts, 3 nonalerts, 7 undetermined | 90 alerts, 3 nonalerts, 7 undetermined |
| 99 easy_ham messages | 3 alerts, 96 nonalerts | 3 alerts, 96 nonalerts |
| 244 hard_ham messages | 207 alerts, 36 nonalerts, 1 undetermined | 206 alerts, 36 nonalerts, 2 undetermined |

The additional corpus is [SpamAssassin hard_ham](https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2),
archive SHA-256 `ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9`.
Three of its 250 messages exceed the 60,000-byte contract, leaving 247 before the
three reference exclusions. All 443 evaluated messages have zero inference
failures. The hard_ham false-alert rate changes from 84.84% to 84.43%, with 95%
Wilson intervals of 79.80–88.79% and 79.35–88.44%. One alert became undetermined;
it did not become a verified legitimate result. False alerts remain excessive.
The easy_ham rate remains 3.03% and phishing alert recall remains 90%.

The dual-class pilot passes the existing comparison policy. The hard_ham cohort
has no phishing class and increases its undetermined count, so it cannot satisfy
that policy as release evidence. Do not lower the comparison gate or claim an
overall accuracy improvement from this change. Representative, independently
reviewed development and holdout mail is still needed before changing sender
weights or the model threshold.

### Sender syntax regression, 2026-09-27

Baseline `f0f6756f4af9af7c75657e2a7712a8460f3c4dbe` accepted unquoted
mailboxes containing ordinary atom punctuation at the API and From-parser
boundaries, but two narrower scoring checks then marked them as suspicious or
invalid. Paired replay found these incorrect syntax flags in 86 hard_ham
senders and one easy_ham sender. Reusing the existing character contract and
mailbox normalizer removes those flags without changing input admission,
sender weights, the committed model or its decision threshold. Malformed dot
atoms still fail validation; brand substitution and dangerous-link controls
remain active.

The same 443 reference-filtered original messages described above were rerun.
They remain inspected development data with the same label, historical-period,
overlap and independence limitations; they are not an untouched holdout.
Medium, High and Critical still count as alerts:

| Cohort | Baseline | Updated |
| --- | --- | --- |
| 100 phishing_pot messages | 90 alerts, 3 nonalerts, 7 undetermined | 90 alerts, 3 nonalerts, 7 undetermined |
| 99 easy_ham messages | 3 alerts, 96 nonalerts | 2 alerts, 97 nonalerts |
| 244 hard_ham messages | 206 alerts, 36 nonalerts, 2 undetermined | 136 alerts, 44 nonalerts, 64 undetermined |

Of the 70 fewer hard_ham alerts, only eight become nonalerts; the other 62
become undetermined under the existing incomplete-content contract. Removing an
incorrect sender signal exposes that uncertainty rather than establishing that
those messages are safe. The hard_ham false-alert rate changes from 84.43% to
55.74% (updated 95% Wilson interval 49.46–61.83%), while its undetermined rate
increases from 0.82% to 26.23% (21.11–32.09%). False alerts and incomplete
analysis remain substantial. Complete-analysis and model-availability rates
are unchanged, and all 443 evaluations have zero inference failures.

Easy_ham false alerts change from 3.03% to 2.02% (0.56–7.07%); phishing alert
recall remains 90% (82.56–94.48%). Paired replay finds no new phishing nonalert
or undetermined result in this cohort. Synthetic controls and the dual-class
pilot pass the unchanged comparison policy. The single-class hard_ham
comparison fails both its two-class requirement and its no-increase-in-unknown
requirement. Preserve that failure; these results do not qualify as real-mail
release acceptance or an overall accuracy improvement. This patch corrects the
documented mailbox-syntax contradiction. It does not justify tuning risk
weights or thresholds on these inspected samples.

### Negative-contraction phrase regression, 2026-09-27

Against baseline `b790e0b6fac1dc324f0ef104d3b5fb925a915db7`, the phrase
matcher incorrectly treated the apostrophe in `You won't` as the end of
`You won`. Ten reference-filtered hard_ham messages had only negative
contractions behind this particular financial-lure match. A suffix guard for
straight and curly apostrophes removes those ten matches. Genuine winning
phrases, quoted phrases, possessives, later independent matches and dangerous
link controls retain their detection. This corrects a phrase boundary; it does
not implement general linguistic negation or change risk weights or the model.

Matched whole-pipeline replay of the same 443 development messages gives:

| Cohort | Baseline | Updated |
| --- | --- | --- |
| 100 phishing_pot messages | 90 alerts, 3 nonalerts, 7 undetermined | 90 alerts, 3 nonalerts, 7 undetermined |
| 99 easy_ham messages | 2 alerts, 97 nonalerts | 2 alerts, 97 nonalerts |
| 244 hard_ham messages | 136 alerts, 44 nonalerts, 64 undetermined | 135 alerts, 44 nonalerts, 65 undetermined |

One hard_ham alert becomes undetermined and one Critical verdict becomes High;
the nonalert count does not increase. The false-alert rate changes from 55.74%
to 55.33% (updated 95% Wilson interval 49.06–61.44%), and the undetermined
rate rises from 26.23% to 26.64% (21.49–32.52%). Complete-analysis and
model-availability rates are unchanged, and all 443 evaluations have zero
inference failures. The synthetic and dual-class pilot comparisons pass.
The hard_ham comparison still fails its two-class requirement and its
no-increase-in-unknown requirement. Preserve that failure and all preceding
label, historical-period, inspection and independence limitations. Removing a
misleading keyword signal does not establish an overall accuracy improvement
or real-mail release acceptance.

### Offline signal attribution (2026-09-27)

The optional sidecar was run on the same 244 reference-filtered historical
`hard_ham` messages. Its evaluated count and cohort digest match the ordinary
report. Of 135 alerted legitimate messages, 30 also had the
`link.brand_lookalike` signal and 20 had `link.display_mismatch`; these groups
may overlap. The 65 undetermined messages all had uninspected remote-image
coverage. These are diagnostic co-occurrences, not verified rule errors or
current-mail performance. The paired 199-message phishing/easy-ham pilot passed
the unchanged two-class comparison with identical recall, false-alert and
undetermined rates; the hard-ham-only comparison still cannot pass that release
policy. No risk weights or model threshold were changed.

### Apple Core newsletter link correction (2026-09-27)

Inspection of those 30 `link.brand_lookalike` alerts found the Apple Core
newsletter host `applecore.lockergnome.com` in each affected message. A complete
`applecore` host label now follows the existing benign-word exception for
Apple-containing names, while compound login lures such as
`applecore-login.example` remain flagged. Replaying the same 244 `hard_ham`
messages removes the brand-lookalike signal from their attribution but leaves
the final 135 alerts, 44 nonalerts and 65 undetermined decisions unchanged;
other evidence still determines those verdicts. The paired 199-message
phishing/easy-ham pilot also remains at 90/100 phishing alerts, 2/99 legitimate
alerts and 7/100 phishing undetermined. This is an explanation correction, not
evidence of improved population accuracy.

## 2. Browser OCR and QR controls

```sh
python3 website/tools/vision-benchmark/serve.py --port 8930
```

Open `http://127.0.0.1:8930/`, select the supplied
`website/tools/vision-benchmark/synthetic-manifest.json` and five PNGs from
`website/tests/fixtures/vision/`, then run and download the report. This calls the
same browser worker as the website. It measures exact QR payloads, strict OCR
character error rate, exact OCR URL spelling, unexpected Han characters on English
images, extraction status and timing. It validates original image hashes and keeps
missing, cancelled or failed inputs in the denominator. No screenshot goes to a
cloud service. See [harness instructions](../website/tools/vision-benchmark/README.md)
for your own annotated datasets and optional local risk assessment.

Five synthetic controls establish that the workflow functions; they cannot estimate
real screenshot accuracy. Expand with independently transcribed, authorized images,
including mixed language, scaled/compressed text, multiple QR codes and difficult
negatives. Record languages and exact URLs before running OCR. Do not use the
recognizer's own output as ground truth. Public QR datasets whose URL mappings or
rights have not been verified are not bundled. Target 30 or more independently
labeled screenshots and 30 QR images in the next evidence-collection stage.

### Optional RapidOCR pilot (2026-09-27)

The separately installed `rapidocr-onnxruntime==1.4.4`/PP-OCRv4 service was
run on the **same five synthetic controls**, with the same manifest SHA-256
`c29a546fdc22d9839e8173e3e4d887b39d89fbab5eb1b0f4924fe4c5dc7705d8`.
The existing browser Tesseract report had 1/3 exact visible-URL sets and
23/238 character edits (CER 9.66%); RapidOCR had 2/3 and 4/238 (CER 1.68%).
Both processed 5/5 images. The proposed 10-percentage-point URL gate passed
on this tiny set, but `adoption_ready` remains false. No QR or risk result is
claimed for the additional OCR service. The comparison uses exact manifest
hashes and scores all records, including failures. See the
[reproduction commands](../website/tools/vision-benchmark/README.md#compare-optional-local-ocr).

As a separate out-of-domain diagnostic, both engines were run against the
previously pinned 30-image SROIE test sample: the same manifest SHA-256
`cc77ec0e08a890c14bd54d36f182a8411451dce73568b20dcf70d1d50f396e6f`
and strict case/punctuation-preserving token-multiset scoring. Each completed
27/30 images. Browser Tesseract matched 1535/3587 reference tokens (F1 0.420);
RapidOCR matched 1060/3587 (F1 0.363). RapidOCR therefore did **not** improve
this broader text diagnostic. Receipts are not email screenshots; token order
is ignored and neither test estimates phishing detection accuracy. Keep the
existing browser OCR as the default until a representative, independently
annotated screenshot holdout establishes a consistent URL gain without
coverage, false-alert or resource regressions.

The three images both engines failed were 4,961 × 7,016 pixels and exceeded
the product's 2 MiB and 4,096-pixel-side input limits. They remain in the
denominator as coverage failures. The
[local holdout preparation tool](../website/tools/vision-benchmark/README.md#prepare-a-reviewed-email-screenshot-holdout)
supports human-reviewed email screenshots with unchanged original-image hashes;
it does not create ground truth or turn these receipts into an adoption test.

Optional risk assessment reports unavailable and undetermined outputs explicitly.
The external local backend's configuration/model identity is not attested by the
harness. Record how that backend was started; extraction-only reports are the
reproducible default. Browser evidence remains unverified and does not become
trusted simply because a benchmark was run. OCR language is now recorded per
observation rather than always displaying the mixed-language engine label.

## 3. Compare a baseline before release

```sh
.venv/bin/python website/tools/compare_evaluations.py --baseline baseline.json --candidate candidate.json --output comparison.json
```

The gate requires the same input, included cohort, ground truth, overlap policy and
scoring implementation. Detector/model or extraction implementation may change.
It rejects missing/nonfinite metrics, changed denominators and inference/extraction
failures, and checks per-group as well as overall changes. Recall, coverage and QR/
URL matches must not decrease; false alerts, unknown rate and CER must not increase.
Existing partial visual extractions are retained, but their count cannot increase.
Timing is diagnostic because browser cache and machine load vary; it is not a gate.
No tolerance is silently applied. A scorer or annotation correction needs a newly
reviewed baseline; do not overwrite a baseline just to make a failing change pass.

### Consented Gmail/Outlook comparisons

Private `local_serving_pipeline` reports now use `schema_version: 1`. Generate both
reports with the updated evaluator, using the same authorized JSONL and explicit
trusted authentication service IDs, before and after a detector/model change:

```sh
.venv/bin/python website/tools/evaluate_serving_pipeline.py --input /absolute/private/cohort.jsonl > /absolute/private/baseline.json
# After the intended detector/model update, evaluate the same input and options.
.venv/bin/python website/tools/evaluate_serving_pipeline.py --input /absolute/private/cohort.jsonl > /absolute/private/candidate.json
.venv/bin/python website/tools/compare_evaluations.py --baseline /absolute/private/baseline.json --candidate /absolute/private/candidate.json --output /absolute/private/comparison.json
```

The private gate requires identical input and included-cohort hashes, labels and
group metadata, scorer identity, duplicate/inclusion policy, and explicit analyzer
configuration. It validates record accounting and each provider, language and month
group, including all observed pair and three-way intersections. Both email classes
must be present overall; single-class subgroups still receive applicable checks.
It compares exact alert, undetermined, complete-analysis and model-availability
counts, so one extra miss or false alert cannot disappear in four-decimal displayed
rates. Intersection counts must also reconcile with all marginal and overall totals.
Code/model identities may change; settings and scoring definitions may not.

The CLI disables network verification, sender history and auxiliary AI, and records
the effective local model/trust settings. Programmatic `evaluate_records` callers
must declare the matching bounded `configuration` to produce comparable reports;
an omitted configuration remains `null` and the gate rejects it. Reports from the
older unversioned evaluator must be regenerated on both versions; adding a version
field by hand cannot recover missing exact counts and identities. Preserve prior
reports as historical evidence, and never fabricate a pre-update baseline. The
comparator rejects an output path that would overwrite either input report or the
release review, including existing symlink or hardlink aliases.

Reports contain aggregate counts and hashes, not message text or original paths.
Keep them private: small intersection groups and dates can still reveal cohort
membership information. Dataset hashes establish reproducibility, not permission,
label quality, training independence or a representative production sample. An
analysis exception aborts report generation instead of silently dropping a row.

### Opt-in independent holdout release review

The ordinary comparator is a regression check. To opt into the release review
contract, use the private evaluator's reports and an independently prepared local
review file:

```sh
.venv/bin/python website/tools/compare_evaluations.py \
  --baseline /absolute/private/baseline.json \
  --candidate /absolute/private/candidate.json \
  --release-review /absolute/private/release-review.json \
  --output /absolute/private/release-comparison.json
```

This retains every exact-count no-regression check above. In addition, every
Gmail/Outlook × English (`en`)/Chinese (`zh`) intersection must have at least 50
unique phishing messages and 50 unique legitimate messages: at least 400 messages
overall. `minimum_per_class_per_provider_language` is an explicit coverage policy;
the reviewer can set it higher, but not below 50. This is a coverage floor, **not**
a statistically adequate sample, target accuracy, or proof of production readiness.
Explicit additional languages, including `mul` for mixed language, may be included
and retain the same regression checks; unlabeled languages do not qualify.

The `release-review.json` object requires these fields:

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1` |
| `dataset_sha256`, `evaluated_cohort_sha256` | Exact matching hashes from both private reports' `input_integrity` |
| `baseline`, `candidate` | Each is an object with the report's exact `model_artifact_sha256` and `reproducibility.source_sha256` as `source_sha256` |
| `minimum_per_class_per_provider_language` | Integer ≥ 50, chosen before comparison |
| `cohort_preparer`, `independent_reviewer` | Distinct pseudonymous IDs, 1–80 ASCII letters, digits, dots, underscores or hyphens |
| `training_cutoff` | Verified last date of training/tuning data, strictly before the earliest cohort arrival |
| `cohort_frozen_at` | Date on/after the latest cohort arrival and on/before candidate development started |
| `candidate_development_started_at` | Date on/before `reviewed_at` |
| `reviewed_at` | Calendar date the human audit was completed |
| `evidence_reference` | Nonempty private audit reference, at most 2,000 characters |
| `attestations` | Object containing each declaration listed below with literal boolean `true` |

All dates use `YYYY-MM-DD`. The required attestations are
`real_consented_mail`, `all_labels_independently_reviewed`,
`provider_language_and_received_dates_verified`,
`families_separated_from_development`, `excluded_from_training_and_tuning`, and
`holdout_untouched_before_this_comparison`. The reviewer must audit every included
row, its label/provider/language/date evidence, authorized use, training and tuning
lineage, family separation and holdout access history. The existing private cohort
builder's annotations and lineage can support this audit; they alone cannot prove
full training independence. The independent reviewer must be separate from the
original case analysts and candidate developers, as well as the cohort preparer;
the tool checks only the declared preparer/reviewer IDs.

These are **human attestations**, not machine verification. The tool does not open
the evidence reference or inspect training mail, and even false declarations can
be structurally valid. If complete training lineage or a pre-development untouched
holdout is unavailable, do not fill those fields with guesses: a release review
cannot be established yet. Repeated tuning on a holdout invalidates its use for
the next candidate; create another untouched set. Missing/malformed review JSON,
small/missing cells, mismatched identities and regressions produce a nonzero exit.
Successful comparison does not deploy anything or authorize release.

No real independently reviewed English/Chinese holdout is bundled with this
repository, so this change establishes gating infrastructure, not a new accuracy
result or a passing release review. Keep the review, raw inputs and private
aggregate reports outside Git. Never replace the existing synthetic baseline with
private mail or fabricated labels to make a gate pass.

The Vercel-runtime CI job smoke-tests four project-owned email controls with the
committed model and compares against `website/tests/fixtures/evaluation/baseline.json`.
Unit tests include deliberately worse, missing, changed and failed results to prove
that the gate rejects them. CI tests the opt-in release contract with synthetic
data; it does not claim a real release gate pass. CI never downloads public mail
or private screenshots.
The [real-browser integration runner](../website/tools/browser-checks/README.md)
automates synthetic OCR/QR, upload, cancellation and case-save checks with Chromium.
Its reports distinguish integration success from literal OCR/URL mismatches;
neither its regression ceilings nor Node metric tests establish OCR accuracy on
real screenshots. The existing manual benchmark remains available for separately
reviewed authorized inputs.

A green gate means no measured regression on that fixed cohort. It is not a claim
of statistical significance or acceptable enterprise accuracy. Review the actual
false alerts and misses before tuning, retain a separate future holdout set, and
keep a changelog explaining model/rule changes. This project currently prioritizes
making errors visible over displaying an unsupported accuracy percentage.

## Initial local findings (2026-09-21)

On the 200-message unreviewed public pilot, medium/high/critical count as alerts:

| Measure | Result |
| --- | --- |
| Upstream phishing messages alerted | 89/100; 89%, Wilson 95% interval 81.37–93.75% |
| Upstream legitimate messages alerted | 28/100; 28%, interval 20.14–37.49% |
| Undetermined | 7/200; 3.5% |
| Analysis complete | 94/200; 47% |
| Content model available | 185/200; 92.5% |
| Inference exceptions / duplicate exclusions | 0 / 0 |

These figures expose substantial false-alert work; they are not enterprise or
Gmail/Outlook performance estimates. Size filtering, historical normal mail,
unreviewed upstream labels and unverified training overlap limit interpretation.
The model and detection thresholds were not tuned on this pilot. The first useful
follow-up is manual error categorization with a separate held-out sample, not a
threshold change chosen solely to improve these 200 results.

## Follow-up routing policy findings (2026-09-21, historical experiment)

Error inspection found all 28 initial normal-mail alerts were medium, with the
content model predicting legitimate. Reply-To and Return-Path domain differences
were being added as independent impersonation evidence. The candidate keeps each
routing observation but applies one combined two-point weak concern. Claimed list
headers do not confer trust. Trusted authentication failures, brand impersonation,
dangerous attachments and malicious-link evidence retain their independent rules.

Also, a low-scoring message dominated by an uninspected remote image now remains
unknown, preserving strong alerts. The previous logic could display low risk based
on a few routing points despite having very little inspected content.

| Cohort | Normal-mail alerts before → after | Phishing alerts before → after | Unknown before → after |
| --- | --- | --- | --- |
| Original pilot, 200 messages | 28/100 → 3/100 | 89/100 → 89/100 | 7 → 8 |
| Follow-up, 194 messages | 24/96 → 9/96 | 83/98 → 82/98 | 10 → 11 |

The follow-up uses seed 20260921 from the same pinned sources. Five exact and one
normalized-template matches against the first pilot were excluded before inference.
Both versions used the same committed model and settings, with zero inference
exceptions. The original-parser baseline was captured before the incomplete-image
change; component identity and settings are recorded in the local controlled
validation report. This is additional evidence from the same sources, not an
independent enterprise dataset. It has now been inspected and is no longer an
untouched holdout.

**The strict no-regression gate rejects this candidate**: fewer false alerts come
with one fewer phishing alert and more explicitly unknown outcomes. The affected
follow-up message has insufficient model text and an uninspected remote image;
its new result is unknown, not an assurance of safety. Do not relabel unknown as an
alert, overwrite the baseline, or weaken the gate to claim a pass. Passing the
synthetic CI controls and unit tests does not override the public-cohort finding.
These are historical experiment findings, not a statement of current deployment
status. Repository inspection on 2026-09-27 at `main@7c1abf7` found the combined
weak routing concern already in `website/email_structure.py`, and the incomplete
remote-image result policy already in `website/app.py`. Their presence in `main`
does not establish which revision is deployed or erase the failed comparison.
Regenerate controlled baseline/candidate evidence from preserved revisions and
run the independent holdout release review before making a current release claim.

OCR diagnostics reproduced `1`/`l` substitutions and malformed URL punctuation.
The local benchmark now offers literal expected/extracted text comparison using
text-only rendering, excluded from downloaded aggregate reports. Visual evidence
adds a server-side instruction to check addresses against the original image
character by character even when OCR confidence is high. No OCR engine, language
model, URL correction or recognition-accuracy improvement is claimed in this step.

The browser now additionally reports the lowest Tesseract line confidence for
URL-like OCR lines, bounded to 0–100 and nullable when none is detected. It is
diagnostic client evidence, has no effect on server risk scoring and does not
correct the original text. On the two unchanged synthetic phishing screenshots,
overall OCR confidence was 92% for each; the misread English URL line scored
48% and the malformed Chinese URL line scored 80%. Exact OCR URL sets remained
1/3. These controls do not measure real screenshot performance, and an
undetected URL may have no line score.
The heuristic excludes numeric-only dotted release markers such as `Q3.2026`,
but some filenames or unknown address formats may still be ambiguous. A separate
ten-image authored font/text stress check records URL-like score coverage and
non-URL false scores without treating its OCR output as ground truth for the
original five-image comparison.

## Hidden text / linked image review signal (phase 3)

The current repository code emits one medium review signal when the same HTML document
contains at least 500 non-whitespace, non-format hidden characters, fewer than 80
visible characters, at least a 10:1 hidden/visible ratio, and a visible image inside
an explicit HTTP(S) anchor. Hidden prose stays excluded from model input. Short
preheaders, zero-width/NBSP filler, inert script/style/template/comment content,
text-rich mail and separate MIME parts do not meet this conjunction. Uncertain CSS,
MSO conditional rendering and recovery parsing suppress the added structural floor.
Nested anchors do not inherit an older web action. This is a suspicious layout for
manual review, not proof of phishing; a legitimate image campaign can also have
large hidden text. Picture/source-only image resources remain a conservative gap.

The 500-character policy was informed by an inspected development failure (779
hidden characters); that case is now a regression example, not holdout evidence.
On the second cohort it restores the lost alert: 83/98 phishing alerts, 9/96 normal
alerts and 10 unknown, matching baseline recall while reducing false alerts.

Third-batch confirmation uses seed 20260922 and excludes both prior batches: 6 exact
and 6 template overlaps are removed, leaving 188 messages (92 upstream phishing,
96 normal). Compared with exact HEAD serving/parser modules under the same model
and settings, normal alerts fall from 19/96 to 6/96, but phishing alerts fall from
81/92 to 79/92; unknown outcomes rise from 9 to 11. No model weights, score threshold
or metric definitions were changed to produce these numbers. A reviewer-found
format-character negative-control fix was applied before inspecting batch results;
the confirmation was rerun afterward. The batch has now been evaluated, so it must
not be treated as untouched evidence for further tuning.

**The third-batch no-regression gate still fails.** Engineering tests and owned CI
controls pass, but that historical run did not satisfy the strict regression
policy. The routing and hidden-image rules are already present in `main@7c1abf7`;
the earlier description of them as an unreleased local candidate was inconsistent
with the checked-in code. Deployment status was not verified. Preserve the failed
result, resolve the recall/unknown tradeoff using independent evidence, and do not
treat restored performance on a development example as universal recovery.

## Jev shadow evaluation

The optional TypeSafe adapter is an experimental semantic opinion. It pins
`jev-1.13.0`; official contracts checked on 2026-09-21:
[HTTP API](https://docs.typesafe.ai/api), [Noul questions](https://docs.typesafe.ai/primitives/noul),
[model limits and languages](https://docs.typesafe.ai/models).
Noul values are estimated probabilities of a proposition, not severity scores.
An output with the right type can still be wrong. English is the provider's
strongest language; this repository has not established multilingual gains.

### Local preflight (no external processing)

```sh
.venv/bin/python website/tools/evaluate_jev.py \
  --manifest website/tests/fixtures/evaluation/manifest.json \
  --output /tmp/jev-preflight.json
```

Default mode validates provenance, hashes, labels, duplicates and optional
`--reference-manifest` overlap. It loads neither detector nor remote model, sends
no message, and reports no detection accuracy. Even a configured API key cannot
turn a dry run into a live call.

### Authorized live experiment

First arrange authorized, independently labeled, minimized test data and confirm
provider data handling and spending controls. Store `TYPESAFE_API_KEY` privately
in the process environment and set `PHISHGUARD_JEV_ENABLED=true`. Do not paste
keys in source, command arguments, Git, reports or chat. Then explicitly opt in:

```sh
.venv/bin/python website/tools/evaluate_jev.py \
  --manifest /absolute/private/corpus/manifest.json \
  --live --allow-external-processing --max-calls 20 \
  --output /absolute/private/jev-report.json
```

The call limit is required (1–1000). Rows after that budget remain in denominators
as undetermined. Choose a balanced, predeclared cohort small enough for the budget;
the tool takes eligible rows in input order and does not silently sample for you.
Local inference uses the committed Vercel model/profile with sender history and
verification disabled. Jev receives readable text, never original MIME bytes or
attachments. MIME plain text stays literal; HTML hidden text is excluded by the
existing parser. Missing nested-message text and other incomplete evidence force
the auxiliary evaluation decision to remain undetermined, even if Jev returns a
high probability. OCR remains unverified text; Jev cannot correct it from pixels.

Reports compare the baseline, auxiliary judgments, and a **hypothetical OR** rule
that retains all original alerts and only adds auxiliary alerts. The exploratory
default threshold is 0.8 for deceptive intent, with insufficient-evidence >=0.5
treated as undetermined. These thresholds are not validated production policy.
Metrics include recovered phishing, new normal-mail alerts, unknown/failure counts,
language/source groups, available-output Brier score, timing and reported token
usage. Failures/skips remain in class denominators and make live CLI runs fail;
Brier excludes missing outputs and states its own denominator. Provider failures
may still incur charges; reported usage is not a complete bill. No pricing-derived
cost claim or automatic deployment gate is produced. Input/cohort/question/model
identities are recorded without mail bodies, raw response errors or file paths.
New independent samples are required after changing prompts or thresholds.

### Optional authenticated workbench

Set the two variables on the server and restart/redeploy only when enabling is
authorized. The case workspace then shows **Jev auxiliary opinion** for analysts.
The checkbox and explicit button call `POST /api/cases/{id}/auxiliary` with
`{"allow_external_processing":true}`. Authentication, no-store headers and existing
rate limiting apply. The browser receives only structured opinions, never the key.
Opinions do not change risk or verdict. Switching cases/signing out clears the
display; **View existing result** reads the current analyst's 24-hour receipt
without sending a new provider request. An analyst may explicitly confirm **Save
opinion to history** to retain a successful server-owned opinion with model/input
provenance under the case retention policy. This appends a case event without
changing human assessment; it neither labels evaluation data nor retrains the model.
Failed, missing, expired or mismatched receipts cannot create a new opinion event.
Legacy raw-email cases without separately saved
MIME text skip auxiliary analysis rather than reinterpreting plain text as HTML.

The adapter masks email local parts and removes HTTP(S) URL credentials, queries
and fragments. This is **data minimization, not full anonymization**: names, URL
paths and free prose can still contain private data. Analyst notes and images are
never sent. Input over 12,000 total subject/body characters is skipped, not silently
truncated. Responses are bounded to 16 KB and strictly validated. Redirects, proxy
environment variables, provider error-body logging and automatic retries are disabled.
The caller has a six-second external-request deadline. At most two daemon requests
can continue waiting on an underlying socket/DNS operation; they retain their
slots until completion, preventing an unbounded retry/thread queue.

Web calls share a daily workspace/environment attempt budget in Upstash (SQLite
locally), default 20, configurable with `PHISHGUARD_JEV_DAILY_LIMIT` (1–1000).
The budget resets at UTC midnight. Requests reserve an attempt before contacting
TypeSafe; failures and uncertain outcomes also consume it. Identical inputs,
actor, case, pinned model and questions reuse a 24-hour receipt, even across a
midnight reset. This limits attempts, not monetary spending; retain provider/account
controls. CLI calls keep their separate explicit budget and do not use web receipts.
The web server releases a reservation only for a confirmed local worker-capacity
rejection before provider I/O; this allows a later deliberate retry. Provider
timeouts, HTTP errors and unknown outcomes retain their existing receipts.
Missing or invalid configuration disables the optional feature without breaking
existing analysis. The production `--require-jev` smoke gate checks only safe
configuration flags and never calls TypeSafe. See [operations](case-workflow.md#jev-availability-and-request-controls).

No live Jev call or accuracy test was performed during implementation. Synthetic
contract/failure tests establish integration behavior, not model effectiveness.
