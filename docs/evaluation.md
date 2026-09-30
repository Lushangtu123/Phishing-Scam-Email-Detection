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

### Offline counterfactual alert diagnostics

The optional counterfactual sidecar reruns **only baseline alerts** on the same
local inputs and evaluation settings, suppressing one fixed evidence family or
link rule at a time. It records how many alerts remain alerts, become nonalerts,
become undetermined, or fail to replay. It does not change production behavior
or put message text, addresses, URLs, record IDs, or exception text in the
sidecar. A failed replay
is counted and makes the CLI exit nonzero rather than silently accepting an
incomplete diagnostic.

```sh
.venv/bin/python website/tools/evaluate_public_corpus.py \
  --manifest .evaluation-data/public-pilot/manifest.json \
  --output .evaluation-data/public-pilot/report.json \
  --counterfactual-output .evaluation-data/public-pilot/counterfactual.json
```

The private serving evaluator accepts the same `--counterfactual-output` option
alongside `--input`; keep its sidecar beside the private report. Both outputs
carry the evaluated-cohort and model digests. Five family-level interventions
remove sender analysis, outer-message structure scoring, link-destination rules,
content keywords (including keyword-dependent credential pressure), or the
content model. Two narrower interventions remove only `link.display_mismatch`
or `link.brand_lookalike` evidence. Other content heuristics and URL-shortener
scoring are not covered by a separate intervention. Removals can overlap: if
two removals each change the same email, their counts must not be added. A
transition on a historical label is a local diagnostic, not proof that removing
that evidence would improve current-mail accuracy or be safe to deploy.

The first paired replay kept all baseline decisions and cohort/model digests
unchanged. Of 135 alerted historical `hard_ham` messages, one-at-a-time removal
produced these transitions; the separate pilot column shows losses among its
90 alerted phishing messages:

| Removed evidence | `hard_ham` → nonalert | `hard_ham` → undetermined | Pilot phishing → nonalert / undetermined |
| --- | ---: | ---: | ---: |
| Sender analysis | 22 | 38 | 1 / 4 |
| Outer-message structure | 6 | 4 | 0 / 1 |
| Link destinations | 4 | 15 | 0 / 1 |
| Display-domain mismatch | 2 | 15 | 0 / 0 |
| Brand lookalike | 0 | 0 | 0 / 1 |
| Content keywords | 5 | 8 | 0 / 0 |
| Content model | 15 | 1 | 28 / 14 |

All seven replays completed without failures. In the pilot, removing sender or
outer-message structure also changed both of its two legitimate alerts to
nonalerts. Those two counts refer to the *same* messages; neither is a safe
production change without a fresh independent holdout. An undetermined result
is not a correct nonalert, and the 2003 `hard_ham` cohort contains no phishing
controls of its own. The brand-lookalike removal changes no `hard_ham` alert
after the Apple Core correction; display-domain mismatch accounts for most of
the link-family transitions, but 15 become undetermined rather than nonalerts.

### Routine sender mailbox correction (2026-09-27)

The sender rule treated complete role names including `subscriptions`,
`updates`, `alerts`, `admin`, `mailer`, `webmaster`, and `postmaster` as high-risk
because a broad substring list matched words such as `subscri`. This is not
evidence of phishing by itself. The sender-only result now excludes those exact
role names from its local-part keyword indicator; domain spoofing and compound
mailbox names still use the existing rules. The test first reproduced the high
indicator, then passed after the correction.

On the same 244 reference-filtered historical `hard_ham` messages, alerts change
from 135 to 114, nonalerts from 44 to 45, and undetermined from 65 to 85. Thus
21 fewer labeled normal messages are alerted, but 20 become undetermined because
other evidence is incomplete. The separate 199-message phishing/easy-ham pilot
is unchanged: 90/100 phishing alerts, 3 nonalerts, 7 undetermined, and 2/99
legitimate alerts. Both replays have zero inference exceptions. The paired
two-class comparison passes; the `hard_ham`-only comparison fails its two-class
requirement and its no-increase-in-unknown rule. These inspected historical
corpora do not establish current-inbox accuracy or an independent release
holdout. In particular, undetermined is not counted as a correct nonalert.

### Filename-label correction (2026-09-27)

At `main@7169ae5`, nine synthetic document labels, including `invoice.pdf`,
`report.docx` and `Budget.xlsx`, incorrectly triggered a high displayed-domain
mismatch against a neutral document host. The correction excludes only complete
bare common filenames whose extension is absent from the bundled public suffix
list. Nine explicit-address/real-suffix controls and four dangerous destination
controls retain their alert evidence. This does not treat a document link as safe.

Paired replay on the same 443 historical messages has zero decision-count
changes or inference failures: `hard_ham` remains 114 alerts, 45 nonalerts and
85 undetermined out of 244; the pilot remains 90/3/7 on 100 phishing messages
and 2/97/0 on 99 legitimate messages (alert/nonalert/undetermined). The two-class
comparison passes. No matching bare document labels were found in these corpora,
so this regression fix does not establish a measured corpus accuracy improvement.

## 2. Browser OCR and QR controls

### Missing CID image coverage (2026-09-28)

At `main@c4ae4ca`, a resource reference such as `cid:missing@example.test` was
silently skipped by browser extraction. An unrelated image attachment could
still produce an observation without disclosing the missing resource. This
was a coverage-reporting defect; the original EML's server analysis already
had its own unresolved-image handling.

Browser extraction now checks CID references in their original MIME context.
Only a nonempty supported image candidate can match; missing, malformed,
ambiguous, unsupported and non-image targets produce coverage warnings.
Warnings omit raw identifiers and do not add risk scores. All image attachments
still undergo the existing collection, format, budget and recognition stages.
A metadata match does not establish that pixels were decoded or displayed.

The adapter preserves postal-mime's existing grouped HTML order while mapping
each entry back to its exact source node. It refuses unverifiable mappings and
retains independent data images and attachments. Scope and comparison controls
follow [RFC 2392](https://www.rfc-editor.org/rfc/rfc2392.html#section-2) and
[RFC 2557](https://www.rfc-editor.org/rfc/rfc2557.html#section-7): decode CID URL
escapes once, preserve identifier case, separate nested messages and parallel
related groups, allow enclosing related resources, and respect mutually exclusive
alternatives. Common opaque IDs and same-message candidates without related
groups are supported conservatively. This is not a complete email-client renderer.

Fifty-seven new helper/collector tests cover these boundaries, inert examples,
empty/unsupported resources, malformed metadata, limits, grouped ordering and
callback failures. Eighteen initial controls failed on the prior implementation;
review added failing-then-passing controls for unescaped fragment delimiters,
non-ASCII header padding and unexpected resolver results.

The actual-browser check compares a valid CID with a missing one beside the
same QR attachment, verifies the missing warning through the public API/UI,
preserves original EML bytes and QR payloads, and confirms that the coverage
warning alone does not change risk. The remaining limitations include client
layout/visibility, Content-Location image resolution and literal OCR errors.
Validation passes: 358 frontend tests, 17 Chromium checks, three local harness
checks and all 34 recognition asset hashes. The 671-test backend suite passes
with 10 local Redis integration skips. The paired five-image comparison has no
regression: exact QR sets 5/5, exact OCR texts 2/5, exact OCR URL sets 1/3 and
23/238 character edits. These synthetic controls verify coverage reporting;
they do not establish a real-mail accuracy improvement.

### OCR failure preserves partial evidence (2026-09-28)

At `main@d36eb80`, four images could each retry a stalled 45-second OCR
initialization. The page terminated the job at 150 seconds before the worker
returned any of its decoded QR evidence. Parameter setup had no deadline, and
awaiting failed or stalled cleanup could also prevent a partial result.
Five new regression controls failed on that implementation; the two original
success/damaged-image controls passed.

The task now stops OCR attempts after the first OCR-stage failure, continues
QR scanning and labels each affected image's missing text coverage. Startup
and parameter setup share 45 seconds; encoding and recognition share 20 seconds
per image. Cleanup cannot block the response. Thirteen VM controls cover these
failures, late startup cleanup, preservation of earlier recognized text,
failed images without QR, normal worker reuse and damaged-image isolation.

All 16 Chromium integration checks pass. Holding the actual local OCR core
request pending returned four distinct QR observations and original EML bytes
through the public form/API in 45,974 ms on the test machine. The original
message's credential request remained high risk, and the UI displayed skipped
text warnings. Later normal jobs recovered OCR after the fault was released.
This timing is a local observation, not a device-wide guarantee.

The 301 frontend tests pass; the 671-test backend suite passes with 10 local
Redis integration skips. All 34 asset hashes pass. The paired five-image
comparison has no regression: exact QR sets 5/5, exact OCR texts 2/5, exact OCR
URL sets 1/3 and 23/238 character edits. These changes address failure handling;
they do not improve literal OCR accuracy or measure real-mail detection rates.
The 150-second overall limit still applies; other browser decoding or resource
failures can still prevent completion. Missing CID coverage remains unresolved.

### Independent MIME and extracted-text sources (2026-09-28)

At `main@24a59d6`, postal-mime's joined HTML could let an unclosed script,
template, comment, style or textarea in one MIME part swallow a later part's
image. The browser collector now reads each decoded HTML entry independently.
The real Chromium regression changes from zero observations to the exact QR
from the later MIME part. Twenty-five new unit controls cover mixed/alternative/
related parts, complete documents, inert markup, cross-part attribute fragments,
transfer/charset decoding, nested budgets and unexpected parser metadata.
The 64-part / 2 Mi-character budget is shared across nested messages; remaining
HTML is reported as uninspected while earlier evidence and attachments survive.

The visual API previously concatenated OCR and QR strings. A separate caption
`Do not` could negate a QR request for credentials (high became low), while
`Enter your` in OCR and `password` in a QR could invent a credential request.
OCR and each distinct nonempty QR now receive separate literal-text rule/model
assessments. Fusion takes the strongest individual risk and maximum rule score,
unions explanatory findings and preserves original-message risk. Categories do
not contribute an accumulated cross-source score. Tests cover both OCR-to-QR
and QR-to-QR boundaries, complete single-source positive/negative controls,
independent model calls, duplicate/empty payloads and the 36-source maximum.
The response states the aggregation method and source count; the UI labels the
maximum individual model probability explicitly.

All 15 Chromium integration checks pass, including the actual visual API's
source-boundary controls. The fixed five-image extraction benchmark remains at
5/5 exact QR sets, 2/5 exact OCR texts, 1/3 exact OCR URL sets and 23/238 character
edits, with a passing paired no-regression comparison. This does not estimate
real-mail accuracy, repair OCR spelling or validate joint visual semantics.
On one local synthetic diagnostic using the pinned serving model, two full
36-source requests took 87.2 and 82.4 ms; these measurements are not production
latency guarantees. Missing CID images and unverified CSS/client rendering
remain outside these corrections.

### HTML image resource context (2026-09-27)

At `main@ec85816`, the data-URI collector searched the entire HTML string. The
new Chromium regression places a phishing QR only inside ordinary comments,
scripts, templates and textarea examples, followed by a real benign image.
Previously the worker returned two observations, including the inert QR. It now
returns only the actual image, with no QR payload. A separate Outlook conditional
version retains that same QR and explicitly warns about client-dependent display.
The browser control also verifies escaped CSS image-set syntax and preservation
of an earlier image when deeply nested template markup exceeds parsing limits.

Locked parse5 and CSSTree bundles identify resource positions without DOM
insertion, script execution or resource fetching. Thirty-nine focused tests
cover inert content, duplicate attributes, character references, CSS escapes,
responsive candidates, conditional backgrounds and parsing limits. An input
with six distinct commented-out images no longer exhausts the budget before a
real image. CSS property/function identifiers are decoded once; URL/string AST
values are already decoded and are not decoded again. Sources:
[parse5 options](https://parse5.js.org/interfaces/parse5.ParserOptions.html),
[CSSTree](https://github.com/csstree/csstree),
[HTML srcset processing](https://html.spec.whatwg.org/multipage/images.html#parsing-a-srcset-attribute).

Limits apply during tree construction and attribute tokenization, before the
potentially expensive full parse. The budget is 128 open elements, 256 attributes
per tag and 20,000 node/text construction operations. Truncation preserves only
earlier candidates and reports incomplete coverage. The attribute hook uses
parse5 8.0.1 internals and must be rechecked on upgrades. The evaluation identity
now hashes `vision-html.mjs` as well as the parser asset manifest.

This is resource-candidate extraction, not a complete rendering engine. CSS
selectors, cascade, viewport and email-client behavior remain unverified; CSS
and responsive/conditional candidates disclose that limitation. CSS values that
the parser cannot represent, including an unquoted escaped `url()` function,
produce an incomplete-coverage warning. Remote pixels and unresolved references
are not fetched. Existing MIME image attachments are still inspected separately.
The unchanged five-image benchmark remains at 5/5 exact QR sets, 2/5 exact OCR
texts, 1/3 exact OCR URL sets and 23/238 character edits. No real-mail accuracy
gain is inferred from these synthetic parser controls.

### Duplicate-image budget and PNG coverage (2026-09-27)

A new Chromium control puts six byte-identical benign inline images before a
different QR attachment. The previous extraction budget was exhausted before
worker deduplication: it inspected only one unique image and missed the QR.
Deduplicating original bytes during collection now inspects both unique images
and recovers the exact QR payload, without a false image-limit warning. Unit
controls cover shared budgets across data URIs, MIME attachments and nested
messages, copies after the fourth unique image, and a real fifth-image warning.
The limits remain four distinct candidates and a 2 MiB input file.

PNG preflight now checks chunk boundaries and rejects APNG instead of inspecting
only its default image. Six format tests cover ordinary PNG, literal `acTL`
metadata, valid two-frame animation, a separate default image with one animation
frame, truncated streams and malformed animation chunks. This follows the
[W3C animation-control chunk definition](https://www.w3.org/TR/png-3/#11acTL);
the preflight does not validate CRC contents or decode all animation frames.

The unchanged five-image benchmark still has 5/5 exact QR sets, 2/5 exact OCR
texts, 1/3 exact OCR URL sets and 23/238 character edits. These extraction fixes
do not resolve existing OCR spelling errors or establish real-mail accuracy.
At that revision, raw HTML data-URI extraction still lacked resource-context
filtering. The subsequent correction and its rendering limits are recorded above.

### Remote-image follow-up and native QR scanning (2026-09-27)

A local diagnostic against `main@79865eb` temporarily removed the image-alt
rendering exclusion from text scoring. On the 244 historical `hard_ham` messages, 84 unknown results became
low risk, but one became an alert, increasing normal-mail alerts from 114 to 115.
The 199-message two-class pilot's alert/nonalert/unknown counts were unchanged.
The false-alert regression rejects that relaxation; it is **not** in serving
code. The [HTML image specification](https://html.spec.whatwg.org/multipage/embedded-content.html#the-img-element)
defines alt text as replacement content, so ignoring it does not establish
coverage of what a recipient may see. Remote pixels remain unavailable in these
EML files, and the preceding 20 newly unknown messages remain unresolved.

The adopted fix instead corrects a reproduced browser extraction defect. A
4,096 × 1,600 authored image has two QR codes, at two and eight pixels per module,
and a separate caption. The old worker found only the larger QR after resizing
to a 2,000-pixel width. Scanning the bounded original pixels before resizing the
masked OCR copy recovers both exact payloads and preserves the exact caption.
The unchanged five-image benchmark retains 5/5 exact QR sets, 2/5 exact OCR texts,
1/3 exact OCR URL sets and 23/238 character edits. The paired visual comparison
passes. These are synthetic controls, not a measured change in real-mail error
rate; native QR scanning can consume more resources on large inputs.

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

## 4. Leave-one-source-out model evaluation

The README's mixed-corpus figures come from a grouped split of pooled corpora, so
every test message has training neighbours from the same corpus. This check asks a
harder question: how does the content-model **training recipe** do on a corpus it
has never seen? For each corpus it trains the deployed configuration (the same
TF-IDF FeatureUnion and `LogisticRegression(C=4, liblinear, balanced)`; a unit test
checks both against the committed artifact) on all other corpora and scores the
held-out one. The in-distribution baseline is grouped 5-fold cross-validation over
all corpora pooled. A large gap means the model relies on features that identify a
corpus rather than phishing.

```sh
.venv/bin/python website/tools/evaluate_source_holdout.py \
  --output .evaluation-data/source-holdout/report.json
# --max-per-source 500 --folds 3 gives a ~1-minute smoke run
```

It reads the public corpora from `phishing-detection/data/` (download them with
`content_model.ensure_real_dataset()`; if Mendeley answers 403 to Python, fetch
`SpaPhish.csv` from the same URL and check the pinned SHA-256) and adds the
synthetic hard negatives. Normalized message families are kept once across all
corpora and label-conflicting families are dropped, so no held-out family is in
training. The report holds aggregate counts, rates with Wilson 95% intervals, PR
and ROC AUC, and each corpus file's SHA-256; no message text. It never replaces
the served artifact.

### Results, 2026-09-28

56,232 messages after cross-corpus deduplication (7,370 duplicate and 533
label-conflict rows removed from 64,135). `phishnchips_legit_v5` does not appear:
all 333 of its messages normalize to messages already in `phishnchips_core`.
Pooled in-distribution baseline: PR AUC 0.9993, phishing recall 99.44% and false
positive rate 2.00% at the deployed threshold 0.3736.

| Held-out corpus | Rows (phish/legit) | PR AUC in-dist → held-out | Recall @0.3736 in-dist → held-out | FPR @0.3736 in-dist → held-out |
|---|---|---|---|---|
| Phishing_Email | 17167 (6469/10698) | 0.9979 → 0.8316 | 99.1% → **78.0%** | 1.9% → **19.4%** |
| CEAS_08 | 33099 (15985/17114) | 0.9999 → 0.9713 | 99.9% → 97.8% | 0.9% → 9.4% |
| Nazario | 1532 (1532/0) | — | 98.9% → 85.7% | — |
| phishnchips_core | 1996 (996/1000) | 0.9985 → 0.7456 | 98.7% → **10.6%** | 3.3% → 1.7% |
| phishnchips_infra | 47 (47/0) | — | 100% → 100% | — |
| SpaPhish | 1347 (684/663) | 0.9856 → 0.5970 | 95.8% → 98.4% | 11.0% → **96.5%** |
| synthetic_hard_negatives | 1044 (0/1044) | — | — | 12.9% → **60.3%** |

Reading the table:

- Performance on a familiar corpus does not carry over. Without its own corpus in
  training, the model misses 22% of `Phishing_Email` phishing and flags 19% of its
  legitimate mail, against 1–2% in the pooled estimate.
- Modern synthetic phishing (`phishnchips_core`) is almost entirely missed (10.6%
  recall) when learned only from the older corpora; the model has little transferable
  notion of phishing that is written differently.
- A language it has not seen is treated as phishing: 96.5% of legitimate Spanish
  (SpaPhish) messages are flagged while recall stays high, so PR AUC falls to 0.60.
- Clean, modern-looking legitimate mail (the synthetic hard negatives) is flagged
  60% of the time when those templates are not in training.

Limits: this evaluates a recipe on full corpora, not the committed artifact (which
used a 30,000-row sample, SpaPhish date partitions and a SpaPhish-selected
threshold). Single-label corpora report only recall or only FPR. `phishnchips_infra`
has 47 messages. CEAS_08 dominates the remaining training data whenever another
corpus is held out, and its labels likely mark spam rather than phishing (inferred
from the deployed model's strongest features, not verified). Corpus-level holdout
also changes era, language and generation process at once, so a gap shows poor
transfer but not which of those causes it. Use this table as the baseline to beat
before changing text normalization, corpora or labels, and re-run it with the same
command after each change.

Corpus SHA-256 used: `Phishing_Email.csv` `18ef4fff…3b97`, `CEAS_08.csv`
`22375e7d…6074`, `Nazario.csv` `b8fbc415…d184`, `phishnchips_core.csv`
`cebb407f…04ef`, `phishnchips_legit_v5.csv` `66df80e1…393c`,
`phishnchips_infra.csv` `839c02c0…ce71`, `SpaPhish.csv` `fdd74842…9cc5` (full
digests are in the JSON report).

### Surface-token normalization experiment, 2026-09-28 (no gain)

`--normalize` applies `website/tools/model_text.py` before vectorizing: URLs,
email addresses, clock times (including `5pm`), years and other numbers become
fixed tokens and quoted-reply `>` markers are removed. Same data, deduplication
and seed as the table above:

| Held-out corpus | PR AUC baseline → normalized | Recall @0.3736 | FPR @0.3736 |
|---|---|---|---|
| Phishing_Email | 0.832 → 0.829 | 78.0% → 73.0% | 19.4% → 14.1% |
| CEAS_08 | 0.971 → 0.956 | 97.8% → 94.2% | 9.4% → 8.8% |
| Nazario | — | 85.7% → 74.5% | — |
| phishnchips_core | 0.746 → 0.786 | 10.6% → 14.3% | 1.7% → 1.9% |
| phishnchips_infra | — | 100% → 93.6% | — |
| SpaPhish | 0.597 → 0.630 | 98.4% → 98.0% | 96.5% → 96.1% |
| synthetic_hard_negatives | — | — | 60.3% → 59.7% |

Pooled in-distribution: PR AUC 0.9993 → 0.9991, recall 99.44% → 99.37%, FPR
2.00% → 2.30%. Threshold-free PR AUC rises on two corpora and falls on two, and
where the FPR falls (Phishing_Email) recall falls with it, so scores shifted
rather than separating better. Nazario recall drops 11 points: URLs and numbers
carried real signal for older phishing.

Refitting the normalized recipe on all corpora shows why. The year shortcut is
gone (`zzyear` weight −0.15), but the model rebuilt corpus shortcuts from the
tokens and names: `zztime` (−3.25) and token pairs such as `zzurl zzemail` and
`zztime zzurl` (Enron headers and mailing-list footers) are strong legitimate
cues, `enron` (−6.6, the most legitimate of 80,000 features), `vince`, `tony` and
`louise` are unchanged, and the mojibake character `â` (+3.3) is a phishing cue.
91% of the 30,519 legitimate training messages come from the two older corpora
(`CEAS_08` 17,114, 68% with mailing-list or reply markers; `Phishing_Email`
10,698, 23% with explicit Enron markers), so legitimate mail that looks different,
modern or non-English, scores as phishing. Surface
normalization renames these cues without removing them; corpus composition is
the lever to test next. The option is kept only to reproduce this result; the
served model does not use it.

### Corpus composition experiments, 2026-09-29 (no gain)

Two options reweight or drop existing public corpora; each corpus is still held
out in turn, on the same 56,232 messages and seed (held-out only,
`--skip-in-distribution`):

- A: `--balance-sources` gives every training corpus the same total weight.
- B: `--exclude-from-training CEAS_08` never trains on CEAS_08 (its phishing
  labels likely mark spam) but still scores it.
- C: both.

| Held-out corpus | PR AUC base / A / B / C | FPR @0.3736 base / A / B / C |
|---|---|---|
| Phishing_Email | 0.832 / 0.793 / 0.551 / 0.553 | 19.4% / 23.8% / 89.1% / 89.0% |
| CEAS_08 | 0.971 / 0.954 / 0.971 / 0.954 | 9.4% / 10.5% / 9.4% / 10.5% |
| phishnchips_core | 0.746 / 0.760 / 0.730 / 0.755 | 1.7% / 1.2% / 3.1% / 1.9% |
| SpaPhish | 0.597 / 0.597 / 0.569 / 0.561 | 96.5% / 98.2% / 98.8% / 98.8% |
| synthetic_hard_negatives | — | 60.3% / 60.7% / 67.3% / 66.2% |

Recall at 0.3736 rose where FPR rose (Phishing_Email 78.0% → 95.5% with B), so
PR AUC is the comparison to trust. Balancing trades a small gain on
`phishnchips_core` for losses on the two large corpora. Dropping CEAS_08 removes
17,114 of the 30,519 legitimate training messages, and legitimate
`Phishing_Email` mail is then flagged 89% of the time: whatever its phishing
labels mean, its legitimate half is most of what the model knows about normal
mail. CEAS_08's own row in B equals the baseline, as expected, because a held-out
corpus is never trained on in either run.

With the normalization result, this points away from reshaping the available
public corpora and towards data they lack: modern legitimate mail (notifications,
transactional and workplace mail) and non-English legitimate mail, consented
and dated, measured with this tool and `evaluate_serving_pipeline.py` before any
retraining.

## 5. External public corpora (2026-09-29)

Three public sources were added for evaluation only; none is used by the served
model. Files stay in the git-ignored `.evaluation-data/` with pinned revisions and
SHA-256s:

| Source | Contents used | Revision | License |
|---|---|---|---|
| [DiFraud](https://huggingface.co/datasets/redasers/difraud) phishing subset | 15,272 messages (6,074 phishing / 9,198 legitimate). Legitimate mail is mostly 2014–2016 organisational mail (23.5% DNC, 3.2% Sony, 3.0% Hacking Team markers; 8.2% Enron); phishing mostly mentions 2005–2007 | `f8fa04af` | MIT |
| [PhishFuzzer](https://github.com/DataPhish/PhishFuzzer) | 3,300 seeds (1,126 phishing / 1,100 valid / 1,074 spam) and 19,800 LLM entity-rephrased variants. Only the 300 `Source: Manual` seeds are recent (2022–2026, 102 valid, 103 phishing; English, Norwegian, Hungarian, German); the rest derive from SpamAssassin and a Kaggle phishing set | `1e21dd4e` | No LICENSE file in the repository; the paper states CC BY 4.0 |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) | 500 phishing `.eml` (seed 20260929) via `prepare_public_pilot.py`, paired with 500 SpamAssassin easy_ham (2003) | pinned by the pilot tool | CC BY-NC 4.0 (non-commercial) |

### Serving pipeline on 1,000 original EML files

`evaluate_public_corpus.py` on the phishing_pot/easy_ham pilot (full rules and
model): phishing alert recall 85.2% (426/500, Wilson 81.8–88.0%); 7 phishing
messages (1.4%) were not alerted and 67 (13.4%) were undetermined; legitimate
false-alert rate 5.0% (25/500, 3.4–7.3%) on 2003 mail. Only 0.4% of phishing_pot
analyses were complete and the text model scored 72.8% of them: most misses
come from image, remote-resource or attachment coverage, not from a low model
score. A few of the 500 may overlap the 2026-09-21 pilots drawn from the same
pool. Labels are upstream and unreviewed.

### Model recipe on external corpora

`evaluate_external_corpora.py` trains the deployed configuration once on the
seven training corpora and scores each external set, after removing external
messages whose normalized family is already in training (44 of 15,272 DiFraud
rows; none from PhishFuzzer):

| External set | Rows (phish/legit) | PR AUC | Recall @0.3736 | FPR @0.3736 |
|---|---|---|---|---|
| DiFraud | 15,228 (6,044/9,184) | 0.963 | 93.2% | 10.5% |
| PhishFuzzer recent real seeds | 205 (103/102) | 0.725 | 83.5% | **67.7%** |
| LLM variants of recent seeds | 1,230 (618/612) | 0.798 | 86.9% | 66.8% |
| LLM variants of legacy seeds | 12,126 (6,138/5,988) | 0.998 | 99.3% | 6.0% |

Spam (not part of either label) is scored as phishing 38–53% of the time. The two
LLM-variant rows differ only in the era of the seed, and the false-positive rate
moves from 6% to 67%: the recipe keys on era and style. Recent legitimate mail is
flagged two times in three.

### Adding public data to training

`--augmentation-experiment` scores the 205 recent real seeds under three training
sets; C2 uses grouped 5-fold cross-validation over seed IDs so no tested seed or
its variants are trained on (a unit test checks this):

| Training set | PR AUC | Recall @0.3736 | FPR @0.3736 (Wilson 95%) |
|---|---|---|---|
| C0: seven training corpora | 0.725 | 83.5% | 67.7% (58.1–75.9%) |
| C1: + DiFraud + LLM variants of legacy seeds | 0.707 | 83.5% | 53.9% (44.3–63.3%) |
| C2: C1 + LLM variants of the *other* recent seeds (984 per fold) | **0.793** | 81.5% | **32.4% (24.1–41.9%)** |

This is the first change that improves separation on recent mail: C2 halves the
false-positive rate with two fewer detected phishing messages and a higher PR
AUC. C1 alone lowers FPR at this threshold without better separation, so
2014–2016 mail and legacy-style variants do not substitute for recent examples.

Limits: 205 seeds is small and the intervals are wide. The seeds come from one
private collection, so seeds in different folds may share senders or
organisations; grouping is by seed, not by submitter, and C2 may be optimistic.
A 32% false-positive rate is still far from usable, and training on LLM variants
risks a new "LLM style" cue. Treat this as evidence that recent-style legitimate
mail is the missing ingredient, to confirm on an independent, consented, dated
holdout (`evaluate_serving_pipeline.py`) before any retraining of the served
artifact.

```sh
.venv/bin/python website/tools/evaluate_external_corpora.py \
  --difraud-dir .evaluation-data/external/difraud \
  --phishfuzzer-dir .evaluation-data/external/phishfuzzer \
  --augmentation-experiment --output .evaluation-data/external/report.json
```

### Newer phishing, marketing mail and transactional templates (2026-09-29)

Three more sources, evaluation only, in the same git-ignored folder:

| Source | Contents used | Revision | License |
|---|---|---|---|
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) yearly mboxes | 2015–2022: 2,153 phishing messages (1,841 after removing families already in training), used for training in C3; 2023–2025: 1,303 (1,297 after removing families in training or C3's additions), test only. Real phishing received by one mailbox; subject plus text body, HTML stripped | per-file SHA-256 in `SOURCES.txt`, fetched 2026-09-29 | CC BY 4.0 |
| [marketeam/Marketing-Emails](https://huggingface.co/datasets/marketeam/Marketing-Emails) | 16,440 legitimate business emails between marketing colleagues, split by normalized family 80/20 (seed 42) into 13,101 training and 3,339 held-out rows. **Fully synthetic**: the dataset card says every email was produced by generative models | `56377f42` | MIT |
| [Postmark transactional templates](https://github.com/ActiveCampaign/postmark-templates) | 10 text templates (welcome, receipt, invoice, dunning, trial expiring/expired, password reset ×2, invitation, comment notification) with fixed example placeholder values. The Mailgun and MailPace repositories were also fetched but ship HTML only and are not scored | `fa73527a` | MIT |
| [UniqueData/email-spam-classification](https://huggingface.co/datasets/UniqueData/email-spam-classification) | The 58 rows labelled "not spam" (one exact duplicate): real mail from around 2023 — account and security notices (Netflix, Steam, Instagram, Twitch, Venmo), statements, orders, job alerts. Test only; the 26 spam rows are not scored. Upstream labels are unreviewed and a few look doubtful (a casting call, a "you have been selected" scholarship) | `f9c3f31e` | CC BY-NC-ND 4.0 (non-commercial) |
| [lists.apache.org](https://lists.apache.org/) public archives | 14 monthly mboxes from 2025 (36 MB, SHA-256s in `SOURCES.txt`): `issues@iceberg` 2025-06 (GitHub notifications), `dev@kafka` 2025-06 (about half human discussion and half Jira/Jenkins notifications), `user@flink` and `users@tomcat` 2025-04 to 06 (human technical Q&A), `announce@apache.org` 2025-01 to 06 (releases and CVE notices). Messages under 8 words are dropped, then each category is deduplicated by family and capped at 500 (seed 42): 500 / 384 / 500 / 386 rows. Test only | fetched 2026-09-29 | Public archives; the ASF privacy policy says third parties may collect and process them |

`--extended-experiment` scores four training sets. On the recent PhishFuzzer seeds, C2 and C3
use grouped folds as in the previous section. All other sets are scored by the full model of each condition:

| Training set | Recent seeds: PR AUC / FPR | Nazario 2023–25 recall | Marketing held-out FPR | Templates flagged | UniqueData real legitimate FPR |
|---|---|---|---|---|---|
| C0: seven training corpora | 0.725 / 67.7% | 97.3% (96.3–98.1%) | 0.8% (26/3,339) | 3/10 | 69.0% (56.2–79.4%) |
| C1: + DiFraud + legacy LLM variants | 0.707 / 53.9% | 96.5% (95.3–97.3%) | 0.0% (1/3,339) | 7/10 | 56.9% (44.1–68.8%) |
| C2: C1 + other recent LLM variants | **0.793** / **32.4%** | 94.5% (93.2–95.6%) | 0.2% (8/3,339) | 3/10 | 53.4% (40.8–65.7%) |
| C3: C2 + Marketing-Emails + Nazario 2015–22 | 0.790 / 37.3% (28.5–46.9%) | 95.2% (93.9–96.3%) | 0.0% (0/3,339) | 5/10 | 58.6% (45.8–70.4%) |

All rates are at the deployed threshold, 0.3736. Intervals are Wilson 95%.

- **The recipe extrapolates forward on phishing.** Trained only on the existing corpora, it
  detects 97.3% of 2023–2025 Nazario phishing. Missed phishing is not the main
  error on recent mail.
- **C3 does not improve on C2.** On the recent seeds, PR AUC is unchanged
  (0.790 vs 0.793). C3 detects 4 more phishing seeds and flags 5 more legitimate ones, which is a threshold
  shift, not better separation. It also costs 1 point of Nazario 2023–25 recall.
- **Synthetic marketing mail is too easy to be informative.** Every condition,
  including C0, flags fewer than 1% of the held-out rows. Adding 13,101 of them teaches the model
  little that transfers to the recent seeds.
- **Transactional mail is where false alerts concentrate.** With C0, the flagged
  templates are Dunning (a failed-payment notice, score 0.84), Trial expired
  (0.47) and Trial expiring (0.45). These use the same urgent account and payment
  wording as phishing. Password-reset templates score below 0.09. With 10 templates the
  intervals span roughly 11–89%, so the per-condition counts are anecdotes. The pattern
  matches the 32–68% FPR on the recent seeds.
- **An independent real set confirms it.** The 58 UniqueData messages come from a different
  collection than the PhishFuzzer seeds. C0 flags 69% of them, the same level as the
  seeds' 68%. With C0, account and security notices score highest:
  - Netflix sign-up confirmation, 0.99;
  - Twitch email verification, 0.97;
  - Steam new-device access, 0.97;
  - Venmo email change, 0.87;
  - an account statement, 0.85;
  - Instagram new login, 0.82.

  A pizza order confirmation and terms-of-service updates score below 0.15.
  C2 lowers the rate only to 53% (intervals overlap). The recent LLM variants help on
  the seeds they resemble but transfer only partly to other real mail.
- **Recent technical mail is not the problem.** On 1,770 real 2025 Apache
  messages, every condition flags under 2%. C0 flags:
  - 0/386 announcements, including CVE notices;
  - 0/500 GitHub notifications;
  - 3/384 dev-list messages, two of them Jenkins "build is unstable" mails;
  - 7/500 user questions.

  The gap is therefore narrower than "recent legitimate mail". It is consumer
  account, security and billing notices from brands. The training corpora contain
  plenty of mailing-list mail and too little of that kind.

Next steps, in order of value:
1. A **real**, dated sample of recent legitimate transactional and account mail
   (billing, trials, shipping, security notices), consented and scored with
   `evaluate_serving_pipeline.py`.
2. Only then, a retraining decision. The public data here has no recent real legitimate
   mail of that kind.

The served artifact is unchanged.

```sh
.venv/bin/python website/tools/evaluate_external_corpora.py \
  --difraud-dir .evaluation-data/external/difraud \
  --phishfuzzer-dir .evaluation-data/external/phishfuzzer \
  --nazario-dir .evaluation-data/external/nazario \
  --marketing-csv .evaluation-data/external/marketing/train.csv \
  --templates-dir .evaluation-data/external/templates \
  --uniquedata-csv .evaluation-data/external/uniquedata/email_spam.csv \
  --apache-dir .evaluation-data/external/apache \
  --extended-experiment --output .evaluation-data/external/report-extended.json
```

### Importing your own consented mailbox

`import_own_mailbox.py` turns a mailbox export into the JSONL that
`evaluate_serving_pipeline.py` reads, so the full rules-and-model pipeline
scores it. The script:

- reads Google Takeout or Thunderbird `.mbox` files, Apple Mail `.mbox`
  folders, and `.eml` files or folders of them;
- writes each unique message once as `.eml` and drops messages without a
  date;
- keeps messages over the 60,000-byte limit as subject/body text rows
  (`--oversized skip` drops them instead);
- refuses output inside the repository unless it is under `.evaluation-data/`;
- prints only counts and sender domains. Subjects stay in the local `manifest.jsonl`.

A suitable collection is a new Gmail or Outlook.com address used only to sign up to
common services and trigger verification, new-sign-in, password-reset and
trial-expiry mail. Disposable inboxes are a poor substitute: large brands often
reject them, they expire before delayed notices arrive, and public ones let
anyone reset the test accounts.

```sh
.venv/bin/python website/tools/import_own_mailbox.py ~/Downloads/Takeout/Mail/Test.mbox \
  --output .evaluation-data/own-mail --provider gmail --language en
.venv/bin/python website/tools/evaluate_serving_pipeline.py \
  --input .evaluation-data/own-mail/messages.jsonl
```

An end-to-end check on the 85 `users@tomcat` messages from 2025-06 gave these
results with the full pipeline:

- 17 alerts (20%, Wilson 12.9–29.7%), although the text model alone
  flags about 1% of this list type;
- a medium sender verdict in 13 of the 17 alerts.

The likely causes are mailing lists rewriting `From` (for example `.invalid`
domains) and setting `Reply-To` to the list. This affects list subscribers
through the rule layer, separately from the model findings above. It is
recorded as a follow-up, not changed here.

### Serving-pipeline fusion on real mail (2026-09-29)

`evaluate_serving_pipeline.py` with `--attribution-output` ran the deployed rules
and model on three real cohorts imported with `import_own_mailbox.py`:

- 1,239 Nazario phishing messages from 2023–2025, labelled phishing;
- the 57 unique UniqueData legitimate messages, as subject/body text;
- 602 legitimate Flink and Tomcat user-list messages from 2025-04 to 06.

| Cohort | Alerts | `model_only` alerts | `model_led` alerts |
|---|---|---|---|
| Nazario 2023–25 phishing | 1,137 / 1,239 (91.8%); 74 undetermined | 35 | 866 |
| UniqueData real legitimate | 41 / 57 (72%) | 21 | 18 |
| Apache user lists (legitimate) | 80 / 602 (13%); 21 undetermined | 0 | 7 |

Uncorroborated model scores are about half of the false alerts on real account
notices, but only 3% of phishing alerts. Their model scores do not separate the
two groups: 20 of the 21 legitimate `model_only` scores fall below 95%, and 9 fall
below 85%. So a stricter model threshold is not a clean fix.

**Change:** `model_only` is now Medium ("Model Signal Needs Review") instead of
High. Alert counts are unchanged in all three cohorts. The severity shifts are:

- UniqueData: High falls from 39 to 18, and Medium rises from 2 to 23;
- Nazario: 35 alerts move from High to Medium.

Not alerting on `model_only` at all would cut UniqueData false alerts from 41
to 20. It would also cut Nazario phishing recall from 91.8% to 89.0%. That is
left as a decision for when a larger real sample of account notices exists.

The Apache false alerts come from sender rules on list `From`/`Reply-To`
rewriting, not from the model (see the importer section above).

### Mailing-list sender rewrites (2026-09-29)

Most sender-rule false alerts on the 602 Flink and Tomcat user-list messages came
from two causes:

- **The `.invalid` suffix.** For DMARC-protected senders, the list appends `.INVALID`
  to the From domain (for example `WCrowell@perforce.com.INVALID`). That reserved TLD
  triggered uncommon-TLD, unrecognized-provider and the looser unknown-domain
  random-username check.
- **Numeric QQ account IDs.** Addresses such as `2428694096@qq.com` were flagged as
  random usernames.

Raw-message sender analysis now strips a trailing `.invalid`, scores the underlying
domain, and adds an info indicator (`sender.list_rewritten`). From is not
authenticated here, so this gives a sender nothing it could not get by writing the
domain directly; a test compares both forms for an attacker domain and a brand
domain. Numeric QQ/Foxmail IDs of 5–11 digits skip the random-username check.

| Cohort | Alerts before | Alerts after |
|---|---|---|
| Apache user lists (legitimate) | 80 / 602 (13.3%) | 44 / 602 (7.3%) |
| Nazario 2023–25 phishing | 1,137 / 1,239 | 1,137 / 1,239 (every risk level identical) |
| UniqueData real legitimate | 41 / 57 | 41 / 57 |

The remaining list alerts are sums of weak signals:

- `Reply-To` set to the list (routing mismatch);
- company domains outside the small known-provider list;
- link and exclamation counts.

Changing those affects phishing from unknown domains too, so it is left for a
separate evaluation.

### Undetermined and missed phishing (2026-09-29)

Of 1,239 Nazario 2023–25 phishing messages, the deployed pipeline left 74
undetermined and 28 not alerted.

**Undetermined (74).** In 69 of these, the model did not score an uncertain HTML
rendering (`unverified_rendering`), because of CSS or inline-style visibility,
image `alt` fallback or MSO conditionals. Their model scores are mostly
15–22%, below the 37.4% threshold. Scoring them anyway would not add alerts.

**Missed (28).** The causes are:

- 13 where the model abstained for feature coverage;
- 12 with the Han-text warning;
- 9 oversized messages imported as text.

Where the model abstained and weak rule points made the result Low, the page
still said Low risk. A clean abstention already becomes `unknown`. Low now
becomes `unknown` in that case too:

| Cohort | Low before → after | Unknown before → after | Alerts |
|---|---|---|---|
| Nazario 2023–25 phishing | 28 → 14 | 74 → 88 | 1,137 (unchanged) |
| Apache user lists (legitimate) | 526 → 492 | 22 → 56 | 44 (unchanged) |
| UniqueData real legitimate | 13 → 13 | 0 → 0 | 41 (unchanged) |

The Apache cases are short replies and code- or log-heavy messages the model
cannot score. Detecting Chinese phishing needs a model trained on Chinese mail;
this change only stops the page from reporting Low for text the model cannot read.

### Chinese official-brand registry (2026-09-29)

`website/data/official_brands_cn.json` lists 39 Chinese organizations:

| Category | Count |
|---|---|
| Banks | 13 |
| Payment | 3 |
| Telecom | 3 |
| Logistics | 6 |
| E-commerce and platforms | 4 |
| Government | 6 |
| Airlines | 3 |
| Education | 1 |

It has 58 official domains and service numbers, all confirmed on each
organization's own site. It also holds 31 "will never" statements, each checked
word for word on its source page. The `source_type` field marks each statement
as official, government, or a media page quoting police. One search summary had
attributed a statement to the wrong Agricultural Bank page; that statement was
removed. One Postal Savings Bank statement stays unverified because the site
could not be reached.

Raw-message analysis now flags a From display name that claims one of these
organizations (curated `display_names`) from any other domain, with the existing
`structure.brand_display_name` indicator. Matching rules:

- The From domain passes only if it equals an official domain or is a subdomain
  of one, so a parent domain such as `com.cn` does not pass.
- Government entries also accept gov.cn senders.
- The `.invalid` mailing-list suffix is stripped first.
- ASCII names match at word boundaries.
- Ambiguous acronyms (ABC, BOC, EMS, QQ) and names shared with other entities
  (中通, 南航, 社保, 海关) are not matched.

Limit: qq.com is both Tencent's domain and a consumer mailbox, so a qq.com
sender displaying 腾讯 is not flagged.

| Cohort | Alerts without → with registry | Registry hits |
|---|---|---|
| Nazario 2023–25 phishing (1,239) | 1,137 → 1,137 | 0 |
| All Apache 2025 list mail (5,054 legitimate) | 123 → 123 | 0 |

No false hits on 5,054 real legitimate messages. Neither cohort contains Chinese
brand impersonation, so the detection gain is shown only by constructed tests.
Real Chinese phishing and genuine notices from these organizations, such as a
consented own-mailbox import, are needed to measure it.

### US and international official-brand registry (2026-09-29)

`website/data/official_brands_intl.json` adds 32 organizations:

| Region | Organizations |
|---|---|
| US | IRS, SSA, USPS, FedEx, UPS, Chase, Bank of America, Wells Fargo, Citi, Capital One, Venmo, Cash App, Zelle |
| Global platforms and brands | DHL, PayPal, Amazon, Apple, Microsoft, Google, Meta, Netflix, American Express, Coinbase, Docusign, HSBC |
| UK | HMRC, Royal Mail, Barclays |
| Canada | CRA, Canada Post |
| Australia | ATO, Australia Post |

It holds 61 domains and 43 "will never" or official-sender statements. They were
read on the source pages, mostly in a real browser because several sites block
automated fetchers. Several organizations publish their sending domains:

- DHL, including its `.dhl` brand TLD;
- Meta: seven domains;
- American Express: nine addresses;
- Canada Post;
- Venmo;
- Amazon;
- HMRC ("an email address that ends in hmrc.gov.uk").

The file also records the Hong Kong (HKMA) and Singapore (MAS/ABS) rules that
banks do not send transaction links by email or SMS.

Display names avoid common words and first names (Chase, Citi, Meta, UPS or
Apple alone). PayPal, Amazon, Microsoft and Google keep the existing
protected-brand rule, and a sender gets at most one impersonation signal.
Government entries accept their country's government suffix.

| Cohort | Alerts: Chinese registry only → with international | New registry hits | Level changes |
|---|---|---|---|
| Nazario 2023–25 phishing (1,239) | 1,137 → 1,144 (91.8% → 92.3%) | 76 | 42 High→Critical, 6 unknown→High, 1 Low→High, 1 Medium→High |
| All Apache 2025 list mail (5,054 legitimate) | 123 → 123 | 0 | none |

The most frequent new hits are Docusign (28), DHL (21), Netflix (6), Wells Fargo (6) and FedEx (3).

Limit: legitimate mail from these organizations is not in either cohort, so the
false-positive side is shown only on unrelated legitimate mail. Brand
notifications sent through third-party services not listed as official would
be flagged. Real notices collected with `import_own_mailbox.py` are the check.

### Sensitive-request rule (2026-09-29)

`_sensitive_requests` looks for a verb that asks the reader to hand something over
(reply with, send, share, provide, give, tell, read out, forward, text us, email
us; 回复, 发送, 提供, 告知, 将…回复给). The object must be one of:

- a one-time code;
- a password or PIN;
- a recovery secret;
- gift card numbers;
- a transfer to a "new" or "safe" wallet or account;
- remote-access software.

A negation or third-party framing earlier in the same clause cancels it (never,
don't, if anyone asks you to, scammers, 请勿, 任何人). Each kind has its own
message code. The rule adds +4 and a High floor.

A 35-case table fixes the behaviour. It covers genuine Apple and Amazon code
emails, "never share this code", retail and gifting gift-card offers, "email
password" as a noun phrase, and "Pay with your Amazon gift card balance".

Two design errors surfaced during evaluation and were fixed before commit:

- "Buy a gift card for Mother's Day" matched until gift cards required a
  hand-over (send, photo, number or code).
- Bare "email" and "text" were read as verbs, so "Email Password Expiration"
  matched 21 Nazario messages. They now require "email us" or "text me".

| Cohort | Messages with a hit | Alerts before → after |
|---|---|---|
| Nazario 2023–25 phishing (1,239) | 1 (password) | 1,144 → 1,144 (1 High→Critical) |
| DiFraud phishing / legitimate | 4 / 6,074 · 0 / 9,198 | — (rule only) |
| PhishFuzzer phishing / legitimate (seeds and LLM variants) | 4 / 6,859 · 0 / 6,702 | — (rule only) |
| Apache 2025 list mail · UniqueData · templates · Marketing-Emails (legitimate) | 0 / 5,054 · 0 / 57 · 0 / 10 · 0 / 16,440 | unchanged |

All 8 corpus hits are phishing, with 0 hits on roughly 37,000 legitimate
messages. Coverage is low because these corpora are dominated by link-based
credential phishing. The gift-card, crypto and remote-access kinds had no corpus
hits and are covered by constructed tests only; collected real scam samples are
needed to measure them.

### Verified official sender with a named mailbox (2026-09-29)

The largest remaining false-alert source is the text model on genuine account,
security and billing notices: 69% of UniqueData. A real PayPal receipt with a
passing DMARC check still scored High, because production trusts no
`Authentication-Results` header by default.

**Change:**

- An `.eml` upload may name its mailbox: a page dropdown shown only for `.eml`
  files, the `mailbox` field of `/api/analyze-visual`, or `?mailbox=` on
  `/api/analyze-eml`. The only value for now is `gmail`, meaning `mx.google.com`.
- With a mailbox named, only the topmost `Authentication-Results` header counts,
  and only when that service wrote it. Server-configured IDs are ignored.
  Attached messages never get a mailbox.
- A trusted DMARC pass counts as verification only when all of these hold:
  - there is no decisive failure;
  - there is exactly one From domain;
  - the DMARC `header.from` equals that domain;
  - the domain, or a parent of it, is an official domain in the registries;
  - it is not a consumer mailbox domain.
- A verified sender is marked `structure.verified_official_sender`, and its sender
  heuristics are not scored. With a Safe or Low floor, a Medium or High result
  becomes "Low Risk — Verified Official Sender". Floors of Medium or higher and
  Critical results are unchanged.
- Outlook.com was added later (see "Real Gmail and Outlook.com downloads" below).

**Checks:**

- Unit tests cover:
  - a verified receipt that becomes Low;
  - a forged `mx.google.com` header below another service's header being ignored;
  - misaligned `header.from`, qq.com and icloud.com senders, DMARC failure, and
    an attacker domain;
  - lookalike links and code requests from a verified sender still alerting;
  - `mailbox` validation.
- Worst case, a user wrongly choosing Gmail: all 1,153 raw Nazario 2023–25
  phishing messages were received by hostedemail.com, so none had a trusted pass
  or a verified sender.

**Limit:** no real Gmail-downloaded genuine notices were available, so the
false-alert reduction is shown only on a constructed receipt. It needs measuring
on consented Gmail downloads imported with `import_own_mailbox.py`.

### Verified services no longer undetermined (2026-09-30)

After the registry work, 38 of 72 genuine downloads were still undetermined. 20
of them were verified senders with a Safe floor, held back only by rendering and
inspection warnings: remote images, unscored MIME views, Outlook conditional
blocks, hidden text, stylesheet rules, image fallback text, and one
insufficient-context model result.

**First attempt: every verified sender.** Worst case, top header trusted:

- Genuine downloads: undetermined 38 → 18, all 20 to Low, with no new alerts.
- Nazario 2015–25 phishing: 8 messages also moved from undetermined to Low.
  - One is genuine Netflix mail in the corpus.
  - Seven are scams sent through genuine platform features, which authenticate
    as the real brand: six PayPal messages (seller-dispute notices such as
    "Don't recognize the seller? Quickly let us know", and "You sent a $179.99
    payment") and one Microsoft invoice.
  - The attacker's text sits in fields such as the seller name, note or company
    name. Here it was in parts the rules could not read.

**Shipped: registered services only.** All 20 genuine messages came from
`sender_only` services, and all 7 scams from the payment and large-platform
brands.

| Cohort | Undetermined | Safe or Low | Alerts |
|---|---|---|---|
| Own genuine downloads (72) | 38 → 18 | 33 → 53 | 1 → 1 |
| Nazario with headers, top header trusted (2,122) | 116 → 116 | 8 → 8 | 1,998 → 1,998 |

**Remaining gaps:**

- Scams sent through genuine PayPal invoices and Microsoft billing still end
  undetermined rather than alerting. Detecting them needs text from the parts
  that are not read today.
- The other 18 undetermined genuine messages come from services not in the
  registry (Vimeo, Notion, Cloudflare, Box, Netlify, Reddit, Pinterest, Steam,
  Zoom, Quora, Adobe).

### Bluesky added to the service registry (2026-09-30)

Bluesky's help center, which its web app links to, asks users not to block
`noreply@bsky.social`. `bsky.social` is registered as a `sender_only` service,
with "Bluesky" as a sender name.

User handles such as `alice.bsky.social` are subdomains of it. Bluesky controls
their DNS and `bsky.social` publishes `DMARC p=reject`, so users cannot send
authenticated mail from them.

The genuine password reset still alerted after registration. Its plain-text part
wrote `Bluesky [https://bsky.app], the social internet`, and bare-URL extraction
kept the closing `]`. `https://bsky.app]` then failed to parse and raised a
Medium floor (`link.malformed_target`). A closing `]` is now trimmed from bare
URLs unless the URL opened one, as a bracketed IPv6 host does.

- Genuine downloads (72): alerts fall from 2 to 1. Only the Trello notice from
  `po.atlassian.net` remains, excluded on purpose.
- Nine Nazario 2015–25 phishing messages contain a URL followed by `]`. All nine
  alert before and after, and none had the malformed-target finding.
- No Nazario message has Bluesky in its From.

### Spotify added to the service registry (2026-09-30)

Spotify's support page says an email is suspicious if the sender does not end in
`@spotify.com`. With `spotify.com` registered as a `sender_only` service:

- Genuine downloads (72): alerts fall from 3 to 2. The account-deletion
  confirmation, which the model alone scored 79%, is now Low. The other three
  Spotify messages are verified senders too.
- The remaining two false alerts are Bluesky (`bsky.social`, not registered) and
  a Trello notice from `po.atlassian.net`, which is excluded because
  `atlassian.net` hosts customer sites.
- No Nazario 2015–25 phishing message with authentication headers has Spotify
  in its From, so the change cannot lower any phishing result there.

### Organizational header.from and www display hosts (2026-09-30)

Eight more genuine downloads (six Gmail, two Outlook.com) left two Spotify false
alerts. Both came from rules being stricter than intended.

- **Organizational `header.from`.** Gmail reported
  `dmarc=pass … header.from=spotify.com` for `no-reply@alerts.spotify.com`. The
  code required the two to match exactly, so the sender was not authenticated
  and its `alerts.` subdomain and `no-reply` username raised a Medium floor. A
  `header.from` equal to the From domain's organizational domain now aligns.
  Other domains, and child domains, do not.
- **`www` display hosts.** A link labelled `https://www.spotify.com` that opened
  Spotify's own `wl.spotify.com` counted as a display mismatch (High), because
  `www.` was only dropped when no scheme was shown. The displayed host now drops
  `www.` in both forms.
- **Public suffixes.** A displayed host that is itself a public suffix must now
  match exactly. This uses the bundled list including private suffixes such as
  `github.io`, and closes an existing gap where `www.github.io` aligned with any
  user's `*.github.io`.

Old code (main) against new code:

| Cohort | Alerts | Undetermined | Safe or Low |
|---|---|---|---|
| Own genuine downloads (72) | 8 → 3 | 36 → 38 | 28 → 31 |
| Nazario 2015–25 phishing, no mailbox (3,466) | 3,271 → 3,271 | 186 → 186 | 9 → 9 |
| Nazario with headers, top header trusted (2,122) | 2,000 → 1,998 | 114 → 116 | 8 → 8 |

- Display-mismatch findings on Nazario were unchanged (207 → 207).
- The two Nazario changes are genuine brand mail in the phishing corpus: an
  AliExpress verification code signed by `aliexpress.com`, and a Netflix price
  notice signed by `account.netflix.com` linking only to Netflix hosts. Both
  became undetermined.
- The Spotify account-deletion confirmation still alerts on the model alone
  (79%), because Spotify is not in the registry.

### Service senders and platform relays (2026-09-30)

Model-led alerts on genuine account mail were the largest remaining false-alert
group on the 64 genuine downloads: codes, password resets and welcome mail from
GitHub, Dropbox, Crunchyroll and similar services.

**A gap in the existing registry.** Before adding services, the existing
registry was checked in the worst case: Nazario 2023–25 phishing with its
topmost header trusted, as if downloaded from Gmail.

- 24 Google Drive share phishing messages and 14 Docusign envelopes counted as
  verified official senders.
- 22 of the Drive shares dropped from High to undetermined, because the
  verified-sender cap removed the model-led alert.
- Drive shares really are delivered to Gmail, so this was a live gap for
  Gmail uploads.

**Relay rule.** All 38 Drive and Docusign messages had "via" in the display
name and a Reply-To to another organization; none of 59 genuine verified
senders had either. Canva documents that its design-share notices use the same
`no-reply@canva.com` address as its account mail, and a reported 2025 campaign
used those notices with SPF, DKIM and DMARC passing. The subject template and
display-name checks cover that case. None of the 59 genuine messages matched
them, apart from one Trello code, which the Atlassian product names now cover.

**Services.** 15 services were added after reading their pages:

| Evidence | Services |
|---|---|
| Official page listing sending addresses or domains | GitHub, Dropbox, Slack, Canva, Atlassian, EA, Figma, Ubisoft, Tumblr |
| Official phishing page naming the domain | Crunchyroll, SoundCloud |
| Homepage only | Duolingo, Asana, Coursera, GitLab |

Old code (main) against new code, top header trusted for Nazario:

| Cohort | Alerts | Undetermined | Safe or Low |
|---|---|---|---|
| Own genuine downloads (64) | 28 → 6 | 24 → 34 | 12 → 24 |
| Nazario 2015–22 phishing with headers (820) | 780 → 780 | 38 → 38 | 2 → 2 |
| Nazario 2023–25 phishing with headers (1,302) | 1,198 → 1,220 | 98 → 76 | 6 → 6 |

- The 22 new Nazario alerts are the Drive shares restored by the relay rule.
- No phishing message lost an alert.
- 10 of the 22 genuine messages that stopped alerting are undetermined rather
  than Low, because their HTML still leaves the model unsure how it renders.

**Limits:**

- None of the 15 services appear as authenticated senders in Nazario, so the
  relay rule's coverage of their share notices rests on the documented
  templates and unit tests, not on observed phishing.
- A platform notice whose display name is the platform, with no Reply-To and an
  unlisted subject, would still be capped.

### Rendering views for uncertain HTML (2026-09-30)

On the 64 genuine downloads, 31 results were undetermined. Most of that HTML was
routine: hidden preheaders, `.hide-mobile` style rules, and Outlook conditional
tables. Because any such rule made the model abstain, a Safe or Low verdict was
impossible even when every plausible reading was clearly benign.

**Change.** Uncertain HTML views are scored as rendering views: visible, strict
non-Outlook, and strict Outlook. A view is scored only if all readings lead to
the same alert decision (see README). Disagreeing views keep abstaining.

**Measured.** Old code (main) against new code; Medium and above count as alerts:

| Cohort | Alerts | Undetermined | Safe or Low |
|---|---|---|---|
| Own genuine downloads (64) | 28 → 28 | 31 → 24 | 5 → 12 |
| Public HTML transactional templates (87) | 4 → 4 | 82 → 57 | 1 → 26 |
| Nazario 2015–22 phishing (2,163) | 2,061 → 2,061 | 99 → 99 | 3 → 3 |
| Nazario 2023–25 phishing (1,303) | 1,210 → 1,210 | 87 → 87 | 6 → 6 |

- Every change came from a previously undetermined result.
- No phishing message became Safe or Low, and no alert was lost.
- 101 phishing alerts rose in severity (76 High → Critical, 25 Medium → High),
  because a newly scored view scored higher.

**Rejected variant.** Using every agreeing view's decision, alerts included, also
turned 62 undetermined phishing messages into alerts, but it added 52 false
alerts on the 151 genuine messages: 7 of the 64 downloads and 45 of the 87
templates. All 62 catches rested on the model alone, whose false-alert rate on
account and security notices is known to be high. The shipped rule therefore
keeps abstaining when only a newly scored view would alert.

**Limits:**

- The templates are public samples with placeholders filled, not delivered mail.
- 24 of 64 genuine downloads remain undetermined. The main remaining causes are:
  - image fallback text, left unresolved on purpose;
  - views that disagree: for one sample newsletter, the model scored 22% with the
    preheader and 64% without it;
  - model-only alerts on account notices.

### Authenticated senders outside the registries (2026-09-30)

On the 64 genuine downloads, 11 alerts came only from sender-address heuristics.
Examples: `no-reply` or `confirm` usernames, and `account.`, `alerts.` or
`login.` subdomains of the brand's own domain. With a trusted, aligned
DMARC pass, the domain owner chose those names, so they say little. The risk is
phishing from attacker-owned domains that also pass DMARC.

**Worst case for missed phishing.** For Nazario 2023–25 phishing, each
message's topmost `Authentication-Results` header (hostedemail.com) was treated
as trusted, as if the user had named that mailbox. 548 of 1,303 messages then
have an authenticated, non-consumer sender (643 with DMARC alone), so phishers
passing DMARC is common.

| Variant | Genuine alerts (of 64) | Phishing alerts (of 1,303) |
|---|---|---|
| Current | 35 | 1,199 |
| Relax on DMARC alone | 28 | 1,191 (−8) |
| Relax on DMARC + aligned DKIM | 28 | 1,192 (−7) |
| Usernames only, DMARC + DKIM | 31 | 1,193 (−6) |
| **DMARC + DKIM + display name names the domain (shipped)** | **28** | **1,199 (−0)** |

- The phishing messages that lost alerts all had display names unrelated to the
  authenticated domain: "IT Support", "Mail Support", "Track & Trace", "NTFX",
  "monkey.org Portal Notification", or a hotel name above a PayPal subject.
- Every genuine message that gained named its own organization.
- A second pass found two gaps, now closed:
  - a display name that was another address (`…@hotmail.com` from mail.ru);
  - a local part carrying the recipient's domain (`"monkey.org accounting"@…`).
- With the shipped rule, phishing severity barely moves: Critical 381→380,
  High 769→768, Medium 49→51.
- Genuine platform mail that phishers abuse, such as Google Drive share notices,
  is still relaxed (Google did send it). Those alerts come from content, and
  none were lost.
- 57 of the 60 authenticated genuine senders pass the name check. The misses are
  a product sent from its parent company's domain, and a brand whose domain
  label differs from its name; they only miss the benefit.

**Limits:**

- The display-name condition and the two fixes were designed after reading the
  Nazario 2023–25 losses, so "−0" is partly fitted.
- Nazario 2015–22 was run as a held-out check. It has only 61 authenticated
  senders, and even the unguarded variant lost no alerts there, so it cannot
  confirm the guard.
- All 7 genuine messages that stopped alerting became undetermined, not Low.
  Their HTML (hidden preheaders, conditional comments) keeps the model from
  running, so sender heuristics were the only signal. The undetermined rate is
  the next thing to fix.

### Real Gmail and Outlook.com downloads (2026-09-30)

The repository owner supplied 64 genuine original messages: 31 downloaded from
Gmail and 33 from Outlook on the web. They are account and service notices from
about 30 software, media and gaming services (sign-up confirmations, codes,
password resets, welcome mail). The files stayed local and are not committed.

**Outlook header format.** In all 33 Outlook messages the topmost
`Authentication-Results` header is Microsoft's inbound check,
`mx.microsoft.com 1; spf=… dkim=… dmarc=pass … header.from=…;compauth=pass`. It
sits above an ARC set and a lower `X-MS-Exchange-Authentication-Results` header
written by the sender's outbound relay (often `dmarc=none`). The existing
parser reads the format, including the version number after the authserv-id and
the missing space before `dmarc=`. `outlook` is therefore now a mailbox value,
meaning `mx.microsoft.com`. `dmarc=bestguesspass` is not a pass. The same
topmost-header rule applies, so a user who wrongly chooses Outlook for mail
delivered elsewhere gets that service's header on top and nothing trusted.

**Results.** Every message had a trusted DMARC pass on top. Medium and above
count as alerts:

| Mailbox | Messages | Alerts, no mailbox | Alerts, mailbox named | Verified official senders | Undetermined |
|---|---|---|---|---|---|
| Gmail | 31 | 13 | 13 | 0 | 16 |
| Outlook.com | 33 | 24 | 22 | 2 | 8 |

Only two senders (both Microsoft account notices) are in the official-brand
registries. Both became "Low Risk — Verified Official Sender", from High and
Critical. The other 35 alerts on these genuine messages come from:

| Cause | Alerts |
|---|---|
| Model-led (probability above the 37.4% threshold) | 18 |
| Sender-address heuristics alone (role usernames such as `no-reply`, keyword subdomains such as `account.` or `alerts.`, random-looking or deep-subdomain addresses) | 11 |
| Other (sub-threshold model score plus weak rules, or structure floors) | 6 |

24 of 64 (38%) were undetermined. The main reasons were hidden preheader text,
Outlook conditional comments, and stylesheet visibility rules, which are routine
in marketing and transactional HTML.

**Limit:** 64 messages from one person's accounts. This is enough to find the
failure modes, not to estimate rates.

### PDF attachment links and IPFS gateways (2026-09-30)

PDF attachments now have their `/URI` link annotations read, including from
FlateDecode object streams, and checked like message links. The PDF text stays
uninspected.

Of 1,303 Nazario 2023–25 phishing messages, 11 carry a PDF and 3 of those PDFs
contain web links:

- an `ipfs.io` page;
- an unlisted shortener (`sprl.in`);
- genuine Microsoft links in a callback-phishing invoice, where the scam is the
  phone number.

None of these tripped an existing rule, so alerts did not change.

The IPFS case pointed to a broader gap: public IPFS gateway links in message
bodies.

| Corpus | Messages with an IPFS gateway link |
|---|---|
| Nazario 2015–22 phishing | 9 / 2,163 (0.4%) |
| Nazario 2023–25 phishing | 119 / 1,303 (9.1%) |
| Apache 2025 list mail (legitimate) | 0 / 5,055 |

The new `link.ipfs_gateway` rule (+4, High floor) recognizes:

- public gateway hosts;
- the `<cid>.ipfs.<gateway>` subdomain form, which needs a long label before
  `.ipfs.`, so `docs.ipfs.tech` does not match;
- `/ipfs/<cid>` and `/ipns/` paths.

| Cohort | IPFS hits | Alerts before → after | Level changes |
|---|---|---|---|
| Nazario 2023–25 phishing (1,239 imported) | 163 | 1,144 → 1,150 (92.3% → 92.8%) | 124 High→Critical, 7 Medium→High, 6 unknown→High, 1 Medium→Critical |
| Apache 2025 list mail (5,054 legitimate) | 0 | 123 → 123 | none |
| UniqueData (57 legitimate) | 0 | 41 → 41 | none |

Limit: NFT and Web3 services may legitimately link to IPFS gateways. None
appear in these legitimate cohorts, so that false-positive risk is untested.

### Callback phishing and post-click guidance (2026-09-30)

Callback phishing sends a fake renewal, charge or order notice and asks the
reader to phone a "support" number. Many of these messages carry no link.
The new `content.callback_request` rule (+4, High floor) needs a phone number
with both a call word and unexpected-charge or not-me framing within 200
characters. Registry service numbers are skipped.

A first version that also accepted plain "cancel" or "refund" hit 15/9,198
DiFraud legitimate messages, mostly airline and hotel confirmations. The
trigger was narrowed to specific cancel objects and charge or not-me wording.

| Cohort | Callback hits | Alerts before → after | Level changes |
|---|---|---|---|
| Nazario 2023–25 phishing (1,239 imported) | 55 | 1,150 → 1,151 | 19 High→Critical, 2 Medium→High, 1 Low→High |
| Apache 2025 list mail (5,054 legitimate) | 0 | unchanged | none |
| UniqueData (57 legitimate) | 0 | unchanged | none |

Rule-only hits on other legitimate text: DiFraud 3/9,198, PhishFuzzer legacy
1/5,988, and 0 on Marketing-Emails, Postmark templates and recent PhishFuzzer.

Most hits were already alerts, so the rule mainly raises severity and names
the number. Results at Medium and above now also show what to do if the reader
already clicked, replied, entered a password or code, ran an attachment, or
sent money. That card is guidance only and is not scored.

Limit: genuine fraud alerts that ask the reader to call an unlisted number
can trigger the rule.

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
