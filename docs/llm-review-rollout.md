# Language-model review: from local trial to the served page

The local review (`website/local_review.py`) asks a language model about alerts that rest
on the text model alone and can only lower them to Low ("Low Risk — Read as Legitimate by a
Local Model"). It runs only in development profiles and only on a loopback address, so no
deployment sends mail text anywhere. This page says what would have to hold before it runs
for visitors of the served page, and how to get there one measured step at a time.

## Where it stands (2026-10-05)

Measured on 2026-10-04 with Qwen3.8 27B (the 18 GB 4-bit MLX build, Ollama 0.34, a 64 GB
Mac), before the 2026-10-05 changes; alerts with the review off, then on
([evaluation log](evaluation.md#review-of-model-only-alerts-by-a-local-language-model-2026-10-04)):

| Cohort | Off | On |
|---|---:|---:|
| The owner's 92 genuine emails, pasted | 35 | 9 |
| PhishFuzzer recent legitimate seeds (102) | 63 | 21 |
| UniqueData legitimate (58) | 39 | 29 |
| Postmark templates (10) | 3 | 0 |
| Nazario phishing (3,466) | 3,445 | 3,444 |
| PhishFuzzer recent phishing seeds (103) | 88 | 85 |

- Since 2026-10-05 a model-only score in an original email (`.eml`) is already a note, so
  the review matters most on pasted text and screenshots, which keep that alert.
- A second use, raising Safe or Low results the language model reads as phishing, was
  rejected: 14 more phishing messages caught for 21 more alerts on the owner's genuine mail.
- Public corpora may be in the language model's training data; the owner's own mail is the
  trustworthy part of these numbers.

**Four models compared (2026-10-05, shadow mode, same cohorts;
[details](evaluation.md#local-review-four-qwen-models-compared-2026-10-05)).** Alerts on the
owner's pasted genuine mail, before → after, and pasted Nazario phishing alerts lost:

| Model | Size | Owner's pasted genuine (35) | Pasted Nazario alerts lost (of 752) | Mean / max seconds |
|---|---:|---:|---:|---:|
| qwen3.5:4b-mlx | 4.0 GB | 19 | 87 | 0.8 / 4.2 |
| qwen3.5:9b | 6.6 GB | 24 | 17 | 1.7 / 7.1 |
| qwen3.8:27b-mlx | 18 GB | 10 | 14 | 3.6 / 26.4 |
| qwen3.8:27b-mxfp8 | 32 GB | 3 | 9 | 4.2 / 27.5 |

Small models do not hold up: the 4B one lowers many phishing alerts and the 9B one removes
few false alerts. The candidate for gate 2 is the 27B model at 8 bits, which needs about
32 GB of memory and a deadline below the 30-second request limit.

## Gates before it runs for visitors

### 1. An independent holdout

Consented, dated real mail in English and Chinese, from Gmail and Outlook.com, kept as both
`.eml` and pasted text, that no rule or threshold was tuned on. The
[release review](evaluation.md#opt-in-independent-holdout-release-review) asks for at least
50 phishing and 50 legitimate messages for each provider and language. The owner sets the
bar before looking at results; a starting proposal: the review removes at least half of the
model-driven false alerts on the holdout and costs at most one phishing alert per hundred
phishing messages, with Wilson intervals reported.

### 2. A model that can be served

Vercel functions have no GPU and a bundle-size limit, and a request here has 30 seconds. The
27B model measured above is 18 GB even at 4 bits and 32 GB at 8 bits, so it would need a
host of its own: the 4B and 9B models that a modest host could serve did not hold up
(above). The options:

- **A self-hosted endpoint** (Ollama or vLLM) behind a private HTTPS gateway and a
  server-side token, the pattern of the optional
  [RapidOCR service](../website/tools/enhanced_vision/README.md).
- **A hosted Qwen API.** Mail text then goes to a third party, which needs the Jev pattern:
  the reader's permission for each request and a daily budget.

### 3. Privacy

The README promises that no message is forwarded to a third-party analysis service, and
the review is refused outside development. Serving it changes that promise, so before any
remote endpoint: update the privacy notice; send only what the text model read (up to 4,000
characters of visible text and up to 15 link hosts, never hidden text, headers or
attachments); keep nothing at the inference host; and, for a third-party API, ask the reader
each time. A shadow run on the served page still sends text, so these apply to it too.

### 4. Prompt injection and abuse

A message can try to talk the model round, and the review can only lower alerts, so an
attacker who succeeds silences a model-driven alert. The guards today:

- only alerts with no rule, sender, link or structure finding are reviewed;
- hidden text never reaches the model, and a message that addresses automated reviewers is
  not reviewed at all (none of about 30,800 legitimate messages matched);
- temperature 0, a JSON schema, a confidence threshold (80), and a visible label on every
  lowered result.

Before serving: a red-team set (instructions in visible text, quoted replies, other
languages, homoglyphs), alert-lowering rates watched over time, and one setting to turn it
off.

## Steps

1. **Shadow mode, locally** (`LOCAL_LLM_REVIEW_SHADOW=true`): the review runs as usual, but
   a legitimate reading only says that it would lower the alert
   (`content.local_review_shadow`); the verdict is unchanged.
2. **Compare models** with `website/tools/evaluate_local_review.py` on the same cohorts
   (procedure below), and pick the smallest model that holds up.
3. **Build the holdout** and run the release review (gate 1).
4. **If a remote endpoint is chosen** (gates 2 and 3): add it behind HTTPS and a token,
   off by default, and start it in shadow mode.
5. **Apply** to model-driven alerts on pasted text and screenshots only, watch the lowering
   rate, and keep the off switch.

**Rollback:** `LOCAL_LLM_REVIEW_ENABLED=false` restores today's behavior, and every reviewed
result carries a `content.local_review_*` indicator, so lowered alerts can be found later.

## Comparing models

Inputs use the `evaluate_serving_pipeline.py` JSONL format (`provider`, `received_at`,
`label`, and `eml_path` or `subject`/`body`). `--paste` analyzes a cohort as a reader would
paste it: the subject and the visible text, without headers. Keep inputs and reports
outside Git; the report holds counts only.

```bash
ollama serve
.venv/bin/python website/tools/evaluate_local_review.py \
  --input genuine_eml=/absolute/private/genuine.jsonl \
  --paste genuine_pasted=/absolute/private/genuine.jsonl \
  --input phishing=/absolute/private/phishing.jsonl \
  --model qwen3.8:27b-mlx --model SMALLER-MODEL \
  --output /absolute/private/local-review-comparison.json
```

For each model, cohort and label the report counts the messages, the alerts, how many alerts
the model would lower, keep (read as phishing, or unsure) or could not review, and the alerts
left if it were applied, with response times, the model digests and the prompt's digest.
Results go to the [evaluation log](evaluation.md).

## Chinese mail

The text model does not read Chinese; Qwen does. Reviewing Chinese mail would be a new use,
not the measured one: Chinese mail without a rule finding is undetermined, not alerted, so
there is nothing for the review to lower. It needs a labelled Chinese cohort first.
