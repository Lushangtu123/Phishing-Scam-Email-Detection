# API overview

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze-email` | Explainable sender/domain risk |
| `POST /api/analyze-content` | Subject/body or raw-message analysis |
| `POST /api/analyze-eml` | Original MIME bytes, maximum 60,000 bytes |
| `POST /api/analyze-sms` | A pasted text message and its sender; 404 unless `SMS_ANALYSIS_ENABLED` |
| `POST /api/verify-email` | Lite domain checks or local full mailbox checks, depending on configuration |
| `GET /api/metrics` | Archived UCI website benchmark and optional live text-model metrics |
| `GET /api/config` | Public feature flags |
| `GET /health` | Detector availability and deployment profile |

## Text messages

`POST /api/analyze-sms` takes JSON `{"sender": "...", "text": "..."}`: `sender` at most
64 characters and optional, `text` at most 2,000 characters and required (400 when blank).
The request body is capped at 16,000 bytes. The endpoint returns 404 and `/api/config`
reports `"sms_analysis_enabled": false` unless `SMS_ANALYSIS_ENABLED` is set; production
runs it as a test before its launch gate
([design](superpowers/specs/2026-10-08-sms-scam-detection-design.md)).

The response has the content fields `risk_level`, `risk_label`, `total_score`,
`category_results` and `extra_indicators` (codes `sms.*` beside the shared `content.*` and
`link.*`), plus:

- `sender_kind`: `short_code`, `cn_port_106`, `cn_mobile`, `nanp_toll_free`,
  `nanp_long_code`, `premium_rate`, `international`, `other_number`, `email`,
  `alphanumeric` or `none`;
- `claimed_brand` and `official_channels`: the organisation the text names and its
  official website, service numbers and verified statement, from the official-brand
  registry;
- `domain_registrations`: registration dates of the links' domains when RDAP lookups are
  on (context only, no points).

No text model runs. With no finding the level is `unknown` ("No Known Scam Signs Found"),
never `safe`, because a text's sender cannot be verified. `POST /api/feedback` accepts
`input_mode: "sms"` with `source` fields `sender` and `text`.

## Message codes

Every server-written English message also carries a stable, dotted `code` and
its `params` (short strings or numbers, each at most 256 characters; never a
message body), so clients can show it in another language. The English text is
unchanged:

- `risk_indicators[]` and `extra_indicators[]` add `code` and `params` next to
  `level`/`msg`. A message wrapped with its source (`Sender: …`,
  `Attached message: …`, `Image (name): …`) keeps the inner code and lists the
  wrappers in `prefixes` (`[{code, params}]`, outermost first).
- String lists keep their type and gain parallel lists of `{code, params, msg}`:
  `analysis_warning_details`, `safety_signal_details`, per-image
  `assessment_warning_details` and the enhancement's `warning_details`.
  `code` is `null` for text the server did not write, such as browser OCR
  warnings.
- `/api/verify-email` adds `code`/`params` to `spf`, `dmarc`, `domain_age` and
  `mx_ptr`, `smtp_message_code`/`smtp_message_params`, `note_code`/`note_params`
  and `mailbox_verification.reason_code`/`reason_params`.

```json
{"level": "low", "code": "sender.domain_hyphen", "params": {"domain": "paypa1-verify.xyz"},
 "msg": "Domain contains a hyphen (paypa1-verify.xyz) — major providers typically do not use hyphens in their domains"}
```

The catalogue of codes and English templates is
[`website/data/server_messages.json`](../website/data/server_messages.json)
(families `sender.`, `content.`, `link.`, `structure.`, `warning.`, `safety.`,
`prefix.`, `verify.`); `msg` is always rendered from it. The homepage dictionary
holds the same English as `server.<code>`, and
`website/static/server-messages.test.mjs` fails when the two differ. Saved cases
keep indicator codes but not the `*_details` lists; case reads (`GET /api/cases/{id}`
and responses that return a record) derive a top-level `analysis_warning_details`
(and `source_preview.warning_details` for retained feedback email) again for
display, outside the stored `analysis`.

The case workspace (`/cases`) uses the same dictionary and EN / 中文 switch as the
homepage and shares its stored choice (`localStorage` `phishguard-lang`). It
localizes its own interface text, coded indicators and warnings (English-match
check), risk labels and levels, category labels and descriptions, statuses,
verdicts, review reasons, evidence bases, report types, history action and field
names, and reported signal codes. Analyst notes, subjects, message bodies, actor
names, API `detail` errors and the audit JSON are shown as stored.

Only the active language's strings are downloaded. `website/static/i18n.js`
holds the runtime and the English dictionary (the fallback, and the reference
for the English-match check); the Chinese dictionary is `i18n-zh.js`. For a
visitor whose language resolves to Chinese, `lang-init.js` requests it in
`<head>` and the page stays hidden until it is applied (or has failed, in which
case the page is shown in English); switching to 中文 loads it once, on demand.
On the homepage, Chart.js is likewise fetched only when the benchmark section
nears the viewport; the benchmark table does not wait for it.

API requests from both pages go through `website/static/request.js`, which gives
up after 45 s for analyses, verification and saves (above Vercel's 30 s
`maxDuration`, after which the platform answers 504 itself) and after 15 s for
small reads (`/api/config`, `/api/metrics`, case-queue reads), with its own
"took too long" message. While a sender or content analysis runs, a Cancel
button stops it and restores the form; a response that still arrives is
ignored. A timed-out report or case creation is treated as unconfirmed and
retried with the same `Idempotency-Key`. Unknown page URLs (not `/api/…`,
`/static/…` or `/_vercel/…`, and not a client asking only for JSON) get the
`404.html` page with status 404; API and asset misses keep the JSON 404.
With JavaScript off, both pages show an English `<noscript>` notice.

Example raw-message request:

```json
{
  "raw_email": "From: Example <notice@example.com>\nReply-To: help@lookalike.example\nSubject: Action required\n\nReview your account."
}
```

Keep `TRUSTED_AUTHSERV_IDS` empty unless you know which receiving mail system
created the uploaded message's authentication results. The upstream receiver
must remove attacker-supplied copies of its own authentication-service ID before
adding its result. Untrusted header claims are returned for inspection but
cannot increase or suppress risk.
Authentication-result extraction separates semicolon-delimited method clauses
from nested comments and quoted explanation strings. Text such as `dmarc=pass`
inside a comment or `reason` cannot overwrite a real `dmarc=fail` result. Common
whitespace and method-version syntax are supported. Unclosed comments or strings
produce an incomplete-analysis warning and cannot confer a trusted pass. This
does not perform live SPF/DKIM/DMARC verification or expand the trust boundary.
