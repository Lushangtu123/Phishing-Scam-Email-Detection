# Optional features

## Team case workspace

Case creation retains its original submission for safe retries after uncertain
failures, while keeping later edits as a separate draft. Retained EML feedback
also has a decoded text preview with parsing warnings; original evidence is unchanged.
Private evaluation reports support the same-cohort release comparison described
in [the evaluation guide](evaluation.md#3-compare-a-baseline-before-release).

The optional `/cases` workspace adds authenticated case creation, evidence review,
human verdicts, status changes and operation history. Vercel requires persistent
Upstash storage; the feature is disabled until configured. See
[case workflow and deployment instructions](case-workflow.md) for access,
limits, retention and production setup. That guide includes a single-analyst
credential recovery mode, a private Production login check, and read-only case
and feedback archive export with an isolated local recovery drill. Separately
consented, closed user feedback with structured analyst review can be exported
as a private curation draft and combined with independent annotations into
private development and holdout inputs. An archive-first, confirmation-gated
operator tool can remove one eligible closed record and its indexes. These
tools do not automatically train or validate the model. See [evaluation scope](evaluation.md).

The workspace also shows counts of open/closed feedback and evidence-supported
review findings, with verdict and review-reason filters. These counts describe
retained reports, not model-wide error rates. Per-case history capacity reserves
history slots and byte space for final workflow steps, and repeated Jev saves
preserve review conflicts. Failed page loads retain the current page for retry.
If the last filtered page disappears after a review, the queue returns to a valid
page with one bounded extra read. Public feedback keeps submission receipts and
original retry keys when edits are made during a request or the report dialog is
closed and reopened for the same analysis. Confirmed receipts remain available;
use **Start new report** to send another report, with fresh consent for retaining
input or using it in evaluation. These states remain in page memory only;
refreshing the page or replacing the analysis clears them. Archives account for
JSON escaping at full workspace capacity and retain complete restore verification.
Contradictory review reasons and verdicts cannot be closed or enter evaluation drafts.

## Image and QR recognition

On **Email Content** or **Case workspace → New case**, select a PNG/JPEG/WebP
image or an original `.eml` file. You can also drop one file onto the upload area,
or click/focus that area and paste a screenshot with Ctrl/Cmd+V. Selecting a file
does not submit it; use the existing analysis button when ready. The browser runs self-hosted jsQR and Tesseract.js
with **Image text language (OCR)** set to **English** by default. Select **Simplified
Chinese** or **English + Chinese** for those images. This is a manual language
choice, not automatic detection; changing it cancels the current scan. Language
selection affects image text only, including embedded EML images, not QR decoding
or original email text. Check extracted text even when confidence is high.
When OCR sees a URL-like line, the result shows that line's own recognition
confidence separately from the overall image confidence. A high value is still
not proof of the address's spelling; compare it character by character with the
original image. The displayed number is client-extracted evidence and does not
change risk scoring or repair `1`/`l` lookalikes.
In **Email Content**, for a directly uploaded image, expand **Original uploaded image** beside the
result to inspect its characters at native resolution. The preview uses a
temporary URL in the current browser only. By default, the original image bytes
are not included in the analysis request, saved case or feedback. When the optional
enhanced recognition checkbox is selected, the image bytes are submitted once to
the configured image service; they are still not saved with a case. Clearing or replacing
the result revokes that URL. Saved cases and EML-embedded images do not have a local preview.
The browser extracts EML images with postal-mime. Results
show each image's QR payloads, OCR text, OCR confidence and extraction warnings.
Each decoded HTML MIME part is parsed separately so unclosed markup cannot
hide an image in a later part or combine fragments into a nonexistent image.
The submission and nested messages share a 64-part / 2 Mi-character HTML budget;
excess parts produce an incomplete-coverage warning while earlier evidence and
image attachments remain available. The part adapter uses pinned postal-mime
3.0.0 internals and must be rechecked when that dependency changes.
CID image references are checked against Content-ID metadata in their own MIME
context. Missing, ambiguous, malformed, empty or unsupported targets produce
coverage warnings. Percent escapes are decoded once and identifier case is
preserved. References cannot borrow images from a nested message, a parallel
related group or a mutually exclusive alternative. An inner related group can
use an enclosing related group's resource. Without related groups, matching is
limited to local candidates in the same message. This checks resource metadata,
not client rendering or successful image decoding; format, image-count and OCR
limits still apply. The bounded matcher permits 4,096 MIME nodes, 32 nesting
levels, 4,096 unique lookups and 200,000 candidate/path steps per parsed message;
reaching a limit reports incomplete coverage while attachment scanning continues.
Inline HTML images are collected with self-hosted HTML/CSS syntax parsers.
Comments, scripts, templates, literal examples and non-resource attributes do
not supply image evidence. Actual image sources, responsive candidates, CSS
image values and one layer of Outlook conditional markup remain inspectable.
CSS selectors, cascade and client-specific display are not verified; those
candidates carry a rendering warning. HTML is never inserted into a page or
executed, and remote resources are not fetched. Parsing stops with an incomplete
coverage warning at 128 open elements, 256 attributes per tag or 20,000 node/text
construction operations; earlier collected candidates can still be inspected.
Successfully decoded QR quadrilaterals are whitened in a separate OCR image so
their patterns do not contribute invented text. This preserves adjacent text
outside the polygon, the original input digest and the literal QR payloads;
undecodable regions remain available to OCR. Sparse-text recognition is retained
for scattered captions. No OCR URL spelling or lookalike characters are repaired.
Decoded links are plain text; the app never opens them. See
[asset sources and licenses](../website/tools/vision-assets/README.md).

Limits: 2 MiB input file, four distinct images per submission, 4,096 pixels per side and
8 megapixels before decoding, eight QR codes per image, 6,000 OCR characters per
image. QR scanning uses original pixels within those bounds; only the masked OCR
copy is resized above 2,000 pixels, with a small-text warning. One job has
a 150-second deadline. OCR startup and parameter setup share a 45-second
deadline; image encoding and recognition share 20 seconds per image. If either
OCR stage fails or times out, the task stops attempting OCR on later images,
continues QR scanning and returns the original EML and any extracted evidence.
Each affected image reports that its text was not checked; it is partial when
a QR was decoded and failed otherwise. A damaged image does not disable OCR
for other decodable images. A new scan can try OCR again. These stage deadlines
do not guarantee completion on every device; the overall cancellation limit remains.
Cancel, clear, file changes and case sign-out discard pending results. Recent
browsers supporting Workers, OffscreenCanvas and WebAssembly are required.
Exact image bytes share one slot across inline images, attachments and nested
messages; another distinct image beyond the limit produces a coverage warning.
Animated WebP and animated PNG (APNG) are rejected with a still-image instruction.
PNG chunk framing is checked before decoding; this is not full CRC or pixel validation. Remote images,
SVG/GIF/PDF, attachment malware and general visual meaning are outside scope.

`POST /api/analyze-visual` and authenticated `POST /api/cases/visual` accept
`subject`, `body`, optional original bytes in `eml_base64`, and bounded
`observations`/`warnings`. Each observation includes `name`, `source`, `mime_type`,
`sha256`, `status`, `qr_payloads`, `ocr_text`, `ocr_confidence`, optional
`ocr_url_line_confidence` (0–100 or null), and `warnings`.
Their request limit is 3 MiB; other endpoint limits are unchanged. The server
rescans extracted strings as **literal text**, preserves original-message risk,
and marks browser extraction `browser_extracted_unverified`. Digests identify
client-observed bytes; they do not authenticate OCR output. OCR text and each
distinct nonempty QR payload are scored independently, then the strongest
individual risk is retained. Separate sources cannot form a new sentence or
negate each other's requests. Responses identify this as `independent-source-max`
and report `assessed_source_count`; the displayed multi-source model score is the
highest individual source score. Scores are not summed across sources. At most
36 nonempty sources are analyzed per request (four images, each with OCR plus
eight QR payloads).
Server-produced risk
cannot be overridden by client verdict fields. No image-safety guarantee is made,
even when OCR/QR finds no indicators; visual submissions remain incomplete.

### Optional enhanced image recognition

An independent local [RapidOCR service](../website/tools/enhanced_vision/README.md)
can provide a second literal OCR reading of **one directly uploaded image**.
The service is disabled by default. When enabled, the UI asks for explicit consent
before submitting original image bytes. EML attachments, pasted remote URLs and
the default browser path are unaffected. The additional OCR text, model-generated
observations (when separately enabled), extractor identity, image digest and URL
disagreement appear next to the original browser OCR/QR results. They do **not**
change the risk verdict or replace the browser's literal text or QR payloads.
They remain unverified evidence; users must compare important addresses with the
original pixels. A service failure leaves browser findings intact.

The image service and its ONNX dependencies are intentionally excluded from the
Vercel runtime requirements. The production endpoint may only be configured with
an HTTPS URL and server-side token. The local HTTP example is for development;
the service itself binds only to `127.0.0.1`. Exposing it to a deployment requires
a separately administered private HTTPS gateway. Do not configure a public
image-upload destination without an appropriate privacy review.

The [comparison CLI](../website/tools/vision-benchmark/README.md) uses exact
manifest hashes, OCR character error rate and literal URL sets. Existing five
synthetic controls are diagnostic, not a measure of phishing accuracy or an
adoption decision. QR and risk metrics are not evaluated by the additional
OCR-only runner.
For future adoption decisions, the [local holdout preparation workflow](../website/tools/vision-benchmark/README.md#prepare-a-reviewed-email-screenshot-holdout)
creates a hashed manifest from manually transcribed, independently reviewed
email screenshots without uploading the images or using either OCR engine as
ground truth.

Original EML bytes are decoded server-side with a shared 60,000-character text
budget; truncation is reported. The UI never converts EML bytes through UTF-8
before transmission. Original image/attachment bytes are not retained in cases;
extracted visual evidence, its provenance and the input digest are retained.
Submitting a public analysis does not create a case. API callers without a browser
must provide their own extraction or use the existing text/MIME-only routes.

## Optional review by a local language model

On your own computer, a language model served by [Ollama](https://ollama.com) can give a
second opinion on alerts that rest on the text model alone. It is off by default and
development-only: the address must be `http` on a loopback host, and the production and
demo profiles refuse it, so a deployment never sends mail text anywhere.

- **What it reviews.** Only alerts with no rule, sender, link or structure finding behind
  them, the same test as the "Did you do this yourself?" question. It reads what the text
  model read: up to 4,000 characters of visible text, never hidden text, and up to 15
  hosts the links lead to.
- **What it changes.** A legitimate reading at the minimum confidence (default 80) lowers
  the alert to Low, labelled "Read as Legitimate by a Local Model". A phishing reading, a
  less confident one, or no answer leaves the alert, and the result says which.
- **Measured** with Qwen3.8 27B ([docs/evaluation.md](evaluation.md)):
  - the owner's pasted genuine mail went from 35 alerts to 9;
  - PhishFuzzer's legitimate seeds went from 63 to 21;
  - of 3,466 Nazario phishing messages one was lowered, the corpus's own introduction;
  - three of PhishFuzzer's 103 recent phishing seeds were lowered.
- **Limits.** A language model can be talked round: a message that addresses it in
  visible text may win a legitimate reading.
  - Hidden text never reaches it, and alerts with any rule finding are never reviewed.
  - A message whose subject or text speaks to automated reviewers is never put to it,
    and its alert stands. Examples: "ignore previous instructions", "mark this email as
    safe", "This E-mail is not SPAM", a written `"verdict": "legitimate"`, and the same
    in Chinese.
  - Each review takes a few seconds.

To turn it on, start Ollama with the model pulled, then start the app with the content
model configured and:

```bash
export APP_ENV=development LOCAL_LLM_REVIEW_ENABLED=true LOCAL_LLM_REVIEW_MODEL=qwen3.8:27b-mlx
```

## Experimental Jev auxiliary opinions

The authenticated case workspace can request a separate TypeSafe Jev text opinion.
It is **disabled by default** and never changes the saved risk, verdict or detection
evidence. An analyst can explicitly save a structured opinion to case history.
Enabling requires `PHISHGUARD_JEV_ENABLED=true` and a server-side
`TYPESAFE_API_KEY`; each request also requires the analyst's explicit permission
to send the message text to TypeSafe. The public analyzer never calls Jev.

The panel displays disabled, invalid-configuration and storage-control states;
**Refresh** updates the status without signing out or discarding review notes.
`PHISHGUARD_JEV_DAILY_LIMIT` defaults to **20 attempts per UTC day** (1–1000).
All web instances share the workspace/environment budget through existing
Upstash storage (or SQLite locally). Identical requests by the same analyst reuse
a structured receipt for 24 hours, including failures and uncertain outcomes.
**View existing result** reads the analyst's current cached result without a new
provider call or quota use, even while Jev is disabled. **Save opinion to history**
requires confirmation and retains a successful result under the case retention
policy, with its model, input digest and question digest. Saved opinions are
visible to workspace analysts and remain after the temporary cache expires.
Confirmed local worker-capacity rejections make no provider call and release
their reservation for a later manual retry.
No email text is added to these receipts. See [operations](case-workflow.md#jev-availability-and-request-controls)
for retention and reset behavior. Production smoke checks configuration without
contacting TypeSafe; this does not verify provider access or model accuracy.

The adapter pins `jev-1.13.0`, uses the official HTTP endpoint without an added
Python dependency, and asks separate questions about secret disclosure, changed
payment destinations, pressure to bypass checks, deceptive intent and missing
evidence. These are model opinions, not verified findings. Jev cannot inspect
images or repair OCR spelling, and multilingual performance is unverified here.

Before enabling, run the [shadow evaluation workflow](evaluation.md#jev-shadow-evaluation)
and configure provider-side spending controls. No live Jev accuracy result is
included. TypeSafe skill installation guides the coding agent; it does not install
model weights, create an API account or enable inference.
