# Deployment, configuration and Python environments

## Runtime configuration

| Variable | Default | Purpose |
|---|---:|---|
| `APP_ENV` | `production` | `development`, `demo`, `production`, or `test` |
| `VERIFICATION_MODE` | `off` | `off`, public-safe `lite`, or local-only `full` |
| `ENABLE_EMAIL_VERIFICATION` | `false` | Legacy local full-mode switch; public full mode is rejected |
| `ENABLE_DOMAIN_VERIFICATION` | `false` | Legacy-compatible switch for Lite domain checks when no explicit mode is set |
| `ENABLE_SMTP_VERIFICATION` | `false` | Legacy-compatible full-mode switch; rejected in public profiles |
| `VERIFICATION_WORKERS` | `10` | Bounded per-process verification jobs (`4` in the Vercel profile) |
| `ANALYSIS_WORKERS` | `4` | Per-process non-queueing parsing/rule/model workers, from 1 through 16; busy requests return retryable 503 |
| `CONTENT_MODEL_ENABLED` | `false` | Loads a verified offline email-text artifact |
| `CONTENT_MODEL_ARTIFACT` | empty | Path to the trusted artifact created by `prebuild_demo_model.py` |
| `CONTENT_MODEL_ARTIFACT_SHA256` | empty | Required SHA-256 digest for the configured artifact |
| `LOCAL_LLM_REVIEW_ENABLED` | `false` | Development only: a language model on this computer reviews alerts that rest on the text model alone |
| `LOCAL_LLM_REVIEW_URL` | `http://127.0.0.1:11434` | Ollama's address: `http` on a loopback host only, and refused in the production and demo profiles |
| `LOCAL_LLM_REVIEW_MODEL` | empty | Required with the review: a model name as `ollama list` shows it |
| `LOCAL_LLM_REVIEW_MIN_CONFIDENCE` | `80` | How sure (50–100) a legitimate reading must be to lower the alert |
| `LOCAL_LLM_REVIEW_SHADOW` | `false` | Record the review's reading without changing the verdict ([rollout plan](llm-review-rollout.md)) |
| `TRUSTED_AUTHSERV_IDS` | empty | Comma-separated authentication service IDs allowed to affect raw-message risk |
| `SENDER_HISTORY_ENABLED` | `false` | Enables optional service-retained sender history and distributed API limiting when all secrets are valid |
| `UPSTASH_REDIS_REST_URL` | empty | HTTPS REST endpoint for an Upstash Redis database (`*.upstash.io`) |
| `UPSTASH_REDIS_REST_TOKEN` | empty | Server-side Upstash REST token; never expose or commit it |
| `SENDER_HISTORY_HMAC_KEY` | empty | Private random key of at least 32 bytes used to derive opaque sender identifiers |
| `SENDER_HISTORY_RETENTION_DAYS` | `90` | Sliding history retention, from 1 through 365 days |
| `SENDER_HISTORY_TIMEOUT_SECONDS` | `1.0` | Fail-open Upstash deadline, from 0.1 through 3.0 seconds |
| `DISTRIBUTED_RATE_LIMIT_ENABLED` | unset | `true` enables shared limits independently of sender history; unset preserves the legacy history-configured limiter; `false` explicitly disables shared limits |
| `RATE_LIMIT_REDIS_REST_URL`, `RATE_LIMIT_REDIS_REST_TOKEN` | empty | Optional dedicated limiter connection; otherwise uses `UPSTASH_REDIS_REST_*` |
| `RATE_LIMIT_HMAC_KEY` | empty | At least 32 bytes for opaque client identifiers; otherwise reuses `SENDER_HISTORY_HMAC_KEY` |
| `RATE_LIMIT_TIMEOUT_SECONDS` | `1.0` | Dedicated limiter deadline, finite and from 0.1 through 3.0 seconds |
| `RATE_LIMIT_BUCKET_CAPACITY` | `4096` | Hard bound for in-process rate-limit keys |
| `MAX_REQUEST_BYTES` | `65536` | Actual HTTP request-body byte limit before decoding; applies without Content-Length |
| `CUSTOM_DOMAINS` | empty | Comma-separated custom hostnames appended to `ALLOWED_HOSTS` |
| `CONTENT_MODEL_USE_REAL` | profile-dependent | Offline training: load local public corpora |
| `CONTENT_MODEL_AUTO_DOWNLOAD` | profile-dependent | Offline training: download configured public corpora when missing |
| `CONTENT_MODEL_USE_CACHE` | `false` | Offline training: explicitly trust/load the local pickle cache |
| `CONTENT_MODEL_AUGMENT_SYNTHETIC` | `false` | Opts into bundled template augmentation for experiments |

The included Render blueprint explicitly sets `CONTENT_MODEL_ENABLED=false`
and `ENABLE_EMAIL_VERIFICATION=false`. The public
demo therefore starts reliably with sender, header, structure, and content-rule
analysis, without presenting a synthetic model as production evidence.

## Vercel Hobby deployment

The repository root is a Vercel-native FastAPI project. Its committed profile
uses one Fluid-compute Python Function, four bounded verification workers, and
`VERIFICATION_MODE=lite`. Lite mode performs format, MX/A/AAAA, SPF, DMARC, PTR,
and best-effort WHOIS checks. It never opens an SMTP connection and returns
`overall=domain_valid` rather than claiming that the mailbox or sender is
verified. The response separates `domain_verification` from
`mailbox_verification`; the latter is `unavailable` on this profile.

The Vercel runtime installs pinned NumPy, SciPy, scikit-learn, joblib, and
threadpoolctl versions for inference but not pandas. These are the versions
validated by the current serving smoke test; the committed model predates
dependency-version recording, so they do not prove its original training
environment. Training remains local-only. When the artifact at
`website/model/content_model_artifact.pkl` is present, `vercel.json` must
contain its exact SHA-256 digest and enable the model. The committed artifact
was saved with scikit-learn 1.9.0. Both the Vercel runtime and local
evaluation requirements pin that exact version.
Startup verifies the digest before deserializing and rejects scikit-learn
estimator version warnings, including patch-version mismatches. New artifacts
record the full scikit-learn version, Python version, and exact versions of the
core numerical dependencies. The loaders reject a recorded runtime dependency
mismatch before serving predictions. Legacy artifacts without this metadata
remain loadable, but cannot establish numerical-dependency parity with their
training run. A rejected or missing artifact leaves rule and structure
analysis available and reports the model error through
`/health`. Successful health and metrics responses expose the loaded artifact
digest and a short `model_id`, so displayed metrics can be tied to the
deployed binary rather than a different training run.

The `/health` response also exposes the full Git commit SHA from Vercel's
`VERCEL_GIT_COMMIT_SHA` system environment variable. Enable System Environment
Variables in the Vercel project settings if that field is null. The production
deployment smoke check requires this SHA to match the deployment event before
it sends analysis controls; an alias still serving older code will fail the
check even when the model artifact has not changed.

Model explanations cache their immutable 80,000-feature name/coefficient arrays
and calculate contributors directly from the sparse request vector. This keeps
the displayed terms unchanged without allocating one dense feature array for
every request.

Before attaching a custom domain, add its apex and optional `www` hostname to
the Vercel `CUSTOM_DOMAINS` environment variable, for example
`phishguard.example,www.phishguard.example`, and redeploy. Do not include a URL
scheme or path. The default `*.vercel.app` allow-list remains active.

Deploy from the repository root with Vercel CLI 48.1.8 or newer, or import the
Git repository in the Vercel dashboard. The deployment is intended for a
personal/course demonstration. It always keeps a bounded in-memory limiter; when
the optional Upstash configuration is ready, POST requests also use an atomic,
HMAC-keyed distributed limit shared by Vercel instances. Upstash failure fails
open to the existing local limiter so detection remains available.
Shared limiting can be enabled with `DISTRIBUTED_RATE_LIMIT_ENABLED=true` while
`SENDER_HISTORY_ENABLED=false`; configure the dedicated Redis variables above or
reuse the Upstash connection with a private `RATE_LIMIT_HMAC_KEY`. This does not
create sender observations. Explicitly enabled but malformed limiter settings
block API mutations and report `distributed_rate_limit_status=configuration_error`
in `/health`, rather than silently removing the requested shared budget.
`configured` describes configuration readiness, not continuous Redis reachability.
When the shared service times out, the local limiter remains the fallback.
CI uses its isolated Redis service to exercise the production limiter's Lua
through the same Upstash-style pipeline request shape, including concurrent
limits, minute/hour TTLs and independent routes. For a local run, set
`PHISHGUARD_TEST_REDIS_PORT` only to an existing trusted localhost Redis port;
the integration case skips when it is unset. It uses random HMAC-derived keys
and deletes them afterward. A skipped local case does not prove Redis behavior.

In-process budgets group case paths together and unknown API paths together,
so arbitrary IDs and unknown paths cannot create unlimited buckets. At hard
capacity, new client groups are denied until an expired slot is reclaimed;
active budgets are never evicted. This can temporarily deny new clients under
capacity pressure. Parsing, sender-candidate selection, content rules and model prediction run in a bounded
worker pool so long analysis does not block the ASGI event loop. Saturation returns
503 with `Retry-After: 1`; it does not queue unbounded work or change risk scoring.
The Vercel profile uses only a single syntactically valid platform-normalized
`X-Forwarded-For` address as the local-limit identity; ambiguous lists and
invalid values fall back to the ASGI peer. Other deployment profiles ignore
that header rather than trusting arbitrary forwarding input.

Email bodies and attachment content are processed server-side for analysis and
are not retained by this application. When sender history is enabled, a
pseudonymous sender observation may be retained as described above. Users
should remove unrelated personal content before submitting an email.

### Optional free sender-history store

[Upstash Redis currently offers a $0 tier for hobby projects](https://upstash.com/pricing/redis),
and Vercel can provision and link it through the
[Upstash Marketplace integration](https://vercel.com/marketplace/upstash).
Limits and pricing can change, so confirm the current plan before provisioning.
The detector remains fully usable without this optional store.

1. In the Vercel project, open **Storage**, choose **Create Database**, select
   **Upstash Redis**, choose the Free plan, and connect it to this project.
2. Confirm Vercel added `UPSTASH_REDIS_REST_URL` and
   `UPSTASH_REDIS_REST_TOKEN` for the Production environment.
3. Generate a private HMAC key locally with `openssl rand -hex 32`. Add the
   output as `SENDER_HISTORY_HMAC_KEY` in Vercel; do not put it in Git.
4. Add `SENDER_HISTORY_ENABLED=true`. Optionally set retention and timeout using
   the variables in the configuration table above.
5. Redeploy, then confirm `/health` reports
   `sender_history_enabled: true`, `sender_history_configured: true`, and
   `sender_history_available: true`.

Missing, partial, malformed, or unreachable configuration disables only history
evidence. Analysis continues, and the UI reports history as unavailable rather
than treating an absent result as “never seen.”
The `configured` and backward-compatible `available` fields describe startup
configuration readiness; they are not a continuous Upstash reachability probe.

Vercel production `deployment_status` events run
`.github/workflows/post-deploy-smoke.yml`. The workflow checks out the deployed
revision and validates `/health`, `/api/config`, the exact model ID, phishing and
legitimate controls, and a unique first/previous sender-history probe against the
public production alias. It rejects cross-host redirects and non-JSON responses,
so Vercel SSO pages cannot be mistaken for application health output.
Read-only health/config readiness checks retry briefly while a deployment alias
converges; phishing, legitimate, and sender-history POST controls run exactly
once after the expected model and configuration are ready.
With `--check-frontend` (enabled in the workflow) it also checks what browsers
receive from the production alias: homepage and `/cases` CSP (`script-src
'self'`, `style-src 'self'`, no `'unsafe-inline'`) and `nosniff`; `br`/`gzip`/`zstd`
compression and the versioned-asset `Cache-Control` (`public, max-age=86400`;
Vercel strips `stale-while-revalidate` from browser responses) on `style.css`,
`i18n.js` and `app-core.js`; an uncached HTML 404 page for unknown page URLs and a JSON
404 for unknown `/api/` paths; and `no-store` plus `noindex` on `/cases`. Every
check runs and all problems are reported together.
Feature-branch pushes run CI, but the production smoke job only runs after a
successful Production deployment event. After merging a reviewed PR, check
that `/health` reports the merged commit SHA and that the production smoke job
completed successfully; a skipped branch run is not production verification.

## Python environments

Use Python **3.12** when loading or rebuilding the committed model. The artifact
loader checks Python major/minor compatibility and exact recorded numerical
package versions; installing a newer scikit-learn independently can make an
otherwise valid artifact unloadable.

All commands below run from the repository root in a dedicated virtual
environment. The entry points share the canonical serving pins in
`requirements.txt`:

| Environment | Install command | Purpose |
|---|---|---|
| Serving | `python -m pip install -r requirements.txt` | Inference and domain checks; excludes pandas/notebooks |
| Email-model research | `python -m pip install -r website/requirements.txt` | Serving stack plus pinned pandas for offline builds/evaluation |
| Development | `python -m pip install -r requirements-dev.txt` | Research stack plus HTTP integration-test client |
| Notebook benchmark | `python -m pip install -r phishing-detection/requirements.txt` | Shared model versions plus plotting, Jupyter and UCI download tools |

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip check
```

On Windows, activate with `.venv\Scripts\activate`. The requirement files pin
direct serving dependencies; they are **not full transitive lockfiles**. The
resolved `requirements-dev-py312-macos-arm64.lock.txt` snapshot records all 35
installed development packages from a clean Python 3.12.14 macOS arm64
environment, including transitive dependencies. To reproduce that package set
on the same platform, install it in a fresh environment instead of the direct
development requirements:

```bash
python -m pip install -r requirements-dev-py312-macos-arm64.lock.txt
python -m pip check
```

This snapshot has no wheel hashes and is not a verified Linux/Windows,
Python 3.13, production deployment, or notebook-training lock. Notebook extras
retain bounded version ranges. For a training experiment, retain
`python -m pip freeze` and the Python/platform details alongside the dataset and
artifact provenance; rerun compatibility checks and evaluation when updating
dependencies. Production CI separately validates the deployment requirements.

For local research with the text model, train and package it before starting the
web service:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r website/requirements.txt
cd website
python prebuild_demo_model.py --output ../phishing-detection/data/content_model_artifact.pkl
# Copy the printed SHA-256 value into CONTENT_MODEL_ARTIFACT_SHA256.
APP_ENV=development CONTENT_MODEL_ENABLED=true \
  CONTENT_MODEL_ARTIFACT=../phishing-detection/data/content_model_artifact.pkl \
  CONTENT_MODEL_ARTIFACT_SHA256=REPLACE_WITH_PRINTED_SHA256 \
  uvicorn app:app --host 127.0.0.1 --port 8000
```

Only load artifacts produced and stored by a trusted build process. The digest
is checked before deserialization, and Python/scikit-learn compatibility metadata
is validated afterward. New builds record the training environment in
`build_provenance` and the serving dependencies in the artifact envelope. Keep
the pinned runtime requirements aligned with those recorded versions when
publishing a newly built artifact; a saved artifact is rejected if its core
packages changed between training and packaging.

To opt into network-based mailbox verification locally, additionally set
`ENABLE_EMAIL_VERIFICATION=true`. Do not expose that endpoint anonymously.

`APP_ENV=development` allows this opt-in but does not enable it by itself.
For local mailbox checks without the optional text model, run from the repository root:

```bash
APP_ENV=development ENABLE_EMAIL_VERIFICATION=true CONTENT_MODEL_ENABLED=false \
  .venv/bin/uvicorn app:app --app-dir website --host 127.0.0.1 --port 8000
```

Restart after changing environment variables, then reload the browser.
`GET /api/config` exposes `deployment_profile` and the independent feature flags;
the UI distinguishes local-disabled, public-disabled, and unavailable configuration.
DNS/WHOIS records and SMTP probes do not authenticate a particular email, and an
SMTP timeout does not prove whether a mailbox exists.
SMTP rejection is interpreted conservatively: a permanent `5.1.1` response means
the server reports a missing mailbox; `5.7.*` policy rejection, `5.2.2` mailbox-full,
and generic rejection remain inconclusive. `smtp_result` can now include
`policy_rejected` and `mailbox_full`. Existing `exists`/`verified` API values are
retained for compatibility but mean only that the server accepted the address,
not guaranteed delivery or sender authenticity. The UI uses “SMTP Accepted”.
See [enhanced SMTP status codes](https://www.rfc-editor.org/rfc/rfc3463.html).

A sole Null MX (`0 .`) returns `null_mx=true`, `mx_found=false`, and
`overall=no_mail_service`, without A-record fallback or further probing. Mixed
or nonzero-preference Null MX configurations are inconclusive. Declaring no mail
service is not phishing evidence; see [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html#section-3).
When no MX record exists, discovery tries A and AAAA records within the shared
deadline. An IPv6-only address record can establish an implicit mail host; it
does not establish mailbox existence. Only definitive absence of both address
types yields the no-records verdict. If neither succeeds and either lookup fails
or times out, the result stays `unverifiable`. Null MX never uses this fallback.

Local verification has a **12-second response deadline**, including initial DNS
discovery. Queries use a shared pool with at most **10 outstanding jobs per
process** and no unbounded waiting queue. At capacity, discovery returns HTTP 503
with `Retry-After`; individual unavailable checks are reported explicitly.
`verification_complete=false` identifies unfinished/unavailable work. DNS timeouts
remain “Unverifiable” in the UI rather than becoming an invalid-mailbox verdict.
Each executed SPF, DMARC, WHOIS, and PTR check now carries `status`; SMTP exposes
`smtp_status`. `ok` and successful `not_found` results count as completed checks,
while `timeout`, `error`, `busy`, `unavailable`, and `skipped` do not. Completion
describes check execution, not address validity. A fast caught exception therefore
cannot produce a complete-verification claim. A partial result preserves any
SMTP evidence and visibly warns “Verification Incomplete”. Early exits such as
Null MX skip remaining checks and retain `verification_complete=false`.

SPF/DMARC TXT fragments within a DNS record are concatenated without inserting
spaces or display quotes. SPF summaries use complete mechanisms in order (including
the implicit `+` in `all`), not substrings inside domain names. DMARC summaries
read individual tags, not policy-looking text inside reporting addresses. Multiple
policy records, recognized malformed SPF term shapes, duplicate DMARC tags, and
invalid DMARC policy/percentage values report an error and incomplete verification.
These are bounded policy summaries: they do not recursively evaluate SPF
include/redirect, expand macros, implement full SPF syntax validation, or authenticate
a particular message. DMARC organizational-domain policy discovery remains unsupported.
DNS lookups use explicit lifetimes, WHOIS uses a 5-second socket timeout, and SMTP
uses a per-probe deadline with socket cleanup. Running threads cannot be forcibly
cancelled; they retain their capacity slot until they actually exit. The response
deadline is not a guarantee that every underlying network operation has stopped.

All HTTP request bodies are bounded by received bytes, including chunked JSON
requests and requests whose length header understates the body. The `.eml`
endpoint additionally retains its stricter 60,000-byte file limit.
