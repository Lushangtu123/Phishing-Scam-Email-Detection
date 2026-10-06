# Testing

GitHub Actions runs the development suite on both Python 3.12 and 3.13,
including HTML recovery regressions that must not depend on standard-library
exceptions. Original-byte evaluation parsing is tested on both versions without
loading the committed model. Tests that load that Python 3.12 artifact are skipped
on incompatible interpreters; the loader's version checks remain enforced.
A separate Python 3.12 job installs the root Vercel dependencies,
checks their consistency, verifies the committed model digest, starts the real
Lite profile with ML enabled, and performs phishing-positive and legitimate-
negative prediction smoke tests. It also uploads original MIME bytes for a
phishing positive control and an uncertain-rendering control.
A lint job runs pinned `ruff` with `ruff.toml`, which enables only syntax
errors and pyflakes defects (undefined names, unused imports and variables);
style rules and exploratory notebooks are out of scope.
Versioned static URLs (`/static/app.js?v=46`) are cached by browsers for a day,
so a changed file needs a new `?v=`. `website/tools/asset-versions/manifest.json`
pins each versioned file's version and SHA-256, and
`website/static/asset-versions.test.mjs` fails when a file changes without a
bump. After editing such a file, run
`node website/tools/asset-versions/update.mjs`: it bumps the integer `?v=`
everywhere the file is referenced (repeating when a bump changes another
versioned file, such as `vision.js` referencing `vision-worker.mjs`) and
rewrites the manifest. Non-integer versions such as Chart.js `4.4.0` are
changed by hand.
A separate deployment-status workflow checks the completed public Vercel
deployment's commit SHA, model digest, and JSON and raw `.eml` controls rather
than assuming that the source checkout represents its bundle. It performs six
POST requests when sender-history checks are enabled, within the committed
10-per-minute per-client limit when no other traffic shares the same rate-limit
bucket.
A `visual` CI job compares 17 screenshots of the homepage (navbar and hero,
sender and content results, a Chinese result, the 390 px menu and the 404 page,
in light and dark at 1280 and 390 px) with committed baselines. It runs in the
pinned Playwright container, serves `website/static/` with a small Node server
and answers the API from fixtures captured from the real backend. Baselines come
only from that container, through the manual **Visual baselines** workflow; see
`website/tools/visual/README.md`.

```bash
# From repository root, after installing requirements-dev.txt
python -m unittest discover -s website/tests -v
python -m compileall -q website phishing-detection/src
python -m pip install ruff==0.16.9 && ruff check .   # optional local lint gate
node --test website/static/app.test.mjs website/static/i18n.test.mjs website/static/cases.test.mjs website/static/page-loading.test.mjs website/static/request.test.mjs
for f in website/static/app*.js website/static/i18n.js website/static/i18n-zh.js website/static/lang-init.js website/static/request.js website/static/cases.js website/tests/fixtures/i18n/*cases*.mjs; do node --check "$f"; done
node website/tools/asset-versions/update.mjs   # after editing a versioned static file
git diff --check
```

The regression suite covers sender-score semantics, authentication-service
trust, protected-brand/IDN and digit-substitution impersonation, Public Suffix
registrable-domain parsing, SMTP public-address enforcement,
bounded rate limiting, verified model artifacts, HTML destination mismatch,
ASCII brand lookalikes, URL userinfo, attachment MIME types, raw-message sender
fusion, footer spoofing, regional-language neutrality, conservative evidence
fusion, group isolation, deployment flags, and frontend payload/rendering
behavior. Disposable-address regressions cover multi-label provider domains,
random-looking Gmail and Outlook mailboxes, versioned privacy relays,
provider-aware plus aliases, Gmail/Googlemail dot variants, and custom-domain
local parts that must not be merged without known provider semantics.
