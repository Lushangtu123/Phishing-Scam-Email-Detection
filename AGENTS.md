# Working on PhishGuard

Instructions for AI coding agents (Codex, Claude Code, Cursor and others) and for people working
the same way. PhishGuard is an explainable phishing and scam detector: a FastAPI backend in
`website/` (served from `app.py` at the root on Vercel), a vanilla-JS frontend in `website/static/`,
and research code in `phishing-detection/`. The site is in production at
<https://phishguard-email-analyzer.vercel.app>.

## Branches, pull requests and releases

- **Never push to `main`.** The "Protect main" ruleset requires a pull request and six passing
  checks from GitHub Actions: `lint`, `test (3.12)`, `test (3.13)`, `vercel-runtime`,
  `optional-vision` and `Visual regression (Playwright container)`. Work on a branch and open a PR.
  If a CI job is renamed, the required list in the ruleset must be renamed with it.
- **Merge only when the owner says so**, and only the commit that CI tested:
  `gh pr merge <n> --merge --match-head-commit <sha>`. Never force-push or rebase a shared branch;
  to bring a branch up to date, merge `main` into it.
- **After a merge, check production:** the merge commit's `Vercel` status and the post-deploy smoke
  run that is not skipped (`.github/workflows/post-deploy-smoke.yml`). Vercel promotes a deployment
  only after the main-branch CI passes. A CI job that failed for an outside reason (a registry pull
  limit, a runner fault) is rerun with `gh run rerun <id> --failed`; Vercel then promotes on its own.
- **Vercel builds only `main` and `preview-*` branches** (`vercel.json`), and the Hobby plan allows
  100 deployments a day, cancelled builds included. Name a branch `preview-…` when Vercel's own
  build must be seen before merging: dependency upgrades and changes to `vercel.json`,
  `pyproject.toml`, `uv.lock` or `.vercelignore`. Preview deployments sit behind Vercel login.
- Never delete the teammates' branches `origin/Minh` and `origin/jchanges`.

## Checks to run before opening a PR

From the repository root, with `requirements-dev.txt` installed (see `docs/testing.md`):

```bash
python -m unittest discover -s website/tests
python -m compileall -q website phishing-detection/src
ruff check .
node --test website/static/*.test.mjs
```

- After editing a versioned static file (`?v=` in the HTML), run
  `node website/tools/asset-versions/update.mjs`; CI fails when a file changes without a new version.
  Versioned files are cached for a year (`immutable`), so a missed bump would be served stale.
- Frontend tests read some backend sources by name (for example `i18n.test.mjs` reads
  `content_rules.py`), so run both suites whatever you changed.
- After a visible frontend change, regenerate the screenshots in the Playwright container:
  `gh workflow run visual-baselines.yml --ref <branch>`, download the `visual-baselines` artifact,
  compare each image with the committed one and commit the reviewed images
  (`website/tools/visual/README.md`).

## CHANGELOG

Every change a reviewer would care about gets an entry at the top of `CHANGELOG.md` in the format of
`.cursor/rules/changelog.mdc` (Why, Files changed, Effect; Pacific time; concrete numbers). Do not
edit old entries; correct them with a new one. Each month is moved to `docs/changelog/YYYY-MM.md`
when it ends. Two PRs that both add an entry conflict at the top: keep both, newest first.

## Dependencies: a 7-day cooling period

- Use only releases published at least seven days earlier. Python versions are locked in `uv.lock`
  with `[tool.uv] exclude-newer` in `pyproject.toml`; the upgrade steps are in
  `docs/deployment.md`. Say which newer releases were held back and why.
- The same applies to GitHub Actions, which are pinned to commit SHAs with the release in a comment,
  and to container images, which are pinned to a digest. Do not use floating tags such as `@v7`.
- scikit-learn cannot move, not even a patch version, without rebuilding and re-evaluating the
  committed model: the loaders reject an artifact pickled with another version.

## The owner's private data

- The owner's own mail, text messages, labels and any model trained on them stay **outside the
  repository** and are never committed, uploaded or deployed. A model built with
  `--private-corpus` carries `private_training` and loads only with `APP_ENV=development`
  (`docs/llm-teacher.md`).
- Do not print or quote message text, addresses or subjects from private data in a conversation, a
  log, a report or a commit, unless the owner allows it for specific rows. Work with counts,
  hashes, column names and masked patterns; reports and docs hold counts only.
- Labels proposed by a model or an agent are not owner labels until the owner confirms them.

## Changing detection, models or evaluations

- Fix the pass criteria in writing **before** a measurement runs, keep them with its inputs, and
  report the result against them, including a failure. A set that has been looked at is no longer a
  held-out set; a new rule needs fresh data.
- Run local language models one at a time through a set: alternating two models per message makes
  Ollama swap them on the GPU and runs about ten times slower.
- Measure page speed and colours only in a foreground or headless browser; a background tab does
  not paint and reports stale styles.

## Refactoring

Refactors must not change behaviour, and the PR shows how that was checked: a golden replay that
runs the same inputs (the unit tests' calls, public corpus samples from `phishing-detection/data`,
never private data, and synthetic cases for missed branches) on `main` and on the branch and
compares the results byte for byte; statement coverage of the changed code; and a planted bug that
the replay must catch. A pure move can instead be shown with identical syntax trees. Examples:
the `app.py` split (PRs #29-#41) and PRs #53 and #54.
