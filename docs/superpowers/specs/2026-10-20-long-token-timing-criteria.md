# Criteria: analysis time of one long whitespace-free token

**Status: criteria only.** Drafted on 2026-10-20 at the owner's request, and committed before the
first measurement. A later change is a new, dated version of this file, with its reason.

- Every input is synthetic and built by a seeded script. No private mail, no file of the owner's
  archive, no download.
- Nothing here changes the model, a rule, a weight, a threshold or an input limit.

## Why

`docs/evaluation.md`, "P1/P2 pairing tool (2026-10-20)", records a finding made in passing: a
plain-text `.eml` whose body is one 55,000-character token took the served analysis about 10
seconds, and ordinary lines of the same length 0.34 seconds. It was measured once and not
again. The owner asked for it to be followed up on its own.

## The question

1. Does analysis time grow faster than the length of one whitespace-free token? For which token
   shapes and input modes?
2. Which step does it?
3. Is there a fix that leaves every analysis result byte-identical?

## Not the question

- **No denial-of-service claim.** Whether the served site can be made unavailable depends on
  concurrency, the rate limit, the analysis pool and Vercel's 30-second `maxDuration`. None of
  these is measured here. Results are single-process wall times on one machine, offline.
- **No change to detection.** The model, rules, weights, thresholds and the input limits
  (60,000 bytes per `.eml`, subject 500 and body 50,000 characters) stay as they are.

## Inputs (seed 20261020)

**Token shapes:**

| | Shape |
|---|---|
| S1 | one letter repeated (`a` × n) |
| S2 | random lowercase letters and digits |
| S3 | random characters of the base64 alphabet (`A-Z a-z 0-9 + /`) |
| S4 | host-like: `x1.` repeated, cut to n |
| S5 | URL-like: `https://example.com/` and random `[a-z0-9/_-]`, cut to n |
| S6 | word-like: `word-` repeated, cut to n |
| S7 | random Han characters (U+4E00 to U+62FF) |

**Control:** ordinary lines of the same length in characters: random lowercase words of 3 to 9
letters, separated by spaces, lines of at most 76 characters.

**Modes:**

| | Mode | Path |
|---|---|---|
| E-plain | `.eml`, `text/plain; charset=utf-8`, 8bit | `analyze_record` with mailbox `none` |
| E-html | `.eml`, `text/html`, the token as the text of one `<p>` | same |
| E-href | `.eml`, `text/html`, `<a href="https://example.com/TOKEN">Open</a>` | same |
| P-body | pasted subject `Synthetic` and the token as body | `analyze_record` on a pasted row |
| P-subject | pasted: the token as subject (n = 500), and a short ordinary body | same |

**Lengths n:** 1,000, 5,000, 10,000, 20,000, 40,000, and the largest length that fits the mode's
limit (`n_max`):

- 55,000 for `.eml` modes, which is the original observation's length;
- for S7 in `.eml` modes, the largest n that fits in 60,000 bytes with the headers;
- 50,000 for P-body;
- 500 for P-subject.

Grid lengths above `n_max` are skipped.

**Outside the served limits:** 100,000 characters, only to measure the growth of the step found,
called directly. It is labelled as unservable wherever it is reported.

## Configuration

- **Interpreter and model.** The repository's `.venv` (Python 3.12.9) and the committed model
  (`sha256:a0a503a0…`). Model-only option A, intent rules off, mailbox `none`.
- **Environment.** `evaluation_environment(<vercel.json env>, ())` from
  `evaluate_serving_pipeline.py`, set before `app` is imported, as `main()` does. This turns RDAP,
  sender history, Jev, the local review, email verification and case management off.
  `PYTHONHASHSEED=0`.
- **Network.** Each run is inside `blocked_network()` (`website/tests/network_guard.py`), in
  process. A recorded attempt voids the run, and the attempt is reported.
- **Timing.** `time.perf_counter` around `analyze_raw_email` and `_analyze_content` separately.
  One warm-up analysis per process, discarded. Then three runs per input, and the median is
  reported. The machine is recorded. cProfile runs separately, so its overhead never enters a
  timing.
- **Baseline.** `main` at `343af047ed78809b50b04b71c7d913762ffdf184`.

## Definitions

- **T(shape, mode, n):** the median time of a token input. **C(mode, n):** the median time of the
  control.
- **Affected:** a cell with T > max(3 × C, C + 1.0 s) at the same mode and n.
- **Grows faster than linear:** T(40,000) / T(20,000) > 2.5.
- **Reproduced:** at least one shape in E-plain has T ≥ 5 s at 55,000, while C ≤ 1 s. If no
  shape reproduces it, the report says so, and names the shapes tried.
- **Located:** one function accounts for at least 50% of T in cProfile (cumulative time) for an
  affected cell at `n_max`, and a direct call of that function on the same token shows the same
  growth.

## Pass criteria for a fix

| | Criterion |
|---|---|
| F1 Time | For every shape and mode at `n_max`: T ≤ max(3 × C, C + 0.5 s). For every shape in E-plain, E-html, E-href and P-body where 40,000 fits: T(40,000) / T(20,000) ≤ 2.5 |
| F2 Same results | A golden replay, on `main` at the baseline and on the branch, is byte-identical. It compares the result JSON of `_analyze_content`, `analyze_email_content`, `analyze_sms` and `analyze_raw_email` on (a) every call the unit suite makes to them, captured during a full run; (b) a seeded sample of the public corpora in `phishing-detection/data`, as pasted subject and body; (c) the whole synthetic grid, controls included. Any difference fails the fix |
| F3 Function-level check | If the changed code is a regular expression or a tokenizer, the old and new versions return identical results on at least 20,000 seeded random strings over the characters they treat specially, and on every input the replay passes to them |
| F4 Coverage | The replay executes every changed statement. The share is reported |
| F5 Planted defects | At least one plausible defect in the changed code makes the replay or a test fail. Reverting the fix makes the regression test fail |
| F6 Regression test | It fails on the baseline and passes with the fix. Any time bound is at least 10 times the fixed time and at most a third of the baseline time, so it does not flake |
| F7 Checks | The unit suite, `compileall`, `ruff` and the Node tests pass locally, and the six required CI checks pass |
| F8 Scope | No change to the model, a rule, a weight, a threshold or an input limit. No new dependency |

## Reporting

- Every cell of the grid, against these criteria, failures included, before and after any fix, on
  the same machine in the same session.
- If no fix meets F1 to F8, none is proposed, and only the findings are reported.
- Claims stay within "this machine, one process, offline configuration".
