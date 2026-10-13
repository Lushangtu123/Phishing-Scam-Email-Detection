# Evaluation plan: model-only alerts on original messages, and intent rules

Status (2026-10-13, revision 3):

- **D1–D11 are locked** at the values below, by the owner, as of this file's commit. A value
  changed after any holdout result has been seen invalidates that holdout (AGENTS.md: "fix the
  pass criteria in writing before a measurement runs").
- **D12 is open:** the independent reviewer is **to be determined and not yet assigned**.
  `reviewer-01` is only a reserved ID.
- **The plan as a whole is not frozen.** No holdout is scored until the reviewer is assigned and
  recorded here in a later commit; that commit freezes the plan.
- **Until then**, work may continue on the evaluation tooling, the synthetic regression and
  development data, and the collection of new mail.
- **Holdout mail is isolated meanwhile:**
  - it is stored apart from development data;
  - it is not opened to develop or tune rules;
  - no evaluation result on it is run or looked at before the freeze.

The plan evaluates two questions separately, and accepts them separately:

1. How an original message (`.eml`, `raw_email`, a visual upload's email) is shown when only
   the text model alerts.
2. Two intent rules: a request to hand over a login secret, and a request to pay to a changed
   destination.

Revision 2 answers the first review. That review found two blockers:

- the review state of option C could count as fewer misses;
- the two parts used one holdout one after the other.

It also asked for four further things:

- authenticated phishing in the comparison;
- evaluator support for both mailbox settings, with public samples kept apart;
- minimum samples for each intent rule;
- a statement of whether thresholds apply to observed counts or interval bounds.

Revision 3 answers the second review. Its blocker: rules must be accepted separately, which
needs 12 configurations, not 6. It also asked for four further things:

- abstention stated exactly;
- quoted text judged by context;
- the 400-message floor and the decisive authenticated subset made explicit;
- how the reviewer works, what "insufficient evidence" means, and per-message counting for the
  combination.

## Why

- `fuse_content_risk` (`website/app.py`) turns a model alert with no rule, sender, link or
  structure support (`fusion_basis == "model_only"`) into **Low — Text Model Signal Only** when
  the input is an original message. Pasted text and screenshots stay **Medium — Model Signal
  Needs Review**. The owner chose this on 2026-10-05 (docs/evaluation.md, "Model-only note
  limited to original messages") to remove false alerts on genuine account notices.
- The 2026-10-13 review points out that this keys on the **input path**, not on authentication.
  Reading headers and finding nothing is not evidence of a trustworthy source. An authenticated
  source is not evidence of harmless content either: `authenticated_sender` holds for any
  non-consumer domain with an aligned DMARC pass, including a domain an attacker owns.
- Reproduced on `main` before #60: "send us the six digit verification code" from a personal
  Gmail address, uploaded as `.eml`, was Low while the model scored it as phishing. #60 fixed
  that wording. Any request the rules miss still falls to Low the same way.
- Two synthetic messages were Low with low model scores: an indirect request for the "secret
  phrase" used to sign in, and a request to settle a debt to new "beneficiary coordinates".
  The optional local review reads only Medium and High alerts that rest on the text model, and
  can only lower them (`_apply_local_review`), so no review model can raise these. Keyword
  patches for those two sentences would not generalize.

## Part 1: model-only alerts on original messages

### Options compared

Only results with `fusion_basis == "model_only"` on an original message change. Everything that
runs after fusion stays as it is in all three options:

- a verified official sender is still lowered to Low;
- the reader's "did you request this" answer still applies.

**Abstention is kept, exactly.** `_apply_abstention` turns a result into Unknown only when a
blocking warning remains **and** the level is Safe, or the level is Low and one of three things
holds: the rendering is uncertain, the main content is an unchecked remote image, or the model
could not score the text. A Medium or higher result is never turned into Unknown.

Raising A's Low to B's Medium, or to C's review state, would therefore skip an abstention A
applies. Rule for B and C: **wherever A's result is Unknown, B's and C's are Unknown too.** The
abstention test runs on A's level, before the option relabels. Unit tests cover each condition
above for B and C, including the verified-sender exception inside `_apply_abstention`.

| Option | Model-only alert on an original message |
|---|---|
| **A. Current** | Low — Text Model Signal Only; counted at most 29% |
| **B. Unauthenticated keeps Medium** | Low note only when `authenticated_sender` or `verified_official_sender` is set (a trusted, aligned DMARC pass on a non-consumer domain); otherwise Medium — Model Signal Needs Review, as for pasted text |
| **C. Explicit review state** | Neither an alert nor a pass: "Needs review — the text model alerts and nothing independent supports it", shown in amber with guidance |

**Known blind spot of all three:** a message sent through a genuine service whose domain is a
verified official sender (a fraudulent invoice from the service's own address) is lowered to
Low after fusion, whatever the option. That cohort is reported, not decided by this plan.

**Mailbox setting:** a trusted DMARC result exists only when the reader names their mailbox, or
when the message carries a verified Google ARC seal. With neither, every sender is
unauthenticated, so B behaves like "Medium everywhere". Real downloads are therefore scored
twice: with no mailbox chosen, and with their verified provider chosen.

### How it is measured

- **No offline reconstruction.** Each option is a value of an evaluation-only parameter of the
  fusion step. The default is A, the served behaviour, and the parameter is not reachable from
  any request. The evaluator runs the complete pipeline once per option and mailbox setting on
  the same inputs, so every later step applies exactly as served.
- **Evidence that the parameter changes nothing by default:**
  - a golden replay shows A byte-identical to `main` on the unit tests' inputs and on the
    development set;
  - unit tests cover B and C, including their interaction with a verified sender, Unknown and
    the reader's answer.
- **Evaluator change:** `evaluate_serving_pipeline.py` gains `--mailbox-setting none|recorded`.
  `recorded` passes the row's verified provider to `analyze_raw_email(mailbox_provider=...)`;
  today the provider is only a reporting field.
- Reports hold counts only, with no text, addresses, subjects or URLs (AGENTS.md).

### Metrics, per cohort, mailbox setting and option

| On phishing | On legitimate mail |
|---|---|
| **Alert rate:** Medium or above | **False-alert rate:** Medium or above |
| **Review rate:** C's review state | **Review rate:** C's review state |
| **False-pass rate:** Safe or Low, neither alert nor review | **Attention rate:** alerts plus reviews, the human cost |
| **Unknown rate** | **Unknown rate** |

- **Reading the metrics:**
  - A review item is not a detection. This plan measures no human review outcome, so
    **detection gain is alerts only**.
  - A review item on phishing reduces false passes. On legitimate mail it costs attention as
    much as a false alert does.
  - Unknown is never a correct nonalert and never a detection.
- **Reported separately:**
  - **authenticated phishing:** phishing whose sender is authenticated under the true mailbox
    setting, whether from an attacker's own domain or a genuine service;
  - the verified-official-sender blind spot above;
  - each provider × language cell.
- Exact counts with 95% Wilson intervals. No pooled accuracy.

### Acceptance (to confirm)

Thresholds apply to the **observed counts at the sample sizes fixed in D10**. Every result is
also reported with its Wilson interval. Passing does not show that the true rate is below the
threshold. For example, 0 false alerts in 100 legitimate messages still allows up to 3.7%, and
an upper bound of 1% needs at least 381 legitimate messages with no false alert.

| | Proposed value |
|---|---|
| **[D1] Attention budget** | On legitimate holdout mail, an option may add at most **2 percentage points** of attention (alerts plus reviews) over A in each mailbox setting, and at most **10%** attention in total |
| **[D2] False-alert budget** | Of that, at most **2 percentage points** more false alerts than A |
| **[D3] False-pass reduction** | On phishing holdout mail, the option must turn at least **one third** of A's false passes into alerts or reviews, and at least **3 messages**. It is named a false-pass reduction, not a detection gain |
| **[D4] Authenticated phishing** | Its false passes are reported for every option. No option may have more false passes there than A. Reported apart: the **decisive subset**, authenticated by a non-official domain (`authenticated_sender` without `verified_official_sender`) and model-only under A, the only messages on which B and C differ |
| **[D5] Decision rule** | Among options meeting D1–D4, take the one with the fewest false passes; on a tie, the one with fewer false alerts on legitimate mail. If none qualifies, keep A |

**Insufficient evidence.** A criterion whose minimum sample (D10, D11) is not met is recorded as
**insufficient evidence**: neither a pass nor a failure. An option or rule that depends on it is
not accepted.

## Part 2: intent rules

The rules look for the **behaviour**, not the two sentences that were missed.

### Behaviours

1. **Credential handover.** The message asks the reader to give a login secret to a person, or
   to enter it where the claimed organisation is not. Login secrets include passwords,
   passphrases, recovery phrases, one-time codes and PINs, and paraphrases such as "the phrase
   you use to sign in". It needs an act (send, reply with, enter, confirm, verify, provide), a
   secret, and a destination: a reply, a person, or a link whose host is unrelated to the
   sender's or claimed brand's domain. These may span **adjacent sentences** and a
   **link in another paragraph**.
2. **Payment redirection.** The message changes where money goes (new or updated beneficiary,
   bank account, IBAN, routing, sort code, wallet) **and** either asks for a payment to it or
   discourages the usual check: do not call, urgent, confidential, or "these details replace any
   on file".

The negation and attribution guard of the sensitive-request rules applies **to the object it
governs only**. "Never share your password; send us the code instead" still matches on the
code.

**Quoted text is judged by its role, not by its quoting:**

- A request presented as someone else's, in a warning or report, does not count. Examples:
  "Scammers may ask you to 'send the code you received'", or "we will never ask you to …".
- Quoted, forwarded or "see below" text that the message asks the reader to act on counts.
  Examples: "please send the code as described in the message below", or a forwarded request
  with "do this today".

Each rule is written in English and Chinese, and each sets a Medium floor.

### Controls the rules must not fire on

- A genuine password reset that links to the brand's own domain, or says "we will never ask for
  your password".
- An official one-time-code notice ("your code is …, do not share it").
- A genuine supplier bank-change notice that sends verification through a known channel
  ("confirm with your account manager on the number you already have").
- A payroll or direct-deposit change confirmation ("if this wasn't you, contact HR").
- An invoice or receipt whose payee has not changed.
- Warnings that quote these scams as examples.

### Required tests, beyond the controls

- A request split across two sentences.
- An act and a secret in one paragraph with the link in another.
- Negation scoped to one object of two.
- A quoted scam inside a warning, which must not count.
- A quoted or forwarded request the message tells the reader to follow, which must count.
- The same behaviours in Chinese.

### Development

- **Development set:**
  - public corpora (already in the training pool, so suitable for development only);
  - newly authored synthetic positives and controls in both languages;
  - the development half of the fresh data below.
- **Regression only:** the two reproduced misses, the 21 synthetic audit messages and #60's
  reproduction.

### Acceptance (to confirm), per rule and language

| | Proposed value |
|---|---|
| **[D6] False rule hits** | At most **2%** of legitimate holdout messages match the rule, **whether or not** their level rises: a wrong hit still misleads the explanation. At most **1** match among the control-type messages |
| **[D7] New false alerts** | At most **1%** of legitimate holdout messages rise to Medium or above because of the rule |
| **[D8] Public corpora** | At most **0.1%** of legitimate public rows match: 36,567 rows today, so at most 36 |
| **[D9] Target behaviour** | Of holdout phishing tagged with the rule's behaviour, at least **50%** reach Medium or above with the rule, and the rule adds at least **3** that A missed |

**Each rule is accepted as a whole, English and Chinese together.** Both languages must meet
D11 and D6–D9. A rule that lacks D11's minimum in either language is insufficient evidence and
is not accepted. No configuration enables one language of a rule alone.

## Holdout use: one pre-registered comparison

To avoid using one holdout twice, **every candidate is frozen before any holdout result is
seen**:

- the three options;
- both rules, developed on development data only.

The holdout is then scored once, for **12 configurations**: A, B and C, each with no rule, the
credential rule only, the payment rule only, and both rules. Every combination that the
separate decisions could produce is therefore measured.

- **Per component:** each option is judged on its no-rule configuration against D1–D5. Each
  rule is judged against D6–D9 by adding it to A alone, and its effect is also reported with
  each other option.
- **The combination proposed for deployment** must itself meet D1, D2 and D7. Its new false
  alerts are counted **per message, deduplicated**: a message raised by two rules counts once,
  and two rules passing separately do not make their combination pass.

If the rules are not ready when Part 1's data is, Part 1 waits. The alternative is a second
holdout collected after a new cut-off for Part 2. Once scored, a holdout becomes development
data.

## Data

### Fresh mail, sources kept apart

- **[D10] Cut-off and sizes.** Only mail that arrives after **2026-10-14** counts as fresh.
  Holdout targets for real downloads:
  - at least 50 unique messages per class in each Gmail/Outlook × English/Chinese cell (the
    existing release-review floor). That is **at least 400 unique messages**, which also covers
    "100 legitimate and 100 phishing".
  - Scoring the same messages under both mailbox settings adds **no** independent samples.
    Every size counts unique messages.
  - At least **30 authenticated phishing** messages, from at least 10 families.
  - Of those, at least **10 in the decisive subset** of D4, from at least 5 families. With fewer,
    D4 is insufficient evidence and B is not accepted.

  Mail already looked at is development or regression data only:
  - the owner's 2026-10-05 downloads;
  - UniqueData, Nazario 2023–25 and the phishing_pot pilot;
  - the audit messages.
- **Real downloads**, the only source for the provider cells and for authenticated phishing:
  - the owner's own Gmail and Outlook downloads;
  - a dedicated test mailbox signed up to common services, which collects codes, sign-ins,
    resets, billing and supplier-style mail;
  - phishing the owner receives.

  Provider and received date come from the provider's own records, not the `Date` header.
- **Public samples** (for example phishing_pot): an upstream commit after the cut-off does not
  mean the mail was received after it, and their provider is unknown. They form a separate
  **public, provenance unverified** cohort:
  - scored with no mailbox chosen only;
  - never counted toward D10's provider cells or the authenticated cohort;
  - downloaded only with the owner's approval.
- **[D11] Minimums for the intent rules**, holdout phishing tagged by behaviour:
  - credential handover: at least **40 English** messages from 15 families and **20 Chinese**
    messages from 8 families;
  - payment redirection: at least **30 English** messages from 10 families and **15 Chinese**
    messages from 6 families;
  - each control type: at least **20 English** legitimate messages from 10 organisations and
    **10 Chinese**.
- **Families.** A family is the sending organisation for legitimate mail, and for phishing the
  campaign: sender domain, subject template and landing host. A family is never split between
  development and holdout, and contributes at most 3 holdout messages.
- **[D12] Labels.** The owner labels and tags behaviours. Every holdout label and behaviour tag
  is then reviewed by an independent reviewer:
  - **Status:** to be determined, not yet assigned. `reviewer-01` is a reserved ID only.
  - **Who:** a classmate or teacher who took no part in developing the candidates or in the
    initial labelling, and who can check mail headers and provenance evidence.
  - **Recorded at the freeze:** their role and a pseudonymous ID.
  - **How:** they review the original evidence without seeing any candidate's output. An AI
    may help organise the material; the final label and behaviour tag are theirs.
  - `build_private_cohort.py` enforces distinct reviewer IDs and family separation.
- **Storage.** Private mail stays outside Git (AGENTS.md). Reports and docs hold counts only.

## Order of work

1. D1–D11 are locked (this commit). The plan is frozen by a later commit that records the
   reviewer's role and pseudonymous ID (D12). Steps 2–4 may proceed before then; step 5 may not.
2. Tooling PR:
   - the evaluation-only fusion parameter, shown not to change behaviour by a golden replay;
   - `--mailbox-setting` in the evaluator;
   - an evaluator option that runs a named configuration (option, credential rule on or off,
     payment rule on or off) and records it in the report;
   - per-configuration metrics, and per-message deduplicated counts for combinations.
3. Collect fresh mail until D10 and D11 are met, then build development and holdout cohorts.
   Holdout mail stays isolated as described in the status above.
4. Develop the two rules on development data, then freeze the rules and options. While they are
   developed, the rules ship **off** by default, behind the same evaluation-only switches, so no
   rule reaches production before its decision.
5. Score the holdout once for all 12 configurations and report against D1–D9 in
   `docs/evaluation.md`, with insufficient evidence marked. The owner decides; the chosen parts
   are implemented in their own PRs.

## Limits

- Labels, provenance and reviewer independence are attested by people. The tools check
  consistency, not truth.
- At these sizes the result picks between configurations. It does not certify a detection or
  false-alert rate.
- Authenticated phishing and the verified-sender blind spot may be hard to collect.
  - B leaves authenticated phishing at Low, as A does, while C flags it for review. Without D10's
    authenticated minimum, that difference is unmeasured, so **B cannot be accepted**.
  - C, which does not depend on authentication, is still compared.
- Out of scope:
  - pasted text and screenshots, which stay Medium for model-only alerts;
  - the text model itself;
  - the optional local LLM review.
