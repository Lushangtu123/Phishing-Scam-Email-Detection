# SMS scam detection design

## Goal

Let a person paste a text message (SMS or iMessage) and, optionally, the number or address it
came from, and get an explainable risk verdict, as the email modes give. The owner receives
texts on a Chinese and a US number, so both regions are covered from the start.

The SMS mode is rule-based. It reuses the content rules that read plain text, the link checks
and the two official registries, and adds rules about the sender. It ships only after it meets
a launch gate, fixed in advance, on the owner's own messages.

## Scope

This change includes:

- `website/sms_analysis.py`: sender classification, brand claims, the SMS rules and the verdict;
- `POST /api/analyze-sms` behind the `SMS_ANALYSIS_ENABLED` flag, off in production until the gate passes;
- a third homepage tab, "SMS", with a sender field and a text field;
- `website/tools/evaluate_sms.py`, a counts-only evaluation tool;
- tests, documentation and changelog entries.

This change does not include:

- the text model: it was trained on email, and texts are short and worded differently;
- screenshot input (OCR): a later change, once pasted text is measured;
- a phone-number reputation service: no public, reliable source without accounts and fees;
- official SMS short codes in the registries (see "Known gaps");
- cases, sender history or report submission for texts.

## Design decisions

| Decision | Choice | Reason |
|---|---|---|
| Regions | China and the US | The owner can supply genuine and scam texts for both numbers |
| Input | Pasted text and an optional sender | Reading the sender from a Messages screenshot is unreliable: saved contacts show a name |
| Architecture | A separate module and endpoint | Email scoring, model fusion and short-text abstention were tuned for email; SMS weights must be calibrated on texts without changing any email result |
| Test data | The owner's texts, plus public datasets | The owner's texts decide the launch; public sets find rule gaps and measure false alerts at scale |

## Architecture

```text
browser ── POST /api/analyze-sms {sender, text} ──▶ app.py: validate, rate-limit
                                                     │
                                                     ▼
                                     app.analyze_sms(sender, text)
                                       ├─ sms_analysis.sms_findings  (sender kind, brand claim,
                                       │                              links, SMS rules)
                                       └─ reused plain-text, link and lure rules (app.py)
                                                     │
                                     app.py: RDAP registration date of up to 5 link domains
                                                     │
                                                     ▼
                                     result JSON, rendered by the existing result components
```

`sms_analysis.py` holds the parts only texts need, as pure functions, and imports nothing from
`app.py`: on Vercel the module named `app` is the root entrypoint, not `website/app.py`.
`app.analyze_sms` combines them with the shared rules, which live in `app.py`. `app.py` also adds
the request model, the endpoint and the asynchronous domain-age lookup, as the content mode does.

## Sender classification

`classify_sender(sender)` removes spaces, hyphens, dots and parentheses, converts full-width
digits (`９５５８８`) and strips zero-width characters. It recognises the `+86`, `0086` and
`+1` prefixes, then returns one kind. International and North American numbers are typed by
libphonenumber (`phonenumberslite`, offline metadata); Chinese 106 ports and short numbers keep
their own rules, which libphonenumber does not know:

| Kind | Examples |
|---|---|
| `short_code` (3–6 digits) | 95588, 10086, 12306, 28777 |
| `cn_port_106` (`106` and at least 5 more digits) | 1069… |
| `cn_mobile` (11 digits starting with `1[3-9]`) | 13812345678, +86 138… |
| `nanp_toll_free` (area code 800, 833, 844, 855, 866, 877 or 888) | (833) 555-0100 |
| `nanp_long_code` (other 10-digit North American numbers) | +1 212… |
| `premium_rate` (a premium-rate number in its numbering plan, from libphonenumber) | +1 900…, +44 909… |
| `international` (any other country code) | +63…, +44… |
| `other_number` (digits of no kind above: a landline, an unusual length) | +86 10 1234 5678 |
| `email` (an address, as iMessage shows it) | name@example.com |
| `alphanumeric` (a sender ID of letters) | USPS |
| `none` (empty or unreadable) | |

The submitted sender is never stored. The result returns only its kind.

## Brand claims

`claimed_brand(text)` finds the organisation a text says it comes from. A claim is either of:

- a signature at the start or end: `【…】` or `[…]`;
- an organisation name the text opens with, such as "工商银行提醒您" or "USPS: ".

Names come from the registries: the Chinese `claim_names` in `official_brands_cn.json` (not their
ASCII abbreviations such as ABC or CCB, which open many English texts) and `display_names` in
`official_brands_intl.json`. Services named only by a verified sender (`sender_only`) are left
out, as in email. Chinese names match as substrings, ASCII names on word boundaries. A brand
mentioned later in the text, as in a friend's "我用工行转你了", is not a claim: "within the first
20 characters" would have counted it.

## Rules

### New SMS rules

Each region has expected sender kinds: `short_code` and `cn_port_106` for organisations in
`official_brands_cn.json`; `short_code` and `nanp_toll_free` for those in
`official_brands_intl.json`. `none` and `alphanumeric` say nothing about the sender and give
no mismatch.

| Code | When | Initial weight |
|---|---|---|
| `sms.sender_mismatch` (strong) | A claimed organisation, and a sender of any other kind, except the weak case below | +4, at least Medium |
| `sms.sender_mismatch_weak` | An organisation in `official_brands_intl.json`, and a `nanp_long_code` sender: many genuine US businesses text from registered 10-digit numbers | +2, no floor |
| `sms.link_off_brand` | A claimed organisation, and a link whose host is neither one of its `official_domains` nor a subdomain of one | +2 |
| `sms.reopen_to_activate` | Instructions to reply (for example "Y") and then exit and reopen the text, or to copy the link into a browser, so that the link becomes active | +4, at least Medium |
| `sms.delivery_lure` | The parcel, fee and address wording of `_delivery_lure`, with a bare link whose organisational domain is not among the known tracking domains | +4, at least High, as the email rule |
| `sms.fine_lure` | `_fine_lure`: with no sender domain, any link host that is neither listed nor a government's | +4, at least High, as the email rule |
| `sms.premium_callback` | A request to call or text a number that a numbering plan lists as premium rate (US, UK or Chinese plan when no country code is given) | +4, at least Medium |
| `sms.prize_callback` | Prize or award wording ("won", not "won't"; "claim", "gift card", "awaits collection"…) and a request to call, text or dial a number of at least five digits (added in calibration, `docs/evaluation.md`) | +4, at least Medium |
| `sms.split_words` | Four or more symbols breaking up Chinese words ("佣.金", "微|信"); the rules read the text joined again (added in calibration on the owner's texts) | +4, at least Medium |
| `sms.external_contact_lure` | Easy money (rebates, commission, part-time pay, sure returns, gambling, refunds) and a move to a private messenger (WeChat, QQ, WhatsApp, Telegram; not a business's WeCom) (added in calibration on the owner's texts) | +4, at least Medium |
| `sms.job_offer` | A job with pay or hours, and a short link, a messenger or "send a message to this number" (added in calibration on the owner's texts) | +4, at least Medium |
| `sms.account_lure` | A bank, its points, security token, card limit or real-name records needing action, and a link outside the registries' official domains or a Chinese mobile number (added in calibration on the FBS development half) | +4, at least Medium |
| `sms.gambling_promo` | Two gambling terms, or one gambling term, rebate or deposit bonus with a sign-up, payout or bonus offer, and a link or a way to reach them (added on the FBS development half) | +4, at least Medium |
| `sms.prize_link` | Being picked or winning a large prize (cash, a laptop, a phone), wording to claim it, and a link outside the official domains (added on the FBS development half) | +4, at least Medium |
| `sms.flight_compensation` | A cancelled or delayed flight, compensation, and a number to call (added on the FBS development half) | +4, at least Medium |
| `sms.stock_group` | Stock tips and a group to join (added on the FBS development half) | +4, at least Medium |
| `sms.album_link` | Photos, an album or "you're in the news" with a hook to look ("你自己看", "看看我们…") and a link outside the official domains (added on the FBS development half) | +4, at least Medium |

The Chinese rules read the text with traditional and look-alike characters made plain (註冊,
婇票, 氺) and spaces between Chinese characters removed.

The two lures have their own codes because the Chinese wording of `content.fine_lure` and
`content.delivery_lure` says "邮件" (email).

So a text signed 【工商银行】 from a `+1` number is a strong mismatch, as is a "USPS" text from
an email address. "Reply Y to confirm your appointment" alone does not trigger
`sms.reopen_to_activate`.

**A matching sender never lowers the risk.** Sender numbers can be forged: ICBC's own page warns
that fraudsters send texts that appear to come from 95588. Sender rules only add points.

The weights above are starting values, calibrated on the development data (below).

### Reused rules

These read plain text and keep their email weights and floors. Where a rule's points are added
inside `analyze_email_content` (the keyword categories, `_fine_lure`), the scoring moves into a
small shared helper, so both modes use the same weights and email results do not change:

- the keyword categories (urgency, threats, credential requests, deception), including the
  Chinese phrases;
- `_sensitive_requests`: verification codes, passwords and card numbers;
- `_callback_request`, with the Chinese registry's service numbers excluded;
- `_analyze_link_destinations`: look-alike domains, IP-address links, free-hosting and
  development-hosting addresses;
- `_has_shortener_url`;
- the registration date of up to five link domains (new within 90 days).

### Not used

HTML and visibility analysis, presentation cues, SPF/DKIM/DMARC, attachments, the text model,
sender history, and the email rules that read button labels or a sender domain (other than the
SMS variant of `_delivery_lure`).

### Chinese lure phrases

The shared Chinese phrases came from Nazario email phishing (mailbox upgrades, "保持我的密码"),
so a text such as "【工商银行】您的账户已冻结，请立即点击…输入密码和验证码解冻" reaches only Low
through its link findings. Common Chinese text scams (ETC authentication, medical-insurance card suspension, points
redemption, parcel compensation, task-based "刷单" jobs) may need new phrases. Phrases are
written only from public data and the development batch, and judged on the held-out batch.

## Verdict

The rule score goes through `fuse_content_risk` with no model reading. Its scale is unchanged:
1–4 points Low, 5 or more Medium, 9 or more High, 13 or more Critical, with rule floors.

When no rule fires, the verdict is `unknown`, shown as "No Known Scam Signs Found", never Safe.
High and Critical texts get their own labels ("High Risk — Likely a Scam Text"), as the email
labels for those levels say "钓鱼邮件" in Chinese; Medium and Low share the email labels.
A text's sender cannot be verified, so the absence of known signs is not evidence of safety,
as in the short-message abstention design. Every result also says that a matching number can
be forged, and that an organisation should be contacted through its official app or the
number on the card.

The response has the shape of a content result (`risk_level`, `risk_label`, score, evidence
with codes and parameters), plus `sender_kind` and `claimed_brand`. Evidence messages are
added to `website/data/server_messages.json` and the English and Chinese front-end catalogues.

## API

`POST /api/analyze-sms` takes `{"sender": str (≤ 64 characters, optional), "text": str (1–2,000 characters)}`.

- An empty text returns 400. A too-long text or sender is rejected by the request model with 422,
  as on the other analysis endpoints, and the page limits both fields. Request bodies over 16,000
  bytes are refused before parsing.
- An unreadable sender is not an error; its kind is `none`.
- An RDAP failure or timeout gives no finding and a warning in the result, as in the content mode.
- With `SMS_ANALYSIS_ENABLED` off, the endpoint returns 404 and `/api/config` hides the tab.
- Rate limits, request size limits and security headers are those of the other analysis endpoints.

Links without a scheme (`ezpass-pay.com/x`) are recognised when `tldextract` finds a public
suffix, so `file.txt` is not a link. An IPv4 host counts after an explicit `http://` or `https://`.

## Front end

- A third tab, "SMS" / "短信", beside "Email Address" and "Email Content", with a sender field
  (placeholder "e.g. 95588, +1 833…, or an email address"), a text field with a character count,
  Ctrl/⌘ + Enter to analyse, the privacy notice and a few synthetic Chinese and English examples.
- The result uses the existing banner and evidence list, plus a "Sender" card: the sender's kind,
  the claimed organisation and the forged-number reminder.
- The three tabs fit at 375 px. Changed static files get new `?v=` versions, and the visual
  regression baselines are updated.

## Privacy

Texts are processed on the server, as email content is, and are not retained. Only the
registrable domains of up to five links are sent to the registry's public RDAP service. The
evaluation tool reports counts only.

## Evaluation and launch gate

### Data

- **The owner's texts**, from both numbers, scam and genuine. Genuine texts are mostly from
  organisations (codes, banks, deliveries, appointments), with a few personal texts that mention
  brands. They are kept outside the repository as JSONL with region, sender, text and label.
  Personal numbers are replaced by fake numbers of the same kind (13800000000). Names and codes
  are masked; links and number kinds are kept.
- **Two batches.** The first is for development. The second is held out and scored once, before
  launch.
- **From a Mac:** `website/tools/export_sms_from_messages.py extract` reads the Messages database
  read-only. It exports only one-way conversations (one other party, never answered), masks codes,
  card tails, the owner's numbers, email local parts and personal senders, and assigns batches;
  the owner labels `review.csv`, and `finish` writes `batch1.jsonl` and `batch2.jsonl`.
- **Public datasets**, for development and large-sample false alerts: the SMS phishing dataset
  of Mishra and Soni (about 6,000 texts, several hundred of them smishing) and the UCI SMS Spam
  Collection. Both are older and mostly English. Their licences and counts are checked, and
  the owner asked, before download.

`website/tools/evaluate_sms.py` reports, per cohort and label, the verdict counts, and how often
each rule fires on genuine texts. It writes no text, number or per-message row.

### Gate (fixed before the held-out run)

| Data | Requirement |
|---|---|
| Owner's genuine texts, held-out batch, each region | At most 4% Medium or above (about 2 in 50), none High or Critical |
| Owner's scam texts, held-out batch | At least 70% Medium or above |
| Public genuine texts | At most 2% Medium or above |

If the gate fails, the flag stays off and the results are documented.

## Launch status

On 2026-10-08 the owner turned the SMS mode on in production (`SMS_ANALYSIS_ENABLED=true` for
the Production environment in Vercel) as a test, before the launch gate was measured. The gate
above, the calibration on the owner's texts and the known gaps below still apply; the
results will be recorded in `docs/evaluation.md` and the rules updated then.

Update, 2026-10-08: with the owner's batch 3 and its supplement, normal texts meet the gate in both
regions (US 0 of 69, Chinese 0 of 52 at Medium or above). US scams meet it (11 of 12). Chinese scams do
not (2 of 5), so the mode stays a test until more Chinese scam texts are calibrated and held out.

## Tests

- `website/tests/test_sms_analysis.py`:
  - sender kinds for every example in the table, `+86`/`0086` prefixes and full-width digits;
  - brand claims from signatures and opening names, but not from a later mention;
  - each new rule, firing and not firing, including "Reply Y to confirm your appointment";
  - no rule fired gives `unknown`, never Safe; a matching official number never lowers the score.
- Endpoint tests: validation, the disabled flag, the response shape and the message catalogue
  for every new code.
- Front-end tests: English and Chinese strings, the tab at mobile width, visual baselines.
- Evaluation tool tests: counts only, with no text in the report.

## Documentation

An SMS section in `docs/detection-design.md`, the endpoint in `docs/api.md`, the measurement
in `docs/evaluation.md`, a README feature line, and a changelog entry for each change.

## Dependencies

The SMS mode reuses the free-hosting and development-hosting link rules of
Lushangtu123/Phishing-Scam-Email-Detection#11. Implementation starts from `main` once #11 is
merged, or stacks on #11 if it is not.

## Known gaps

- `official_brands_intl.json` has no names for some brands (Amazon), removed to avoid email
  false alerts. Texts claiming them do not trigger sender rules until names are added through
  the registry review.
- The registries do not list official SMS short codes (USPS 28777, for example). A later change
  can add them, with the registry's evidence gate, to name the official number in the result.
- Forged senders that match the official number are caught only by the content and link rules.
- VoIP numbers are not recognised where a country gives them no separate range (the US);
  line-type services would receive the reader's numbers and are not used.
- The impersonation keyword category is a list of brand names. A text that signs as a brand
  does not score that brand's own name (calibration, 2026-10-08), but an unsigned genuine text
  naming a brand still scores Low.
- `sms.prize_callback` would match genuine loyalty texts that offer reward points and a number
  to call; the public data has none to measure.
