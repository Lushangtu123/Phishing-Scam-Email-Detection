# Design: PhishGuard's own DKIM verification of an uploaded message

**Status: design and criteria only.** The owner approved this design work on 2026-10-15.

- Nothing is implemented or enabled.
- Implementing it, turning it on and letting it affect any verdict are three separate later
  decisions.
- It must stay apart from the 2026-10-13 evaluation plan's baseline: see "Freeze" below.

## Why

Today an uploaded `.eml` is judged authenticated only through evidence of these kinds
(`email_structure.analyze_raw_email`, field `authentication_source`):

| Source | What it is | Its limit |
|---|---|---|
| `mailbox` | The topmost `Authentication-Results` written by the mailbox the user says they downloaded from (Gmail `mx.google.com`, Outlook `mx.microsoft.com`) | The choice of mailbox is the user's declaration; the file's origin is not proven |
| `server` | An `Authentication-Results` header whose authserv-id the deployment trusts (`TRUSTED_AUTHSERV_IDS`) | Holds only behind an entry point that removes forged headers |
| `arc` | The sealed results of an ARC chain PhishGuard verifies itself, sealed by a known mailbox service (today `google.com`) | Outlook's downloads rewrite the message, so their seals do not verify |

Every other result header is recorded as an untrusted claim (`untrusted_authentication_claims`).

What is missing is PhishGuard checking the message's own **DKIM signatures** against the
uploaded bytes. This is cryptographic evidence that does not depend on where the file came from
or on what any header says ([RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376)).

## What a DKIM pass shows, and what it does not

**A valid signature shows** that the holder of a key published under the signing domain (`d=`)
signed these header fields and this body, or the stated part of it, at signing time.

**It does not show:**

- **where the file came from:** a genuine signed message can be saved, replayed or re-uploaded;
- **who the sender is, or that they are trustworthy:** it only names the domain that signed;
- **that the content is safe:** a phishing domain can sign its own mail;
- **anything about the body after the `l=` length**, when the signature sets one;
- **forgery, when an old message fails:** its key may have been rotated away since.

The wording must therefore name the evidence: "PhishGuard verified the DKIM signature of
example.com". It must say whether that domain is aligned with the `From` domain. It must never
say that the message, sender or email "is verified".

## Design

1. **Input.** The raw bytes exactly as uploaded:
   - before any decoding, normalisation or line-ending change;
   - within the existing upload limit.

   A message whose bytes were altered on the way, for example when line endings were rewritten,
   is reported as failing. The failure is not hidden.
2. **Verification.**
   - **Library:** dkimpy, already pinned (1.1.8) and used for ARC; no new dependency.
   - **Which signatures:** each `DKIM-Signature` header, at most 5 per message.
   - **Algorithms:** `rsa-sha1` signatures are not accepted
     ([RFC 8301](https://datatracker.ietf.org/doc/html/rfc8301)).
3. **DNS.**
   - Only TXT lookups of `<selector>._domainkey.<domain>`.
   - Through a guarded resolver like ARC's: at most 2 seconds a lookup and 5 lookups a message,
     4 seconds in all.
   - On a small bounded pool, so slow DNS never holds the analysis workers. When the pool is busy
     or the budget is spent, the result is "could not be checked".
   - A short-lived key cache, as for ARC.
4. **Results per signature:** the signing domain `d=`, the selector `s=`, the algorithm, whether
   `l=` limits the body, and one of:
   - **`pass`**: the signature verifies;
   - **`fail`**: body hash or signature mismatch;
   - **`permerror`**: malformed signature, no key, revoked key (`p=` empty), or unaccepted algorithm;
   - **`temperror`**: DNS timeout or failure, budget spent, or pool busy.
5. **Message summary**, with these states kept apart:
   - **no signature;**
   - **at least one passing signature;**
   - **signatures, none passing, at least one definite failure;**
   - **could not be checked**, when only `temperror`.
6. **Alignment** with the single `From` domain, after
   [RFC 7489 §3.1.1](https://datatracker.ietf.org/doc/html/rfc7489#section-3.1.1):
   - relaxed: the same organisational domain;
   - strict: the same domain.

   Both are reported for each passing signature. With several `From` addresses, alignment is not
   assessed.
7. **A separate evidence type.**
   - **New field.** The result is a new field (working name `dkim_verification`). It is not a
     new value of `authentication_source`.
   - **ARC stays separate.** ARC keeps its own evidence type and is never merged with it.
   - **Nothing else changes.** `mailbox`, `server` and `arc` keep their meaning.
8. **Display wording** (English and Chinese, reviewed with the owner before any UI change):
   - **pass:** "PhishGuard verified the DKIM signature of example.com. Aligned with the From
     domain: yes/no."
   - **fail:** "A DKIM signature of example.com did not verify."
   - **no signature:** "The message has no DKIM signature."
   - **could not be checked:** "PhishGuard could not check the DKIM signature (DNS did not answer
     in time)."
   - **Every passing result adds:** "A valid signature shows that example.com signed this content.
     It does not show where the file came from, who wrote it, or that it is safe."
9. **Phase 1 has no effect on any verdict.**
   - **Unchanged:** the risk level, total score, `fusion_basis`, `authenticated_sender`,
     `verified_official_sender`, the abstention and the mail-type note.
   - **Shown only:** the result appears as information.
   - **Off by default:** a server setting (working name `DKIM_SELF_VERIFICATION`), off by default.
     No request can turn it on.
10. **Phase 2 is a separate decision** after its own evaluation. It asks whether a self-verified,
    aligned DKIM pass may stand in for a provider's result in `authenticated_sender`.
    - It needs its own criteria fixed in advance and its own data.
    - It is not part of the 2026-10-13 plan's holdout.

## Freeze

The 2026-10-13 plan's holdout is scored once, at a frozen commit.

- **Default off until then.** Until that scoring is done, DKIM self-verification either does not
  land on `main`, or lands off by default with criterion 2 below shown.
- **Recorded off.** The frozen configuration records the setting as off.
- **Nothing it touches changes during scoring:** `authenticated_sender`, the fusion and any level
  stay as they are.

## Security and privacy

- **DNS discloses the signing domain and selector to the resolver**, as ARC verification already
  does. Nothing from the message body is sent.
- **Untrusted input.** Malformed headers and signatures are handled as such, with the size,
  signature-count and time limits above.
- **No network in tests.** Tests use a stub resolver and keys generated for the test.
- **Logging.** No header or key is logged.

## Criteria for the implementation (fixed now, before any implementation or measurement)

1. **Synthetic messages**, signed with locally generated test keys served by a stub resolver. Each
   case gives the stated result:

   | Case | Expected result |
   |---|---|
   | Intact message | `pass` |
   | Changed body | `fail` |
   | Changed signed header | `fail` |
   | Key not found | `permerror` |
   | Revoked key | `permerror` |
   | Malformed signature | `permerror` |
   | `rsa-sha1` | `permerror` (not accepted) |
   | DNS timeout or busy pool | `temperror`, "could not be checked" |
   | No signature | "no signature" |
   | `l=` shorter than the body | `pass`, flagged as partial |
   | Rewritten line endings | `fail` |
   | Two signatures, one aligned and one not | each reported, alignment correct |

   Relaxed and strict alignment are correct. Disabling the verification makes these tests fail.
2. **Off by default.** With the setting off, a golden replay against `main` is byte-identical. The
   replay covers the unit suite's inputs, the intent fixtures and every 40th public-corpus row.
3. **On, phase 1.** For every replay item, the risk level, total score, `fusion_basis`,
   `authenticated_sender` and `verified_official_sender` are byte-identical to the setting off.
   Only the new field and its information items differ.
4. **Development measurement**, counts only, on `.eml` already allowed for development: the
   owner's 2026-10-05 downloads and the phishing_pot pilot. It reports:
   - the number of messages in each summary state;
   - the number of aligned passes;
   - the added latency (median and 95th percentile). The 95th percentile must not exceed the
     4-second cap.

   No holdout mail is used.
5. **Wording.** Every user-facing string names the evidence ("DKIM signature of <domain>") and
   alignment. None says the message, sender or email is verified. The owner reviews the English
   and Chinese text.

## Open questions for the owner

- **Display.** Phase 1 results in the user interface, or in the API and case record only at first?
- **DNS budget.** Shared with ARC, or its own?
- **Several `From` addresses.** Should their signatures still be shown, without alignment?
