# Official-brand registry: review checklist

`website/data/official_brands_intl.json` and `website/data/official_brands_cn.json` do
three things:

- A From display name that claims a listed organization, sent from another domain, is an
  impersonation finding.
- A trusted DMARC pass on a listed `official_domains` entry makes a **verified official
  sender**: the text model and weak rules alone cannot raise its mail above Low. A wrong
  domain is therefore a trust anchor that an attacker who can send from it may use.
- Results name the organization's official channels.

## Before adding or changing an entry

1. **Domain evidence.** Read a page on the organization's own site that names each official
   domain as a sending domain or a report address, and record its URL in `domain_sources`
   (HTTPS). A homepage shows where the site is, not where the mail comes from. "From prior
   knowledge" is not evidence.
2. **Relays.** Ask whether mail from the domain can carry someone else's content: shares,
   comments, invoices, money requests, marketplace or seller messages, issue notifications.
   If it can, list those addresses in `relay_addresses`, or leave the organization out.
   Cloudflare, Adobe and AliExpress were left out for this reason.
3. **Shared domains.** Customer-controlled or shared domains (`atlassian.net`, Zendesk
   subdomains, `onmicrosoft.com`) are never official.
4. **Display names.** No common words, first names or ambiguous acronyms (`Chase`, `Apple`,
   `UPS`, `BOC`); `test_registry_entries_are_complete_and_sourced` rejects the known ones.
   When other organizations' own mail carries the name (American Airlines Vacations, BMO
   Stadium), use a narrower name or register a `sender_only` service.
5. **Statements.** Quote `verified_statements` from the page itself, with its URL and
   `source_type`.
6. **Measure** before and after on the usual cohorts (`evaluate_serving_pipeline.py`,
   `evaluate_public_corpus.py`) and record the change in `docs/evaluation.md`.

A list of official websites, such as the owner's list of 460 common sites (2026-10-06), suggests
organizations to check. Its domains still need step 1.

## Recheck

Re-read every `domain_sources` page at least every six months, and whenever an
organization's own domain is reported sending phishing. Remove a domain that the page no
longer names.

## Pending confirmation

`website/tests/test_registry_evidence.py` lists the official domains that have no recorded
evidence at all: no `domain_sources` on their entry, no `verified_statements` page on the
domain, and no official contact address there. On 2026-10-05 there were 79, recorded before
per-domain evidence was required. Two are marked "from prior knowledge" in their own notes:
`jpmorganchase.com` (Chase) and `square.com` / `squareup.com` (Cash App).

The test fails when an entry adds a domain without evidence, and when a listed domain gains
evidence but stays on the list. Confirm the listed domains one by one and remove each from
the list; the list must only shrink.
