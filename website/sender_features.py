"""Sender-address feature extraction for PhishGuard.

Moved verbatim from ``app.py``: the known-domain registries, sender address
normalization, and ``extract_email_features``. ``app`` re-exports every name
defined here, so existing ``app.<name>`` references keep working.
"""

from __future__ import annotations

import math
import re

import tldextract

from disposable_registry import load_disposable_registry, load_privacy_relay_registry
from email_structure import _PROTECTED_BRAND_DOMAINS, normalize_domain
from sender_history import supports_plus_alias, uses_gmail_dot_aliasing

# ── Known domains ─────────────────────────────────────────────────────────────
LEGIT_PROVIDERS = {
     # Email providers
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
    'aol.com', 'protonmail.com', 'zoho.com', 'mail.com', 'yandex.com',
    'live.com', 'msn.com', 'me.com', 'apple.com', 'google.com',
    'microsoft.com', 'amazon.com', 'qq.com', '163.com', '126.com',
    'sina.com', 'sohu.com', 'foxmail.com',
    # Big tech companies
    'paypal.com', 'netflix.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'github.com', 'adobe.com',
    'dropbox.com', 'spotify.com', 'uber.com', 'airbnb.com',
    'salesforce.com', 'slack.com', 'zoom.us', 'stripe.com',
    # Banks
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'capitalone.com', 'americanexpress.com', 'discover.com',
    # Shipping
    'fedex.com', 'ups.com', 'dhl.com', 'usps.com',
    # Education
    'stanford.edu', 'mit.edu', 'harvard.edu', 'berkeley.edu',
}


HIGH_TRAFFIC = {
     'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'icloud.com', 'protonmail.com', 'live.com', 'qq.com', '163.com',
    'paypal.com', 'netflix.com', 'microsoft.com', 'apple.com',
    'google.com', 'amazon.com', 'facebook.com', 'linkedin.com',
    'github.com', 'spotify.com', 'chase.com', 'bankofamerica.com',
}


SUSPICIOUS_KEYWORDS = [
    'verify', 'verification', 'secure', 'security', 'bank', 'account',
    'update', 'confirm', 'login', 'signin', 'password', 'credential',
    'ebay', 'service', 'admin', 'official', 'alert', 'notice',
    'suspended', 'blocked', 'urgent', 'important', 'limited', 'claim',
    'prize', 'winner', 'free', 'bonus', 'reward',
    # Extended: action / account management keywords
    'recover', 'recovery', 'restore', 'reactivate', 'unlock', 'validate',
    'authenticate', 'protect', 'notification', 'warning', 'billing',
    'invoice', 'refund', 'payment', 'subscri', 'renew', 'expir',
    # Extended: financial / crypto
    'crypto', 'bitcoin', 'wallet', 'token', 'trading', 'invest',
    # Extended: impersonation signals in domain/username
    'no-reply', 'donotreply', 'postmaster', 'mailer',
    'webmaster', 'hostmaster', 'abuse',
]


# A role mailbox's name describes its function, not the message's intent.
# Require additional evidence (domain, authentication, links, content) before
# treating one of these complete local parts as phishing. Compounds such as
# verify-account and secure-update still follow the ordinary keyword rules.
ROUTINE_MAILBOX_NAMES = frozenset({
    'subscriptions', 'subscriber', 'updates', 'alerts',
    'admin', 'mailer', 'webmaster', 'postmaster',
})


BRAND_DOMAINS = {
    # Consumer tech / social
    'paypal', 'google', 'microsoft', 'amazon', 'apple', 'netflix',
    'facebook', 'twitter', 'instagram', 'linkedin', 'ebay', 'alibaba',
    'dropbox', 'adobe', 'docusign', 'salesforce', 'stripe', 'shopify',
    # Banks & financial
    'chase', 'citibank', 'wellsfargo', 'bankofamerica', 'barclays',
    'hsbc', 'santander', 'natwest', 'lloyds', 'capitalone', 'usbank',
    'schwab', 'fidelity', 'vanguard', 'robinhood',
    # Crypto
    'coinbase', 'binance', 'kraken', 'metamask',
    # Government / regulatory (non-.gov impersonation)
    'irs', 'fbi', 'dhs', 'interpol', 'europol',
    # Logistics
    'fedex', 'ups', 'dhl', 'usps',
}


# Financial-sector keywords commonly embedded in phishing domain labels
FINANCIAL_DOMAIN_KEYWORDS = {
    'bank', 'banking', 'banc', 'credit', 'debit', 'loan', 'mortgage',
    'invest', 'investment', 'capital', 'fund', 'finance', 'financial',
    'wealth', 'trading', 'forex', 'crypto', 'bitcoin', 'blockchain',
    'insurance', 'ins', 'assurance', 'revenue', 'treasury', 'fiscal',
    'pension', 'savings', 'wallet', 'transfer', 'remit', 'clearing',
    'brokerage', 'exchange', 'escrow', 'leasing', 'billing', 'refund',
    'invoice', 'payroll', 'accounting', 'audit', 'taxserv', 'taxrefund',
    # Government/regulatory impersonation
    'federal', 'national', 'official', 'government', 'regulatory',
    'authority', 'ministry', 'bureau',
}


# Business entity suffixes that scammers append to fake-brand abbreviations
BUSINESS_SUFFIX_KEYWORDS = {
    'group', 'corp', 'corporation', 'inc', 'incorporated', 'ltd', 'limited',
    'llc', 'plc', 'holdings', 'holding', 'management', 'enterprise', 'enterprises',
    'solutions', 'service', 'services', 'associates', 'association',
    'partners', 'partnership', 'international', 'global',
    'agency', 'institute', 'trust', 'ventures', 'systems', 'technologies',
    'administration', 'department', 'commission', 'organisation', 'organization',
    'centre', 'center', 'network', 'networks', 'alliance', 'union',
    'foundation', 'consultants', 'consulting', 'advisory',
}


SPAM_TLDS = {'xyz', 'top', 'click', 'loan', 'win', 'gq', 'tk', 'ml', 'cf', 'ga', 'pw', 'cc'}


COMMON_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'cn'}


ABUSED_CCTLDS = {'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'xyz'}


SHORT_SERVICES = {'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'short.io'}


# ── Versioned disposable / temporary email domain registry ────────────────────
_DISPOSABLE_DOMAIN_SOURCE, DISPOSABLE_REGISTRY_METADATA = load_disposable_registry()


PRIVACY_RELAY_DOMAINS, PRIVACY_RELAY_REGISTRY_METADATA = load_privacy_relay_registry()


DISPOSABLE_DOMAINS = _DISPOSABLE_DOMAIN_SOURCE - PRIVACY_RELAY_DOMAINS


# Always use tldextract's bundled Public Suffix List snapshot. Runtime sender
# analysis must remain deterministic and must never perform a network refresh.
_DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


_DISPOSABLE_DOMAIN_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"^(?:temp|temporary)-?(?:mail|email|inbox|box)\d*$",
    r"^(?:trash|discard|throwaway|burner)-?(?:mail|email|inbox|box)\d*$",
    r"^(?:mail)-?(?:temp|trash|drop)\d*$",
    r"^(?:fake)-?(?:mail|email|inbox)\d*$",
    r"^(?:10|20|30|60)(?:minute|min)-?mail(?:box)?\d*$",
))


def _match_domain_registry(domain: str, candidates) -> str | None:
    """Return the most specific exact or subdomain-boundary registry match."""
    normalized = (domain or "").strip().lower().rstrip(".")
    matches = [
        candidate
        for candidate in candidates
        if normalized == candidate or normalized.endswith("." + candidate)
    ]
    return max(matches, key=len, default=None)


def _matches_disposable_domain_pattern(domain: str) -> bool:
    labels = (domain or "").strip().lower().rstrip(".").split(".")
    return any(
        pattern.fullmatch(label)
        for label in labels
        for pattern in _DISPOSABLE_DOMAIN_PATTERNS
    )


def normalize_homoglyphs(text: str) -> str:
    """Convert typosquatting characters back to normal letters."""
    result = text.lower()
    # Multi-char substitutions first
    result = result.replace('vv', 'w')
    result = result.replace('rn', 'm')
    result = result.replace('nn', 'm')
    result = result.replace('cl', 'd')
    # Single char substitutions
    result = result.replace('0', 'o')
    result = result.replace('1', 'l')
    result = result.replace('3', 'e')
    result = result.replace('4', 'a')
    result = result.replace('5', 's')
    result = result.replace('6', 'g')
    result = result.replace('8', 'b')
    result = result.replace('@', 'a')
    return result


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


def extract_email_features(email: str) -> tuple[dict, list, bool, bool, str | None, dict]:
    """
    Extract 30 phishing-indicator features from an email address.
    Returns feature data plus the compatible booleans and detailed disposable classification.
    Each feature value ∈ {-1 (phishing), 0 (suspicious), 1 (legitimate)}.
    """
    email = email.strip().lower()
    risk_indicators = []

    # Parse local part and domain
    at_count = email.count('@')
    if at_count == 0:
        raw_local, domain = email, ''
    else:
        parts = email.split('@')
        raw_local = parts[0]
        domain = parts[-1]

    base_local, plus_separator, alias_tag = raw_local.partition("+")
    is_subaddress = bool(
        supports_plus_alias(domain)
        and plus_separator
        and base_local
        and alias_tag
        and re.fullmatch(r"[a-z0-9._%+\-]+", alias_tag)
    )
    address_alias_type = "subaddress" if is_subaddress else None
    tag_stripped_local = base_local if is_subaddress else raw_local
    local = tag_stripped_local
    if uses_gmail_dot_aliasing(domain):
        local = local.replace(".", "")
    scoring_local = local if uses_gmail_dot_aliasing(domain) else tag_stripped_local
    scoring_email = (
        f"{scoring_local}@{domain}"
        if at_count == 1
        else email
    )

    # Check for IP address domain before splitting
    is_ip_domain = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
    public_suffix = ""
    if is_ip_domain:
        domain_parts = [domain]
        tld = ''
        base_domain = domain
        domain_label = domain
        subdomain_count = 0
    else:
        domain_parts = domain.split('.') if domain else ['']
        extracted_domain = _DOMAIN_EXTRACTOR(domain)
        public_suffix = extracted_domain.suffix
        tld = public_suffix.rsplit('.', 1)[-1] if public_suffix else domain_parts[-1]
        if extracted_domain.domain and public_suffix:
            base_domain = extracted_domain.top_domain_under_public_suffix
            domain_label = extracted_domain.domain
            subdomain_count = len([
                label for label in extracted_domain.subdomain.split('.') if label
            ])
        else:
            base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
            domain_label = domain_parts[-2] if len(domain_parts) >= 2 else domain
            subdomain_count = max(0, len(domain_parts) - 2)

    matched_disposable_domain = _match_domain_registry(domain, DISPOSABLE_DOMAINS)
    matched_privacy_relay = _match_domain_registry(domain, PRIVACY_RELAY_DOMAINS)
    matched_legit_provider = _match_domain_registry(domain, LEGIT_PROVIDERS)
    matched_high_traffic = _match_domain_registry(domain, HIGH_TRAFFIC)
    matched_mail_service = matched_disposable_domain or matched_privacy_relay

    features = {}

    # 1. having_ip_address
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))
    features['having_ip_address'] = -1 if is_ip else 1
    if is_ip:
        risk_indicators.append({"level": "high", "msg": f"Domain is a raw IP address ({domain}) instead of a hostname"})

    # 2. url_length
    total_len = len(scoring_email)
    features['url_length'] = -1 if total_len > 50 else (0 if total_len > 30 else 1)
    if total_len > 50:
        risk_indicators.append({"level": "medium", "msg": f"Email address is unusually long ({total_len} chars) — typical addresses are under 50 characters"})

    # 3. shortining_service
    features['shortining_service'] = -1 if base_domain in SHORT_SERVICES else 1
    if base_domain in SHORT_SERVICES:
        risk_indicators.append({"level": "high", "msg": f"Domain ({base_domain}) is a known URL shortening service frequently abused in phishing"})

    # 4. having_at_symbol
    features['having_at_symbol'] = -1 if at_count > 1 else 1
    if at_count > 1:
        risk_indicators.append({"level": "high", "msg": f"Address contains {at_count} @ symbols — invalid email format"})

    # 5. double_slash_redirecting
    features['double_slash_redirecting'] = -1 if '//' in domain else 1
    if '//' in domain:
        risk_indicators.append({"level": "high", "msg": "Domain contains '//' — possible redirect deception trick"})

    # 6. prefix_suffix (hyphen in base domain)
    has_hyphen = '-' in base_domain
    features['prefix_suffix'] = -1 if has_hyphen else 1
    if has_hyphen:
        risk_indicators.append({"level": "low", "msg": f"Domain contains a hyphen ({base_domain}) — major providers typically do not use hyphens in their domains"})

    # 7. having_sub_domain
    if matched_privacy_relay:
        subdomain_count = 0
    features['having_sub_domain'] = -1 if subdomain_count > 1 else (0 if subdomain_count == 1 else 1)
    if subdomain_count > 1:
        risk_indicators.append({"level": "medium", "msg": f"Domain has {subdomain_count} subdomain levels — phishing sites commonly use deep subdomains to impersonate brands"})

    # 8. https_token
    has_http_in_email = 'http' in scoring_email
    features['https_token'] = -1 if has_http_in_email else 1
    if has_http_in_email:
        risk_indicators.append({"level": "medium", "msg": "Email address contains the token 'http' — used to create visual confusion"})

    # 9. sslfinal_state (known legitimate provider)
    is_known = bool(
        matched_legit_provider
        or matched_disposable_domain
        or matched_privacy_relay
        or domain.endswith('.edu')
        or domain.endswith('.gov')
    )
    features['sslfinal_state'] = 1 if is_known else -1
    if not is_known:
        risk_indicators.append({"level": "medium", "msg": f"Domain ({base_domain}) is not a recognized legitimate mail provider"})

    # 10. domain_registration_length (TLD)
    has_common_tld = bool(public_suffix) or tld in COMMON_TLDS or bool(matched_privacy_relay)
    features['domain_registration_length'] = 1 if has_common_tld else -1
    if tld and not has_common_tld:
        risk_indicators.append({"level": "medium", "msg": f"TLD '.{tld}' is uncommon — phishing emails often use obscure or cheap TLDs"})

    # 11. age_of_domain (domain length as proxy)
    dom_len = len(domain_label)
    features['age_of_domain'] = -1 if dom_len > 20 else (0 if dom_len > 12 else 1)
    if dom_len > 20:
        risk_indicators.append({"level": "low", "msg": f"Domain label is unusually long ({dom_len} characters)"})

    # 12. dnsrecord (digits in domain)
    has_digits_domain = bool(re.search(r'\d', domain_label)) and not matched_privacy_relay
    features['dnsrecord'] = -1 if has_digits_domain else 1
    if has_digits_domain:
        risk_indicators.append({"level": "low", "msg": f"Domain label contains digits ({domain_label}) — legitimate brand domains are usually letters only"})

    # 13. web_traffic (high-traffic provider)
    features['web_traffic'] = 1 if (matched_high_traffic or matched_privacy_relay) else -1

    # 14. page_rank (suspicious keywords in domain)
    domain_susp = [] if matched_privacy_relay else [
        kw for kw in SUSPICIOUS_KEYWORDS if kw in domain.replace('.', '')
    ]
    features['page_rank'] = -1 if domain_susp else 1
    if domain_susp:
        risk_indicators.append({"level": "high", "msg": f"Domain contains phishing keywords: {', '.join(domain_susp[:3])}"})

    # 15. google_index (suspicious keywords in local part)
    local_susp = ([] if local in ROUTINE_MAILBOX_NAMES else
                  [kw for kw in SUSPICIOUS_KEYWORDS if kw in local])
    features['google_index'] = -1 if local_susp else 1
    if local_susp:
        risk_indicators.append({"level": "high", "msg": f"Username contains phishing keywords: {', '.join(local_susp[:3])}"})

    # 16. statistical_report (spam TLDs)
    features['statistical_report'] = -1 if tld in SPAM_TLDS else 1
    if tld in SPAM_TLDS:
        risk_indicators.append({"level": "high", "msg": f"TLD '.{tld}' is a known high-risk or free domain extension heavily used in phishing campaigns"})

    # 17. favicon (excessive digits in local)
    num_ratio = sum(c.isdigit() for c in local) / max(len(local), 1)
    features['favicon'] = 1

    # 18. port (entropy of local part) — threshold matches the auto-gen heuristic
    local_entropy = _shannon_entropy(local)
    features['port'] = 1

    # 19. request_url (special chars in local)
    # Use the same character contract as the API/From parser. RFC atom
    # punctuation such as #, = and apostrophes is not a phishing signal.
    special = {char for char in local if not _RAW_SENDER_LOCAL_RE.fullmatch(char)}
    features['request_url'] = -1 if special else 1
    if special:
        risk_indicators.append({"level": "medium", "msg": f"Username contains unsupported mailbox characters: {''.join(sorted(special))}"})

    # 20. url_of_anchor (local part length)
    local_len = len(local)
    features['url_of_anchor'] = (
        1 if matched_mail_service
        else (-1 if local_len > 30 else (0 if local_len > 15 else 1))
    )
    if local_len > 30 and not matched_mail_service:
        risk_indicators.append({"level": "low", "msg": f"Username is unusually long ({local_len} characters) — typical usernames are under 30 characters"})

    # 21. links_in_tags (brand spoofing)
    brand_spoof = None
    brand_substitution_detected = False
    normalized_domain = normalize_homoglyphs(domain_label)

    for brand in (() if matched_privacy_relay else BRAND_DOMAINS):
        canonical_domains = set(_PROTECTED_BRAND_DOMAINS.get(brand, set()))
        canonical_domains.update({brand + '.com', brand + '.net', brand + '.org'})
        is_official_domain = base_domain in canonical_domains
        # Check original domain
        original_match = brand in domain_label and not is_official_domain
        # Check normalized domain (catches paypa1, vvindows, amaz0n etc)
        normalized_match = (
            normalized_domain != domain_label
            and brand in normalized_domain
            and not is_official_domain
        )

        if original_match or normalized_match:
            brand_spoof = brand
            # Show which substitution was used
            if normalized_match and not original_match:
                brand_substitution_detected = True
                risk_indicators.append({
                    "level": "high",
                    "msg": f"Homoglyph attack detected — '{domain_label}' uses character substitution to impersonate '{brand}' (e.g. 1→l, 0→o, vv→w)"
                })
            break
    features['links_in_tags'] = -1 if brand_spoof else 1
    features['_brand_substitution_detected'] = brand_substitution_detected
    # 22. sfh (noreply address — neutral)
    features['sfh'] = 0 if ('noreply' in local or 'no-reply' in local or 'donotreply' in local) else 1

    # 23. submitting_to_email (repeated chars)
    max_repeat = max((local.count(c) for c in set(local)), default=0)
    repeat_ratio = max_repeat / max(len(local), 1)
    repeated_local = repeat_ratio > 0.5 and len(local) > 3
    features['submitting_to_email'] = 1

    # 24. abnormal_url (digit-letter mix + homoglyph in domain label)
    digit_letter_mix = (
        bool(re.search(r'(?<=[a-z])\d|(?<=\d)[a-z]', domain_label))
        and not matched_privacy_relay
    )
    # Also check if normalizing changes the domain significantly (indicates substitution)
    normalized = normalize_homoglyphs(domain_label)
    homoglyph_detected = (
        not matched_privacy_relay
        and normalized != domain_label
        and any(brand in normalized for brand in BRAND_DOMAINS)
    )
    features['abnormal_url'] = -1 if (digit_letter_mix or homoglyph_detected) else 1
    if homoglyph_detected and not digit_letter_mix:
        risk_indicators.append({
            "level": "high",
            "msg": f"Character substitution detected in domain '{domain_label}' — normalized to '{normalized}'"
        })

    # 25. redirect (default legit — can't check without network)
    features['redirect'] = 1

    # 26. on_mouseover (abused ccTLD)
    features['on_mouseover'] = -1 if tld in ABUSED_CCTLDS else 1
    if tld in ABUSED_CCTLDS:
        risk_indicators.append({"level": "medium", "msg": f"TLD '.{tld}' is a country-code domain commonly abused in phishing attacks"})

    # 27. rightclick (auto-generated pattern: lowercase letters + digits)
    auto_gen = bool(re.match(r'^[a-z]{2,5}\d{4,12}$', local))
    features['rightclick'] = 1

    # 28. popupwindow (too many domain word segments)
    domain_words = re.findall(r'[a-z]+', domain_label)
    features['popupwindow'] = -1 if len(domain_words) > 3 else 1

    # 29. iframe (overall phishing count as cumulative risk)
    phish_count = sum(1 for v in features.values() if v == -1)
    features['iframe'] = -1 if phish_count > 8 else (0 if phish_count > 4 else 1)

    # 30. links_pointing_to_page (basic email format validity)
    email_valid = bool(_normalize_sender_address(scoring_email))
    features['links_pointing_to_page'] = 1 if email_valid else -1
    if not email_valid:
        risk_indicators.append({"level": "high", "msg": "Email address has unsupported or malformed mailbox syntax."})

    # ── Extended semantic domain analysis (extra risk signals beyond ML) ──────
    if not is_known:
        fin_kw_found  = sorted({kw for kw in FINANCIAL_DOMAIN_KEYWORDS if kw in domain_label}, key=len, reverse=True)
        biz_sfx_found = sorted({kw for kw in BUSINESS_SUFFIX_KEYWORDS  if kw in domain_label}, key=len, reverse=True)

        # Detect the fake-business-name compound pattern:
        #   [short abbreviation 0-4 chars] + [financial keyword] + [business suffix]
        # e.g. bpinsgroup → bp + ins + group
        fake_biz_breakdown = None
        for fkw in fin_kw_found:
            idx = domain_label.find(fkw)
            if idx < 0:
                continue
            prefix    = domain_label[:idx]
            remainder = domain_label[idx + len(fkw):]
            if len(prefix) <= 4 and prefix.isalpha() and any(bkw == remainder for bkw in biz_sfx_found):
                fake_biz_breakdown = f"'{prefix or '(none)'}' + '{fkw}' + '{remainder}'"
                break
            # Also catch: financial keyword at start, business suffix follows
            if idx == 0 and any(bkw == remainder for bkw in biz_sfx_found):
                fake_biz_breakdown = f"[start] + '{fkw}' + '{remainder}'"
                break

        if fake_biz_breakdown:
            risk_indicators.insert(0, {
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' follows an [abbreviation]+[financial term]+"
                    f"[business suffix] pattern ({fake_biz_breakdown}) — a known technique "
                    f"used to fabricate fake financial institution email domains"
                ),
            })
        elif fin_kw_found and biz_sfx_found:
            risk_indicators.append({
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' combines financial keywords "
                    f"({', '.join(fin_kw_found[:2])}) with business entity suffixes "
                    f"({', '.join(biz_sfx_found[:2])}) — pattern commonly seen in "
                    f"financial phishing and business email compromise (BEC) domains"
                ),
            })
        elif fin_kw_found:
            risk_indicators.append({
                "level": "medium",
                "msg": (
                    f"Domain '{base_domain}' contains financial-sector keywords "
                    f"({', '.join(fin_kw_found[:3])}) on an unverified provider — "
                    f"verify the sender before sharing financial or personal information"
                ),
            })
        elif biz_sfx_found:
            risk_indicators.append({
                "level": "low",
                "msg": (
                    f"Domain '{base_domain}' uses a business entity suffix "
                    f"({', '.join(biz_sfx_found[:2])}) but is not a recognized "
                    f"or verified organization"
                ),
            })

        # Detect domain that embeds a known brand name as a sub-string
        # (catches cases not handled by exact-match brand spoofing check above)
        if not brand_spoof:
            partial_brands = [b for b in BRAND_DOMAINS if b in domain_label and b != domain_label]
            if partial_brands:
                risk_indicators.append({
                    "level": "high",
                    "msg": (
                        f"Domain '{base_domain}' contains the name of a well-known brand "
                        f"({', '.join(partial_brands[:2])}) as a substring but is not the "
                        f"official domain — possible typosquatting or brand impersonation"
                    ),
                })

        # Detect government/regulatory keyword on a non-.gov domain
        gov_kw = {'federal', 'national', 'authority', 'ministry', 'government',
                  'regulatory', 'commission', 'bureau', 'department', 'administration'}
        gov_hits = [kw for kw in gov_kw if kw in domain_label]
        if gov_hits and tld not in {'gov', 'mil'}:
            risk_indicators.append({
                "level": "high",
                "msg": (
                    f"Domain '{base_domain}' contains government/regulatory keywords "
                    f"({', '.join(gov_hits[:2])}) but is NOT a .gov/.mil domain — "
                    f"likely impersonating an official body"
                ),
            })

        # Detect very long domain label (>15 chars) that is a concatenated word chain
        if len(domain_label) > 15 and (fin_kw_found or biz_sfx_found):
            risk_indicators.append({
                "level": "medium",
                "msg": (
                    f"Domain label '{domain_label}' is long ({len(domain_label)} chars) and "
                    f"appears to be a compound of multiple words — bulk phishing campaigns "
                    f"often generate such domains to appear business-like"
                ),
            })

    # ── Disposable email classification (separate from the 30 ML features) ────
    disposable_status = "no_known_match"
    disposable_confidence = "unknown"
    matched_provider_domain = None
    if matched_disposable_domain:
        disposable_status = "known_disposable_provider"
        disposable_confidence = "confirmed"
        matched_provider_domain = matched_disposable_domain
    elif matched_privacy_relay:
        disposable_status = "privacy_relay"
        disposable_confidence = "confirmed"
        matched_provider_domain = matched_privacy_relay

    is_disposable = disposable_status == "known_disposable_provider"
    is_suspected_disposable = False

    # 2. Auto-generated username heuristic:
    #    High-entropy all-lowercase-letters username (no vowel pattern, no digits,
    #    length 8-20) on an unknown domain  →  very likely a randomly-generated
    #    disposable address even if the domain is not in the list.
    if not matched_disposable_domain and not matched_privacy_relay and local:
        is_unknown_domain = not matched_legit_provider and not matched_high_traffic

        # ── Multi-factor randomness scoring ───────────────────────────────────
        # Regex now allows . _ - separators (e.g. word.word, word-word patterns)
        # Unknown domains use threshold 2; recognized providers use threshold 4.
        if bool(re.fullmatch(r'[a-z0-9._-]{8,25}', local)):

            letters_only = ''.join(c for c in local if c.isalpha())
            digit_count  = sum(c.isdigit() for c in local)
            vowel_ratio  = sum(1 for c in letters_only if c in 'aeiou') / max(len(letters_only), 1)
            entropy      = _shannon_entropy(local)

            # ── Firstname.Lastname exemption ──────────────────────────────────
            # Legitimate users often use first.last@company.com patterns.
            # Skip the heuristic for confirmed real-name combinations.
            _FIRST = {
                'alice','john','jane','mark','mike','kate','jack','alex','adam',
                'luke','mary','anna','sara','lisa','emma','ryan','paul','eric',
                'alan','kyle','noah','liam','dave','owen','evan','peter','james',
                'chris','david','emily','grace','oliver','daniel','thomas','robert',
                'william','joseph','henry','samuel','joshua','andrew','michael',
                'jacob','ethan','mason','logan','lucas','sophia','isabella','mia',
                'charlotte','amelia','harper','evelyn','abigail','madison','ella',
                'chloe','riley','layla','zoey','nora','lily','eleanor','hannah',
                'addison','stella','natalie','zoe','leah','hazel','violet','claire',
                'skylar','lucy','anna','caroline','jennifer','jessica','ashley',
                'sarah','amanda','brittany','samantha','elizabeth','megan','rachel',
                'kayla','andrea','lauren','victoria','matthew','christopher',
                'justin','brandon','tyler','jonathan','nicholas','nathan','zachary',
                'kevin','timothy','steven','austin','travis','jordan','derek','dylan',
                'sean','brian','scott','patrick','keith','gary','dennis','frank',
                'harold','raymond','samuel','jerry','teresa','diana','joyce',
            }
            _LAST = {
                'smith','jones','brown','davis','wilson','taylor','anderson',
                'jackson','white','harris','martin','thompson','garcia','martinez',
                'robinson','clark','rodriguez','lewis','lee','walker','hall',
                'allen','young','hernandez','king','wright','lopez','hill','scott',
                'green','adams','baker','gonzalez','nelson','carter','mitchell',
                'perez','roberts','turner','phillips','campbell','parker','evans',
                'edwards','collins','stewart','sanchez','morris','rogers','reed',
                'cook','morgan','bell','murphy','bailey','rivera','cooper',
                'richardson','cox','howard','ward','torres','peterson','gray',
                'ramirez','watson','brooks','kelly','sanders','price','bennett',
                'wood','barnes','ross','henderson','coleman','jenkins','perry',
                'powell','long','patterson','hughes','flores','washington','butler',
                'simmons','foster','gonzales','bryant','alexander','russell',
                'griffin','diaz','hayes','fisher','cole','frank','owens',
                'reynolds','mills','grant','wells','ford','porter','hunt','stone',
                'dixon','hawkins','burns','berry','shaw','reyes','medina',
                'doe','johnson','williams','miller','moore','thomas','wright',
                'walker','hall','allen','young','adams','nelson','carter',
            }
            sep_parts = re.split(r'[._-]', tag_stripped_local)
            is_separated_real_name = (
                len(sep_parts) == 2 and
                all(p.isalpha() and len(p) >= 2 for p in sep_parts) and
                ((sep_parts[0] in _FIRST and sep_parts[1] in _LAST) or
                 (sep_parts[0] in _LAST  and sep_parts[1] in _FIRST))
            )
            canonical_name = re.sub(r'[._-]', '', tag_stripped_local)
            is_concatenated_real_name = any(
                (
                    canonical_name.startswith(first)
                    and canonical_name[len(first):] in _LAST
                )
                or (
                    canonical_name.endswith(first)
                    and canonical_name[:-len(first)] in _LAST
                )
                for first in _FIRST
            )
            is_real_name = is_separated_real_name or is_concatenated_real_name

            if not is_real_name:
                # Factor 1 – Shannon entropy indicates near-uniform character spread
                f_entropy = entropy > 3.0

                # Factor 2 – Low vowel ratio (random strings often lack vowels)
                f_vowels = vowel_ratio <= 0.30

                # Factor 3 – Digits scattered inside the string, not just at the end
                f_digits = (digit_count >= 2 and
                            bool(re.search(r'[a-z]\d[a-z]|\d[a-z]\d', local)))

                # Factor 4 – High unique-character ratio (random = few repeats)
                unique_ratio = len(set(local)) / max(len(local), 1)
                f_unique = unique_ratio >= 0.75

                # Factor 5 – No recognisable English word embedded
                _COMMON = {'user','mail','info','test','home','name','blog','help',
                           'shop','work','love','life','data','code','tech','site',
                           'link','post','news','real','best','john','jane','mark',
                           'mike','kate','jack','alex','adam','luke','mary','anna',
                           'sara','lisa','emma','ryan','paul','eric','alan','kyle',
                           'noah','liam','dave','owen','evan','alice','smith','jones',
                           'peter','james','chris','david','emily','grace','hello',
                           'world','super','admin','sales','brown','davis','thomas',
                           'robert','oliver','daniel','master','shadow','dragon','tiger',
                           'support','contact','service','secure','account','email',
                           'notify','alert','update','welcome','newsletter','webmaster',
                           'phoenix','mighty','dark','light','storm','fire','ice',
                           'wolf','hawk','eagle','falcon','raven','fox','bear','lion',
                           'night','star','moon','blue','red','black','white','gold',
                           'cyber','neon','nova','omega','alpha','prime','mega','ninja',
                           'king','queen','lord','knight','warrior','hunter','ranger',
                           'swift','brave','sharp','smart','bold','wild','free',}
                letters_lower = letters_only.lower()
                has_real_word = any(w in letters_lower for w in _COMMON)
                f_noword = not has_real_word

                # Factor 6 – word.word separator pattern where words are NOT real names
                #             (username generators often combine random words with dots)
                word_parts = [p for p in sep_parts if p.isalpha() and len(p) >= 3]
                f_word_combo = (
                    len(word_parts) >= 2 and
                    not any(w in (_FIRST | _LAST | _COMMON) for w in word_parts)
                )

                rnd_score = sum([f_entropy, f_vowels, f_digits, f_unique, f_noword, f_word_combo])

                threshold = 2 if is_unknown_domain else 4
                if rnd_score >= threshold:
                    disposable_status = "suspicious_mailbox_pattern"
                    disposable_confidence = "heuristic"
                    is_suspected_disposable = True
                    features['favicon'] = -1 if num_ratio > 0.4 else 1
                    features['port'] = -1 if local_entropy > 3.0 else 1
                    features['submitting_to_email'] = -1 if repeated_local else 1
                    features['rightclick'] = -1 if auto_gen else 1
                    factors_hit = []
                    if f_entropy:    factors_hit.append(f"entropy {entropy:.2f}")
                    if f_vowels:     factors_hit.append(f"vowel {vowel_ratio:.0%}")
                    if f_digits:     factors_hit.append("digits scattered")
                    if f_unique:     factors_hit.append(f"unique-ratio {unique_ratio:.0%}")
                    if f_noword:     factors_hit.append("no real word")
                    if f_word_combo: factors_hit.append("unusual word combo")
                    risk_indicators.insert(0, {
                        "level": "medium",
                        "msg": (
                            f"Username '{local}' matches {rnd_score}/6 randomness factors "
                            f"({', '.join(factors_hit)}) — the mailbox pattern looks "
                            f"automatically generated, but account age and lifetime "
                            f"cannot be confirmed"
                        ),
                    })

    if (
        disposable_status == "no_known_match"
        and _matches_disposable_domain_pattern(domain)
    ):
        disposable_status = "suspicious_domain_pattern"
        disposable_confidence = "heuristic"
        is_suspected_disposable = True
        risk_indicators.insert(0, {
            "level": "medium",
            "msg": (
                f"Domain ({domain}) resembles a temporary-email provider name, "
                f"but is not in the confirmed provider registry"
            ),
        })

    disposable_service = matched_disposable_domain if is_disposable else None
    if disposable_status == "known_disposable_provider":
        risk_indicators.insert(0, {
            "level": "info",
            "msg": (
                f"Known disposable-email provider detected ({matched_disposable_domain}). "
                "Provider category alone is not phishing evidence; mailbox lifetime is unknown."
            ),
        })
    elif disposable_status == "privacy_relay":
        risk_indicators.insert(0, {
            "level": "info",
            "msg": (
                f"Privacy relay or masked-address provider detected "
                f"({matched_privacy_relay}); this is not phishing evidence by itself."
            ),
        })

    if address_alias_type:
        risk_indicators.append({
            "level": "info",
            "msg": "Address uses plus subaddressing; the tag is not a phishing signal.",
        })

    classification = {
        "disposable_status": disposable_status,
        "disposable_confidence": disposable_confidence,
        "matched_provider_domain": matched_provider_domain,
        "address_alias_type": address_alias_type,
    }
    return (
        features,
        risk_indicators,
        is_disposable,
        is_suspected_disposable,
        disposable_service,
        classification,
    )


_RAW_SENDER_LOCAL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$"
)


_RAW_SENDER_DOMAIN_LABEL_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def _normalize_sender_address(address: str) -> str:
    address = address.strip()
    if address.count('@') != 1 or any(c.isspace() for c in address):
        return ''
    local, domain = address.rsplit('@', 1)
    domain = normalize_domain(domain)
    labels = domain.split('.')
    if (not 0 < len(local) <= 64 or not _RAW_SENDER_LOCAL_RE.fullmatch(local)
            or local.startswith('.') or local.endswith('.') or '..' in local
            or len(domain) > 253 or len(labels) < 2
            or any(not _RAW_SENDER_DOMAIN_LABEL_RE.fullmatch(label) for label in labels)):
        return ''
    return f'{local}@{domain}'
