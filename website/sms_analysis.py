"""Text messages (SMS, iMessage): what kind of sender a number is, which organisation a text
says it comes from, its links, and the rules only texts need.

app.analyze_sms runs these beside the plain-text rules texts share with email
(docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md). This module needs nothing
from app.py, so app.py can import it.
"""
from __future__ import annotations

import json
import re
import unicodedata
from urllib.parse import urlsplit

from email_structure import _OFFICIAL_BRANDS_PATHS, _ORGANIZATIONAL_DOMAINS, normalize_domain
from server_messages import indicator

SENDER_KINDS = ('short_code', 'cn_port_106', 'cn_mobile', 'nanp_toll_free', 'nanp_long_code', 'international',
                'other_number', 'email', 'alphanumeric', 'none')
_ZERO_WIDTH = re.compile('[​-‏⁠﻿]')
_EMAIL = re.compile(r'[^@\s]+@[^@\s]+\.[A-Za-z]{2,}')
_CN_MOBILE = re.compile(r'1[3-9]\d{9}')
_TOLL_FREE_AREA_CODES = frozenset({'800', '833', '844', '855', '866', '877', '888'})


def clean_text(text: str) -> str:
    """The text without zero-width characters, which scams put inside names and links."""
    return _ZERO_WIDTH.sub('', text or '')


def _chinese_kind(national: str) -> str | None:
    if _CN_MOBILE.fullmatch(national):
        return 'cn_mobile'
    if national.startswith('106') and len(national) >= 8:
        return 'cn_port_106'
    if 3 <= len(national) <= 6:
        return 'short_code'
    return None


def _north_american_kind(ten: str) -> str | None:
    if len(ten) == 10 and ten[0] in '23456789':
        return 'nanp_toll_free' if ten[:3] in _TOLL_FREE_AREA_CODES else 'nanp_long_code'
    return None


def classify_sender(sender: str) -> str:
    """The kind of sender, one of SENDER_KINDS. The number itself is never kept.

    A bare 11-digit number starting with 13–19 is read as a Chinese mobile: phones show
    North American numbers with +1 or as 10 digits.
    """
    value = clean_text(unicodedata.normalize('NFKC', sender or '')).strip()
    if not value:
        return 'none'
    if _EMAIL.fullmatch(value):
        return 'email'
    compact = re.sub(r'[\s\-.() ]', '', value)
    if not re.fullmatch(r'\+?\d+', compact):
        return 'alphanumeric' if re.search(r'[^\W\d_]', value) else 'other_number'
    plus, digits = compact.startswith('+'), compact.lstrip('+')
    if not plus and digits.startswith('00'):
        plus, digits = True, digits[2:]
    if plus:
        if digits.startswith('86'):
            return _chinese_kind(digits[2:]) or 'other_number'
        if digits.startswith('1') and len(digits) == 11:
            return _north_american_kind(digits[1:]) or 'other_number'
        return 'international'
    return (_chinese_kind(digits) or _north_american_kind(digits)
            or (len(digits) == 11 and digits.startswith('1') and _north_american_kind(digits[1:]))
            or (digits.startswith('86') and _chinese_kind(digits[2:])) or 'other_number')


def _load_brands(paths=_OFFICIAL_BRANDS_PATHS) -> tuple[dict, ...]:
    """Organisations a text can claim to be, with their region and official domains.

    Services named only by a verified sender (display_check "sender_only") are left out, as
    in email. Chinese organisations are claimed by their Chinese names only: their ASCII
    abbreviations (ABC, CCB, BOC) open many English texts.
    """
    brands = []
    for path in paths:
        region = 'cn' if path.name == 'official_brands_cn.json' else 'intl'
        for brand in json.loads(path.read_text(encoding='utf-8'))['brands']:
            if brand.get('display_check') == 'sender_only':
                continue
            names = ([name for name in brand.get('claim_names') or brand['display_names'] if not name.isascii()]
                     if region == 'cn' else brand['display_names'])
            if names:
                brands.append({
                    'name': brand['name'], 'region': region,
                    'names': tuple(sorted(names, key=len, reverse=True)),
                    'domains': frozenset(normalize_domain(domain) for domain in (
                        *brand['official_domains'], *brand.get('gov_suffixes', ()), *brand.get('brand_tlds', ()))),
                })
    return tuple(brands)


BRANDS = _load_brands()
_SIGNATURE = re.compile(r'^\s*[【\[]([^】\]\n]{1,24})[】\]]|[【\[]([^】\]\n]{1,24})[】\]]\s*$')


def _names(text: str, name: str, *, opening: bool) -> bool:
    """Whether text shows name: anywhere in a signature, or at its very start."""
    folded = unicodedata.normalize('NFKC', text).casefold()
    if name.isascii():
        pattern = r'\s*'.join(map(re.escape, name.casefold().split()))
        found = (re.match if opening else re.search)(rf'(?<![a-z0-9])(?:{pattern})(?![a-z0-9])', folded.lstrip())
        return found is not None
    joined = ''.join(folded.split())
    return joined.startswith(name.casefold()) if opening else name.casefold() in joined


def claimed_brand(text: str) -> dict | None:
    """The organisation a text says it comes from: its signature (【…】 or […] at the start or
    end) or the name it opens with. A later mention ("我用工行转你了") is no claim."""
    text = clean_text(text)
    signatures = [group for match in _SIGNATURE.finditer(text) for group in match.groups() if group]
    for brand in BRANDS:
        for name in brand['names']:
            if any(_names(signature, name, opening=False) for signature in signatures) or _names(text, name, opening=True):
                return brand
    return None


# Hosts with or without a scheme: texts often write ezpass-pay.com/x, and Chinese texts put no
# space around a link (点击t.cn/abc查看). A bare host counts only when the Public Suffix List
# knows its suffix, so file.txt or e.g. is no link.
_LINK = re.compile(
    r'(?<![@A-Za-z0-9.\-])((?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{2,5})?'
    r'(?:/[^\s<>"　-〿一-鿿＀-￯]*)?'
    # An IPv4 host only after an explicit scheme: "version 1.2.3.4" is no link.
    r'|https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?:/[^\s<>"　-〿一-鿿＀-￯]*)?)', re.IGNORECASE)


def text_links(text: str) -> list[tuple[str, str]]:
    """(label, url) for each link, as the email link rules take them; a bare host gets http://."""
    links = []
    for match in _LINK.finditer(clean_text(text)):
        label = match.group(1).rstrip('.,;:!?)\'"')
        url = label if re.match(r'https?://', label, re.IGNORECASE) else 'http://' + label
        host = (urlsplit(url).hostname or '').lower()
        parts = _ORGANIZATIONAL_DOMAINS(host)
        if (parts.suffix and parts.domain) or re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host):
            links.append((label, url))
    return links


def link_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


# "Reply Y, then exit and reopen this text to activate the link", or copy it into a
# browser: phones disable links in texts from unknown senders until the reader replies.
# A request only to reply (to confirm an appointment, or STOP) is not this.
_REOPEN_TO_ACTIVATE = re.compile(
    r"\breply\b.{0,80}?\b(?:re-?open|open\s+(?:(?:this|the|it)\s+)?(?:(?:text\s+)?message\s+|text\s+|sms\s+|link\s+)?again"
    r"|return\s+to\s+(?:this|the)\s+(?:message|text))"
    r"|\bcopy\b.{0,30}?\b(?:link|url|web\s*address|website)\b.{0,40}?\b(?:browser|safari|chrome)\b"
    r"|回复.{0,20}?(?:重新打开|再次打开|重新进入|退出.{0,10}?(?:打开|进入))"
    r"|复制.{0,15}?(?:链接|网址).{0,20}?浏览器|(?:链接|网址).{0,15}?复制.{0,20}?浏览器",
    re.IGNORECASE | re.DOTALL)
# A prize, award or free offer to claim by calling, texting or dialling a number: the prize
# scams of the Mishra and Soni development half. "won't" is no win. A premium-rate number alone
# (09…, 087…) is left out: it marks old British texts, not today's US or Chinese ones.
_PRIZE = re.compile(
    r"\b(?:won(?!['’]t)|winners?|prizes?|claim|award(?:ed)?|rewards?|congratulations|congrats|guaranteed"
    r"|selected\s+to\s+receive|free\s+(?:entry|gift|flights?|holiday|cruise|phone|mobile)|for\s+free"
    r"|gift\s*cards?|vouchers?|cash\s+prize|awaits?\s+collection|unclaimed|complimentary|entitled\s+to)\b",
    re.IGNORECASE)
_CALL_A_NUMBER = re.compile(
    r"\b(?:call|dial|ring|phone|text|txt|send|reply|contact|claim)\b[^.!?\n]{0,40}?(?<![\d£$€])\+?\d[\d\s-]{3,}\d",
    re.IGNORECASE)
# Senders each region's organisations text from; "none" and "alphanumeric" say nothing.
_EXPECTED_SENDERS = {'cn': frozenset({'short_code', 'cn_port_106'}),
                     'intl': frozenset({'short_code', 'nanp_toll_free'})}
_UNINFORMATIVE_SENDERS = frozenset({'none', 'alphanumeric'})


def sms_findings(sender: str, text: str) -> dict:
    """The SMS rules: points, the floor they set, and their indicators.

    A sender that matches the claimed organisation never lowers the risk: sender numbers
    can be forged (ICBC warns of texts that appear to come from 95588).
    """
    text = clean_text(text)
    kind = classify_sender(sender)
    brand = claimed_brand(text)
    links = text_links(text)
    score, floor, found = 0, 'safe', []
    if brand and kind not in _UNINFORMATIVE_SENDERS and kind not in _EXPECTED_SENDERS[brand['region']]:
        if brand['region'] == 'intl' and kind == 'nanp_long_code':
            # Many genuine US businesses text from registered 10-digit numbers.
            score += 2
            found.append(indicator('medium', 'sms.sender_mismatch_weak', brand=brand['name']))
        else:
            score += 4
            floor = 'medium'
            found.append(indicator('high', 'sms.sender_mismatch', brand=brand['name']))
    if brand:
        host = next((host for host in map(link_host, (url for _label, url in links)) if host and not any(
            host == domain or host.endswith('.' + domain) for domain in brand['domains'])), None)
        if host:
            score += 2
            found.append(indicator('medium', 'sms.link_off_brand', brand=brand['name'], host=host))
    if _REOPEN_TO_ACTIVATE.search(text):
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.reopen_to_activate'))
    if _PRIZE.search(text) and _CALL_A_NUMBER.search(text):
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.prize_callback'))
    return {'score': score, 'floor': floor, 'indicators': found, 'sender_kind': kind,
            'claimed_brand': brand['name'] if brand else None, 'claimed_names': brand['names'] if brand else (),
            'links': links}
