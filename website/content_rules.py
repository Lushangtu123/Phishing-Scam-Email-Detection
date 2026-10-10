"""Content rules: the keyword categories, requests for codes, passwords, payments or callbacks,
the lures (mailbox, delivery, fine, account hold, file share, subsidy), presentation cues, and the
rules for attachment text and registration dates. Email and text messages share them; app.py
combines their findings with the structure, sender, links and model. Needs nothing from app.py.
"""
from __future__ import annotations

import base64
import domain_age
import re
import unicodedata
from datetime import datetime, timezone
from email.utils import parseaddr
from email_structure import (
    _ORGANIZATIONAL_DOMAINS,
    _official_sender,
    _CONSUMER_MAILBOX_DOMAINS,
    organizational_domain as _organizational_domain,
    registrable_domain as _registrable_domain,
    OFFICIAL_SERVICE_NUMBERS as _OFFICIAL_SERVICE_NUMBERS,
)
from functools import lru_cache
from html_visibility import (
    _AnalysisHTMLParser,
    _collect_html,
    _first_html_attributes,
    _parse_link_target,
    _strip_invisible_format_controls,
    _unescape_css,
)
from link_analysis import _is_ip_host
from pathlib import PurePath
from sender_features import normalize_homoglyphs
from server_messages import indicator
from urllib.parse import unquote, urljoin


CONTENT_RULES: dict = {
    "urgency": {
        "label": "Urgency & Pressure",
        "level": "high",
        "icon": "⏰",
        "description": "Phishing emails create artificial time pressure to prevent careful thinking.",
        "keywords": [
            "urgent", "immediately", "act now", "respond within", "respond today",
            "within 24 hours", "within 48 hours", "within 72 hours", "limited time",
            "today only", "expires soon", "expiring", "deadline", "last chance",
            "final notice", "final warning", "time sensitive", "time-sensitive",
            "asap", "do not delay", "action required", "response required",
            "reply immediately", "prompt action", "critical alert", "important notice",
            "account will be deleted", "service will be discontinued",
            "must respond", "failure to respond", "failure to act",
            "your access will be", "expiration notice",
        ],
    },
    "threats": {
        "label": "Threats & Fear Tactics",
        "level": "high",
        "icon": "🚨",
        "description": "Scammers use fear of account loss, legal trouble, or arrest to coerce victims.",
        "keywords": [
            "account suspended", "account blocked", "account terminated", "account closed",
            "access denied", "access revoked", "will be terminated", "will be suspended",
            "legal action", "lawsuit", "arrested", "penalty", "criminal charges",
            "your account has been", "unusual activity", "suspicious activity",
            "unauthorized access", "security breach", "compromised", "hacked",
            "report you", "law enforcement", "police", "fbi", "irs audit",
            "debt collection", "warrant issued", "court order",
            "face prosecution", "civil lawsuit", "criminal investigation",
            "your ip address", "your device has been", "data breach",
            "identity theft", "we have recorded", "we have detected",
        ],
    },
    "financial": {
        "label": "Financial Lure",
        "level": "high",
        "icon": "💰",
        "description": "Promises of unexpected money or urgent payment demands are classic scam patterns.",
        "keywords": [
            "free money", "lottery", "you won", "you have won", "prize winner",
            "million dollar", "billion dollar", "inheritance", "unclaimed funds",
            "transfer funds", "wire transfer", "bitcoin", "cryptocurrency", "crypto wallet",
            "investment opportunity", "guaranteed return", "100% profit", "risk-free",
            "send money", "western union", "moneygram", "gift card", "itunes card",
            "google play card", "steam card",
            "overdue payment", "unpaid invoice", "outstanding balance",
            "refund pending", "tax refund", "claim your refund", "unclaimed prize",
            "processing fee", "advance fee", "release fee", "activation fee",
            "donation", "charity fund", "humanitarian fund",
            "next of kin", "deceased customer", "deceased estate",
        ],
    },
    "credential": {
        "label": "Credential Harvesting",
        "level": "high",
        "icon": "🔑",
        "description": "Requests for passwords, card numbers, SSN, or account details are major red flags.",
        "keywords": [
            "click here to verify", "verify your account", "verify your email",
            "confirm your account", "confirm your identity", "confirm your details",
            "reset your password", "update your password", "enter your password",
            "provide your password", "validate your account", "re-enter your",
            "social security number", "ssn", "credit card number",
            "bank account number", "routing number", "date of birth",
            "mother's maiden name", "security question", "pin number",
            "login to your account", "sign in to verify", "update your information",
            "submit your details", "fill in the form below",
            "complete the form", "fill out the form", "enter your details",
            "passport number", "driver's license", "national id",
            "two-factor", "one-time password", "otp code",
        ],
    },
    "impersonation": {
        "label": "Possible Brand Impersonation",
        "level": "medium",
        "icon": "🎭",
        "description": "Mentions of well-known brands alongside action requests may indicate spoofing.",
        "keywords": [
            "paypal", "amazon", "apple id", "google account", "microsoft account",
            "netflix", "facebook", "instagram", "twitter", "linkedin", "ebay",
            "fedex", "ups delivery", "dhl express", "usps", "royal mail",
            "bank of america", "chase bank", "wells fargo", "citibank", "hsbc",
            "barclays", "santander", "natwest", "lloyds",
            "internal revenue service", "irs", "social security administration",
            "department of homeland security", "interpol", "europol",
            "world health organization", "united nations",
            "dropbox", "docusign", "adobe sign", "wetransfer",
        ],
    },
    "deception": {
        "label": "Deceptive Tactics",
        "level": "medium",
        "icon": "🎪",
        "description": "Phrases designed to manipulate behavior, bypass skepticism, or avoid scrutiny.",
        "keywords": [
            "do not share this", "keep this confidential", "keep this secret",
            "delete this email", "do not forward", "burn after reading",
            "you have been specially selected", "you have been chosen",
            "congratulations you are", "dear valued customer",
            "dear account holder", "dear user", "dear beneficiary",
            "dear friend", "dear sir", "dear madam", "dear sir/madam",
            "your package is waiting", "delivery attempt failed",
            "click the link below", "click the button below",
            "download the attachment", "open the attachment",
            "we will never ask for your password",
            "this is not spam", "this email is legitimate",
            "100% safe", "guaranteed secure", "verified by",
            "forward this email", "share with your friends",
            "as seen on cnn", "as seen on bbc",
        ],
    },
    # ── New categories ────────────────────────────────────────────────────────
    "attachments": {
        "label": "Suspicious Attachment References",
        "level": "high",
        "icon": "📎",
        "description": "References to file attachments, especially executables or documents with macros, are a primary malware delivery vector.",
        "keywords": [
            "see the attached", "please find attached", "open the attached file",
            "attached invoice", "attached document", "attached receipt",
            "download and run", "run the installer", "execute the file",
            "attached .exe", "attached .zip", "attached .doc", "attached .pdf",
            "scan the attached", "view the attached", "enable macros",
            "enable editing", "enable content", "allow this document",
            "extract the zip", "unzip the file", "password is attached",
            "attachment contains", "file attached",
        ],
    },
    "tech_scam": {
        "label": "Tech Support / Malware Scam",
        "level": "high",
        "icon": "💻",
        "description": "Fake security alerts claiming your device is infected, designed to make you call fraudulent 'support' numbers.",
        "keywords": [
            "your computer is infected", "your device is infected", "virus detected",
            "malware detected", "spyware detected", "ransomware detected",
            "call microsoft", "call apple support", "call our toll-free",
            "windows has detected", "microsoft security alert", "apple security alert",
            "your subscription has expired", "renew your antivirus",
            "your computer has been hacked", "hacker has access to your webcam",
            "your files have been encrypted", "pay to decrypt",
            "remote access", "allow remote connection", "install this software",
            "technical support", "tech support", "call immediately",
            "do not turn off your computer", "do not restart",
        ],
    },
    "job_scam": {
        "label": "Job / Money Mule Scam",
        "level": "medium",
        "icon": "💼",
        "description": "Fake job offers, work-from-home schemes, or requests to receive and forward money on behalf of others.",
        "keywords": [
            "work from home", "work at home", "home-based job", "remote job offer",
            "earn per day", "earn per week", "earn $", "make money online",
            "no experience required", "no experience needed",
            "part time job", "flexible hours", "be your own boss",
            "package forwarding", "parcel forwarding", "reshipping agent",
            "receive payment", "transfer the funds", "keep a commission",
            "money transfer agent", "financial agent", "payment processor",
            "lottery agent", "claims agent", "prize agent",
            "data entry job", "typing job", "easy job", "simple task",
            "multi-level marketing", "mlm", "pyramid scheme",
        ],
    },
    "social_engineering": {
        "label": "Social Engineering",
        "level": "medium",
        "icon": "🧠",
        "description": "Psychological manipulation tactics that exploit trust, authority, or reciprocity to bypass judgment.",
        "keywords": [
            "i am the ceo", "i am a doctor", "i am a lawyer", "i am an agent",
            "on behalf of", "acting on behalf",
            "god bless you", "may god bless", "in god we trust",
            "i need your help", "please help me", "only you can help",
            "i trust you", "you are the only person", "i chose you",
            "our mutual friend", "your friend recommended",
            "strictly confidential", "top secret", "classified information",
            "do not tell anyone", "between you and me",
            "i found your contact", "i got your email from",
            "dying of cancer", "terminal illness", "last wish",
            "refugee", "stranded abroad", "stuck in",
        ],
    },
}

# Chinese phrasing of the same tactics (simplified and traditional). Mailbox-credential
# lures dominate Chinese phishing in the Nazario corpus: quota full, account expiring
# or being deactivated, "upgrade" or "re-verify" the mailbox, "keep the same password".
# Only phrases that tie the threat or request to the account or mailbox are listed;
# generic words such as 验证码, 立即查看 or 账户 appear in genuine notices too.
_CONTENT_RULES_ZH = {
    "urgency": [
        "最后警告", "最終警告", "最终警告", "最後警告", "紧急通知", "緊急通知", "立即升级", "立即升級",
        "尽快升级", "儘快升級", "立即增加空间", "立即增加空間",
    ],
    "threats": [
        "将被关闭", "將被關閉", "将被停用", "將被停用", "将被禁用", "將被禁用", "将被锁定", "將被鎖定",
        "被迫锁定", "被迫鎖定", "防止您的帐户被停用", "防止您的帳戶被停用", "取消激活", "取消啟用",
        "邮箱将被停用", "邮箱即将过期", "帐户即将过期", "账户即将过期", "帳戶即將過期", "帐户将过期",
        "账户将过期", "帐户已被限制", "账户已被限制", "帳戶已被限制", "关闭所有不活跃的账户",
        "关闭所有不活跃的帐户", "停止向您帐户中的传入电子邮件", "您的帐户可能会丢失", "您的账户可能会丢失",
    ],
    "credential": [
        "重新验证您的帐户", "重新验证您的账户", "重新驗證您的帳戶", "验证您的电子邮件帐户",
        "驗證您的電子郵件帳戶", "确认有效账户", "确认有效帐户", "保持相同的密码", "保持相同的密碼",
        "保持我的密码", "保持我的密碼", "保持当前密码", "保持當前密碼", "更新您的电子邮件密码",
        "的所有权以继续使用此邮箱", "激活我的帐户", "激活我的账户", "啟用我的帳戶", "激活我的帳戶",
        "升级您的邮箱", "升級您的郵箱", "验证升级", "完成验证升级", "请指出您是否仍在使用此邮箱",
    ],
    "deception": [
        "邮箱配额已满", "郵箱配額已滿", "存储空间已满", "存儲空間已滿", "邮件存储空间很小",
        "增加存储容量", "增加存儲容量", "未送达的邮件", "未送達的郵件", "无法发送的新邮件",
        "传入邮件无法传送", "傳入郵件無法傳送", "邮件数量过多", "由于数据库错误", "由於數據庫錯誤",
        "此消息来自电子邮件服务器", "登录可能存在异常",
    ],
}
for _category, _keywords in _CONTENT_RULES_ZH.items():
    CONTENT_RULES[_category]["keywords"].extend(_keywords)


# Character obfuscation substitution map (leetspeak / homoglyph tricks)
_OBFUSCATION_PAIRS = [
    (r'p[@4]yp[@4]l', 'PayPal'),
    (r'am[@4]z[o0]n', 'Amazon'),
    (r'[a4]ppl[e3]', 'Apple'),
    (r'm[i1]cr[o0]s[o0]ft', 'Microsoft'),
    (r'g[o0][o0]gl[e3]', 'Google'),
    (r'n[e3]tfl[i1]x', 'Netflix'),
    (r'[i1]nst[@a4]gr[@a4]m', 'Instagram'),
    (r'f[@a4]c[e3]b[o0][o0]k', 'Facebook'),
    (r'[l1][o0]g[i1]n', 'login'),
    (r'v[e3]r[i1]fy', 'verify'),
    (r'[a4]cc[o0]unt', 'account'),
    (r'p[@a4]ssw[o0]rd', 'password'),
    (r'b[a4]nk', 'bank'),
]


def _excessive_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


# Brand names and lure words written with a capital I for a lowercase l ("PayPaI", "Trust
# WaIIet", "AppIe", "WeIIs Fargo") or a lowercase l for an initial i (ltunes, lnvoice):
# many fonts draw I and l alike. Only a word that becomes one of these counts, so
# "LinkedIn" and "McIntyre" never match. 58 Nazario messages and 22 DIFraud fraud messages
# carry such a word (sender, subject or text); no message of the 92 genuine downloads,
# 9,198 genuine DIFraud messages, 16,440 marketing emails or 5,055 Apache list messages does.
_LETTER_SWAP_WORDS = {word.lower(): word for word in (
    'PayPal', 'Apple', 'iCloud', 'iTunes', 'Netflix', 'Wells', 'Wallet', 'Outlook', 'Google', 'Gmail', 'Hotmail',
    'Alibaba', 'Blockchain', 'Ledger', 'Lloyds', 'Telstra', 'Royal', 'Instagram', 'Inbox', 'Invoice',
    'Mail', 'Email', 'Mailbox', 'Webmail', 'Login', 'Unlock', 'Locked', 'Billing', 'Bill', 'Delivery', 'Deliver',
    'Delivered', 'Parcel', 'Label', 'Failed', 'Alert', 'Helpdesk', 'Payroll', 'Salary', 'Cancelled', 'Closed',
    'Flagged', 'Online', 'Claim', 'Loan', 'File', 'Files')}
_LETTER_SWAP_TOKEN = re.compile(r"\b[A-Za-z]{4,}\b")


def _letter_swaps(text: str) -> list[str]:
    """Words of _LETTER_SWAP_WORDS written with I for l, or l for an initial i."""
    found = set()
    for token in set(_LETTER_SWAP_TOKEN.findall(text)):
        if token.lower() in _LETTER_SWAP_WORDS or token.isupper():
            continue
        candidates = []
        if 'I' in token[1:]:
            candidates.append((token[0] + token[1:].replace('I', 'l')).lower())
        if token[0] == 'l':
            candidates.append('i' + token[1:].lower())
        found.update(_LETTER_SWAP_WORDS[word] for word in candidates if word in _LETTER_SWAP_WORDS)
    return sorted(found)


def _detect_obfuscation(text: str) -> list[str]:
    """Detect leetspeak / homoglyph substitution tricks (e.g. P@yP@l, Amaz0n, PayPaI)."""
    found = []
    for pattern, brand in _OBFUSCATION_PAIRS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            matched = match.group(0).casefold()
            # The permissive patterns intentionally match both the original and
            # substituted spellings. Only report an evasion when normalization
            # actually changes the matched text into the protected term.
            if matched != brand.casefold() and normalize_homoglyphs(matched) == brand.casefold():
                found.append(brand)
                break
    return found + [word for word in _letter_swaps(text) if word not in found]


_HAN = re.compile(r"[\u3400-\u9fff\uf900-\ufaff]")
# What senders put inside Chinese words to break keyword matches: spaces and line breaks,
# brackets, quotes and symbols ("补〉贴", "《财 政》"). Sentence punctuation is not in it.
_HAN_FILLER = (r"[\s\u00b7\u2022\u30fb*#~^_|/\\=+.<>()\[\]{}《》〈〉【】〔〕（）［］｛｝「」『』“”‘’\"'"
               r"＊＃～＿｜／＝＋．＜＞]")


def _han_compact(text: str) -> str:
    """Text without whitespace, and without the fillers between Chinese characters."""
    text = re.sub(rf"(?<={_HAN.pattern}){_HAN_FILLER}+(?={_HAN.pattern})", "", text)
    return re.sub(r"\s+", "", text)


@lru_cache(maxsize=None)
def _keyword_pattern(keyword: str) -> re.Pattern:
    """The compiled pattern of one rule keyword: more keywords exist than re's own cache holds."""
    if _HAN.match(keyword):
        # Chinese has no spaces between words, so there is no word boundary to keep;
        # senders split phrases with spaces, line breaks or symbols ("确 认", "补〉贴"),
        # which are skipped.
        return re.compile(f"{_HAN_FILLER}*".join(map(re.escape, keyword)))
    escaped = re.escape(keyword)
    prefix = r"(?<!\w)" if keyword and keyword[0].isalnum() else ""
    # Python's word characters exclude apostrophes. Keep a negative contraction
    # together (won't is not won), while retaining possessives and quoted words.
    suffix = r"(?!\w|['’]t(?!\w))" if keyword and keyword[-1].isalnum() else ""
    return re.compile(prefix + escaped + suffix, re.IGNORECASE)


def _keyword_matches(text: str, keyword: str) -> bool:
    """Match phrases while preventing short tokens from firing inside words."""
    return bool(_keyword_pattern(keyword).search(text))


def _large_currency_amounts(text: str) -> list[str]:
    """Find patterns like $5,000,000 or USD 2000000 suggesting implausible winnings."""
    raw = re.finditer(r'(?:\$|usd|gbp|eur|€|£)\s*(\d[\d,.]*)', text, re.IGNORECASE)
    results = []
    for match in raw:
        number = ''.join(str(unicodedata.decimal(ch)) if ch.isdecimal() else ch
                         for ch in match.group(1)).rstrip('.,')
        # Common decimal styles have one/two fractional digits; grouping must
        # consist of three-digit groups. Reject malformed mixed grouping rather
        # than converting punctuation into a much larger integer.
        last_separator = max(number.rfind('.'), number.rfind(','))
        if last_separator >= 0 and len(number) - last_separator - 1 in {1, 2}:
            separator = number[last_separator]
            integer = number[:last_separator]
            if separator in integer:
                continue
        else:
            integer = number
        if '.' in integer or ',' in integer:
            if not (re.fullmatch(r'\d{1,3}(?:,\d{3})+', integer)
                    or re.fullmatch(r'\d{1,3}(?:\.\d{3})+', integer)):
                continue
        # No int/float conversion, including for arbitrarily long digit runs.
        digits = integer.replace(',', '').replace('.', '').lstrip('0')
        if len(digits) >= 5:
            amount = match.group(0).strip()
            results.append(amount[:80] + ('…' if len(amount) > 80 else ''))
            if len(results) == 4:
                break
    return results


def _count_generic_cta(text: str) -> int:
    """Count generic call-to-action phrases that hide real link destinations."""
    patterns = [
        r'\bclick here\b', r'\bclick now\b', r'\bclick below\b',
        r'\bclick this link\b', r'\bpress here\b', r'\btap here\b',
        r'\bfollow this link\b', r'\bopen this link\b',
    ]
    return sum(len(re.findall(p, text, re.IGNORECASE)) for p in patterns)


def _has_generic_salutation(text: str) -> bool:
    """Detect impersonal greetings that suggest bulk phishing campaigns."""
    generics = [
        r'\bdear\s+(sir|madam|sir/madam|customer|user|account\s+holder|'
        r'beneficiary|friend|winner|client|member|valued\s+customer|'
        r'valued\s+member|applicant)\b',
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in generics)


def _detect_non_native_phrases(text: str) -> list[str]:
    """Report regional/formal English variants without treating them as risk."""
    markers = [
        "kindly revert", "kindly do", "kindly note", "kindly confirm",
        "kindly send", "kindly provide", "revert back to me",
        "do the needful", "at the earliest", "i am mr.", "i am mrs.",
        "i am barrister", "i am dr.", "attached herewith",
        "please do the", "for your kind", "your swift response",
        "your prompt response", "be informed that",
        "we wish to inform", "we are pleased to inform",
        "i write to inform", "i write to bring",
        "seeking for", "in need of your",
    ]
    lower = text.lower()
    return [m for m in markers if m in lower]


def _mask_inline_data_payloads(text: str) -> str:
    """Keep image data bytes out of URL scans without hiding real destinations."""
    def mask_css_url(match):
        normalized = _unescape_css(match.group(0))
        if re.search(r'url\(\s*[\'\"]?\s*data:image/', normalized, re.IGNORECASE):
            return 'url(data:image/opaque)'
        return match.group(0)

    css_url = r"""url\(\s*(?:"(?:\\.|[^"<>])*"|'(?:\\.|[^'<>])*'|(?:\\.|[^)'"<>])*)\s*\)"""
    text = re.sub(css_url, mask_css_url, text, flags=re.IGNORECASE)
    return re.sub(r'data:image/[^\s\'"<>)]*', 'data:image/opaque', text, flags=re.IGNORECASE)


def _image_reference_counts(text: str, parse_warnings=None) -> tuple[int, int, int]:
    """Count embedded, remote, and unresolved image references without inspecting pixels."""
    data_image = re.compile(r'^\s*data:image/[a-z0-9.+-]+', re.IGNORECASE)
    data_css = re.compile(r'url\(\s*[\'\"]?\s*data:image/[a-z0-9.+-]+', re.IGNORECASE)
    remote_image = re.compile(r'^\s*(?:https?:)?//', re.IGNORECASE)
    remote_css = re.compile(r'url\(\s*[\'\"]?\s*(?:https?:)?//', re.IGNORECASE)
    css_url = re.compile(r'url\(\s*[\'\"]?([^\'\")\s]+)', re.IGNORECASE)

    def srcset_urls(value):
        """Read URL tokens without treating a data URI's comma as a separator."""
        position = 0
        while position < len(value):
            while position < len(value) and value[position] in ' \t\n\r\f,':
                position += 1
            start = position
            while position < len(value) and not value[position].isspace():
                position += 1
            token = value[start:position]
            if token.rstrip(','):
                yield token.rstrip(',')
            if not token.endswith(','):
                depth = 0
                while position < len(value):
                    character = value[position]
                    position += 1
                    if character == '(':
                        depth += 1
                    elif character == ')':
                        depth = max(0, depth - 1)
                    elif character == ',' and depth == 0:
                        break

    class ImageCollector(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.data_count = 0
            self.remote_count = 0
            self.unresolved_count = 0
            self.in_style = False
            self.in_script = False
            self.remote_base = None

        def is_remote(self, value):
            if remote_image.match(value):
                return True
            if not self.remote_base or data_image.match(value) or value.lstrip().startswith('#'):
                return False
            try:
                return bool(remote_image.match(urljoin(self.remote_base, value)))
            except ValueError:
                return False

        def add_reference(self, value):
            if data_image.match(value):
                self.data_count = min(20, self.data_count + 1)
            elif self.is_remote(value):
                self.remote_count = min(20, self.remote_count + 1)
            elif value.strip() and not value.lstrip().lower().startswith(('data:', '#')):
                self.unresolved_count = min(20, self.unresolved_count + 1)

        def add_css(self, value):
            without_comments = re.sub(r'/\*.*?\*/', '', value, flags=re.DOTALL)
            normalized = _unescape_css(without_comments)
            self.data_count = min(20, self.data_count + len(data_css.findall(normalized)))
            self.remote_count = min(20, self.remote_count + len(remote_css.findall(normalized)))
            for match in css_url.finditer(normalized):
                value = match.group(1)
                if not (data_image.match(value) or remote_image.match(value)):
                    self.add_reference(value)

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            if tag == 'script':
                self.in_script = True
                return
            if self.in_script:
                return
            if tag == 'style':
                self.in_style = True
            if tag == 'base':
                href = dict(attrs).get('href') or ''
                if remote_image.match(href):
                    self.remote_base = href
            for name, value in attrs:
                if not value:
                    continue
                if tag in {'img', 'source', 'v:imagedata', 'v:fill', 'image'}:
                    if name == 'src':
                        if tag != 'source' or data_image.match(value):
                            self.add_reference(value)
                    elif tag == 'image' and name in {'href', 'xlink:href'}:
                        self.add_reference(value)
                    elif name == 'srcset':
                        for url in srcset_urls(value):
                            self.add_reference(url)
                if name == 'background' and tag in {'body', 'table', 'td', 'th'}:
                    self.add_reference(value)
                if name == 'style':
                    self.add_css(value)

        def handle_endtag(self, tag):
            if tag == 'style':
                self.in_style = False
            elif tag == 'script':
                self.in_script = False

        def collect_data(self, data):
            if self.in_style and not self.in_script:
                self.add_css(data)

    collector = _collect_html(ImageCollector, text, parse_warnings)
    return collector.data_count, collector.remote_count, collector.unresolved_count


def _has_password_form(text: str, parse_warnings=None) -> bool:
    class FormCollector(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__()
            self.depth = 0
            self.form_ids = set()
            self.password_forms = []

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            attributes = dict(attrs)
            if tag == 'form':
                self.depth += 1
                if attributes.get('id'):
                    self.form_ids.add(attributes['id'])
            if tag == 'input' and (attributes.get('type') or '').lower() == 'password' and 'disabled' not in attributes:
                self.password_forms.append((self.depth > 0, attributes.get('form')))

        def handle_endtag(self, tag):
            if tag == 'form':
                self.depth = max(0, self.depth - 1)

    collector = _collect_html(FormCollector, text, parse_warnings)
    return any(in_form if form_id is None else form_id in collector.form_ids
               for in_form, form_id in collector.password_forms)


def _has_pressured_credential_request(text: str) -> bool:
    """Narrow conjunction, not a blanket penalty for password-reset notices."""
    pattern = r'\b(?:enter|provide|send|share|submit)\s+(?:(?:your|the)\s+)?(?:password|passcode|one-time password|otp code|credit card number)\b'
    for match in re.finditer(pattern, text, re.IGNORECASE):
        prefix = re.split(r'[.!?;]', text[max(0, match.start() - 100):match.start()])[-1]
        if re.search(r"\b(?:never(?:\s+ask(?:\s+you)?\s+to)?|do not|don't|must not|should not|will not|won't|not to)(?:\s+(?:ever|directly))?\s*$", prefix, re.IGNORECASE):
            continue
        context = text[max(0, match.start() - 240):match.end() + 240].lower()
        if all(any(_keyword_matches(context, keyword) for keyword in CONTENT_RULES[key]['keywords'])
               for key in ('urgency', 'threats')):
            return True
    return False


# What an email asks the reader to hand over. Genuine one-time-code emails say
# "enter this code"; asking the reader to send, reply with, share or read out a
# code, secret or payment is what official organizations say they never do.
_SENSITIVE_REQUEST_VERB = (r"(?:reply(?:\s+(?:back|to\s+(?:this\s+|our\s+)?(?:email|message|mail|text|us|me)))?\s+with"
                           r"|send(?:\s+(?:us|me|it|them|back))?|share|provide|give|tell|read(?:\s+(?:it|them))?\s+(?:out|back)"
                           # "email"/"text" alone are nouns ("email password"); only "email us", "text me" ask.
                           r"|forward|text\s+(?:us|me|back)|email\s+(?:us|me))")
# An optional recipient ("give the agent …", "tell our officer …") before the object.
_SENSITIVE_REQUEST_RECIPIENT = (r"(?:(?:to\s+)?(?:the|our|this|a|your)?\s*(?:agent|caller|officer|representative|technician|"
                                r"support(?:\s+team)?|team|advisor|specialist|us|me)\s+)?")
_SENSITIVE_REQUEST_DETERMINERS = r"(?:(?:your|the|this|that|these|those|all|both|two|three|a|an|new|received)\s+){0,3}"
_CODE_MODIFIER = (r"(?:\d[\s-]?digit|verification|security|confirmation|authentication|authorization|sign[\s-]?in|log[\s-]?in"
                  r"|access|sms|text|otp|2fa|two[\s-]?factor|one[\s-]?time)")
_SENSITIVE_REQUEST_OBJECTS = {
    'one_time_code': r"(?:(?:" + _CODE_MODIFIER + r"\s+){1,2}(?:pass)?codes?|one[\s-]?time\s+pass(?:code|word)s?|otps?)",
    'password_pin': r"(?:(?:online\s+banking\s+|account\s+|email\s+)?password|passcodes?|(?:card\s+|atm\s+)?pin(?:\s+(?:code|number))?)(?!\s+(?:change|reset|update)\b)",
    'recovery_secret': r"(?:(?:backup|recovery)(?:\s+(?:backup|recovery))?\s+(?:codes?|keys?|phrases?)|(?:seed|secret|recovery|mnemonic)\s+phrases?|private\s+keys?)",
    # A gift card by itself is retail; its number, code or PIN is what a scam collects.
    'gift_card': r"(?:gift\s*cards?|itunes\s+cards?|steam\s+cards?|google\s+play\s+cards?)\s+(?:numbers?|codes?|pins?|claim\s+codes?|details|photos?|pictures?)",
}
_SENSITIVE_REQUEST_EN = {
    kind: re.compile(r"\b" + _SENSITIVE_REQUEST_VERB + r"\s+" + _SENSITIVE_REQUEST_RECIPIENT + _SENSITIVE_REQUEST_DETERMINERS + obj + r"\b",
                     re.IGNORECASE)
    for kind, obj in _SENSITIVE_REQUEST_OBJECTS.items()
}
# Paying or buying with gift cards is ordinary retail ("pay with your gift card
# balance"); it becomes a scam signal when the reader must then hand the cards over.
_SENSITIVE_REQUEST_EN['gift_card_payment'] = re.compile(
    r"\b(?:pay(?:\s+(?:\w+\s+){0,3}?(?:with|using|via|in))?|buy|purchase)\s+(?:(?:some|a|an|the|two|three|several|\$?\d+)\s+)?(?:\w+\s+)?"
    r"(?:gift\s*cards?|itunes\s+cards?|steam\s+cards?|google\s+play\s+cards?)"
    r"(?![^.!?;\n]*\b(?:friends?|family|loved\s+ones?|recipients?|someone\s+special)\b)"  # gifting, not paying
    r"[^.!?;\n]{0,80}\b(?:send|reply|provide|give|text|email|share|scratch|photos?|pictures?|claim\s+codes?|card\s+numbers?)",
    re.IGNORECASE)
_SENSITIVE_REQUEST_EN['crypto_transfer'] = re.compile(
    r"\b(?:move|transfer|send)\s+(?:(?:all\s+)?(?:your|the)\s+)?(?:funds|money|savings|crypto(?:currency)?|bitcoin|btc|usdt|eth(?:ereum)?|coins|assets|balance)\s+"
    r"(?:\w+\s+){0,3}?to\s+(?:a|an|the|this|our|your)?\s*(?:(?:new|secure|safe|protected|verified|holding|temporary)\s+){1,2}(?:wallet|address|account|vault)\b",
    re.IGNORECASE)
_SENSITIVE_REQUEST_EN['remote_access'] = re.compile(
    r"\b(?:download|install|open|run|launch)\s+(?:the\s+)?(?:anydesk|teamviewer|ultraviewer|rustdesk|quick\s*assist|screenconnect|logmein|supremo)\b",
    re.IGNORECASE)
_SENSITIVE_REQUEST_ZH = {
    'one_time_code': re.compile(r"(?:回复|发送|发给|提供|告知|告诉|报给|转发|念给|读给|说出)(?:[^，。！？；,.!?;]{0,8})(?:验证码|校验码|动态码|动态口令|短信码)"
                                r"|(?:将|把)(?:[^，。！？；,.!?;]{0,8})(?:验证码|校验码|动态码|动态口令|短信码)(?:[^，。！？；,.!?;]{0,4})(?:回复|发送|发给|告知|告诉|提供|报给|转发)"),
    'password_pin': re.compile(r"(?:回复|发送|发给|提供|告知|告诉|报给|转发|说出)(?:[^，。！？；,.!?;]{0,8})(?:支付密码|取款密码|登录密码|银行卡密码|交易密码|密码)"
                               r"|(?:将|把)(?:[^，。！？；,.!?;]{0,8})(?:支付密码|取款密码|登录密码|银行卡密码|交易密码|密码)(?:[^，。！？；,.!?;]{0,4})(?:回复|发送|发给|告知|告诉|提供|报给)"),
    'recovery_secret': re.compile(r"(?:回复|发送|发给|提供|告知|告诉|说出)(?:[^，。！？；,.!?;]{0,8})(?:助记词|私钥|恢复码)"),
    'gift_card': re.compile(r"(?:回复|发送|发给|提供|告知|拍照)(?:[^，。！？；,.!?;]{0,8})(?:礼品卡|购物卡|充值卡)(?:[^，。！？；,.!?;]{0,4})(?:卡号|卡密|密码|兑换码)|(?:回复|发送|发给|提供|告知)(?:[^，。！？；,.!?;]{0,6})卡密"),
    'crypto_transfer': re.compile(r"(?:转账|转入|汇入|转移)(?:[^，。！？；,.!?;]{0,10})(?:安全账户|安全帐户|新钱包)"),
    'remote_access': re.compile(r"(?:下载|安装|打开)(?:[^，。！？；,.!?;]{0,6})(?:远程控制|向日葵|anydesk|teamviewer|会议软件)|共享屏幕|屏幕共享", re.IGNORECASE),
}
_SENSITIVE_REQUEST_NEGATION = re.compile(
    r"(?:\b(?:never|not|don['’]?t|do\s+not|won['’]?t|will\s+not|must\s+not|should\s+not|shouldn['’]?t|no\s+one|nobody|anyone\s+who|if\s+(?:someone|anyone|somebody|a\s+caller|they)"
    r"|asks?\s+you\s+to|asked\s+(?:you\s+)?to|requests?\s+(?:you\s+)?to|scammers?|fraudsters?|criminals?)\b"
    r"|不会|不要|切勿|请勿|勿|千万别|千万不要|绝不|绝对不|不得|严禁|任何人|凡是|如果有人|若有人|谨防|警惕|骗子)", re.IGNORECASE)
_SENSITIVE_REQUEST_CODES = {
    'one_time_code': 'content.sensitive_request.one_time_code',
    'password_pin': 'content.sensitive_request.password_pin',
    'recovery_secret': 'content.sensitive_request.recovery_secret',
    'gift_card': 'content.sensitive_request.gift_card',
    'gift_card_payment': 'content.sensitive_request.gift_card',
    'crypto_transfer': 'content.sensitive_request.crypto_transfer',
    'remote_access': 'content.sensitive_request.remote_access',
}


# Callback phishing: no link, just a phone number to "cancel", "dispute" or "refund" a
# charge the reader never made. Genuine receipts also list phone numbers, but for
# questions; the dispute or not-me framing next to the number is what separates them.
_CALLBACK_PHONE = re.compile(
    r"(?<![\d-])(?:\+?1[\s.-]*)?\(?[2-9]\d{2}\)?[\s.-]*\d{3}[\s.-]*\d{4}(?![\d-])"   # North American numbers
    r"|(?<!\d)(?:400|800)[\s-]?\d{3}[\s-]?\d{4}(?!\d)"                                 # 中国 400/800 服务号
)
_CALLBACK_TRIGGER = re.compile(
    # An unexpected charge or a not-me framing. "Refund policy", "change your reservation"
    # or "cancel this hotel booking" in genuine receipts do not count.
    r"\b(?:(?:was|is|wasn['’]t)\s+not\s+you|not\s+(?:authori[sz]ed|recogni[sz]ed)|did(?:n['’]t|\s+not)\s+(?:make|authori[sz]e|order|place|"
    r"recogni[sz]e|request)|do(?:n['’]t|\s+not)\s+recogni[sz]e|unauthori[sz]ed|if\s+(?:this|it)\s+wasn['’]t\s+you"
    r"|if\s+you\s+did(?:n['’]t|\s+not)"
    r"|dispute|(?:has|have)\s+been\s+(?:charged|debited|auto[\s-]?renewed|renewed)|will\s+be\s+(?:charged|debited)"
    r"|auto[\s-]?renew(?:al|ed)?|cancel\s+(?:(?:this|the|your|my)\s+)?(?:order|subscription|renewal|charge|payment|"
    r"transaction|membership|plan|purchase))\b"
    r"|扣款|扣费|自动续费|不是本人|非本人|未授权|取消(?:该|此|这笔)?(?:订单|订阅|服务|扣费|续费|交易)", re.IGNORECASE)
_CALLBACK_CALL = re.compile(r"\b(?:call|dial|phone|ring|reach|contact|helpline|toll[\s-]?free|support\s+(?:line|number))\b"
                            r"|致电|拨打|来电|联系客服|客服电话|热线", re.IGNORECASE)


# Letters written for digits in a phone number ("I(888) 673-593I"), a way to slip past
# number filters. Only a letter touching a digit or an opening bracket, and not part of
# a word, is read as a digit; the replacement keeps the text length.
_PHONE_LOOKALIKE = re.compile(r"(?<![A-Za-z])[Il|O](?=[\d(])|(?<=[\d)\-.])[Il|O](?![A-Za-z])")
_PHONE_LOOKALIKE_DIGITS = {"I": "1", "l": "1", "|": "1", "O": "0"}


def _callback_request(text: str, official_numbers=frozenset()) -> str | None:
    """A phone number asked to be called, with dispute/cancel/refund framing within ~200 characters.

    Numbers published as an organization's official service numbers never count.
    """
    unmasked = _PHONE_LOOKALIKE.sub(lambda match: _PHONE_LOOKALIKE_DIGITS[match.group(0)], text)
    for match in _CALLBACK_PHONE.finditer(unmasked):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) < 7 or digits in official_numbers or digits.lstrip("1") in official_numbers:
            continue
        window = text[max(0, match.start() - 200):match.end() + 200]
        if _CALLBACK_CALL.search(window) and _CALLBACK_TRIGGER.search(window):
            return text[match.start():match.end()].strip()
    return None


# Subsidy and tax-refund lures ("2023年个人劳动补贴，当天未完成视为放弃申领",
# "高温补助-请今日立即申请"): a payment the reader must claim at once or by scanning a
# code. A genuine notice about a high-temperature allowance alone does not match; the
# pressure must be there too.
_SUBSIDY_TERM = re.compile(r"劳动补贴|补贴申领|申领补贴|补贴领取|领取补贴|个税退税|退税申请|退税申领|纳税人退税"
                           r"|社保补贴|医保补贴|高温补[贴助]|工资补贴|财政补贴|劳动津贴")
_SUBSIDY_PRESSURE = re.compile(r"视为放弃|逾期(?:将)?(?:不予|作废|视为)|当[天日]内?未完成|今日内?(?:立即)?申请|立即申领"
                               r"|扫码|二维码|扫描.{0,6}(?:申领|领取|办理)")


def _subsidy_lure(text: str) -> bool:
    compact = _han_compact(text)
    return bool(_SUBSIDY_TERM.search(compact) and _SUBSIDY_PRESSURE.search(compact))


# Mailbox credential lures: the mail system is upgrading, full, moving or closing (in one
# sentence), and a link labelled with the fix ("点此登录完成本次升级") leaves the sender's
# domain for one no registry lists. Providers' and schools' own notices link to their own
# domains, or to a mail provider's sign-in.
_MAILBOX_TERM = r"邮箱|郵箱|邮件系统|郵件系統|电子邮件|電子郵件|帐户|账户|帳戶|账号|帳號"
_MAILBOX_STATE = (r"升级|升級|迁移|遷移|切换|切換|备案|備案|容量|上限|已满|已滿|过期|過期|停用|暂停|暫停"
                  r"|停止服务|停止服務|关闭|關閉|冻结|凍結|注销|註銷|受限|限制|禁用|失效")
_MAILBOX_LURE = re.compile(rf"(?:{_MAILBOX_TERM})[^。！？!?]{{0,30}}(?:{_MAILBOX_STATE})"
                           rf"|(?:{_MAILBOX_STATE})[^。！？!?]{{0,30}}(?:{_MAILBOX_TERM})")
_MAILBOX_ACTION = re.compile(r"登录|登陆|登入|登錄|升级|升級|验证|驗證|激活|啟用|启用|扩容|擴容|清理|恢复|恢復"
                             r"|解除|移除|保留|保持|迁移|遷移|备案|備案|点此|點此|点击|點擊")
_MAIL_SIGN_IN_DOMAINS = _CONSUMER_MAILBOX_DOMAINS | {'office.com', 'office365.com', 'microsoftonline.com'}
# The same lures in English and other languages. Only threats to the mailbox count (full,
# blocked, held, expiring, closing): "verify your email address" is how genuine sign-ups
# begin, often through a mailing service's tracking domain.
_MAILBOX_TERM_EN = (r"(?:mail\s?box(?:es)?|e-?mails?(?:\s+accounts?)?|mail\s+accounts?|inbox(?:es)?|webmail|mail\s+server"
                    r"|incoming\s+(?:mails?|messages))")
_MAILBOX_STATE_EN = (r"(?:quota|storage\s+(?:is\s+)?(?:full|limit)|(?:almost|is|now)\s+full|exceeded"
                     r"|reached\s+(?:its|the|your)\s+(?:limit|capacity)|deactivat\w*|suspend\w*|terminat\w*|clos(?:e|ed|ing|ure)\b"
                     r"|expir\w*|disabled|disconnect\w*|blocked|restricted|pending|undelivered|on\s+hold|held|stuck"
                     r"|failed\s+to\s+(?:be\s+)?deliver\w*|not\s+(?:been\s+)?delivered|delayed|shut\s*down|delet(?:e|ed|ion)"
                     r"|de-?activation|re-?activation|upgrade\s+required|server\s+error|out\s+of\s+date|new\s+version"
                     r"|requires?\s+(?:an?\s+)?(?:immediate\s+|urgent\s+)?(?:update|upgrade|verification|validation))")
_MAILBOX_LURE_OTHER = re.compile(
    rf"\b{_MAILBOX_TERM_EN}\b[^.!?\n]{{0,80}}\b{_MAILBOX_STATE_EN}|\b{_MAILBOX_STATE_EN}[^.!?\n]{{0,80}}\b{_MAILBOX_TERM_EN}\b"
    r"|(?:우편함|메일함|계정|이메일)[^.!?\n]{0,40}(?:할당량|폐쇄|중단|차단|만료|삭제|업그레이드)"
    r"|(?:почтов\w+\s+ящик|ящик|квота|аккаунт|обліков\w+)[^.!?\n]{0,40}"
    r"(?:истекает|перевищен\w*|превышен\w*|заблокир\w+|отключ\w+|видал\w+)"
    r"|(?:アカウント|メールボックス)[^。！？\n]{0,40}(?:再認証|停止|制限|凍結|削除)"
    r"|(?:كلمة\s+(?:المرور|السر)|حساب|البريد)[^.!?\n]{0,60}(?:تنتهي|انتهاء|إيقاف|تعليق|حظر)"
    r"|messages?\s+bloqu\w+|bo[iî]te\s+(?:aux\s+lettres|mail)[^.!?\n]{0,40}(?:pleine|bloqu\w+|expir\w+|suspend\w+)"
    r"|caixa\s+de\s+(?:correio|e-?mail)[^.!?\n]{0,40}(?:cheia|bloquead\w+|expir\w+|suspens\w+)"
    r"|buz[oó]n[^.!?\n]{0,40}(?:lleno|bloquead\w+|expir\w+|suspendid\w+)"
    # The mail account's password expiring, and mail that can no longer be sent or received.
    r"|\bpassword\s+(?:for\s+)?(?:your\s+)?(?:address|e-?mail|mail\s?box|webmail)\b[^.!?\n]{0,60}\bexpir\w*"
    r"|\b(?:address|e-?mail|mail\s?box|webmail)\s+(?:account\s+)?password\b[^.!?\n]{0,40}\bexpir\w*"
    r"|\b(?:unable|not\s+(?:be\s+)?able|won.?t\s+be\s+able|cannot|can.?t)\s+to\s+send\s+(?:and|or)\s+receive\b",
    re.IGNORECASE)
_MAILBOX_ACTION_OTHER = re.compile(
    r"\b(?:upgrade|log\s?in|login|sign\s?in|update|restore|release|retrieve|recover|keep|re-?activate|increase|unlock"
    r"|deliver|resolve|fix|retain|migrate|activate|validate|verify|confirm|access|view|review|click\s+here|continue"
    r"|read\s+(?:\w+\s+)?(?:messages|mails?|e-?mails))\b"
    r"|업그레이드|확인|로그인|추가|обнов\w+|онов\w+|войти|увійти|продовж\w+|再認証|ログイン|تحديث|تسجيل|متابعة|استخدام"
    r"|\blire\b|\bvoir\b"
    r"|atualiz\w+|verificar|actualizar", re.IGNORECASE)


# Places on trusted platforms where anyone can publish: documents, drawings, forms, sites
# and shared files. A lure's button often leads there, because the domain itself is
# trusted. (host, path) patterns; for_actions marks those an account or payment button
# never leads to in genuine mail (company SharePoint sites do).
_USER_CONTENT_LOCATIONS = tuple((re.compile(host, re.IGNORECASE), re.compile(path, re.IGNORECASE) if path else None, actions)
                                for host, path, actions in (
    (r'docs\.google\.com', r'^/(?:drawings|forms|presentation|document|spreadsheets)/', True),
    (r'forms\.gle', '', True), (r'sites\.google\.com', '', True),
    (r'drive\.google\.com', r'^/(?:file|open|uc)\b', True), (r'script\.google\.com', r'^/macros/', True),
    (r'(?:firebasestorage|storage)\.googleapis\.com', '', True),
    (r'forms\.office\.com|forms\.microsoft\.com', '', True),
    (r'onedrive\.live\.com|1drv\.ms', '', True),
    (r'(?:www\.)?dropbox\.com', r'^/(?:s|scl|sh)/', True),
    (r'[\w-]+\.notion\.site', '', True), (r'(?:www\.)?canva\.com', r'^/design/', True),
    (r'docs\.qq\.com|(?:www\.)?kdocs\.cn|shimo\.im', '', True),
    (r'[\w-]+(?:-my)?\.sharepoint\.com', r'^/(?::[a-z]:/|sites/|personal/)', False),
))
# Buttons that act on an account or a payment. "Confirm" or "Sign in" alone also label
# event forms and sign-in sheets.
_ACCOUNT_ACTION = re.compile(
    r"\b(?:log\s?in|sign\s?in\s+to\s+(?:your\s+)?account|(?:verify|confirm|validate)\s+(?:your\s+)?"
    r"(?:account|identity|information|details|payment|billing)|update\s+(?:your\s+)?(?:information|info|account|payment"
    r"|billing|details|card)|unlock|restore\s+(?:your\s+)?account|re-?activate|keep\s+(?:my\s+)?(?:password|account)"
    r"|secure\s+(?:your\s+)?account)\b", re.IGNORECASE)


def _user_content_location(destination: str, *, actions: bool = False) -> bool:
    """Whether a link leads to content anyone can publish on a trusted platform."""
    try:
        target = _parse_link_target(destination)
    except ValueError:
        return False
    # Servers read /%64ocument/ as /document/.
    host, path = (target.hostname or '').lower().rstrip('.'), unquote(target.path or '/')
    return any(pattern.fullmatch(host) and (place is None or place.search(path)) and (for_actions or not actions)
               for pattern, place, for_actions in _USER_CONTENT_LOCATIONS)


def _user_content_action(links) -> bool:
    """An account or payment button that leads to a published document, form or site."""
    return any(_ACCOUNT_ACTION.search(label or '') and _user_content_location(destination, actions=True)
               for label, destination in links or ())


def _unlisted_off_sender_host(destination: str, sender_domain: str) -> str | None:
    """The host of a link that leaves the sender's domain for one no registry lists.

    Published documents and forms on trusted platforms count as unlisted, whatever the
    From domain claims: anyone can publish there, and a From of google.com is not proof
    of anything. A known mail provider's sign-in does not count.
    """
    try:
        host = (_parse_link_target(destination).hostname or '').lower().rstrip('.')
    except ValueError:
        return None
    sender = _organizational_domain(sender_domain) if '.' in sender_domain else ''
    domain = _organizational_domain(host) if host else ''
    if domain and (_user_content_location(destination) or not (sender and domain == sender) and (
            domain not in _MAIL_SIGN_IN_DOMAINS and not _official_sender(domain))):
        return host
    return None


# The reader's address inside a sentence ("квота jose@example.org перевищена") would end
# the sentence at its dots.
_MAIL_ADDRESS = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Labels in small capitals ("Cᴏɴғɪʀᴍ ᴀᴄᴄᴏᴜɴᴛ"), which have no compatibility decomposition.
_SMALL_CAPITALS = str.maketrans({'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ꜰ': 'f', 'ғ': 'f', 'ɢ': 'g',
                                 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o',
                                 'ᴘ': 'p', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z'})


def _mailbox_lure(text: str, links, sender_domain: str = '') -> bool:
    """A mailbox lure whose action link leads off the sender's domain to an unlisted one."""
    text = _MAIL_ADDRESS.sub(' address ', text)
    if not (_MAILBOX_LURE.search(_han_compact(text)) or _MAILBOX_LURE_OTHER.search(text)):
        return False
    labels = (((label or '').translate(_SMALL_CAPITALS), destination) for label, destination in links or ())
    return any((_MAILBOX_ACTION.search(_han_compact(label)) or _MAILBOX_ACTION_OTHER.search(label))
               and _unlisted_off_sender_host(destination, sender_domain)
               for label, destination in labels)


# Account-hold lures in document attachments: the body says a line or nothing, and a PDF
# says the reader's account, access or a payment is restricted, on hold or compromised,
# asks them to verify or sign on, and links off the sender's domain. The text model never
# reads attachments. On message text, the wording (without the link) appears in 2 of
# 9,198 genuine DIFraud messages, none of 16,440 marketing emails, and 1,408 of 6,074
# DIFraud fraud messages.
_HOLD_OWNER = r"(?:your|this|the)\s+(?:[\w-]+\s+){0,2}?"
_HOLD_ACCOUNT = r"(?:accounts?|access|online\s+banking|profile)"
_HOLD_MONEY = r"(?:(?:debit\s+|credit\s+)?cards?|payments?|transfers?|deposits?|transactions?|funds)"
_HOLD_STATE = (r"(?:restrict(?:ed|ions?)|suspen(?:ded|sion|d)|(?:is|are|be|been|was|temporarily)\s+limited|limitations?"
               r"|locked|blocked|disabled|deactivated|frozen|compromised|on\s+hold|(?:been|put)\s+(?:a\s+)?(?:on\s+)?hold"
               r"|hold\s+on|prevented|pending\s+(?:verification|approval|confirmation)|revers(?:al|ed)"
               # "regain full access": genuine resets say "regain access to your account".
               r"|(?:regain|restore)\s+full\s+access)")
# Only an account ends: "your card expired" is how genuine payment reminders begin.
_HOLD_ENDED = r"(?:expired|closed|terminated|cancell?ed)"
_ACCOUNT_HOLD = re.compile(
    rf"\b{_HOLD_OWNER}(?:{_HOLD_ACCOUNT}\b[^.!?]{{0,80}}?\b(?:{_HOLD_STATE}|{_HOLD_ENDED})"
    rf"|{_HOLD_MONEY}\b[^.!?]{{0,80}}?\b{_HOLD_STATE})\b"
    rf"|\b(?:{_HOLD_STATE}|{_HOLD_ENDED})\b[^.!?]{{0,60}}?\b{_HOLD_OWNER}{_HOLD_ACCOUNT}\b"
    rf"|\b{_HOLD_STATE}\b[^.!?]{{0,60}}?\b{_HOLD_OWNER}{_HOLD_MONEY}\b", re.IGNORECASE)
# "has not been compromised"; "is not updated now, it will be restricted" still holds.
_HOLD_NEGATED = re.compile(rf"(?:\bnot|\bnever|n't)\s+(?:(?:been|be|being|yet|temporarily)\s+){{0,2}}"
                           rf"(?:{_HOLD_STATE}|{_HOLD_ENDED})\b", re.IGNORECASE)
_HOLD_ACTION = re.compile(r"\b(?:verify|update|re-?confirm|confirm|validate|unlock|restore|re-?activate|log\s?on|log\s?in"
                          r"|login|sign[\s-]?on|sign[\s-]?in|approve|accept)\b", re.IGNORECASE)


def _account_hold_lure(text: str) -> bool:
    """Text saying an account or payment is held, with a request to verify or sign on near it."""
    text = re.sub(r'\s+', ' ', text or '')  # PDF lines break mid-sentence
    for match in _ACCOUNT_HOLD.finditer(text):
        if not _HOLD_NEGATED.search(match.group(0)) and _HOLD_ACTION.search(
                text[max(0, match.start() - 300):match.end() + 400]):
            return True
    return False


# File-sharing notices whose button leaves the service: "info@… sent you some files" in
# WeTransfer's layout, "shared a file with you using OneDrive", with the Download or Open
# button on an unrelated host. Genuine notices link to the service's own domains (listed
# here with their short-link and e-signature domains), or a company's own SharePoint.
# The wording appears in none of the 92 genuine downloads, 5,055 Apache list messages,
# 9,198 genuine DIFraud messages or 16,440 marketing emails.
_FILE_SHARE_SERVICES = {
    'WeTransfer': ('wetransfer.com', 'we.tl'),
    'OneDrive': ('onedrive.com', 'live.com', '1drv.ms', 'sharepoint.com', 'microsoft.com', 'office.com',
                 'microsoftonline.com', 'office365.com', 'aka.ms'),
    'SharePoint': ('sharepoint.com', 'microsoft.com', 'office.com', 'microsoftonline.com', 'office365.com', 'aka.ms'),
    'Dropbox': ('dropbox.com', 'dropboxmail.com', 'db.tt', 'hellosign.com'),
    'Google Drive': ('google.com', 'goo.gl', 'googleusercontent.com'),
    'DocuSign': ('docusign.com', 'docusign.net'),
}
_FILE_SHARE_DOMAINS = frozenset(domain for domains in _FILE_SHARE_SERVICES.values() for domain in domains)
_FILE_SHARE_NAME = re.compile(r"\b(?:(we\s?transfer)|(one\s?drive)|(share\s?point)|(dropbox)|(google\s+drive)|(docu\s?sign))\b",
                              re.IGNORECASE)
_FILE_SHARE_NOTICE = re.compile(
    r"\b(?:sent|shared)\s+(?:you\s+)?(?:(?:a|an|the|some|\d+)\s+)?(?:new\s+)?(?:pdf\s+)?(?:files?|documents?|folders?|items?)\b"
    r"|\bshared\s+(?:(?:a|an|the|some|\d+)\s+)?(?:files?|documents?|folders?)\s+with\s+you\b"
    r"|\b(?:received|have)\s+(?:(?:a|some|\d+)\s+)?(?:new\s+)?(?:pdf\s+)?(?:files?|documents?)\s+(?:via|from|through|using)\b"
    r"|\b(?:files?|documents?|docs|folders?)\s+shared\s+with\s+you\b"
    r"|\b(?:has|have)\s+been\s+(?:sent|shared|uploaded)\s+(?:to\s+you\s+)?(?:using|via|through|on)\s+(?:the\s+)?"
    r"(?:we\s?transfer|one\s?drive|share\s?point|dropbox|google\s+drive|docu\s?sign)\b"
    r"|\b(?:files?|documents?|folders?)\b[^.!?]{0,40}\b(?:was|were|has\s+been|have\s+been)\s+shared\s+with\s+you\b"
    r"|\b(?:files?|documents?|items?)\b[^.!?]{0,40}\b(?:will\s+be\s+deleted|expires?\s+on)\b"
    r"|\b(?:get|download|view|access|open|retrieve)\s+(?:your\s+|the\s+)?(?:completed\s+|shared\s+)?(?:files?|documents?)\b",
    re.IGNORECASE)
_FILE_SHARE_ACTION = re.compile(r"\b(?:download|open|view|get|access|review|preview|retrieve|see)\b", re.IGNORECASE)


def _file_share_elsewhere(text: str, display_name: str, links, sender_domain: str = '') -> tuple[str, str] | None:
    """(service, host) when a file-sharing notice's button leaves the service it names."""
    text = re.sub(r'\s+', ' ', _strip_invisible_format_controls(text or ''))
    named = _FILE_SHARE_NAME.search(display_name or '') or _FILE_SHARE_NAME.search(text)
    if not (named and _FILE_SHARE_NOTICE.search(text)):
        return None
    service = tuple(_FILE_SHARE_SERVICES)[named.lastindex - 1]
    for label, destination in links or ():
        label = _strip_invisible_format_controls(label or '')
        if not label.strip() and destination in text:
            # A bare address in plain text: its instruction stands just before it
            # ("Press Here sign in with your email to view the message. http://…").
            label = text[max(0, text.index(destination) - 120):text.index(destination)]
        if not _FILE_SHARE_ACTION.search(label):
            continue
        host = _unlisted_off_sender_host(destination, sender_domain)
        if host and _organizational_domain(host) not in _FILE_SHARE_DOMAINS:
            return service, host
    return None


# Delivery lures: a parcel held for an unpaid shipping or customs fee ("A R 25.00 shipping
# cost have not been paid", "Confirm the shipping fee 50 ZAR"), or undeliverable for a
# wrong address the reader must correct, with the button on an unrelated host. Carriers'
# official domains, the sender's own and the tracking platforms retailers use are exempt.
# "Sorry we missed you, reschedule" alone is left out: genuine retailers send it. The
# wording appears in none of the 92 genuine downloads, 5,055 Apache list messages, 9,198
# genuine DIFraud messages or 16,440 marketing emails.
_DELIVERY_PARCEL = re.compile(r"\b(?:packages?|parcels?|shipments?|deliver(?:y|ies|ed)?|couriers?|consignments?)\b",
                              re.IGNORECASE)
_DELIVERY_CHARGE = (r"(?:shipping|delivery|re-?delivery|customs|postage|handling|clearance)\s+"
                    r"(?:fees?|costs?|charges?|dut(?:y|ies))")
_DELIVERY_FEE = re.compile(
    rf"\b{_DELIVERY_CHARGE}\b[^.!?]{{0,40}}?\b(?:(?:have|has)\s+not\s+(?:yet\s+)?been\s+paid|not\s+(?:been\s+)?paid"
    rf"|unpaid|outstanding|due)\b"
    rf"|\b(?:pay|confirm|settle)\s+(?:the\s+|a\s+|your\s+)?(?:outstanding\s+|small\s+)?{_DELIVERY_CHARGE}\b"
    rf"|\b{_DELIVERY_CHARGE}\s+(?:of\s+)?(?:[$€£]\s?\d|\d+(?:[.,]\d+)?\s?(?:usd|eur|gbp|zar|aud|cad|r\b))",
    re.IGNORECASE)
_DELIVERY_ADDRESS = re.compile(
    r"\b(?:incorrect|incomplete|wrong|invalid|insufficient|unclear|mix[\s-]?up\s+in\s+(?:your|the))\s+"
    r"(?:delivery\s+|shipping\s+|recipient\s+)?address|\bunable\s+to\s+locate\s+(?:you|your\s+address)",
    re.IGNORECASE)
_DELIVERY_ADDRESS_FIX = re.compile(
    r"\b(?:update|confirm|fill(?:\s+in)?|correct|verify|provide|re-?enter|enter)\s+(?:your\s+|the\s+)?"
    r"(?:correct\s+|full\s+|complete\s+)?(?:delivery\s+|shipping\s+)?address", re.IGNORECASE)
_DELIVERY_ACTION = re.compile(r"\b(?:update|confirm|continue|pay|click\s+here|schedule|reschedule|submit|verify|proceed"
                              r"|track|release|redeliver|correct)\b", re.IGNORECASE)
_DELIVERY_TRACKING_DOMAINS = frozenset({'narvar.com', 'aftership.com', 'route.com', 'parcelpanel.com', '17track.net',
                                        'shopify.com'})


# Unpaid fine and toll lures: "Multa no pagada", "unpaid toll balance", "交通违法", with a
# link to view or pay that leaves the sender's domain for one that is neither listed nor
# a government's. Authorities and toll operators link to their own or government sites.
# The wording appears in no message of the genuine downloads, Apache lists, genuine
# DIFraud or marketing sets.
_FINE_LURE = re.compile(
    r"\b(?:unpaid|outstanding|overdue|pending|unsettled)\s+(?:(?:road\s+)?tolls?|toll\s+(?:balance|charges?|invoice)"
    r"|(?:traffic|parking|speeding)\s+(?:fines?|tickets?|violations?|penalt(?:y|ies))|fines?|penalty\s+(?:notice|charges?))\b"
    r"|\b(?:tolls?|traffic|parking|speeding)\s+(?:fines?|tickets?|violations?|penalt(?:y|ies)|charges?|balance)\b"
    r"[^.!?]{0,60}?\b(?:unpaid|outstanding|overdue|not\s+(?:been\s+)?paid|past\s+due)\b"
    r"|\bpenalty\s+charge\s+notice\b"
    r"|\bmulta(?:\s+de\s+tr[aá]fico)?\s+(?:pendiente|no\s+pagada|impagada|pendente|n[aã]o\s+paga|non\s+pagata)"
    r"|\bmulta\s+de\s+tr[aá]fico\b|\bamende\s+(?:impay[ée]e|non\s+r[ée]gl[ée]e|en\s+attente)|\bavis\s+de\s+contravention\b"
    r"|\bsanzione\s+(?:non\s+pagata|pendente)\b|\b(?:offene[sn]?|unbezahlte[sn]?)\s+(?:bu(?:ß|ss)geld|strafzettel"
    r"|verwarnungsgeld|maut)\w*"
    r"|交通违法|违章(?:罚款|缴费|处理|记录)|未缴(?:纳)?(?:的)?罚款|罚款未(?:缴|交)|ETC.{0,8}(?:失效|停用|过期|异常)", re.IGNORECASE)
# Government suffixes are those the Public Suffix List names (gov.uk, go.jp, gc.ca,
# nsw.gov.au, .gov): a second level anyone may register (go.to) is none.
_GOVERNMENT_LABELS = frozenset({'gov', 'gob', 'gouv', 'govt', 'go', 'gc', 'gv'})


def _government_host(host: str) -> bool:
    suffix = _ORGANIZATIONAL_DOMAINS(host).suffix.split('.')
    return (suffix in (['gov'], ['mil']) or bool(_GOVERNMENT_LABELS.intersection(suffix[:-1]))
            or host.endswith(('.admin.ch', '.bund.de')))


# A link carrying the recipient's own address ("?email=jose@example.org", or in base64) to
# a site that is neither the sender's nor listed: phishing kits pre-fill their sign-in
# page so it looks like the reader's own account. 1,324 of 3,466 Nazario messages carry
# one; none of the 92 genuine downloads or 5,055 Apache list messages do. Unsubscribe and
# preference links, which carry the address in genuine mail, are left out.
_SUBSCRIPTION_LINK = re.compile(r"unsubscribe|opt[-_]?out|preferences|manage[-_]?(?:subscription|email)|email[-_]?settings"
                                r"|退订|取消订阅", re.IGNORECASE)
# Mailchimp's list-management domain.
_SUBSCRIPTION_HOSTS = frozenset({'list-manage.com'})


def _subscription_link(label: str, destination: str) -> bool:
    """An unsubscribe or preferences link, by its label, its path or a list-management
    host: a word anywhere else in the URL ("?preferences=0") proves nothing."""
    if _SUBSCRIPTION_LINK.search(label or ''):
        return True
    try:
        target = _parse_link_target(destination)
    except ValueError:
        return False
    host = (target.hostname or '').lower().rstrip('.')
    return (_organizational_domain(host) in _SUBSCRIPTION_HOSTS if host else False) or bool(
        _SUBSCRIPTION_LINK.search(unquote(target.path or '')))


def _recipient_prefilled_link(links, recipients, sender_domain: str = '') -> str | None:
    """The host of an unlisted link, off the sender's domain, whose URL carries a recipient's address."""
    forms = set()
    for recipient in recipients or ():
        address = recipient.strip().lower()
        if '@' in address:
            encoded = base64.b64encode(address.encode()).decode().rstrip('=').lower()
            forms |= {address, encoded, encoded.replace('+', '-').replace('/', '_')}
    if not forms:
        return None
    for label, destination in links or ():
        if _subscription_link(label, destination):
            continue
        host = _unlisted_off_sender_host(destination, sender_domain)
        if not host:
            continue
        try:
            target = _parse_link_target(destination)
        except ValueError:
            continue
        tail = unquote(unquote(f"{target.path or ''}?{target.query or ''}#{target.fragment or ''}")).lower()
        if any(form in tail for form in forms):
            return host
    return None


def _fine_lure(text: str, links, sender_domain: str = '') -> str | None:
    """The host an unpaid-fine or toll notice links to, off the sender's and government domains."""
    if not _FINE_LURE.search(re.sub(r'\s+', ' ', text or '')):
        return None
    for _label, destination in links or ():
        host = _unlisted_off_sender_host(destination, sender_domain)
        if host and not _government_host(host):
            return host
    return None


def _lure_points(item: dict) -> int:
    """The points of a lure finding (fine, delivery, account hold, file share), which also
    sets its level as the floor. Email and SMS (sms_analysis.py) score lures alike."""
    return 4 if item['level'] == 'high' else 3


def _delivery_wording(text: str) -> bool:
    """A parcel, and a fee to pay or an address to correct."""
    text = re.sub(r'\s+', ' ', text or '')
    return bool(_DELIVERY_PARCEL.search(text) and (
        _DELIVERY_FEE.search(text) or (_DELIVERY_ADDRESS.search(text) and _DELIVERY_ADDRESS_FIX.search(text))))


def _delivery_lure(text: str, links, sender_domain: str = '') -> str | None:
    """The host a delivery-fee or wrong-address lure's button leads to, off the sender's domain."""
    if not _delivery_wording(text):
        return None
    for label, destination in links or ():
        if _DELIVERY_ACTION.search(label or ''):
            host = _unlisted_off_sender_host(destination, sender_domain)
            if host and _organizational_domain(host) not in _DELIVERY_TRACKING_DOMAINS:
                return host
    return None


# Texts rarely ask for a fee outright: "set delivery preferences", "the scheduled delivery
# changed, please confirm here". "Track" is left out, as genuine notices invite it.
_SMS_PARCEL_ACTION = re.compile(r"\b(?:confirm|update|set|schedule|reschedule|verify|pay|release|redeliver|claim)\b",
                                re.IGNORECASE)


def _sms_delivery_lure(text: str, links) -> str | None:
    """_delivery_lure for a text message, whose links are bare, with no button to read: a
    parcel, an action to take, and a link that is neither official nor a known tracker."""
    if not (_delivery_wording(text) or (_DELIVERY_PARCEL.search(text) and _SMS_PARCEL_ACTION.search(text))):
        return None
    for _label, destination in links or ():
        host = _unlisted_off_sender_host(destination, '')
        if host and _organizational_domain(host) not in _DELIVERY_TRACKING_DOMAINS:
            return host
    return None


# Domains registered this recently are named in the result (registry RDAP records).
_NEW_DOMAIN_DAYS = 90


def _registration_candidates(sender: str, link_hosts) -> list[tuple[str, str]]:
    """(role, registrable domain) pairs whose registration date is worth asking: the From
    domain, then link domains. Official brands, mail providers, file-sharing services and
    hosts on shared suffixes (alice.github.io, whose suffix's age says nothing) are left
    out, as are IP addresses."""
    sender_host = parseaddr(sender)[1].rpartition('@')[2].lower().rstrip('.')
    found = []
    for role, host in [('sender', sender_host)] + [('link', host) for host in link_hosts]:
        if not host or '.' not in host or _is_ip_host(host):
            continue
        domain = _organizational_domain(host)
        if (domain != _registrable_domain(host) or domain in _CONSUMER_MAILBOX_DOMAINS or domain in _FILE_SHARE_DOMAINS
                or _official_sender(domain) or any(known == domain for _role, known in found)):
            continue
        found.append((role, domain))
    return found[:domain_age.MAX_LOOKUPS_PER_MESSAGE]


def _registration_findings(candidates, dates, now=None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    findings = []
    for role, domain in candidates:
        date = dates.get(domain)
        if date is None:
            continue
        days = max(0, (now - date).days)
        if days < _NEW_DOMAIN_DAYS:
            findings.append(indicator('info', 'sender.recently_registered' if role == 'sender'
                                      else 'link.recently_registered', domain=domain,
                                      date=date.date().isoformat(), days=days))
    return findings


def _account_hold_link(text: str, links, sender_domain: str = '') -> str | None:
    """The host a message body's account-hold lure links to, off the sender's domain.

    The attachment rule's wording, read in the body: genuine account notices use it too
    (2 of the 92 genuine downloads), but link to the service's own or an official domain.
    In Nazario, 429 of 3,466 messages fire; no genuine download or Apache list message
    does. Medium only, as a genuine notice sent through an unlisted click-tracking domain
    would match."""
    if not _account_hold_lure(text):
        return None
    return next(filter(None, (_unlisted_off_sender_host(destination, sender_domain)
                              for _label, destination in links or ())), None)


def _attachment_account_lure(attachment: dict, sender_domain: str) -> str | None:
    """The host an account-hold lure in a document attachment links to, off the sender's domain."""
    if not _account_hold_lure(attachment.get('extracted_text') or ''):
        return None
    return next(filter(None, (_unlisted_off_sender_host(destination, sender_domain)
                              for destination in attachment.get('extracted_links', ()))), None)


# In attachments, which have no button labels to read, only the mailbox itself counts:
# "this email" beside "pending" is no mailbox lure.
_MAILBOX_ACCOUNT_EN = (r"(?:mail\s?box(?:es)?|e-?mail\s+accounts?|mail\s+accounts?|inbox(?:es)?|web-?mail(?:\s+accounts?)?"
                       r"|mail\s+server)")
_ATTACHMENT_MAILBOX_LURE = re.compile(rf"\b{_MAILBOX_ACCOUNT_EN}\b[^.!?\n]{{0,80}}\b{_MAILBOX_STATE_EN}"
                                      rf"|\b{_MAILBOX_STATE_EN}[^.!?\n]{{0,80}}\b{_MAILBOX_ACCOUNT_EN}\b", re.IGNORECASE)


def _attachment_mailbox_lure(attachment: dict, sender_domain: str) -> str | None:
    """The host a mailbox lure in a document attachment links to, off the sender's domain:
    the body says a line or nothing, and a Word file says the mailbox needs an update."""
    text = re.sub(r'\s+', ' ', _MAIL_ADDRESS.sub(' address ', attachment.get('extracted_text') or ''))
    if not (_MAILBOX_LURE.search(_han_compact(text)) or _ATTACHMENT_MAILBOX_LURE.search(text)):
        return None
    return next(filter(None, (_unlisted_off_sender_host(destination, sender_domain)
                              for destination in attachment.get('extracted_links', ()))), None)


def _attachment_text_findings(text: str) -> list[dict]:
    """Strong requests in attachment text: callback numbers, secrets, subsidy lures."""
    findings = []
    number = _callback_request(text, _OFFICIAL_SERVICE_NUMBERS)
    if number:
        findings.append(indicator('high', 'content.callback_request', number=number))
    findings.extend(indicator('high', code) for code in _sensitive_requests(text))
    if _subsidy_lure(text):
        findings.append(indicator('high', 'content.subsidy_lure'))
    return findings


def _is_docx(attachment: dict) -> bool:
    return (attachment.get('content_type') == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            or PurePath(attachment.get('filename') or '').suffix.lower() == '.docx')


_ADVERTISING_TERMS = (
    "优惠", "促销", "折扣", "特价", "报价", "礼品", "公开课", "课程", "培训", "招商", "加盟", "推广",
    "团购", "限时", "秒杀", "免费试用", "新品", "包邮", "营销", "招聘会", "研讨会", "会议邀请",
    "% off", "discount", "promo code", "coupon", "limited-time offer", "limited time offer",
    "special offer", "shop now", "buy now", "free shipping", "new arrivals", "flash sale", "webinar",
    "early bird", "exclusive offer", "best price", "free trial",
    # Academic and publishing solicitations: predatory conferences, journals, editing.
    "征稿", "投稿", "约稿", "截稿", "润色", "期刊", "检索", "call for papers", "call for speakers",
    "submit your paper", "manuscript", "scopus", "proceedings",
)
_UNSUBSCRIBE_TERMS = ("unsubscribe", "退订", "取消订阅")


def _advertising_terms(text: str) -> list[str]:
    """Distinct sales terms in the text, plus "unsubscribe" when an opt-out is offered."""
    lowered = (text or "").lower()
    found = [term for term in _ADVERTISING_TERMS if term in lowered]
    if any(term in lowered for term in _UNSUBSCRIBE_TERMS):
        found.append("unsubscribe")
    return found


def _sensitive_requests(text: str) -> list[str]:
    """Message codes for requests to hand over codes, secrets, gift cards, crypto or remote access.

    A request counts only when the same clause does not negate it or attribute it to
    someone else ("never share this code", "if anyone asks you to send…", "请勿告知他人").
    """
    found: list[str] = []
    for patterns in (_SENSITIVE_REQUEST_EN, _SENSITIVE_REQUEST_ZH):
        for kind, pattern in patterns.items():
            code = _SENSITIVE_REQUEST_CODES[kind]
            if code in found:
                continue
            for match in pattern.finditer(text):
                clause = re.split(r"[.!?;。！？；\n]", text[max(0, match.start() - 120):match.start()])[-1]
                if not _SENSITIVE_REQUEST_NEGATION.search(clause):
                    found.append(code)
                    break
    return found


def _text_rule_findings(full_orig: str) -> dict:
    """Keyword categories and text checks for one reading of the message text."""
    analysis_text = _strip_invisible_format_controls(full_orig)
    full_lower = analysis_text.lower()
    categories, score, floor = [], 0, 'safe'
    presentation = 0  # the score's points from _PRESENTATION_CUES
    for cat_key, cat_info in CONTENT_RULES.items():
        matched = [
            kw for kw in cat_info["keywords"]
            if _keyword_matches(full_lower, kw)
        ]
        if matched:
            capped = min(len(matched), 5)
            score += capped
            categories.append({
                "key":         cat_key,
                "label":       cat_info["label"],
                "level":       cat_info["level"],
                "icon":        cat_info["icon"],
                "description": cat_info["description"],
                "matched":     matched[:6],
                "count":       len(matched),
                "score":       capped,
            })

    requests = []
    if _has_pressured_credential_request(analysis_text):
        score += 4
        floor = 'high'
        requests.append(indicator('high', 'content.pressured_credential_request'))

    # Requests to hand over one-time codes, secrets, gift cards, crypto or remote
    # access: one strong signal however many kinds appear, each kind listed.
    callback_number = _callback_request(analysis_text, _OFFICIAL_SERVICE_NUMBERS)
    if callback_number:
        score += 4
        floor = 'high'
        requests.append(indicator('high', 'content.callback_request', number=callback_number))

    if _subsidy_lure(analysis_text):
        score += 4
        floor = 'high'
        requests.append(indicator('high', 'content.subsidy_lure'))

    sensitive_requests = _sensitive_requests(analysis_text)
    if sensitive_requests:
        score += 4
        floor = 'high'
        requests.extend(indicator('high', code) for code in sensitive_requests)

    style = []
    # 4. Excessive exclamation marks
    excl = full_orig.count("!")
    if excl >= 3:
        score += 1
        presentation += 1
        style.append(indicator("medium", "content.exclamation_marks", count=excl))

    # 5. Excessive capitalization
    caps_ratio = _excessive_caps_ratio(full_orig)
    if caps_ratio > 0.40 and len(full_orig) > 60:
        score += 1
        presentation += 1
        style.append(indicator("medium", "content.capitalization",
                               percent=int(f"{caps_ratio:.0%}"[:-1])))

    wording = []
    # 8. Generic/impersonal salutation
    if _has_generic_salutation(full_orig):
        score += 2
        wording.append(indicator("medium", "content.generic_greeting"))

    # 9. Implausibly large currency amounts
    large_amounts = _large_currency_amounts(full_orig)
    if large_amounts:
        score += 2
        wording.append(indicator("high", "content.large_amounts", amounts=', '.join(large_amounts)))

    # 10. Excessive generic CTAs
    cta_count = _count_generic_cta(full_orig)
    if cta_count >= 2:
        score += 1
        presentation += 1
        wording.append(indicator("medium", "content.generic_cta", count=cta_count))

    # 11. Regional/formal English variants are context only. Language variety
    # is neither malicious nor a reliable signal against modern LLM phishing.
    non_native = _detect_non_native_phrases(full_orig)
    if non_native:
        wording.append(indicator(
            "info", "content.regional_phrasing_more" if len(non_native) > 1 else "content.regional_phrasing",
            phrase=non_native[0]))

    # 12. Character obfuscation / leetspeak
    obfuscated = _detect_obfuscation(full_orig)
    if obfuscated:
        score += 3
        wording.append(indicator("high", "content.obfuscation", brands=', '.join(set(obfuscated))))

    return {"full_orig": full_orig, "analysis_text": analysis_text, "categories": categories, "score": score,
            "presentation": presentation, "floor": floor, "requests": requests, "style": style, "wording": wording}


def _discount_claimed_brand(rules: dict, names) -> None:
    """A text names the organisation it signs as, and the sender rules judge that claim: its own
    name is no impersonation keyword there (a genuine USPS text names USPS). Other brands count."""
    names = {name.casefold() for name in names}
    for index, category in enumerate(rules['categories'] if names else ()):
        if category['key'] != 'impersonation':
            continue
        lowered = rules['analysis_text'].lower()
        matched = [keyword for keyword in CONTENT_RULES['impersonation']['keywords']
                   if keyword.casefold() not in names and _keyword_matches(lowered, keyword)]
        rules['score'] -= category['score'] - min(len(matched), 5)
        if matched:
            rules['categories'][index] = {**category, 'matched': matched[:6], 'count': len(matched),
                                          'score': min(len(matched), 5)}
        else:
            del rules['categories'][index]
        return
