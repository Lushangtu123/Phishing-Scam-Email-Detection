"""Parse RFC 5322 messages and expose phishing-relevant structural signals."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage
from email.utils import parseaddr, getaddresses
from email.errors import HeaderParseError
from email.header import decode_header, make_header
import fnmatch
import html
import io
import ipaddress
import json
import math
from pathlib import Path, PurePath
import re
import time
import zipfile
import zlib
import unicodedata
import codecs
from itertools import product

import tldextract

from ip_reputation import load_ip_reputation
from server_messages import indicator, text as message_text, warning_indicator


_AUTH_FAILURES = {"fail", "softfail", "permerror", "temperror"}
MAX_MIME_PARTS = 200
# Larger messages are not ARC-verified (hashing and canonicalizing them is not worth it).
MAX_ARC_MESSAGE_BYTES = 10 * 1024 * 1024


class _MimeResourceLimit(Exception):
    """Abort tree construction before excessive parts or nesting consume resources."""


_DANGEROUS_EXTENSIONS = {
    ".bat", ".chm", ".cmd", ".com", ".dll", ".docm", ".exe", ".hta",
    ".html", ".htm", ".img", ".iso", ".jar", ".js", ".lnk", ".msi",
    ".one", ".ps1", ".scr", ".vbs", ".vhd", ".vhdx", ".wsf", ".xlam",
    ".xlsm", ".xll",
}
_ARCHIVE_EXTENSIONS = {".7z", ".gz", ".rar", ".tar", ".tgz", ".zip"}
_DANGEROUS_MIME_TYPES = {
    "application/java-archive",
    "application/javascript",
    "application/vnd.microsoft.portable-executable",
    "application/vnd.ms-excel.addin.macroenabled.12",
    "application/vnd.ms-excel.sheet.binary.macroenabled.12",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-excel.template.macroenabled.12",
    "application/vnd.ms-powerpoint.addin.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
    "application/vnd.ms-powerpoint.template.macroenabled.12",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-word.template.macroenabled.12",
    "application/x-apple-diskimage",
    "application/x-bat",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-iso9660-image",
    "application/x-java-archive",
    "application/x-msdos-program",
    "application/x-msdownload",
    "application/x-sh",
    "text/javascript",
}
_ARCHIVE_MIME_TYPES = {
    "application/gzip",
    "application/vnd.rar",
    "application/x-7z-compressed",
    "application/x-gzip",
    "application/x-rar-compressed",
    "application/x-tar",
    "application/x-zip-compressed",
    "application/zip",
}
_PROTECTED_BRAND_DOMAINS = {
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de"},
    "google": {"google.com", "google.co.uk", "googleusercontent.com"},
    "microsoft": {"microsoft.com"},
    "paypal": {"paypal.com"},
}
_OFFICIAL_BRANDS_PATHS = tuple(
    Path(__file__).resolve().parent / "data" / name
    for name in ("official_brands_cn.json", "official_brands_intl.json")
)
_LIST_REWRITE_SUFFIX = ".invalid"


def _load_official_brands(paths=_OFFICIAL_BRANDS_PATHS) -> tuple[dict, ...]:
    """Reviewed regional registries: names a sender may display, and that brand's own domains.

    Government entries also accept their country's government suffixes (gov.cn, gov,
    gov.uk, gc.ca, gov.au); brand_tlds accepts a brand top-level domain such as .dhl.
    Entries without display names are covered by the protected-brand rule instead.
    """
    return tuple(
        {
            "names": tuple(sorted(brand["display_names"], key=len, reverse=True)),
            "domains": frozenset(normalize_domain(domain) for domain in
                                 (*brand["official_domains"], *brand.get("gov_suffixes", ()),
                                  *brand.get("brand_tlds", ()))),
        }
        for path in paths
        for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]
        if brand["display_names"]
    )


# Mailbox services whose own domain anyone can send from: a DMARC pass for these
# proves only that the sender has an account, not that the brand sent the message.
_CONSUMER_MAILBOX_DOMAINS = frozenset({
    "qq.com", "foxmail.com", "163.com", "126.com", "yeah.net", "sina.com", "sohu.com",
    "icloud.com", "me.com", "mac.com", "gmail.com", "googlemail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "yahoo.com", "aol.com", "proton.me", "protonmail.com",
    "139.com", "189.cn", "aliyun.com", "sina.cn", "live.cn", "yahoo.co.jp", "yahoo.co.uk", "hotmail.co.uk",
    "hotmail.fr", "outlook.fr", "mail.ru", "inbox.ru", "list.ru", "bk.ru", "yandex.ru", "yandex.com", "ya.ru",
    "gmx.com", "gmx.de", "gmx.net", "web.de", "t-online.de", "zoho.com", "zohomail.com", "mail.com",
    "email.com", "naver.com", "daum.net", "hanmail.net", "rediffmail.com", "tutanota.com", "tuta.io",
    "laposte.net", "orange.fr", "libero.it", "seznam.cz", "wp.pl", "o2.pl", "interia.pl",
})
# Per-upload mailbox choice: the receiving service's authserv-id. Only the topmost
# Authentication-Results header is trusted, because the receiving service prepends it
# above anything the sender wrote.
# Outlook.com writes "mx.microsoft.com 1" above its ARC headers; the lower
# X-MS-Exchange-Authentication-Results header is Microsoft's outbound relay, not the check.
MAILBOX_AUTHSERV_IDS = {"gmail": "mx.google.com", "outlook": "mx.microsoft.com"}
# The bundled Public Suffix List snapshot only; never fetched at runtime.
_ORGANIZATIONAL_DOMAINS = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
# With private suffixes (github.io, netlify.app), each user's subdomain on a shared
# host is its own registrable domain, so two such users never share an organization.
_REGISTRABLE_DOMAINS = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                             include_psl_private_domains=True)
# An authenticated sender also needs a passing DKIM signature from its own organizational
# domain; an SPF-only DMARC pass can come from a shared sending service.
_AUTHENTICATED_SENDER_NEEDS_DKIM = True


def _load_official_sender_domains(paths=_OFFICIAL_BRANDS_PATHS) -> dict[str, str]:
    """Official sending domain -> organization name, for a DMARC-verified sender."""
    domains: dict[str, str] = {}
    for path in paths:
        for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]:
            for domain in (*brand["official_domains"], *brand.get("brand_tlds", ())):
                domains.setdefault(normalize_domain(domain), brand["name"])
    return domains


def _load_relay_addresses(paths=_OFFICIAL_BRANDS_PATHS) -> dict[str, tuple[str, ...]]:
    """Organization -> address patterns (fnmatch) that only carry other users' content."""
    return {brand["name"]: tuple(pattern.lower() for pattern in brand["relay_addresses"])
            for path in paths for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]
            if brand.get("relay_addresses")}


def _load_organization_names(paths=_OFFICIAL_BRANDS_PATHS) -> dict[str, tuple[str, ...]]:
    """Organization -> names its own mail may carry: display names, product names, its name."""
    return {
        brand["name"]: tuple(dict.fromkeys((*brand["display_names"], *brand.get("sender_names", ()), brand["name"])))
        for path in paths
        for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]
    }


def _load_sender_only_services(paths=_OFFICIAL_BRANDS_PATHS) -> frozenset[str]:
    """Organizations registered only to verify their own account mail (display_check: sender_only)."""
    return frozenset(brand["name"] for path in paths
                     for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]
                     if brand.get("display_check") == "sender_only")


def _official_sender(domain: str) -> str | None:
    """Organization whose official domain (or a subdomain of it) this is; never a consumer mailbox."""
    if domain in _CONSUMER_MAILBOX_DOMAINS:
        return None
    labels = domain.split(".")
    for index in range(len(labels)):
        name = _OFFICIAL_SENDER_DOMAINS.get(".".join(labels[index:]))
        if name:
            return name
    return None


_NEVER_STATEMENT = re.compile(r"\b(?:never|will not|won't|does not|do not)\b|不会|绝不|绝对不|未授权", re.IGNORECASE)


def _load_official_channels(paths=_OFFICIAL_BRANDS_PATHS) -> tuple[dict, ...]:
    """Per organization: names to recognize, website, service numbers and one verified statement."""
    channels = []
    for path in paths:
        for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]:
            statements = brand.get("verified_statements") or ()
            # Prefer a "we will never …" statement; it tells the reader what to refuse.
            statement = next((item for item in statements if _NEVER_STATEMENT.search(item["quote"])),
                             next(iter(statements), None))
            # Services registered only to verify their own senders ("sender_only") are
            # named by the verified sender, not by matching words such as "Slack" in text.
            names = (brand.get("sender_names", ()) if brand.get("display_check") == "sender_only"
                     else brand["display_names"] or (brand["name"],))
            channels.append({
                "organization": brand["name"],
                "names": tuple(sorted(names, key=len, reverse=True)),
                "website": brand["official_domains"][0],
                "service_numbers": list(brand.get("service_numbers") or ()),
                "statement": statement["quote"] if statement else None,
                "statement_source": statement["source"] if statement else None,
            })
    return tuple(channels)


def official_channels(texts, *, first: str | None = None, limit: int = 2) -> list[dict]:
    """Official channels for organizations named in short texts (display name, subject).

    Guidance only, never scored: the reader is told to verify through the
    organization's own app, website and numbers instead of the message.
    """
    found: list[dict] = []
    for channel in _OFFICIAL_CHANNELS:
        if channel["organization"] == first:
            found.append(channel)
    for channel in _OFFICIAL_CHANNELS:
        if len(found) >= limit:
            break
        if channel in found:
            continue
        if any(_display_name_claims(text, name) for text in texts if text for name in channel["names"]):
            found.append(channel)
    return [{key: value for key, value in channel.items() if key != "names"} for channel in found[:limit]]


def _dkim_pass_domains(value: str) -> set[str]:
    """Signing domains (header.d, or the domain of header.i) of every passing DKIM clause.
    A clause naming two different domains for the same property names none."""
    domains = set()
    for segment in _authentication_segments(value)[0][1:]:
        properties = _clause_properties(segment)
        if not properties or properties[0][0] != "dkim" or properties[0][1].lower() != "pass":
            continue
        domain = _single_property(properties[1:], "header.d")
        if domain is None and not any(name == "header.d" for name, _value in properties[1:]):
            domain = _single_property(properties[1:], "header.i")
        if domain:
            domains.add(domain)
    return domains - {''}


def _same_registrable_domain(left: str, right: str) -> bool:
    """Sibling hosts of one registrable domain (gaia.bounces.google.com, accounts.google.com)."""
    registrable = _REGISTRABLE_DOMAINS(left).top_domain_under_public_suffix
    return bool(registrable) and registrable == _REGISTRABLE_DOMAINS(right).top_domain_under_public_suffix


def organizational_domain(domain: str) -> str:
    """Registrable domain under the bundled Public Suffix List (mail.example.co.uk -> example.co.uk)."""
    return _ORGANIZATIONAL_DOMAINS(domain).top_domain_under_public_suffix or domain


def registrable_domain(domain: str) -> str:
    """organizational_domain with private suffixes too: a user's site on a shared host
    (alice.github.io) is its own registrable domain."""
    return _REGISTRABLE_DOMAINS(domain).top_domain_under_public_suffix or domain


# Words any sender can put in a display name; they never tie a name to a domain.
_GENERIC_DISPLAY_WORDS = frozenset("""
    access account accounts admin administrator alert alerts and app apps auth bank billing care center centre
    cloud co com community confirm confirmation contact corp customer customers delivery department dept desk
    digital do email for from global group hello help helpdesk hi host hosting hr id inc info information it llc
    login ltd mail member members membership message messages net network news newsletter no noreply not
    notification notifications notify of office official online org payroll portal reply secure security server
    service services sign system systems team teams the trace track tracking update updates verification verify
    web webmail welcome www you your
""".split())


def _names_other_domain(text: str, organization: str) -> bool:
    """Whether text contains a domain (or address) of another organization, e.g. "monkey.org"."""
    for candidate in re.findall(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", text):
        extracted = _ORGANIZATIONAL_DOMAINS(candidate)
        if extracted.suffix and extracted.domain and extracted.top_domain_under_public_suffix != organization:
            return True
    return False


def display_name_matches_domain(display_name: str, domain: str, local_part: str = "") -> bool:
    """Whether a From display name names the organization that owns this domain.

    "Dropbox" <no-reply@txn.dropbox.com> matches; "IT Support" or "monkey.org Portal"
    <account@unrelated.example> does not, nor does any name or local part that
    carries another organization's domain. An empty name shows only the address.
    """
    name = display_name.strip().strip('"')
    if '=?' in name:
        try:
            name = str(make_header(decode_header(name)))
        except (ValueError, LookupError, HeaderParseError):
            pass
    folded = _folded_display_name(name)
    organization = organizational_domain(domain)
    if _names_other_domain(folded, organization) or _names_other_domain(local_part.casefold(), organization):
        return False
    if not folded.strip():
        return True
    label = re.sub(r"[^a-z0-9]", "", organization.split(".", 1)[0])
    tokens = [token for token in re.findall(r"[a-z0-9]+", folded) if token not in _GENERIC_DISPLAY_WORDS]
    if any(token == label or (len(token) >= 3 and token in label) for token in tokens):
        return True
    return len(label) >= 4 and label in "".join(tokens)


# Subjects of platform notifications that carry another user's content (a share, an
# invitation, a comment, a signature request). The template is the platform's; the
# document, message and links inside it are the other user's.
_RELAY_SUBJECT = re.compile(
    r"\b(?:shared|sharing|invit(?:ed|ing) you|invit(?:e|ation)s? (?:you )?to|sent you|mentioned you|commented|replied to"
    r"|assigned (?:you|to you|a task)|added you|requested (?:access|your signature)|wants to (?:share|connect)"
    r"|review and sign|please sign|signature (?:request|required)|left a comment|messaged you|new message from)\b"
    r"|分享了|邀请你|邀请您|给你发送|评论了|提到了你"
    # Invoices, money requests and seller disputes carry the requester's name, note,
    # amount and links (PayPal's own help describes invoice and money-request scams).
    r"|\binvoice\b|\bmoney request|\brequest(?:ed|s|ing)? (?:money|a payment|payment)|\bpayment request"
    r"|\bdon'?t recogni[sz]e the seller|发票|付款请求|收款请求", re.IGNORECASE)


def _claims_other_organization(display_name: str, own: str | None) -> bool:
    """Whether a display name names a registered organization other than the sender's own
    ("GitHub" from githubdocuments.com); a lookalike domain label is no evidence."""
    return any(organization != own and any(_display_name_claims(display_name, name) for name in names)
               for organization, names in _ORGANIZATION_NAMES.items())


def _platform_relay(from_mailboxes, reply_to_values, subject: str, organization: str, domain: str) -> str | None:
    """Why mail from an organization's own domain carries someone else's content, or None.

    Drive, Docusign, Canva and similar notifications are sent and signed by the
    platform, so DMARC passes, but a user wrote the document, message and links.
    """
    organization_domain = organizational_domain(domain)
    names = _ORGANIZATION_NAMES.get(organization, (organization,))
    for _name, address in from_mailboxes:
        if any(fnmatch.fnmatchcase(address.strip().lower(), pattern)
               for pattern in _RELAY_ADDRESSES.get(organization, ())):
            return "address"
    for name, address in from_mailboxes:
        if re.search(r"\bvia\b", name, re.IGNORECASE):
            return "via"
        if not (display_name_matches_domain(name, domain, address.rpartition("@")[0])
                or any(_display_name_claims(name, alias) for alias in names)):
            return "display_name"
    for _name, address in getaddresses(list(reply_to_values)):
        if "@" in address and organizational_domain(_domain(address)) != organization_domain:
            return "reply_to"
    if _RELAY_SUBJECT.search(subject):
        return "subject"
    return None


def _dmarc_aligned(from_domain: str, header_from: str) -> bool:
    """Whether a DMARC result is for this From domain. Gmail may report the
    organizational domain (header.from=spotify.com for alerts.spotify.com) when the
    policy came from it."""
    return bool(header_from) and header_from in {from_domain, organizational_domain(from_domain)}


_CLAUSE_PROPERTY = re.compile(r'([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s"]+)')


def _clause_properties(segment: str) -> list[tuple[str, str]]:
    """key=value pairs of one comment-free clause, in order. A value is consumed whole,
    so "reason=header.from=x" is a reason, never a header.from property."""
    return [(key.lower(), value[1:-1] if value.startswith('"') else value)
            for key, value in _CLAUSE_PROPERTY.findall(segment)]


def _single_property(properties: list[tuple[str, str]], key: str) -> str | None:
    """The one value of a property; None when it is absent or repeated with different values."""
    values = {normalize_domain(value.rpartition("@")[2] if key == "header.i" else value)
              for name, value in properties if name == key}
    return values.pop() if len(values) == 1 else None


def _dmarc_header_from(value: str) -> str:
    """header.from of the single passing DMARC clause. Several DMARC clauses that
    disagree, or one clause naming two identities, give no identity."""
    clauses = []
    for segment in _authentication_segments(value)[0][1:]:
        properties = _clause_properties(segment)
        if properties and properties[0][0] == "dmarc" and re.fullmatch(r"[a-z]+", properties[0][1], re.IGNORECASE):
            clauses.append((properties[0][1].lower(), _single_property(properties[1:], "header.from") or ""))
    if len(set(clauses)) != 1 or clauses[0][0] != "pass":
        return ""
    return clauses[0][1]


def _folded_display_name(display_name: str) -> str:
    """NFKC, casefolded, without invisible format characters ("Git\u200bHub" is "github"),
    with Greek and Cyrillic letters drawn like Latin ones read as those ("Βank oϝ Αmerica")."""
    folded = unicodedata.normalize("NFKC", display_name).translate(_CONFUSABLE_CAPITALS).casefold()
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf").translate(_CONFUSABLE_TRANSLATION)


def _capital_i_as_l(display_name: str) -> str:
    """A capital I after a lowercase letter read as the l it imitates ("PayPaI", "WeIIs")."""
    return re.sub(r"(?<=[a-z])I+", lambda match: "l" * len(match.group()), display_name)


def _display_name_claims(display_name: str, name: str) -> bool:
    """Whether the display name shows name, as written or with a capital I for l."""
    for spelling in dict.fromkeys((display_name, _capital_i_as_l(display_name))):
        folded = _folded_display_name(spelling)
        if name.isascii():
            # Word boundaries keep ICBCX or 123067 from claiming ICBC or 12306.
            pattern = r"(?<![a-z0-9])" + r"\s*".join(map(re.escape, name.casefold().split())) + r"(?![a-z0-9])"
            if re.search(pattern, folded):
                return True
        elif name.casefold() in "".join(ch for ch in folded if not ch.isspace()):
            return True
    return False


def _registry_brand_claim(display_name: str, from_domain: str) -> str | None:
    """Return a registered brand name displayed from a domain that is not that brand's own."""
    for brand in _OFFICIAL_BRANDS:
        # Exact domain or a subdomain of it; a parent such as com.cn never counts.
        if any(from_domain == domain or from_domain.endswith("." + domain) for domain in brand["domains"]):
            continue
        claimed = next((name for name in brand["names"] if _display_name_claims(display_name, name)), None)
        if claimed:
            return claimed
    return None


_CONFUSABLE_TRANSLATION = str.maketrans({
    # Cyrillic characters commonly used in Latin-brand lookalikes.
    "а": "a", "е": "e", "і": "i", "ј": "j", "о": "o",
    "р": "p", "с": "c", "х": "x", "у": "y", "ӏ": "l",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    # Greek characters with a close Latin appearance.
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "y", "χ": "x", "ϝ": "f",
})
# Greek and Cyrillic capitals drawn like Latin ones, read before casefolding turns them
# into lowercase letters that look different (Β becomes β, Н becomes н).
_CONFUSABLE_CAPITALS = str.maketrans({
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ϝ": "F",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J", "Ԛ": "Q", "Ԝ": "W",
})


def normalize_domain(domain: str) -> str:
    try:
        return domain.encode('idna').decode('ascii').lower().rstrip('.')
    except UnicodeError:
        return ''


_OFFICIAL_BRANDS = _load_official_brands()
# Domain labels that are ordinary words or names (delta, discover, canada, trip, meta),
# and the protected brands, whose lookalikes link.brand_lookalike already reports.
_COMMON_SITE_LABELS = frozenset({
    "apple", "amazon", "google", "microsoft", "paypal",
    "battle", "blizzard", "canada", "cash", "chase", "customs", "delta", "discover", "fidelity",
    "hilton", "meta", "passage", "square", "trip",
})


def _load_brand_site_labels(paths=_OFFICIAL_BRANDS_PATHS) -> dict[str, str]:
    """First label of a registered organization's own domain (wellsfargo, ctrip) -> its name.

    Only organizations matched by display name, whose names were checked as distinctive;
    labels of four or more letters or digits; and whole registrable domains, not subdomains
    of a shared service (metamask.discoursemail.com).
    """
    labels: dict[str, str] = {}
    for path in paths:
        for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]:
            if not brand["display_names"]:
                continue
            for domain in brand["official_domains"]:
                domain = normalize_domain(domain)
                if organizational_domain(domain) != domain:
                    continue
                label = domain.split(".", 1)[0]
                if len(label) >= 4 and label.isalnum() and label not in _COMMON_SITE_LABELS:
                    labels.setdefault(label, brand["name"])
    return labels


BRAND_SITE_LABELS = _load_brand_site_labels()
_OFFICIAL_SENDER_DOMAINS = _load_official_sender_domains()
_ORGANIZATION_NAMES = _load_organization_names()
_RELAY_ADDRESSES = _load_relay_addresses()
SENDER_ONLY_SERVICES = _load_sender_only_services()
_OFFICIAL_CHANNELS = _load_official_channels()
# Digits of every published official service number, e.g. 95588, 18005551234.
OFFICIAL_SERVICE_NUMBERS = frozenset(re.sub(r"\D", "", number) for channel in _OFFICIAL_CHANNELS
                                     for number in channel["service_numbers"] if re.sub(r"\D", "", number))


def _domain(address: str) -> str:
    parsed = parseaddr(address or "")[1].lower()
    return normalize_domain(parsed.rsplit("@", 1)[-1]) if "@" in parsed else ""


def _domains_align(left: str, right: str) -> bool:
    """Accept exact domains and ordinary parent/subdomain relationships."""
    return bool(left and right) and (
        left == right or left.endswith("." + right) or right.endswith("." + left)
    )


def _decode_idna_domain(domain: str) -> str:
    labels = []
    for label in domain.lower().strip(".").split("."):
        try:
            labels.append(label.encode("ascii").decode("idna"))
        except (UnicodeError, UnicodeEncodeError):
            labels.append(label)
    return ".".join(labels)


def _confusable_skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.translate(_CONFUSABLE_CAPITALS).casefold())
    without_marks = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return without_marks.translate(_CONFUSABLE_TRANSLATION)


def _canonical_brand_domain(domain: str, canonical_domains: set[str]) -> bool:
    return any(_domains_align(domain, canonical) for canonical in canonical_domains)


def _recipient_domain_claim(display_name: str, from_domain: str, recipients) -> str | None:
    """The recipient's own domain when the From display name shows it ("monkey.org",
    "monkey.org Delivery System") but the message comes from another domain: phishing
    poses as the recipient's mail or IT team this way. In Nazario, 485 of 3,466 messages
    do; none of 5,055 Apache list messages or DataCon's 611 does. Mail providers' domains
    (gmail.com) are no organization's, relays name the person they carry ("Jane
    <jane@company.com> via Dropbox"), and registered services' own mail is left out."""
    sender = organizational_domain(from_domain) if from_domain else ""
    if not display_name or re.search(r"\bvia\b", display_name, re.IGNORECASE) or (sender and _official_sender(sender)):
        return None
    folded = _folded_display_name(display_name)
    for recipient in recipients:
        domain = organizational_domain(recipient.rpartition("@")[2].rstrip(".")) if "@" in recipient else ""
        if (domain and "." in domain and domain != sender and domain not in _CONSUMER_MAILBOX_DOMAINS
                and re.search(r"(?<![a-z0-9.-])" + re.escape(domain) + r"(?![a-z0-9-])", folded)):
            return domain
    return None


def _brand_identity_signals(display_name: str, from_domain: str) -> tuple[int, list[dict]]:
    # Mailing lists append the reserved .invalid TLD to DMARC-protected senders.
    # From is unauthenticated here, so this gives nothing over writing the domain.
    if from_domain.endswith(_LIST_REWRITE_SUFFIX):
        from_domain = from_domain[:-len(_LIST_REWRITE_SUFFIX)]
    decoded_domain = _decode_idna_domain(from_domain)
    # Preserve word boundaries so Appleton/Pineapple are not brand identities.
    # Ignore format controls and allow separators inside an obfuscated brand.
    display_skeletons = ["".join(ch for ch in _confusable_skeleton(spelling) if unicodedata.category(ch) != "Cf")
                         for spelling in dict.fromkeys((display_name, _capital_i_as_l(display_name)))]
    domain_skeleton = _confusable_skeleton(decoded_domain)
    domain_label_skeleton = domain_skeleton.split(".", 1)[0]
    indicators: list[dict] = []
    score = 0

    for brand, canonical_domains in _PROTECTED_BRAND_DOMAINS.items():
        canonical = _canonical_brand_domain(from_domain, canonical_domains)
        brand_pattern = r"(?<!\w)" + r"[\W_]*".join(brand) + r"(?!\w)"
        if any(re.search(brand_pattern, skeleton) for skeleton in display_skeletons) and not canonical:
            score += 4
            indicators.append(indicator('high', 'structure.brand_display_name', brand=brand, domain=from_domain))
        if (
            brand in domain_label_skeleton
            and domain_skeleton != decoded_domain.casefold()
            and not canonical
        ):
            score += 4
            indicators.append(indicator('high', 'structure.idn_sender_domain', domain=from_domain, brand=brand))

    claimed = _registry_brand_claim(display_name, from_domain)
    if claimed and not indicators:  # one impersonation signal per sender, not one per rule
        score += 4
        indicators.append(indicator('high', 'structure.brand_display_name', brand=claimed, domain=from_domain))

    return score, indicators


# PDF attachments: only link annotations (/URI) are read, from plain objects and from
# FlateDecode streams (PDF 1.5 object streams). Nothing is rendered or executed, and
# every step is bounded so a crafted file cannot exhaust memory or time.
_MAX_PDF_BYTES = 2 * 1024 * 1024
_MAX_PDF_INFLATED_BYTES = 4 * 1024 * 1024
_MAX_PDF_STREAMS = 64
_MAX_PDF_LINKS = 50
_PDF_FLATE_STREAM = re.compile(rb"/FlateDecode(?:(?!endobj|endstream).){0,300}?stream\r?\n", re.S)
_PDF_URI = re.compile(rb"/URI\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)", re.S)
_PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}


def _pdf_string(token: bytes) -> str:
    if token.startswith(b"<"):
        digits = re.sub(rb"\s", b"", token[1:-1])
        try:
            value = bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("ascii"))
        except ValueError:
            return ""
    else:
        value = re.sub(rb"\\([0-7]{1,3}|.)",
                       lambda m: bytes([int(m.group(1), 8) & 0xFF]) if m.group(1)[:1].isdigit()
                       else _PDF_ESCAPES.get(m.group(1), m.group(1)), token[1:-1], flags=re.S)
    return value.decode("latin-1").strip()


def pdf_link_targets(data: bytes) -> list[str]:
    """http(s) targets of PDF link annotations, bounded in input, inflation and count."""
    data = data[:_MAX_PDF_BYTES]
    chunks, budget = [data], _MAX_PDF_INFLATED_BYTES
    for index, match in enumerate(_PDF_FLATE_STREAM.finditer(data)):
        if index >= _MAX_PDF_STREAMS or budget <= 0:
            break
        end = data.find(b"endstream", match.end())
        if end < 0:
            break
        try:
            inflated = zlib.decompressobj().decompress(data[match.end():end], budget)
        except zlib.error:
            continue
        budget -= len(inflated)
        chunks.append(inflated)
    targets: list[str] = []
    for chunk in chunks:
        for match in _PDF_URI.finditer(chunk):
            target = _pdf_string(match.group(1))
            if re.match(r"(?:https?|hxxps?)://", target, re.IGNORECASE) and target not in targets:
                targets.append(target)
                if len(targets) >= _MAX_PDF_LINKS:
                    return targets
    return targets


# PDF text: the text operators of content streams, decoded through each font's ToUnicode
# map, with compressed object streams expanded. Bounded in objects, tokens and output.
_MAX_PDF_OBJECTS = 5000
_MAX_PDF_TOKENS = 300_000
_MAX_PDF_CMAP_ENTRIES = 100_000
_MAX_PDF_TEXT_CHARS = 20_000
_PDF_OBJECT = re.compile(rb"(\d+)\s+\d+\s+obj\b")
_PDF_WHITESPACE = frozenset(b" \t\r\n\x0c\x00")
_PDF_DELIMITERS = frozenset(b"()<>[]{}/%")
_PDF_NUMBER = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)")


def _pdf_tokens(data: bytes, budget: list):
    """Content-stream tokens: ('string', bytes), ('name', bytes), ('number', float),
    ('op', bytes), ('[',) and (']',). budget[0] is what the document may still read."""
    index, size = 0, len(data)
    while index < size and budget[0] > 0:
        budget[0] -= 1
        byte = data[index]
        if byte in _PDF_WHITESPACE:
            index += 1
        elif byte == 0x25:  # % comment
            end = data.find(b"\n", index)
            index = size if end < 0 else end + 1
        elif byte == 0x28:  # (literal string), nested parentheses and escapes
            depth, cursor, value = 1, index + 1, bytearray()
            while cursor < size:
                byte = data[cursor]
                if byte == 0x5C:
                    stop = cursor + 1
                    while stop < min(cursor + 4, size) and 0x30 <= data[stop] <= 0x37:
                        stop += 1
                    if stop > cursor + 1:
                        value.append(int(data[cursor + 1:stop], 8) & 0xFF)
                        cursor = stop
                    else:
                        escaped = data[cursor + 1:cursor + 2]
                        if escaped not in (b"\r", b"\n"):
                            value += _PDF_ESCAPES.get(escaped, escaped)
                        cursor += 2
                    continue
                if byte == 0x28:
                    depth += 1
                elif byte == 0x29:
                    depth -= 1
                    if not depth:
                        break
                value.append(byte)
                cursor += 1
            yield ("string", bytes(value))
            index = cursor + 1
        elif byte == 0x3C:  # <hex string> or <<
            if data[index + 1:index + 2] == b"<":
                yield ("op", b"<<")
                index += 2
                continue
            end = data.find(b">", index)
            end = size if end < 0 else end
            digits = re.sub(rb"[^0-9A-Fa-f]", b"", data[index + 1:end])
            yield ("string", bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("ascii")))
            index = end + 1
        elif byte == 0x3E:
            double = data[index + 1:index + 2] == b">"
            yield ("op", b">>" if double else b">")
            index += 2 if double else 1
        elif byte in (0x5B, 0x5D):
            yield ("[",) if byte == 0x5B else ("]",)
            index += 1
        elif byte in (0x7B, 0x7D):
            index += 1
        elif byte == 0x2F:  # /Name
            end = index + 1
            while end < size and data[end] not in _PDF_WHITESPACE and data[end] not in _PDF_DELIMITERS:
                end += 1
            yield ("name", data[index + 1:end])
            index = end
        else:
            end = index
            while end < size and data[end] not in _PDF_WHITESPACE and data[end] not in _PDF_DELIMITERS:
                end += 1
            end = max(end, index + 1)
            word = data[index:end]
            if _PDF_NUMBER.fullmatch(word):
                yield ("number", float(word))
            else:
                yield ("op", word)
            index = end


def _pdf_objects(data: bytes) -> dict[int, tuple[bytes, bytes | None]]:
    """Indirect objects, number -> (dictionary, inflated stream or None), with compressed
    object streams expanded."""
    objects, budget = {}, _MAX_PDF_INFLATED_BYTES
    for match in _PDF_OBJECT.finditer(data):
        if len(objects) >= _MAX_PDF_OBJECTS:
            break
        end = data.find(b"endobj", match.end())
        if end < 0:
            continue
        body, stream = data[match.end():end], None
        at = body.find(b"stream")
        if at >= 0:
            head, raw = body[:at], body[at + 6:]
            raw = raw[2:] if raw.startswith(b"\r\n") else raw[1:] if raw[:1] in (b"\r", b"\n") else raw
            stop = raw.rfind(b"endstream")
            raw = raw[:stop] if stop >= 0 else raw
            if b"/FlateDecode" in head and budget > 0:
                try:
                    stream = zlib.decompressobj().decompress(raw, budget)
                except zlib.error:
                    stream = None
                budget -= len(stream or b"")
            elif b"/Filter" not in head:
                stream = raw
            body = head
        objects[int(match.group(1))] = (body, stream)
    for body, stream in list(objects.values()):
        first, count = re.search(rb"/First\s+(\d+)", body), re.search(rb"/N\s+(\d+)", body)
        if b"/ObjStm" not in body or not stream or not first or not count:
            continue
        first = int(first.group(1))
        pairs = re.findall(rb"(\d+)\s+(\d+)", stream[:first])[:int(count.group(1))]
        offsets = [(int(number), first + int(offset)) for number, offset in pairs]
        for (number, offset), following in zip(offsets, [*offsets[1:], (None, len(stream))]):
            if len(objects) >= _MAX_PDF_OBJECTS:
                break
            objects.setdefault(number, (stream[offset:following[1]], None))
    return objects


def _pdf_cmap(stream: bytes) -> tuple[dict[bytes, str], int]:
    """A ToUnicode CMap: character code -> text, and the code length in bytes."""
    mapping, lengths = {}, set()
    text = stream.decode("latin-1")

    def target(hexadecimal: str) -> str:
        return bytes.fromhex(hexadecimal + "0" * (len(hexadecimal) % 2)).decode("utf-16-be", "replace")
    for block in re.findall(r"beginbfchar(.*?)endbfchar", text, re.S):
        for source, value in re.findall(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>", block):
            if len(mapping) < _MAX_PDF_CMAP_ENTRIES:
                mapping[bytes.fromhex(source + "0" * (len(source) % 2))] = target(value)
                lengths.add((len(source) + 1) // 2)
    for block in re.findall(r"beginbfrange(.*?)endbfrange", text, re.S):
        for low, high, value in re.findall(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[[^\]]*\])", block):
            start, stop, width = int(low, 16), int(high, 16), (len(low) + 1) // 2
            lengths.add(width)
            if (stop < start or stop - start > 0xFFFF or len(mapping) + stop - start > _MAX_PDF_CMAP_ENTRIES
                    or stop >= 1 << 8 * width):
                continue
            if value.startswith("["):
                for offset, item in enumerate(re.findall(r"<([0-9A-Fa-f]*)>", value)):
                    mapping[(start + offset).to_bytes(width, "big")] = target(item)
                continue
            base = bytes.fromhex(value[1:-1] + "0" * (len(value[1:-1]) % 2))
            first, capacity = int.from_bytes(base, "big") if base else 0, max(len(base), 2)
            for offset in range(min(stop - start + 1, (1 << 8 * capacity) - first)):
                code = (first + offset).to_bytes(capacity, "big")
                mapping[(start + offset).to_bytes(width, "big")] = code.decode("utf-16-be", "replace")
    return mapping, max(lengths) if lengths else 1


def _pdf_array(objects, body: bytes, key: bytes) -> bytes:
    """The text of an array entry of a dictionary, following an indirect reference."""
    match = re.search(rb"/" + key + rb"\s*(\[|(\d+)\s+\d+\s+R)", body)
    if not match:
        return b""
    if match.group(2):
        source = objects.get(int(match.group(2)), (b"", None))[0]
        start = source.find(b"[")
    else:
        source, start = body, match.start(1)
    depth = 0
    for index in range(max(start, 0), len(source)):
        depth += (source[index:index + 1] == b"[") - (source[index:index + 1] == b"]")
        if depth == 0:
            return source[start + 1:index]
    return b""


_PDF_UNSIGNED = rb"(?:\d+\.?\d*|\.\d+)"
# Character codes are at most four bytes; widths beyond this are not glyph widths.
_MAX_PDF_CODE = 0xFFFFFFFF
_MAX_PDF_WIDTH = 100_000.0


def _pdf_width(value: bytes) -> float | None:
    """A glyph width, or None for one no font could hold."""
    width = float(value)
    return width if math.isfinite(width) and width <= _MAX_PDF_WIDTH else None


def _pdf_code(value: bytes) -> int | None:
    """A character code, or None outside the four bytes a code may take."""
    code = float(value)
    return int(code) if math.isfinite(code) and code <= _MAX_PDF_CODE else None


def _pdf_widths(objects, body: bytes) -> tuple[dict[int, float], float]:
    """Glyph widths in thousandths of the font size: /FirstChar and /Widths of a simple
    font, or /W and /DW of a composite font's descendant. Values that are no number, or
    out of range, are skipped."""
    descendant = re.search(rb"/DescendantFonts\s*(?:\[\s*)?(\d+)\s+\d+\s+R", body)
    if descendant:
        cid_font = objects.get(int(descendant.group(1)), (b"", None))[0]
        default = re.search(rb"/DW\s+(" + _PDF_UNSIGNED + rb")", cid_font)
        default = _pdf_width(default.group(1)) if default else None
        widths = {}
        numbers = re.findall(rb"\[[^\]]*\]|" + _PDF_UNSIGNED, _pdf_array(objects, cid_font, b"W"))
        index = 0
        while index + 1 < len(numbers) and len(widths) < _MAX_PDF_CMAP_ENTRIES:
            first, following = numbers[index], numbers[index + 1]
            if following.startswith(b"["):
                start = _pdf_code(first)
                for offset, width in enumerate(re.findall(_PDF_UNSIGNED, following)):
                    if start is not None and _pdf_width(width) is not None:
                        widths[start + offset] = _pdf_width(width)
                index += 2
            elif index + 2 < len(numbers) and not numbers[index + 2].startswith(b"["):
                low, high, width = _pdf_code(first), _pdf_code(following), _pdf_width(numbers[index + 2])
                if low is not None and high is not None and width is not None:
                    for code in range(low, min(high, low + 0xFFFF) + 1):
                        widths[code] = width
                index += 3
            else:
                break
        return widths, 1000.0 if default is None else default
    first = re.search(rb"/FirstChar\s+(\d+)", body)
    first = _pdf_code(first.group(1)) if first else None
    values = [_pdf_width(value) for value in re.findall(_PDF_UNSIGNED, _pdf_array(objects, body, b"Widths"))]
    if first is None or not values:
        return {}, 500.0
    return {first + offset: width for offset, width in enumerate(values) if width is not None}, 500.0


def _pdf_dictionary(objects, body: bytes, key: bytes) -> bytes | None:
    """The dictionary a /Key of body holds, written in place or as a reference, or None."""
    match = re.search(rb"/" + key + rb"\s*(<<|(\d+)\s+\d+\s+R)", body)
    if not match:
        return None
    if match.group(2):
        return objects.get(int(match.group(2)), (None, None))[0]
    depth = 0
    for bracket in re.finditer(rb"<<|>>", body[match.start(1):]):
        depth += 1 if bracket.group() == b"<<" else -1
        if depth == 0:
            return body[match.start(1) + 2:match.start(1) + bracket.start()]
    return body[match.start(1) + 2:]


def _pdf_font_map(objects, resources: bytes | None, described: dict) -> dict[bytes, tuple]:
    """Font resource names (/F1) of one Resources dictionary -> their descriptions."""
    fonts = _pdf_dictionary(objects, resources, b"Font") if resources else None
    return {name: described[int(number)]
            for name, number in re.findall(rb"/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R", fonts or b"")
            if int(number) in described}


def _pdf_fonts(objects) -> tuple[dict[bytes, tuple], dict[int, dict[bytes, tuple]]]:
    """Font descriptions (ToUnicode CMap or None, code length, glyph widths, default
    width) by resource name: for every document, and for each content stream by the
    Resources of its page (inherited from parent page nodes) or form. Two pages may give
    one name (/F1) to different fonts."""
    described = {}
    for number, (body, _stream) in objects.items():
        if b"/Font" not in body and b"/ToUnicode" not in body:
            continue
        reference = re.search(rb"/ToUnicode\s+(\d+)\s+\d+\s+R", body)
        target = objects.get(int(reference.group(1))) if reference else None
        mapping, length = _pdf_cmap(target[1]) if target and target[1] else (None, 2 if b"/Type0" in body else 1)
        widths, default = _pdf_widths(objects, body)
        described[number] = (mapping, length, widths, default)
    fonts = {}
    for body, _stream in objects.values():
        blocks = re.findall(rb"/Font\s*<<(.*?)>>", body, re.S)
        indirect = re.search(rb"/Font\s+(\d+)\s+\d+\s+R", body)
        if indirect and int(indirect.group(1)) in objects:
            blocks.append(objects[int(indirect.group(1))][0])
        for block in blocks:
            for name, number in re.findall(rb"/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R", block):
                if int(number) in described:
                    fonts.setdefault(name, described[int(number)])
    scoped = {}
    for number, (body, stream) in objects.items():
        if stream is not None and re.search(rb"/Subtype\s*/Form\b", body):
            resources = _pdf_dictionary(objects, body, b"Resources")
            if resources is not None:
                scoped[number] = _pdf_font_map(objects, resources, described)
            continue
        contents = re.search(rb"/Contents\s*(\[[^\]]*\]|\d+\s+\d+\s+R)", body)
        if not contents or not re.search(rb"/Type\s*/Page\b", body):
            continue
        node, resources, seen = body, None, set()
        while node is not None and resources is None and len(seen) < 32:
            resources = _pdf_dictionary(objects, node, b"Resources")
            parent = re.search(rb"/Parent\s+(\d+)\s+\d+\s+R", node)
            if not parent or int(parent.group(1)) in seen:
                break
            seen.add(int(parent.group(1)))
            node = objects.get(int(parent.group(1)), (None, None))[0]
        page_fonts = _pdf_font_map(objects, resources, described)
        for content in re.findall(rb"(\d+)\s+\d+\s+R", contents.group(1)):
            scoped.setdefault(int(content), page_fonts)
    return fonts, scoped


def pdf_text(data: bytes) -> str:
    """The text of a PDF's content streams, bounded. Glyphs are joined by where the page
    puts them: a gap wider than a third of the font size is a space, a new line a line
    break. Images, scripts and embedded files are never read."""
    data = data[:_MAX_PDF_BYTES]
    if not data.startswith(b"%PDF"):
        return ""
    objects = _pdf_objects(data)
    document_fonts, page_fonts = _pdf_fonts(objects)
    pieces, budget, written = [], [_MAX_PDF_TOKENS], [0]
    for number, (body, stream) in sorted(objects.items()):
        if not stream or b"BT" not in stream or re.search(rb"/(?:Subtype\s*/Image|FontFile|Length1|ObjStm)\b", body):
            continue
        # A stream no page or form claims keeps the document's names.
        fonts = page_fonts.get(number, document_fonts)
        font, size, scale = None, 12.0, 1.0
        x = y = line_x = line_y = 0.0
        end_x, last_y, leading = None, None, 0.0
        operands, array = [], None

        def show(string):
            nonlocal x, end_x, last_y
            unit = max(size * scale, 1.0)
            mapping, length, widths, default = font or (None, 1, {}, 500.0)
            codes = [string[index:index + length] for index in range(0, len(string) - length + 1, length)]
            # A simple font's codes missing from its ToUnicode map still draw their glyphs:
            # read them in the standard encoding, as a map of a few codes would hide the rest.
            text = ("".join(mapping.get(code, code.decode("cp1252", "replace") if length == 1 else "")
                            for code in codes) if mapping
                    else string.decode("cp1252", "replace"))
            if end_x is not None:
                if last_y is not None and abs(y - last_y) > unit * 0.5:
                    pieces.append("\n")
                elif x - end_x > unit * 0.15 or x < end_x - unit * 4:
                    pieces.append(" ")
            pieces.append(text)
            written[0] += len(text)
            x += unit * sum(widths.get(int.from_bytes(code, "big"), default) for code in codes) / 1000
            end_x, last_y = x, y
        for token in _pdf_tokens(stream, budget):
            kind = token[0]
            if kind == "[":
                array = []
            elif kind == "]":
                operands.append(("array", array or []))
                array = None
            elif array is not None:
                array.append(token)
            elif kind != "op":
                operands.append(token)
            else:
                op = token[1]
                numbers = [value for kind_, value in operands if kind_ == "number"]
                if op == b"BT":
                    x = y = line_x = line_y = 0.0
                    scale = 1.0
                elif op == b"Tf":
                    names = [value for kind_, value in operands if kind_ == "name"]
                    font = fonts.get(names[-1]) if names else None
                    size = abs(numbers[-1]) if numbers and numbers[-1] else size
                elif op in (b"Td", b"TD") and len(numbers) >= 2:
                    line_x += numbers[-2] * scale
                    line_y += numbers[-1] * scale
                    x, y = line_x, line_y
                    if op == b"TD":
                        leading = -numbers[-1]
                elif op == b"Tm" and len(numbers) >= 6:
                    scale = (numbers[-6] ** 2 + numbers[-5] ** 2) ** 0.5 or 1.0
                    x = line_x = numbers[-2]
                    y = line_y = numbers[-1]
                elif op == b"TL" and numbers:
                    leading = numbers[-1]
                elif op in (b"T*", b"'", b'"'):
                    line_y -= leading * scale
                    x, y = line_x, line_y
                if op in (b"Tj", b"'", b'"'):
                    strings = [value for kind_, value in operands if kind_ == "string"]
                    if strings:
                        show(strings[-1])
                elif op == b"TJ":
                    items = next((value for kind_, value in reversed(operands) if kind_ == "array"), [])
                    for item in items:
                        if item[0] == "string":
                            show(item[1])
                        elif item[0] == "number":
                            x -= item[1] / 1000 * size * scale
                            if item[1] <= -250 and end_x is not None:
                                # A shift of a quarter em or more is a word space.
                                pieces.append(" ")
                                end_x = x
                operands = []
                if written[0] > _MAX_PDF_TEXT_CHARS:
                    break
        pieces.append("\n")
        if budget[0] <= 0 or written[0] > _MAX_PDF_TEXT_CHARS:
            break
    text = re.sub(r"[ \t]+", " ", "".join(pieces))
    return re.sub(r" ?\n[\n ]*", "\n", text).strip()[:_MAX_PDF_TEXT_CHARS]


_MAX_DOCX_BYTES = 10 * 1024 * 1024
_MAX_DOCX_ENTRIES = 2000
_MAX_DOCX_PART_BYTES = 2 * 1024 * 1024
_MAX_DOCX_TEXT_CHARS = 20_000
_DOCX_TEXT_RUN = re.compile(r"<w:t(?:\s[^>]*)?>([^<]*)</w:t>")
_DOCX_RELATIONSHIP = re.compile(r"<Relationship\b[^>]*>")


def _bulk_mail(message) -> bool:
    """List-Unsubscribe or a bulk/list Precedence header: mailing-list or marketing mail.

    Senders write these headers themselves, so they only describe the kind of mail
    (a hint for the mail-type note); they are never evidence of safety.
    """
    try:
        precedence = str(message.get("Precedence") or "").strip().lower()
        return bool(message.get("List-Unsubscribe")) or precedence in {"bulk", "list", "junk"}
    except Exception:  # malformed header values: no hint
        return False


def docx_text_and_links(data: bytes) -> tuple[str, list[str]]:
    """Paragraph text and external http(s) hyperlinks of a .docx, bounded.

    Only word/document.xml and its relationship list are read, each capped before and
    while decompressing. Macros, embedded objects and images are never opened.
    """
    if len(data) > _MAX_DOCX_BYTES or not data.startswith(b"PK"):
        return "", []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        if len(archive.infolist()) > _MAX_DOCX_ENTRIES:
            return "", []
    except (zipfile.BadZipFile, ValueError, OSError):
        return "", []

    def read(name: str) -> str:
        try:
            info = archive.getinfo(name)
            if info.flag_bits & 0x1 or info.file_size > _MAX_DOCX_PART_BYTES:
                return ""
            with archive.open(info) as handle:
                raw = handle.read(_MAX_DOCX_PART_BYTES + 1)
        except (KeyError, zipfile.BadZipFile, ValueError, OSError, RuntimeError, EOFError, zlib.error):
            return ""
        return "" if len(raw) > _MAX_DOCX_PART_BYTES else raw.decode("utf-8", "replace")

    paragraphs = (html.unescape("".join(_DOCX_TEXT_RUN.findall(paragraph)))
                  for paragraph in read("word/document.xml").split("</w:p>"))
    text = "\n".join(paragraph for paragraph in paragraphs if paragraph.strip())[:_MAX_DOCX_TEXT_CHARS]
    links: list[str] = []
    for relationship in _DOCX_RELATIONSHIP.findall(read("word/_rels/document.xml.rels")):
        target = re.search(r'\bTarget="([^"]*)"', relationship)
        if (target and 'TargetMode="External"' in relationship
                and "relationships/hyperlink" in relationship):
            url = html.unescape(target.group(1)).strip()
            if re.match(r"(?:https?|hxxps?)://", url, re.IGNORECASE) and url not in links:
                links.append(url)
                if len(links) >= _MAX_PDF_LINKS:
                    break
    return text, links


def _walk_message_parts(message):
    """Walk one message, leaving encapsulated messages to bounded analysis."""
    pending = [message]
    while pending:
        part = pending.pop()
        yield part
        if part.is_multipart() and part.get_content_type() not in {'message/rfc822', 'message/global'}:
            pending.extend(reversed(part.get_payload()))


def _mime_candidates(message, warnings):
    """Recover bounded alternate leaf interpretations; never reparse MIME trees."""
    remaining = 32
    names = ('Content-Type', 'Content-Transfer-Encoding', 'Content-Disposition')
    for part in _walk_message_parts(message):
        choices = [[value for key, value in part.raw_items() if key.lower() == name.lower()]
                   for name in names]
        duplicate_names = [name for name, values in zip(names, choices) if len(values) > 1]
        if duplicate_names:
            warnings.append(message_text('warning.duplicate_mime_headers', headers=', '.join(duplicate_names)))
        yield part, part
        if not duplicate_names:
            continue
        choices = [list(dict.fromkeys(values)) or [None] for values in choices]
        for index, candidate in enumerate(product(*choices)):
            if index == 0:
                continue  # Original interpretation was already inspected.
            if index > 8 or remaining <= 0:
                warnings.append(message_text('warning.mime_candidate_limit'))
                break
            remaining -= 1
            alternate = EmailMessage(policy=part.policy)
            alternate.set_default_type(part.get_default_type())
            for key, value in part.raw_items():
                if key.lower() not in {name.lower() for name in names}:
                    alternate.set_raw(key, value)
            for name, value in zip(names, candidate):
                if value is not None:
                    alternate.set_raw(name, value)
            alternate.set_payload(part.get_payload())
            yield alternate, part


def _message_text(message, *, unicode_source: bool = False) -> tuple[str, str, list[dict], list[str], list[dict]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    parse_warnings: list[str] = []
    content_parts: list[dict] = []

    # A multipart/alternative contributes one rendered branch, not the text
    # from every branch. Keep each leaf's choices for bounded model views.
    alternative_paths = {}
    pending = [(message, ())]
    next_group = 0
    while pending:
        current, path = pending.pop()
        alternative_paths[id(current)] = path
        if not current.is_multipart() or current.get_content_type() in {'message/rfc822', 'message/global'}:
            continue
        children = current.get_payload()
        if current.get_content_type() == 'multipart/alternative':
            group = next_group
            next_group += 1
            pending.extend((child, path + ((group, index),))
                           for index, child in reversed(list(enumerate(children))))
        else:
            pending.extend((child, path) for child in reversed(children))

    for part, original in _mime_candidates(message, parse_warnings):
        content_type = part.get_content_type()
        if content_type in {'message/rfc822', 'message/global'}:
            attachments.append({'filename': part.get_filename() or 'attached.eml',
                                'content_type': content_type, 'inspection_status': 'metadata_only'})
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if (
            filename
            or disposition == "attachment"
            or content_type in _DANGEROUS_MIME_TYPES
            or content_type in _ARCHIVE_MIME_TYPES
            or (not part.is_multipart() and content_type not in {'text/plain', 'text/html'})
        ):
            attachments.append({
                "filename": filename or "unnamed",
                "content_type": content_type,
                "inspection_status": "metadata_only",
            })
            if content_type == "application/pdf" or PurePath(filename or "").suffix.lower() == ".pdf":
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:  # malformed transfer encoding: keep metadata only
                    payload = b""
                try:
                    links = pdf_link_targets(payload) if payload.startswith(b"%PDF") else []
                    pdf_body = pdf_text(payload)
                except Exception:  # a malformed document: leave its text and links unread
                    links, pdf_body = [], ''
                    warning = message_text('warning.attachment_unreadable')
                    if warning not in parse_warnings:
                        parse_warnings.append(warning)
                # Links and text are read; images (often QR codes) stay uninspected.
                if links:
                    attachments[-1]["extracted_links"] = links
                if pdf_body:
                    attachments[-1]["extracted_text"] = pdf_body
            if (content_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    or PurePath(filename or "").suffix.lower() == ".docx"):
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:  # malformed transfer encoding: keep metadata only
                    payload = b""
                # Text and hyperlinks are read; images (often QR codes) stay uninspected.
                try:
                    docx_text, links = docx_text_and_links(payload)
                except Exception:  # a malformed document: leave its text and links unread
                    docx_text, links = '', []
                    warning = message_text('warning.attachment_unreadable')
                    if warning not in parse_warnings:
                        parse_warnings.append(warning)
                if docx_text:
                    attachments[-1]["extracted_text"] = docx_text
                if links:
                    attachments[-1]["extracted_links"] = links
            if PurePath(filename or '').suffix.lower() == '.eml':
                warning = message_text('warning.opaque_eml_attachment')
                if warning not in parse_warnings:
                    parse_warnings.append(warning)
            continue
        if part.is_multipart():
            continue
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            if unicode_source and str(part.get('Content-Transfer-Encoding', '')).lower() not in {'base64', 'quoted-printable'}:
                # Legacy JSON already contains Unicode text, not original MIME
                # bytes. Do not round-trip it through raw-unicode-escape.
                codecs.lookup(part.get_content_charset() or 'utf-8')
                content = part.get_payload()
            else:
                content = part.get_content(errors='strict')
        except Exception:
            payload = part.get_payload(decode=True) or b""
            try:
                content = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
            except (LookupError, UnicodeError):
                content = payload.decode('utf-8', errors='replace')
            warning = message_text('warning.mime_decoding_fallback')
            if warning not in parse_warnings:
                parse_warnings.append(warning)
        path = alternative_paths[id(original)]
        existing = next((record for record in content_parts
                         if record['content_type'] == content_type and record['content'] == str(content)), None)
        if existing is not None:
            if path not in existing['alternative_paths']:
                existing['alternative_paths'].append(path)
            continue
        record = {'content_type': content_type, 'content': str(content), 'alternative_paths': [path]}
        content_parts.append(record)
        if content_type == "text/html":
            html_parts.append(str(content))
        else:
            plain_parts.append(str(content))

    # Preserve the prior de-duplicated response shape while retaining enough
    # internal evidence to avoid claiming one of several identical parts was
    # fully inspected when another was not.
    distinct_attachments = {}
    for attachment in attachments:
        key = (attachment['filename'], attachment['content_type'])
        if key in distinct_attachments:
            distinct_attachments[key]['_occurrences'] += 1
        else:
            attachment['_occurrences'] = 1
            distinct_attachments[key] = attachment
    attachments = list(distinct_attachments.values())
    return "\n".join(plain_parts), "\n".join(html_parts), attachments, parse_warnings, content_parts


# ARC (RFC 8617). When no mailbox is named, a valid ARC chain whose newest set a mailbox
# service sealed shows that service received this exact message and recorded its own
# checks in the sealed ARC-Authentication-Results. The seal is verified against the
# service's public key in DNS, so it cannot be forged into a forwarded attachment, and
# any change to the signed headers or body breaks it. Seal domain -> its authserv-id.
# Outlook.com's "Download as EML" rewrites the message, so its seals do not verify.
ARC_SEALERS = {"google.com": "mx.google.com"}
_ARC_DNS_TIMEOUT = 2.0
_ARC_KEY_TTL = 3600.0
_ARC_KEY_CACHE: dict[bytes, tuple[float, bytes | None]] = {}
_ARC_KEY_CACHE_LIMIT = 256


def _arc_dns_txt(name, timeout=5):
    """DNS TXT lookup for ARC keys: short timeout, cached in process."""
    now = time.monotonic()
    cached = _ARC_KEY_CACHE.get(name)
    if cached and cached[0] > now:
        return cached[1]
    try:
        import dkim.dnsplug
        value = dkim.dnsplug.get_txt(name, timeout=min(timeout, _ARC_DNS_TIMEOUT))
    except Exception:  # resolver failure: no key, so no trust; not cached
        return None
    if len(_ARC_KEY_CACHE) >= _ARC_KEY_CACHE_LIMIT:
        _ARC_KEY_CACHE.clear()
    _ARC_KEY_CACHE[name] = (now + _ARC_KEY_TTL, value)
    return value


def arc_sealed_results(raw_email: str | bytes, dnsfunc=None) -> tuple[str, str] | None:
    """(sealing domain, sealed Authentication-Results value) when the ARC chain is valid and
    its newest set was sealed by a known mailbox service; otherwise None."""
    data = raw_email if isinstance(raw_email, bytes) else raw_email.encode("utf-8", "surrogateescape")
    head = data.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    if b"arc-seal" not in head.lower() or len(data) > MAX_ARC_MESSAGE_BYTES:
        return None
    # Look up keys only for known services: verifying a seal from any other domain would
    # send a DNS query to whoever wrote the message, telling them it was analyzed.
    unfolded = re.sub(rb"\r?\n[ \t]+", b" ", head)
    sealers = {match.group(1).strip().lower().decode("ascii", "replace")
               for match in re.finditer(rb"(?im)^arc-(?:seal|message-signature)\s*:[^\n]*?\bd\s*=\s*([^;\s]+)", unfolded)}
    if not sealers or not sealers <= set(ARC_SEALERS):
        return None
    try:
        import dkim
        cv, results, _reason = dkim.arc_verify(data, dnsfunc=dnsfunc or _arc_dns_txt, timeout=_ARC_DNS_TIMEOUT)
    except Exception:  # missing library, malformed headers or keys: no trust
        return None
    if cv != dkim.CV_Pass or not results:
        return None
    newest = results[0]
    domain = (newest.get("as-domain") or b"").decode("ascii", "replace").lower()
    if newest.get("ams-domain", b"").decode("ascii", "replace").lower() != domain:
        return None
    sealed = (newest.get("aar-value") or b"").decode("utf-8", "replace")
    # Drop the instance tag ("i=1;") so the value reads like an Authentication-Results header.
    value = re.sub(r"^\s*i\s*=\s*\d+\s*;\s*", "", sealed).strip()
    authserv_id = _authentication_results(value)[0]
    if ARC_SEALERS.get(domain) != authserv_id:
        return None
    return domain, value


def analyze_raw_email(
    raw_email: str | bytes,
    *,
    trusted_authserv_ids: set[str] | frozenset[str] | None = None,
    mailbox_provider: str | None = None,
) -> dict:
    """Return normalized content plus authentication, identity, and attachment signals.

    mailbox_provider names the service the user downloaded this message from
    (MAILBOX_AUTHSERV_IDS). Then only the topmost Authentication-Results header is
    trusted, and only when that service wrote it; server-configured IDs are ignored.
    """
    count = 0
    def bounded_factory(*, policy):
        nonlocal count
        count += 1
        if count > MAX_MIME_PARTS:
            raise _MimeResourceLimit()
        return EmailMessage(policy=policy)

    def parse(parser_policy, *, headersonly=False):
        if isinstance(raw_email, bytes):
            return BytesParser(policy=parser_policy).parsebytes(raw_email, headersonly=headersonly)
        return Parser(policy=parser_policy).parsestr(raw_email, headersonly=headersonly)

    limited = False
    try:
        message = parse(policy.default.clone(message_factory=bounded_factory))
    except (_MimeResourceLimit, RecursionError):
        # Headers-only mode never descends into the body. Do not reinterpret
        # unparsed MIME payload as ordinary text or claim it was inspected.
        message = parse(policy.default, headersonly=True)
        message.set_payload('')
        limited = True
    result = _analyze_message(message, unicode_source=isinstance(raw_email, str),
                              trusted_authserv_ids=trusted_authserv_ids, depth=0, budget=[20],
                              mailbox_provider=mailbox_provider, raw_email=raw_email)
    if limited:
        item = indicator('info', 'warning.mime_resource_limit')
        result['parse_warnings'].append(item['msg'])
        result['indicators'].append(item)
    return result


def _authentication_segments(value: str) -> tuple[list[str], bool]:
    """Split an Authentication-Results value into clauses, dropping comments."""
    segments, current = [], []
    comment_depth = 0
    quoted = escaped = False
    for char in value:
        if escaped:
            if not comment_depth:
                current.append(char)
            escaped = False
        elif char == '\\' and (comment_depth or quoted):
            escaped = True
            if quoted:
                current.append(char)
        elif comment_depth:
            if char == '(':
                comment_depth += 1
            elif char == ')':
                comment_depth -= 1
        elif char == '"':
            quoted = not quoted
            current.append(char)
        elif not quoted and char == '(':
            comment_depth = 1
            current.append(' ')
        elif not quoted and char == ';':
            segments.append(''.join(current).strip())
            current = []
        else:
            current.append(char)
    segments.append(''.join(current).strip())
    return segments, not (comment_depth or quoted or escaped)


def _authentication_results(value: str) -> tuple[str, dict[str, str], bool]:
    """Read result clauses, never method-like text inside comments or strings."""
    segments, complete = _authentication_segments(value)
    identity = re.fullmatch(r'(?:"([^"\\]+)"|([^\s";]+))(?:\s+\d+)?', segments[0])
    authserv_id = (identity.group(1) or identity.group(2)).lower() if identity else ''
    results = {}
    for segment in segments[1:]:
        match = re.match(r'^(spf|dkim|dmarc)(?:\s*/\s*\d+)?\s*=\s*([a-z]+)(?=\s|$)',
                         segment, re.IGNORECASE)
        if match:
            mechanism, result = (part.lower() for part in match.groups())
            results[mechanism] = result
    return authserv_id, results, bool(identity) and complete


# The hosts of each mailbox service's own Received lines. Gmail's internal hops are
# written "by 2002:…" (an IPv6 address); Outlook's by Exchange Online servers.
_MAILBOX_RECEIVING_HOSTS = {
    "gmail": re.compile(r"(?:^|\.)(?:google\.com|googlemail\.com|gmail\.com)$|^[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}$"),
    "outlook": re.compile(r"(?:^|\.)(?:outlook\.com|office365\.com|microsoft\.com|exchangelabs\.com|hotmail\.com"
                          r"|live\.com)$"),
}
# The networks each service's own servers send and relay from (Google's mail netblocks;
# Exchange Online's ranges), without the cloud ranges its customers rent. A peer that names
# itself after the service (its HELO, which the sender writes) is one of its servers only
# when the receiving server recorded an address in them.
_MAILBOX_NETWORKS = {
    "gmail": tuple(map(ipaddress.ip_network, """64.233.160.0/19 66.102.0.0/20 66.249.80.0/20 72.14.192.0/18
        74.125.0.0/16 108.177.0.0/17 172.217.0.0/16 172.253.0.0/16 173.194.0.0/16 209.85.128.0/17 216.58.192.0/19
        216.239.32.0/19 2001:4860::/32 2404:6800::/32 2607:f8b0::/32 2800:3f0::/32 2a00:1450::/32
        2c0f:fb50::/32""".split())),
    "outlook": tuple(map(ipaddress.ip_network, """40.92.0.0/15 40.107.0.0/16 52.96.0.0/14 52.100.0.0/14
        104.47.0.0/17 2603:1000::/24 2a01:111::/32""".split())),
}
_RECEIVED_FROM = re.compile(r"^\s*from\s+(\S+)(.*?)\sby\s+(\S+)", re.I | re.S)
_RECEIVED_ADDRESS = re.compile(r"\[(?:ipv6:)?([0-9a-f:.]+)\]|\(([0-9a-f:.]+)\)|\s([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", re.I)
_MAX_RECEIVED = 30


def _public_address(text: str) -> str | None:
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _sending_server(message, mailbox_provider: str | None) -> tuple[str, bool] | None:
    """The address of the server that handed the message to the user's mail service, and
    whether that service's own Received lines say so.

    Received lines are read from the top while they are the receiving service's (anything
    below may be written by the sender). The first hop from outside the service is the
    sending server: a peer that is not the service's by its recorded address, whatever
    name it gives; mail sent from the service itself ends at its own outbound server.
    Without a chosen mailbox the service is recognised from the topmost line, and the
    address is unverified."""
    values = [str(value) for value in message.get_all("Received", [])[:_MAX_RECEIVED]]
    by_hosts = [by.group(1).lower().rstrip(";.") if by else "" for by in
                (re.search(r"\sby\s+(\S+)", " " + value, re.I) for value in values)]
    service = mailbox_provider if mailbox_provider in _MAILBOX_RECEIVING_HOSTS else None
    verified = service is not None
    if service is None:
        top = next(filter(None, by_hosts), "")
        service = next((name for name, pattern in _MAILBOX_RECEIVING_HOSTS.items() if pattern.search(top)), None)
    receiving = _MAILBOX_RECEIVING_HOSTS.get(service or "")
    own = None
    for value, by_host in zip(values, by_hosts):
        if receiving is not None and not receiving.search(by_host):
            break
        match = _RECEIVED_FROM.match(value)
        if not match:
            continue
        from_host, details = match.group(1).lower().rstrip("."), match.group(2)
        # The address the receiving server recorded; the peer's own name only without one.
        found = _RECEIVED_ADDRESS.findall(" " + details + " ") or _RECEIVED_ADDRESS.findall(" " + from_host + " ")
        address = next(filter(None, (_public_address(next(filter(None, parts))) for parts in found)), None)
        if address is None:
            continue
        if receiving is None or not receiving.search(from_host) or not any(
                ipaddress.ip_address(address) in network for network in _MAILBOX_NETWORKS[service]):
            return address, verified
        own = address
    return (own, verified) if own else None


def _originating_address(message) -> str | None:
    """X-Originating-IP: the sending device's address as some services record it. The
    sender can write it, so it is only ever compared with the lists."""
    value = message.get("X-Originating-IP")
    return _public_address(str(value).strip().strip("[]")) if value else None


def _analyze_message(message, *, unicode_source, trusted_authserv_ids, depth, budget, mailbox_provider=None,
                     raw_email=None):
    # Attached (nested) messages are analyzed without a mailbox or their raw bytes: their
    # headers were never stamped by the user's receiving service, and an ARC seal on an
    # attached message says nothing about how the user received the outer one.
    plain, html, attachments, parse_warnings, content_parts = _message_text(message, unicode_source=unicode_source)
    header_candidates = {
        name: []
        for name in ('From', 'To', 'Cc', 'Subject', 'Reply-To', 'Return-Path')
    }
    canonical_names = {name.lower(): name for name in header_candidates}
    # headerregistry can itself raise for malformed address headers. Parse one
    # field at a time, preserving raw candidates and other evidence on failure.
    defect_names = set()
    for part in _walk_message_parts(message):
        defect_names.update(type(defect).__name__ for defect in part.defects)
        for name, raw_value in part.raw_items():
            try:
                header = part.policy.header_fetch_parse(name, raw_value)
                value = str(header)
                defect_names.update(type(defect).__name__ for defect in getattr(header, 'defects', ()))
            except Exception:
                value = raw_value
                warning = message_text('warning.header_unparsed', header=name)
                if warning not in parse_warnings:
                    parse_warnings.append(warning)
            candidate_name = canonical_names.get(name.lower())
            if part is message and candidate_name:
                header_candidates[candidate_name].append(value)
    for name, values in header_candidates.items():
        if len(values) > 1:
            parse_warnings.append(message_text('warning.duplicate_header', header=name))
    if depth and not (plain.strip() or html.strip() or attachments or any(header_candidates.values())
                      or message.get('Authentication-Results')):
        parse_warnings.append(message_text('warning.attached_message_empty'))
    if defect_names:
        parse_warnings.append(message_text('warning.mime_malformed', defects=', '.join(sorted(defect_names))))
    nested_messages = []
    attachments_by_key = {(item['filename'], item['content_type']): item for item in attachments}
    for part in _walk_message_parts(message):
        if part.get_content_type() not in {'message/rfc822', 'message/global'}:
            continue
        attachment = attachments_by_key.get((part.get_filename() or 'attached.eml', part.get_content_type()))
        encoding = str(part.get('Content-Transfer-Encoding', '')).strip().lower()
        if encoding not in {'', '7bit', '8bit', 'binary'}:
            warning = message_text('warning.attached_message_encoded')
            if warning not in parse_warnings:
                parse_warnings.append(warning)
            continue
        children = part.get_payload()
        if not isinstance(children, list) or not children:
            parse_warnings.append(message_text('warning.attached_message_unparsed'))
            continue
        fully_analyzed = True
        for child in children:
            if depth >= 3 or budget[0] <= 0:
                warning = message_text('warning.attached_message_limit')
                if warning not in parse_warnings:
                    parse_warnings.append(warning)
                fully_analyzed = False
                break
            budget[0] -= 1
            nested = _analyze_message(child, unicode_source=unicode_source,
                                      trusted_authserv_ids=set(), depth=depth + 1, budget=budget)
            nested_messages.append(nested)
            if nested['parse_warnings']:
                fully_analyzed = False
            for warning in nested['parse_warnings']:
                prefixed = message_text('prefix.attached_message', text=warning)
                if prefixed not in parse_warnings:
                    parse_warnings.append(prefixed)
        ambiguous_headers = any(
            sum(name.lower() == field for name, _ in part.raw_items()) > 1
            for field in ('content-type', 'content-transfer-encoding', 'content-disposition')
        )
        filename_is_unique = attachment and sum(
            item['filename'] == attachment['filename'] for item in attachments
        ) == 1
        if (fully_analyzed and attachment and attachment['_occurrences'] == 1
                and filename_is_unique and not ambiguous_headers):
            attachment['inspection_status'] = 'message_analyzed'
    for attachment in attachments:
        del attachment['_occurrences']
    # Analyze both alternatives. Phishers commonly put harmless text in the
    # plain part and the credential link only in the HTML part.
    body = "\n".join(part for part in (plain, html) if part)
    indicators: list[dict] = [warning_indicator(warning) for warning in parse_warnings]
    score = 0
    risk_floor = "safe"

    from_mailboxes = [mailbox for value in header_candidates['From']
                      for mailbox in getaddresses([value])]
    from_domains = {_domain(address) for _, address in from_mailboxes} - {''}
    from_addresses = {
        address.strip().lower() for _, address in from_mailboxes if address.strip()
    }
    recipient_addresses = {
        address.strip().lower()
        for name in ('To', 'Cc')
        for value in header_candidates[name]
        for _, address in getaddresses([value])
        if address.strip()
    }
    if not recipient_addresses:
        indicators.append(indicator('info', 'structure.no_visible_recipient'))
    elif from_addresses & recipient_addresses:
        score += 1
        indicators.append(indicator('low', 'structure.self_addressed'))
    brand_score, brand_indicators = max(
        (_brand_identity_signals(name, _domain(address)) for name, address in from_mailboxes),
        key=lambda pair: pair[0], default=(0, []),
    )
    score += brand_score
    indicators.extend(brand_indicators)
    if brand_score:
        risk_floor = "high"
    claimed_domain = next(filter(None, (_recipient_domain_claim(name, _domain(address), recipient_addresses)
                                        for name, address in from_mailboxes)), None)
    if claimed_domain:
        score += 3
        if risk_floor == "safe":
            risk_floor = "medium"
        indicators.append(indicator('medium', 'structure.recipient_domain_display', domain=claimed_domain))

    # Reply and bounce routing may legitimately differ from the visible author
    # (for example with discussion lists and delivery services). They are one
    # weak routing concern, not independent evidence of sender impersonation.
    # Keep every observation; never trust a List-Id or other claimed list header
    # to suppress this concern or unrelated authentication/content evidence.
    routing_mismatch = False
    for name in ('Reply-To', 'Return-Path'):
        domains = {_domain(address) for value in header_candidates[name]
                   for _, address in getaddresses([value])} - {''}
        mismatch = next((other for other in sorted(domains) if from_domains
                         and not any(_domains_align(other, sender) or _same_registrable_domain(other, sender)
                                     for sender in from_domains)), None)
        if mismatch:
            routing_mismatch = True
            indicators.append(indicator('low', 'structure.routing_mismatch', header=name, domain=mismatch,
                                        from_domains=', '.join(sorted(from_domains))))
    if routing_mismatch:
        score += 2

    trusted_ids = {
        value.strip().lower()
        for value in (trusted_authserv_ids or set())
        if value.strip()
    }
    auth_results: dict[str, str] = {}
    dmarc_header_from = ""
    dkim_pass_domains: set[str] = set()
    untrusted_authentication_claims = []
    mailbox_authserv_id = MAILBOX_AUTHSERV_IDS.get(mailbox_provider or "")
    if mailbox_authserv_id:
        trusted_ids = {mailbox_authserv_id}
    for position, auth_header in enumerate(message.get_all("Authentication-Results", [])):
        authserv_id, claimed_results, auth_complete = _authentication_results(str(auth_header))
        # With a named mailbox, a header below the topmost one was written by someone
        # else (often the sender), whatever service it claims to be.
        trusted_header = authserv_id in trusted_ids and not (mailbox_authserv_id and position)
        if not auth_complete:
            warning = message_text('warning.auth_results_incomplete')
            if warning not in parse_warnings:
                parse_warnings.append(warning)
                indicators.append(indicator('info', 'warning.auth_results_incomplete'))
            # Incomplete claims cannot confer a trusted pass.
            claimed_results = {key: value for key, value in claimed_results.items() if value != 'pass'}
        if claimed_results and trusted_header and not auth_results:
            auth_results = claimed_results
            dmarc_header_from = _dmarc_header_from(str(auth_header))
            dkim_pass_domains = _dkim_pass_domains(str(auth_header))
        elif claimed_results:
            untrusted_authentication_claims.append({
                "authserv_id": authserv_id,
                "results": claimed_results,
            })
    authentication_source = ("mailbox" if mailbox_authserv_id else "server") if auth_results else None
    if not auth_results and not mailbox_authserv_id and raw_email is not None:
        arc = arc_sealed_results(raw_email)
        if arc:
            sealed_by, sealed_value = arc
            authserv_id, claimed_results, auth_complete = _authentication_results(sealed_value)
            if claimed_results and auth_complete:
                auth_results = claimed_results
                dmarc_header_from = _dmarc_header_from(sealed_value)
                dkim_pass_domains = _dkim_pass_domains(sealed_value)
                authentication_source = "arc"
                # The service's own header now counts through its seal, not as a claim.
                untrusted_authentication_claims = [claim for claim in untrusted_authentication_claims
                                                   if claim["authserv_id"] != authserv_id]
                indicators.append(indicator('info', 'structure.arc_sealed_results', domain=sealed_by))
    failures = {
        mechanism for mechanism, result in auth_results.items()
        if result in _AUTH_FAILURES
    }
    dmarc_passes = auth_results.get("dmarc") == "pass"
    decisive_failure = (
        auth_results.get("dmarc") in _AUTH_FAILURES
        or {"spf", "dkim"}.issubset(failures)
    )
    if decisive_failure and not dmarc_passes:
        score += 6
        risk_floor = "high"
        indicators.append(indicator('high', 'structure.auth_failed',
                                    mechanisms=", ".join(sorted(failures)).upper()))
    elif failures and not dmarc_passes:
        score += 2
        indicators.append(indicator('medium', 'structure.auth_partial_failure',
                                    mechanisms=", ".join(sorted(failures)).upper()))

    # A trusted DMARC pass for the single From domain, which is an organization's own
    # sending domain, verifies the sender. It says nothing about links or requests,
    # which are still scored.
    verified_official_sender = None
    if dmarc_passes and not decisive_failure and len(from_domains) == 1:
        from_domain = next(iter(from_domains))
        if _dmarc_aligned(from_domain, dmarc_header_from):
            organization = _official_sender(from_domain)
            relay = organization and _platform_relay(
                from_mailboxes, header_candidates['Reply-To'], '\n'.join(header_candidates['Subject']),
                organization, from_domain)
            if relay:
                # Genuinely sent by the platform, but for another user: not an official message.
                indicators.append(indicator('info', 'structure.platform_relay', organization=organization,
                                            domain=from_domain))
            elif organization:
                verified_official_sender = {"organization": organization, "domain": from_domain}
                indicators.append(indicator('info', 'structure.verified_official_sender',
                                            organization=organization, domain=from_domain))

    # Any other organization's domain (not a consumer mailbox) with a trusted, aligned
    # DMARC pass is authenticated: its address naming is the owner's choice. This is
    # not official: it only says who sent the message, not that they are trustworthy.
    authenticated_sender = None
    if dmarc_passes and not decisive_failure and len(from_domains) == 1:
        from_domain = next(iter(from_domains))
        organization_domain = organizational_domain(from_domain)
        if (_dmarc_aligned(from_domain, dmarc_header_from)
                and not {from_domain, organization_domain} & _CONSUMER_MAILBOX_DOMAINS
                and (not _AUTHENTICATED_SENDER_NEEDS_DKIM
                     or any(organizational_domain(domain) == organization_domain for domain in dkim_pass_domains))):
            own = _official_sender(from_domain)
            authenticated_sender = {
                "domain": from_domain, "organizational_domain": organization_domain,
                "display_name_matches": all(
                    display_name_matches_domain(name, from_domain, address.rpartition("@")[0])
                    and not _claims_other_organization(name, own)
                    for name, address in from_mailboxes),
            }

    # Without a trusted DMARC result (no mailbox chosen, or none recorded), a From on a
    # sender-only service's own domain can be spoofed exactly as written, so its address
    # shape (alerts.spotify.com, security-noreply@) cannot tell a spoof from the real
    # message; only authentication can. Name the service so address-shape findings stop
    # scoring. Nothing is verified: links, content and requests are still scored, and
    # platform relays (other users' content) are excluded as for verified senders.
    service_domain_sender = None
    if (verified_official_sender is None and authenticated_sender is None and not decisive_failure
            and len(from_domains) == 1):
        from_domain = next(iter(from_domains))
        organization = _official_sender(from_domain)
        if (organization in SENDER_ONLY_SERVICES
                and not _platform_relay(from_mailboxes, header_candidates['Reply-To'],
                                        '\n'.join(header_candidates['Subject']), organization, from_domain)):
            service_domain_sender = {"organization": organization, "domain": from_domain,
                                     "organizational_domain": organizational_domain(from_domain)}

    for attachment in attachments:
        # Windows drops trailing dots and spaces from a file name: "vm.htm." opens as .htm.
        suffix = PurePath(attachment["filename"].rstrip(". ")).suffix.lower()
        content_type = attachment["content_type"].lower().split(";", 1)[0].strip()
        if suffix in _DANGEROUS_EXTENSIONS or content_type in _DANGEROUS_MIME_TYPES:
            score += 4
            risk_floor = "high"
            indicators.append(indicator('high', 'structure.dangerous_attachment', filename=attachment['filename']))
        elif suffix in _ARCHIVE_EXTENSIONS or content_type in _ARCHIVE_MIME_TYPES:
            score += 2
            if risk_floor == "safe":
                risk_floor = "medium"
            indicators.append(indicator('medium', 'structure.archive_attachment', filename=attachment['filename']))

    # The server that handed the message to the user's mail service, and the sending
    # device as X-Originating-IP claims it, compared with the checked-in Tor exit and
    # Spamhaus DROP lists. Context only for now: the lists are today's, not the sending
    # day's. Attached messages were never received by the user's service.
    sending_server = None
    if depth == 0:
        found = _sending_server(message, mailbox_provider)
        reputation = load_ip_reputation()
        if found:
            address, verified = found
            sending_server = {"address": address, "verified": verified}
            indicators.append(indicator('info', 'structure.sending_server' if verified
                                        else 'structure.sending_server_unverified', ip=address))
        for address, tor_code, drop_code in (
                (sending_server and sending_server["address"], 'structure.sending_server_tor',
                 'structure.sending_server_drop'),
                (_originating_address(message), 'structure.originating_ip_tor', 'structure.originating_ip_drop')):
            if not address or reputation is None:
                continue
            if reputation.tor_exit(address):
                indicators.append(indicator('info', tor_code, ip=address, date=reputation.tor_date))
            listing = reputation.drop_listing(address)
            if listing:
                indicators.append(indicator('info', drop_code, ip=address, listing=listing, date=reputation.drop_date))

    return {
        "input_mode": "raw-email",
        "subject": '\n'.join(header_candidates['Subject']),
        "header_candidates": header_candidates,
        "body": body,
        "html_body": html,
        "content_parts": content_parts,
        "nested_messages": nested_messages,
        "from": next(iter(header_candidates['From']), ''),
        "reply_to": next(iter(header_candidates['Reply-To']), ''),
        "return_path": next(iter(header_candidates['Return-Path']), ''),
        "auth_results": auth_results,
        "authentication_trusted": dmarc_passes,
        "verified_official_sender": verified_official_sender,
        "authenticated_sender": authenticated_sender,
        "service_domain_sender": service_domain_sender,
        "sending_server": sending_server,
        "bulk_mail": _bulk_mail(message),
        "authentication_results_trusted": bool(auth_results),
        "authentication_source": authentication_source,
        "untrusted_authentication_claims": untrusted_authentication_claims,
        "attachments": attachments,
        "parse_warnings": parse_warnings,
        "structure_score": score,
        "risk_floor": risk_floor,
        "indicators": indicators,
    }
