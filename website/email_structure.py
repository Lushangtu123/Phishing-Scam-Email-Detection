"""Parse RFC 5322 messages and expose phishing-relevant structural signals."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage
from email.utils import parseaddr, getaddresses
import json
from pathlib import Path, PurePath
import re
import zlib
import unicodedata
import codecs
from itertools import product

from server_messages import indicator, text as message_text, warning_indicator


_AUTH_FAILURES = {"fail", "softfail", "permerror", "temperror"}
MAX_MIME_PARTS = 200


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
})
# Per-upload mailbox choice: the receiving service's authserv-id. Only the topmost
# Authentication-Results header is trusted, because the receiving service prepends it
# above anything the sender wrote.
MAILBOX_AUTHSERV_IDS = {"gmail": "mx.google.com"}


def _load_official_sender_domains(paths=_OFFICIAL_BRANDS_PATHS) -> dict[str, str]:
    """Official sending domain -> organization name, for a DMARC-verified sender."""
    domains: dict[str, str] = {}
    for path in paths:
        for brand in json.loads(path.read_text(encoding="utf-8"))["brands"]:
            for domain in (*brand["official_domains"], *brand.get("brand_tlds", ())):
                domains.setdefault(normalize_domain(domain), brand["name"])
    return domains


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
            channels.append({
                "organization": brand["name"],
                "names": tuple(sorted(brand["display_names"] or (brand["name"],), key=len, reverse=True)),
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


def _dmarc_header_from(value: str) -> str:
    match = re.search(r"\bdmarc\s*=\s*pass\b[^;]*?\bheader\.from\s*=\s*\"?([^\s;\"()]+)", value, re.IGNORECASE)
    return normalize_domain(match.group(1)) if match else ""


def _display_name_claims(display_name: str, name: str) -> bool:
    folded = unicodedata.normalize("NFKC", display_name).casefold()
    if name.isascii():
        # Word boundaries keep ICBCX or 123067 from claiming ICBC or 12306.
        pattern = r"(?<![a-z0-9])" + r"\s*".join(map(re.escape, name.casefold().split())) + r"(?![a-z0-9])"
        return re.search(pattern, folded) is not None
    compact = "".join(ch for ch in folded if not ch.isspace() and unicodedata.category(ch) != "Cf")
    return name.casefold() in compact


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
    # Greek characters with a close Latin appearance.
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "y", "χ": "x",
})


def normalize_domain(domain: str) -> str:
    try:
        return domain.encode('idna').decode('ascii').lower().rstrip('.')
    except UnicodeError:
        return ''


_OFFICIAL_BRANDS = _load_official_brands()
_OFFICIAL_SENDER_DOMAINS = _load_official_sender_domains()
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
    normalized = unicodedata.normalize("NFKD", value.casefold())
    without_marks = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return without_marks.translate(_CONFUSABLE_TRANSLATION)


def _canonical_brand_domain(domain: str, canonical_domains: set[str]) -> bool:
    return any(_domains_align(domain, canonical) for canonical in canonical_domains)


def _brand_identity_signals(display_name: str, from_domain: str) -> tuple[int, list[dict]]:
    # Mailing lists append the reserved .invalid TLD to DMARC-protected senders.
    # From is unauthenticated here, so this gives nothing over writing the domain.
    if from_domain.endswith(_LIST_REWRITE_SUFFIX):
        from_domain = from_domain[:-len(_LIST_REWRITE_SUFFIX)]
    decoded_domain = _decode_idna_domain(from_domain)
    # Preserve word boundaries so Appleton/Pineapple are not brand identities.
    # Ignore format controls and allow separators inside an obfuscated brand.
    display_skeleton = "".join(
        ch for ch in _confusable_skeleton(display_name)
        if unicodedata.category(ch) != "Cf"
    )
    domain_skeleton = _confusable_skeleton(decoded_domain)
    domain_label_skeleton = domain_skeleton.split(".", 1)[0]
    indicators: list[dict] = []
    score = 0

    for brand, canonical_domains in _PROTECTED_BRAND_DOMAINS.items():
        canonical = _canonical_brand_domain(from_domain, canonical_domains)
        brand_pattern = r"(?<!\w)" + r"[\W_]*".join(brand) + r"(?!\w)"
        if re.search(brand_pattern, display_skeleton) and not canonical:
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
                links = pdf_link_targets(payload) if payload.startswith(b"%PDF") else []
                # Only links are read; the PDF text stays uninspected (metadata_only).
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
                              mailbox_provider=mailbox_provider)
    if limited:
        item = indicator('info', 'warning.mime_resource_limit')
        result['parse_warnings'].append(item['msg'])
        result['indicators'].append(item)
    return result


def _authentication_results(value: str) -> tuple[str, dict[str, str], bool]:
    """Read result clauses, never method-like text inside comments or strings."""
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
    complete = not (comment_depth or quoted or escaped)
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


def _analyze_message(message, *, unicode_source, trusted_authserv_ids, depth, budget, mailbox_provider=None):
    # Attached (nested) messages are analyzed without a mailbox: their headers were
    # never stamped by the user's receiving service.
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
                         and not any(_domains_align(other, sender) for sender in from_domains)), None)
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
        elif claimed_results:
            untrusted_authentication_claims.append({
                "authserv_id": authserv_id,
                "results": claimed_results,
            })
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
        if from_domain == dmarc_header_from:
            organization = _official_sender(from_domain)
            if organization:
                verified_official_sender = {"organization": organization, "domain": from_domain}
                indicators.append(indicator('info', 'structure.verified_official_sender',
                                            organization=organization, domain=from_domain))

    for attachment in attachments:
        suffix = PurePath(attachment["filename"]).suffix.lower()
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
        "authentication_results_trusted": bool(auth_results),
        "untrusted_authentication_claims": untrusted_authentication_claims,
        "attachments": attachments,
        "parse_warnings": parse_warnings,
        "structure_score": score,
        "risk_floor": risk_floor,
        "indicators": indicators,
    }
