"""Links in a message: extracting them from text and HTML, and what their destinations say.

Shorteners, IP-literal and IPFS hosts, free and developer hosting, brand lookalikes, visible
text that names one host while the link goes to another, and sensitive paths. Email and text
messages (app.analyze_sms) share these checks. This module needs nothing from app.py.
"""
from __future__ import annotations

import ipaddress
import re
from html import escape as escape_html
from urllib.parse import unquote

import tldextract

from email_structure import (
    BRAND_SITE_LABELS as _BRAND_SITE_LABELS,
    _PROTECTED_BRAND_DOMAINS,
    _confusable_skeleton,
    _decode_idna_domain,
    _domains_align,
)
from html_visibility import (
    _AnalysisHTMLParser, _collect_html, _first_html_attributes, _parse_link_target, _visible_content_text,
)
from sender_features import LEGIT_PROVIDERS, _DOMAIN_EXTRACTOR
from server_messages import indicator, text as message_text


SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "short.link", "rb.gy", "cutt.ly", "is.gd", "buff.ly",
    "ift.tt", "dlvr.it", "wp.me", "tiny.cc", "clck.ru",
    "qr.ae", "su.pr", "lnkd.in", "db.tt", "qr.net",
]

_ASCII_BRAND_TRANSLATION = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
})
_BENIGN_BRAND_LABELS = {
    "apple": {"applecore", "crabapple", "dapple", "grapple", "pineapple", "snapple"},
}


def _count_urls(links: list[tuple[str, str]]) -> int:
    """Count inspected visible URLs and explicit destinations, not hidden prose."""
    return sum(bool(re.match(r'^https?://', destination, re.IGNORECASE))
               for _visible, destination in links)


def _has_ip_url(text: str, *, links=None) -> bool:
    for _visible, destination in (_extract_links(text) if links is None else links):
        try:
            parsed = _parse_link_target(destination)
            if parsed.scheme in {'http', 'https'} and _is_ip_host(_link_host(parsed)):
                return True
        except ValueError:
            continue
    return False


def _link_host(parsed) -> str:
    # Decode host escapes only after parsing authority; escaped separators must
    # not become a different userinfo/path boundary.
    return unquote(parsed.hostname or '').lower().rstrip('.')


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Also recognize legacy IPv4 URL forms: one integer, abbreviated dotted
    # components, and hex/octal numbers. Never resolve a hostname on the network.
    parts = host.split('.')
    if not 1 <= len(parts) <= 4:
        return False
    numbers = []
    for part in parts:
        if not re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)', part):
            return False
        base = 16 if part.startswith('0x') else 8 if len(part) > 1 and part.startswith('0') else 10
        try:
            numbers.append(int(part, base))
        except ValueError:
            return False
    return all(number <= 255 for number in numbers[:-1]) and numbers[-1] < 256 ** (5 - len(parts))


def _has_shortener_url(text: str, *, links=None) -> bool:
    for _visible, destination in (_extract_links(text) if links is None else links):
        try:
            parsed = _parse_link_target(destination)
            host = _link_host(parsed)
            if parsed.scheme in {'http', 'https'} and any(
                host == shortener or host.endswith('.' + shortener) for shortener in SHORTENER_DOMAINS
            ):
                return True
        except ValueError:
            continue
    return False


def _trim_bare_url(url: str) -> str:
    """Drop sentence punctuation after a bare URL, and a closing "]" from the common
    "Label [https://example.com]" plain-text form unless the URL opened one (IPv6)."""
    while True:
        trimmed = url.rstrip(".,;:)")
        if trimmed.endswith("]") and "[" not in trimmed:
            trimmed = trimmed[:-1]
        if trimmed == url:
            return url
        url = trimmed


def _extract_links(text: str, *, parse_html: bool = True, parse_warnings=None,
                   visible_text: str | None = None, hidden_labels: bool = False) -> list[tuple[str, str]]:
    """Extract visible text and destination from Markdown and HTML links. With hidden_labels,
    a label is all of its text, including what styles may hide (the hidden-text reading)."""
    # Free-text URLs and Markdown links must come from visible prose, while
    # explicit href/action destinations remain inspectable even when hidden.
    scan_text = (visible_text if visible_text is not None else _visible_content_text(text, parse_warnings)) if parse_html else text
    links = list(re.findall(r'\[([^\]]+)\]\(((?:https?|hxxps?)://[^)]+)\)', scan_text, re.IGNORECASE))

    class LinkCollector(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__()
            self.href = None
            self.label_markup = []
            self.links = []
            self.base_href = None

        def finish_anchor(self):
            if self.href is not None:
                readings = {} if hidden_labels else None
                label = _visible_content_text(''.join(self.label_markup), readings=readings)
                self.links.append((readings.get('all_text', label) if hidden_labels else label, self.href))
            self.href = None
            self.label_markup = []

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            attributes = dict(attrs)
            if tag == 'base' and self.base_href is None and 'href' in attributes:
                self.base_href = attributes['href'] or ''
            if tag == 'form' and attributes.get('action'):
                self.links.append(('', attributes['action']))
            if tag in {'input', 'button'} and attributes.get('formaction') and 'disabled' not in attributes:
                self.links.append(('', attributes['formaction']))
            if tag.lower() == "a":
                if self.href is not None:
                    self.finish_anchor()
                self.href = next((value for name, value in attrs if name == 'href'), None)
                self.label_markup = [self.get_starttag_text() or '<a>']
            elif self.href is not None:
                self.label_markup.append(self.get_starttag_text() or f'<{tag}>')

        def collect_data(self, data):
            if self.href is not None:
                self.label_markup.append(escape_html(data))

        def handle_endtag(self, tag):
            if self.href is not None:
                self.label_markup.append(f'</{tag}>')
                if tag.lower() == 'a':
                    self.finish_anchor()

    collector = _collect_html(LinkCollector, text, parse_warnings) if parse_html else LinkCollector()
    try:
        if collector.href is not None:
            collector.finish_anchor()
        base = None
        try:
            candidate = _parse_link_target(collector.base_href or '')
            if candidate.scheme in {'http', 'https'} and candidate.hostname:
                base = candidate.geturl()
        except ValueError:
            pass
        for visible, destination in collector.links:
            try:
                # Only resolve HTML targets, not unrelated plain-text URLs.
                # Keep obfuscated schemes intact for their existing indicator.
                resolved = (_parse_link_target(destination, base=base).geturl()
                            if base and not re.match(r'^hxxps?:', destination, re.IGNORECASE)
                            else destination)
            except ValueError:
                resolved = destination  # Preserve malformed-target evidence.
            links.append((visible, resolved))
    except Exception:
        pass

    links.extend(
        ("", _trim_bare_url(url))
        for url in re.findall(r"(?:https?|hxxps?)://[^\s<>\"']+", scan_text, re.IGNORECASE)
    )

    return [
        (str(visible or "").strip(), str(destination or "").strip())
        for visible, destination in links
        if destination
    ]


# The bundled Public Suffix List snapshot, including private suffixes (github.io,
# netlify.app), so a user's subdomain on a shared host is its own registrable domain.
_PRIVATE_SUFFIX_DOMAINS = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                                include_psl_private_domains=True)


def _display_host_aligns(visible: str, target: str) -> bool:
    """Whether a link's displayed host names the site it actually opens.

    "https://www.spotify.com" names spotify.com, so its own wl.spotify.com aligns.
    A displayed public suffix (co.uk, or github.io under the private suffix list)
    must match exactly: its subdomains belong to different owners.
    """
    if visible.startswith('www.'):
        visible = visible[4:]
    if not _PRIVATE_SUFFIX_DOMAINS(visible).top_domain_under_public_suffix:
        return visible == target
    return _domains_align(visible, target)


def _visible_link_host(link_text: str) -> str:
    """Extract an address presented to the reader, not a domain in article prose."""
    link_text = link_text.strip(" \t\r\n<>()[]{}'\",;.!?")
    matches = re.finditer(
        r"(?<![\w@./-])(?P<prefix>https?://|www\.)?"
        r"(?P<host>[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)"
        r"(?![\w-]|\.[a-z0-9])",
        link_text,
        re.IGNORECASE,
    )
    for match in matches:
        host = match.group('host').lower()
        suffix = host.rsplit('.', 1)[-1]
        domain = '.' in host and bool(re.fullmatch(r'[a-z]{2,63}|xn--[a-z0-9-]+', suffix))
        # Bare dotted releases are not addresses. Preserve full IPv4 labels and
        # explicitly displayed legacy IP URLs without resolving any host.
        ip = _is_ip_host(host) and (bool(match.group('prefix')) or host.count('.') == 3)
        # A bare domain must occupy the address label (optional port/path).
        # Merely mentioning a publisher in a headline does not promise that
        # the link skips a redirect. Its actual target is still analyzed below.
        address_label = match.start() == 0 and bool(re.fullmatch(
            r'(?::[0-9]{1,5})?(?:[/?#]\S*)?', link_text[match.end():],
        ))
        navigation = bool(re.search(
            r'(?<!\w)(?:visit|open|go to|log\s*in (?:to|at)|sign\s*in (?:to|at))\s*$'
            r'|(?:访问|打开|登录|登陆)\s*$', link_text[:match.start()], re.IGNORECASE,
        ))
        # A complete filename such as invoice.pdf labels a document, not its
        # hosting domain. Keep explicit addresses, paths/ports and real public
        # suffixes (including file-like .zip/.mov) eligible for mismatch checks.
        filename_label = (
            not match.group('prefix') and match.start() == 0
            and match.end() == len(link_text)
            and suffix in {
                'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                'png', 'jpg', 'jpeg', 'gif', 'webp', 'txt', 'csv',
                'json', 'xml', 'yaml', 'yml', 'zip', 'mov',
            }
            and not _DOMAIN_EXTRACTOR(host).suffix
        )
        if filename_label:
            continue
        if (domain or ip) and (match.group('prefix') or address_label or navigation):
            return host
    return ""


def _known_link_host(host: str) -> bool:
    return any(host == known or host.endswith("." + known) for known in LEGIT_PROVIDERS)


def _label_uses_brand_lookalike(label: str, brand: str) -> bool:
    """Match protected brands after separator and common digit normalization."""
    skeleton = _confusable_skeleton(label)
    translated = skeleton.translate(_ASCII_BRAND_TRANSLATION)
    tokens = [
        re.sub(r"[^a-z]", "", token)
        for token in re.findall(r"[a-z0-9]+", translated)
    ]
    if brand in tokens:
        return True
    compact = re.sub(r"[^a-z]", "", translated)
    if compact in _BENIGN_BRAND_LABELS.get(brand, set()):
        return False
    return brand in compact


# Public IPFS gateways, and the subdomain form <cid>.ipfs.<gateway>. Paths /ipfs/<cid>
# or /ipns/<name> on any host are the same content-addressed pages.
_IPFS_GATEWAY_HOSTS = frozenset({
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "gateway.pinata.cloud", "mypinata.cloud",
    "ipfs.fleek.co", "w3s.link", "nftstorage.link", "4everland.io", "ipfs.infura.io",
})
_IPFS_PATH = re.compile(r"^/ip[fn]s/[A-Za-z0-9]{20,}", re.IGNORECASE)
_IPFS_SUBDOMAIN = re.compile(r"^[a-z0-9-]{20,}\.ip[fn]s\.")


def _is_ipfs_gateway(host: str, path: str) -> bool:
    host = host.lower().rstrip(".")
    if any(host == gateway or host.endswith("." + gateway) for gateway in _IPFS_GATEWAY_HOSTS):
        return True
    # Subdomain gateways put a long content ID (or IPNS name) before ".ipfs."/".ipns.";
    # ordinary hosts such as docs.ipfs.tech do not.
    return bool(_IPFS_SUBDOMAIN.match(host) or _IPFS_PATH.match(path or ""))


# Free development, storage and tunnel addresses anyone can create in minutes (Cloudflare R2
# and Workers dev URLs, Glitch, Replit, tunnels, Azure storage web endpoints). Organizations
# send customers to their own domains, not here. In the corpora on this computer, 2023-24
# phishing linked to them and real legitimate mail did not (docs/evaluation.md).
_DEV_HOSTING_SUFFIXES = (
    "r2.dev", "workers.dev", "glitch.me", "cyclic.app", "replit.app", "replit.dev", "repl.co",
    "trycloudflare.com", "ngrok.io", "ngrok-free.app", "000webhostapp.com", "web.core.windows.net",
)
# Free hosting and site-builder services whose subdomains anyone can claim. Organizations do
# not serve their own sign-in or account pages there, so a site named after a registered
# one is a lookalike. Code and blog hosts (github.io, gitlab.io, blogspot.com) are left out:
# organizations publish official project pages and blogs there under their own names.
_FREE_HOSTING_SUFFIXES = _DEV_HOSTING_SUFFIXES + (
    "pages.dev", "vercel.app", "netlify.app", "web.app", "firebaseapp.com", "onrender.com", "up.railway.app",
    "fly.dev", "herokuapp.com", "surge.sh", "weebly.com", "weeblysite.com", "wixsite.com", "webflow.io",
    "square.site", "framer.website", "framer.app", "amplifyapp.com", "azurestaticapps.net", "canva.site",
    "godaddysites.com", "mystrikingly.com", "jimdosite.com",
)


def _free_hosting_suffix(host: str) -> str:
    """The free hosting service a host is a site on, or ''."""
    return next((suffix for suffix in _FREE_HOSTING_SUFFIXES if host.endswith("." + suffix)), "")


def _brand_in_site_name(site: str) -> str | None:
    """Registered organization a site name is built on (s-wellsfargo-online, docusign2494...)."""
    site = site.casefold()
    if "clone" in site:
        # Developers' practice copies of well-known apps (netflix-clone).
        return None
    tokens = dict.fromkeys(re.findall(r"[a-z0-9]+", site)
                           + re.findall(r"[a-z0-9]+", _confusable_skeleton(site).translate(_ASCII_BRAND_TRANSLATION)))
    for token in tokens:
        for label, organization in _BRAND_SITE_LABELS.items():
            if token == label or (len(label) >= 6 and (token.startswith(label) or token.endswith(label))):
                return organization
    return None


_SENSITIVE_HOST_TERMS = frozenset({
    "account", "credential", "login", "password", "reactivate",
    "secure", "security", "signin", "unlock", "verification", "verify",
    "wallet",
})


def _analyze_link_destinations(text: str, *, links=None, parse_warnings=None) -> tuple[int, list[dict], str]:
    """Inspect actual link targets, including links with generic button text."""
    score = 0
    findings: list[dict] = []
    risk_floor = "safe"
    finding_types: set[str] = set()
    sensitive_host_terms = _SENSITIVE_HOST_TERMS

    for link_text, url in (_extract_links(text) if links is None else links):
        lowered_url = url.lower()
        if lowered_url.startswith(("hxxp://", "hxxps://")):
            if "obfuscated-scheme" not in finding_types:
                score += 3
                risk_floor = "high"
                finding_types.add("obfuscated-scheme")
                findings.append({"rule_id": "link.obfuscated_scheme",
                                 **indicator("high", "link.obfuscated_scheme")})
            if lowered_url.startswith("hxxps://"):
                url = "https://" + url[8:]
            else:
                url = "http://" + url[7:]
        try:
            parsed = _parse_link_target(url)
        except ValueError:
            warning = message_text('warning.link_unparsed')
            if parse_warnings is not None and warning not in parse_warnings:
                parse_warnings.append(warning)
            if "malformed-target" not in finding_types:
                score += 2
                if risk_floor == "safe":
                    risk_floor = "medium"
                finding_types.add("malformed-target")
                findings.append({"rule_id": "link.malformed_target",
                                 **indicator("medium", "link.malformed_target")})
            continue
        if parsed.scheme.lower() not in {"http", "https"}:
            if parsed.scheme.lower() in {"data", "file", "javascript"} and "unsafe-scheme" not in finding_types:
                score += 5
                risk_floor = "high"
                finding_types.add("unsafe-scheme")
                findings.append({"rule_id": "link.unsafe_scheme",
                                 **indicator("high", "link.unsafe_scheme", scheme=parsed.scheme.lower())})
            continue

        if (
            bool(parsed.username or parsed.password)
            and "url-userinfo" not in finding_types
        ):
            score += 5
            risk_floor = "high"
            finding_types.add("url-userinfo")
            findings.append({"rule_id": "link.url_userinfo", **indicator("high", "link.url_userinfo")})

        target_host = _link_host(parsed)
        if not target_host:
            continue
        if _is_ip_host(target_host) and 'ip-host' not in finding_types:
            score += 3
            risk_floor = 'high'
            finding_types.add('ip-host')
            findings.append({'rule_id': 'link.ip_host', **indicator('high', 'link.ip_host')})
        if _is_ipfs_gateway(target_host, parsed.path) and 'ipfs-gateway' not in finding_types:
            # Content-addressed pages on public IPFS gateways cannot be taken down by
            # the impersonated brand. In 2023-25 phishing 119/1,303 used them; 0/5,055
            # legitimate list messages did (docs/evaluation.md).
            score += 4
            risk_floor = 'high'
            finding_types.add('ipfs-gateway')
            findings.append({'rule_id': 'link.ipfs_gateway', **indicator('high', 'link.ipfs_gateway', host=target_host)})
        decoded_host = _decode_idna_domain(target_host)

        visible_host = _visible_link_host(link_text)
        if (
            visible_host
            and not _display_host_aligns(_decode_idna_domain(visible_host), decoded_host)
            and "display-mismatch" not in finding_types
        ):
            score += 3
            risk_floor = "high"
            finding_types.add("display-mismatch")
            findings.append({"rule_id": "link.display_mismatch",
                             **indicator("high", "link.display_mismatch",
                                         display_host=visible_host, host=target_host)})

        decoded_skeleton = _confusable_skeleton(decoded_host)
        first_label = decoded_skeleton.split(".", 1)[0]
        decoded_labels = [label for label in decoded_host.split(".") if label]
        for brand, canonical_domains in _PROTECTED_BRAND_DOMAINS.items():
            canonical = any(_domains_align(target_host, domain) for domain in canonical_domains)
            if (
                brand in first_label
                and not canonical
                and (
                    target_host.startswith("xn--")
                    or decoded_skeleton != decoded_host.casefold()
                )
                and "idn-confusable" not in finding_types
            ):
                score += 5
                risk_floor = "high"
                finding_types.add("idn-confusable")
                findings.append({"rule_id": "link.idn_confusable",
                                 **indicator("high", "link.idn_confusable", host=target_host, brand=brand)})
            elif (
                not canonical
                and any(
                    _label_uses_brand_lookalike(label, brand)
                    for label in decoded_labels
                )
                and "brand-lookalike" not in finding_types
            ):
                score += 5
                risk_floor = "high"
                finding_types.add("brand-lookalike")
                findings.append({"rule_id": "link.brand_lookalike",
                                 **indicator("high", "link.brand_lookalike", host=target_host, brand=brand)})

        free_host = _free_hosting_suffix(target_host)
        if free_host in _DEV_HOSTING_SUFFIXES and "dev-hosting" not in finding_types:
            # An alert on its own (Medium), not High: developers do share such addresses.
            score += 4
            if risk_floor in {"safe", "low"}:
                risk_floor = "medium"
            finding_types.add("dev-hosting")
            findings.append({"rule_id": "link.dev_hosting",
                             **indicator("medium", "link.dev_hosting", host=target_host, service=free_host)})
        site_brand = free_host and _brand_in_site_name(_decode_idna_domain(target_host[: -len(free_host) - 1]))
        if site_brand and "brand-free-host" not in finding_types:
            # Supporting evidence only (no floor): tools named after a platform
            # (youtube-summarizer.vercel.app) are ordinary in developers' mail. In
            # 2023-24 phishing 99/787 messages linked to these services; 3 named a brand.
            score += 4
            finding_types.add("brand-free-host")
            findings.append({"rule_id": "link.brand_on_free_host",
                             **indicator("medium", "link.brand_on_free_host", host=target_host,
                                         brand=site_brand, service=free_host)})

        host_tokens = set(re.findall(r"[a-z0-9]+", decoded_skeleton))
        credential_collection = bool(
            host_tokens & {"credential", "password", "passcode", "otp"}
            and host_tokens & {"capture", "harvest", "steal"}
        )
        host_finding = "credential-collection-host" if credential_collection else "sensitive-host"
        if (
            not _known_link_host(target_host)
            and host_tokens & sensitive_host_terms
            and host_finding not in finding_types
        ):
            # Login/account labels are ordinary on legitimate custom domains.
            # Keep them as weak context, not a stand-alone high-risk verdict.
            score += 4 if credential_collection else 2
            if credential_collection:
                risk_floor = "high"
            finding_types.add(host_finding)
            rule_id = ("link.credential_collection_host" if credential_collection
                       else "link.sensitive_host")
            findings.append({"rule_id": rule_id, **indicator(
                "high" if credential_collection else "low", rule_id, host=target_host)})

    return score, findings, risk_floor


def _has_mismatched_link_text(text: str) -> bool:
    """Compatibility wrapper for callers that only need a mismatch boolean."""
    _score, findings, _floor = _analyze_link_destinations(text)
    return any("does not match" in finding["msg"] for finding in findings)


def _link_hosts(links) -> list[str]:
    hosts = []
    for _label, destination in links:
        try:
            host = (_parse_link_target(destination).hostname or '').lower().rstrip('.')
        except ValueError:
            continue
        if host and host not in hosts:
            hosts.append(host)
    return hosts
