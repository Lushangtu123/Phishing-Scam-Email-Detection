"""Domain registration dates from the registries' RDAP servers (RFC 9083, 9224).

Off unless RDAP_LOOKUPS is set (the deployment profile sets it). Only a registrable
domain is ever sent, never a subdomain, a path or message text, and only to the RDAP
server the checked-in IANA bootstrap names for its top-level domain: the registry, not
the domain's owner. Each lookup is bounded in time and size and cached; a failure leaves
the date unknown and changes nothing else.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from functools import lru_cache
import json
from pathlib import Path
import re
import threading
import time
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

BOOTSTRAP_SCHEMA = "phishguard-rdap-bootstrap-v1"
DEFAULT_BOOTSTRAP_PATH = Path(__file__).parent / "data" / "rdap_bootstrap.json"
LOOKUP_TIMEOUT = 2.0
LOOKUP_DEADLINE = 3.0
MAX_LOOKUPS_PER_MESSAGE = 5
MAX_RESPONSE_BYTES = 256 * 1024
CACHE_TTL = 24 * 3600
FAILURE_TTL = 3600
CACHE_LIMIT = 2048
MIN_TLDS = 100
USER_AGENT = "PhishGuard-RDAP/1"
_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}")


def validate_bootstrap(payload: dict) -> None:
    """Raise ValueError unless payload is a usable bootstrap snapshot."""
    if payload.get("schema") != BOOTSTRAP_SCHEMA or not payload.get("source") or not payload.get("fetched"):
        raise ValueError("unknown RDAP bootstrap snapshot")
    services = payload.get("services")
    if not isinstance(services, list):
        raise ValueError("RDAP bootstrap has no services")
    tlds = 0
    for entry in services:
        if not (isinstance(entry, list) and len(entry) == 2 and all(isinstance(part, list) for part in entry)):
            raise ValueError("malformed RDAP bootstrap service")
        if not any(str(url).startswith("https://") for url in entry[1]):
            raise ValueError("an RDAP service without an https URL")
        tlds += len(entry[0])
    if tlds < MIN_TLDS:
        raise ValueError("too few top-level domains in the RDAP bootstrap")


@lru_cache(maxsize=1)
def load_bootstrap(path: Path = DEFAULT_BOOTSTRAP_PATH) -> dict[str, str] | None:
    """Top-level domain -> its RDAP base URL (https, ending in /), or None."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_bootstrap(payload)
    except (OSError, ValueError, TypeError):
        return None
    servers = {}
    for tlds, urls in payload["services"]:
        url = next(str(url) for url in urls if str(url).startswith("https://"))
        for tld in tlds:
            servers[str(tld).lower()] = url if url.endswith("/") else url + "/"
    return servers


def rdap_base(domain: str, servers: dict[str, str] | None = None) -> str | None:
    """The RDAP server for domain's top-level domain (the longest label suffix listed)."""
    servers = load_bootstrap() if servers is None else servers
    if not servers:
        return None
    labels = domain.split(".")
    for index in range(1, len(labels)):
        base = servers.get(".".join(labels[index:]))
        if base:
            return base
    return None


class _HttpsOnly(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if urlsplit(new_url).scheme != "https":
            return None
        return super().redirect_request(request, response, code, message, headers, new_url)


_OPENER = build_opener(_HttpsOnly)


def _fetch(url: str, timeout: float) -> dict | None:
    request = Request(url, headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT})
    with _OPENER.open(request, timeout=timeout) as response:
        data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        return None
    return json.loads(data.decode("utf-8"))


def registration_date(record: dict) -> datetime | None:
    """The registration event of an RDAP domain record."""
    for event in record.get("events") or ():
        if isinstance(event, dict) and str(event.get("eventAction", "")).lower() == "registration":
            try:
                date = datetime.fromisoformat(str(event.get("eventDate", "")).replace("Z", "+00:00"))
            except ValueError:
                return None
            return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    return None


_cache: dict[str, tuple[float, datetime | None]] = {}
_cache_lock = threading.Lock()


def lookup(domain: str, *, fetch=_fetch, servers: dict[str, str] | None = None,
           timeout: float = LOOKUP_TIMEOUT) -> datetime | None:
    """The registration date of a registrable domain, or None when unknown."""
    domain = domain.lower().rstrip(".")
    if not _DOMAIN.fullmatch(domain):
        return None
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(domain)
        if cached and cached[0] > now:
            return cached[1]
    base = rdap_base(domain, servers)
    date = None
    if base:
        try:
            date = registration_date(fetch(base + "domain/" + quote(domain), timeout) or {})
        except Exception:  # unreachable server, refusal, timeout, malformed record
            date = None
    with _cache_lock:
        if len(_cache) >= CACHE_LIMIT:
            _cache.clear()
        _cache[domain] = (now + (CACHE_TTL if date else FAILURE_TTL), date)
    return date


_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="rdap")


def _submit(domains, fetch, servers):
    domains = list(dict.fromkeys(domains))[:MAX_LOOKUPS_PER_MESSAGE]
    return {domain: _pool.submit(lookup, domain, fetch=fetch, servers=servers) for domain in domains}


def _collect(futures) -> dict[str, datetime | None]:
    return {domain: future.result() if future.done() and not future.exception() else None
            for domain, future in futures.items()}


def lookup_many(domains, *, fetch=_fetch, servers: dict[str, str] | None = None,
                deadline: float = LOOKUP_DEADLINE) -> dict[str, datetime | None]:
    """Registration dates of up to MAX_LOOKUPS_PER_MESSAGE domains, in parallel. A domain
    not answered before the deadline is unknown."""
    futures = _submit(domains, fetch, servers)
    wait(futures.values(), timeout=deadline)
    return _collect(futures)


async def lookup_many_async(domains, *, fetch=_fetch, servers: dict[str, str] | None = None,
                            deadline: float = LOOKUP_DEADLINE) -> dict[str, datetime | None]:
    """lookup_many for the event loop: waiting holds no analysis worker."""
    futures = _submit(domains, fetch, servers)
    if futures:
        await asyncio.wait([asyncio.wrap_future(future) for future in futures.values()], timeout=deadline)
    return _collect(futures)
