"""Domain registration dates from the registries' RDAP servers (RFC 9083, 9224).

Off unless RDAP_LOOKUPS is set (the deployment profile sets it). Only a registrable
domain is ever sent, never a subdomain, a path or message text, and only to the RDAP
server the checked-in IANA bootstrap names for its top-level domain: the registry, not
the domain's owner. Each lookup is bounded in time and size and cached; a failure leaves
the date unknown and changes nothing else.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor, wait
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
# Lookup work items admitted at once across all messages, running or queued (including
# those nobody waits for any more, until the pool reaches and skips them): beyond it a
# domain's date is unknown rather than queued without bound.
MAX_PENDING_LOOKUPS = 16
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


class _Lookup:
    """One admitted lookup: its future and the messages waiting for it. Its work item holds
    an admission slot from submission until it leaves the pool's queue and ends, so a
    lookup nobody waits for any more still counts while it sits in the queue."""
    __slots__ = ("future", "waiters")

    def __init__(self):
        self.future, self.waiters = None, 0


# Lookups not yet ended, by domain: one serves every message that asks for the domain.
_pending: dict[str, _Lookup] = {}
_admitted = 0  # work items submitted and not yet ended: running, queued or abandoned
_pending_lock = threading.Lock()


def _cached(domain: str):
    with _cache_lock:
        cached = _cache.get(domain)
    return cached if cached and cached[0] > time.monotonic() else None


def _work(domain: str, entry: _Lookup, fetch, servers) -> datetime | None:
    """Look the domain up, unless no message waits for it any more; free the slot after."""
    global _admitted
    try:
        with _pending_lock:
            if entry.waiters <= 0:
                return None
        return lookup(domain, fetch=fetch, servers=servers)
    finally:
        with _pending_lock:
            _admitted -= 1
            if _pending.get(domain) is entry:
                del _pending[domain]


def _submit(domains, fetch, servers):
    """Futures (or cached dates) for up to MAX_LOOKUPS_PER_MESSAGE domains."""
    global _admitted
    domains = list(dict.fromkeys(domain.lower().rstrip(".") for domain in domains))[:MAX_LOOKUPS_PER_MESSAGE]
    futures = {}
    with _pending_lock:
        for domain in domains:
            cached = _cached(domain)
            if cached:
                futures[domain] = cached[1]
                continue
            entry = _pending.get(domain)
            if entry is None:
                if _admitted >= MAX_PENDING_LOOKUPS:
                    futures[domain] = None
                    continue
                entry = _pending[domain] = _Lookup()
                _admitted += 1
                entry.future = _pool.submit(_work, domain, entry, fetch, servers)
            # A queued lookup another message gave up on is taken up again.
            entry.waiters += 1
            futures[domain] = entry.future
    return futures


def _collect(futures) -> dict[str, datetime | None]:
    """The dates answered so far. A lookup no message waits for any more is skipped when
    the pool reaches it; one already running finishes and fills the cache."""
    dates = {}
    with _pending_lock:
        for domain, future in futures.items():
            if not isinstance(future, Future):
                dates[domain] = future
                continue
            if future.done():
                dates[domain] = None if future.exception() else future.result()
                continue
            dates[domain] = None
            entry = _pending.get(domain)
            if entry is not None and entry.future is future:
                entry.waiters -= 1
    return dates


def lookup_many(domains, *, fetch=_fetch, servers: dict[str, str] | None = None,
                deadline: float = LOOKUP_DEADLINE) -> dict[str, datetime | None]:
    """Registration dates of up to MAX_LOOKUPS_PER_MESSAGE domains, in parallel. A domain
    not answered before the deadline, or beyond MAX_PENDING_LOOKUPS, is unknown."""
    futures = _submit(domains, fetch, servers)
    waiting = [future for future in futures.values() if isinstance(future, Future)]
    if waiting:
        wait(waiting, timeout=deadline)
    return _collect(futures)


async def lookup_many_async(domains, *, fetch=_fetch, servers: dict[str, str] | None = None,
                            deadline: float = LOOKUP_DEADLINE) -> dict[str, datetime | None]:
    """lookup_many for the event loop: waiting holds no analysis worker."""
    futures = _submit(domains, fetch, servers)
    waiting = [future for future in futures.values() if isinstance(future, Future)]
    if waiting:
        await asyncio.wait([asyncio.wrap_future(future) for future in waiting], timeout=deadline)
    return _collect(futures)
