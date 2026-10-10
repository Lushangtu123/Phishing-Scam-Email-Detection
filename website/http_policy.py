"""HTTP policy with no application state: allowed hosts, rate-limit keys and buckets, browser
security and cache headers, hash-validated file responses and which 404s get the HTML page.

app.py keeps the middleware, routes and the state they share (the rate-limit buckets and
store, page paths), because the lifespan sets that state and tests patch it on app.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from collections import deque
from pathlib import Path

from fastapi import Request
from fastapi.responses import Response


def _build_allowed_hosts(base_hosts: str, custom_domains: str = "") -> list[str]:
    """Merge configured deployment hosts and custom domains without duplicates."""
    hosts: list[str] = []
    for host in base_hosts.split(","):
        normalized = host.strip().lower().rstrip(".")
        if normalized and normalized not in hosts:
            hosts.append(normalized)

    custom_host_re = re.compile(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
    )
    for host in custom_domains.split(","):
        raw_host = host.strip().lower()
        if not raw_host:
            continue
        normalized = raw_host.rstrip(".")
        if (
            not normalized
            or len(normalized) > 253
            or not custom_host_re.fullmatch(normalized)
        ):
            raise ValueError(
                "CUSTOM_DOMAINS entries must be hostnames without a URL scheme, port, or path"
            )
        if normalized not in hosts:
            hosts.append(normalized)
    return hosts


class _RateLimitBucket(deque):
    def __init__(self, window_seconds):
        super().__init__()
        self.window_seconds = window_seconds


_RATE_LIMIT_PATHS = frozenset({
    '/api/analyze-email', '/api/analyze-content', '/api/analyze-eml',
    '/api/analyze-visual', '/api/verify-email', '/api/feedback', '/api/analyze-sms',
})


def _rate_limit_key(request: Request) -> str:
    """Use Vercel's normalized client address only in the Vercel profile."""
    client_ip = request.client.host if request.client else "unknown"
    if os.getenv("PHISHGUARD_DEPLOYMENT_PROFILE", "").strip().lower() == "vercel-free":
        forwarded_ip = request.headers.get("x-forwarded-for", "").strip()
        if forwarded_ip and "," not in forwarded_ip:
            try:
                client_ip = str(ipaddress.ip_address(forwarded_ip))
            except ValueError:
                pass
    path = request.url.path
    if path == '/api/cases' or path.startswith('/api/cases/'):
        # Untrusted case IDs must not create a separate budget for each request.
        path = '/api/cases'
    elif path not in _RATE_LIMIT_PATHS:
        path = '/api/unknown'
    return f"{client_ip}:{path}"


def _record_rate_limit_hit(
    bucket_key: str,
    *,
    now: float,
    buckets: dict[str, deque[float]],
    limit: int,
    capacity: int,
    window_seconds: float,
) -> bool:
    stale_keys = []
    for key, hits in buckets.items():
        # Minute requests must not erase still-live hourly feedback restrictions.
        cutoff = now - getattr(hits, 'window_seconds', window_seconds)
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if not hits:
            stale_keys.append(key)
    for key in stale_keys:
        buckets.pop(key, None)

    if bucket_key not in buckets:
        if len(buckets) >= capacity:
            # Preserve live restrictions even under key churn. Expired entries
            # were reclaimed above; a new identity must wait for a free slot.
            return False
        buckets[bucket_key] = _RateLimitBucket(window_seconds)

    bucket = buckets[bucket_key]
    if len(bucket) >= limit:
        return False
    bucket.append(now)
    return True


# Browsers reuse a versioned file for one day. On Vercel the CDN acts on
# stale-while-revalidate itself (x-vercel-cache: HIT) and strips it from the
# browser response, so browsers see only max-age=86400; each deployment clears
# the CDN cache. A missed ?v= bump can serve a stale file for up to a day, which
# website/tools/asset-versions guards against.
VERSIONED_ASSET_CACHE_CONTROL = "public, max-age=86400, stale-while-revalidate=604800"


# Browser protections on every response. On Vercel the CDN serves /static itself, without
# this app's middleware, so vercel.json "headers" repeats these, the worker policy below and
# VERSIONED_ASSET_CACHE_CONTROL for /static (test_vercel_static_headers.py pins them).
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    # Scripts are same-origin files only: no inline handlers or CDN hosts.
    # Styles are same-origin stylesheets only: no style="" attributes or
    # <style> elements (scripts may still set element.style via the CSSOM).
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
}
# The vision worker scripts run WebAssembly and may start their own workers.
WORKER_SCRIPT_PATHS = frozenset({'/static/vision-worker.mjs', '/static/vendor/vision/worker.min.js'})
WORKER_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; "
    "connect-src 'self'; worker-src 'self'; object-src 'none'")


def _with_security_headers(response):
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    return response


def _revalidated_file(path: Path, request: Request, media_type: str) -> Response:
    """A file whose ETag is the hash of its bytes, revalidated on every use (no-cache).

    FileResponse derives its ETag from the modification time and size, and Vercel gives every
    deployed file the same time: a page whose ?v= numbers changed without changing its length
    kept its ETag, and returning browsers were answered 304 with the previous deployment's page.
    """
    body = path.read_bytes()
    etag = '"' + hashlib.sha256(body).hexdigest() + '"'
    headers = {'ETag': etag, 'Cache-Control': 'no-cache'}
    # A proxy may weaken the tag (W/"…") on its way back; the hash is the same.
    sent = {tag.strip().removeprefix('W/') for tag in request.headers.get('if-none-match', '').split(',')}
    if etag in sent:
        return Response(status_code=304, headers=headers)
    return Response(body, media_type=media_type, headers=headers)


# API errors stay JSON for scripts. A missing static asset (or Vercel collector
# script) is requested by a <script>/<link>/<img>, never shown as a page, so it
# keeps the short JSON 404 instead of an HTML document.
_NOT_FOUND_JSON_PREFIXES = ("/api/", "/static/", "/_vercel/")
_NOT_FOUND_JSON_PATHS = frozenset({"/api", "/static", "/_vercel"})


def _wants_not_found_page(request: Request) -> bool:
    """A GET/HEAD for a page URL, unless the client asks for JSON and not HTML."""
    path = request.url.path
    if request.method not in ("GET", "HEAD"):
        return False
    if path in _NOT_FOUND_JSON_PATHS or path.startswith(_NOT_FOUND_JSON_PREFIXES):
        return False
    accept = request.headers.get("accept", "").lower()
    return "text/html" in accept or "application/json" not in accept
