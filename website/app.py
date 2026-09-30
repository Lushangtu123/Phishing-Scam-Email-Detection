"""
app.py – FastAPI backend for the Phishing Email Detector demo.

Sender addresses use explainable domain heuristics. Full messages additionally
use RFC 5322 structure/authentication signals and, when enabled, a separately
validated offline email-text classifier. Historical UCI website-model metrics
remain available only as a clearly scoped course benchmark.
Routes:
  GET  /                      → serve index.html
  GET  /api/metrics           → classifier performance metrics
  GET  /api/features          → feature metadata
  GET  /api/config            → public-safe feature configuration
  POST /api/analyze-email     → explainable sender/domain risk analysis
  POST /api/analyze-content   → message structure + content analysis
  POST /api/analyze-eml       → byte-preserving MIME upload analysis
"""

from __future__ import annotations

import os
import asyncio
import json
import hashlib
import ipaddress
import re
import socket
import smtplib
import threading
import time
import unicodedata
import warnings
from collections import deque
from email.utils import getaddresses
from html.parser import HTMLParser
from html import escape as escape_html, unescape as unescape_html
from itertools import product
from functools import partial
from urllib.parse import parse_qs, unquote, urlparse, urljoin

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from config import load_settings
from case_api import build_case_service, make_case_router, public_jev_status
from feedback_api import make_feedback_router
from disposable_registry import REGISTRY_DOMAIN_RE as _REGISTRY_DOMAIN_RE  # noqa: F401 -- used by tests via app._REGISTRY_DOMAIN_RE
from request_limits import RequestBodyLimitMiddleware
from rate_limits import DisabledRateLimitStore, build_rate_limit_store
from verification_runtime import BoundedExecutor
from server_messages import (annotate_content, indicator, message as coded_message, strip_details,
                             text as message_text, warning_indicator, wrap as wrap_message)
from visual_evidence import (VisualRequest, VISUAL_PATHS, MAX_VISUAL_REQUEST_BYTES,
                             bound_message_text, merge_visual_findings, merge_visual_sources)
from enhanced_vision import load_enhanced_vision_settings, recognize_image, enhanced_evidence
from language_coverage import (has_substantial_han_text as _has_substantial_han_text,
                               non_latin_script_segments)
from sender_history import (
    DisabledSenderHistoryStore,
    SenderHistoryResult,
    build_sender_history_store,
    canonicalize_sender_address,
)
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

BASE_DIR = Path(__file__).parent
SETTINGS = load_settings()
ENHANCED_VISION = load_enhanced_vision_settings()


def load_content_pipeline_artifact(path: Path, expected_sha256: str) -> dict:
    """Load the optional scientific stack only when ML is enabled."""
    from content_inference import load_content_pipeline_artifact as loader

    return loader(path, expected_sha256)


def predict_content(pipeline: dict, subject: str, body: str, *, canonical_text: bool = False) -> dict:
    """Run optional inference without importing training dependencies."""
    from content_inference import predict_content as predictor

    return predictor(pipeline, subject, body, canonical_text=canonical_text)


from email_structure import (
    MAILBOX_AUTHSERV_IDS,
    SENDER_ONLY_SERVICES,
    OFFICIAL_SERVICE_NUMBERS as _OFFICIAL_SERVICE_NUMBERS,
    official_channels as _official_channels,
    _PROTECTED_BRAND_DOMAINS,
    _confusable_skeleton,
    _decode_idna_domain,
    _domains_align,
    analyze_raw_email,
)
import tldextract
from sender_features import (  # noqa: F401 -- re-exported for app callers and tests
    LEGIT_PROVIDERS,
    HIGH_TRAFFIC,
    SUSPICIOUS_KEYWORDS,
    ROUTINE_MAILBOX_NAMES,
    BRAND_DOMAINS,
    FINANCIAL_DOMAIN_KEYWORDS,
    BUSINESS_SUFFIX_KEYWORDS,
    SPAM_TLDS,
    COMMON_TLDS,
    ABUSED_CCTLDS,
    SHORT_SERVICES,
    _DISPOSABLE_DOMAIN_SOURCE,
    DISPOSABLE_REGISTRY_METADATA,
    PRIVACY_RELAY_DOMAINS,
    PRIVACY_RELAY_REGISTRY_METADATA,
    DISPOSABLE_DOMAINS,
    _DOMAIN_EXTRACTOR,
    _DISPOSABLE_DOMAIN_PATTERNS,
    _match_domain_registry,
    _matches_disposable_domain_pattern,
    normalize_homoglyphs,
    _shannon_entropy,
    extract_email_features,
    _RAW_SENDER_LOCAL_RE,
    _RAW_SENDER_DOMAIN_LABEL_RE,
    _normalize_sender_address,
)

RATE_LIMIT_PER_MINUTE = max(1, int(os.getenv("RATE_LIMIT_PER_MINUTE", "20")))
RATE_LIMIT_BUCKET_CAPACITY = max(128, int(os.getenv("RATE_LIMIT_BUCKET_CAPACITY", "4096")))
MAX_REQUEST_BYTES = max(1024, int(os.getenv("MAX_REQUEST_BYTES", "65536")))
try:
    ANALYSIS_WORKERS = int(os.getenv('ANALYSIS_WORKERS', '4'))
except ValueError as exc:
    raise ValueError('ANALYSIS_WORKERS must be an integer') from exc
if not 1 <= ANALYSIS_WORKERS <= 16:
    raise ValueError('ANALYSIS_WORKERS must be between 1 and 16')
_analysis_pool = BoundedExecutor(workers=ANALYSIS_WORKERS, thread_name_prefix='analysis')


async def _run_analysis(function, *args, **kwargs):
    """Keep synchronous parsing/inference off the event loop, without a queue."""
    future = _analysis_pool.submit(partial(function, *args, **kwargs))
    if future is None:
        raise HTTPException(503, 'Analysis is busy; retry shortly.',
                            headers={'Retry-After': '1'})
    return await asyncio.wrap_future(future)

# ── Feature definitions (UCI Phishing Websites Dataset mapping) ───────────────
FEATURE_INFO = [
    {"name": "having_ip_address",
     "label": "IP Address Domain",        "group": "URL-based",
     "email_desc":     "Domain is a raw IP address instead of a proper hostname — highly suspicious",
     "email_desc_pos": "Domain uses a proper hostname, not a raw IP address"},
    {"name": "url_length",
     "label": "Address Length",           "group": "URL-based",
     "email_desc":     "Total email address is abnormally long — phishing addresses are often padded",
     "email_desc_pos": "Email address length is within normal limits"},
    {"name": "shortining_service",
     "label": "URL Shortener Domain",     "group": "URL-based",
     "email_desc":     "Domain belongs to a known URL shortening service — frequently abused in phishing",
     "email_desc_pos": "Domain is not a URL shortening service"},
    {"name": "having_at_symbol",
     "label": "Multiple @ Symbols",       "group": "URL-based",
     "email_desc":     "Address contains more than one @ symbol — invalid / malformed email",
     "email_desc_pos": "Address has exactly one @ symbol — correct format"},
    {"name": "double_slash_redirecting",
     "label": "Double Slash in Domain",   "group": "URL-based",
     "email_desc":     "Domain contains '//' — possible redirect deception trick",
     "email_desc_pos": "No double-slash redirect found in the domain"},
    {"name": "prefix_suffix",
     "label": "Hyphen in Domain",         "group": "URL-based",
     "email_desc":     "Base domain contains a hyphen — legitimate providers rarely use hyphens",
     "email_desc_pos": "Domain has no hyphens — consistent with legitimate mail providers"},
    {"name": "having_sub_domain",
     "label": "Subdomain Depth",          "group": "URL-based",
     "email_desc":     "Domain has multiple subdomain levels — phishing sites use deep subdomains to impersonate brands",
     "email_desc_pos": "Domain has normal subdomain depth (0–1 level)"},
    {"name": "https_token",
     "label": "'http' Token in Address",  "group": "URL-based",
     "email_desc":     "The string 'http' appears inside the email address — a visual confusion trick",
     "email_desc_pos": "No misleading 'http' token found in the address"},
    {"name": "sslfinal_state",
     "label": "Recognized Provider / Domain", "group": "Domain-based",
     "email_desc":     "Domain does not match the local provider or institutional-domain rules",
     "email_desc_pos": "Domain matches a provider registry or institutional-domain rule; this does not authenticate the sender"},
    {"name": "domain_registration_length",
     "label": "Recognized Public Suffix",  "group": "Domain-based",
     "email_desc":     "Domain suffix is not recognized by the bundled Public Suffix List",
     "email_desc_pos": "Domain suffix is recognized; this alone does not establish reputation"},
    {"name": "age_of_domain",
     "label": "Domain Label Length",      "group": "Domain-based",
     "email_desc":     "Domain label is abnormally long — may be disguising a legitimate domain name",
     "email_desc_pos": "Domain label length is within normal range"},
    {"name": "dnsrecord",
     "label": "Digits in Domain",         "group": "Domain-based",
     "email_desc":     "Domain name contains embedded digits — legitimate brand domains are usually letters only",
     "email_desc_pos": "Domain name contains no suspicious digit patterns"},
    {"name": "web_traffic",
     "label": "High-Traffic Mail Platform","group": "Domain-based",
     "email_desc":     "Domain is not in the high-traffic provider registry; this alone does not establish malicious intent",
     "email_desc_pos": "Domain matches a high-traffic provider or privacy relay; this does not authenticate the sender"},
    {"name": "page_rank",
     "label": "Phishing Keywords in Domain","group": "Domain-based",
     "email_desc":     "Domain part contains known phishing-related keywords",
     "email_desc_pos": "No phishing keywords detected in the domain"},
    {"name": "google_index",
     "label": "Phishing Keywords in Local","group": "Domain-based",
     "email_desc":     "Username (local part) contains known phishing-related keywords",
     "email_desc_pos": "No phishing keywords detected in the username"},
    {"name": "statistical_report",
     "label": "Suspicious TLD",           "group": "Domain-based",
     "email_desc":     "TLD is a known high-risk or free domain extension heavily used in phishing",
     "email_desc_pos": "TLD is not associated with high-risk or free domain registrations"},
    {"name": "favicon",
     "label": "High Digit Ratio in Local","group": "HTML/Content-based",
     "email_desc":     "Username has an unusually high proportion of digits",
     "email_desc_pos": "Username digit ratio is within normal limits"},
    {"name": "port",
     "label": "Username Randomness",      "group": "HTML/Content-based",
     "email_desc":     "Username has high Shannon entropy — likely randomly auto-generated",
     "email_desc_pos": "Username entropy is normal — does not appear randomly generated"},
    {"name": "request_url",
     "label": "Special Chars in Local",   "group": "HTML/Content-based",
     "email_desc":     "Username contains characters outside the supported mailbox syntax",
     "email_desc_pos": "Username characters are supported, including ordinary atom punctuation"},
    {"name": "url_of_anchor",
     "label": "Username Length",          "group": "HTML/Content-based",
     "email_desc":     "Username exceeds 30 characters — abnormally long",
     "email_desc_pos": "Username length is within normal range (≤ 30 characters)"},
    {"name": "links_in_tags",
     "label": "Brand Domain Spoofing",    "group": "HTML/Content-based",
     "email_desc":     "Domain appears to impersonate a well-known brand (e.g. paypal, apple)",
     "email_desc_pos": "No brand domain spoofing detected"},
    {"name": "sfh",
     "label": "noreply Address",          "group": "HTML/Content-based",
     "email_desc":     "Sender is a noreply / no-reply / donotreply address — cannot receive replies",
     "email_desc_pos": "Normal sender address — not a noreply / donotreply"},
    {"name": "submitting_to_email",
     "label": "Repeated Characters",      "group": "HTML/Content-based",
     "email_desc":     "Username contains heavily repeated characters — possibly auto-generated",
     "email_desc_pos": "Username has no abnormal character repetition"},
    {"name": "abnormal_url",
     "label": "Digit-Letter Mix in Domain","group": "HTML/Content-based",
     "email_desc":     "Domain mixes digits and letters suspiciously (e.g. paypa1, g00gle)",
     "email_desc_pos": "No suspicious digit-letter mixing detected in the domain"},
    {"name": "redirect",
     "label": "Redirect Detection",       "group": "HTML/Content-based",
     "email_desc":     "Potential network-layer redirect detected",
     "email_desc_pos": "No network-layer redirect detected"},
    {"name": "on_mouseover",
     "label": "Abused Country-Code TLD",  "group": "HTML/Content-based",
     "email_desc":     "TLD is a country code commonly abused in phishing attacks",
     "email_desc_pos": "TLD is not a commonly abused country-code domain"},
    {"name": "rightclick",
     "label": "Auto-Generated Username",  "group": "HTML/Content-based",
     "email_desc":     "Username matches common auto-generated patterns (short prefix + digits)",
     "email_desc_pos": "Username does not match typical auto-generated patterns"},
    {"name": "popupwindow",
     "label": "Domain Word Segments",     "group": "HTML/Content-based",
     "email_desc":     "Domain label contains too many word segments — suspicious construction",
     "email_desc_pos": "Domain label word structure is normal"},
    {"name": "iframe",
     "label": "Composite Risk Score",     "group": "HTML/Content-based",
     "email_desc":     "Multiple risk factors detected — composite score indicates elevated phishing risk",
     "email_desc_pos": "Composite risk score is low — few phishing indicators present"},
    {"name": "links_pointing_to_page",
     "label": "Valid Email Format",       "group": "HTML/Content-based",
     "email_desc":     "Email address has unsupported or malformed mailbox syntax",
     "email_desc_pos": "Email address matches the supported mailbox syntax"},
]

FEATURE_NAMES = [f["name"] for f in FEATURE_INFO]

MAJOR_MAILBOX_PROVIDERS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'icloud.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com',
    'zoho.com', 'mail.com', 'yandex.com', 'live.com', 'msn.com', 'me.com',
    'qq.com', '163.com', '126.com', 'sina.com', 'sohu.com', 'foxmail.com',
}
HOMOGLYPH_MAP = {
    '0': 'o',   # amaz0n → amazon
    '1': 'l',   # paypa1 → paypal, app1e → apple
    '3': 'e',   # n3tflix → netflix
    '4': 'a',   # p4ypal → paypal
    '5': 's',   # micro5oft → microsoft
    '6': 'g',   # 6oogle → google
    '8': 'b',   # 8ank → bank
    '@': 'a',   # p@ypal → paypal
    'vv': 'w',  # vvindows → windows
    'rn': 'm',  # rnicro → micro
    'nn': 'm',  # nnicrosoft → microsoft
    'ii': 'u',  # giithub → github (rare)
    'cl': 'd',  # clomain → domain (rare)
}
# ── Pre-computed model metrics ────────────────────────────────────────────────
MODEL_METRICS = {
    "Random Forest":      {"Accuracy": 0.9747, "Precision": 0.9748, "Recall": 0.9747, "F1": 0.9746, "ROC_AUC": 0.9977},
    "SVM (RBF)":          {"Accuracy": 0.9516, "Precision": 0.9520, "Recall": 0.9516, "F1": 0.9515, "ROC_AUC": 0.9893},
    "Decision Tree":      {"Accuracy": 0.9480, "Precision": 0.9481, "Recall": 0.9480, "F1": 0.9480, "ROC_AUC": 0.9865},
    "Logistic Regression":{"Accuracy": 0.9285, "Precision": 0.9287, "Recall": 0.9285, "F1": 0.9284, "ROC_AUC": 0.9808},
}

# ── Global optional model state ───────────────────────────────────────────────
_content_model_error: str | None = None
_content_model_artifact_sha256: str | None = None

# Optional email-content text classifier (TF-IDF + selected linear model).
# Populated at startup only from a verified offline artifact.
_content_pipeline: dict | None = None
_sender_history_store = DisabledSenderHistoryStore()
_rate_limit_store = DisabledRateLimitStore()

@asynccontextmanager
async def lifespan(_app: FastAPI):
    _app.state.case_service = None
    _app.state.case_configuration_error = False
    try:
        _app.state.case_service = build_case_service(os.environ)
    except (ValueError, OSError):
        # Optional case configuration must fail closed without taking down
        # the independent transient analyzer. Never log configuration values.
        _app.state.case_configuration_error = True
        print('Case management unavailable: invalid configuration or inaccessible storage.')
    global _content_pipeline, _content_model_error, _content_model_artifact_sha256
    global _sender_history_store, _rate_limit_store
    _sender_history_store = build_sender_history_store(SETTINGS)
    _rate_limit_store = build_rate_limit_store(os.environ, SETTINGS)
    if SETTINGS.content_model_enabled:
        if not SETTINGS.content_model_artifact or not SETTINGS.content_model_artifact_sha256:
            _content_pipeline = None
            _content_model_error = (
                "Content ML is enabled but CONTENT_MODEL_ARTIFACT and "
                "CONTENT_MODEL_ARTIFACT_SHA256 are not both configured."
            )
            _content_model_artifact_sha256 = None
        else:
            try:
                _content_pipeline = load_content_pipeline_artifact(
                    Path(SETTINGS.content_model_artifact),
                    SETTINGS.content_model_artifact_sha256,
                )
                _content_model_error = None
                _content_model_artifact_sha256 = SETTINGS.content_model_artifact_sha256.lower()
                print("Loaded verified offline email-content model artifact.")
            except ValueError as exc:
                _content_pipeline = None
                _content_model_error = f"Content-model artifact rejected: {exc}"
                _content_model_artifact_sha256 = None
                print(_content_model_error)
            except Exception as exc:
                _content_pipeline = None
                _content_model_error = (
                    f"Content-model artifact unavailable ({type(exc).__name__})."
                )
                _content_model_artifact_sha256 = None
                print(_content_model_error)
    else:
        _content_pipeline = None
        _content_model_error = None
        _content_model_artifact_sha256 = None
        print("Content ML disabled; verified heuristic and message-structure analysis remain available.")
    yield


app = FastAPI(title="Phishing Email Detector", version="2.0.0", lifespan=lifespan)


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


allowed_hosts = _build_allowed_hosts(
    os.getenv("ALLOWED_HOSTS", "*.onrender.com,localhost,127.0.0.1,testserver"),
    os.getenv("CUSTOM_DOMAINS", ""),
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES,
                   path_limits={**{path: MAX_VISUAL_REQUEST_BYTES for path in VISUAL_PATHS},
                                '/api/feedback': 100_000})

_rate_limit_lock = threading.Lock()
_rate_limit_buckets: dict[str, deque[float]] = {}


class _RateLimitBucket(deque):
    def __init__(self, window_seconds):
        super().__init__()
        self.window_seconds = window_seconds


_RATE_LIMIT_PATHS = frozenset({
    '/api/analyze-email', '/api/analyze-content', '/api/analyze-eml',
    '/api/analyze-visual', '/api/verify-email', '/api/feedback',
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


def _with_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        # Scripts are same-origin files only: no inline handlers or CDN hosts.
        # Styles are same-origin stylesheets only: no style="" attributes or
        # <style> elements (scripts may still set element.style via the CSSOM).
        "default-src 'self'; script-src 'self'; "
        "style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    return response


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Bound request cost and add browser protections for the public demo."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            limit = (MAX_VISUAL_REQUEST_BYTES if request.url.path in VISUAL_PATHS
                     else 100_000 if request.url.path == '/api/feedback' else MAX_REQUEST_BYTES)
            if int(content_length) > limit:
                return _with_security_headers(JSONResponse(
                    status_code=413,
                    content={"detail": "Request body is too large"},
                ))
        except ValueError:
            return _with_security_headers(JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length"},
            ))

    if request.method in {"POST", "PATCH"} and request.url.path.startswith("/api/"):
        bucket_key = _rate_limit_key(request)
        now = time.monotonic()

        with _rate_limit_lock:
            if not _record_rate_limit_hit(
                bucket_key,
                now=now,
                buckets=_rate_limit_buckets,
                limit=RATE_LIMIT_PER_MINUTE,
                capacity=RATE_LIMIT_BUCKET_CAPACITY,
                window_seconds=60.0,
            ):
                return _with_security_headers(JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests; try again in a minute"},
                    headers={"Retry-After": "60"},
                ))

        distributed_decision = await _rate_limit_store.check_rate_limit(
            bucket_key,
            limit=RATE_LIMIT_PER_MINUTE,
            window_seconds=60,
        )
        if distributed_decision is not None and not distributed_decision.allowed:
            return _with_security_headers(JSONResponse(
                status_code=429,
                content={"detail": "Too many requests; try again shortly"},
                headers={
                    "Retry-After": str(distributed_decision.retry_after),
                },
            ))

        if request.url.path == '/api/feedback':
            feedback_key = bucket_key + ':feedback'
            with _rate_limit_lock:
                allowed = _record_rate_limit_hit(
                    feedback_key, now=now, buckets=_rate_limit_buckets,
                    limit=5, capacity=RATE_LIMIT_BUCKET_CAPACITY, window_seconds=3600.0)
            if not allowed:
                return _with_security_headers(JSONResponse(
                    status_code=429, content={'detail': 'Too many reports; try again later'},
                    headers={'Retry-After': '3600'}))
            feedback_decision = await _rate_limit_store.check_rate_limit(
                feedback_key, limit=5, window_seconds=3600)
            if feedback_decision is not None and not feedback_decision.allowed:
                return _with_security_headers(JSONResponse(
                    status_code=429, content={'detail': 'Too many reports; try again later'},
                    headers={'Retry-After': str(feedback_decision.retry_after)}))

    response = _with_security_headers(await call_next(request))
    if request.url.path in {'/static/vision-worker.mjs', '/static/vendor/vision/worker.min.js'}:
        response.headers['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; "
            "connect-src 'self'; worker-src 'self'; object-src 'none'")
    # A versioned URL (?v=...) changes whenever its file does, so browsers may
    # reuse it without revalidating. 304s carry it too, or a browser that cached
    # the old max-age=0 would keep revalidating.
    if (request.url.path.startswith('/static/') and request.query_params.get('v')
            and response.status_code in (200, 304)):
        response.headers['Cache-Control'] = VERSIONED_ASSET_CACHE_CONTROL
    return response


@app.middleware("http")
async def private_case_responses(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == '/cases' or request.url.path.startswith('/api/cases') or request.url.path == '/api/feedback':
        response.headers['Cache-Control'] = 'no-store'
    if request.url.path == '/cases' or request.url.path.startswith('/api/cases'):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    return response


@app.get('/cases', include_in_schema=False)
async def serve_cases():
    return FileResponse(str(BASE_DIR / 'static' / 'cases.html'))


VERCEL_COLLECTORS = frozenset({'insights', 'speed-insights'})


@app.get('/_vercel/{collector}/script.js', include_in_schema=False)
async def local_vercel_collector(collector: str):
    """Answer the page's Vercel collector tags off-platform instead of 404ing.

    On Vercel the platform serves these paths itself; if a request still reaches
    the app there, keep the original 404 so a misconfiguration stays visible.
    """
    if os.getenv('VERCEL') or collector not in VERCEL_COLLECTORS:
        raise HTTPException(status_code=404, detail='Not Found')
    return Response('', media_type='text/javascript', headers={'Cache-Control': 'no-store'})


# ── Static files ──────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
async def serve_index():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


# Browsers request /favicon.ico regardless of the page's <link rel="icon">.
@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon():
    return FileResponse(str(BASE_DIR / "static" / "favicon.svg"), media_type="image/svg+xml")


# ── Not-found page ────────────────────────────────────────────────────────────
NOT_FOUND_PAGE = BASE_DIR / "static" / "404.html"
# API errors stay JSON for scripts. A missing static asset (or Vercel collector
# script) is requested by a <script>/<link>/<img>, never shown as a page, so it
# keeps the short JSON 404 instead of an HTML document.
_NOT_FOUND_JSON_PREFIXES = ("/api/", "/static/", "/_vercel/")
_NOT_FOUND_JSON_PATHS = frozenset({"/api", "/static", "/_vercel"})
_not_found_page_body: bytes | None = None


def _wants_not_found_page(request: Request) -> bool:
    """A GET/HEAD for a page URL, unless the client asks for JSON and not HTML."""
    path = request.url.path
    if request.method not in ("GET", "HEAD"):
        return False
    if path in _NOT_FOUND_JSON_PATHS or path.startswith(_NOT_FOUND_JSON_PREFIXES):
        return False
    accept = request.headers.get("accept", "").lower()
    return "text/html" in accept or "application/json" not in accept


def _not_found_page() -> bytes | None:
    global _not_found_page_body
    if _not_found_page_body is None:
        try:
            _not_found_page_body = NOT_FOUND_PAGE.read_bytes()
        except OSError:
            return None
    return _not_found_page_body


@app.exception_handler(StarletteHTTPException)
async def not_found_page(request: Request, exc: StarletteHTTPException):
    """Unknown page URLs get the HTML 404 page; everything else is unchanged.

    The security middleware adds the usual headers and CSP to this response.
    """
    if exc.status_code == 404 and _wants_not_found_page(request):
        body = _not_found_page()
        if body is not None:
            # A 404 page must not be cached as if it were the page asked for.
            return HTMLResponse(body, status_code=404, headers={"Cache-Control": "no-store"})
    return await http_exception_handler(request, exc)


@app.get("/health")
async def health():
    """Liveness/readiness probe for deployments and load balancers."""
    commit_sha = os.getenv("VERCEL_GIT_COMMIT_SHA", "")
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            **public_jev_status(app),
            "commit_sha": commit_sha.lower() if re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha) else None,
            "model_loaded": _content_pipeline is not None,
            "content_model_loaded": _content_pipeline is not None,
            "content_model_error": _content_model_error,
            "content_model_artifact_sha256": _content_model_artifact_sha256,
            "content_model_id": (
                f"sha256:{_content_model_artifact_sha256[:12]}"
                if _content_model_artifact_sha256 else None
            ),
            "model_data_source": (
                _content_pipeline.get("metrics", {}).get("data_source")
                if _content_pipeline is not None else None
            ),
            "sender_analysis_method": "sender-domain-heuristics",
            "sender_history_enabled": SETTINGS.sender_history_enabled,
            "sender_history_configured": SETTINGS.sender_history_ready,
            "sender_history_available": SETTINGS.sender_history_ready,
            "sender_history_error": SETTINGS.sender_history_config_error,
            "distributed_rate_limit_status": _rate_limit_store.status,
            "analysis_workers": ANALYSIS_WORKERS,
            "deployment_profile": SETTINGS.app_env,
            "email_verification_enabled": SETTINGS.domain_verification_enabled,
            "verification_mode": SETTINGS.effective_verification_mode,
            "domain_verification_enabled": SETTINGS.domain_verification_enabled,
            "smtp_verification_enabled": SETTINGS.smtp_verification_enabled,
            "verification_workers": VERIFICATION_WORKERS,
        },
    )


# ── API ───────────────────────────────────────────────────────────────────────
@app.get("/api/metrics")
async def get_metrics():
    payload = {
        "metrics": MODEL_METRICS,
        "benchmark_scope": "uci-phishing-websites-only",
        "benchmark_note": (
            "These historical notebook metrics describe the UCI Phishing Websites "
            "dataset and are not email-sender accuracy claims."
        ),
    }
    if _content_pipeline is not None:
        m = _content_pipeline["metrics"]
        payload["content_model"] = {
            "name": f"TF-IDF (word + char n-gram) + {m.get('model', 'classifier')}",
            "metrics":     m,
            "data_source": m.get("data_source", ""),
            "top_terms":   _content_pipeline["top_terms"],
            "artifact_sha256": _content_model_artifact_sha256,
            "model_id": (
                f"sha256:{_content_model_artifact_sha256[:12]}"
                if _content_model_artifact_sha256 else None
            ),
        }
    return JSONResponse(payload)


@app.get("/api/features")
async def get_features():
    return JSONResponse({"features": FEATURE_INFO})


@app.get("/api/config")
async def get_public_config():
    return JSONResponse({
        **public_jev_status(app),
        "deployment_profile": SETTINGS.app_env,
        "email_verification_enabled": SETTINGS.domain_verification_enabled,
        "verification_mode": SETTINGS.effective_verification_mode,
        "domain_verification_enabled": SETTINGS.domain_verification_enabled,
        "smtp_verification_enabled": SETTINGS.smtp_verification_enabled,
        "content_model_enabled": SETTINGS.content_model_enabled,
        "sender_history_enabled": SETTINGS.sender_history_enabled,
        "sender_history_configured": SETTINGS.sender_history_ready,
        "sender_history_available": SETTINGS.sender_history_ready,
        "feedback_enabled": (getattr(app.state, 'case_service', None) is not None
                             and not getattr(app.state, 'case_configuration_error', False)),
        "full_version_local_only": True,
        "enhanced_vision_enabled": ENHANCED_VISION.enabled,
        "enhanced_vision_semantics_enabled": ENHANCED_VISION.enabled and ENHANCED_VISION.semantics_enabled,
    })


class EmailRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=254)


def _analyze_sender_address(email: str) -> dict:
    """Return the shared explainable sender/domain heuristic result."""
    email = email.strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email address is required")

    (
        feature_dict,
        risk_indicators,
        is_disposable,
        is_suspected_disposable,
        disposable_service,
        disposable_classification,
    ) = extract_email_features(_normalize_sender_address(email))

    # The UCI model is a phishing-*website* benchmark. Its URL/HTML feature
    # weights are not valid probabilities for sender addresses, so this API
    # deliberately reports an explainable heuristic risk score instead.
    cols = FEATURE_NAMES
    feature_values = [feature_dict.get(name, 0) for name in cols]
    info_map = {f["name"]: f for f in FEATURE_INFO}
    feature_breakdown = []
    for name in cols:
        info = info_map.get(name, {"label": name, "email_desc": "", "group": ""})
        val = int(float(feature_dict.get(name, 0)))
        # Choose description that matches the current value direction
        if val == 1:
            desc = info.get("email_desc_pos") or info.get("email_desc", "")
        else:
            desc = info.get("email_desc", "")
        feature_breakdown.append({
            "name": name,
            "label": info["label"],
            "email_desc": desc,
            "group": info["group"],
            "value": val,
        })
    feature_breakdown.sort(key=lambda item: {-1: 0, 0: 1, 1: 2}[item["value"]])

    high_risks = sum(1 for r in risk_indicators if r["level"] == "high")
    med_risks = sum(1 for r in risk_indicators if r["level"] == "medium")
    phish_features = sum(1 for v in feature_values if v == -1)
    risk_score = _sender_risk_score(risk_indicators)
    if feature_dict.get("_brand_substitution_detected") is True:
        risk_score = max(risk_score, 60)
    verdict, label = _sender_verdict(risk_score)

    return {
        "email": email,
        "analysis_method": "sender-domain-heuristics",
        "verdict": verdict,
        "label": label,
        "risk_score": risk_score,
        "risk_indicators": risk_indicators,
        "high_risk_count": high_risks,
        "med_risk_count": med_risks,
        "phish_feature_count": phish_features,
        "feature_breakdown": feature_breakdown[:10],
        "is_disposable": is_disposable,
        "is_suspected_disposable": is_suspected_disposable,
        "disposable_service": disposable_service,
        **disposable_classification,
    }


def _sender_risk_score(risk_indicators: list[dict]) -> int:
    levels = [item["level"] for item in risk_indicators]
    return min(100, levels.count("high") * 28 + levels.count("medium") * 10 + levels.count("low") * 3)


def _sender_verdict(risk_score: int) -> tuple[str, str]:
    if risk_score >= 80:
        return "critical", "Critical Sender Risk"
    if risk_score >= 60:
        return "high", "High Sender Risk"
    if risk_score >= 30:
        return "medium", "Suspicious Sender"
    return "low", "Low Sender Risk"


# Address-shape findings an authenticated domain's owner chooses for itself. Anything
# about the registrable domain (brand, lookalike, keywords, TLD) is still scored.
_AUTHENTICATED_SENDER_RELAXED = frozenset({
    'sender.username_keywords', 'sender.random_username', 'sender.long_username',
    'sender.long_address', 'sender.unrecognized_provider', 'sender.deep_subdomains',
})
_RELAX_SUBDOMAIN_KEYWORDS = True
# Relax only when the display name names the authenticated organization, so "IT Support"
# or "monkey.org Portal" from an unrelated authenticated domain keeps its address findings.
_AUTHENTICATED_SENDER_NEEDS_NAME_MATCH = True


def _relax_authenticated_sender(analysis: dict, authenticated: dict) -> dict:
    """Show, but stop scoring, address-shape findings for a DMARC- and DKIM-authenticated domain."""
    registrable = authenticated["organizational_domain"].replace(".", "")
    original_score = analysis["risk_score"]
    brand_floor = original_score > _sender_risk_score(analysis["risk_indicators"])
    for item in analysis["risk_indicators"]:
        relaxed = item.get("code") in _AUTHENTICATED_SENDER_RELAXED or (
            _RELAX_SUBDOMAIN_KEYWORDS and item.get("code") == "sender.domain_keywords"
            and not any(keyword in registrable for keyword in SUSPICIOUS_KEYWORDS))
        if relaxed and item["level"] != "info":
            item["level"] = "info"
    risk_score = _sender_risk_score(analysis["risk_indicators"])
    if brand_floor:
        risk_score = max(risk_score, 60)
    if risk_score < original_score:
        analysis["risk_indicators"].append(indicator('info', 'sender.authenticated_domain',
                                                     domain=authenticated["domain"]))
    analysis["risk_score"] = risk_score
    analysis["verdict"], analysis["label"] = _sender_verdict(risk_score)
    analysis["high_risk_count"] = sum(1 for item in analysis["risk_indicators"] if item["level"] == "high")
    analysis["med_risk_count"] = sum(1 for item in analysis["risk_indicators"] if item["level"] == "medium")
    return analysis


def _sender_account_observability(analysis: dict) -> str:
    if analysis.get("disposable_status") in {
        "known_disposable_provider", "privacy_relay",
    }:
        return "not_applicable"
    normalized = _normalize_sender_address(str(analysis.get("email", "")))
    domain = normalized.rsplit("@", 1)[-1].lower() if normalized else ""
    if _match_domain_registry(domain, MAJOR_MAILBOX_PROVIDERS):
        return "provider_account_unverifiable"
    return "unknown"


async def _analyze_and_observe_sender(address: str, *, analysis: dict | None = None) -> dict:
    """Analyze one raw-message sender and record one retained observation."""
    if analysis is None:
        analysis = await _run_analysis(_analyze_sender_address, address)
    normalized_address = _normalize_sender_address(address)
    history_address = canonicalize_sender_address(normalized_address or address)
    history = await _sender_history_store.observe(history_address)
    analysis["account_observability"] = _sender_account_observability(analysis)
    analysis.update(history.as_dict())
    return analysis


def _analyze_sender_without_history_lookup(address: str) -> dict:
    """Analyze an address without exposing retained service-wide history."""
    analysis = _analyze_sender_address(address)
    analysis["account_observability"] = _sender_account_observability(analysis)
    analysis.update(SenderHistoryResult(status="raw_message_required").as_dict())
    return analysis


def _raw_sender_addresses(from_header: str) -> list[str]:
    """Return unique, plausible public-mailbox addr-specs from a From header."""
    addresses: list[str] = []
    seen: set[str] = set()
    for _display_name, parsed_address in getaddresses([from_header or ""]):
        normalized = _normalize_sender_address(parsed_address)
        if not normalized:
            continue
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            addresses.append(normalized)
    return addresses


def _undo_list_rewrite(address: str) -> tuple[str, bool]:
    """Strip the reserved ".invalid" suffix mailing lists append to DMARC-protected From domains.

    Such a domain can never exist (RFC 6761), so scoring it only produced unknown-TLD
    and unknown-provider noise. From is unauthenticated here, so scoring the underlying
    domain gives a sender nothing it could not get by writing that domain directly.
    """
    local, _, domain = address.rpartition('@')
    suffix = '.invalid'
    if domain.lower().endswith(suffix):
        stripped = _normalize_sender_address(local + '@' + domain[:-len(suffix)])
        if stripped:
            return stripped, True
    return address, False


def _select_message_sender(headers: list[str]) -> dict | None:
    """Score untrusted From candidates in a worker, preserving first-wins ties."""
    seen = set()
    selected = None
    for header in headers:
        for raw_address in _raw_sender_addresses(header):
            address, list_rewritten = _undo_list_rewrite(raw_address)
            canonical = canonicalize_sender_address(address)
            if canonical in seen:
                continue
            seen.add(canonical)
            analysis = _analyze_sender_address(address)
            if list_rewritten:
                analysis['risk_indicators'].append(indicator('info', 'sender.list_rewritten'))
            if selected is None or analysis['risk_score'] > selected['risk_score']:
                selected = analysis
    return selected


@app.post("/api/analyze-email")
async def analyze_email(request: EmailRequest):
    address = request.email.strip()
    if not _normalize_sender_address(address):
        raise HTTPException(
            status_code=400,
            detail="Enter a single email address, such as user@example.com. Use Email Content to analyze a message.",
        )
    return JSONResponse(_analyze_sender_without_history_lookup(address))


# ─────────────────────────────────────────────────────────────────────────────
# Email Content Analysis (heuristic rule-based, no ML model required)
# ─────────────────────────────────────────────────────────────────────────────

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

# (keyword, description); each description is the English template of a
# `safety.*` code in data/server_messages.json.
CONTENT_SAFETY_SIGNALS: list = [(keyword, message_text('safety.' + code)) for keyword, code in (
    ("unsubscribe", "unsubscribe"),
    ("privacy policy", "privacy_policy"),
    ("terms of service", "terms_of_service"),
    ("terms and conditions", "terms_and_conditions"),
    ("to stop receiving", "opt_out"),
    ("if you did not request", "not_requested"),
    ("if you didn't request", "not_requested"),
    ("contact us at", "contact_information"),
    ("© ", "copyright"),
    ("all rights reserved", "copyright"),
    ("sent from", "sender_system"),
    ("view in browser", "web_version"),
    ("manage preferences", "preferences"),
    ("update your preferences", "preferences"),
    ("you are receiving this", "receiving_reason"),
    ("you subscribed", "subscription_consent"),
    ("hello [name]", "named_greeting"),
    ("hi [name]", "greeting"),
)]

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


def _parse_link_target(destination: str, *, base: str | None = None):
    destination = re.sub(r'[\t\r\n]', '', destination.strip())
    destination = re.sub(r'^hxxp(s?)://', r'http\1://', destination, flags=re.IGNORECASE)
    scheme = re.match(r'^([a-z][a-z0-9+.-]*):', destination, re.IGNORECASE)
    if not scheme or scheme.group(1).lower() in {'http', 'https'}:
        # HTTP(S) uses backslashes as separators, but not inside query/fragment.
        # Normalize authority slashes BEFORE joining a base, otherwise urljoin
        # can turn an external host into an apparently same-origin path.
        pieces = re.split(r'([?#])', destination, maxsplit=1)
        pieces[0] = pieces[0].replace('\\', '/')
        destination = ''.join(pieces)
        if scheme:
            protocol = scheme.group(1).lower()
            rest = destination[scheme.end():]
            if not base or protocol != urlparse(base).scheme or rest.startswith('//'):
                destination = protocol + '://' + rest.lstrip('/')
        elif destination.startswith('//'):
            destination = '//' + destination.lstrip('/')
            if not base:
                destination = 'https:' + destination
    if (destination.startswith('//') or re.match(r'^https?://', destination, re.IGNORECASE)):
        if not urlparse(destination).hostname:
            raise ValueError('Explicit HTTP(S) authority has no host')
    if base:
        destination = urljoin(base, destination)
    parsed = urlparse(destination)
    if parsed.scheme in {'http', 'https'}:
        if not parsed.hostname:
            raise ValueError('HTTP(S) destination has no host')
        _ = parsed.port  # Validate ports as well as bracketed address syntax.
    return parsed


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


def _excessive_caps_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c.isupper()) / len(letters)


def _detect_obfuscation(text: str) -> list[str]:
    """Detect leetspeak / homoglyph substitution tricks (e.g. P@yP@l, Amaz0n)."""
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
    return found


def _keyword_matches(text: str, keyword: str) -> bool:
    """Match phrases while preventing short tokens from firing inside words."""
    escaped = re.escape(keyword)
    prefix = r"(?<!\w)" if keyword and keyword[0].isalnum() else ""
    # Python's word characters exclude apostrophes. Keep a negative contraction
    # together (won't is not won), while retaining possessives and quoted words.
    suffix = r"(?!\w|['’]t(?!\w))" if keyword and keyword[-1].isalnum() else ""
    return bool(re.search(prefix + escaped + suffix, text, re.IGNORECASE))


def _strip_invisible_format_controls(text: str) -> str:
    """Remove zero-width formatting controls commonly used to split keywords."""
    return "".join(character for character in text if unicodedata.category(character) != "Cf")


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


def _first_html_attributes(attrs):
    """Use HTML's first occurrence of each attribute, including empty values."""
    attributes = {}
    for name, value in attrs:
        attributes.setdefault(name, value)
    return attributes


class _AnalysisHTMLParser(HTMLParser):
    _marked_declaration = re.compile(r'<!\[([a-zA-Z][-_.a-zA-Z0-9]*)')
    _literal_elements = {'textarea', 'title', 'xmp'}
    CDATA_CONTENT_ELEMENTS = (*HTMLParser.CDATA_CONTENT_ELEMENTS, *_literal_elements)

    def set_cdata_mode(self, elem, *, escapable=False):
        # New CPython patch releases pass escapable here. Keep the base parser
        # in raw mode: handle_data owns the one-time RCDATA decoding below.
        # Omitting the keyword also supports older HTMLParser signatures.
        super().set_cdata_mode(elem)
        if elem in self._literal_elements:
            # Only the matching HTML end-tag name leaves RCDATA/RAWTEXT.
            # In particular, </textareax> and </ textarea> remain literal.
            self.interesting = re.compile(r'</' + elem + r'(?=[\t\n\f\r />])', re.I | re.ASCII)

    def parse_endtag(self, index):
        if self.cdata_elem in self._literal_elements:
            # End tags may have (ignored) attributes or a trailing slash. Keep
            # quoted '>' characters inside those attributes, including when
            # input arrives in separate feed() calls.
            ending = re.match(r'''</[a-z]+(?=[\t\n\f\r />])(?:[^'">]|"[^"]*"|'[^']*')*>''',
                              self.rawdata[index:], re.I | re.ASCII)
            if ending is None:
                return -1
            self.handle_endtag(self.cdata_elem)
            self.clear_cdata_mode()
            return index + ending.end()
        return super().parse_endtag(index)

    def handle_startendtag(self, tag, attrs):
        # A self-closing slash does not close a non-void HTML element.
        self.handle_starttag(tag, attrs)
        if tag in _HTML_VOID_ELEMENTS:
            self.handle_endtag(tag)
        elif tag in self.CDATA_CONTENT_ELEMENTS:
            self.set_cdata_mode(tag)

    def handle_data(self, data):
        # RCDATA decodes references once; RAWTEXT preserves them literally.
        # Collectors receive text tokens, never reparse them as nested markup.
        self.collect_data(unescape_html(data) if self.cdata_elem in {'textarea', 'title'} else data)

    def collect_data(self, data):
        pass

    def goahead(self, end):
        super().goahead(end)
        if end and self.cdata_elem in self._literal_elements and self.rawdata:
            # HTMLParser buffers unclosed CDATA even at EOF. A visible textarea
            # or xmp still has text in that case, so do not silently drop it.
            self.handle_data(self.rawdata)
            self.updatepos(0, len(self.rawdata))
            self.rawdata = ''

    def parse_html_declaration(self, index):
        # Recent CPython versions silently consume unknown marked declarations
        # as bogus comments. Detect them at the parser boundary, not by scanning
        # raw HTML (which would also match comments, attributes and scripts).
        if self.rawdata.startswith('<![', index):
            match = self._marked_declaration.match(self.rawdata, index)
            if not match or match.group(1).lower() not in {
                'temp', 'cdata', 'ignore', 'include', 'rcdata', 'if', 'else', 'endif',
            }:
                raise ValueError('Unrecognized HTML marked declaration')
        return super().parse_html_declaration(index)


_MSO_CONDITIONAL_WARNING = message_text('warning.mso_conditional')


# Private-use sentinels that bracket Outlook-only content (U+E000/U+E001) and content
# hidden from Outlook (U+E002/U+E003) in the rendering-view pass only.
_RENDERING_SENTINELS = re.compile('[\ue000-\ue003]')


def _expand_mso_comments(text: str, parse_warnings=None, *, mark=False, unresolved=None) -> str:
    """Expose one bounded layer of conditional markup to every HTML collector.

    Parse actual comment tokens, not comment-like strings in attributes/scripts.
    The expanded document is evidence only, not a verified client rendering.
    Nested or malformed branches retain the incomplete-analysis warning.
    With mark, Outlook-only and Outlook-hidden content is bracketed by sentinels,
    and a branch that cannot be bracketed is appended to unresolved.
    """
    if mark:
        text = _RENDERING_SENTINELS.sub('', text)
    comment_end = re.compile(r'--\s*>')
    offsets = [0]
    offsets.extend(match.end() for match in re.finditer(r'\n', text))

    class ConditionalComments(_AnalysisHTMLParser):
        def __init__(self):
            super().__init__()
            self.replacements = []
            self.hidden_from_outlook = 0

        def _span(self):
            line, column = self.getpos()
            start = offsets[line - 1] + column
            close = comment_end.search(text, start + 4)
            return start, close.end() if close else None

        def handle_comment(self, data):
            if mark and data.strip() == '<![endif]' and self.hidden_from_outlook:
                # Closes <!--[if !mso]><!--> ... : the content between was hidden from Outlook.
                self.hidden_from_outlook -= 1
                start, _end = self._span()
                self.replacements.append((start, start, '\ue003'))
                return
            opening = re.match(r'\[if\s+([^\]]+)\]>', data.strip(), re.IGNORECASE)
            if not opening or not re.search(r'\bmso\b', opening.group(1), re.IGNORECASE):
                return
            condition = re.sub(r'\s+', '', opening.group(1).casefold())
            if (condition.count('(') == condition.count(')')
                    and re.fullmatch(r'\(*(?:!|not)\(*mso\)*', condition)):
                if mark and re.fullmatch(r'\[if\s+[^\]]+\]><!', data.strip(), re.IGNORECASE):
                    _start, end = self._span()
                    if end is None:
                        unresolved.append('conditional')
                        return
                    self.hidden_from_outlook += 1
                    self.replacements.append((end, end, '\ue002'))
                return
            if parse_warnings is not None and _MSO_CONDITIONAL_WARNING not in parse_warnings:
                parse_warnings.append(_MSO_CONDITIONAL_WARNING)
            conditional = re.fullmatch(r'\[if\s+[^\]]+\]>(.*?)<!\[endif\]',
                                       data.strip(), flags=re.IGNORECASE | re.DOTALL)
            if not conditional:
                # <!--[if mso]><!--> content <!--<![endif]--> shows everywhere; any other
                # unexpanded branch leaves an Outlook view the text pass cannot see.
                if mark and not re.fullmatch(r'\[if\s+[^\]]+\]><!', data.strip(), re.IGNORECASE):
                    unresolved.append('conditional')
                return
            start, end = self._span()
            if end is not None:
                content = f'\ue000{conditional.group(1)}\ue001' if mark else conditional.group(1)
                self.replacements.append((start, end, content))
            elif mark:
                unresolved.append('conditional')

    scanner = ConditionalComments()
    scanner.feed(text)
    scanner.close()
    if mark and scanner.hidden_from_outlook:
        unresolved.append('conditional')
    parts = []
    cursor = 0
    for start, end, content in scanner.replacements:
        parts.extend((text[cursor:start], content))
        cursor = end
    parts.append(text[cursor:])
    return ''.join(parts)


def _collect_html(factory, text: str, parse_warnings=None, *, mark=False, unresolved=None):
    collector = factory()
    try:
        collector.feed(_expand_mso_comments(text, parse_warnings, mark=mark, unresolved=unresolved))
        collector.close()
    except (AssertionError, ValueError):
        warning = message_text('warning.malformed_html')
        if parse_warnings is not None and warning not in parse_warnings:
            parse_warnings.append(warning)
        if unresolved is not None:
            unresolved.append('malformed')
        # Neutralize broken marked declarations, then start fresh so partially
        # collected text/forms/links are neither duplicated nor allowed to hide
        # the rest of the document. Final fallback is literal text, not success.
        collector = factory()
        try:
            collector.feed(_expand_mso_comments(text.replace('<![', '&lt;!['), parse_warnings,
                                                mark=mark, unresolved=unresolved))
            collector.close()
        except (AssertionError, ValueError):
            collector = factory()
            collector.feed(escape_html(text))
            collector.close()
    return collector


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
                   visible_text: str | None = None) -> list[tuple[str, str]]:
    """Extract visible text and destination from Markdown and HTML links."""
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
                self.links.append((_visible_content_text(''.join(self.label_markup)), self.href))
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


def _analyze_link_destinations(text: str, *, links=None, parse_warnings=None) -> tuple[int, list[dict], str]:
    """Inspect actual link targets, including links with generic button text."""
    score = 0
    findings: list[dict] = []
    risk_floor = "safe"
    finding_types: set[str] = set()
    sensitive_host_terms = {
        "account", "credential", "login", "password", "reactivate",
        "secure", "security", "signin", "unlock", "verification", "verify",
        "wallet",
    }

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


_HIDDEN_HTML_TEXT_WARNING = message_text('warning.hidden_html_text')
_STYLESHEET_VISIBILITY_WARNING = message_text('warning.stylesheet_visibility')
_INLINE_CSS_VISIBILITY_WARNING = message_text('warning.inline_css_visibility')
_IMAGE_ALT_FALLBACK_WARNING = message_text('warning.image_alt_fallback')
_MIME_ALTERNATIVE_LIMIT_WARNING = message_text('warning.mime_alternative_limit')
_MIME_ALTERNATIVE_MODEL_WARNING = message_text('warning.mime_alternative_model')
_MAX_MIME_MODEL_VIEWS = 16
# Plausible renderings the model must agree on are every reading except 'hidden'
# (strict non-Outlook, strict Outlook, and one per @media context, media_N);
# definitely hidden text may only lift the abstention.
_HTML_VOID_ELEMENTS = {
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
    'param', 'source', 'track', 'wbr',
}
_P_IMPLIED_END_START_TAGS = {
    'address', 'article', 'aside', 'blockquote', 'details', 'dialog', 'div',
    'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2',
    'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'main', 'menu', 'nav',
    'ol', 'p', 'pre', 'search', 'section', 'table', 'ul',
}


def _inline_visibility(style: str) -> tuple[bool, bool | None, bool, bool]:
    """Read bounded visibility declarations, respecting !important."""
    # A semicolon inside quoted content, url(), or a CSS escape is not a
    # declaration boundary. Splitting it blindly can hide genuinely visible
    # text when an unrelated property contains the string "; display:none".
    declarations = []
    current = []
    quote = None
    depth = 0
    index = 0
    while index < len(style):
        character = style[index]
        following = style[index + 1] if index + 1 < len(style) else ''
        if quote:
            current.append(character)
            if character == '\\' and following:
                current.append(following)
                index += 1
            elif character == quote:
                quote = None
        elif character == '/' and following == '*':
            ending = style.find('*/', index + 2)
            if ending < 0:
                break
            index = ending + 1
        elif character == '\\' and following:
            current.extend((character, following))
            index += 1
        elif character in {'"', "'"}:
            quote = character
            current.append(character)
        elif character == '(':
            depth += 1
            current.append(character)
        elif character == ')':
            depth = max(0, depth - 1)
            current.append(character)
        elif character == ';' and depth == 0:
            declarations.append(''.join(current))
            current = []
        else:
            current.append(character)
        index += 1
    declarations.append(''.join(current))
    values = {}
    for declaration in declarations:
        name, separator, value = declaration.partition(':')
        name = _unescape_css(name).strip().lower()
        if not separator or name not in {'display', 'visibility', 'opacity', 'font-size', 'color'}:
            continue
        value = _unescape_css(value).strip().lower()
        important = bool(re.search(r'!\s*important\s*$', value))
        value = re.sub(r'!\s*important\s*$', '', value).strip()
        if name not in values or important or not values[name][1]:
            values[name] = (value, important)
    display_hidden = values.get('display', ('', False))[0] == 'none'
    visibility = values.get('visibility', ('', False))[0]
    if visibility in {'hidden', 'collapse'}:
        visibility_hidden = True
    elif visibility in {'visible', 'initial'}:
        visibility_hidden = False
    else:
        # inherit/unset/invalid values cannot clear a hidden parent.
        visibility_hidden = None
    opacity = values.get('opacity', ('', False))[0]
    # Zero opacity applies to the entire rendered subtree; children cannot
    # restore it with their own opacity declaration.
    opacity_number = opacity.removesuffix('%')
    opacity_hidden = bool(
        re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?', opacity_number)
        and float(opacity_number) <= 0
    ) or bool(re.fullmatch(r'calc\(\s*[+-]?0+(?:\.0+)?%?\s*\)', opacity))
    font_size = values.get('font-size', ('', False))[0]
    color = values.get('color', ('', False))[0]
    uncertain = bool(
        re.fullmatch(r'[+]?0+(?:\.0+)?(?:[a-z]+|%)?', font_size)
        or color == 'transparent'
        or re.fullmatch(r'(?:rgba|hsla)\([^)]*,\s*0+(?:\.0+)?\s*\)', color)
        or (opacity.startswith('calc(') and not opacity_hidden)
    )
    return display_hidden, visibility_hidden, opacity_hidden, uncertain


def _strip_css_comments(css: str) -> tuple[str, bool]:
    """Remove real comments while preserving comment-like text in CSS strings.

    Returns the text and whether every string was closed. content:"/*" opens no comment.
    """
    without_comments = []
    quote = None
    index = 0
    while index < len(css):
        character = css[index]
        following = css[index + 1] if index + 1 < len(css) else ''
        if quote:
            without_comments.append(character)
            if character == '\\' and following:
                without_comments.append(following)
                index += 1
            elif character == quote:
                quote = None
        elif character == '/' and following == '*':
            ending = css.find('*/', index + 2)
            if ending < 0:
                break
            index = ending + 1
        elif character in {'"', "'"}:
            quote = character
            without_comments.append(character)
        else:
            without_comments.append(character)
        index += 1
    return ''.join(without_comments), quote is None


def _stylesheet_may_hide_text(css: str) -> bool:
    """Flag hiding declarations without claiming to implement CSS cascade."""
    # Find balanced rule bodies outside quoted CSS strings. A brace in
    # content:"}" must not end the rule before its hiding declaration.
    cleaned, _complete = _strip_css_comments(css)
    depth = 0
    segment_start = 0
    quote = None
    index = 0
    while index < len(cleaned):
        character = cleaned[index]
        if character == '\\' and index + 1 < len(cleaned):
            index += 2
            continue
        if quote:
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == '{':
            if depth:
                display, visibility, opacity, uncertain = _inline_visibility(
                    cleaned[segment_start:index]
                )
                if display or visibility is True or opacity or uncertain:
                    return True
            depth += 1
            segment_start = index + 1
        elif character == '}' and depth:
            display, visibility, opacity, uncertain = _inline_visibility(
                cleaned[segment_start:index]
            )
            if display or visibility is True or opacity or uncertain:
                return True
            depth -= 1
            segment_start = index + 1
        index += 1
    return False


def _split_selectors(prelude: str) -> list[str] | None:
    """Top-level comma-separated selectors, or None for anything this reader does not model."""
    if '\\' in prelude:
        return None
    selectors, current, depth = [], [], 0
    for character in prelude:
        if character in '([':
            depth += 1
        elif character in ')]':
            depth -= 1
        if character == ',' and depth == 0:
            selectors.append(''.join(current).strip())
            current = []
        else:
            current.append(character)
    selectors.append(''.join(current).strip())
    return selectors if depth == 0 else None


def _hidden_selector_targets(selector: str):
    """Class names, ids and class-attribute fragments one of which a matched element must carry.

    Returns () for a selector that only styles generated content (::before), and None
    when any element could match (a bare tag, *, :not(), an attribute other than class/id).
    """
    # The subject is the last compound selector; combinators inside [] or () do not count.
    subject, depth = [], 0
    for character in selector.strip():
        depth += (character in '([') - (character in ')]')
        if depth == 0 and (character.isspace() or character in '>+~'):
            subject = []
        else:
            subject.append(character)
    subject = ''.join(subject)
    if not subject:
        return None
    if re.search(r'::|:(?:before|after|first-line|first-letter|marker|placeholder|selection)\b', subject, re.IGNORECASE):
        return ()
    subject = re.sub(r':not\([^)]*\)', '', subject, flags=re.IGNORECASE)
    fragments = re.findall(r'\[\s*class\s*[~|^$*]?=\s*([^\]\s]+)\s*\]', subject, re.IGNORECASE)
    ids = re.findall(r'\[\s*id\s*=\s*([^\]\s]+)\s*\]', subject, re.IGNORECASE)
    classes = re.findall(r'\.(-?[_a-zA-Z][\w-]*)', subject)
    ids += re.findall(r'#(-?[_a-zA-Z][\w-]*)', subject)
    if not (classes or ids or fragments):
        return None
    return ([('class', name.casefold()) for name in classes] + [('id', name.casefold()) for name in ids]
            + [('fragment', fragment.strip('"\'').casefold()) for fragment in fragments])


_MAX_RENDERING_CONTEXTS = 8


def _declares_shown(block: str) -> bool:
    """Whether declarations turn an element back on (display other than none, visibility:visible)."""
    return bool(re.search(r'(?:^|;)\s*(?:display\s*:\s*(?!none\b)[a-z-]+|visibility\s*:\s*visible\b)',
                          block.casefold()))


def _stylesheet_hidden_targets(css: str):
    """Which elements hiding rules can reach, and the views of the rendering contexts.

    Returns {"union": (classes, ids, class fragments), "views": [hidden tokens, ...]}
    or None if unmodelled. Marketing mail hides preheaders and mobile/desktop variants
    with class rules such as ".hide-mobile { display:none }", switched in @media blocks,
    so each @media context is its own view: the base rules' hidden targets, minus those
    it shows, plus those it hides. Views are empty when no context changes anything.
    Tag-only rules that show elements (td{display:block}) are not modelled: without
    !important they cannot override a class or id rule.
    """
    cleaned, complete = _strip_css_comments(css)
    if not complete:
        return None
    hidden, shown = {}, {}
    preludes, start, index = [], 0, 0
    quote = None
    while index < len(cleaned):
        character = cleaned[index]
        if character == '\\':
            index += 2
            continue
        if quote:
            if character == quote:
                quote = None
        elif character in {'"', "'"}:
            quote = character
        elif character == '{':
            prelude = cleaned[start:index].strip()
            if preludes and not preludes[-1].startswith('@') and ':' in prelude.split(';')[0]:
                return None  # nested declarations (CSS nesting) are not modelled
            preludes.append(prelude)
            start = index + 1
        elif character == '}' and preludes:
            prelude = preludes.pop()
            block = cleaned[start:index]
            display, visibility, opacity, uncertain = _inline_visibility(block)
            start = index + 1
            hides = display or visibility is True or opacity or uncertain
            if hides or _declares_shown(block):
                if prelude.startswith('@'):
                    if hides:
                        return None
                    index += 1
                    continue
                context = ' '.join(re.sub(r'\s+', ' ', item) for item in preludes if item.startswith('@'))
                for selector in _split_selectors(prelude) or [None]:
                    targets = None if selector is None else _hidden_selector_targets(selector)
                    if targets is None:
                        if hides:
                            return None
                        continue
                    (hidden if hides else shown).setdefault(context, set()).update(targets)
        index += 1
    union = set().union(*hidden.values()) if hidden else set()
    contexts = sorted((set(hidden) | set(shown)) - {''})
    if len(contexts) + 1 > _MAX_RENDERING_CONTEXTS:
        return None
    base = frozenset(hidden.get('', ()))
    views = ([base] + [frozenset((base - shown.get(context, set())) | hidden.get(context, set()))
                       for context in contexts]) if contexts else []
    return {
        "union": tuple(frozenset(name for kind, name in union if kind == wanted)
                       for wanted in ('class', 'id', 'fragment')),
        "views": list(dict.fromkeys(views)),
    }


def _visible_content_text(text: str, parse_warnings=None, *, structure_stats=None, readings=None) -> str:
    """Decode HTML text separately from destinations, preserving inline words."""
    class TextCollector(_AnalysisHTMLParser):
        head_elements = {'html', 'head', 'base', 'basefont', 'bgsound', 'link',
                         'meta', 'title', 'noscript', 'noframes', 'script', 'style', 'template'}

        def __init__(self, targets=None):
            super().__init__(convert_charrefs=True)
            # targets is set only in the rendering-view pass (see readings below).
            self.targets = targets
            self.strict_parts = []
            self.outlook_parts = []
            self.certain_parts = []
            self.view_hidden = targets["views"] if targets else []
            self.view_parts = [[] for _view in self.view_hidden]
            self.hidden_parts = []
            self.outlook_only = 0
            self.hidden_from_outlook = 0
            self.parts = []
            self.hidden = []
            self.elements = []
            self.excluded_hidden_text = False
            self.hidden_characters = 0
            self.linked_visible_images = 0
            self.stylesheet_parts = []
            self.conditional_image_alt = False
            self.uncertain_inline_style = False
            self.open_paragraph = False

        def _visually_hidden(self):
            return bool(self.elements and (self.elements[-1][1] or self.elements[-1][2]))

        def _emit(self, text, tokens=None):
            self.parts.append(text)
            if self.targets is None:
                return
            if tokens is None:
                tokens = self.elements[-1][5] if self.elements else frozenset()
            if not tokens:
                self.certain_parts.append(text)
                if not self.outlook_only:
                    self.strict_parts.append(text)
                if not self.hidden_from_outlook:
                    self.outlook_parts.append(text)
            # Each rendering context shows what none of its hiding rules reaches.
            if not self.outlook_only and '#inline' not in tokens:
                for parts, hidden in zip(self.view_parts, self.view_hidden):
                    if not tokens & hidden:
                        parts.append(text)

        def _targeted(self, attrs):
            classes, ids, fragments = self.targets["union"]
            values = dict(attrs)
            class_value = (values.get('class') or '').casefold()
            element_id = (values.get('id') or '').strip().casefold()
            return frozenset(
                {('class', name) for name in set(class_value.split()) & classes}
                | ({('id', element_id)} if element_id in ids else set())
                | {('fragment', fragment) for fragment in fragments if fragment in class_value})

        def _truncate_elements(self, index):
            if self.open_paragraph and any(item[0] == 'p' for item in self.elements[index:]):
                self.open_paragraph = False
            del self.elements[index:]

        def _implicitly_close(self, tag):
            if tag in {'td', 'th', 'tr'}:
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing == 'table':
                        break
                    if tag in {'td', 'th'} and existing == 'tr':
                        break
                    if existing in ({'td', 'th'} if tag in {'td', 'th'} else {'tr'}):
                        self._truncate_elements(index)
                        break
            if self.open_paragraph and tag in _P_IMPLIED_END_START_TAGS:
                for index in range(len(self.elements) - 1, -1, -1):
                    if self.elements[index][0] == 'p':
                        self._truncate_elements(index)
                        break
            if tag == 'li':
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing in {'ul', 'ol', 'menu'}:
                        break
                    if existing == 'li':
                        self._truncate_elements(index)
                        break
            if tag in {'dt', 'dd'}:
                for index in range(len(self.elements) - 1, -1, -1):
                    existing = self.elements[index][0]
                    if existing == 'dl':
                        break
                    if existing in {'dt', 'dd'}:
                        self._truncate_elements(index)
                        break

        def handle_starttag(self, tag, attrs):
            attrs = list(_first_html_attributes(attrs).items())
            # A head end tag is optional: body content implicitly closes it.
            # Do not do this inside title/script/style or inert template text.
            if self.hidden == ['head'] and tag not in self.head_elements:
                self.hidden.pop()
            if tag == 'head' and 'head' in self.hidden:
                return
            if tag in {'script', 'style', 'head', 'title', 'template', 'noframes'}:
                self.hidden.append(tag)
            if self.hidden:
                return
            self._implicitly_close(tag)
            if tag == 'a':
                # HTML closes a prior anchor when another anchor starts. Do not
                # inherit an old HTTP action through a nested mailto/fragment link.
                self.elements = [(*element[:4], False, *element[5:]) if element[0] == 'a' else element
                                 for element in self.elements]
            # Browsers retain the first duplicate attribute, not the last.
            style = next((value for name, value in attrs if name == 'style'), '')
            display_hidden, visibility_hidden, opacity_hidden, uncertain_style = _inline_visibility(style or '')
            parent_display = self.elements[-1][1] if self.elements else False
            parent_visibility = self.elements[-1][2] if self.elements else False
            element_display = (parent_display or any(name == 'hidden' for name, _ in attrs)
                               or display_hidden or opacity_hidden)
            element_visibility = parent_visibility if visibility_hidden is None else visibility_hidden
            if uncertain_style and not (element_display or element_visibility):
                self.uncertain_inline_style = True
            # Hiding targets that can reach this element, inherited from its ancestors;
            # '#inline' marks a zero-size or transparent inline style.
            element_tokens = frozenset() if self.targets is None else (
                (self.elements[-1][5] if self.elements else frozenset()) | self._targeted(attrs)
                | ({'#inline'} if uncertain_style else frozenset()))
            if tag == 'source' and any(name == 'srcset' and value and value.strip()
                                       for name, value in attrs):
                for index in range(len(self.elements) - 1, -1, -1):
                    if self.elements[index][0] == 'picture':
                        picture = self.elements[index]
                        self.elements[index] = (*picture[:3], True, *picture[4:])
                        break
            if (tag == 'img' and not element_display and not element_visibility
                    and any(element[4] for element in self.elements)
                    and any(name in {'src', 'srcset'} and value and value.strip() for name, value in attrs)):
                self.linked_visible_images += 1
            if tag == 'img':
                alt = next((value for name, value in attrs if name == 'alt'), '') or ''
                if alt.strip():
                    if element_display or element_visibility:
                        self.excluded_hidden_text = True
                        self.hidden_parts.append(alt)
                    elif (not any(name in {'src', 'srcset'} and value and value.strip()
                                  for name, value in attrs)
                          and not any(element[0] == 'picture' and element[3]
                                      for element in self.elements)):
                        # With no image resource, HTML's replacement text is
                        # the text the reader can see or hear.
                        for piece in (' ', alt, ' '):
                            self._emit(piece, element_tokens)
                    else:
                        # A two-word decorative label such as "Company logo"
                        # should not disable scoring of an otherwise text-rich
                        # email. Longer fallback instructions may change what a
                        # reader sees when images fail or are blocked.
                        self.conditional_image_alt |= (
                            bool(re.search(
                                r'\b(?:enter|provide|send|share|submit|type|verify|confirm|reset|update)\s+'
                                r'(?:(?:your|the|a)\s+)?(?:password|passcode|otp|one-time password|'
                                r'credit card number|account)\b', alt, re.IGNORECASE,
                            ))
                            or (sum(not char.isspace() for char in alt) >= 12
                                and (len(re.findall(r'\w+', alt, flags=re.UNICODE)) >= 3
                                     or bool(non_latin_script_segments(alt, 12))))
                        )
            if tag not in _HTML_VOID_ELEMENTS:
                href = dict(attrs).get('href') or ''
                actionable_anchor = False
                if tag == 'a' and re.sub(r'[\t\r\n]', '', href).strip().lower().startswith(('http://', 'https://')):
                    try:
                        target = _parse_link_target(href)
                        actionable_anchor = target.scheme.lower() in {'http', 'https'} and bool(target.hostname)
                    except ValueError:
                        pass
                self.elements.append((tag, element_display, element_visibility, False, actionable_anchor,
                                      element_tokens))
                if tag == 'p':
                    self.open_paragraph = True
            if not element_display and not element_visibility and tag in {'p', 'div', 'br', 'li', 'tr', 'td', 'hr', 'section'}:
                self._emit(' ', element_tokens)

        def handle_endtag(self, tag):
            if self.hidden == ['head'] and tag in {'body', 'html', 'br'}:
                self.hidden.pop()
            if self.hidden and tag == self.hidden[-1]:
                self.hidden.pop()
                return
            for index in range(len(self.elements) - 1, -1, -1):
                if self.elements[index][0] == tag:
                    self._truncate_elements(index)
                    break
            if not self.hidden and not self._visually_hidden() and tag in {'p', 'div', 'li', 'tr', 'td', 'section'}:
                self._emit(' ')

        def collect_data(self, data):
            if self.targets is not None and _RENDERING_SENTINELS.search(data):
                for piece in re.split('([\ue000-\ue003])', data):
                    if piece in {'\ue000', '\ue001'}:
                        self.outlook_only = max(0, self.outlook_only + (1 if piece == '\ue000' else -1))
                    elif piece in {'\ue002', '\ue003'}:
                        self.hidden_from_outlook = max(0, self.hidden_from_outlook + (1 if piece == '\ue002' else -1))
                    elif piece:
                        self._collect_text(piece)
                return
            self._collect_text(data)

        def _collect_text(self, data):
            if self.hidden == ['head'] and data.strip():
                self.hidden.pop()
            if self.hidden:
                if self.hidden[-1] == 'style' and 'template' not in self.hidden[:-1]:
                    self.stylesheet_parts.append(data)
                return
            if self._visually_hidden():
                self.hidden_characters += sum(not char.isspace() for char in _strip_invisible_format_controls(data))
                if data.strip():
                    self.excluded_hidden_text = True
                    self.hidden_parts.append(data)
            else:
                self._emit(data)

    collector = _collect_html(TextCollector, text, parse_warnings)
    if collector.excluded_hidden_text and parse_warnings is not None:
        parse_warnings.append(_HIDDEN_HTML_TEXT_WARNING)
    if parse_warnings is not None and _stylesheet_may_hide_text(''.join(collector.stylesheet_parts)):
        parse_warnings.append(_STYLESHEET_VISIBILITY_WARNING)
    if collector.uncertain_inline_style and parse_warnings is not None:
        parse_warnings.append(_INLINE_CSS_VISIBILITY_WARNING)
    if collector.conditional_image_alt and parse_warnings is not None:
        parse_warnings.append(_IMAGE_ALT_FALLBACK_WARNING)
    visible = re.sub(r'\s+', ' ', ''.join(collector.parts)).strip()
    if readings is not None:
        # Other plausible renderings, for the model to check that uncertain text cannot
        # change its answer: the strictest non-Outlook and Outlook views (without text a
        # stylesheet or zero-size/transparent style may hide), and the visible text plus
        # definitely hidden text. None of them replaces the visible text. Image fallback
        # text stays unresolved: a short instruction such as "Enter password" is beyond
        # the model's judgement.
        stylesheet = ''.join(collector.stylesheet_parts)
        uncertain = (collector.uncertain_inline_style or collector.conditional_image_alt
                     or collector.excluded_hidden_text or _stylesheet_may_hide_text(stylesheet)
                     or (parse_warnings is not None and _MSO_CONDITIONAL_WARNING in parse_warnings))
        if uncertain:
            targets = _stylesheet_hidden_targets(stylesheet)
            unresolved = []
            if targets is not None:
                views = _collect_html(lambda: TextCollector(targets), text, [], mark=True, unresolved=unresolved)
            readings['resolved'] = targets is not None and not unresolved and not collector.conditional_image_alt

            def joined(parts):
                return re.sub(r'\s+', ' ', ''.join(parts)).strip()
            if targets is not None and 'malformed' not in unresolved:
                # Text rules may read what no style can hide, and what each @media
                # context shows, even where the model's renderings stay unresolved
                # (image fallbacks, odd conditional comments).
                readings['certain'] = joined(views.certain_parts)
                readings['media'] = [joined(parts) for parts in views.view_parts]
            if readings['resolved']:
                readings.update(strict=joined(views.strict_parts), outlook=joined(views.outlook_parts),
                                hidden=joined([visible, ' ', *collector.hidden_parts]))
                readings.update({f'media_{index}': text for index, text in enumerate(readings['media'])})
    if structure_stats is not None:
        structure_stats.update(hidden_characters=collector.hidden_characters,
                               visible_characters=sum(not char.isspace() for char in _strip_invisible_format_controls(visible)),
                               linked_visible_images=collector.linked_visible_images)
    return visible


_INLINE_IMAGE_WARNING = message_text('warning.inline_images')
_REMOTE_IMAGE_WARNING = message_text('warning.remote_images')
_UNRESOLVED_IMAGE_WARNING = message_text('warning.unresolved_images')
_HAN_TEXT_WARNING = message_text('warning.han_text')
_REMOTE_IMAGE_MIN_VISIBLE_CHARS = 80


def _unescape_css(value: str) -> str:
    value = re.sub(r'\\(?:\r\n|[\n\r\f])', '', value)
    def replacement(match):
        if match.group(1):
            codepoint = int(match.group(1), 16)
            return chr(codepoint) if 0 < codepoint <= 0x10ffff else '\ufffd'
        return match.group(2)

    return re.sub(r'\\(?:([0-9a-fA-F]{1,6})(?:[ \t\n\r\f])?|([^\n\r\f]))',
                  replacement, value)


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
    r"recogni[sz]e|request)|unauthori[sz]ed|if\s+(?:this|it)\s+wasn['’]t\s+you|if\s+you\s+did(?:n['’]t|\s+not)"
    r"|dispute|(?:has|have)\s+been\s+(?:charged|debited|auto[\s-]?renewed|renewed)|will\s+be\s+(?:charged|debited)"
    r"|auto[\s-]?renew(?:al|ed)?|cancel\s+(?:(?:this|the|your|my)\s+)?(?:order|subscription|renewal|charge|payment|"
    r"transaction|membership|plan|purchase))\b"
    r"|扣款|扣费|自动续费|不是本人|非本人|未授权|取消(?:该|此|这笔)?(?:订单|订阅|服务|扣费|续费|交易)", re.IGNORECASE)
_CALLBACK_CALL = re.compile(r"\b(?:call|dial|phone|ring|reach|contact|helpline|toll[\s-]?free|support\s+(?:line|number))\b"
                            r"|致电|拨打|来电|联系客服|客服电话|热线", re.IGNORECASE)


def _callback_request(text: str, official_numbers=frozenset()) -> str | None:
    """A phone number asked to be called, with dispute/cancel/refund framing within ~200 characters.

    Numbers published as an organization's official service numbers never count.
    """
    for match in _CALLBACK_PHONE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) < 7 or digits in official_numbers or digits.lstrip("1") in official_numbers:
            continue
        window = text[max(0, match.start() - 200):match.end() + 200]
        if _CALLBACK_CALL.search(window) and _CALLBACK_TRIGGER.search(window):
            return match.group(0).strip()
    return None


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
        style.append(indicator("medium", "content.exclamation_marks", count=excl))

    # 5. Excessive capitalization
    caps_ratio = _excessive_caps_ratio(full_orig)
    if caps_ratio > 0.40 and len(full_orig) > 60:
        score += 1
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
            "floor": floor, "requests": requests, "style": style, "wording": wording}


def analyze_email_content(subject: str, body: str, *, content_parts: list[dict] | None = None,
                          _model_view: dict | None = None) -> dict:
    """Rule-based heuristic phishing analysis of email subject + body text."""
    analysis_warnings = []

    hidden_image_padding = []

    def visible_html(part):
        part_warnings = []
        stats = {}
        readings = {}
        visible = _visible_content_text(part, part_warnings, structure_stats=stats, readings=readings)
        # Require a large explicitly concealed block and an actionable image in
        # this same HTML document. Short preheaders and text-rich mail do not qualify.
        hidden_image_padding.append(
            stats['hidden_characters'] >= 500
            and stats['visible_characters'] < _REMOTE_IMAGE_MIN_VISIBLE_CHARS
            and stats['hidden_characters'] >= 10 * max(stats['visible_characters'], 1)
            and stats['linked_visible_images'] > 0
            and not any(warning in part_warnings for warning in (
                _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
                _MSO_CONDITIONAL_WARNING))
            and not any('malformed' in warning.lower() or 'recovery' in warning.lower()
                        for warning in part_warnings))
        analysis_warnings.extend(part_warnings)
        stylesheet_uncertain = any(warning in part_warnings for warning in (
            _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
        ))
        # With every uncertain element located, the model can score each plausible
        # rendering instead of abstaining (see _agreeing_model_views).
        model_uncertain = stylesheet_uncertain or any(warning in part_warnings for warning in (
            _IMAGE_ALT_FALLBACK_WARNING, _MSO_CONDITIONAL_WARNING,
        ))
        resolved = bool(readings.get('resolved'))
        return (visible, stylesheet_uncertain, model_uncertain and not resolved,
                {key: value for key, value in readings.items() if isinstance(value, str) and key != 'certain'}
                if resolved else {},
                model_uncertain and resolved, readings.get('certain'), readings.get('media') or [])

    if content_parts is None:
        raw_parts = [subject, body]
        html_parts = [False, True]
        parsed_parts = [(subject, False, False, {}, False, None, []), visible_html(body)]
        visible_parts = [parsed[0] for parsed in parsed_parts]
        stylesheet_uncertain_parts = [parsed[1] for parsed in parsed_parts]
        model_uncertain_parts = [parsed[2] for parsed in parsed_parts]
        reading_parts = [parsed[3] for parsed in parsed_parts]
        resolved_parts = [parsed[4] for parsed in parsed_parts]
        certain_parts = [parsed[5] for parsed in parsed_parts]
        media_parts = [parsed[6] for parsed in parsed_parts]
    else:
        # Each MIME part is its own document. Plain text must not be interpreted
        # as markup, nor may an unclosed tag in one part hide another part.
        raw_parts = [subject] + [part['content'] for part in content_parts]
        html_parts = [False] + [part['content_type'] == 'text/html' for part in content_parts]
        parsed_parts = [visible_html(part['content']) if part['content_type'] == 'text/html'
                        else (part['content'], False, False, {}, False, None, []) for part in content_parts]
        visible_parts = [subject] + [parsed[0] for parsed in parsed_parts]
        stylesheet_uncertain_parts = [False] + [parsed[1] for parsed in parsed_parts]
        model_uncertain_parts = [False] + [parsed[2] for parsed in parsed_parts]
        reading_parts = [{}] + [parsed[3] for parsed in parsed_parts]
        resolved_parts = [False] + [parsed[4] for parsed in parsed_parts]
        certain_parts = [None] + [parsed[5] for parsed in parsed_parts]
        media_parts = [[]] + [parsed[6] for parsed in parsed_parts]
    raw_parts = [_strip_invisible_format_controls(part) for part in raw_parts]
    if _model_view is not None:
        # The model and rule checks consume the same MIME-aware visible text.
        def normalized(part):
            return re.sub(r'\s+', ' ', _strip_invisible_format_controls(part)).strip()
        model_parts = [normalized(part) for part in visible_parts]
        reading_texts = [{key: normalized(text) for key, text in readings.items()} for readings in reading_parts]
        reading_keys = sorted(set().union(*reading_texts))

        def view_readings(included):
            views = {}
            for key in reading_keys:
                if any(key in texts for texts, use in zip(reading_texts[1:], included) if use):
                    views[key] = '\n'.join(texts.get(key, model) for model, texts, use
                                           in zip(model_parts[1:], reading_texts[1:], included) if use).strip()
            return views
        _model_view['subject'] = model_parts[0]
        _model_view['body'] = '\n'.join(model_parts[1:]).strip()
        _model_view['mime_views'] = [(_model_view['body'], any(model_uncertain_parts[1:]))]
        _model_view['view_readings'] = {_model_view['body']: [view_readings([True] * (len(model_parts) - 1))]}
        # Views the model could not score before rendering views existed.
        _model_view['resolved_views'] = {_model_view['body']} if any(resolved_parts[1:]) else set()
        if content_parts is not None:
            choices = {}
            for part in content_parts:
                for path in part.get('alternative_paths', [()]):
                    for group, branch in path:
                        choices.setdefault(group, set()).add(branch)
            if choices:
                groups = sorted(choices)
                views = {}
                defaults = tuple(min(choices[group]) for group in groups)
                combinations = 1
                for group in groups:
                    combinations *= len(choices[group])
                    if combinations > _MAX_MIME_MODEL_VIEWS:
                        _model_view['mime_alternatives_truncated'] = True
                        break
                # Cover a leaf from each branch before spending the remaining
                # budget on Cartesian combinations. Nested decoys must not
                # starve a later, shallower phishing alternative.
                paths = {tuple(path) for part in content_parts
                         for path in part.get('alternative_paths', [()])}
                assignments = [defaults]
                for path in sorted(paths, key=lambda item: (len(item), item)):
                    selected = dict(zip(groups, defaults))
                    selected.update(path)
                    branches = tuple(selected[group] for group in groups)
                    if branches not in assignments:
                        assignments.append(branches)
                    if len(assignments) == _MAX_MIME_MODEL_VIEWS:
                        break
                if len(assignments) < _MAX_MIME_MODEL_VIEWS:
                    for branches in product(*(sorted(choices[group]) for group in groups)):
                        if branches not in assignments:
                            assignments.append(branches)
                        if len(assignments) == _MAX_MIME_MODEL_VIEWS:
                            break
                readings_by_view = {}
                earlier_uncertain = {}
                for branches in assignments:
                    selected = dict(zip(groups, branches))
                    included = [
                        any(all(selected[group] == branch for group, branch in path)
                            for path in part.get('alternative_paths', [()]))
                        for part in content_parts
                    ]
                    body_view = '\n'.join(text for text, use in zip(model_parts[1:], included)
                                          if use).strip()
                    uncertain = any(use and part_uncertain for use, part_uncertain
                                    in zip(included, model_uncertain_parts[1:]))
                    # Identical visible text is safe to score if any MIME path
                    # reaches it without uncertain rendering.
                    views[body_view] = views.get(body_view, True) and uncertain
                    readings_by_view.setdefault(body_view, []).append(view_readings(included))
                    # As above, but with resolved parts still counted as uncertain.
                    earlier_uncertain[body_view] = earlier_uncertain.get(body_view, True) and any(
                        use and (part_uncertain or part_resolved) for use, part_uncertain, part_resolved
                        in zip(included, model_uncertain_parts[1:], resolved_parts[1:]))
                _model_view['mime_views'] = list(views.items())
                _model_view['view_readings'] = readings_by_view
                _model_view['resolved_views'] = {body for body, uncertain in earlier_uncertain.items() if uncertain}
    html_image_parts = [(part, visible) for part, visible, is_html
                        in zip(raw_parts[1:], visible_parts[1:], html_parts[1:]) if is_html]
    image_counts = [_image_reference_counts(part, analysis_warnings)
                    for part, _visible in html_image_parts]
    image_count = min(20, sum(counts[0] for counts in image_counts))
    remote_image_count = min(20, sum(counts[1] for counts in image_counts))
    unresolved_image_count = min(20, sum(counts[2] for counts in image_counts))
    if _model_view is not None:
        _model_view['remote_image_dominant'] = any(
            counts[1] > 0 and sum(not char.isspace() for char in _strip_invisible_format_controls(visible))
            < _REMOTE_IMAGE_MIN_VISIBLE_CHARS
            for counts, (_part, visible) in zip(image_counts, html_image_parts)
        )
    if image_count:
        analysis_warnings.append(_INLINE_IMAGE_WARNING)
    if remote_image_count:
        analysis_warnings.append(_REMOTE_IMAGE_WARNING)
    if unresolved_image_count:
        analysis_warnings.append(_UNRESOLVED_IMAGE_WARNING)
    url_parts = [_mask_inline_data_payloads(part) if is_html else part
                 for part, is_html in zip(raw_parts, html_parts)]
    raw_text = '\n'.join(url_parts)
    links = []
    for part, visible, is_html, stylesheet_uncertain in zip(
        url_parts, visible_parts, html_parts, stylesheet_uncertain_parts,
    ):
        part_links = _extract_links(
            part, parse_html=is_html, parse_warnings=analysis_warnings,
            visible_text=('' if stylesheet_uncertain else _strip_invisible_format_controls(visible))
            if is_html else None,
        )
        # Explicit destinations remain actionable. Without a CSS renderer,
        # neither naked HTML URLs nor displayed anchor labels are reliable.
        links.extend((('', destination) for _label, destination in part_links)
                     if is_html and stylesheet_uncertain else part_links)
    # CSS may hide arbitrary body text. Do not derive high phishing scores from
    # prose that might be hidden; independent destination/form checks still run.
    # Where every hiding rule's targets are known, the text no style can hide is scored,
    # and so is the text each @media context shows; the riskiest reading counts.
    scored_parts = [visible if not uncertain else (certain or '') for visible, uncertain, certain
                    in zip(visible_parts, stylesheet_uncertain_parts, certain_parts)]
    readings_for_rules = [scored_parts] + [
        [media[index] if uncertain and index < len(media) else scored
         for scored, uncertain, media in zip(scored_parts, stylesheet_uncertain_parts, media_parts)]
        for index in range(max((len(media) for media in media_parts), default=0))]
    base_text = _strip_invisible_format_controls(re.sub(r'\s+', ' ', '\n'.join(scored_parts)).strip())
    if _has_substantial_han_text(base_text):
        analysis_warnings.append(_HAN_TEXT_WARNING)
    floor_rank = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    rules = max((_text_rule_findings(re.sub(r'\s+', ' ', '\n'.join(parts)).strip()) for parts in readings_for_rules),
                key=lambda found: (floor_rank[found['floor']], found['score']))
    analysis_text = rules['analysis_text']
    full_lower = analysis_text.lower()
    category_results = rules['categories']
    total_score = rules['score']
    risk_floor = rules['floor']

    extra_indicators = []

    if any(hidden_image_padding):
        total_score += 4
        risk_floor = max((risk_floor, 'medium'), key=floor_rank.get)
        extra_indicators.append(indicator('medium', 'content.hidden_text_padding'))

    if any(_has_password_form(part, analysis_warnings) for part, is_html in zip(raw_parts, html_parts) if is_html):
        total_score += 4
        risk_floor = max((risk_floor, 'medium'), key=floor_rank.get)
        extra_indicators.append(indicator('medium', 'content.password_form'))

    extra_indicators.extend(rules['requests'])

    # ── Structural & heuristic checks ────────────────────────────────────────

    # 2. URL shorteners
    if _has_shortener_url(raw_text, links=links):
        total_score += 2
        extra_indicators.append(indicator("high", "content.shortened_urls"))

    # 3. Inspect every actual link target, even when its visible text is a
    # generic button such as "Review document".
    link_score, link_findings, link_floor = _analyze_link_destinations(
        raw_text, links=links, parse_warnings=analysis_warnings)
    total_score += link_score
    extra_indicators.extend(link_findings)
    risk_floor = max((risk_floor, link_floor), key=floor_rank.get)

    extra_indicators.extend(rules['style'])

    # 6. Excessive question marks in subject
    subj_q = scored_parts[0].count("?")
    if subj_q >= 2:
        total_score += 1
        extra_indicators.append(indicator("medium", "content.subject_question_marks", count=subj_q))

    # 7. High URL count
    url_count = _count_urls(links)
    if url_count > 6:
        total_score += 1
        extra_indicators.append(indicator("medium", "content.url_count", count=url_count))

    extra_indicators.extend(rules['wording'])

    # Cosmetic legitimacy signals are context only. Attackers can copy these
    # strings, so they must never lower the risk score by themselves.
    safety_found = [
        desc for (kw, desc) in CONTENT_SAFETY_SIGNALS if kw.lower() in full_lower
    ]

    if total_score > 15:
        risk_level, risk_label = "critical", "Critical Risk — Very Likely Phishing"
    elif risk_floor == "high":
        risk_level, risk_label = "high", "High Risk — Likely Phishing"
    elif risk_floor == "medium" and total_score <= 8:
        risk_level, risk_label = "medium", "Medium Risk — Suspicious Content"
    elif total_score == 0:
        risk_level, risk_label = "safe",     "No Phishing Indicators Found"
    elif total_score <= 3:
        risk_level, risk_label = "low",      "Low Risk — Minor Concerns"
    elif total_score <= 8:
        risk_level, risk_label = "medium",   "Medium Risk — Suspicious Content"
    else:
        risk_level, risk_label = "high",     "High Risk — Likely Phishing"

    extra_indicators.extend(warning_indicator(warning) for warning in analysis_warnings)
    return {
        "analysis_warnings": analysis_warnings,
        "inline_image_coverage": {
            "count": image_count,
            "inspection_status": "metadata_only" if image_count else "not_applicable",
        },
        "remote_image_coverage": {
            "count": remote_image_count,
            "inspection_status": "metadata_only" if remote_image_count else "not_applicable",
        },
        "unresolved_image_coverage": {
            "count": unresolved_image_count,
            "inspection_status": "metadata_only" if unresolved_image_count else "not_applicable",
        },
        "risk_level":        risk_level,
        "risk_label":        risk_label,
        "total_score":       total_score,
        "category_results":  category_results,
        "extra_indicators":  extra_indicators,
        "safety_signals":    safety_found,
        "url_count":         url_count,
        "has_ip_url":        _has_ip_url(raw_text, links=links),
        "has_shortener":     _has_shortener_url(raw_text, links=links),
        "risk_floor":        risk_floor,
    }


class ContentRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=50_000)
    raw_email: str = Field(default="", max_length=60_000)


def fuse_content_risk(
    *,
    ml_phishing_probability: float | None,
    ml_decision_threshold: float,
    heuristic_score: int,
    minimum_level: str = "safe",
) -> dict:
    """Conservatively fuse independent evidence without averaging it away."""
    heuristic_risk = min(1.0, max(0.0, heuristic_score / 16.0))
    ml_risk = 0.0 if ml_phishing_probability is None else min(
        1.0, max(0.0, ml_phishing_probability)
    )
    floor_scores = {
        "safe": 0.0,
        "low": 0.10,
        "medium": 0.30,
        "high": 0.55,
        "critical": 0.80,
    }
    floor_score = max(floor_scores.get(minimum_level, 0.0), 0.10 if heuristic_score > 0 else 0.0)
    combined = max(heuristic_risk, ml_risk, floor_score)
    model_signal = ml_phishing_probability is not None and ml_risk >= ml_decision_threshold
    # A high model score alone is not enough to justify a Critical label.
    independent_support = heuristic_score >= 9 or minimum_level in {"high", "critical"}
    model_only = model_signal and heuristic_score == 0 and minimum_level == "safe"
    model_led = model_signal and not independent_support and not model_only

    if minimum_level == "critical" or heuristic_risk >= 0.80 or (ml_risk >= 0.80 and independent_support):
        level, label = "critical", "Critical Risk — Very Likely Phishing"
    elif minimum_level == "high" or heuristic_risk >= 0.55 or (model_signal and not model_only):
        level = "high"
        label = "High Risk — Model Signal Needs Review" if model_led else "High Risk — Likely Phishing"
    elif model_only:
        # With no rule, sender, link or structure evidence the text model alone flags
        # 72% of real 2023 account and security notices (docs/evaluation.md), so an
        # uncorroborated score stays an alert for review but not a High verdict.
        level, label = "medium", "Medium Risk — Model Signal Needs Review"
    elif combined >= 0.30:
        level, label = "medium", "Medium Risk — Suspicious Content"
    elif combined >= 0.10:
        level, label = "low", "Low Risk — Minor Concerns"
    else:
        level, label = "safe", "No Phishing Indicators Found"
    return {
        "combined_phishing_score": round(combined * 100, 1),
        "risk_level": level,
        "risk_label": label,
        "fusion_method": "conservative-evidence-max",
        "fusion_basis": ("model_only" if model_only else "model_led" if model_led else
                         "corroborated" if model_signal and independent_support else "other"),
    }


def _model_choice(predictions, threshold):
    """The highest scored MIME view, or an unverified-rendering result when none could be used."""
    scored = [prediction for prediction in predictions if prediction['_phishing_probability'] is not None]
    if scored:
        return max(scored, key=lambda prediction: prediction['_phishing_probability'])
    if predictions:
        return predictions[0]
    return {'ml_status': 'unverified_rendering', '_phishing_probability': None,
            'ml_phishing_probability': None, 'ml_legitimate_probability': None, 'ml_label': None,
            'ml_prediction': None, 'ml_decision_threshold': round(threshold * 100, 1), 'ml_top_contributors': []}


def _agreeing_model_views(bodies, view_readings, predictions, *, threshold, heuristic_score, minimum_level):
    """Keep the MIME views whose plausible renderings all lead to the same decision.

    The decision is whether the fused result alerts (Medium or above). Each kept
    (body, prediction) is scored at its highest-risk rendering. A view whose renderings disagree is
    dropped, so text that may be hidden can neither dilute a phishing message nor
    pad a benign one into an alert. Returns the kept predictions, whether every view
    was checked this way, and whether adding definitely hidden text (excluded from
    every rendering) would also leave each decision unchanged.
    """
    def level(prediction):
        probability = prediction['_phishing_probability']
        return None if probability is None else fuse_content_risk(
            ml_phishing_probability=probability, ml_decision_threshold=threshold,
            heuristic_score=heuristic_score, minimum_level=minimum_level,
        )['risk_level'] in {'medium', 'high', 'critical'}
    kept, resolved, hidden_agrees = [], True, True
    for body in bodies:
        base = predictions[body]
        renderings = [predictions[text] for view in view_readings.get(body, ())
                      for key, text in view.items() if key != 'hidden']
        if level(base) is None:
            kept.append((body, base))
            resolved = False
            continue
        if len({level(prediction) for prediction in (base, *renderings)}) > 1:
            resolved = False
            continue
        kept.append((body, max((base, *renderings), key=lambda prediction: prediction['_phishing_probability'])))
        hidden_agrees &= all(level(predictions[view['hidden']]) == level(base)
                             for view in view_readings.get(body, ()) if 'hidden' in view)
    return kept, resolved, hidden_agrees


@app.post("/api/analyze-content")
async def analyze_content_endpoint(request: ContentRequest):
    return await _analyze_content(request)


@app.post("/api/analyze-eml")
async def analyze_eml_endpoint(request: Request):
    if request.headers.get('content-type', '').split(';', 1)[0].lower() not in {'message/rfc822', 'application/octet-stream'}:
        raise HTTPException(status_code=415, detail='Upload the original .eml bytes as message/rfc822')
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 60_000:
            raise HTTPException(status_code=413, detail='Email file exceeds the 60,000-byte limit')
        raw.extend(chunk)
    if not raw.strip():
        raise HTTPException(status_code=400, detail='Email file is empty')
    # Minimal ASGI scopes (tests, the runtime smoke check) may omit the query string.
    mailbox = parse_qs(request.scope.get('query_string', b'').decode('latin-1')).get('mailbox', [''])[-1]
    if mailbox not in {'', *MAILBOX_AUTHSERV_IDS}:
        raise HTTPException(status_code=400, detail='Unsupported mailbox; use gmail, outlook or leave it empty')
    structure = await _run_analysis(analyze_raw_email, bytes(raw),
                                    trusted_authserv_ids=SETTINGS.trusted_authserv_ids,
                                    mailbox_provider=mailbox or None)
    return await _analyze_content(ContentRequest(), structure)


async def _analyze_content(
    request: ContentRequest,
    structure: dict | None = None,
    *,
    observe_sender_history: bool = True,
    plain_text: bool = False,
    allow_empty: bool = False,
):
    subject = request.subject.strip()
    body    = request.body.strip()
    if structure is not None or request.raw_email.strip():
        if structure is None:
            structure = await _run_analysis(analyze_raw_email,
                request.raw_email,
                trusted_authserv_ids=SETTINGS.trusted_authserv_ids,
            )
        # Raw-message mode is authoritative, including empty fields. Stale
        # manual input must not replace evidence from the uploaded message.
        subject = structure["subject"]
        body = structure["body"]
    has_structure = structure and (
        structure["attachments"] or structure["from"] or structure["reply_to"]
        or structure["return_path"] or structure["auth_results"]
        or structure["untrusted_authentication_claims"]
        or structure["parse_warnings"]
    )
    if not subject and not body and not has_structure and not allow_empty:
        raise HTTPException(status_code=400, detail="Subject, body, or message structure is required")

    # 1. Rule-based heuristic scan (explainable categories + extra indicators)
    model_view = {}
    result = await _run_analysis(analyze_email_content, subject, body, content_parts=(structure['content_parts'] if structure else
                                       [{'content_type': 'text/plain', 'content': body}] if plain_text else None),
                                   _model_view=model_view)
    if model_view.get('mime_alternatives_truncated'):
        result['analysis_warnings'].append(_MIME_ALTERNATIVE_LIMIT_WARNING)
    remote_image_dominant = model_view['remote_image_dominant']
    result["input_mode"] = "raw-email" if structure else "subject-body"
    result["structure_score"] = structure["structure_score"] if structure else 0
    if structure:
        result["extra_indicators"].extend(structure["indicators"])
        result["total_score"] += structure["structure_score"]
        result["message_structure"] = {
            key: structure[key]
            for key in (
                "from", "reply_to", "return_path", "auth_results",
                "authentication_trusted", "authentication_results_trusted",
                "untrusted_authentication_claims", "attachments", "risk_floor", "parse_warnings", "header_candidates",
            )
        }
        floor_rank = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if floor_rank[structure["risk_floor"]] > floor_rank[result["risk_floor"]]:
            result["risk_floor"] = structure["risk_floor"]

        # Link annotations read from PDF attachments go through the same destination
        # checks as message links; the PDF text itself stays uninspected.
        pdf_links = [('', target) for attachment in structure['attachments']
                     for target in attachment.get('extracted_links', ())]
        if pdf_links:
            pdf_score, pdf_findings, pdf_floor = _analyze_link_destinations('', links=pdf_links)
            if _has_shortener_url('', links=pdf_links):
                pdf_score += 2
                pdf_findings.append(indicator('high', 'content.shortened_urls'))
            result["total_score"] += pdf_score
            result["extra_indicators"].extend(
                wrap_message({key: item[key] for key in ('level', 'msg', 'code', 'params', 'prefixes') if key in item},
                             'prefix.pdf_attachment')
                for item in pdf_findings)
            if floor_rank[pdf_floor] > floor_rank[result["risk_floor"]]:
                result["risk_floor"] = pdf_floor
            result["pdf_link_count"] = len(pdf_links)

        selected_sender = await _run_analysis(
            _select_message_sender, structure['header_candidates']['From'])
        verified_sender = structure.get('verified_official_sender')
        if selected_sender is not None and verified_sender:
            # A DMARC-verified official domain makes address-shape heuristics
            # (unknown provider, long labels) moot; keep the analysis for display only.
            result["sender_analysis"] = selected_sender
            result["sender_score"] = 0
        elif selected_sender is not None:
            authenticated = structure.get('authenticated_sender')
            if (authenticated and (authenticated["display_name_matches"] or not _AUTHENTICATED_SENDER_NEEDS_NAME_MATCH)
                    and selected_sender["email"].rpartition("@")[2].lower() == authenticated["domain"]):
                selected_sender = _relax_authenticated_sender(selected_sender, authenticated)
            # Select locally before touching the external history store. An
            # attacker can inject many ambiguous From values into one message;
            # only the sender that actually drives the result gets one bounded
            # observation request.
            sender_analysis = (
                await _analyze_and_observe_sender(selected_sender["email"], analysis=selected_sender)
                if observe_sender_history
                else selected_sender
            )
            result["sender_analysis"] = sender_analysis
            sender_verdict = sender_analysis["verdict"]
            sender_contribution = {
                "critical": 6,
                "high": 5,
                "medium": 3,
            }.get(sender_verdict, 1 if sender_analysis["risk_score"] else 0)
            result["total_score"] += sender_contribution
            result["sender_score"] = sender_contribution
            result["extra_indicators"].extend(
                wrap_message({key: item[key] for key in ('level', 'msg', 'code', 'params', 'prefixes')
                              if key in item}, 'prefix.sender')
                for item in sender_analysis["risk_indicators"]
            )
            sender_floor = (
                "high" if sender_verdict in {"critical", "high"}
                else "medium" if sender_verdict == "medium"
                else "safe"
            )
            if floor_rank[sender_floor] > floor_rank[result["risk_floor"]]:
                result["risk_floor"] = sender_floor

        if result["total_score"] > 15:
            result["risk_level"], result["risk_label"] = "critical", "Critical Risk — Very Likely Phishing"
        elif result["risk_floor"] == "high":
            result["risk_level"], result["risk_label"] = "high", "High Risk — Likely Phishing"
        elif result["risk_floor"] == "medium":
            result["risk_level"], result["risk_label"] = "medium", "Medium Risk — Suspicious Content"
        elif result["total_score"] > 8:
            result["risk_level"], result["risk_label"] = "high", "High Risk — Likely Phishing"
        elif result["total_score"] > 3:
            result["risk_level"], result["risk_label"] = "medium", "Medium Risk — Suspicious Content"

    if structure:
        nested_summaries = []
        floor_rank = {'safe': 0, 'unknown': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        for nested in structure['nested_messages']:
            nested_result = json.loads((await _analyze_content(
                ContentRequest(), nested, observe_sender_history=False,
            )).body)
            result['analysis_warnings'].extend(message_text('prefix.attached_message', text=warning)
                                                for warning in nested_result['analysis_warnings']
                                                if warning not in {_INLINE_IMAGE_WARNING, _REMOTE_IMAGE_WARNING,
                                                                   _UNRESOLVED_IMAGE_WARNING})
            coverage = result['inline_image_coverage']
            coverage['count'] = min(20, coverage['count'] + nested_result['inline_image_coverage']['count'])
            if coverage['count']:
                coverage['inspection_status'] = 'metadata_only'
            remote_coverage = result['remote_image_coverage']
            remote_coverage['count'] = min(20, remote_coverage['count']
                                          + nested_result['remote_image_coverage']['count'])
            if remote_coverage['count']:
                remote_coverage['inspection_status'] = 'metadata_only'
            unresolved_coverage = result['unresolved_image_coverage']
            unresolved_coverage['count'] = min(20, unresolved_coverage['count']
                                               + nested_result['unresolved_image_coverage']['count'])
            if unresolved_coverage['count']:
                unresolved_coverage['inspection_status'] = 'metadata_only'
            if (nested_result['remote_image_coverage']['count']
                    and nested_result['risk_level'] == 'unknown'):
                remote_image_dominant = True
            result['total_score'] = max(result['total_score'], nested_result['total_score'])
            nested_floor = 'safe' if nested_result['risk_level'] == 'unknown' else nested_result['risk_level']
            result['risk_floor'] = max((result['risk_floor'], nested_floor), key=floor_rank.get)
            result['extra_indicators'].extend(
                wrap_message({key: item[key] for key in ('level', 'msg', 'rule_id', 'code', 'params', 'prefixes')
                              if key in item}, 'prefix.attached_message')
                for item in nested_result['extra_indicators']
                if item['msg'] not in {_INLINE_IMAGE_WARNING, _REMOTE_IMAGE_WARNING,
                                      _UNRESOLVED_IMAGE_WARNING})
            # Categories are not parent-body matches; expose their provenance.
            result['extra_indicators'].extend(
                wrap_message(indicator(cat['level'], 'content.nested_category', label=cat['label'],
                                       matched=', '.join(cat['matched']), category=cat['key']),
                             'prefix.attached_message')
                for cat in nested_result['category_results'])
            nested_summaries.append({
                'from': nested['from'], 'subject': nested['subject'],
                'risk_level': nested_result['risk_level'],
                'analysis_complete': nested_result['analysis_complete'],
                'authentication_results_trusted': nested['authentication_results_trusted'],
                'nested_messages': nested_result['message_structure']['nested_messages'],
            })
        result['message_structure']['nested_messages'] = nested_summaries

    if result['inline_image_coverage']['count'] and _INLINE_IMAGE_WARNING not in result['analysis_warnings']:
        result['analysis_warnings'].append(_INLINE_IMAGE_WARNING)
        result['extra_indicators'].append(indicator('info', 'warning.inline_images'))
    if result['remote_image_coverage']['count'] and _REMOTE_IMAGE_WARNING not in result['analysis_warnings']:
        result['analysis_warnings'].append(_REMOTE_IMAGE_WARNING)
        result['extra_indicators'].append(indicator('info', 'warning.remote_images'))
    if (result['unresolved_image_coverage']['count']
            and _UNRESOLVED_IMAGE_WARNING not in result['analysis_warnings']):
        result['analysis_warnings'].append(_UNRESOLVED_IMAGE_WARNING)
        result['extra_indicators'].append(indicator('info', 'warning.unresolved_images'))

    # 2. Optional ML text classifier (TF-IDF + selected linear model)
    rendering_uncertain = any(warning in result['analysis_warnings'] for warning in (
        _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
        _IMAGE_ALT_FALLBACK_WARNING, _MSO_CONDITIONAL_WARNING,
    ))
    # Warnings about text that may be hidden or shown only in some clients stop
    # blocking a verdict once every plausible rendering was scored and they agree.
    resolved_warnings = set()
    if _content_pipeline is not None:
        threshold = float(_content_pipeline.get('decision_threshold', 0.5))
        views = model_view.get('mime_views', [(model_view['body'], rendering_uncertain)])
        view_readings = model_view.get('view_readings', {})
        bodies = [body for body, uncertain in views if not uncertain]
        kept, rendering_resolved, hidden_agrees = [], False, True
        if bodies:
            texts = list(dict.fromkeys([*bodies, *(text for body in bodies for view in view_readings.get(body, ())
                                                   for text in view.values())]))
            predictions = dict(zip(texts, await _run_analysis(
                lambda pipeline, subject, texts: [
                    predict_content(pipeline, subject, text, canonical_text=True) for text in texts],
                _content_pipeline, model_view['subject'], texts)))
            kept, rendering_resolved, hidden_agrees = _agreeing_model_views(
                bodies, view_readings, predictions, threshold=threshold,
                heuristic_score=result['total_score'], minimum_level=result['risk_floor'])

        def alerts(ml):
            return fuse_content_risk(
                ml_phishing_probability=ml['_phishing_probability'], ml_decision_threshold=threshold,
                heuristic_score=result['total_score'], minimum_level=result['risk_floor'],
            )['risk_level'] in {'medium', 'high', 'critical'}
        ml = _model_choice([prediction for _body, prediction in kept], threshold)
        earlier = [(body, prediction) for body, prediction in kept
                   if body not in model_view.get('resolved_views', set())]
        if len(earlier) < len(kept) and alerts(ml) and not alerts(_model_choice(
                [prediction for _body, prediction in earlier], threshold)):
            # Only a newly scored rendering alerts. On such HTML (mostly account and
            # security notices) the model alone raised 52 false alerts against 62 phishing
            # catches (docs/evaluation.md), so keep the earlier abstention.
            kept, rendering_resolved = earlier, False
            ml = _model_choice([prediction for _body, prediction in kept], threshold)
        if rendering_resolved and len(kept) == len(views):
            rendering_uncertain = False
            resolved_warnings = {_STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
                                 _MSO_CONDITIONAL_WARNING}
            if hidden_agrees:
                resolved_warnings.add(_HIDDEN_HTML_TEXT_WARNING)
            if resolved_warnings & set(result['analysis_warnings']):
                result['extra_indicators'].append(indicator('info', 'content.rendering_views_agree'))
        if kept:
            scored = [prediction for _body, prediction in kept if prediction['_phishing_probability'] is not None]
            if len(views) > 1 and (len(kept) != len(views) or len(scored) != len(kept)):
                result['analysis_warnings'].append(_MIME_ALTERNATIVE_MODEL_WARNING)
        result.update({key: value for key, value in ml.items() if key != '_phishing_probability'})
        result["ml_metrics"] = _content_pipeline["metrics"]

        ml_probability = ml['_phishing_probability']
        if ml.get("ml_status") == "insufficient_context":
            result["analysis_warnings"].append(message_text('warning.model_insufficient_context'))
        elif ml.get("ml_status") == "insufficient_feature_coverage":
            result["analysis_warnings"].append(message_text('warning.model_insufficient_coverage'))

        result.update(fuse_content_risk(
            ml_phishing_probability=ml_probability,
            ml_decision_threshold=float(_content_pipeline.get("decision_threshold", 0.5)),
            heuristic_score=result["total_score"],
            minimum_level=result["risk_floor"],
        ))
    else:
        result.update(fuse_content_risk(
            ml_phishing_probability=None,
            ml_decision_threshold=0.5,
            heuristic_score=result["total_score"],
            minimum_level=result["risk_floor"],
        ))

    # A verified official sender (trusted DMARC pass on the organization's own domain)
    # cannot be raised above Low by the text model or weak rules alone. Evidence that
    # sets a Medium or higher floor (links, attachments, requests for codes) still
    # alerts, and a very high rule score keeps Critical.
    verified_sender = structure.get('verified_official_sender') if structure else None
    result['verified_official_sender'] = verified_sender
    # Where to verify independently: organizations named by the verified sender, the
    # From display name or the subject. Guidance only; it never changes the score.
    from_names = [name for value in (structure['header_candidates']['From'] if structure else ())
                  for name, _address in getaddresses([value]) if name]
    result['official_channels'] = _official_channels(
        [*from_names, structure['subject'] if structure else request.subject],
        first=verified_sender['organization'] if verified_sender else None)
    if verified_sender and result['risk_floor'] in {'safe', 'low'} and result['risk_level'] in {'medium', 'high'}:
        result['risk_level'] = 'low'
        result['risk_label'] = 'Low Risk — Verified Official Sender'

    if structure and any(item['inspection_status'] == 'metadata_only'
                         for item in structure['attachments']):
        item = indicator('info', 'warning.attachments_uninspected')
        result['analysis_warnings'].append(item['msg'])
        result['extra_indicators'].append(item)

    result['analysis_warnings'] = list(dict.fromkeys(result['analysis_warnings']
        + (structure['parse_warnings'] if structure else [])))
    result['analysis_complete'] = not bool(result['analysis_warnings'])
    # Weak routing/text evidence cannot establish low risk when the main visible
    # content is an uninspected image, or when the model could not score the text
    # (e.g. Han script); a clean result already becomes unknown in that case.
    # Keep independently supported alerts. Resolved rendering warnings stay listed
    # but no longer block.
    blocking_warnings = [warning for warning in result['analysis_warnings'] if warning not in resolved_warnings]
    model_unscored = result.get('ml_status') in {'insufficient_context', 'insufficient_feature_coverage'}
    if blocking_warnings and (result['risk_level'] == 'safe'
                              or (rendering_uncertain or remote_image_dominant or model_unscored)
                              and result['risk_level'] == 'low'):
        if blocking_warnings == [_REMOTE_IMAGE_WARNING] and not remote_image_dominant:
            result['risk_label'] = 'No Indicators in Inspected Text — Remote Image Unchecked'
        elif (verified_sender and verified_sender['organization'] in SENDER_ONLY_SERVICES
              and result['risk_floor'] in {'safe', 'low'} and not remote_image_dominant):
            # A registered service's own account mail (platform relays are excluded):
            # hidden or client-specific text, image fallbacks and unscored views are its
            # own, so they leave the verified Low rather than an undetermined result.
            # Payment, bank and large-platform brands keep abstaining: scams sent through
            # their genuine invoices and money requests put attacker text in fields that
            # an unreadable part may hold (7 such PayPal and Microsoft messages in Nazario).
            # Mail whose main content is an uninspected remote image keeps abstaining too.
            result['risk_level'] = 'low'
            result['risk_label'] = 'Low Risk — Verified Official Sender'
        else:
            result['risk_level'] = 'unknown'
            result['risk_label'] = 'Analysis Incomplete — Risk Undetermined'
            result['combined_phishing_score'] = None
    return JSONResponse(annotate_content(result))


@app.post('/api/analyze-visual')
async def analyze_visual_endpoint(payload: VisualRequest):
    return await _analyze_visual(payload)


# Do not echo private image text/base64 (or non-JSON NaN values) in validation errors.
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler


@app.exception_handler(RequestValidationError)
async def safe_visual_validation(request, exc):
    if request.url.path in VISUAL_PATHS:
        return JSONResponse(status_code=422, content={'detail': 'Invalid image evidence or email input. Check file size and recognition limits.'})
    return await request_validation_exception_handler(request, exc)


async def _analyze_visual(payload, structure=None, *, observe_sender_history=True):
    raw = payload.eml_bytes()
    enhancement = None
    if payload.enhancement is not None:
        if raw or len(payload.observations) != 1:
            raise HTTPException(422, 'Enhanced recognition supports one standalone image')
        try:
            enhancement = await _run_analysis(recognize_image, ENHANCED_VISION,
                                             payload.enhancement, payload.observations[0])
        except HTTPException as exc:
            if exc.status_code != 502:
                raise
            failed = coded_message('warning.enhanced_failed')
            enhancement = {'status': 'unavailable', 'warnings': [failed['msg']], 'warning_details': [failed]}
    if structure is None and raw is not None:
        structure = bound_message_text(await _run_analysis(analyze_raw_email, raw,
            trusted_authserv_ids=SETTINGS.trusted_authserv_ids, mailbox_provider=payload.mailbox or None))
    if not (raw or payload.subject.strip() or payload.body.strip() or payload.observations or payload.warnings):
        raise HTTPException(400, 'Image evidence or an email is required')
    base = json.loads((await _analyze_content(
        ContentRequest(subject=payload.subject, body=payload.body), structure,
        observe_sender_history=observe_sender_history, allow_empty=True,
    )).body)
    findings = []
    for item in payload.observations:
        # Treat extracted strings as text, never as an HTML document or a URL to fetch.
        # OCR and separate QR codes have no shared sentence or model context:
        # joining them can invent a request or negate a real request in another.
        texts = [text for text in [item.ocr_text, *dict.fromkeys(item.qr_payloads)]
                 if text.strip()]
        source_findings = []
        for text in texts or ['']:
            source_findings.append(json.loads((await _analyze_content(
                ContentRequest(body=text), observe_sender_history=False,
                plain_text=True, allow_empty=True,
            )).body))
        findings.append(merge_visual_sources(source_findings, source_count=len(texts)))
    base['input_mode'] = 'raw-email' if raw else 'image-evidence'
    merged = merge_visual_findings(base, payload.observations, findings, payload.warnings)
    if enhancement is not None:
        merged['visual_analysis']['enhancement'] = (enhancement if isinstance(enhancement, dict)
            else enhanced_evidence(enhancement, payload.observations[0]))
    return JSONResponse(annotate_content(merged))


# ── Email Authenticity Verification ──────────────────────────────────────────

from concurrent.futures import TimeoutError as FutureTimeout, wait as futures_wait

VERIFICATION_TIMEOUT = 12.0
try:
    VERIFICATION_WORKERS = int(os.getenv("VERIFICATION_WORKERS", "10"))
except ValueError as exc:
    raise ValueError("VERIFICATION_WORKERS must be an integer") from exc
if not 1 <= VERIFICATION_WORKERS <= 32:
    raise ValueError("VERIFICATION_WORKERS must be between 1 and 32")
_verification_pool = BoundedExecutor(workers=VERIFICATION_WORKERS)


class VerifyRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=254)


def _verify_message(code: str, key: str = 'message', **params) -> dict:
    """An English verification message plus its stable code and parameters.

    ``message`` gets ``code``/``params``; another field (``smtp_message``,
    ``note``, ``reason``) gets ``<field>_code``/``<field>_params``.
    """
    coded = coded_message(code, **params)
    prefix = '' if key == 'message' else key + '_'
    return {key: coded['msg'], prefix + 'code': code, prefix + 'params': coded['params']}


# ── Helper: SMTP mailbox probe ────────────────────────────────────────────────
def _resolve_public_smtp_addresses(
    mx_host: str,
    *,
    resolver=None,
    timeout: float = 5,
) -> list[str]:
    """Resolve a mail host once and retain only globally routable targets."""
    addresses: list[str] = []
    if resolver is None:
        import dns.resolver
        import dns.exception
        answers = []
        deadline = time.monotonic() + timeout
        for kind in ('A', 'AAAA'):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                records = dns.resolver.resolve(mx_host, kind, lifetime=remaining)
                answers.extend((None, None, None, None, (str(r), 25)) for r in records)
            except dns.exception.DNSException:
                continue
    else:
        try:
            answers = resolver(mx_host, 25, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            return addresses

    for _family, _socktype, _proto, _canonname, sockaddr in answers:
        address = str(sockaddr[0]).split("%", 1)[0]
        try:
            is_global = ipaddress.ip_address(address).is_global
        except ValueError:
            continue
        if is_global and address not in addresses:
            addresses.append(address)
    return addresses


def _smtp_probe(
    email: str,
    mx_host: str,
    smtp_address: str | None = None,
    timeout: int = 8,
) -> dict:
    result = {"connectable": False, "result": "unverifiable", "message": "", "code": None, "params": {},
              "status": "error"}
    deadline = time.monotonic() + timeout
    if smtp_address is None:
        public_addresses = _resolve_public_smtp_addresses(mx_host, timeout=min(5, timeout))
        smtp_address = public_addresses[0] if public_addresses else None
    try:
        is_public_target = bool(
            smtp_address and ipaddress.ip_address(smtp_address).is_global
        )
    except ValueError:
        is_public_target = False
    if not is_public_target:
        result['status'] = 'unavailable'
        result.update(_verify_message('verify.smtp_non_public_target', host=mx_host))
        return result

    smtp = None
    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise socket.timeout()
        return seconds
    try:
        smtp = smtplib.SMTP(timeout=remaining())
        smtp.connect(smtp_address, 25)
        result["connectable"] = True
        smtp.sock.settimeout(remaining())
        smtp.helo("verify.phishguard.local")
        smtp.sock.settimeout(remaining())
        smtp.mail("")
        smtp.sock.settimeout(remaining())
        code, msg_bytes = smtp.rcpt(email)
        result['status'] = 'ok'
        msg_str = msg_bytes.decode(errors="replace") if isinstance(msg_bytes, bytes) else str(msg_bytes)
        enhanced_match = re.match(r'^\s*([245]\.\d{1,3}\.\d{1,3})(?:\s|$)', msg_str)
        enhanced = enhanced_match.group(1) if enhanced_match else None
        try:
            smtp.sock.settimeout(remaining())
            smtp.quit()
        except Exception:
            pass
        if code == 250:
            result["result"] = "exists"
            result.update(_verify_message('verify.smtp_accepted', smtp_code=code))
        elif 500 <= code < 600 and enhanced == '5.1.1':
            result["result"] = "does_not_exist"
            result.update(_verify_message('verify.smtp_no_such_mailbox', smtp_code=code, response=msg_str[:120]))
        elif 500 <= code < 600 and enhanced and enhanced.startswith('5.7.'):
            result['result'] = 'policy_rejected'
            result.update(_verify_message('verify.smtp_policy_rejected', smtp_code=code, response=msg_str[:120]))
        elif 500 <= code < 600 and enhanced == '5.2.2':
            result['result'] = 'mailbox_full'
            result.update(_verify_message('verify.smtp_mailbox_full', smtp_code=code, response=msg_str[:120]))
        elif code in (421, 450, 451, 452):
            result["result"] = "temporarily_unavailable"
            result.update(_verify_message('verify.smtp_temporary_error', smtp_code=code))
        else:
            result["result"] = "unknown"
            result.update(_verify_message('verify.smtp_inconclusive', smtp_code=code, response=msg_str[:120]))
    except smtplib.SMTPConnectError as e:
        result.update(_verify_message('verify.smtp_connect_failed', host=mx_host, error=str(e)))
    except smtplib.SMTPServerDisconnected as e:
        result.update(_verify_message('verify.smtp_disconnected', error=str(e)))
    except socket.timeout:
        result['status'] = 'timeout'
        result.update(_verify_message('verify.smtp_connection_timeout', host=mx_host, seconds=timeout))
    except OSError as e:
        result.update(_verify_message('verify.smtp_network_error', error=str(e)))
    except Exception as e:
        result.update(_verify_message('verify.smtp_error', error=str(e)[:150]))
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass
    return result


# ── Helper: SPF record check ──────────────────────────────────────────────────
def _check_spf(domain: str) -> dict:
    """Look up SPF TXT record and parse the enforcement policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "message": "", "code": None, "params": {},
              "status": "not_found"}
    try:
        records = [b''.join(r.strings).decode('ascii', errors='replace')
                   for r in dns.resolver.resolve(domain, 'TXT', lifetime=5)]
        records = [txt for txt in records if re.match(r'^v=spf1(?:\s|$)', txt, re.IGNORECASE)]
        if len(records) > 1:
            raise ValueError('Multiple SPF records; policy is inconclusive')
        for txt in records:
            terms = txt.split()
            if terms and terms[0].lower() == 'v=spf1':
                # Validate local term shapes before summarizing the first all.
                # This does not expand macros or evaluate include/redirect.
                mechanism = (r'[+?~-]?(?:all|(?:include|exists):\S+|'
                             r'(?:a|mx)(?::\S+|/[0-9]+(?://[0-9]+)?|//[0-9]+)?|'
                             r'ptr(?::\S+)?|ip[46]:\S+)')
                modifier = r'[a-z][a-z0-9._-]*=\S+'
                if any(not re.fullmatch(mechanism + '|' + modifier, term, re.IGNORECASE)
                       for term in terms[1:]):
                    raise ValueError('Malformed or unsupported SPF mechanism')
                result['status'] = 'ok'
                result["found"]  = True
                result["record"] = txt[:250]
                all_term = next((term.lower() for term in terms[1:]
                                 if re.fullmatch(r'[+?~-]?all', term, re.IGNORECASE)), None)
                if all_term == '-all':
                    result["policy"]  = "strict"
                    result.update(_verify_message('verify.spf_strict'))
                elif all_term == '~all':
                    result["policy"]  = "softfail"
                    result.update(_verify_message('verify.spf_softfail'))
                elif all_term == '?all':
                    result["policy"]  = "neutral"
                    result.update(_verify_message('verify.spf_neutral'))
                elif all_term in {'+all', 'all'}:
                    result["policy"]  = "open"
                    result.update(_verify_message('verify.spf_open'))
                else:
                    result["policy"]  = "unknown"
                    result.update(_verify_message('verify.spf_unclear'))
                break
        if not result["found"]:
            result.update(_verify_message('verify.spf_missing'))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.update(_verify_message('verify.no_txt_records'))
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result.update(_verify_message('verify.dns_error', error=str(e)))
    except Exception as e:
        result['status'] = 'error'
        result.update(_verify_message('verify.spf_error', error=str(e)[:100]))
    return result


# ── Helper: DMARC policy check ────────────────────────────────────────────────
def _check_dmarc(domain: str) -> dict:
    """Look up DMARC TXT record at _dmarc.<domain> and parse the p= policy."""
    import dns.resolver, dns.exception
    result = {"found": False, "record": None, "policy": None, "pct": None, "message": "", "code": None, "params": {},
              "status": "not_found"}
    try:
        dmarc_domain = f"_dmarc.{domain}"
        records = [b''.join(r.strings).decode('ascii', errors='replace')
                   for r in dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)]
        records = [txt for txt in records if re.match(r'^v\s*=\s*DMARC1\s*(?:;|$)', txt)]
        if len(records) > 1:
            raise ValueError('Multiple DMARC records; policy is inconclusive')
        for txt in records:
            result['found'] = True
            result['record'] = txt[:250]
            tags = {}
            for field in txt.rstrip().rstrip(';').split(';'):
                match = re.fullmatch(r'\s*([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*(.*?)\s*', field)
                if not match or match.group(1) in tags:
                    raise ValueError('Malformed or duplicate DMARC tag')
                tags[match.group(1)] = match.group(2)
            p = tags.get('p')
            if p not in {'reject', 'quarantine', 'none'}:
                raise ValueError('Missing or invalid DMARC p= policy')
            pct_text = tags.get('pct', '100')
            if not re.fullmatch(r'[0-9]{1,3}', pct_text) or int(pct_text) > 100:
                raise ValueError('DMARC pct must be between 0 and 100')
            pct = int(pct_text)
            result.update(status='ok', policy=p, pct=pct)
            # p=none never mentions pct; a partial pct names its percentage.
            partial = pct < 100 and p != 'none'
            result.update(_verify_message(f'verify.dmarc_{p}{"_partial" if partial else ""}',
                                          **({'pct': pct} if partial else {})))
        if not result["found"]:
            result.update(_verify_message('verify.dmarc_missing', domain=domain))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.update(_verify_message('verify.dmarc_not_found', domain=domain))
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result.update(_verify_message('verify.dns_error', error=str(e)))
    except Exception as e:
        result['status'] = 'error'
        result.update(_verify_message('verify.dmarc_error', error=str(e)[:100]))
    return result


# ── Helper: Domain age via WHOIS ──────────────────────────────────────────────
def _check_domain_age(domain: str) -> dict:
    """Retrieve domain creation date via WHOIS and assess age."""
    result = {"found": False, "creation_date": None, "age_days": None,
              "registrar": None, "message": "", "code": None, "params": {}, "status": "not_found"}
    try:
        import whois
        from datetime import datetime, timezone
        w = whois.whois(domain, timeout=5)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (now - creation).days
            result["found"]         = True
            result['status'] = 'ok'
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            result["age_days"]      = age
            result["registrar"]     = (w.registrar or "")[:80] if w.registrar else None
            if age < 30:
                result.update(_verify_message('verify.age_very_new', days=age))
            elif age < 180:
                result.update(_verify_message('verify.age_new', days=age, months=age // 30))
            elif age < 365:
                result.update(_verify_message('verify.age_under_year', days=age))
            else:
                years = age // 365
                result.update(_verify_message(
                    'verify.age_established' if years != 1 else 'verify.age_established_one',
                    date=creation.strftime('%Y-%m-%d'), years=years))
        else:
            result.update(_verify_message('verify.age_no_date'))
    except Exception as e:
        result['status'] = 'timeout' if isinstance(e, TimeoutError) else 'error'
        result.update(_verify_message('verify.age_failed', error=str(e)[:100]))
    return result


# ── Helper: MX PTR (reverse DNS) check ───────────────────────────────────────
def _check_mx_ptr(mx_host: str) -> dict:
    """Check if the primary MX server has a valid PTR (reverse DNS) record."""
    import dns.resolver, dns.reversename, dns.exception
    result = {"found": False, "ptr": None, "ip": None, "message": "", "code": None, "params": {},
              "status": "not_found"}
    try:
        a_records = dns.resolver.resolve(mx_host, "A", lifetime=5)
        ip = str(a_records[0])
        result["ip"] = ip
        rev = dns.reversename.from_address(ip)
        ptr_records = dns.resolver.resolve(rev, "PTR", lifetime=5)
        ptr = str(ptr_records[0]).rstrip(".")
        result["found"] = True
        result["ptr"]   = ptr
        result['status'] = 'ok'
        result.update(_verify_message('verify.ptr_found', ip=ip, ptr=ptr))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.update(_verify_message('verify.ptr_missing_ip', ip=result['ip']) if result['ip']
                      else _verify_message('verify.ptr_missing'))
    except dns.exception.DNSException as e:
        result['status'] = 'timeout' if isinstance(e, dns.exception.Timeout) else 'error'
        result.update(_verify_message('verify.ptr_lookup_error', error=str(e)))
    except Exception as e:
        result['status'] = 'error'
        result.update(_verify_message('verify.ptr_error', error=str(e)[:100]))
    return result


def _lookup_mail_domain(domain: str, deadline: float) -> dict:
    """Perform bounded DNS discovery; a timeout is not a nonexistent mailbox."""
    import dns.resolver
    import dns.exception
    result = {'mx_found': False, 'mx_records': [], 'overall': 'unverifiable',
              **_verify_message('verify.dns_timeout', 'smtp_message')}
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result
        answers = dns.resolver.resolve(domain, 'MX', lifetime=min(6, remaining))
        records = sorted((r.preference, str(r.exchange).rstrip('.')) for r in answers)
        if any(not host for _, host in records):
            if records == [(0, '')]:
                return {**result, 'null_mx': True, 'overall': 'no_mail_service',
                        **_verify_message('verify.null_mx', 'smtp_message')}
            return {**result, **_verify_message('verify.invalid_null_mx', 'smtp_message')}
        if records:
            return {'mx_found': True, 'mx_records': records}
    except dns.resolver.NXDOMAIN:
        return {**result, 'overall': 'likely_invalid', **_verify_message('verify.domain_not_found', 'smtp_message')}
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException:
        return result
    address_lookup_failed = False
    for kind in ('A', 'AAAA'):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result
        try:
            addresses = dns.resolver.resolve(domain, kind, lifetime=min(4, remaining))
            if addresses:
                return {'mx_found': True, 'mx_records': [[0, domain]],
                        **_verify_message('verify.address_record_fallback', 'note', record_type=kind)}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            address_lookup_failed = True
    if address_lookup_failed:
        return result
    return {**result, 'overall': 'likely_invalid', **_verify_message('verify.no_mail_records', 'smtp_message')}


def _summarize_verification(out: dict, *, smtp_enabled: bool) -> None:
    """Add explicit domain/mailbox summaries without overstating evidence."""
    domain_complete = False
    if not out["format_valid"]:
        domain_status = "invalid_format"
    elif out["null_mx"]:
        domain_status = "no_mail_service"
    elif out["mx_found"]:
        domain_checks = (out["spf"], out["dmarc"], out["domain_age"], out["mx_ptr"])
        domain_complete = all(
            info is not None and info.get("status") in {"ok", "not_found"}
            for info in domain_checks
        )
        domain_status = "valid" if domain_complete else "partial"
    elif out["overall"] == "likely_invalid":
        domain_status = "invalid"
    else:
        domain_status = "unavailable"

    # The reason repeats smtp_message (or the disabled notice) with its code.
    reason = {'reason': out["smtp_message"], 'reason_code': out.get("smtp_message_code"),
              'reason_params': out.get("smtp_message_params") or {}}
    if not smtp_enabled:
        mailbox_status = "unavailable"
        reason = _verify_message('verify.smtp_disabled_reason', 'reason')
    elif out["smtp_result"] == "exists":
        mailbox_status = "accepted"
    elif out["smtp_result"] == "does_not_exist":
        mailbox_status = "rejected"
    else:
        mailbox_status = "inconclusive"

    out["domain_verification"] = {
        "status": domain_status,
        "complete": domain_complete,
        "mx_found": out["mx_found"],
    }
    out["mailbox_verification"] = {
        "status": mailbox_status,
        **reason,
    }
    out["verification_complete"] = (
        domain_complete and mailbox_status in {"accepted", "rejected"}
    )


@app.post("/api/verify-email")
def verify_email_endpoint(req: VerifyRequest):
    """
    Six-stage email authenticity check (stages 3-6 run in parallel):
      1. RFC 5321 format validation
      2. DNS MX (+ A/AAAA fallback) record lookup
      3. Optional SMTP RCPT TO probe  ┐
      4. SPF record & policy          ├─ parallel
      5. DMARC record & policy        │
      6. MX PTR / reverse-DNS         │
      7. Domain age (WHOIS)           ┘
    """
    if not SETTINGS.domain_verification_enabled:
        raise HTTPException(
            status_code=404,
            detail=(
                "Domain verification is disabled in this deployment. "
                "Enable Lite mode or run full SMTP checks locally."
            ),
        )

    email = req.email.strip()
    out = {
        "email": email,
        "format_valid": False,
        "mx_found": False,
        "mx_records": [],
        "null_mx": False,
        "smtp_connectable": False,
        "smtp_result": None,
        "smtp_message": None,
        "smtp_message_code": None,
        "smtp_message_params": {},
        "smtp_status": "skipped",
        "spf":  None,
        "dmarc": None,
        "domain_age": None,
        "mx_ptr": None,
        "note": None,
        "note_code": None,
        "note_params": {},
        "overall": None,
        "verification_complete": False,
    }

    def respond():
        _summarize_verification(
            out,
            smtp_enabled=SETTINGS.smtp_verification_enabled,
        )
        return JSONResponse(out)

    # ── Stage 1: Format ───────────────────────────────────────────────────────
    normalized_email = _normalize_sender_address(email)
    if not normalized_email:
        out["overall"]       = "invalid_format"
        out.update(_verify_message('verify.format_invalid', 'smtp_message'))
        return respond()
    out["format_valid"] = True
    # Retain the submitted address for display, but use the same canonical
    # IDNA domain/address as sender analysis for DNS, WHOIS and SMTP checks.
    email = normalized_email
    domain = email.split("@")[1].lower()

    # One deadline covers DNS discovery and every subsequent check.
    deadline = time.monotonic() + VERIFICATION_TIMEOUT
    discovery = _verification_pool.submit(_lookup_mail_domain, domain, deadline)
    if discovery is None:
        raise HTTPException(status_code=503, detail='Verification capacity is busy; retry later.', headers={'Retry-After': '12'})
    try:
        out.update(discovery.result(timeout=max(0, deadline - time.monotonic())))
    except FutureTimeout:
        discovery.cancel()
        out['overall'] = 'unverifiable'
        out.update(_verify_message('verify.dns_timeout', 'smtp_message'))
        return respond()
    except Exception:
        out['overall'] = 'unverifiable'
        out.update(_verify_message('verify.dns_unavailable', 'smtp_message'))
        return respond()
    if not out['mx_found']:
        return respond()
    mx_host = out['mx_records'][0][1]
    if time.monotonic() >= deadline:
        out['overall'] = 'unverifiable'
        out.update(_verify_message('verify.deadline_after_dns', 'smtp_message'))
        return respond()

    # No per-request context manager: its shutdown would wait past the deadline.
    f_smtp = (
        _verification_pool.submit(_smtp_probe, email, mx_host)
        if SETTINGS.smtp_verification_enabled else None
    )
    f_spf = _verification_pool.submit(_check_spf, domain)
    f_dmarc = _verification_pool.submit(_check_dmarc, domain)
    f_age = _verification_pool.submit(_check_domain_age, domain)
    f_ptr = _verification_pool.submit(_check_mx_ptr, mx_host)
    futures = [f for f in (f_smtp, f_spf, f_dmarc, f_age, f_ptr) if f is not None]
    done, pending = futures_wait(futures, timeout=max(0, deadline - time.monotonic()))
    for future in pending:
        future.cancel()

    def safe_result(future, fallback):
        if future is None:
            return {**fallback, 'status': 'busy', **_verify_message('verify.check_busy')}
        if future not in done:
            return {**fallback, 'status': 'timeout'}
        try:
            return future.result(timeout=0)
        except Exception:
            return {**fallback, 'status': 'error', **_verify_message('verify.check_failed')}

    if SETTINGS.smtp_verification_enabled:
        probe = safe_result(f_smtp, {"connectable": False, "result": "unverifiable",
                                     **_verify_message('verify.smtp_timeout')})
    else:
        probe = {
            "connectable": False,
            "result": "unavailable",
            **_verify_message('verify.smtp_disabled'),
            "status": "skipped",
        }
    spf_info     = safe_result(f_spf,   {"found": False, "policy": None,
                                          **_verify_message('verify.spf_timeout')})
    dmarc_info   = safe_result(f_dmarc, {"found": False, "policy": None,
                                          **_verify_message('verify.dmarc_timeout')})
    age_info     = safe_result(f_age,   {"found": False, "age_days": None,
                                          **_verify_message('verify.age_timeout')})
    ptr_info     = safe_result(f_ptr,   {"found": False, "ptr": None,
                                          **_verify_message('verify.ptr_timeout')})

    out["smtp_connectable"] = probe["connectable"]
    out['smtp_status'] = probe['status']
    out["smtp_result"]      = probe["result"]
    out["smtp_message"]     = probe["message"]
    # A mocked or legacy probe may lack a code; the English message stays as sent.
    out["smtp_message_code"] = probe.get("code") if probe["message"] else None
    out["smtp_message_params"] = (probe.get("params") or {}) if probe["message"] else {}
    out["spf"]              = spf_info
    out["dmarc"]            = dmarc_info
    out["domain_age"]       = age_info
    out["mx_ptr"]           = ptr_info

    # ── Overall verdict ───────────────────────────────────────────────────────
    if not SETTINGS.smtp_verification_enabled:
        out["overall"] = "domain_valid"
    elif probe["result"] == "exists":
        out["overall"] = "verified"
    elif probe["result"] == "does_not_exist":
        out["overall"] = "likely_invalid"
    elif not probe["connectable"]:
        out["overall"] = "unverifiable"
        if not out["smtp_message"]:
            out.update(_verify_message('verify.smtp_port_blocked', 'smtp_message'))
    else:
        out["overall"] = "unverifiable"

    # Escalate: very new domain is a serious additional red flag
    age_days = age_info.get("age_days")
    if age_days is not None and age_days < 30 and out["overall"] != "likely_invalid":
        out["overall"] = "suspicious"

    return respond()



async def _analyze_case(payload, raw):
    """Capture server evidence once; clients cannot submit or edit detection results."""
    structure = None
    visual = isinstance(payload, VisualRequest)
    raw_input = payload.eml_bytes() if visual else raw if raw is not None else payload.raw_email
    if raw_input:
        structure = await _run_analysis(analyze_raw_email, raw_input,
            trusted_authserv_ids=SETTINGS.trusted_authserv_ids)
    if visual:
        if structure:
            bound_message_text(structure)
        response = await _analyze_visual(payload, structure, observe_sender_history=False)
    else:
        response = await _analyze_content(ContentRequest(**payload.model_dump()), structure,
                                         observe_sender_history=False)
    analysis = json.loads(response.body)
    analysis.pop('ml_metrics', None)  # Dataset-wide metrics are not per-message evidence.
    # Message codes on indicators are kept; the *_details lists only repeat the
    # stored English warnings for display, so they are not retained.
    strip_details(analysis)
    source = {'subject': structure['subject'] if structure else payload.subject.strip(),
              'body': structure['body'] if structure else payload.body.strip(),
              'input_mode': analysis['input_mode']}
    if visual:
        # Analyze the original message above, but retain text rather than embedded
        # image bytes. Plain MIME parts remain literal text, including angle brackets.
        parts = structure['content_parts'] if structure else [
            {'content_type': 'text/html', 'content': source['body']}]
        source['body'] = '\n'.join(_mask_inline_data_payloads(
            _visible_content_text(part['content']) if part['content_type'] == 'text/html'
            else part['content']) for part in parts)
    if visual and not structure and not source['subject'] and payload.observations:
        source['subject'] = 'Image: ' + payload.observations[0].name
    source['text_truncated'] = bool(len(source['body']) > 60000 or
                                    (visual and structure and structure.get('text_truncated')))
    source['body'] = source['body'][:60000]
    # Preserve MIME text/plain literally for later optional semantic analysis.
    # Saved legacy raw-email bodies mix HTML/plain and cannot be re-parsed safely.
    semantic_parts = structure['content_parts'] if structure else [
        {'content_type': 'text/html', 'content': payload.body}]
    source['auxiliary_text'] = '\n'.join(
        _mask_inline_data_payloads(_visible_content_text(part['content'])
                                  if part['content_type'] == 'text/html' else part['content'])
        for part in semantic_parts)[:12001]  # Over-limit sentinel length makes Jev skip, not silently truncate.
    source['auxiliary_omitted_nested_messages'] = bool(structure and structure.get('nested_messages'))
    digest = hashlib.sha256()
    for path in sorted([*BASE_DIR.glob('*.py'), *(BASE_DIR / 'data').glob('*.json')]):
        digest.update(str(path.relative_to(BASE_DIR)).encode() + b'\0' + path.read_bytes())
    provenance = {'code_sha256': digest.hexdigest(), 'model_sha256': _content_model_artifact_sha256,
                  'commit': os.getenv('VERCEL_GIT_COMMIT_SHA') or None,
                  'trusted_authserv_ids': sorted(SETTINGS.trusted_authserv_ids)}
    return source, analysis, provenance


app.include_router(make_case_router(_analyze_case, visible_text=_visible_content_text,
                                   mask_inline_data=_mask_inline_data_payloads))
app.include_router(make_feedback_router())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
