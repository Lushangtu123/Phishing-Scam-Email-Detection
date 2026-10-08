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
import base64
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
from datetime import datetime, timezone
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser  # noqa: F401 -- tests patch app.HTMLParser, the class html_visibility uses
from html import escape as escape_html
from itertools import product
from functools import lru_cache, partial
from urllib.parse import parse_qs, unquote, urljoin

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
from pathlib import Path, PurePath
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from typing import Literal

from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from config import load_settings
import domain_age
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
from local_review import addresses_reviewers, load_local_review_settings, review as local_review
from html_visibility import (  # the HTML/CSS visibility reader
    _AnalysisHTMLParser, _HIDDEN_HTML_TEXT_WARNING, _IMAGE_ALT_FALLBACK_WARNING,
    _INLINE_CSS_VISIBILITY_WARNING, _MSO_CONDITIONAL_WARNING, _POSSIBLY_INVISIBLE_WARNING,
    _SAME_COLOUR_MODEL_LETTERS, _STYLESHEET_VISIBILITY_WARNING, _collect_html,
    _first_html_attributes, _parse_link_target, _strip_invisible_format_controls, _unescape_css,
    _visible_content_text
)
from html_visibility import (  # noqa: F401 -- re-exported for tests that reach them through app
    _MAX_MEDIA_CONTEXTS, _background_clip, _background_clip_valid, _background_parts,
    _background_tiling_valid, _background_uncertain, _background_valid, _color_class, _color_state,
    _colour_rgba, _colours_may_match, _css_math_type, _css_words, _declared_values,
    _document_features, _expand_mso_comments, _font_size_class, _font_size_state, _geometry_hidden,
    _gradient_stops, _hiding_value, _inline_text_state, _legacy_colour, _parse_selector,
    _same_colour, _style_values, _stylesheet_cascade, _stylesheet_may_hide_text,
    _with_custom_properties
)
from language_coverage import has_substantial_han_text as _has_substantial_han_text
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
# A language model on this computer may review model-only alerts (development only; local_review.py).
LOCAL_REVIEW = load_local_review_settings()


def load_content_pipeline_artifact(path: Path, expected_sha256: str) -> dict:
    """Load the optional scientific stack only when ML is enabled."""
    from content_inference import load_content_pipeline_artifact as loader

    return loader(path, expected_sha256)


def predict_content(pipeline: dict, subject: str, body: str, *, canonical_text: bool = False) -> dict:
    """Run optional inference without importing training dependencies."""
    from content_inference import predict_content as predictor

    return predictor(pipeline, subject, body, canonical_text=canonical_text)


from email_structure import (
    _ORGANIZATIONAL_DOMAINS,
    _official_sender,
    _CONSUMER_MAILBOX_DOMAINS,
    organizational_domain as _organizational_domain,
    registrable_domain as _registrable_domain,
    MAILBOX_AUTHSERV_IDS,
    SENDER_ONLY_SERVICES,
    OFFICIAL_SERVICE_NUMBERS as _OFFICIAL_SERVICE_NUMBERS,
    BRAND_SITE_LABELS as _BRAND_SITE_LABELS,
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
    if request.url.path in WORKER_SCRIPT_PATHS:
        response.headers['Content-Security-Policy'] = WORKER_CONTENT_SECURITY_POLICY
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


INDEX_PAGE = BASE_DIR / "static" / "index.html"
FAVICON = BASE_DIR / "static" / "favicon.svg"


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


@app.get("/")
async def serve_index(request: Request):
    return _revalidated_file(INDEX_PAGE, request, "text/html")


# Browsers request /favicon.ico regardless of the page's <link rel="icon">.
@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon(request: Request):
    return _revalidated_file(FAVICON, request, "image/svg+xml")


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
            "rdap_lookups_enabled": SETTINGS.rdap_lookups_enabled,
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
        "rdap_lookups_enabled": SETTINGS.rdap_lookups_enabled,
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


def _relax_authenticated_sender(analysis: dict, authenticated: dict,
                                code: str = 'sender.authenticated_domain') -> dict:
    """Show, but stop scoring, address-shape findings for a DMARC- and DKIM-authenticated domain,
    or (with code sender.service_domain) a sender-only service's own domain."""
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
        analysis["risk_indicators"].append(indicator('info', code, domain=authenticated["domain"],
                                                     organization=authenticated.get("organization", "")))
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


_MIME_ALTERNATIVE_LIMIT_WARNING = message_text('warning.mime_alternative_limit')
_MIME_ALTERNATIVE_MODEL_WARNING = message_text('warning.mime_alternative_model')
# Plausible renderings the model must agree on are every reading except 'hidden'
# (strict non-Outlook, strict Outlook, and one per @media context, media_N);
# definitely hidden text may only lift the abstention.
_MAX_MIME_MODEL_VIEWS = 16
_INLINE_IMAGE_WARNING = message_text('warning.inline_images')
_REMOTE_IMAGE_WARNING = message_text('warning.remote_images')
_UNRESOLVED_IMAGE_WARNING = message_text('warning.unresolved_images')
_HAN_TEXT_WARNING = message_text('warning.han_text')
_REMOTE_IMAGE_MIN_VISIBLE_CHARS = 80


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


def _delivery_lure(text: str, links, sender_domain: str = '') -> str | None:
    """The host a delivery-fee or wrong-address lure's button leads to, off the sender's domain."""
    text = re.sub(r'\s+', ' ', text or '')
    if not (_DELIVERY_PARCEL.search(text) and (
            _DELIVERY_FEE.search(text) or (_DELIVERY_ADDRESS.search(text) and _DELIVERY_ADDRESS_FIX.search(text)))):
        return None
    for label, destination in links or ():
        if _DELIVERY_ACTION.search(label or ''):
            host = _unlisted_off_sender_host(destination, sender_domain)
            if host and _organizational_domain(host) not in _DELIVERY_TRACKING_DOMAINS:
                return host
    return None


# Domains registered this recently are named in the result (registry RDAP records).
_NEW_DOMAIN_DAYS = 90


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


# ── Mail-type note: phishing/scam vs advertising ─────────────────────────────────
# A note beside the verdict, never a change to it. "phishing" needs an alert and at least
# one concrete scam finding (a model-only alert is not enough: on genuine account and
# notification mail the model alone raises many false alerts). "advertising" needs sales
# wording; marketing from genuine brands is advertising too.
_PHISHING_TACTICS = {
    "credential": {"content.pressured_credential_request", "content.password_form", "content.mailbox_lure",
                   "content.sensitive_request.password_pin", "content.sensitive_request.one_time_code",
                   "content.sensitive_request.recovery_secret", "link.credential_collection_host",
                   "link.user_content_action", "content.attachment_account_lure", "content.attachment_mailbox_lure",
                   "link.recipient_prefilled",
                   "content.account_hold_lure"},
    "callback": {"content.callback_request"},
    "subsidy": {"content.subsidy_lure"},
    "payment": {"content.sensitive_request.gift_card", "content.sensitive_request.crypto_transfer",
                "content.large_amounts", "content.delivery_lure", "content.fine_lure"},
    "remote_access": {"content.sensitive_request.remote_access"},
    "impersonation": {"link.brand_lookalike", "link.idn_confusable", "link.brand_on_free_host",
                      "structure.brand_display_name",
                      "structure.idn_sender_domain", "sender.homoglyph_brand", "content.obfuscation",
                      "link.file_share_elsewhere", "structure.recipient_domain_display"},
    "deceptive_link": {"link.display_mismatch", "link.ip_host", "link.url_userinfo", "link.ipfs_gateway",
                       "link.dev_hosting",
                       "link.obfuscated_scheme", "link.unsafe_scheme"},
    "spoofed_sender": {"structure.auth_failed"},
    "dangerous_attachment": {"structure.dangerous_attachment"},
}
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
_SCAM_CATEGORIES = {"credential", "threats", "impersonation", "tech_scam", "financial", "urgency"}


def _advertising_terms(text: str) -> list[str]:
    """Distinct sales terms in the text, plus "unsubscribe" when an opt-out is offered."""
    lowered = (text or "").lower()
    found = [term for term in _ADVERTISING_TERMS if term in lowered]
    if any(term in lowered for term in _UNSUBSCRIBE_TERMS):
        found.append("unsubscribe")
    return found


# Notices about something the reader did themselves: a one-time code, a sign-in, a new
# account, an order or purchase, a job application, a support request. On these the
# text model alone raises most of its false alerts, and only the reader knows whether
# they did it. Deliveries, payments received, renewals, memberships and statements are
# left out: a reader expecting a parcel or a payment would say yes to the phishing that
# imitates them.
_ACCOUNT_NOTICE = re.compile("|".join((
    r"\b(?:verification|security|login|log-in|sign[- ]in|one[- ]time|confirmation|authentication|access|passcode)\s+code\b",
    r"\byour code is\b", r"\b(?:guard|launch) code\b", r"\bcode (?:you need|to (?:log ?in|sign in|verify))\b",
    r"\breset (?:your )?password\b", r"\bpassword (?:reset|changed?)\b",
    r"\b(?:confirm|verify) (?:your )?(?:email|e-mail)(?: address)?\b",
    r"\bnew (?:sign[- ]in|login|device)\b", r"\bsigned[- ]in\b", r"\bsign[- ]in (?:attempt|alert|activity)\b",
    r"\b(?:access|login|sign-in) from (?:a )?new\b", r"\bwelcome to\b",
    r"\b(?:thank you|thanks) for (?:creating|joining|signing up|registering|your (?:order|purchase|application))\b",
    r"\byour (?:new )?account (?:is (?:ready|active|created)|has been (?:created|linked|activated))\b", r"\baccount linked\b",
    r"\border (?:confirmation|confirmed|#|number)\b", r"\byour (?:order|purchase) (?:of|has been placed|is confirmed|was placed)\b",
    r"\byour application (?:for|to|at|has|was)\b", r"\bthank you for (?:applying|your interest)\b",
    r"\bjob (?:alert|recommendations?)\b", r"\b(?:ticket|request) (?:#|number|id)?\s*\w*\d",
    r"\bwe(?:'ve| have) received your (?:request|application|order|message)\b",
    r"验证码|重置密码|修改密码|登录提醒|新设备登录|确认(?:您的|你的)?邮箱",
    r"下单成功|订单(?:已确认|确认|号)|注册成功|欢迎(?:加入|注册)|申请(?:已提交|已收到|进度)|工单",
)), re.IGNORECASE)
# The left-out kinds, wherever they appear: an order number or a code inside a delivery,
# payment or renewal notice does not make it the reader's own action.
_NOT_OWN_ACTION_NOTICE = re.compile("|".join((
    r"\b(?:deliver(?:y|ies|ed)|parcels?|packages?|shipments?|shipping|shipped|couriers?|consignments?)\b",
    r"\btrack(?:ing)? (?:number|id|code|link|your (?:order|parcel|package|shipment))\b",
    r"\b(?:ups|fedex|dhl|usps|royal mail|canada post|australia post|evri|dpd|gls|aramex)\b",
    r"\b(?:payments?|refunds?|invoices?|statements?|bills?|billing|renew(?:al|als|ed|s)?|auto-?renew\w*|memberships?)\b",
    r"\b(?:you(?:'ve| have)? received|sent you) (?:a |\$|money|funds)",
    r"快递|包裹|物流|派送|配送|签收|运单|收款|到账|退款|转账|付款|扣款|账单|发票|续费|续订|自动续|会员",
)), re.IGNORECASE)


# Presentation cues that genuine notices share (many links, exclamation marks, capitals,
# "click here" twice, a doubled question mark): they add a point to the score but say
# nothing about the sender, the links or the request. They make no alert against a model
# reading below its threshold (fuse_content_risk). Counting them would stop the question
# on 10 of the 16 genuine downloads it reaches, and on 2 Nazario messages.
_PRESENTATION_CUES = frozenset({
    'content.url_count', 'content.exclamation_marks', 'content.capitalization',
    'content.generic_cta', 'content.subject_question_marks',
})


def _rests_on_text_model(result: dict) -> bool:
    """Whether an alert rests on the text model alone, so the reader's answer may settle it.

    No rule, sender, link or structure finding may stand behind it: neither a Medium
    floor nor any Medium or higher indicator (a shortened link adds to the score
    without setting a floor), presentation cues aside. Keyword categories only add to
    the score and fusion basis.
    """
    return (result.get('risk_level') in {'medium', 'high'}
            and result.get('fusion_basis') in {'model_only', 'model_led'}
            and result.get('risk_floor') in {'safe', 'low'}
            and not any(item.get('level') in {'medium', 'high', 'critical'} and item.get('code') not in _PRESENTATION_CUES
                        for item in result.get('extra_indicators', [])))


def _apply_requested_answer(result: dict, requested: str) -> None:
    """Ask, or apply the answer, for a model-driven alert on a notice of the reader's own action.

    "yes" lowers it to Low with a reminder to check the sender and links; "no" keeps it
    and says why an unrequested notice matters. It runs before the completeness check,
    so a confirmed notice whose text could not all be read still becomes unknown.
    """
    notice = result.pop('account_notice', False)
    model_driven = _rests_on_text_model(result)
    result['requested_question'] = bool(notice and model_driven and not requested)
    if not (notice and model_driven):
        return
    if requested == 'yes':
        result['risk_level'] = 'low'
        result['risk_label'] = 'Low Risk — Confirmed as Your Own Action'
        result['extra_indicators'].append(indicator('info', 'content.requested_notice'))
    elif requested == 'no':
        result['extra_indicators'].append(indicator('medium', 'content.unrequested_notice'))


async def _apply_local_review(result: dict, subject: str, body: str, hosts) -> None:
    """Ask the optional language model on this computer about an alert that rests on the
    text model alone (local_review.py).

    A legitimate reading at the configured confidence lowers the alert to Low, or in shadow
    mode only says that it would. Any other answer, or none, leaves it, and the result says
    which. With Qwen3.8 27B it lowered 26
    of the 35 alerts on the owner's pasted genuine mail. Of 3,466 Nazario phishing messages
    it lowered one, the corpus's own introduction (docs/evaluation.md).
    """
    if not (LOCAL_REVIEW.enabled and _rests_on_text_model(result)):
        return
    if addresses_reviewers(subject + '\n' + body):
        # A message that tells reviewers how to label it is never put to the model.
        result['extra_indicators'].append(indicator('info', 'content.local_review_skipped', model=LOCAL_REVIEW.model))
        return
    reading = await asyncio.to_thread(local_review, LOCAL_REVIEW, subject, body, hosts)
    if reading is None:
        result['extra_indicators'].append(indicator('info', 'content.local_review_unavailable',
                                                    model=LOCAL_REVIEW.model))
        return
    params = {'model': LOCAL_REVIEW.model, 'confidence': reading['confidence']}
    if reading['verdict'] == 'phishing':
        result['extra_indicators'].append(indicator('info', 'content.local_review_phishing', **params))
    elif reading['confidence'] < LOCAL_REVIEW.min_confidence:
        result['extra_indicators'].append(indicator('info', 'content.local_review_unsure', **params))
    elif LOCAL_REVIEW.shadow:
        result['extra_indicators'].append(indicator('info', 'content.local_review_shadow', **params))
    else:
        result['risk_level'] = 'low'
        result['risk_label'] = 'Low Risk — Read as Legitimate by a Local Model'
        result['extra_indicators'].append(indicator('info', 'content.local_review_legitimate', **params))


def _advertising(result: dict, bulk_mail: bool, *, strict: bool = False) -> bool:
    # Scams dressed as deals ("90% OFF", "limited-time offer") carry scam wording too;
    # such mail is never called advertising, whatever its sales terms.
    if {item.get("key") for item in result.get("category_results", [])} & _SCAM_CATEGORIES:
        return False
    terms = result.get("advertising_terms") or []
    sales = [term for term in terms if term != "unsubscribe"]
    return len(sales) >= 2 or bool(not strict and sales and (bulk_mail or "unsubscribe" in terms))


def _tracked_sales_links(result: dict) -> bool:
    """Every disguised link shows a host that names no registered brand and no account page.

    A click tracker behind "www.conference-2023.org" fits; a link shown as
    "https://accounts.google.com" or a bare IP never does, whatever the sales wording.
    """
    links = [item for item in result.get("extra_indicators", [])
             if item.get("code") in _PHISHING_TACTICS["deceptive_link"]
             and item.get("level") in {"medium", "high", "critical"}]
    for item in links:
        if item.get("code") != "link.display_mismatch":
            return False
        host = _decode_idna_domain(str((item.get("params") or {}).get("display_host", "")).lower().strip("."))
        if (not host or _official_sender(host)
                or any(_domains_align(host, domain) for domains in _PROTECTED_BRAND_DOMAINS.values()
                       for domain in domains)
                or set(re.split(r"[^a-z0-9]+", host)) & (_SENSITIVE_HOST_TERMS | {"accounts", "auth", "sso"})):
            return False
    return bool(links)


def _mail_type(result: dict, bulk_mail: bool) -> dict | None:
    """{"type": "phishing", "tactics": [...]} or {"type": "advertising"}, or None."""
    advertising = _advertising(result, bulk_mail)
    if result.get("risk_level") in {"medium", "high", "critical"}:
        codes = {item.get("code") for item in result.get("extra_indicators", [])
                 if item.get("level") in {"medium", "high", "critical"}}
        tactics = [tactic for tactic, members in _PHISHING_TACTICS.items() if codes & members]
        # Bulk sales mail routed through click trackers or bare IPs (predatory
        # conferences, editing and lead-generation offers) shows only the link finding.
        # With no scam wording it is advertising; the alert and its note stay.
        # Two distinct sales terms are needed here: one phrase plus an unsubscribe footer
        # also appears in phishing ("Mail Notification Alert" with a "special offer").
        if tactics and not (tactics == ["deceptive_link"] and _tracked_sales_links(result)
                            and _advertising(result, bulk_mail, strict=True)):
            return {"type": "phishing", "tactics": tactics}
    return {"type": "advertising"} if advertising else None
    terms = result.get("advertising_terms") or []
    sales = [term for term in terms if term != "unsubscribe"]
    if len(sales) >= 2 or (sales and (bulk_mail or "unsubscribe" in terms)):
        return {"type": "advertising"}
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


def analyze_email_content(subject: str, body: str, *, content_parts: list[dict] | None = None,
                          _model_view: dict | None = None, sender: str = '', recipients=()) -> dict:
    """Rule-based heuristic phishing analysis of email subject + body text."""
    analysis_warnings = []

    hidden_image_padding = []
    same_colour_letters = []

    def visible_html(part):
        part_warnings = []
        stats = {}
        readings = {}
        visible = _visible_content_text(part, part_warnings, structure_stats=stats, readings=readings)
        same_colour_letters.append(readings.get('same_colour_letters', 0))
        # Require a large explicitly concealed block and an actionable image in
        # this same HTML document. Short preheaders and text-rich mail do not qualify.
        hidden_image_padding.append(
            stats['hidden_characters'] >= 500
            and stats['visible_characters'] < _REMOTE_IMAGE_MIN_VISIBLE_CHARS
            and stats['hidden_characters'] >= 10 * max(stats['visible_characters'], 1)
            and stats['linked_visible_images'] > 0
            and not any(warning in part_warnings for warning in (
                _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
                _MSO_CONDITIONAL_WARNING, _POSSIBLY_INVISIBLE_WARNING))
            and not any('malformed' in warning.lower() or 'recovery' in warning.lower()
                        for warning in part_warnings))
        analysis_warnings.extend(part_warnings)
        stylesheet_uncertain = any(warning in part_warnings for warning in (
            _STYLESHEET_VISIBILITY_WARNING, _INLINE_CSS_VISIBILITY_WARNING,
        ))
        # With every uncertain element located, the model can score each plausible
        # rendering instead of abstaining (see _agreeing_model_views).
        earlier_uncertain = stylesheet_uncertain or any(warning in part_warnings for warning in (
            _IMAGE_ALT_FALLBACK_WARNING, _MSO_CONDITIONAL_WARNING,
        ))
        model_uncertain = earlier_uncertain or _POSSIBLY_INVISIBLE_WARNING in part_warnings
        resolved = bool(readings.get('resolved'))
        return (visible, stylesheet_uncertain, model_uncertain and not resolved,
                {key: value for key, value in readings.items()
                 if isinstance(value, str) and key not in {'certain', 'certain_off', 'all_text'}} if resolved else {},
                # Text that only box geometry may hide was scored before views existed.
                earlier_uncertain and resolved, readings.get('certain'), readings.get('rules_media') or [],
                readings.get('images_off'), readings.get('certain_off'), readings.get('rules_media_off') or [],
                # Each reading's link labels, as far as the views followed them.
                {key: readings[key] for key in ('certain_links', 'rules_media_links', 'certain_links_off',
                                                'rules_media_links_off', 'links_complete') if key in readings}
                if 'certain_links' in readings else None,
                # All the text, hidden or not, where styles may hide some of it.
                readings.get('all_text'))

    if content_parts is None:
        raw_parts = [subject, body]
        html_parts = [False, True]
        parsed_parts = [(subject, False, False, {}, False, None, [], None, None, [], None, None), visible_html(body)]
        visible_parts = [parsed[0] for parsed in parsed_parts]
        stylesheet_uncertain_parts = [parsed[1] for parsed in parsed_parts]
        model_uncertain_parts = [parsed[2] for parsed in parsed_parts]
        reading_parts = [parsed[3] for parsed in parsed_parts]
        resolved_parts = [parsed[4] for parsed in parsed_parts]
        certain_parts = [parsed[5] for parsed in parsed_parts]
        media_parts = [parsed[6] for parsed in parsed_parts]
        off_parts = [parsed[7:10] for parsed in parsed_parts]
        view_links = [parsed[10] for parsed in parsed_parts]
        all_texts = [parsed[11] for parsed in parsed_parts]
    else:
        # Each MIME part is its own document. Plain text must not be interpreted
        # as markup, nor may an unclosed tag in one part hide another part.
        raw_parts = [subject] + [part['content'] for part in content_parts]
        html_parts = [False] + [part['content_type'] == 'text/html' for part in content_parts]
        parsed_parts = [visible_html(part['content']) if part['content_type'] == 'text/html'
                        else (part['content'], False, False, {}, False, None, [], None, None, [], None, None)
                        for part in content_parts]
        visible_parts = [subject] + [parsed[0] for parsed in parsed_parts]
        stylesheet_uncertain_parts = [False] + [parsed[1] for parsed in parsed_parts]
        model_uncertain_parts = [False] + [parsed[2] for parsed in parsed_parts]
        reading_parts = [{}] + [parsed[3] for parsed in parsed_parts]
        resolved_parts = [False] + [parsed[4] for parsed in parsed_parts]
        certain_parts = [None] + [parsed[5] for parsed in parsed_parts]
        media_parts = [[]] + [parsed[6] for parsed in parsed_parts]
        off_parts = [(None, None, [])] + [parsed[7:10] for parsed in parsed_parts]
        view_links = [None] + [parsed[10] for parsed in parsed_parts]
        all_texts = [None] + [parsed[11] for parsed in parsed_parts]
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
    links, part_links_by_part = [], []
    for part, visible, is_html, stylesheet_uncertain, certain in zip(
        url_parts, visible_parts, html_parts, stylesheet_uncertain_parts, certain_parts,
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
        part_links_by_part.append((part_links, is_html and stylesheet_uncertain))

    def reading_links(parts, index=0, off=False):
        """The links of one reading with their labels. Where a stylesheet makes the
        rendering uncertain, each link's label is what that reading (index 0: the text no
        style can hide; index n: rendering view n) shows of it, children a rule hides left
        out; without views, a label counts if the reading's text shows it whole."""
        found = []
        for text, (part_links, uncertain), labels in zip(parts, part_links_by_part, view_links):
            if not uncertain:
                found.extend(part_links)
            elif labels is not None:
                certain = labels.get('certain_links_off' if off else 'certain_links') or []
                media = labels.get('rules_media_links_off' if off else 'rules_media_links') or []
                found.extend((label, destination) for label, destination
                             in (media[index - 1] if 0 < index <= len(media) else certain) if label.strip())
                if not labels.get('links_complete'):
                    # Past the budget, the labels the reading's text shows whole are read too.
                    shown = _han_compact(text or '')
                    found.extend((label, destination) for label, destination in part_links
                                 if label.strip() and _han_compact(label) in shown)
            else:
                shown = _han_compact(text or '')
                found.extend((label, destination) for label, destination in part_links
                             if label.strip() and _han_compact(label) in shown)
        return found
    # CSS may hide arbitrary body text. Do not derive high phishing scores from
    # prose that might be hidden; independent destination/form checks still run, and the
    # floor-setting request and lure rules read hidden text too, with a Medium floor (below).
    # Where every hiding rule's targets are known, the text no style can hide is scored,
    # and so is the text each @media context shows; the riskiest reading counts.
    scored_parts = [visible if not uncertain else (certain or '') for visible, uncertain, certain
                    in zip(visible_parts, stylesheet_uncertain_parts, certain_parts)]
    # Each rendering view of a part (its contexts, Outlook, undecidable text) is read too,
    # wherever views were computed: the riskiest plausible rendering counts.
    readings_for_rules = [scored_parts] + [
        [media[index] if index < len(media) else scored for scored, media in zip(scored_parts, media_parts)]
        for index in range(max((len(media) for media in media_parts), default=0))]
    readings_off = []
    if any(images_off is not None for images_off, _certain, _media in off_parts):
        # With images off, linked images show their alt text in place: the same readings,
        # each with that text where the image stands.
        scored_off = [(certain_off if certain_off is not None else scored) if uncertain
                      else (images_off if images_off is not None else scored)
                      for scored, uncertain, (images_off, certain_off, _media)
                      in zip(scored_parts, stylesheet_uncertain_parts, off_parts)]
        readings_off = [scored_off] + [
            [media[index] if index < len(media) else scored for scored, (_images, _certain, media) in zip(scored_off, off_parts)]
            for index in range(max((len(media) for _images, _certain, media in off_parts), default=0))]
    base_text = _strip_invisible_format_controls(re.sub(r'\s+', ' ', '\n'.join(scored_parts)).strip())
    if _has_substantial_han_text(base_text):
        analysis_warnings.append(_HAN_TEXT_WARNING)
    floor_rank = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    def riskiest(readings):
        # Views often share their text; each distinct text is read once.
        texts = dict.fromkeys(re.sub(r'\s+', ' ', '\n'.join(parts)).strip() for parts in readings)
        return max((_text_rule_findings(text) for text in texts),
                   key=lambda found: (floor_rank[found['floor']], found['score']))
    rules = riskiest(readings_for_rules)
    if readings_off:
        # Image fallback text counts when it holds a finding that sets a floor (a callback
        # or credential request), not for the keyword score: genuine mail labels its
        # button images "Verify your email".
        rules_off = riskiest(readings_off)
        if floor_rank[rules_off['floor']] > floor_rank[rules['floor']]:
            rules = rules_off
    analysis_text = rules['analysis_text']
    full_lower = analysis_text.lower()
    category_results = rules['categories']
    total_score = rules['score']
    presentation_score = rules['presentation']
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

    # The lures read by their buttons are checked in every reading, each with the labels
    # it shows: the riskiest plausible rendering counts for these rules as for the others.
    sender_domain = parseaddr(sender)[1].rpartition('@')[2].lower()
    display_name = parseaddr(sender)[0]
    lure_readings = dict.fromkeys(
        (_strip_invisible_format_controls(re.sub(r'\s+', ' ', '\n'.join(parts)).strip()),
         tuple(reading_links(parts, index, off)))
        for off, readings in ((False, readings_for_rules), (True, readings_off))
        for index, parts in enumerate(readings))

    def lure_findings(readings):
        """The lures any of these (text, labelled links) readings shows, as indicators."""
        mailbox_lure = user_content_action = False
        file_share = delivery_host = fine_host = hold_host = None
        for text, labelled_links in readings:
            mailbox_lure = mailbox_lure or _mailbox_lure(text, labelled_links, sender_domain)
            user_content_action = user_content_action or _user_content_action(labelled_links)
            file_share = file_share or _file_share_elsewhere(text, display_name, labelled_links, sender_domain)
            delivery_host = delivery_host or _delivery_lure(text, labelled_links, sender_domain)
            # Labels do not matter here: every destination counts, as for the link checks.
            fine_host = fine_host or _fine_lure(text, links, sender_domain)
            hold_host = hold_host or _account_hold_link(text, links, sender_domain)
        found = []
        if mailbox_lure:
            found.append(indicator('high', 'content.mailbox_lure'))
        elif user_content_action:
            found.append(indicator('high', 'link.user_content_action'))
        if file_share:
            found.append(indicator('high', 'link.file_share_elsewhere', service=file_share[0], host=file_share[1]))
        if delivery_host:
            found.append(indicator('high', 'content.delivery_lure', host=delivery_host))
        if fine_host:
            found.append(indicator('high', 'content.fine_lure', host=fine_host))
        if hold_host:
            found.append(indicator('medium', 'content.account_hold_lure', host=hold_host))
        return found

    for item in lure_findings(lure_readings):
        total_score += 4 if item['level'] == 'high' else 3
        risk_floor = max((risk_floor, item['level']), key=floor_rank.get)
        extra_indicators.append(item)

    # Text that styles may hide is read too, by the request and lure rules that set a floor
    # (not by the keyword score or the model). A rendering judgement this reader gets wrong
    # (an unusual gradient, calc() or colour; each of the eleven reviews from 2026-10-01 to
    # 10-03 found one) must not clear a scam, and a hidden request for a code, password,
    # payment or callback is a sign of one in itself. Whether the reader sees it stays
    # undecided, so a finding only this reading makes is marked and sets a Medium floor,
    # in _analyze_content after the model's renderings are chosen: it never lets the model
    # score hidden text.
    hidden_text_findings = 0
    if any(text is not None for text in all_texts):
        hidden_reading = _strip_invisible_format_controls(re.sub(r'\s+', ' ', '\n'.join(
            text if text is not None else scored for scored, text in zip(scored_parts, all_texts))).strip())
        # Each link with all of its label, wherever styles may hide some text.
        all_links = tuple(link for part, (part_links, _uncertain), text in zip(url_parts, part_links_by_part, all_texts)
                          for link in (part_links if text is None else
                                       _extract_links(part, visible_text=text, hidden_labels=True)))
        listed = {item.get('code') for item in extra_indicators}
        hidden_found = [item for item in (*_text_rule_findings(hidden_reading)['requests'],
                                          *lure_findings([(hidden_reading, all_links)]))
                        if item['code'] not in listed]
        hidden_text_findings = len(hidden_found)
        extra_indicators.extend({**wrap_message(item, 'prefix.hidden_text'), 'level': 'medium'}
                                for item in hidden_found)
    prefilled_host = _recipient_prefilled_link(links, recipients, sender_domain)
    if prefilled_host:
        total_score += 3
        risk_floor = max((risk_floor, 'medium'), key=floor_rank.get)
        extra_indicators.append(indicator('medium', 'link.recipient_prefilled', host=prefilled_host))
    # Hidden-text salting: a block of text in its background's colour, which no reader
    # sees, padding the message for filters (white Wikipedia paragraphs under "Sorry we
    # missed you"). 15 of 3,466 Nazario messages hide 200 letters or more this way; none
    # of the 92 genuine downloads, DataCon day 1 or the 87 public templates hides any.
    padding = max(same_colour_letters, default=0)
    if padding >= _SAME_COLOUR_MODEL_LETTERS:
        total_score += 3
        risk_floor = max((risk_floor, 'medium'), key=floor_rank.get)
        extra_indicators.append(indicator('medium', 'content.hidden_padding', letters=padding))

    extra_indicators.extend(rules['style'])

    # 6. Excessive question marks in subject
    subj_q = scored_parts[0].count("?")
    if subj_q >= 2:
        total_score += 1
        presentation_score += 1
        extra_indicators.append(indicator("medium", "content.subject_question_marks", count=subj_q))

    # 7. High URL count
    url_count = _count_urls(links)
    if url_count > 6:
        total_score += 1
        presentation_score += 1
        extra_indicators.append(indicator("medium", "content.url_count", count=url_count))

    extra_indicators.extend(rules['wording'])
    # The sender's display name ("PayPaI", "AppIe ltunes") is not part of the text.
    if not any(item.get('code') == 'content.obfuscation' for item in rules['wording']):
        display_obfuscated = _detect_obfuscation(parseaddr(sender)[0])
        if display_obfuscated:
            total_score += 3
            extra_indicators.append(indicator('high', 'content.obfuscation', brands=', '.join(display_obfuscated)))

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
        # For the fusion only; removed before the response.
        "presentation_score": presentation_score,
        "hidden_text_findings": hidden_text_findings,
        "category_results":  category_results,
        "extra_indicators":  extra_indicators,
        "safety_signals":    safety_found,
        "url_count":         url_count,
        "advertising_terms": _advertising_terms(analysis_text),
        "account_notice": bool(_ACCOUNT_NOTICE.search(analysis_text)
                               and not _NOT_OWN_ACTION_NOTICE.search(analysis_text)),
        "has_ip_url":        _has_ip_url(raw_text, links=links),
        "has_shortener":     _has_shortener_url(raw_text, links=links),
        "risk_floor":        risk_floor,
        # For registration-date lookups only; removed before the response.
        "link_hosts":        _link_hosts(links),
    }


class ContentRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=50_000)
    raw_email: str = Field(default="", max_length=60_000)
    # The reader's answer to "Did you do this yourself?" for a model-driven notice of their own action.
    requested: Literal['', 'yes', 'no'] = ''


def fuse_content_risk(
    *,
    ml_phishing_probability: float | None,
    ml_decision_threshold: float,
    heuristic_score: int,
    presentation_score: int = 0,
    minimum_level: str = "safe",
    raw_message: bool = False,
) -> dict:
    """Conservatively fuse independent evidence without averaging it away.

    raw_message: the text came with an original message (an .eml or raw headers), whose
    sender, authentication and structure were read too.
    """
    ml_risk = 0.0 if ml_phishing_probability is None else min(
        1.0, max(0.0, ml_phishing_probability)
    )
    model_signal = ml_phishing_probability is not None and ml_risk >= ml_decision_threshold
    # Presentation cues (_PRESENTATION_CUES) back a model alert but never outweigh the model's
    # reading: genuine notices share them, and they say nothing about the sender, the links
    # or the request. When the model reads the text as legitimate, the rule score leaves them
    # out; when it gives no reading, they count as before. Callers pass 0 when any other
    # reading of the message reaches the threshold.
    model_reads_legitimate = ml_phishing_probability is not None and not model_signal
    rule_score = heuristic_score - presentation_score if model_reads_legitimate else heuristic_score
    heuristic_risk = min(1.0, max(0.0, rule_score / 16.0))
    floor_scores = {
        "safe": 0.0,
        "low": 0.10,
        "medium": 0.30,
        "high": 0.55,
        "critical": 0.80,
    }
    floor_score = max(floor_scores.get(minimum_level, 0.0), 0.10 if heuristic_score > 0 else 0.0)
    # A high model score alone is not enough to justify a Critical label.
    independent_support = heuristic_score >= 9 or minimum_level in {"high", "critical"}
    model_only = model_signal and heuristic_score == 0 and minimum_level == "safe"
    model_led = model_signal and not independent_support and not model_only
    # Below its decision threshold the model reads the text as legitimate (the threshold was
    # chosen within a 20% false-positive budget, so a 30–37% probability lies inside it): it
    # counts at most as Low (29%). Above it, with no rule, sender, link or structure evidence,
    # an original message's reading is a note, not an alert, counted the same way: its sender,
    # authentication and structure were read and showed nothing. Pasted text and screenshots
    # carry none of that, so there it stays an alert for review. The owner chose this on
    # 2026-10-05: a note everywhere cost 25 to 56 points of recall on pasted public corpora
    # (docs/evaluation.md). ml_phishing_probability keeps the model's reading either way.
    model_note = model_only and raw_message
    model_counted = ml_risk if model_signal and not model_note else min(ml_risk, 0.29)
    combined = max(heuristic_risk, model_counted, floor_score)

    if minimum_level == "critical" or heuristic_risk >= 0.80 or (ml_risk >= 0.80 and independent_support):
        level, label = "critical", "Critical Risk — Very Likely Phishing"
    elif minimum_level == "high" or heuristic_risk >= 0.55 or (model_signal and not model_only):
        level = "high"
        label = "High Risk — Model Signal Needs Review" if model_led else "High Risk — Likely Phishing"
    elif model_note:
        level, label = "low", "Low Risk — Text Model Signal Only"
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


def _fused_decision(fused: dict) -> bool:
    """Whether a fused result alerts or carries a text-model note: the decision that
    plausible renderings must agree on. A model-only note counts (it was a Medium alert
    until 2026-10-05), so text that may be hidden can neither add one nor take one away."""
    return fused['risk_level'] in {'medium', 'high', 'critical'} or fused['fusion_basis'] == 'model_only'


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


def _agreeing_model_views(bodies, view_readings, predictions, *, threshold, heuristic_score, minimum_level,
                          presentation_score=0):
    """Keep the MIME views whose plausible renderings all lead to the same decision.

    The decision is whether the fused result alerts (Medium or above) or carries a
    text-model note (_fused_decision). Each kept (body, prediction) is scored at its
    highest-risk rendering. A view whose renderings disagree is
    dropped, so text that may be hidden can neither dilute a phishing message nor
    pad a benign one into an alert. Returns the kept predictions, whether every view
    was checked this way, and whether adding definitely hidden text (excluded from
    every rendering) would also leave each decision unchanged.
    """
    def level(prediction):
        probability = prediction['_phishing_probability']
        return None if probability is None else _fused_decision(fuse_content_risk(
            ml_phishing_probability=probability, ml_decision_threshold=threshold,
            heuristic_score=heuristic_score, presentation_score=presentation_score, minimum_level=minimum_level,
        ))
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
    query = parse_qs(request.scope.get('query_string', b'').decode('latin-1'))
    mailbox = query.get('mailbox', [''])[-1]
    if mailbox not in {'', *MAILBOX_AUTHSERV_IDS}:
        raise HTTPException(status_code=400, detail='Unsupported mailbox; use gmail, outlook or leave it empty')
    requested = query.get('requested', [''])[-1]
    if requested not in {'', 'yes', 'no'}:
        raise HTTPException(status_code=400, detail='Unsupported requested answer; use yes, no or leave it empty')
    structure = await _run_analysis(analyze_raw_email, bytes(raw),
                                    trusted_authserv_ids=SETTINGS.trusted_authserv_ids,
                                    mailbox_provider=mailbox or None)
    return await _analyze_content(ContentRequest(requested=requested), structure)


async def _analyze_content(
    request: ContentRequest,
    structure: dict | None = None,
    *,
    observe_sender_history: bool = True,
    plain_text: bool = False,
    allow_empty: bool = False,
    raw_message: bool | None = None,
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
    # Whether the text came with an original message (fuse_content_risk); text extracted
    # from an uploaded .eml's images is part of that message.
    raw_message = structure is not None if raw_message is None else raw_message
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
                                   _model_view=model_view, sender=structure['from'] if structure else '',
                                   recipients=[address for name in ('To', 'Cc') for value in
                                               (structure['header_candidates'][name] if structure else ())
                                               for _name, address in getaddresses([value]) if '@' in address])
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
                "sending_server",
            )
        }
        floor_rank = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if floor_rank[structure["risk_floor"]] > floor_rank[result["risk_floor"]]:
            result["risk_floor"] = structure["risk_floor"]

        # Link annotations read from PDF attachments and hyperlinks read from Word
        # attachments go through the same destination checks as message links.
        for is_docx, prefix in ((False, 'prefix.pdf_attachment'), (True, 'prefix.docx_attachment')):
            attachment_links = [('', target) for attachment in structure['attachments']
                                if _is_docx(attachment) == is_docx
                                for target in attachment.get('extracted_links', ())]
            if not attachment_links:
                continue
            link_score, link_findings, link_floor = _analyze_link_destinations('', links=attachment_links)
            if _has_shortener_url('', links=attachment_links):
                link_score += 2
                link_findings.append(indicator('high', 'content.shortened_urls'))
            result["total_score"] += link_score
            result["extra_indicators"].extend(
                wrap_message({key: item[key] for key in ('level', 'msg', 'code', 'params', 'prefixes') if key in item},
                             prefix)
                for item in link_findings)
            if floor_rank[link_floor] > floor_rank[result["risk_floor"]]:
                result["risk_floor"] = link_floor
            result["docx_link_count" if is_docx else "pdf_link_count"] = len(attachment_links)

        # Word and PDF attachment text: lures often sit in the attachment while the body
        # has a line or none (a callback "invoice"). Only strong requests are scored here,
        # never keyword categories: genuine contracts, quotes and invoices are full of
        # "payment", "invoice" and "urgent". An account-hold lure also needs the
        # attachment's own link to leave the sender's domain.
        text_findings = []
        sender_domain = parseaddr(structure['from'])[1].rpartition('@')[2].lower()
        for is_docx, prefix in ((True, 'prefix.docx_text'), (False, 'prefix.pdf_text')):
            attachment_text = '\n'.join(attachment['extracted_text'] for attachment in structure['attachments']
                                         if attachment.get('extracted_text') and _is_docx(attachment) == is_docx)
            if attachment_text:
                text_findings.extend(wrap_message(item, prefix) for item in _attachment_text_findings(attachment_text))
            lure_host = next(filter(None, (_attachment_account_lure(attachment, sender_domain)
                                           for attachment in structure['attachments']
                                           if attachment.get('extracted_text') and _is_docx(attachment) == is_docx)), None)
            if lure_host:
                text_findings.append(wrap_message(indicator('high', 'content.attachment_account_lure', domain=lure_host),
                                                  prefix))
            mailbox_host = next(filter(None, (_attachment_mailbox_lure(attachment, sender_domain)
                                              for attachment in structure['attachments']
                                              if attachment.get('extracted_text') and _is_docx(attachment) == is_docx)),
                                None)
            if mailbox_host:
                text_findings.append(wrap_message(indicator('high', 'content.attachment_mailbox_lure', domain=mailbox_host),
                                                  prefix))
        if text_findings:
            result["total_score"] += 4
            result["risk_floor"] = max(result["risk_floor"], 'high', key=floor_rank.__getitem__)
            result["extra_indicators"].extend(text_findings)

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
            service_domain = structure.get('service_domain_sender')
            if service_domain and selected_sender["email"].rpartition("@")[2].lower() == service_domain["domain"]:
                selected_sender = _relax_authenticated_sender(selected_sender, service_domain,
                                                              'sender.service_domain')
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
        _IMAGE_ALT_FALLBACK_WARNING, _MSO_CONDITIONAL_WARNING, _POSSIBLY_INVISIBLE_WARNING,
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
            # Presentation cues give way only to a model that reads every view and rendering
            # as legitimate; one reading at the threshold keeps them in the rule score.
            if any(prediction['_phishing_probability'] is not None and prediction['_phishing_probability'] >= threshold
                   for prediction in predictions.values()):
                result['presentation_score'] = 0
            kept, rendering_resolved, hidden_agrees = _agreeing_model_views(
                bodies, view_readings, predictions, threshold=threshold,
                heuristic_score=result['total_score'], minimum_level=result['risk_floor'],
                presentation_score=result['presentation_score'])

        def alerts(ml):
            return _fused_decision(fuse_content_risk(
                ml_phishing_probability=ml['_phishing_probability'], ml_decision_threshold=threshold,
                heuristic_score=result['total_score'], presentation_score=result['presentation_score'],
                minimum_level=result['risk_floor'],
            ))
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
                                 _MSO_CONDITIONAL_WARNING, _IMAGE_ALT_FALLBACK_WARNING, _POSSIBLY_INVISIBLE_WARNING}
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
        ml_threshold = float(_content_pipeline.get("decision_threshold", 0.5))
    else:
        ml_probability, ml_threshold = None, 0.5
    # A request or lure found only in text that styles may hide sets a Medium floor now that
    # the model's renderings are chosen without it (analyze_email_content).
    if result.pop("hidden_text_findings"):
        result["total_score"] += 3
        if result["risk_floor"] in {"safe", "low"}:
            result["risk_floor"] = "medium"
    result.update(fuse_content_risk(
        ml_phishing_probability=ml_probability,
        ml_decision_threshold=ml_threshold,
        heuristic_score=result["total_score"],
        presentation_score=result["presentation_score"],
        minimum_level=result["risk_floor"],
        raw_message=raw_message,
    ))
    del result["presentation_score"]

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
    if verified_sender and result['risk_floor'] in {'safe', 'low'} and (
            result['risk_level'] in {'medium', 'high'} or result.get('fusion_basis') == 'model_only'):
        result['risk_level'] = 'low'
        result['risk_label'] = 'Low Risk — Verified Official Sender'

    if structure and any(item['inspection_status'] == 'metadata_only'
                         for item in structure['attachments']):
        item = indicator('info', 'warning.attachments_uninspected')
        result['analysis_warnings'].append(item['msg'])
        result['extra_indicators'].append(item)

    # Registration dates of the sender's and the links' domains, from the registries'
    # RDAP servers where the deployment enables it. Context only: no points.
    link_hosts = result.get('link_hosts', [])
    candidates = _registration_candidates(structure['from'] if structure else '', result.pop('link_hosts', []))
    if SETTINGS.rdap_lookups_enabled and candidates:
        dates = await domain_age.lookup_many_async([domain for _role, domain in candidates])
        result['domain_registrations'] = {domain: date.date().isoformat() if date else None
                                          for domain, date in dates.items()}
        result['extra_indicators'].extend(_registration_findings(candidates, dates))

    result['analysis_warnings'] = list(dict.fromkeys(result['analysis_warnings']
        + (structure['parse_warnings'] if structure else [])))
    result['analysis_complete'] = not bool(result['analysis_warnings'])
    await _apply_local_review(result, model_view.get('subject', ''), model_view.get('body', ''), link_hosts)
    _apply_requested_answer(result, request.requested)
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
    result['mail_type'] = _mail_type(result, bool(structure and structure.get('bulk_mail')))
    result.pop('advertising_terms', None)
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
        ContentRequest(subject=payload.subject, body=payload.body, requested=payload.requested), structure,
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
                plain_text=True, allow_empty=True, raw_message=raw is not None,
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
