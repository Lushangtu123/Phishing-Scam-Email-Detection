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
import re
import threading
import time
import warnings
from collections import deque
from email.utils import getaddresses, parseaddr
from itertools import product
from functools import partial
from urllib.parse import parse_qs

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from typing import Literal, NamedTuple

from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from config import load_settings
import domain_age
import sms_analysis
from case_api import build_case_service, make_case_router, public_jev_status
from feedback_api import make_feedback_router
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
    _HIDDEN_HTML_TEXT_WARNING, _IMAGE_ALT_FALLBACK_WARNING,
    _INLINE_CSS_VISIBILITY_WARNING, _MSO_CONDITIONAL_WARNING, _POSSIBLY_INVISIBLE_WARNING,
    _SAME_COLOUR_MODEL_LETTERS, _STYLESHEET_VISIBILITY_WARNING, _strip_invisible_format_controls, _visible_content_text
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
    _official_sender,
    MAILBOX_AUTHSERV_IDS,
    SENDER_ONLY_SERVICES,
    official_channels as _official_channels,
    _PROTECTED_BRAND_DOMAINS,
    _decode_idna_domain,
    _domains_align,
    analyze_raw_email,
)
from sender_features import (
    SUSPICIOUS_KEYWORDS,
    _match_domain_registry,
    extract_email_features,
    _normalize_sender_address,
)
from http_policy import (
    _build_allowed_hosts,
    _rate_limit_key,
    _record_rate_limit_hit,
    VERSIONED_ASSET_CACHE_CONTROL,
    WORKER_SCRIPT_PATHS,
    WORKER_CONTENT_SECURITY_POLICY,
    _with_security_headers,
    _revalidated_file,
    _wants_not_found_page,
)
from link_analysis import (
    _analyze_link_destinations,
    _count_urls,
    _extract_links,
    _has_ip_url,
    _has_shortener_url,
    _link_hosts,
    _SENSITIVE_HOST_TERMS,
)
from content_rules import (
    _account_hold_link,
    _advertising_terms,
    _attachment_account_lure,
    _attachment_mailbox_lure,
    _attachment_text_findings,
    _delivery_lure,
    _detect_obfuscation,
    _discount_claimed_brand,
    _file_share_elsewhere,
    _fine_lure,
    _han_compact,
    _has_password_form,
    _image_reference_counts,
    _is_docx,
    _lure_points,
    _mailbox_lure,
    _mask_inline_data_payloads,
    _recipient_prefilled_link,
    _registration_candidates,
    _registration_findings,
    _sms_delivery_lure,
    _text_rule_findings,
    _user_content_action,
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


allowed_hosts = _build_allowed_hosts(
    os.getenv("ALLOWED_HOSTS", "*.onrender.com,localhost,127.0.0.1,testserver"),
    os.getenv("CUSTOM_DOMAINS", ""),
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES,
                   path_limits={**{path: MAX_VISUAL_REQUEST_BYTES for path in VISUAL_PATHS},
                                '/api/feedback': 100_000, '/api/analyze-sms': 16_000})

_rate_limit_lock = threading.Lock()
_rate_limit_buckets: dict[str, deque[float]] = {}


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


@app.get("/")
async def serve_index(request: Request):
    return _revalidated_file(INDEX_PAGE, request, "text/html")


# Browsers request /favicon.ico regardless of the page's <link rel="icon">.
@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon(request: Request):
    return _revalidated_file(FAVICON, request, "image/svg+xml")


# ── Not-found page ────────────────────────────────────────────────────────────
NOT_FOUND_PAGE = BASE_DIR / "static" / "404.html"
_not_found_page_body: bytes | None = None


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
        "sms_analysis_enabled": SETTINGS.sms_analysis_enabled,
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
_SCAM_CATEGORIES = {"credential", "threats", "impersonation", "tech_scam", "financial", "urgency"}


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


class _PartReading(NamedTuple):
    """What one part of a message shows: plain text as it is, HTML as the HTML/CSS reader reads it."""
    visible: str
    # A stylesheet or inline style may hide text the reader cannot place.
    stylesheet_uncertain: bool
    # The model cannot score this part's rendering, and no rendering views resolved it.
    model_uncertain: bool
    # The rendering views the model scores, where the views resolved the uncertainty.
    readings: dict
    # Text that only box geometry may hide was scored before views existed.
    resolved: bool
    # The text no style can hide, and the text each rendering view shows, for the rules.
    certain: str | None
    rules_media: list
    # The same with images off: linked images show their alt text in place.
    images_off: str | None
    certain_off: str | None
    rules_media_off: list
    # Each reading's link labels, as far as the views followed them.
    link_labels: dict | None
    # All the text, hidden or not, where styles may hide some of it.
    all_text: str | None


def _plain_part(text: str) -> _PartReading:
    return _PartReading(text, False, False, {}, False, None, [], None, None, [], None, None)


def _read_html_part(part: str, analysis_warnings: list) -> tuple[_PartReading, bool, int]:
    """One HTML part as read; whether it hides a large block beside a linked image (hidden
    image padding); and how many letters it writes in their background's colour."""
    part_warnings = []
    stats = {}
    readings = {}
    visible = _visible_content_text(part, part_warnings, structure_stats=stats, readings=readings)
    same_colour_letters = readings.get('same_colour_letters', 0)
    # Require a large explicitly concealed block and an actionable image in
    # this same HTML document. Short preheaders and text-rich mail do not qualify.
    hidden_image_padding = (
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
    reading = _PartReading(
        visible=visible,
        stylesheet_uncertain=stylesheet_uncertain,
        model_uncertain=model_uncertain and not resolved,
        readings={key: value for key, value in readings.items()
                  if isinstance(value, str) and key not in {'certain', 'certain_off', 'all_text'}} if resolved else {},
        resolved=earlier_uncertain and resolved,
        certain=readings.get('certain'),
        rules_media=readings.get('rules_media') or [],
        images_off=readings.get('images_off'),
        certain_off=readings.get('certain_off'),
        rules_media_off=readings.get('rules_media_off') or [],
        link_labels={key: readings[key] for key in ('certain_links', 'rules_media_links', 'certain_links_off',
                                                    'rules_media_links_off', 'links_complete') if key in readings}
        if 'certain_links' in readings else None,
        all_text=readings.get('all_text'))
    return reading, hidden_image_padding, same_colour_letters


def _read_parts(subject: str, body: str, content_parts: list[dict] | None, analysis_warnings: list):
    """The subject and each part: their original text, which are HTML, how each reads, and
    for each HTML part its hidden image padding and same-colour letter count."""
    hidden_image_padding = []
    same_colour_letters = []

    def read_html(part):
        reading, padding, letters = _read_html_part(part, analysis_warnings)
        hidden_image_padding.append(padding)
        same_colour_letters.append(letters)
        return reading

    if content_parts is None:
        raw_parts = [subject, body]
        html_parts = [False, True]
        parts = [_plain_part(subject), read_html(body)]
    else:
        # Each MIME part is its own document. Plain text must not be interpreted
        # as markup, nor may an unclosed tag in one part hide another part.
        raw_parts = [subject] + [part['content'] for part in content_parts]
        html_parts = [False] + [part['content_type'] == 'text/html' for part in content_parts]
        parts = [_plain_part(subject)] + [read_html(part['content']) if part['content_type'] == 'text/html'
                                          else _plain_part(part['content'])
                                          for part in content_parts]
    return raw_parts, html_parts, parts, hidden_image_padding, same_colour_letters


def _build_model_views(model_view: dict, parts: list[_PartReading], content_parts: list[dict] | None) -> None:
    """Fill model_view with what the model scores: the subject, the body, and the body as each
    MIME alternative shows it, with its rendering views and whether its rendering is uncertain."""
    model_uncertain_parts = [part.model_uncertain for part in parts]
    resolved_parts = [part.resolved for part in parts]

    # The model and rule checks consume the same MIME-aware visible text.
    def normalized(part):
        return re.sub(r'\s+', ' ', _strip_invisible_format_controls(part)).strip()
    model_parts = [normalized(part.visible) for part in parts]
    reading_texts = [{key: normalized(text) for key, text in part.readings.items()} for part in parts]
    reading_keys = sorted(set().union(*reading_texts))

    def view_readings(included):
        views = {}
        for key in reading_keys:
            if any(key in texts for texts, use in zip(reading_texts[1:], included) if use):
                views[key] = '\n'.join(texts.get(key, model) for model, texts, use
                                       in zip(model_parts[1:], reading_texts[1:], included) if use).strip()
        return views
    model_view['subject'] = model_parts[0]
    model_view['body'] = '\n'.join(model_parts[1:]).strip()
    model_view['mime_views'] = [(model_view['body'], any(model_uncertain_parts[1:]))]
    model_view['view_readings'] = {model_view['body']: [view_readings([True] * (len(model_parts) - 1))]}
    # Views the model could not score before rendering views existed.
    model_view['resolved_views'] = {model_view['body']} if any(resolved_parts[1:]) else set()
    if content_parts is None:
        return
    choices = {}
    for part in content_parts:
        for path in part.get('alternative_paths', [()]):
            for group, branch in path:
                choices.setdefault(group, set()).add(branch)
    if not choices:
        return
    groups = sorted(choices)
    views = {}
    defaults = tuple(min(choices[group]) for group in groups)
    combinations = 1
    for group in groups:
        combinations *= len(choices[group])
        if combinations > _MAX_MIME_MODEL_VIEWS:
            model_view['mime_alternatives_truncated'] = True
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
    model_view['mime_views'] = list(views.items())
    model_view['view_readings'] = readings_by_view
    model_view['resolved_views'] = {body for body, uncertain in earlier_uncertain.items() if uncertain}


def _image_coverage(raw_parts: list[str], parts: list[_PartReading], html_parts: list[bool],
                    analysis_warnings: list, model_view: dict | None) -> tuple[int, int, int]:
    """Inline, remote and unresolved image counts of the HTML parts (each at most 20), with their
    warnings; model_view also learns whether a remote image is some part's main content."""
    html_image_parts = [(part, reading.visible) for part, reading, is_html
                        in zip(raw_parts[1:], parts[1:], html_parts[1:]) if is_html]
    image_counts = [_image_reference_counts(part, analysis_warnings)
                    for part, _visible in html_image_parts]
    image_count = min(20, sum(counts[0] for counts in image_counts))
    remote_image_count = min(20, sum(counts[1] for counts in image_counts))
    unresolved_image_count = min(20, sum(counts[2] for counts in image_counts))
    if model_view is not None:
        model_view['remote_image_dominant'] = any(
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
    return image_count, remote_image_count, unresolved_image_count


_FLOOR_RANK = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _collect_links(url_parts: list[str], parts: list[_PartReading], html_parts: list[bool],
                   analysis_warnings: list) -> tuple[list, list]:
    """The message's links, and per part its links with whether styles make its rendering
    uncertain. Where they do, the message's links keep their destinations but lose labels."""
    links, part_links_by_part = [], []
    for part, reading, is_html in zip(url_parts, parts, html_parts):
        visible, stylesheet_uncertain = reading.visible, reading.stylesheet_uncertain
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
    return links, part_links_by_part


def _reading_links(texts: list, part_links_by_part: list, parts: list[_PartReading],
                   index: int = 0, off: bool = False) -> list:
    """The links of one reading with their labels. Where a stylesheet makes the
    rendering uncertain, each link's label is what that reading (index 0: the text no
    style can hide; index n: rendering view n) shows of it, children a rule hides left
    out; without views, a label counts if the reading's text shows it whole."""
    found = []
    for text, (part_links, uncertain), labels in zip(texts, part_links_by_part,
                                                     [part.link_labels for part in parts]):
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


def _rule_readings(parts: list[_PartReading]) -> tuple[list, list, list]:
    """The text the rules score (per part), and every reading of the message the rules read:
    with images shown, and with images off where some part's images have alt text."""
    # CSS may hide arbitrary body text. Do not derive high phishing scores from
    # prose that might be hidden; independent destination/form checks still run, and the
    # floor-setting request and lure rules read hidden text too, with a Medium floor (below).
    # Where every hiding rule's targets are known, the text no style can hide is scored,
    # and so is the text each @media context shows; the riskiest reading counts.
    scored_parts = [part.visible if not part.stylesheet_uncertain else (part.certain or '') for part in parts]
    media_parts = [part.rules_media for part in parts]
    # Each rendering view of a part (its contexts, Outlook, undecidable text) is read too,
    # wherever views were computed: the riskiest plausible rendering counts.
    readings_for_rules = [scored_parts] + [
        [media[index] if index < len(media) else scored for scored, media in zip(scored_parts, media_parts)]
        for index in range(max((len(media) for media in media_parts), default=0))]
    readings_off = []
    off_parts = [(part.images_off, part.certain_off, part.rules_media_off) for part in parts]
    if any(images_off is not None for images_off, _certain, _media in off_parts):
        # With images off, linked images show their alt text in place: the same readings,
        # each with that text where the image stands.
        scored_off = [(certain_off if certain_off is not None else scored) if part.stylesheet_uncertain
                      else (images_off if images_off is not None else scored)
                      for scored, part, (images_off, certain_off, _media)
                      in zip(scored_parts, parts, off_parts)]
        readings_off = [scored_off] + [
            [media[index] if index < len(media) else scored for scored, (_images, _certain, media) in zip(scored_off, off_parts)]
            for index in range(max((len(media) for _images, _certain, media in off_parts), default=0))]
    return scored_parts, readings_for_rules, readings_off


def _riskiest_rules(readings: list) -> dict:
    """The rule findings of the riskiest reading: by floor, then by score."""
    # Views often share their text; each distinct text is read once.
    texts = dict.fromkeys(re.sub(r'\s+', ' ', '\n'.join(parts)).strip() for parts in readings)
    return max((_text_rule_findings(text) for text in texts),
               key=lambda found: (_FLOOR_RANK[found['floor']], found['score']))


def _lure_findings(readings, links: list, sender_domain: str, display_name: str) -> list[dict]:
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


def _hidden_text_findings(scored_parts: list, parts: list[_PartReading], url_parts: list[str],
                          part_links_by_part: list, listed: list[dict], links: list,
                          sender_domain: str, display_name: str) -> list[dict]:
    """Requests and lures found only once text that styles may hide is read too, and not
    already listed. Empty unless some part's styles may hide text."""
    # Text that styles may hide is read too, by the request and lure rules that set a floor
    # (not by the keyword score or the model). A rendering judgement this reader gets wrong
    # (an unusual gradient, calc() or colour; each of the eleven reviews from 2026-10-01 to
    # 10-03 found one) must not clear a scam, and a hidden request for a code, password,
    # payment or callback is a sign of one in itself. Whether the reader sees it stays
    # undecided, so a finding only this reading makes is marked and sets a Medium floor,
    # in _analyze_content after the model's renderings are chosen: it never lets the model
    # score hidden text.
    all_texts = [part.all_text for part in parts]
    if not any(text is not None for text in all_texts):
        return []
    hidden_reading = _strip_invisible_format_controls(re.sub(r'\s+', ' ', '\n'.join(
        text if text is not None else scored for scored, text in zip(scored_parts, all_texts))).strip())
    # Each link with all of its label, wherever styles may hide some text.
    all_links = tuple(link for part, (part_links, _uncertain), text in zip(url_parts, part_links_by_part, all_texts)
                      for link in (part_links if text is None else
                                   _extract_links(part, visible_text=text, hidden_labels=True)))
    listed_codes = {item.get('code') for item in listed}
    return [item for item in (*_text_rule_findings(hidden_reading)['requests'],
                              *_lure_findings([(hidden_reading, all_links)], links, sender_domain, display_name))
            if item['code'] not in listed_codes]


def _content_verdict(total_score: int, risk_floor: str) -> tuple[str, str]:
    """The content level and label from the rule score and the floor its findings set."""
    if total_score > 15:
        return "critical", "Critical Risk — Very Likely Phishing"
    elif risk_floor == "high":
        return "high", "High Risk — Likely Phishing"
    elif risk_floor == "medium" and total_score <= 8:
        return "medium", "Medium Risk — Suspicious Content"
    elif total_score == 0:
        return "safe",     "No Phishing Indicators Found"
    elif total_score <= 3:
        return "low",      "Low Risk — Minor Concerns"
    elif total_score <= 8:
        return "medium",   "Medium Risk — Suspicious Content"
    else:
        return "high",     "High Risk — Likely Phishing"


def analyze_email_content(subject: str, body: str, *, content_parts: list[dict] | None = None,
                          _model_view: dict | None = None, sender: str = '', recipients=()) -> dict:
    """Rule-based heuristic phishing analysis of email subject + body text."""
    analysis_warnings = []
    raw_parts, html_parts, parts, hidden_image_padding, same_colour_letters = _read_parts(
        subject, body, content_parts, analysis_warnings)
    raw_parts = [_strip_invisible_format_controls(part) for part in raw_parts]
    if _model_view is not None:
        _build_model_views(_model_view, parts, content_parts)
    image_count, remote_image_count, unresolved_image_count = _image_coverage(
        raw_parts, parts, html_parts, analysis_warnings, _model_view)
    url_parts = [_mask_inline_data_payloads(part) if is_html else part
                 for part, is_html in zip(raw_parts, html_parts)]
    raw_text = '\n'.join(url_parts)
    links, part_links_by_part = _collect_links(url_parts, parts, html_parts, analysis_warnings)
    scored_parts, readings_for_rules, readings_off = _rule_readings(parts)
    base_text = _strip_invisible_format_controls(re.sub(r'\s+', ' ', '\n'.join(scored_parts)).strip())
    if _has_substantial_han_text(base_text):
        analysis_warnings.append(_HAN_TEXT_WARNING)
    floor_rank = _FLOOR_RANK
    rules = _riskiest_rules(readings_for_rules)
    if readings_off:
        # Image fallback text counts when it holds a finding that sets a floor (a callback
        # or credential request), not for the keyword score: genuine mail labels its
        # button images "Verify your email".
        rules_off = _riskiest_rules(readings_off)
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
        (_strip_invisible_format_controls(re.sub(r'\s+', ' ', '\n'.join(texts)).strip()),
         tuple(_reading_links(texts, part_links_by_part, parts, index, off)))
        for off, readings in ((False, readings_for_rules), (True, readings_off))
        for index, texts in enumerate(readings))

    for item in _lure_findings(lure_readings, links, sender_domain, display_name):
        total_score += _lure_points(item)
        risk_floor = max((risk_floor, item['level']), key=floor_rank.get)
        extra_indicators.append(item)

    # Text that styles may hide: its requests and lures are marked and set a Medium floor
    # in _analyze_content (see _hidden_text_findings).
    hidden_found = _hidden_text_findings(scored_parts, parts, url_parts, part_links_by_part, extra_indicators,
                                         links, sender_domain, display_name)
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

    risk_level, risk_label = _content_verdict(total_score, risk_floor)

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


def analyze_sms(sender: str, text: str) -> dict:
    """A text message: the SMS rules (sms_analysis.py) beside the plain-text rules texts share
    with email, scored as email is. No text model: it was trained on email. With no finding
    the verdict is unknown, never safe: a text's sender cannot be verified."""
    floor_rank = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    sms = sms_analysis.sms_findings(sender, text)
    text, links = sms_analysis.clean_text(text), sms['links']
    rules = _text_rule_findings(text)
    _discount_claimed_brand(rules, sms['claimed_names'])
    score, floor = rules['score'] + sms['score'], max((rules['floor'], sms['floor']), key=floor_rank.get)
    indicators = [*rules['requests'], *rules['style'], *rules['wording'], *sms['indicators']]
    if _has_shortener_url(text, links=links):
        score += 2
        indicators.append(indicator('high', 'content.shortened_urls'))
    link_score, link_findings, link_floor = _analyze_link_destinations(text, links=links)
    score += link_score
    floor = max((floor, link_floor), key=floor_rank.get)
    indicators.extend(link_findings)
    for code, host in (('sms.fine_lure', _fine_lure(text, links)), ('sms.delivery_lure', _sms_delivery_lure(text, links))):
        if host:
            item = indicator('high', code, host=host)
            score += _lure_points(item)
            floor = max((floor, item['level']), key=floor_rank.get)
            indicators.append(item)
    fused = fuse_content_risk(ml_phishing_probability=None, ml_decision_threshold=1.0, heuristic_score=score,
                              minimum_level=floor)
    result = {
        'risk_level': fused['risk_level'], 'risk_label': fused['risk_label'], 'total_score': score,
        'category_results': rules['categories'], 'extra_indicators': indicators,
        'sender_kind': sms['sender_kind'], 'claimed_brand': sms['claimed_brand'],
        'link_hosts': _link_hosts(links),
        'official_channels': _official_channels((), first=sms['claimed_brand'], limit=1) if sms['claimed_brand'] else [],
    }
    if score == 0 and floor == 'safe':
        result['risk_level'] = 'unknown'
        result['risk_label'] = 'No Known Scam Signs Found'
    # The email labels for these levels name email ("钓鱼邮件" in Chinese).
    elif result['risk_level'] == 'critical':
        result['risk_label'] = 'Critical Risk — Very Likely a Scam Text'
    elif result['risk_level'] == 'high':
        result['risk_label'] = 'High Risk — Likely a Scam Text'
    return result


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


class SmsRequest(BaseModel):
    sender: str = Field(default="", max_length=64)
    text: str = Field(default="", max_length=2_000)


@app.post("/api/analyze-sms")
async def analyze_sms_endpoint(request: SmsRequest):
    """A pasted text message and, optionally, its sender. Off until the launch gate passes."""
    if not SETTINGS.sms_analysis_enabled:
        raise HTTPException(status_code=404, detail='Not Found')
    if not request.text.strip():
        raise HTTPException(status_code=400, detail='Text message is required')
    result = await _run_analysis(analyze_sms, request.sender, request.text)
    # Registration dates of the links' domains, as for email: context only, no points.
    candidates = _registration_candidates('', result.pop('link_hosts'))
    if SETTINGS.rdap_lookups_enabled and candidates:
        dates = await domain_age.lookup_many_async([domain for _role, domain in candidates])
        result['domain_registrations'] = {domain: date.date().isoformat() if date else None
                                          for domain, date in dates.items()}
        result['extra_indicators'].extend(_registration_findings(candidates, dates))
    return JSONResponse(annotate_content(result))


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


async def _resolve_content_input(request: ContentRequest, structure: dict | None, *, plain_text: bool,
                                 allow_empty: bool, raw_message: bool | None):
    """The subject, body and parsed structure to analyze, and whether they came with an
    original message. An uploaded message wins over the subject and body fields."""
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
    return subject, body, structure, raw_message


def _add_structure_evidence(result: dict, structure: dict) -> None:
    """The message structure's indicators, score and floor, and its summary for display."""
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
    if _FLOOR_RANK[structure["risk_floor"]] > _FLOOR_RANK[result["risk_floor"]]:
        result["risk_floor"] = structure["risk_floor"]


def _add_attachment_links(result: dict, structure: dict) -> None:
    """Link annotations read from PDF attachments and hyperlinks read from Word
    attachments go through the same destination checks as message links."""
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
        if _FLOOR_RANK[link_floor] > _FLOOR_RANK[result["risk_floor"]]:
            result["risk_floor"] = link_floor
        result["docx_link_count" if is_docx else "pdf_link_count"] = len(attachment_links)


def _add_attachment_text(result: dict, structure: dict) -> None:
    """Word and PDF attachment text: lures often sit in the attachment while the body
    has a line or none (a callback "invoice"). Only strong requests are scored here,
    never keyword categories: genuine contracts, quotes and invoices are full of
    "payment", "invoice" and "urgent". An account-hold lure also needs the
    attachment's own link to leave the sender's domain."""
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
        result["risk_floor"] = max(result["risk_floor"], 'high', key=_FLOOR_RANK.__getitem__)
        result["extra_indicators"].extend(text_findings)


async def _add_sender_evidence(result: dict, structure: dict, observe_sender_history: bool) -> None:
    """The sender that drives the result: its analysis, relaxed for an authenticated or
    service-domain sender and set aside for a verified official one, and its score and floor."""
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
        if _FLOOR_RANK[sender_floor] > _FLOOR_RANK[result["risk_floor"]]:
            result["risk_floor"] = sender_floor


def _apply_structure_verdict(result: dict) -> None:
    """The level once structure, attachment and sender evidence is in. Unlike
    _content_verdict, a Medium floor holds at any score, and the level is never lowered."""
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


def _add_nested_coverage(result: dict, nested_result: dict, key: str) -> None:
    coverage = result[key]
    coverage['count'] = min(20, coverage['count'] + nested_result[key]['count'])
    if coverage['count']:
        coverage['inspection_status'] = 'metadata_only'


async def _merge_nested_messages(result: dict, structure: dict) -> bool:
    """Analyze each attached message and merge its warnings, image coverage, score, level and
    indicators, marked as from the attached message. True if one is an unchecked remote image."""
    remote_image_dominant = False
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
        for key in ('inline_image_coverage', 'remote_image_coverage', 'unresolved_image_coverage'):
            _add_nested_coverage(result, nested_result, key)
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
    return remote_image_dominant


def _ensure_image_warnings(result: dict) -> None:
    """Each image kind counted (here or in an attached message) is warned about once."""
    for key, warning, code in (('inline_image_coverage', _INLINE_IMAGE_WARNING, 'warning.inline_images'),
                               ('remote_image_coverage', _REMOTE_IMAGE_WARNING, 'warning.remote_images'),
                               ('unresolved_image_coverage', _UNRESOLVED_IMAGE_WARNING, 'warning.unresolved_images')):
        if result[key]['count'] and warning not in result['analysis_warnings']:
            result['analysis_warnings'].append(warning)
            result['extra_indicators'].append(indicator('info', code))


async def _apply_content_model(result: dict, model_view: dict):
    """Score the views the rules could not rule out with the text model, when one is loaded.
    Returns the model's probability and threshold for the fusion, whether the rendering is
    still uncertain, and the rendering warnings that every scored view resolved."""
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
    return ml_probability, ml_threshold, rendering_uncertain, resolved_warnings


def _fuse_content_result(result: dict, ml_probability, ml_threshold: float, raw_message: bool) -> None:
    """The final level from the rule score and floor and the model's probability."""
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


def _apply_verified_sender(result: dict, structure: dict | None, request: ContentRequest) -> dict | None:
    """Keep a verified official sender's mail at Low unless strong evidence alerts, and list
    where to verify independently. Returns the verified sender, if any."""
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
    return verified_sender


async def _add_registration_dates(result: dict, structure: dict | None) -> list[str]:
    """Registration dates of the sender's and links' domains (context only). Returns the link
    hosts, which leave the result here."""
    # Registration dates of the sender's and the links' domains, from the registries'
    # RDAP servers where the deployment enables it. Context only: no points.
    link_hosts = result.get('link_hosts', [])
    candidates = _registration_candidates(structure['from'] if structure else '', result.pop('link_hosts', []))
    if SETTINGS.rdap_lookups_enabled and candidates:
        dates = await domain_age.lookup_many_async([domain for _role, domain in candidates])
        result['domain_registrations'] = {domain: date.date().isoformat() if date else None
                                          for domain, date in dates.items()}
        result['extra_indicators'].extend(_registration_findings(candidates, dates))
    return link_hosts


def _apply_abstention(result: dict, resolved_warnings: set, rendering_uncertain: bool,
                      remote_image_dominant: bool, verified_sender: dict | None) -> None:
    """Undetermined rather than Safe or Low where part of the message could not be read."""
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


async def _analyze_content(
    request: ContentRequest,
    structure: dict | None = None,
    *,
    observe_sender_history: bool = True,
    plain_text: bool = False,
    allow_empty: bool = False,
    raw_message: bool | None = None,
):
    subject, body, structure, raw_message = await _resolve_content_input(
        request, structure, plain_text=plain_text, allow_empty=allow_empty, raw_message=raw_message)

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
        _add_structure_evidence(result, structure)
        _add_attachment_links(result, structure)
        _add_attachment_text(result, structure)
        await _add_sender_evidence(result, structure, observe_sender_history)
        _apply_structure_verdict(result)
        remote_image_dominant = await _merge_nested_messages(result, structure) or remote_image_dominant
    _ensure_image_warnings(result)

    # 2. Optional ML text classifier (TF-IDF + selected linear model)
    ml_probability, ml_threshold, rendering_uncertain, resolved_warnings = await _apply_content_model(
        result, model_view)
    _fuse_content_result(result, ml_probability, ml_threshold, raw_message)

    verified_sender = _apply_verified_sender(result, structure, request)

    if structure and any(item['inspection_status'] == 'metadata_only'
                         for item in structure['attachments']):
        item = indicator('info', 'warning.attachments_uninspected')
        result['analysis_warnings'].append(item['msg'])
        result['extra_indicators'].append(item)

    link_hosts = await _add_registration_dates(result, structure)

    result['analysis_warnings'] = list(dict.fromkeys(result['analysis_warnings']
        + (structure['parse_warnings'] if structure else [])))
    result['analysis_complete'] = not bool(result['analysis_warnings'])
    await _apply_local_review(result, model_view.get('subject', ''), model_view.get('body', ''), link_hosts)
    _apply_requested_answer(result, request.requested)
    _apply_abstention(result, resolved_warnings, rendering_uncertain, remote_image_dominant, verified_sender)
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
# The checks themselves; the endpoint below calls them, and tests patch them on app.
from domain_verification import (
    _check_dmarc,
    _check_domain_age,
    _check_mx_ptr,
    _check_spf,
    _lookup_mail_domain,
    _smtp_probe,
    _summarize_verification,
    _verify_message,
)

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
