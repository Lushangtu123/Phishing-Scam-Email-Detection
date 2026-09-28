"""Optional image-service boundary. No model dependencies in the public runtime."""
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from server_messages import details as message_details, text as message_text


@dataclass(frozen=True)
class EnhancedVisionSettings:
    url: str | None = None
    token: str | None = field(default=None, repr=False)
    semantics_enabled: bool = False

    @property
    def enabled(self):
        return self.url is not None


def load_enhanced_vision_settings(environ=None):
    source = os.environ if environ is None else environ
    if source.get('ENHANCED_VISION_ENABLED', '').lower() not in {'true', '1'}:
        return EnhancedVisionSettings()
    url = source.get('ENHANCED_VISION_URL', '').strip()
    token = source.get('ENHANCED_VISION_TOKEN', '').strip()
    try:
        parsed = urlsplit(url)
        local = parsed.hostname in {'127.0.0.1', 'localhost', '::1'}
        public = source.get('APP_ENV', 'production').lower() in {'production', 'demo'}
        valid = (parsed.hostname and parsed.username is None and parsed.password is None
                 and parsed.path == '/recognize' and not parsed.query and not parsed.fragment
                 and ((parsed.scheme == 'https' and token) or
                      (parsed.scheme == 'http' and local and not public))
                 and parsed.port != 0 and not re.search(r'[\x00-\x20\x7f]', url)
                 and len(token) <= 4096 and not re.search(r'[\x00-\x20\x7f]', token))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('Invalid enhanced image service configuration')
    return EnhancedVisionSettings(url, token or None,
        source.get('ENHANCED_VISION_SEMANTICS_ENABLED', '').lower() in {'true', '1'})


class OCRResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    engine: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=120)
    text: str = Field(max_length=6000)
    confidence: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)


class SemanticResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    status: Literal['disabled', 'available', 'unavailable']
    model: str = Field(default='', max_length=160)
    observations: list[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=8)
    visible_urls: list[Annotated[str, Field(max_length=2048)]] = Field(default_factory=list, max_length=8)


class RecognitionProvenance(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    runtime_version: str = Field(default='', max_length=100)
    model_sha256: dict[Annotated[str, Field(max_length=120)], Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]] = Field(default_factory=dict, max_length=8)
    engine_source_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')


class EnhancedResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    schema_version: Literal['phishguard-enhanced-vision/v1'] = Field(alias='schema')
    image_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    ocr: OCRResult
    semantic: SemanticResult
    warnings: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=8)
    provenance: RecognitionProvenance = Field(default_factory=RecognitionProvenance)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def recognize_image(settings, enhancement, observation):
    if not settings.enabled:
        raise HTTPException(503, 'Enhanced image recognition is unavailable. Use browser recognition.')
    raw = enhancement.image_bytes()
    if observation.source != 'upload' or hashlib.sha256(raw).hexdigest() != observation.sha256:
        raise HTTPException(422, 'Enhanced image must match the selected original image')
    if enhancement.include_semantics and not settings.semantics_enabled:
        raise HTTPException(503, 'Image understanding is unavailable. Use text recognition.')
    request = Request(settings.url, data=json.dumps({
        'image_base64': enhancement.image_base64, 'language': observation.ocr_language or 'eng',
        'include_semantics': enhancement.include_semantics,
    }).encode(), headers={'Content-Type': 'application/json',
        **({'Authorization': 'Bearer ' + settings.token} if settings.token else {})})
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=55) as response:
            if response.status != 200:
                raise ValueError('Recognition failed')
            data = response.read(64 * 1024 + 1)
            if len(data) > 64 * 1024:
                raise ValueError('Response limit')
            result = EnhancedResult.model_validate_json(data)
        if result.image_sha256 != observation.sha256:
            raise ValueError('Image mismatch')
        if not enhancement.include_semantics and (result.semantic.status != 'disabled'
                or result.semantic.observations or result.semantic.visible_urls):
            raise ValueError('Unexpected image understanding')
        return result
    except Exception:
        # Never expose image content, credentials, endpoint or upstream errors.
        raise HTTPException(502, 'Enhanced recognition failed. Retry with browser recognition.') from None


def enhanced_evidence(result, browser_observation):
    warnings = result.warnings + [message_text('warning.enhanced_unverified'),
                                  message_text('warning.enhanced_model_output')]
    browser_urls = set(re.findall(r'https?://[^\s<>"\']+', browser_observation.ocr_text))
    service_urls = set(re.findall(r'https?://[^\s<>"\']+', result.ocr.text))
    return {'status': 'available', 'provenance': 'service_extracted_unverified',
        'image_sha256': result.image_sha256, 'ocr': result.ocr.model_dump(),
        'semantic': result.semantic.model_dump(),
        'url_disagreement': browser_urls != service_urls,
        # Service-written warnings have no code; details keep them as sent.
        'warnings': warnings, 'warning_details': message_details(warnings),
        # Do not retain arbitrary upstream metadata or image bytes in case records.
        'provenance_metadata': result.provenance.model_dump(exclude_none=True)}
