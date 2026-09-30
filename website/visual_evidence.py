"""Bounded, explicitly unverified client extraction; never accept a client verdict."""
import base64
import binascii
from copy import deepcopy
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from server_messages import details as message_details, indicator, text as message_text, wrap as wrap_message

MAX_VISUAL_REQUEST_BYTES = 3 * 1024 * 1024
MAX_VISUAL_FILE_BYTES = 2 * 1024 * 1024
VISUAL_PATHS = frozenset({'/api/analyze-visual', '/api/cases/visual'})


class VisualObservation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(max_length=160)
    mime_type: Literal['image/png', 'image/jpeg', 'image/webp']
    source: Literal['upload', 'mime', 'data-uri']
    sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    status: Literal['processed', 'partial', 'failed', 'skipped']
    qr_payloads: list[Annotated[str, Field(max_length=2048)]] = Field(default_factory=list, max_length=8)
    ocr_language: Literal['eng', 'chi_sim', 'eng+chi_sim'] | None = None
    ocr_text: str = Field(default='', max_length=6000)
    ocr_confidence: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    ocr_url_line_confidence: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    warnings: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=6)


class VisualEnhancement(BaseModel):
    model_config = ConfigDict(extra='forbid')
    image_base64: str = Field(min_length=1, max_length=2796204)
    consent: Literal[True]
    include_semantics: StrictBool = False

    @field_validator('consent', mode='before')
    @classmethod
    def explicit_consent(cls, value):
        if value is not True:
            raise ValueError('Explicit image processing consent is required')
        return value

    def image_bytes(self):
        try:
            raw = base64.b64decode(self.image_base64, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPException(422, 'Invalid image input') from None
        if not raw or len(raw) > MAX_VISUAL_FILE_BYTES:
            raise HTTPException(413, 'Choose a nonempty image up to 2 MiB')
        return raw


class VisualRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    subject: str = Field(default='', max_length=500)
    body: str = Field(default='', max_length=50000)
    eml_base64: str = Field(default='', max_length=2796204)
    observations: list[VisualObservation] = Field(default_factory=list, max_length=4)
    warnings: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=8)
    enhancement: VisualEnhancement | None = None
    # Mailbox the .eml was downloaded from; only then is its topmost authentication header trusted.
    mailbox: Literal['', 'gmail', 'outlook'] = ''

    def eml_bytes(self):
        if not self.eml_base64:
            return None
        try:
            raw = base64.b64decode(self.eml_base64, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPException(422, 'Invalid base64 email bytes') from None
        if not raw.strip() or len(raw) > MAX_VISUAL_FILE_BYTES:
            raise HTTPException(413, 'Choose a nonempty email up to 2 MiB')
        return raw


def bound_message_text(structure, remaining=None):
    """Share a text budget across a larger image-bearing MIME message and its children."""
    remaining = [60000] if remaining is None else remaining
    truncated = len(structure['subject']) > 500 or len(structure['body']) > 60000 or len(structure['html_body']) > 60000
    structure['subject'] = structure['subject'][:500]
    for part in structure['content_parts']:
        text = part['content']
        part['content'] = text[:remaining[0]]
        remaining[0] -= len(part['content'])
        truncated |= len(part['content']) != len(text)
    structure['body'] = structure['body'][:60000]
    structure['html_body'] = structure['html_body'][:60000]
    for nested in structure['nested_messages']:
        bound_message_text(nested, remaining)
    if truncated:
        structure['parse_warnings'].append(message_text('warning.visual_text_limit'))
    structure['text_truncated'] = truncated or any(child.get('text_truncated') for child in structure['nested_messages'])
    return structure


def merge_visual_sources(findings, *, source_count):
    """Keep OCR and each QR payload independent, including their model context."""
    ranks = {'unknown': 0, 'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    strongest = max(findings, key=lambda finding: (
        ranks[finding['risk_level']], finding.get('combined_phishing_score') or 0))
    result = deepcopy(strongest)
    result['total_score'] = max(finding['total_score'] for finding in findings)
    result['extra_indicators'] = []
    result['analysis_warnings'] = []
    categories = {}
    for finding in findings:
        for item in finding['extra_indicators']:
            if item not in result['extra_indicators']:
                result['extra_indicators'].append(dict(item))
        for warning in finding['analysis_warnings']:
            if warning not in result['analysis_warnings']:
                result['analysis_warnings'].append(warning)
        for category in finding['category_results']:
            key = category['key']
            if key not in categories:
                categories[key] = deepcopy(category)
                continue
            combined = categories[key]
            combined['matched'] = list(dict.fromkeys(combined['matched'] + category['matched']))
            combined['count'] = max(combined['count'], category['count'], len(combined['matched']))
            # The merged labels describe the evidence; they must not add a
            # cross-source score that no individual source received.
            combined['score'] = max(combined['score'], category['score'])
    result['category_results'] = list(categories.values())
    scored = [finding for finding in findings
              if finding.get('ml_status') == 'available'
              and finding.get('ml_phishing_probability') is not None]
    if scored:
        model_result = max(scored, key=lambda finding: finding['ml_phishing_probability'])
        result.update({key: deepcopy(value) for key, value in model_result.items()
                       if key.startswith('ml_')})
    result['assessment_method'] = 'independent-source-max'
    result['assessed_source_count'] = source_count
    if source_count > 1:
        result['analysis_warnings'].append(message_text('warning.visual_independent_sources'))
    return result


def merge_visual_findings(base, observations, findings, warnings):
    """Independent visual evidence can raise risk, but cannot erase original findings."""
    ranks = {'unknown': 0, 'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    records = []
    for observation, finding in zip(observations, findings):
        record = observation.model_dump()
        record['risk_level'] = 'unknown' if finding['risk_level'] == 'safe' else finding['risk_level']
        record['indicators'] = finding['extra_indicators']
        record['categories'] = finding['category_results']
        record['assessment_warnings'] = list(finding['analysis_warnings'])
        if observation.ocr_text.strip():
            record['assessment_warnings'].append(message_text('warning.ocr_verify_urls'))
        record['assessment_warning_details'] = message_details(record['assessment_warnings'])
        record['ml_status'] = finding.get('ml_status')
        record['ml_phishing_probability'] = finding.get('ml_phishing_probability')
        record['assessment_method'] = finding['assessment_method']
        record['assessed_source_count'] = finding['assessed_source_count']
        records.append(record)
        base['extra_indicators'].extend(wrap_message(item, 'prefix.image', name=observation.name)
                                       for item in finding['extra_indicators'])
        base['extra_indicators'].extend(
            wrap_message(indicator(cat['level'], 'content.category', label=cat['label'], category=cat['key']),
                         'prefix.image', name=observation.name)
            for cat in finding['category_results'] if cat['count'])
        if ranks[finding['risk_level']] > ranks[base['risk_level']]:
            for key in ('risk_level', 'risk_label', 'combined_phishing_score'):
                base[key] = finding.get(key)
            base['fusion_basis'] = 'visual_evidence'
        elif finding['risk_level'] == base['risk_level'] and finding.get('combined_phishing_score') is not None:
            base['combined_phishing_score'] = max(base.get('combined_phishing_score') or 0, finding['combined_phishing_score'])
        base['total_score'] = max(base['total_score'], finding['total_score'])
    if observations:
        base['fusion_method'] = 'conservative-message-visual-max'
    base['visual_analysis'] = {'provenance': 'browser_extracted_unverified',
        'extractors': 'jsQR 1.4.0; Tesseract.js 6.0.1; postal-mime 3.0.0',
        'observations': records, 'warnings': warnings}
    if observations or warnings:
        base['analysis_warnings'].append(message_text('warning.visual_unverified'))
        base['analysis_warnings'].extend(message_text('prefix.image_recognition', text=w) for w in warnings)
        for item in observations:
            base['analysis_warnings'].extend(message_text('prefix.image', name=item.name, text=w)
                                             for w in item.warnings)
        base['analysis_complete'] = False
        if base['risk_level'] == 'safe':
            base['risk_level'] = 'unknown'
            base['risk_label'] = 'Image Analysis Incomplete — Risk Undetermined'
            base['combined_phishing_score'] = None
    return base
