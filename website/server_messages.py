"""Stable machine codes for server-generated English messages.

Every free-text message the analysis APIs return (sender risk indicators,
content ``extra_indicators``, ``safety_signals``, ``analysis_warnings``, image
assessment warnings and the verification ``message`` fields) is rendered from
one English template in ``data/server_messages.json`` (code → template, with
``str.format`` named fields such as ``{domain}``). Clients receive the English
text unchanged plus ``code`` and ``params``, so they can render the same
message in another language; the homepage dictionary (``static/i18n.js``)
holds ``server.<code>`` with the identical English template, which
``static/server-messages.test.mjs`` enforces.

Codes are lowercase and dotted: ``sender.*`` (address heuristics),
``content.*`` / ``link.*`` / ``structure.*`` (message evidence),
``warning.*`` (coverage and parsing warnings), ``safety.*`` (context-only
safety signals), ``prefix.*`` (a message wrapped with its source, e.g.
``Sender: …``; the wrapped text is the ``{text}`` field) and ``verify.*``
(mailbox verification). A code is never reused for different wording; change
the English template and both dictionary entries together.

Parameters are only strings or numbers and carry short evidence (a domain, a
count, a matched keyword), never a message body; strings are truncated to
``PARAM_MAX_CHARS`` characters as a defensive bound. The English ``msg`` is
always rendered from the untruncated values, exactly as before codes existed.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

TEMPLATES: dict[str, str] = json.loads(
    (Path(__file__).resolve().parent / 'data' / 'server_messages.json').read_text(encoding='utf-8'))
PARAM_MAX_CHARS = 256
CODE_PATTERN = re.compile(r'[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+')
_FIELD = re.compile(r'\{([a-z_][a-z0-9_]*)\}')
# Only these families are recognized from plain strings (warnings, safety
# signals); indicator codes are always attached where the message is built.
_DESCRIBABLE = ('warning.', 'safety.', 'prefix.')
_MAX_PREFIX_DEPTH = 8


def fields(template: str) -> list[str]:
    return _FIELD.findall(template)


def text(code: str, **params) -> str:
    """The English message for ``code``; a missing field raises KeyError."""
    return TEMPLATES[code].format(**params)


def clean_params(params: dict) -> dict:
    """Bound parameter values to short strings or finite numbers."""
    cleaned = {}
    for key, value in params.items():
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            value = str(value)
        elif isinstance(value, float) and not math.isfinite(value):
            value = str(value)
        if isinstance(value, str) and len(value) > PARAM_MAX_CHARS:
            value = value[:PARAM_MAX_CHARS - 1] + '…'
        cleaned[key] = value
    return cleaned


def message(code: str, **params) -> dict:
    """``{'code', 'params', 'msg'}`` for one message."""
    return {'code': code, 'params': clean_params(params), 'msg': text(code, **params)}


def indicator(level: str, code: str, **params) -> dict:
    """A risk indicator: the historical ``level``/``msg`` plus ``code``/``params``."""
    return {'level': level, 'msg': text(code, **params), 'code': code, 'params': clean_params(params)}


def wrap(item: dict, prefix_code: str, **params) -> dict:
    """Copy ``item`` with its ``msg`` wrapped by a ``prefix.*`` template.

    A coded item keeps its own code; the prefix is recorded in ``prefixes``
    (outermost first). An uncoded item becomes the prefix's ``{text}`` field.
    """
    wrapped = dict(item)
    wrapped['msg'] = text(prefix_code, text=item['msg'], **params)
    if item.get('code'):
        wrapped['prefixes'] = [{'code': prefix_code, 'params': clean_params(params)},
                               *item.get('prefixes', [])]
    else:
        wrapped['code'] = prefix_code
        wrapped['params'] = clean_params({**params, 'text': item['msg']})
    return wrapped


def _pattern(template: str) -> re.Pattern:
    parts, position = [], 0
    for match in _FIELD.finditer(template):
        parts.append(re.escape(template[position:match.start()]))
        parts.append(f'(?P<{match.group(1)}>.+?)')
        position = match.end()
    parts.append(re.escape(template[position:]))
    return re.compile(''.join(parts), re.S)


_EXACT = {template: code for code, template in TEMPLATES.items()
          if code.startswith(_DESCRIBABLE) and not fields(template)}
_PATTERNS = [(code, _pattern(template)) for code, template in TEMPLATES.items()
             if code.startswith(_DESCRIBABLE[:2]) and fields(template)]
_PREFIXES = [(code, _pattern(template)) for code, template in TEMPLATES.items()
             if code.startswith('prefix.')]


def describe(value: str, _depth: int = 0) -> dict:
    """``{'code', 'params', 'msg'}`` (plus ``prefixes``) for a warning or safety string.

    ``code`` is None for text that no template produces, such as warnings
    written by the browser recognizer.
    """
    if value in _EXACT:
        return {'code': _EXACT[value], 'params': {}, 'msg': value}
    for code, pattern in _PATTERNS:
        match = pattern.fullmatch(value)
        if match:
            return {'code': code, 'params': clean_params(match.groupdict()), 'msg': value}
    if _depth < _MAX_PREFIX_DEPTH:
        for code, pattern in _PREFIXES:
            match = pattern.fullmatch(value)
            if match:
                params = {key: item for key, item in match.groupdict().items() if key != 'text'}
                inner = describe(match.group('text'), _depth + 1)
                return wrap(inner, code, **params) | {'msg': value}
    return {'code': None, 'params': {}, 'msg': value}


def details(values) -> list[dict]:
    """Parallel ``*_details`` entries for a list of message strings."""
    return [describe(value) for value in values]


def warning_indicator(value: str) -> dict:
    """An informational indicator repeating one warning string."""
    described = describe(value)
    item = {'level': 'info', 'msg': value}
    if described['code']:
        item.update({key: entry for key, entry in described.items() if key != 'msg'})
    return item


def ensure_codes(indicators) -> None:
    """Attach codes to indicators built from warning strings (``level: info``)."""
    for item in indicators:
        if isinstance(item, dict) and 'code' not in item and isinstance(item.get('msg'), str):
            described = describe(item['msg'])
            if described['code']:
                item.update({key: value for key, value in described.items() if key != 'msg'})


def annotate_content(result: dict) -> dict:
    """Add codes and the parallel detail lists to a content/visual result."""
    ensure_codes(result.get('extra_indicators', []))
    result['analysis_warning_details'] = details(result.get('analysis_warnings', []))
    result['safety_signal_details'] = details(result.get('safety_signals', []))
    return result


def strip_details(analysis: dict) -> dict:
    """Drop the derived detail lists (they duplicate stored English text)."""
    analysis.pop('analysis_warning_details', None)
    analysis.pop('safety_signal_details', None)
    visual = analysis.get('visual_analysis')
    if isinstance(visual, dict):
        for record in visual.get('observations') or []:
            if isinstance(record, dict):
                record.pop('assessment_warning_details', None)
        if isinstance(visual.get('enhancement'), dict):
            visual['enhancement'].pop('warning_details', None)
    return analysis
