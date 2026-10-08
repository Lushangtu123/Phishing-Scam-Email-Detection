"""Privacy-bounded, non-causal signal counts for offline serving evaluations.

Only fixed signal names leave this module. Never serialize indicator messages,
matched terms, addresses, URLs, model explanations, or individual records.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import re


_CATEGORIES = frozenset({
    'urgency', 'threats', 'financial', 'credential', 'impersonation',
    'deception', 'attachments', 'tech_scam', 'job_scam', 'social_engineering',
})
_FUSION = frozenset({'model_only', 'model_led', 'corroborated', 'other'})
_ML_STATUS = frozenset({
    'available', 'insufficient_context', 'insufficient_feature_coverage',
    'unverified_rendering', 'unavailable',
})
_LEVELS = frozenset({'safe', 'low', 'medium', 'high', 'critical'})
_VERDICTS = frozenset({'safe', 'low', 'medium', 'high', 'critical', 'invalid'})
_RULE_IDS = frozenset({
    'link.obfuscated_scheme', 'link.malformed_target', 'link.unsafe_scheme',
    'link.url_userinfo', 'link.ip_host', 'link.display_mismatch',
    'link.idn_confusable', 'link.brand_lookalike', 'link.brand_on_free_host',
    'link.credential_collection_host', 'link.sensitive_host',
})
_OUTCOMES = frozenset({
    f'{label}_{decision}'
    for label in ('legitimate', 'phishing')
    for decision in ('alerted', 'not_alerted', 'undetermined')
})
_SCOPES = frozenset({'local_serving_pipeline', 'public_corpus_local_serving_pipeline'})


def _fixed(value, allowed: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in allowed else 'unrecognized'


def _positive_number(value) -> bool:
    return type(value) in (int, float) and value > 0


class EvidenceAttribution:
    """Count co-occurring signals by label and decision, without changing either."""

    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._signals: dict[str, Counter[str]] = defaultdict(Counter)

    def add(self, label: str, decision: str, result: dict | None) -> None:
        bucket = f'{label}_{decision}'
        if bucket not in _OUTCOMES:
            raise ValueError('Unsupported evaluation outcome')
        self._counts[bucket] += 1
        if result is None:
            self._signals[bucket]['analysis_failed'] += 1
            return
        if not isinstance(result, dict):
            raise ValueError('Invalid analyzer result')

        signals = set()
        if result.get('analysis_complete') is False:
            signals.add('analysis_incomplete')
        if _positive_number(result.get('sender_score')):
            signals.add('sender_signal')
        if _positive_number(result.get('structure_score')):
            signals.add('structure_signal')
        for key, name in (('fusion_basis', 'fusion'), ('ml_status', 'ml_status'),
                          ('risk_floor', 'risk_floor')):
            if key in result:
                allowed = {'fusion_basis': _FUSION, 'ml_status': _ML_STATUS,
                           'risk_floor': _LEVELS}[key]
                signals.add(f'{name}.{_fixed(result[key], allowed)}')
        sender = result.get('sender_analysis')
        if isinstance(sender, dict) and 'verdict' in sender:
            signals.add('sender_verdict.' + _fixed(sender['verdict'], _VERDICTS))
        structure = result.get('message_structure')
        if isinstance(structure, dict) and 'risk_floor' in structure:
            signals.add('structure_floor.' + _fixed(structure['risk_floor'], _LEVELS))
        categories = result.get('category_results')
        if isinstance(categories, list):
            for item in categories:
                if isinstance(item, dict):
                    signals.add('category.' + _fixed(item.get('key'), _CATEGORIES))
        indicators = result.get('extra_indicators')
        if isinstance(indicators, list):
            for item in indicators:
                if isinstance(item, dict) and 'rule_id' in item:
                    signals.add('rule.' + _fixed(item['rule_id'], _RULE_IDS))
        for key, name in (('inline_image_coverage', 'inline_image_uninspected'),
                          ('remote_image_coverage', 'remote_image_uninspected'),
                          ('unresolved_image_coverage', 'unresolved_image_uninspected')):
            coverage = result.get(key)
            if isinstance(coverage, dict) and _positive_number(coverage.get('count')):
                signals.add(name)
        for signal in signals:
            self._signals[bucket][signal] += 1

    def snapshot(self, serving_report: dict) -> dict:
        scope = serving_report.get('evaluation_scope')
        if scope not in _SCOPES:
            raise ValueError('Unsupported evaluation scope')
        integrity = serving_report.get('input_integrity', {})
        evaluated = (integrity.get('evaluated_rows') if integrity else
                     serving_report.get('counts', {}).get('evaluated'))
        if evaluated != sum(self._counts.values()):
            raise ValueError('Attribution count does not match the evaluated cohort')
        cohort_digest = (integrity.get('evaluated_cohort_sha256') if integrity else
                         serving_report.get('evaluated_cohort_sha256'))
        model_digest = serving_report.get('model_artifact_sha256')
        if any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
               for value in (cohort_digest, model_digest)):
            raise ValueError('Attribution requires full cohort and model digests')
        return {
            'schema_version': 'evidence-attribution/v1',
            'evaluation_scope': scope,
            'evaluated_cohort_sha256': cohort_digest,
            'model_artifact_sha256': model_digest,
            'evaluated_count': evaluated,
            'interpretation': ('Signals co-occur with decisions; counts are not causal '
                               'contributions or evidence of population accuracy.'),
            'outcomes': {
                bucket: {'n': self._counts[bucket],
                         'signals': dict(sorted(self._signals[bucket].items()))}
                for bucket in sorted(self._counts)
            },
        }
