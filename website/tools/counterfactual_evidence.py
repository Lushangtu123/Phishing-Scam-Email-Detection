"""Local one-family-or-rule-at-a-time replay of alerted email decisions.

The sidecar contains only fixed family names and aggregate transitions. It is
diagnostic: overlapping evidence means a transition cannot be credited to a
unique rule, and historical labels do not establish current-mail accuracy.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import ExitStack
import re
from typing import Callable
from unittest.mock import patch


FAMILIES = (
    'sender_analysis',
    'message_structure',
    'link_destinations',
    'link_display_mismatch',
    'link_brand_lookalike',
    'content_keywords',
    'content_model',
)
_LABELS = frozenset({'legitimate', 'phishing'})
_DECISIONS = frozenset({'alerted', 'not_alerted', 'undetermined'})
_TRANSITIONS = ('alerted', 'not_alerted', 'undetermined', 'analysis_failed')
_LEVELS = frozenset({'safe', 'low', 'medium', 'high', 'critical', 'unknown'})
_SCOPES = frozenset({'local_serving_pipeline', 'public_corpus_local_serving_pipeline'})
_SPECIFIC_LINK_RULES = {
    'link_display_mismatch': 'link.display_mismatch',
    'link_brand_lookalike': 'link.brand_lookalike',
}


def _decision(level: str) -> str:
    if level not in _LEVELS:
        raise ValueError('Invalid risk level')
    if level == 'unknown':
        return 'undetermined'
    return 'alerted' if level in {'medium', 'high', 'critical'} else 'not_alerted'


def reanalyze_without(row: dict, family: str) -> dict:
    """Rerun the same local serving path with one evidence family or rule absent."""
    import app
    import content_rules
    import link_analysis
    from tools.evaluate_serving_pipeline import analyze_record

    if family not in FAMILIES:
        raise ValueError('Unsupported counterfactual family')
    with ExitStack() as stack:
        if family == 'sender_analysis':
            stack.enter_context(patch.object(app, '_select_message_sender', return_value=None))
        elif family == 'message_structure':
            original = app.analyze_raw_email

            def without_outer_structure(*args, **kwargs):
                structure = original(*args, **kwargs)
                return {**structure, 'structure_score': 0, 'risk_floor': 'safe',
                        'indicators': []}

            stack.enter_context(patch.object(app, 'analyze_raw_email',
                                             side_effect=without_outer_structure))
        elif family == 'link_destinations':
            stack.enter_context(patch.object(app, '_analyze_link_destinations',
                                             return_value=(0, [], 'safe')))
        # Only link_analysis calls these two, so they are patched there, not on app.
        elif family == 'link_display_mismatch':
            stack.enter_context(patch.object(link_analysis, '_visible_link_host', return_value=''))
        elif family == 'link_brand_lookalike':
            stack.enter_context(patch.object(link_analysis, '_label_uses_brand_lookalike',
                                             return_value=False))
        elif family == 'content_keywords':
            # Credential-pressure detection reads the same registry by key.
            # Retain its shape while removing all keyword matches, including
            # pressure that depends on those matches.
            empty_keywords = {key: {**rule, 'keywords': []}
                              for key, rule in content_rules.CONTENT_RULES.items()}
            stack.enter_context(patch.dict(content_rules.CONTENT_RULES, empty_keywords, clear=True))
        elif family == 'content_model':
            stack.enter_context(patch.object(app, '_content_pipeline', None))
        return analyze_record(row)


class CounterfactualEvidence:
    """Count paired decision changes without retaining individual messages."""

    def __init__(self, replay: Callable[[dict, str], dict] = reanalyze_without) -> None:
        self._replay = replay
        self._baseline: Counter[str] = Counter()
        self._after: dict[str, dict[str, Counter[str]]] = defaultdict(
            lambda: defaultdict(Counter))

    @property
    def failure_count(self) -> int:
        return sum(outcomes.get('analysis_failed', 0) for family in self._after.values()
                   for outcomes in family.values())

    def add(self, row: dict, label: str, decision: str, result: dict | None) -> None:
        if label not in _LABELS or decision not in _DECISIONS:
            raise ValueError('Unsupported evaluation outcome')
        if result is None:
            if decision != 'undetermined':
                raise ValueError('Missing result for a determined outcome')
        elif not isinstance(result, dict) or _decision(result.get('risk_level')) != decision:
            raise ValueError('Baseline decision does not match the analyzer result')
        bucket = f'{label}_{decision}'
        self._baseline[bucket] += 1
        if decision != 'alerted':
            return
        for family in FAMILIES:
            indicators = result.get('extra_indicators')
            rule_id = _SPECIFIC_LINK_RULES.get(family)
            if (rule_id and isinstance(indicators, list)
                    and not any(isinstance(item, dict) and item.get('rule_id') == rule_id
                                for item in indicators)):
                # These helpers only feed their own link rule. If that rule did
                # not fire in the baseline, removing it cannot change a verdict.
                self._after[family][bucket]['alerted'] += 1
                continue
            try:
                candidate = self._replay(row, family)
                transition = _decision(candidate.get('risk_level')) if isinstance(candidate, dict) else 'analysis_failed'
            except Exception:
                # Analyzer exceptions can contain private sender or URL text.
                transition = 'analysis_failed'
            self._after[family][bucket][transition] += 1

    def snapshot(self, serving_report: dict) -> dict:
        scope = serving_report.get('evaluation_scope')
        if scope not in _SCOPES:
            raise ValueError('Unsupported evaluation scope')
        integrity = serving_report.get('input_integrity')
        evaluated = (integrity.get('evaluated_rows') if isinstance(integrity, dict)
                     else serving_report.get('counts', {}).get('evaluated'))
        if evaluated != sum(self._baseline.values()):
            raise ValueError('Counterfactual count does not match the evaluated cohort')
        cohort_digest = (integrity.get('evaluated_cohort_sha256')
                         if isinstance(integrity, dict) else
                         serving_report.get('evaluated_cohort_sha256'))
        model_digest = serving_report.get('model_artifact_sha256')
        if any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
               for value in (cohort_digest, model_digest)):
            raise ValueError('Counterfactual requires full cohort and model digests')
        after = {}
        for family in FAMILIES:
            after[family] = {
                bucket: {transition: self._after[family][bucket][transition]
                         for transition in _TRANSITIONS}
                for bucket in ('legitimate_alerted', 'phishing_alerted')
            }
            for bucket in ('legitimate_alerted', 'phishing_alerted'):
                if sum(after[family][bucket].values()) != self._baseline[bucket]:
                    raise ValueError('Counterfactual transition count does not reconcile')
        return {
            'schema_version': 'counterfactual-evidence/v1',
            'evaluation_scope': scope,
            'evaluated_cohort_sha256': cohort_digest,
            'model_artifact_sha256': model_digest,
            'evaluated_count': evaluated,
            'interpretation': ('One evidence family or targeted link rule is removed per replay of baseline alerts. '
                               'Transitions are not unique causal attribution, and no serving rule changes.'),
            'baseline_outcomes': {
                f'{label}_{decision}': self._baseline[f'{label}_{decision}']
                for label in sorted(_LABELS) for decision in sorted(_DECISIONS)
            },
            'after_removal': after,
        }
