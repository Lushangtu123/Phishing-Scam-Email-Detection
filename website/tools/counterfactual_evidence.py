"""Local one-family-or-rule-at-a-time replay of alerted email decisions.

The sidecar contains only fixed family names and aggregate transitions. It is
diagnostic: overlapping evidence means a transition cannot be credited to a
unique rule, and historical labels do not establish current-mail accuracy.

Version 2 (docs/evaluation.md, 2026-10-19) replays through the evaluation's own
analyzer, verifies that a replay without intervention reproduces each baseline,
and adds families for the request, lure, HTML and weak-cue rules and for the
outermost fusion without the model probability. Each family removes its evidence
where it is found, so the finding's points and floor go with it.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import ExitStack
import contextvars
import hashlib
import json
from pathlib import Path
import re
from typing import Callable
from unittest.mock import patch

SCHEMA_VERSION = 'counterfactual-evidence/v2'
V1_FAMILIES = (
    'sender_analysis',
    'message_structure',
    'link_destinations',
    'link_display_mismatch',
    'link_brand_lookalike',
    'content_keywords',
    'content_model',
)
V2_FAMILIES = (
    'text_requests',
    'lures',
    'html_tricks',
    'weak_cues',
    'intent_rules',
    'outer_fusion_without_model_probability',
)
FAMILIES = V1_FAMILIES + V2_FAMILIES
# Replayed only when the evaluation turns intent rules on; otherwise not applicable.
_INTENT_FAMILY = 'intent_rules'
_LABELS = frozenset({'legitimate', 'phishing'})
_DECISIONS = frozenset({'alerted', 'not_alerted', 'undetermined'})
_TRANSITIONS = ('alerted', 'not_alerted', 'undetermined', 'analysis_failed')
_LEVELS = frozenset({'safe', 'low', 'medium', 'high', 'critical', 'unknown'})
_SCOPES = frozenset({'local_serving_pipeline', 'public_corpus_local_serving_pipeline'})
_SPECIFIC_LINK_RULES = {
    'link_display_mismatch': 'link.display_mismatch',
    'link_brand_lookalike': 'link.brand_lookalike',
}
# Weak cues counted inline, with no check of their own to switch off: (points, presentation
# points). content_rules._text_rule_findings scores the first two, app.analyze_email_content the
# others. Mixed-script words also set a Medium floor, the only Medium floor that function sets.
_TEXT_RULE_CUES = {'content.exclamation_marks': (1, 1), 'content.mixed_script_words': (3, 0)}
_CONTENT_CUES = {'content.subject_question_marks': (1, 1), 'content.url_count': (1, 1)}
# How deep the replay is in _analyze_content: attached messages are analysed one level down.
_DEPTH: contextvars.ContextVar[int] = contextvars.ContextVar('counterfactual_depth', default=0)


def _decision(level: str) -> str:
    if level not in _LEVELS:
        raise ValueError('Invalid risk level')
    if level == 'unknown':
        return 'undetermined'
    return 'alerted' if level in {'medium', 'high', 'critical'} else 'not_alerted'


def _canonical(result) -> str:
    return json.dumps(result, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def _without_structure(structure: dict) -> dict:
    """A structure, and each attached message's at every depth, with no score, floor or findings."""
    cleared = {**structure, 'structure_score': 0, 'risk_floor': 'safe', 'indicators': []}
    if 'nested_messages' in structure:
        cleared['nested_messages'] = [_without_structure(nested) for nested in structure['nested_messages']]
    return cleared


def _drop_cues(items: list, cues: dict) -> tuple[list, int, int, set]:
    kept, points, presentation, dropped = [], 0, 0, set()
    for item in items:
        cue = cues.get(item.get('code')) if isinstance(item, dict) else None
        if cue is None:
            kept.append(item)
            continue
        points += cue[0]
        presentation += cue[1]
        dropped.add(item['code'])
    return kept, points, presentation, dropped


def _interventions(stack: ExitStack, family: str) -> None:
    import app
    import content_rules
    import link_analysis

    def replace(target, name, value):
        stack.enter_context(patch.object(target, name, value))

    if family == 'sender_analysis':
        replace(app, '_select_message_sender', lambda *args, **kwargs: None)
    elif family == 'message_structure':
        original = app.analyze_raw_email
        replace(app, 'analyze_raw_email', lambda *args, **kwargs: _without_structure(original(*args, **kwargs)))
    elif family == 'link_destinations':
        replace(app, '_analyze_link_destinations', lambda *args, **kwargs: (0, [], 'safe'))
    # Only link_analysis calls these two, so they are patched there, not on app.
    elif family == 'link_display_mismatch':
        replace(link_analysis, '_visible_link_host', lambda *args, **kwargs: '')
    elif family == 'link_brand_lookalike':
        replace(link_analysis, '_label_uses_brand_lookalike', lambda *args, **kwargs: False)
    elif family == 'content_keywords':
        # Credential-pressure detection reads the same registry by key.
        # Retain its shape while removing all keyword matches, including
        # pressure that depends on those matches.
        empty_keywords = {key: {**rule, 'keywords': []}
                          for key, rule in content_rules.CONTENT_RULES.items()}
        stack.enter_context(patch.dict(content_rules.CONTENT_RULES, empty_keywords, clear=True))
    elif family == 'content_model':
        replace(app, '_content_pipeline', None)
    elif family == 'text_requests':
        # content_rules reads these in every reading, in text styles may hide and in attachment text.
        replace(content_rules, '_has_pressured_credential_request', lambda *args, **kwargs: False)
        replace(content_rules, '_callback_request', lambda *args, **kwargs: None)
        replace(content_rules, '_subsidy_lure', lambda *args, **kwargs: False)
        replace(content_rules, '_sensitive_requests', lambda *args, **kwargs: [])
    elif family == 'lures':
        for name, value in (('_mailbox_lure', False), ('_user_content_action', False), ('_file_share_elsewhere', None),
                            ('_delivery_lure', None), ('_fine_lure', None), ('_account_hold_link', None),
                            ('_attachment_account_lure', None), ('_attachment_mailbox_lure', None)):
            replace(app, name, lambda *args, _value=value, **kwargs: _value)
    elif family == 'html_tricks':
        password_form, read_parts = app._has_password_form, app._read_parts

        def no_password_form(part, warnings):
            password_form(part, warnings)  # its warnings stay
            return False

        def no_padding(*args, **kwargs):
            raw_parts, html_parts, parts, padding, letters = read_parts(*args, **kwargs)
            return raw_parts, html_parts, parts, [False] * len(padding), [0] * len(letters)

        replace(app, '_has_password_form', no_password_form)
        replace(app, '_read_parts', no_padding)
        replace(app, '_recipient_prefilled_link', lambda *args, **kwargs: None)
        replace(app, '_hidden_text_findings', lambda *args, **kwargs: [])
    elif family == 'weak_cues':
        replace(content_rules, '_excessive_caps_ratio', lambda *args, **kwargs: 0.0)
        replace(content_rules, '_has_generic_salutation', lambda *args, **kwargs: False)
        replace(content_rules, '_large_currency_amounts', lambda *args, **kwargs: [])
        replace(content_rules, '_count_generic_cta', lambda *args, **kwargs: 0)
        replace(content_rules, '_detect_obfuscation', lambda *args, **kwargs: [])
        replace(app, '_detect_obfuscation', lambda *args, **kwargs: [])  # the display name
        replace(app, '_has_shortener_url', lambda *args, **kwargs: False)
        text_rules, content = app._text_rule_findings, app.analyze_email_content

        def without_text_cues(text):
            found = text_rules(text)
            style, points, presentation, dropped = _drop_cues(found['style'], _TEXT_RULE_CUES)
            wording, more_points, more_presentation, more_dropped = _drop_cues(found['wording'], _TEXT_RULE_CUES)
            floor = found['floor']
            if 'content.mixed_script_words' in more_dropped and floor == 'medium':
                floor = 'safe'  # look-alike letters stay read as Latin: the text was folded
            return {**found, 'style': style, 'wording': wording, 'floor': floor,
                    'score': found['score'] - points - more_points,
                    'presentation': found['presentation'] - presentation - more_presentation}

        def without_content_cues(*args, **kwargs):
            result = content(*args, **kwargs)
            kept, points, presentation, dropped = _drop_cues(result['extra_indicators'], _CONTENT_CUES)
            if dropped:
                result['extra_indicators'] = kept
                result['total_score'] -= points
                result['presentation_score'] -= presentation
                result['risk_level'], result['risk_label'] = app._content_verdict(
                    result['total_score'], result['risk_floor'])
            return result

        replace(app, '_text_rule_findings', without_text_cues)
        replace(app, 'analyze_email_content', without_content_cues)
    elif family == 'intent_rules':
        replace(app, 'intent_findings', lambda *args, **kwargs: [])
    elif family == 'outer_fusion_without_model_probability':
        analyze_content, fuse = app._analyze_content_within_budget, app._fuse_content_result

        async def counted(*args, **kwargs):
            token = _DEPTH.set(_DEPTH.get() + 1)
            try:
                return await analyze_content(*args, **kwargs)
            finally:
                _DEPTH.reset(token)

        def outer_fusion(result, ml_probability, ml_threshold, raw_message):
            # Only the outermost message's final fusion; attached messages are analysed as before.
            return fuse(result, None if _DEPTH.get() == 1 else ml_probability, ml_threshold, raw_message)

        replace(app, '_analyze_content_within_budget', counted)
        replace(app, '_fuse_content_result', outer_fusion)
    else:
        raise ValueError('Unsupported counterfactual family')


def reanalyze_without(row: dict, family: str | None, analyze: Callable[[dict], dict] | None = None) -> dict:
    """Rerun the evaluation's own analyzer with one evidence family or rule absent, or, with
    family None, with no intervention at all."""
    if analyze is None:
        from tools.evaluate_serving_pipeline import analyze_record as analyze
    if family is not None and family not in FAMILIES:
        raise ValueError('Unsupported counterfactual family')
    with ExitStack() as stack:
        if family is not None:
            _interventions(stack, family)
        return analyze(row)


class CounterfactualEvidence:
    """Count paired decision changes without retaining individual messages.

    analyze is the evaluation's analyzer, with its mailbox setting and intent rules; replays
    run through it. A custom replay(row, family) gets family None for the identity check."""

    def __init__(self, replay: Callable[[dict, str | None], dict] | None = None, *,
                 analyze: Callable[[dict], dict] | None = None, intent_rules_enabled: bool = False) -> None:
        if replay is None:
            def replay(row, family):
                return reanalyze_without(row, family, analyze)
        self._replay = replay
        self._families = tuple(family for family in FAMILIES
                               if family != _INTENT_FAMILY or intent_rules_enabled)
        self._identity_verified = 0
        self._baseline: Counter[str] = Counter()
        self._after: dict[str, dict[str, Counter[str]]] = defaultdict(
            lambda: defaultdict(Counter))

    @property
    def families(self) -> tuple[str, ...]:
        return self._families

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
        # A replay with no intervention must reproduce the baseline before anything is removed.
        try:
            identity = self._replay(row, None)
        except Exception:
            # Analyzer exceptions can contain private sender or URL text.
            raise RuntimeError('The replay without intervention failed') from None
        if _canonical(identity) != _canonical(result):
            raise ValueError('The replay without intervention does not reproduce the baseline')
        self._identity_verified += 1
        indicators = result.get('extra_indicators')
        for family in self._families:
            rule_id = _SPECIFIC_LINK_RULES.get(family)
            # Attachment link findings carry the rule as their code only.
            if (rule_id and isinstance(indicators, list)
                    and not any(isinstance(item, dict) and rule_id in (item.get('rule_id'), item.get('code'))
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
        alerted = self._baseline['legitimate_alerted'] + self._baseline['phishing_alerted']
        if self._identity_verified != alerted:
            raise ValueError('Every replayed alert needs a verified identity replay')
        after = {}
        for family in self._families:
            after[family] = {
                bucket: {transition: self._after[family][bucket][transition]
                         for transition in _TRANSITIONS}
                for bucket in ('legitimate_alerted', 'phishing_alerted')
            }
            for bucket in ('legitimate_alerted', 'phishing_alerted'):
                if sum(after[family][bucket].values()) != self._baseline[bucket]:
                    raise ValueError('Counterfactual transition count does not reconcile')
        reproducibility = serving_report.get('reproducibility')
        commit = reproducibility.get('git_commit') if isinstance(reproducibility, dict) else None
        return {
            'schema_version': SCHEMA_VERSION,
            'tool': {'file_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     'evaluated_commit': commit if isinstance(commit, str) and re.fullmatch(r'[0-9a-f]{40}', commit)
                     else None},
            'evaluation_scope': scope,
            'evaluated_cohort_sha256': cohort_digest,
            'model_artifact_sha256': model_digest,
            'evaluated_count': evaluated,
            'interpretation': ('One evidence family or targeted link rule is removed per replay of baseline alerts. '
                               'Transitions are not unique causal attribution, and no serving rule changes.'),
            'comparability': ('Families named as in counterfactual-evidence/v1 are not directly comparable with it: '
                              'v2 replays use the evaluation\'s own mailbox setting and intent rules, clear attached '
                              'messages\' structure evidence and match attachment link rules by code.'),
            'identity_verified_alerts': self._identity_verified,
            'families': list(self._families),
            'not_applicable': [family for family in FAMILIES if family not in self._families],
            'baseline_outcomes': {
                f'{label}_{decision}': self._baseline[f'{label}_{decision}']
                for label in sorted(_LABELS) for decision in sorted(_DECISIONS)
            },
            'after_removal': after,
        }
