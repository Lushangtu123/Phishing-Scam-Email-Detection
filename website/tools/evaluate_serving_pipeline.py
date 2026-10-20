"""Evaluate the deployed analysis path on locally supplied, consented JSONL.

Reports contain aggregate results and execution metadata, never message content.
This does not fetch inbox messages, train a model, or establish that a cohort is
independent of training data.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter, defaultdict
from datetime import date
from functools import partial
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Callable, Iterable
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROVIDERS = {'gmail', 'outlook'}
LABELS = {'phishing', 'legitimate'}
ALERT_LEVELS = {'medium', 'high', 'critical'}
RISK_LEVELS = ALERT_LEVELS | {'safe', 'low', 'unknown'}
WILSON_95_Z = 1.959963984540054
MAX_EML_BYTES = 60_000
ALERT_POLICY = 'medium/high/critical count as alerts; unknown is undetermined'
# docs/superpowers/specs/2026-10-13-model-only-and-intent-rules-evaluation-plan.md
MODEL_ONLY_OPTIONS = ('A', 'B', 'C')
MAILBOX_SETTINGS = ('none', 'recorded')
# Part 2 of the plan: the intent rules a configuration turns on. A rule is applied only once
# this build implements it (app.IMPLEMENTED_INTENT_RULES, with app.INTENT_RULES as its
# evaluation-only switch); until then a configuration that names it is refused, never run as
# if the rule were on. A rule's finding is its indicator code in the result.
INTENT_RULE_SETTINGS = {'none': (), 'credential': ('credential',), 'payment': ('payment',),
                        'both': ('credential', 'payment')}
INTENT_RULE_CODES = {'credential': 'content.intent.credential_handover',
                     'payment': 'content.intent.payment_redirection'}
INTENT_BEHAVIOURS = {'credential': 'credential_handover', 'payment': 'payment_redirection'}
CONTROL_TYPES = ('password_reset', 'otp_notice', 'supplier_change_known_channel', 'payroll_confirmation',
                 'unchanged_invoice', 'quoted_warning')
PLAN_PATH = 'docs/superpowers/specs/2026-10-13-model-only-and-intent-rules-evaluation-plan.md'
INCLUSION_POLICY = 'all valid unique inputs; analysis errors abort without a report; training overlap not verified'


def _validated_record(row: dict, index: int) -> dict:
    if not isinstance(row, dict):
        raise ValueError(f'Row {index}: expected a JSON object')
    provider = row.get('provider')
    label = row.get('label')
    received_at = row.get('received_at')
    if provider not in PROVIDERS:
        raise ValueError(f'Row {index}: provider must be gmail or outlook')
    if label not in LABELS:
        raise ValueError(f'Row {index}: label must be phishing or legitimate')
    if 'language' in row and (not isinstance(row['language'], str)
                              or not re.fullmatch(r'[a-z]{2,3}', row['language'])):
        raise ValueError(f'Row {index}: language must be a lowercase two- or three-letter code')
    if not isinstance(received_at, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', received_at):
        raise ValueError(f'Row {index}: received_at must be YYYY-MM-DD')
    try:
        date.fromisoformat(received_at)
    except ValueError as exc:
        raise ValueError(f'Row {index}: received_at is not a calendar date') from exc
    for field in ('subject', 'body', 'raw_email'):
        if field in row and not isinstance(row[field], str):
            raise ValueError(f'Row {index}: {field} must be text')
    if 'eml_path' in row:
        if not isinstance(row['eml_path'], str) or not Path(row['eml_path']).is_absolute():
            raise ValueError(f'Row {index}: eml_path must be an absolute path')
        if any(row.get(field) for field in ('subject', 'body', 'raw_email')):
            raise ValueError(f'Row {index}: eml_path cannot be mixed with text input')
    elif not any(row.get(field) for field in ('subject', 'body', 'raw_email')):
        raise ValueError(f'Row {index}: message content is required')
    # The plan's tags: a phishing message's behaviours, a legitimate message's control type.
    if 'behaviour' in row:
        behaviours = row['behaviour'] if isinstance(row['behaviour'], list) else [row['behaviour']]
        if not behaviours or any(value not in INTENT_BEHAVIOURS.values() for value in behaviours):
            raise ValueError(f'Row {index}: behaviour must be credential_handover or payment_redirection')
    if 'control_type' in row and (row['control_type'] not in CONTROL_TYPES or label != 'legitimate'):
        raise ValueError(f'Row {index}: control_type must be one of the plan\'s control types, on legitimate mail')
    return row


def _tags(row: dict) -> list:
    """The row's plan tags, sorted; empty for an untagged row."""
    behaviours = row.get('behaviour', [])
    behaviours = sorted(set(behaviours if isinstance(behaviours, list) else [behaviours]))
    return [behaviours, row['control_type']] if 'control_type' in row else [behaviours] if behaviours else []


def _read_eml(path: str) -> bytes:
    with Path(path).open('rb') as source:
        raw = source.read(MAX_EML_BYTES + 1)
    if len(raw) > MAX_EML_BYTES or not raw.strip():
        raise ValueError('Email file must contain 1 to 60,000 bytes')
    return raw


def _json_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':')).encode('ascii')


def _prepare_record(row: dict) -> tuple[dict, str]:
    """Snapshot effective input once; paths and ignored annotations are not identity."""
    prepared = dict(row)
    # JSONL must not be able to supply the evaluator's internal byte snapshot.
    prepared.pop('_eml_bytes', None)
    if 'eml_path' in prepared:
        raw = _read_eml(prepared['eml_path'])
        prepared['_eml_bytes'] = raw
        payload = b'eml-bytes\0' + raw
    elif prepared.get('raw_email'):
        payload = b'raw-unicode\0' + _json_bytes(prepared['raw_email'])
    else:
        payload = b'subject-body\0' + _json_bytes([
            prepared.get('subject', ''), prepared.get('body', ''),
        ])
    return prepared, hashlib.sha256(payload).hexdigest()


def _rate_with_interval(successes: int, total: int) -> tuple[float | None, list[float] | None]:
    """Return a rate and two-sided 95% Wilson interval, or null for no data."""
    if total == 0:
        return None, None
    rate = successes / total
    z_squared = WILSON_95_Z ** 2
    denominator = 1 + z_squared / total
    center = (rate + z_squared / (2 * total)) / denominator
    margin = WILSON_95_Z * math.sqrt(
        rate * (1 - rate) / total + z_squared / (4 * total * total)
    ) / denominator
    lower = 0.0 if successes == 0 else max(0.0, center - margin)
    upper = 1.0 if successes == total else min(1.0, center + margin)
    return round(rate, 4), [round(lower, 4), round(upper, 4)]


def _summary(outcomes: list[dict]) -> dict:
    by_label = {label: Counter() for label in sorted(LABELS)}
    for item in outcomes:
        by_label[item['label']][item['decision']] += 1
    phishing = by_label['phishing']
    legitimate = by_label['legitimate']
    phishing_total = sum(phishing.values())
    legitimate_total = sum(legitimate.values())
    total = len(outcomes)
    phishing_recall, phishing_recall_ci = _rate_with_interval(
        phishing['alerted'], phishing_total,
    )
    legitimate_false_alert, legitimate_false_alert_ci = _rate_with_interval(
        legitimate['alerted'], legitimate_total,
    )
    unknown_rate, unknown_ci = _rate_with_interval(
        sum(item['decision'] == 'undetermined' for item in outcomes), total,
    )
    complete_rate, complete_ci = _rate_with_interval(
        sum(item['complete'] for item in outcomes), total,
    )
    ml_available_rate, ml_available_ci = _rate_with_interval(
        sum(item['ml_available'] for item in outcomes), total,
    )
    return {
        'n': total,
        'phishing_count': phishing_total,
        'legitimate_count': legitimate_total,
        'phishing': {key: phishing[key] for key in ('alerted', 'not_alerted', 'undetermined')},
        'legitimate': {key: legitimate[key] for key in ('alerted', 'not_alerted', 'undetermined')},
        # Unknown cases remain in the denominator: they were not detected.
        'phishing_alert_recall': phishing_recall,
        'phishing_alert_recall_95_ci': phishing_recall_ci,
        'legitimate_false_alert_rate': legitimate_false_alert,
        'legitimate_false_alert_rate_95_ci': legitimate_false_alert_ci,
        'unknown_rate': unknown_rate,
        'unknown_rate_95_ci': unknown_ci,
        'complete_rate': complete_rate,
        'complete_rate_95_ci': complete_ci,
        'ml_available_rate': ml_available_rate,
        'ml_available_rate_95_ci': ml_available_ci,
    }


def _private_summary(outcomes: list[dict]) -> dict:
    # Preserve the public evaluator's scoring implementation and baseline hash.
    return {**_summary(outcomes),
            'unknown_count': sum(item['decision'] == 'undetermined' for item in outcomes),
            'complete_count': sum(item['complete'] for item in outcomes),
            'ml_available_count': sum(item['ml_available'] for item in outcomes)}


def _plan_counts(items: list[dict]) -> dict:
    """Alerts, reviews, false passes and Unknown, kept apart (the 2026-10-13 plan)."""
    counts = Counter()
    for item in items:
        counts['undetermined' if item['decision'] == 'undetermined' else
               'alerted' if item['decision'] == 'alerted' else
               'reviewed' if item['review'] else 'passed'] += 1
    total = len(items)
    rates = {name: _rate_with_interval(counts[name], total) for name in ('alerted', 'reviewed', 'passed', 'undetermined')}
    return {'n': total, **{name: counts[name] for name in ('alerted', 'reviewed', 'passed', 'undetermined')},
            **{f'{name}_rate': rate for name, (rate, _ci) in rates.items()},
            **{f'{name}_rate_95_ci': ci for name, (_rate, ci) in rates.items()}}


def _plan_summary(outcomes: list[dict]) -> dict:
    """Per label, and for phishing whose sender is authenticated, and its decisive subset:
    authenticated by a non-official domain and model-only, where options B and C differ.
    On phishing "passed" is a false pass; on legitimate mail, alerts plus reviews are the
    attention the option costs."""
    phishing = [item for item in outcomes if item['label'] == 'phishing']
    legitimate = [item for item in outcomes if item['label'] == 'legitimate']
    authenticated = [item for item in phishing if item['authenticated']]
    decisive = [item for item in authenticated if not item['official'] and item['model_only']]
    legitimate_counts = _plan_counts(legitimate)
    attention = legitimate_counts['alerted'] + legitimate_counts['reviewed']
    attention_rate, attention_ci = _rate_with_interval(attention, len(legitimate))
    return {
        'phishing': _plan_counts(phishing),
        'legitimate': {**legitimate_counts, 'attention': attention, 'attention_rate': attention_rate,
                       'attention_rate_95_ci': attention_ci},
        'authenticated_phishing': _plan_counts(authenticated),
        'authenticated_phishing_decisive': _plan_counts(decisive),
        'authentication_known': sum(item['authenticated'] is not None for item in outcomes),
    }


def _intent_counts(items: list[dict], rule: str, paired: bool) -> dict:
    """One rule in one language: D6's matches on legitimate mail and on each control type, D7's
    alerts it adds there, and D9's alerts on phishing tagged with its behaviour, with those it
    adds. Added alerts need the paired run without rules; without it they are null."""
    legitimate = [item for item in items if item['label'] == 'legitimate']
    target = [item for item in items if item['label'] == 'phishing' and INTENT_BEHAVIOURS[rule] in item['behaviours']]
    matched = sum(rule in item['matched'] for item in legitimate)
    risen = (sum(rule in item['matched'] and item['decision'] == 'alerted' and item['without_decision'] != 'alerted'
                 for item in legitimate) if paired else None)
    alerted = sum(item['decision'] == 'alerted' for item in target)
    added = (sum(item['decision'] == 'alerted' and item['without_decision'] != 'alerted' for item in target)
             if paired else None)
    matched_rate, matched_ci = _rate_with_interval(matched, len(legitimate))
    risen_rate, risen_ci = (_rate_with_interval(risen, len(legitimate)) if paired else (None, None))
    alerted_rate, alerted_ci = _rate_with_interval(alerted, len(target))
    return {
        'legitimate': {'n': len(legitimate), 'matched': matched, 'matched_rate': matched_rate,
                       'matched_rate_95_ci': matched_ci, 'new_alerts': risen, 'new_alerts_rate': risen_rate,
                       'new_alerts_rate_95_ci': risen_ci},
        'controls': {control: {'n': sum(item['control_type'] == control for item in legitimate),
                               'matched': sum(item['control_type'] == control and rule in item['matched']
                                              for item in legitimate)} for control in CONTROL_TYPES},
        'behaviour_phishing': {'n': len(target), 'alerted': alerted, 'alerted_rate': alerted_rate,
                               'alerted_rate_95_ci': alerted_ci, 'added': added},
        'phishing_matched': sum(rule in item['matched'] for item in items if item['label'] == 'phishing'),
    }


def _intent_summary(outcomes: list[dict], rules: tuple) -> dict:
    """Per rule and language, and for the configuration as a whole: the alerts its rules add,
    counted once per message however many rules match it (the plan's deduplicated count)."""
    paired = bool(rules)
    languages = defaultdict(list)
    for item in outcomes:
        languages[item['language']].append(item)
    combined = {}
    for language, items in sorted(languages.items()):
        legitimate = [item for item in items if item['label'] == 'legitimate']
        risen = (sum(item['decision'] == 'alerted' and item['without_decision'] != 'alerted' for item in legitimate)
                 if paired else None)
        rate, ci = _rate_with_interval(risen, len(legitimate)) if paired else (None, None)
        combined[language] = {
            'legitimate_n': len(legitimate), 'legitimate_new_alerts': risen, 'legitimate_new_alerts_rate': rate,
            'legitimate_new_alerts_rate_95_ci': ci,
            'phishing_added': (sum(item['decision'] == 'alerted' and item['without_decision'] != 'alerted'
                                   for item in items if item['label'] == 'phishing') if paired else None)}
    return {
        'enabled': list(rules),
        'paired_without_rules': paired,
        'by_rule': {rule: {language: _intent_counts(items, rule, paired) for language, items in sorted(languages.items())}
                    for rule in INTENT_RULE_SETTINGS['both']},
        'combined': combined,
    }


def _decision(risk: str) -> str:
    return ('undetermined' if risk == 'unknown' else
            'alerted' if risk in ALERT_LEVELS else 'not_alerted')


def _scoring_sha256() -> str:
    payload = [inspect.getsource(function) for function in
               (_summary, _private_summary, _rate_with_interval, _decision)]
    payload.append({'labels': sorted(LABELS), 'alert_levels': sorted(ALERT_LEVELS),
                    'risk_levels': sorted(RISK_LEVELS), 'wilson_95_z': WILSON_95_Z})
    return hashlib.sha256(b'private-serving-scoring-v1\0' + _json_bytes(payload)).hexdigest()


# How rows are analysed: as submitted, or as a reader would paste them (tools/pasted_cohort.py).
INPUT_MODES = ('as_submitted', 'pasted')


# Services an evaluation must not reach (docs/evaluation.md, 2026-10-19). The deployment profile
# turns RDAP lookups on; an evaluation turns them, and the other services, off.
OFFLINE_ENVIRONMENT = {'RDAP_LOOKUPS': 'false', 'SENDER_HISTORY_ENABLED': 'false',
                       'PHISHGUARD_JEV_ENABLED': 'false', 'LOCAL_LLM_REVIEW_ENABLED': 'false'}


def evaluation_environment(profile: dict, trusted_ids=()) -> dict:
    """The environment a private evaluation runs in: the deployment profile without its services."""
    return {**profile, 'TRUSTED_AUTHSERV_IDS': ','.join(trusted_ids), 'VERIFICATION_MODE': 'off',
            'CASE_MANAGEMENT_ENABLED': 'false', **OFFLINE_ENVIRONMENT}


def external_services(app, settings, environment: dict) -> dict:
    """The services this run could reach, read from its loaded configuration. ARC verification stays
    as served: analyze_record lets analyze_raw_email verify a chain, looking up only the keys of the
    known sealers (email_structure.ARC_SEALERS). The network flag is false only if all are off."""
    import email_structure
    from jev import configuration as jev_configuration

    services = {
        'rdap_lookups': bool(settings.rdap_lookups_enabled),
        'sender_history': bool(settings.sender_history_enabled),
        'jev': jev_configuration(environment)['status'] != 'disabled',
        'local_llm_review': bool(app.LOCAL_REVIEW.enabled),
        'arc_key_lookups': sorted(email_structure.ARC_SEALERS),
        # The setting of /api/verify-email; content analysis does not use it.
        'email_verification_mode': settings.effective_verification_mode,
    }
    network = any((services['rdap_lookups'], services['sender_history'], services['jev'],
                   services['local_llm_review'], services['arc_key_lookups']))
    return {'external_services': services, 'network_services_enabled': network}


def _validated_configuration(configuration: dict | None) -> dict | None:
    # A supplied analyzer must declare its configuration; do not guess it from
    # the current machine or accidentally serialize arbitrary environment data.
    if configuration is None:
        return None
    keys = {'trusted_authserv_ids', 'observe_sender_history', 'verification_mode',
            'content_model_enabled', 'auxiliary_enabled'}
    # The 2026-10-13 plan's settings; reports made before them omit both (option A, no mailbox).
    plan_keys = {'model_only_option', 'mailbox_setting', 'intent_rules'}
    # The services a run could reach (2026-10-19) and the input mode (2026-10-20); earlier reports omit them.
    service_keys = {'external_services', 'network_services_enabled', 'input_mode'}
    if (not isinstance(configuration, dict) or not keys <= set(configuration) <= keys | plan_keys | service_keys
            or configuration.get('input_mode', 'as_submitted') not in INPUT_MODES
            or not isinstance(configuration.get('external_services', {}), dict)
            or type(configuration.get('network_services_enabled', False)) is not bool
            or configuration.get('model_only_option', 'A') not in MODEL_ONLY_OPTIONS
            or configuration.get('mailbox_setting', 'none') not in MAILBOX_SETTINGS
            or configuration.get('intent_rules', 'none') not in INTENT_RULE_SETTINGS):
        raise ValueError('Evaluation configuration is incomplete or unsupported')
    ids = configuration['trusted_authserv_ids']
    if (not isinstance(ids, list) or any(not isinstance(value, str) or
            not re.fullmatch(r'[a-z0-9._-]{1,253}', value) for value in ids)
            or ids != sorted(set(ids))
            or configuration['observe_sender_history'] is not False
            or configuration['verification_mode'] != 'off'
            or type(configuration['content_model_enabled']) is not bool
            or configuration['auxiliary_enabled'] is not False):
        raise ValueError('Evaluation configuration is invalid or uses external state')
    return json.loads(_json_bytes(configuration))


def evaluate_records(
    rows: Iterable[dict],
    analyze: Callable[[dict], dict],
    *,
    model_sha256: str,
    duplicate_policy: str = 'drop',
    configuration: dict | None = None,
    evidence_observer: Callable[[str, str, dict], None] | None = None,
    counterfactual_observer: Callable[[dict, str, str, dict], None] | None = None,
    holdout_authorized: bool = False,
    paste: bool = False,
) -> dict:
    """Run each row through the supplied serving analyzer and emit aggregates. Rows marked
    `cohort_role: holdout` are refused before any analysis unless holdout_authorized: the
    plan keeps the holdout sealed until it is frozen. With paste, each row is analysed as a
    reader would paste it (tools/pasted_cohort.py); a row that cannot be pasted whole is
    excluded and counted by reason, with its input line, never truncated."""
    from tools import pasted_cohort

    if not re.fullmatch(r'[0-9a-f]{64}', model_sha256):
        raise ValueError('A full lowercase model SHA-256 is required')
    if duplicate_policy not in {'drop', 'error'}:
        raise ValueError('duplicate_policy must be drop or error')
    configuration = _validated_configuration(configuration)
    outcomes = []
    dates = []
    seen = {}
    input_digests = []
    included_digests = []
    duplicate_rows = 0
    paste_excluded: dict[str, list[int]] = defaultdict(list)
    for index, raw_row in enumerate(rows, 1):
        row = _validated_record(raw_row, index)
        if row.get('cohort_role') == 'holdout' and not holdout_authorized:
            raise ValueError(f'Row {index}: holdout rows are sealed until the evaluation plan is frozen '
                             '(--frozen-plan-commit)')
        if paste:
            try:
                row = pasted_cohort.pasted(row)
            except pasted_cohort.PasteExcluded as exclusion:
                paste_excluded[exclusion.reason].append(index)
                # Excluded rows stay part of the supplied cohort's identity.
                input_digests.append(hashlib.sha256(_json_bytes(
                    ['paste-excluded', exclusion.reason, row['label'], row['provider'], row['received_at']])).digest())
                continue
            except Exception:
                raise RuntimeError(f'Row {index}: message input could not be read') from None
        try:
            row, content_digest = _prepare_record(row)
        except Exception:
            raise RuntimeError(f'Row {index}: message input could not be read') from None
        # Tags join the metadata only where present, so untagged inputs keep their digests.
        metadata = [row['label'], row['provider'], row['received_at'], row.get('language', 'unlabeled'), *_tags(row)]
        input_digests.append(hashlib.sha256(_json_bytes([content_digest, metadata])).digest())
        if content_digest in seen:
            previous_index, previous_metadata = seen[content_digest]
            if metadata != previous_metadata:
                raise ValueError(f'Row {index}: identical message content has conflicting labels or '
                                 f'group metadata with row {previous_index}')
            if duplicate_policy == 'error':
                raise ValueError(f'Row {index}: duplicate message of row {previous_index}')
            duplicate_rows += 1
            continue
        seen[content_digest] = (index, metadata)
        included_digests.append(input_digests[-1])
        try:
            result = analyze(row)
        except Exception:
            # Never echo a message, sender, URL, or library exception that may
            # contain one of those values.
            raise RuntimeError(f'Row {index}: analysis failed') from None
        risk = result.get('risk_level') if isinstance(result, dict) else None
        if risk not in RISK_LEVELS:
            raise ValueError(f'Row {index}: analyzer returned an invalid risk level')
        decision = _decision(risk)
        evaluation = result.get('_evaluation') or {}
        without = evaluation.get('without_intent_rules')
        outcomes.append({
            'provider': row['provider'],
            'language': row.get('language', 'unlabeled'),
            'month': row['received_at'][:7],
            'label': row['label'],
            'decision': decision,
            'complete': result.get('analysis_complete') is True,
            'ml_available': result.get('ml_status') == 'available',
            # The plan's measures: a review is neither an alert nor a pass.
            'review': result.get('model_only_review') is True,
            'model_only': result.get('fusion_basis') == 'model_only',
            'authenticated': evaluation.get('authenticated'),
            'official': evaluation.get('official'),
            # Part 2: the rules whose findings the result shows, the row's tags, and the
            # decision of the paired run without rules (null when no rule is on).
            'matched': {rule for rule, code in INTENT_RULE_CODES.items()
                        if any(isinstance(indicator, dict) and indicator.get('code') == code
                               for indicator in result.get('extra_indicators') or ())},
            'behaviours': set(_tags(row)[0]) if _tags(row) else set(),
            'control_type': row.get('control_type'),
            'without_decision': _decision(without['risk_level']) if isinstance(without, dict) else None,
        })
        if evidence_observer is not None:
            evidence_observer(row['label'], decision, result)
        if counterfactual_observer is not None:
            counterfactual_observer(row, row['label'], decision, result)
        dates.append(row['received_at'])
    if not outcomes:
        raise ValueError('No evaluation rows were supplied')

    def grouped(items, dimensions):
        if not dimensions:
            return _private_summary(items)
        buckets = defaultdict(list)
        for item in items:
            buckets[item[dimensions[0]]].append(item)
        return {key: grouped(values, dimensions[1:]) for key, values in sorted(buckets.items())}

    return {
        'schema_version': 1,
        'evaluation_scope': 'local_serving_pipeline',
        'scoring_sha256': _scoring_sha256(),
        'inclusion_policy': INCLUSION_POLICY,
        'reproducibility': {'configuration': configuration},
        'input_integrity': {
            'input_rows': len(input_digests),
            'evaluated_rows': len(outcomes),
            'duplicate_rows': duplicate_rows,
            'duplicate_policy': duplicate_policy,
            'deduplication': 'exact effective message input; conflicting labels or group metadata rejected',
            'fingerprint_schema': 'phishguard-evaluation-input-v1',
            # Fixed-length record digests form an order-independent multiset.
            # Include omitted repeats so changes to the supplied cohort remain visible.
            'dataset_sha256': hashlib.sha256(
                b'phishguard-evaluation-input-v1\0' + b''.join(sorted(input_digests))
            ).hexdigest(),
            'evaluated_cohort_sha256': hashlib.sha256(
                b'phishguard-evaluation-cohort-v1\0' + b''.join(sorted(included_digests))
            ).hexdigest(),
            'warnings': ([f'{duplicate_rows} duplicate rows were excluded from all metrics.']
                         if duplicate_rows else []),
            **({'input_mode': 'pasted',
                'paste_exclusions': {reason: len(lines) for reason, lines in sorted(paste_excluded.items())},
                # Input line numbers only, so P1 and P2 can be paired by source message.
                'paste_excluded_lines': {reason: lines for reason, lines in sorted(paste_excluded.items())}}
               if paste else {}),
        },
        'alert_policy': ALERT_POLICY,
        'confidence_intervals': 'two-sided 95% Wilson score intervals',
        'temporal_isolation': 'not_verified',
        'model_artifact_sha256': model_sha256,
        'first_received_at': min(dates),
        'last_received_at': max(dates),
        'overall': _private_summary(outcomes),
        'model_only_plan': _plan_summary(outcomes),
        'intent_rules': _intent_summary(outcomes, INTENT_RULE_SETTINGS[(configuration or {}).get('intent_rules', 'none')]),
        **{'by_' + '_'.join(dimensions): grouped(outcomes, dimensions) for dimensions in (
            ('provider',), ('language',), ('month',), ('provider', 'language'),
            ('provider', 'month'), ('language', 'month'), ('provider', 'language', 'month'))},
    }


def _jsonl_records(path: Path):
    with path.open(encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f'Line {line_number}: invalid JSON') from None


def analyze_record(row: dict, *, mailbox_setting: str = 'none', intent_rules: tuple = ()) -> dict:
    """Analyze one validated row using the configured local app, without history writes.

    mailbox_setting "recorded" reads an .eml as downloaded from the row's verified provider
    (analyze_raw_email(mailbox_provider=...)); "none" as if no mailbox were chosen. For an .eml
    the result also carries, for the evaluator only, whether its sender is authenticated.
    With intent rules on, the row is analysed again with none, and that run's level is kept
    beside the result, so the report can count the alerts the rules add."""
    import app

    if mailbox_setting not in MAILBOX_SETTINGS:
        raise ValueError('Unknown mailbox setting')
    rules = frozenset(intent_rules)
    if not rules <= getattr(app, 'IMPLEMENTED_INTENT_RULES', frozenset()):
        raise ValueError('This build does not implement that intent rule')
    if 'eml_path' not in row and mailbox_setting == 'recorded':
        raise ValueError('The recorded mailbox setting needs .eml input')

    def analyze(enabled: frozenset) -> tuple[dict, dict | None]:
        structure = None
        if 'eml_path' in row:
            raw = row['_eml_bytes'] if '_eml_bytes' in row else _read_eml(row['eml_path'])
            structure = app.analyze_raw_email(
                raw, trusted_authserv_ids=app.SETTINGS.trusted_authserv_ids,
                mailbox_provider=row['provider'] if mailbox_setting == 'recorded' else None,
            )
            request = app.ContentRequest()
        else:
            request = app.ContentRequest(
                subject=row.get('subject', ''), body=row.get('body', ''),
                raw_email=row.get('raw_email', ''),
            )
        token = app.INTENT_RULES.set(enabled) if rules else None
        try:
            return json.loads(asyncio.run(app._analyze_content(
                request, structure, observe_sender_history=False,
            )).body), structure
        finally:
            if token is not None:
                app.INTENT_RULES.reset(token)

    result, structure = analyze(rules)
    if rules:
        without, _structure = analyze(frozenset())
        result.setdefault('_evaluation', {})['without_intent_rules'] = {'risk_level': without.get('risk_level')}
    if structure is not None:
        result.setdefault('_evaluation', {}).update({
            'authenticated': bool(structure.get('authenticated_sender') or structure.get('verified_official_sender')),
            'official': bool(structure.get('verified_official_sender'))})
    return result


def _evaluation_metadata(configuration: dict) -> dict:
    from model_environment import RUNTIME_PACKAGE_NAMES, package_versions

    # Include local edits and the registries, without publishing source or mail.
    sources = sorted(WEBSITE_DIR.glob('*.py')) + sorted((WEBSITE_DIR / 'data').glob('*.json'))
    sources += [Path(__file__).resolve(), PROJECT_ROOT / 'app.py']
    source_digest = hashlib.sha256()
    for path in sources:
        source_digest.update(path.relative_to(PROJECT_ROOT).as_posix().encode() + b'\0')
        source_digest.update(hashlib.sha256(path.read_bytes()).digest())
    commit = dirty = None
    try:
        commit = subprocess.run(
            ['git', 'rev-parse', 'HEAD'], cwd=PROJECT_ROOT, check=True,
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ['git', 'status', '--porcelain'], cwd=PROJECT_ROOT, check=True,
            capture_output=True, text=True, timeout=5,
        ).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return {
        'git_commit': commit,
        'git_dirty': dirty,
        'source_sha256': source_digest.hexdigest(),
        'deployment_profile_sha256': hashlib.sha256((PROJECT_ROOT / 'vercel.json').read_bytes()).hexdigest(),
        'python_version': platform.python_version(),
        'platform': {'system': platform.system(), 'machine': platform.machine()},
        'package_versions': package_versions((*RUNTIME_PACKAGE_NAMES, 'fastapi', 'pydantic', 'tldextract')),
        'configuration': configuration,
    }


def _frozen_plan(commit: str) -> dict:
    """The plan at a commit, if it was frozen there: D12's reviewer recorded, not pending."""
    if not re.fullmatch(r'[0-9a-f]{7,40}', commit or ''):
        raise SystemExit('--frozen-plan-commit must be a commit hash')
    try:
        text = subprocess.run(['git', 'show', f'{commit}:{PLAN_PATH}'], cwd=PROJECT_ROOT, check=True,
                              capture_output=True, text=True, timeout=10).stdout
        full = subprocess.run(['git', 'rev-parse', '--verify', commit + '^{commit}'], cwd=PROJECT_ROOT,
                              check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise SystemExit('The evaluation plan was not found at that commit') from None
    if 'not yet assigned' in text or 'not frozen' in text:
        raise SystemExit('The evaluation plan is not frozen at that commit: the reviewer (D12) is still pending')
    return {'commit': full, 'plan_sha256': hashlib.sha256(text.encode()).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path,
                        help='Local JSONL file with consented, labeled messages')
    parser.add_argument('--trusted-authserv-id', action='append', default=[],
                        help='Explicit trusted authentication service ID; repeat for multiple IDs (default: none)')
    parser.add_argument('--duplicate-policy', choices=('drop', 'error'), default='drop',
                        help='Drop exact duplicates (default), or reject them; metadata conflicts always fail')
    parser.add_argument('--attribution-output', type=Path,
                        help='Optional aggregate signal counts; keep beside the private input')
    parser.add_argument('--artifact', type=Path,
                        help='A candidate model artifact (for example one trained on private mail) '
                             'instead of the committed one; requires --artifact-sha256')
    parser.add_argument('--artifact-sha256',
                        help='SHA-256 digest of --artifact, as prebuild_demo_model.py printed it')
    parser.add_argument('--counterfactual-output', type=Path,
                        help='Optional aggregate alert transitions after one-family removal')
    parser.add_argument('--option', choices=MODEL_ONLY_OPTIONS, default='A',
                        help="How a model-only alert on an original message is labelled (the 2026-10-13 "
                             "evaluation plan); A is the served behaviour")
    parser.add_argument('--mailbox-setting', choices=MAILBOX_SETTINGS, default='none',
                        help='"recorded" reads each .eml as downloaded from its row\'s verified provider')
    parser.add_argument('--intent-rules', choices=tuple(INTENT_RULE_SETTINGS), default='none',
                        help='Intent rules of the 2026-10-13 plan to turn on (evaluation only). Refused until '
                             'this build implements the rule. With a rule on, each message is also analysed '
                             'without rules, to count the alerts the rules add')
    parser.add_argument('--paste', action='store_true',
                        help='Analyse each row as a reader would paste it: subject and visible text, no '
                             'headers, read with ARC off; rows too long are excluded and counted, never truncated')
    parser.add_argument('--frozen-plan-commit',
                        help='Commit at which the evaluation plan was frozen (D12 recorded); required '
                             'before any row marked cohort_role=holdout is scored')
    args = parser.parse_args()
    if (args.artifact is None) != (args.artifact_sha256 is None):
        parser.error('--artifact and --artifact-sha256 go together')
    if args.paste and args.mailbox_setting == 'recorded':
        parser.error('--paste reads no headers, so it cannot use a recorded mailbox')
    paths = [path.resolve() for path in (args.input, args.attribution_output,
                                        args.counterfactual_output) if path is not None]
    if len(paths) != len(set(paths)):
        parser.error('Input and diagnostic outputs must use distinct paths')
    trusted_ids = sorted({value.strip().lower() for value in args.trusted_authserv_id})
    if any(not re.fullmatch(r'[a-z0-9._-]{1,253}', value) for value in trusted_ids):
        parser.error('Trusted authentication service IDs must contain only ASCII letters, digits, dots, underscores or hyphens')

    frozen_plan = _frozen_plan(args.frozen_plan_commit) if args.frozen_plan_commit else None
    sys.path.insert(0, str(WEBSITE_DIR))
    from content_inference import load_content_pipeline_artifact
    from config import load_settings
    from tools.evidence_attribution import EvidenceAttribution
    from tools.counterfactual_evidence import CounterfactualEvidence

    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    evaluation_env = evaluation_environment(profile, trusted_ids)
    # Import-time settings must not inherit the invoking shell's trust or services.
    with patch.dict(os.environ, evaluation_env, clear=True):
        import app
    intent_rules = INTENT_RULE_SETTINGS[args.intent_rules]
    missing = sorted(set(intent_rules) - getattr(app, 'IMPLEMENTED_INTENT_RULES', frozenset()))
    if missing:
        raise SystemExit(f'This build does not implement the intent rule(s) {", ".join(missing)}; '
                         'none has been approved for wiring yet')
    settings = load_settings(evaluation_env)
    configuration = {'trusted_authserv_ids': sorted(settings.trusted_authserv_ids),
                     'observe_sender_history': False, 'verification_mode': settings.effective_verification_mode,
                     'content_model_enabled': settings.content_model_enabled, 'auxiliary_enabled': False,
                     'model_only_option': args.option, 'mailbox_setting': args.mailbox_setting,
                     'intent_rules': args.intent_rules, **external_services(app, settings, evaluation_env),
                     'input_mode': 'pasted' if args.paste else 'as_submitted'}
    if args.artifact is not None:
        # A local candidate: it may be trained on private mail, which only a local run may load.
        model_sha256 = args.artifact_sha256.strip().lower()
        pipeline = load_content_pipeline_artifact(args.artifact, model_sha256, allow_private=True)
    else:
        model_sha256 = profile['CONTENT_MODEL_ARTIFACT_SHA256'].lower()
        pipeline = load_content_pipeline_artifact(
            PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], model_sha256,
        )

    analyze = partial(analyze_record, mailbox_setting=args.mailbox_setting, intent_rules=intent_rules)
    attribution = EvidenceAttribution() if args.attribution_output else None
    # Replays run through the same analyzer, so with the baseline's mailbox setting and intent rules;
    # the model-only option below holds for both.
    counterfactual = (CounterfactualEvidence(analyze=analyze, intent_rules_enabled=bool(intent_rules))
                      if args.counterfactual_output else None)
    option_token = app.MODEL_ONLY_OPTION.set(args.option)
    try:
        with patch.object(app, '_content_pipeline', pipeline), patch.object(app, 'SETTINGS', settings):
            report = evaluate_records(_jsonl_records(args.input), analyze,
                                      model_sha256=model_sha256, duplicate_policy=args.duplicate_policy,
                                      configuration=configuration,
                                      evidence_observer=attribution.add if attribution else None,
                                      counterfactual_observer=counterfactual.add if counterfactual else None,
                                      holdout_authorized=frozen_plan is not None, paste=args.paste)
    finally:
        app.MODEL_ONLY_OPTION.reset(option_token)
    report['reproducibility'] = {**_evaluation_metadata(configuration), 'frozen_plan': frozen_plan}
    if attribution:
        args.attribution_output.write_text(json.dumps(attribution.snapshot(report), indent=2,
                                                sort_keys=True) + '\n', encoding='utf-8')
    if counterfactual:
        args.counterfactual_output.write_text(json.dumps(counterfactual.snapshot(report),
                                                   indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2, sort_keys=True))
    if counterfactual and counterfactual.failure_count:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
