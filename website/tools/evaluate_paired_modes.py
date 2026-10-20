"""Compare the owner's originals read as .eml (P1) and as pasted text (P2), paired by source, in memory.

docs/superpowers/specs/2026-10-20-p1-p2-pairing-design.md (approved 2026-10-20):

- Each row is validated once, a holdout row is refused, and internal fields are dropped, all before
  any source is read. Each original is then read once, into a trusted snapshot of at most 3 MiB.
  Its digest, P1 view and P2 view all come from that snapshot. A larger source gets no digest.
- Duplicates are decided per mode by a stable rule: the smallest source digest represents its
  content. Byte-identical originals are one source; the copies are "neither".
- Sources fall into pairs, P1 only, P2 only and neither. Only counts and set digests leave the
  process, never which source is where. Errors carry no row position.
- Each non-empty set and mode is evaluated by evaluate_records, unchanged, with its sidecars; the
  3 x 3 decision table of the pairs is for the private report only.

usage: evaluate_paired_modes.py --input /abs/sources.jsonl --output /abs/private-report.json
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))
from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools import pasted_cohort  # noqa: E402

SCHEMA_VERSION = 'paired-modes/v1'
SETS = ('pairs', 'p1_only', 'p2_only', 'neither')
DECISIONS = ('alerted', 'not_alerted', 'undetermined')
_SET_PREFIX = b'phishguard-paired-set-v1\0'
_FIELDS_OF_METADATA = ('label', 'provider', 'received_at', 'language')


class PairedRunError(RuntimeError):
    """A stopped run. Its message is fixed: no row position, identifier, path or text."""


def _read_snapshot(path: str) -> bytes:
    """The one read of an original: at most one byte past the paste source limit."""
    with Path(path).open('rb') as source:
        return source.read(pasted_cohort.MAX_SOURCE_BYTES + 1)


def _metadata(row: dict) -> list:
    return [row['label'], row['provider'], row['received_at'], row.get('language', 'unlabeled'), *serving._tags(row)]


def _set_digest(digests: list[str | None]) -> str | None:
    if any(digest is None for digest in digests):
        return None
    return hashlib.sha256(_SET_PREFIX + b''.join(sorted(bytes.fromhex(digest) for digest in digests))).hexdigest()


def _p1_content(snapshot: bytes) -> str:
    return hashlib.sha256(b'eml-bytes\0' + snapshot).hexdigest()


def _p2_content(row: dict) -> str:
    return hashlib.sha256(b'subject-body\0' + serving._json_bytes([row['subject'], row['body']])).hexdigest()


def _sources(rows, read):
    """Validated, cleaned rows with their snapshots and digests; refuses a holdout row before any
    source is read."""
    try:
        validated = [serving._validated_record(row, index) for index, row in enumerate(rows, 1)]
    except Exception:
        raise PairedRunError('An input row is invalid') from None
    if any(row.get('cohort_role') == 'holdout' for row in validated):
        raise PairedRunError('A holdout row was supplied; the holdout stays sealed')
    if any('eml_path' not in row for row in validated):
        raise PairedRunError('Every input row must name an original .eml file')
    sources = []
    for row in validated:
        clean = {key: value for key, value in row.items() if not key.startswith('_')}
        try:
            snapshot = read(clean['eml_path'])
        except Exception:
            raise PairedRunError('A source file could not be read') from None
        too_large = len(snapshot) > pasted_cohort.MAX_SOURCE_BYTES
        sources.append({'row': clean, 'snapshot': None if too_large else snapshot,
                        'digest': None if too_large else hashlib.sha256(snapshot).hexdigest(),
                        'p1': None, 'p2': None, 'p1_reason': None, 'p2_reason': None})
    return sources


def _views(sources) -> None:
    """Each source's P1 and P2 view, or the reason it has none; then duplicates, by a stable rule."""
    by_digest = defaultdict(list)
    for source in sources:
        snapshot = source['snapshot']
        if snapshot is None:
            source['p1_reason'] = source['p2_reason'] = 'source_too_large'
            continue
        if not snapshot.strip():
            source['p1_reason'] = source['p2_reason'] = 'empty_source'
            continue
        by_digest[source['digest']].append(source)
    # Byte-identical originals are one source: they must agree on their metadata.
    for copies in by_digest.values():
        if any(_metadata(copy['row']) != _metadata(copies[0]['row']) for copy in copies):
            raise PairedRunError('Identical originals carry conflicting labels or group metadata')
        for copy in copies[1:]:
            copy['p1_reason'] = copy['p2_reason'] = 'duplicate_source'
    unique = [copies[0] for copies in by_digest.values()]
    for source in unique:
        if len(source['snapshot']) > serving.MAX_EML_BYTES:
            source['p1_reason'] = 'eml_too_large'
        else:
            source['p1'] = source['snapshot']
        try:
            source['p2'] = pasted_cohort.pasted({**source['row'], '_eml_bytes': source['snapshot']})
        except pasted_cohort.PasteExcluded as exclusion:
            source['p2_reason'] = exclusion.reason
    # Within each mode, equal content is represented by the smallest source digest.
    for mode, content in (('p1', _p1_content), ('p2', _p2_content)):
        groups = defaultdict(list)
        for source in unique:
            if source[mode] is not None:
                groups[content(source[mode])].append(source)
        for group in groups.values():
            if any(_metadata(member['row']) != _metadata(group[0]['row']) for member in group):
                raise PairedRunError('Equal content carries conflicting labels or group metadata')
            group.sort(key=lambda member: member['digest'])
            for member in group[1:]:
                member[mode], member[f'{mode}_reason'] = None, 'duplicate'


def _set_of(source) -> str:
    has_p1, has_p2 = source['p1'] is not None, source['p2'] is not None
    return 'pairs' if has_p1 and has_p2 else 'p1_only' if has_p1 else 'p2_only' if has_p2 else 'neither'


def evaluate_paired(rows, *, model_sha256: str, configurations: dict, read=_read_snapshot) -> dict:
    """The private report of a paired run. configurations holds the 'p1' and 'p2' evaluation
    configurations (as evaluate_serving_pipeline.py records them)."""
    from tools.counterfactual_evidence import CounterfactualEvidence
    from tools.evidence_attribution import EvidenceAttribution

    sources = _sources(rows, read)
    _views(sources)
    members = defaultdict(list)
    for source in sources:
        members[_set_of(source)].append(source)
    # The same order whatever the input order: by source digest, unhashed sources last.
    for group in members.values():
        group.sort(key=lambda source: (source['digest'] is None, source['digest'] or ''))
    analyzers = {'p1': partial(serving.analyze_record, mailbox_setting='recorded'), 'p2': serving.analyze_record}
    reports, decisions = {}, defaultdict(dict)
    for set_name, modes in (('pairs', ('p1', 'p2')), ('p1_only', ('p1',)), ('p2_only', ('p2',))):
        if not members[set_name]:
            continue  # an empty set is reported as a zero count; evaluate_records refuses it
        reports[set_name] = {}
        for mode in modes:
            attribution, counterfactual = EvidenceAttribution(), CounterfactualEvidence(analyze=analyzers[mode])
            content = _p1_content if mode == 'p1' else _p2_content

            def observe(row, label, decision, result, _mode=mode, _counterfactual=counterfactual, _content=content,
                        _set=set_name):
                if _set == 'pairs':
                    decisions[_mode][_content(row['_eml_bytes'] if _mode == 'p1' else row)] = (label, decision)
                _counterfactual.add(row, label, decision, result)

            group = members[set_name]
            if mode == 'p1':
                batch = {'rows': [source['row'] for source in group], 'snapshots': [source['p1'] for source in group]}
            else:
                batch = {'rows': [source['row'] for source in group], 'snapshots': [source['snapshot'] for source in group],
                         'paste': True}
            try:
                report = serving.evaluate_records(batch['rows'], analyzers[mode], model_sha256=model_sha256,
                                                  configuration=configurations[mode], snapshots=batch['snapshots'],
                                                  paste=batch.get('paste', False),
                                                  evidence_observer=attribution.add, counterfactual_observer=observe)
            except PairedRunError:
                raise
            except Exception:
                raise PairedRunError('An analysis failed or a row was refused') from None
            reports[set_name][mode] = {'report': report, 'set_digest': _set_digest([s['digest'] for s in group]),
                                       'counterfactual': counterfactual.snapshot(report),
                                       'attribution': attribution.snapshot(report)}
    table = {label: {p1: {p2: 0 for p2 in DECISIONS} for p1 in DECISIONS} for label in sorted(serving.LABELS)}
    for source in members['pairs']:
        label, p1 = decisions['p1'][_p1_content(source['p1'])]
        _label, p2 = decisions['p2'][_p2_content(source['p2'])]
        table[label][p1][p2] += 1
    reasons = {mode: dict(sorted(Counter(source[f'{mode}_reason'] for source in sources
                                         if source[f'{mode}_reason'] is not None).items())) for mode in ('p1', 'p2')}
    counts = {name: len(members[name]) for name in SETS}
    if sum(counts.values()) != len(sources):
        raise PairedRunError('The sets do not account for every input record')
    return {
        'schema_version': SCHEMA_VERSION,
        'input_integrity': {
            # Input records that passed validation, duplicate copies included.
            'valid_records': len(sources),
            'sets': counts,
            'set_digests': {name: _set_digest([source['digest'] for source in members[name]]) if members[name] else None
                            for name in SETS},
            'unhashed': {name: sum(source['digest'] is None for source in members[name]) for name in SETS},
            'without_view': reasons,
        },
        'reports': reports,
        # Private: counts of the pairs' decisions, P1 by row, P2 by column. Never shared as it is.
        'decision_table': table,
    }


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--input', required=True, type=Path, help='JSONL of the original sources (eml_path rows)')
    parser.add_argument('--output', required=True, type=Path, help='the private report, beside the private data')
    args = parser.parse_args(argv)
    if not args.input.is_absolute() or not args.output.is_absolute() or args.input.resolve() == args.output.resolve():
        parser.error('--input and --output must be distinct absolute paths')
    try:
        from config import load_settings
        from content_inference import load_content_pipeline_artifact

        profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
        environment = serving.evaluation_environment(profile)
        with patch.dict(os.environ, environment, clear=True):
            import app
        settings = load_settings(environment)
        model_sha256 = profile['CONTENT_MODEL_ARTIFACT_SHA256'].lower()
        pipeline = load_content_pipeline_artifact(PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], model_sha256)
        base = {'trusted_authserv_ids': [], 'observe_sender_history': False,
                'verification_mode': settings.effective_verification_mode,
                'content_model_enabled': settings.content_model_enabled, 'auxiliary_enabled': False,
                'model_only_option': 'A', 'intent_rules': 'none',
                **serving.external_services(app, settings, environment)}
        configurations = {'p1': {**base, 'mailbox_setting': 'recorded', 'input_mode': 'as_submitted'},
                          'p2': {**base, 'mailbox_setting': 'none', 'input_mode': 'pasted'}}
        try:
            rows = list(serving._jsonl_records(args.input))
        except Exception:
            raise PairedRunError('The input file is not valid JSONL') from None
        with patch.object(app, '_content_pipeline', pipeline), patch.object(app, 'SETTINGS', settings):
            report = evaluate_paired(rows, model_sha256=model_sha256, configurations=configurations)
        report['tool'] = {'file_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        report['reproducibility'] = serving._evaluation_metadata(configurations)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    except PairedRunError as error:
        sys.stderr.write(f'Paired run stopped: {error}\n')
        raise SystemExit(1) from None
    except Exception:
        sys.stderr.write('Paired run stopped: an unexpected error\n')
        raise SystemExit(1) from None
    # Counts only on standard output.
    print(json.dumps({'valid_records': report['input_integrity']['valid_records'],
                      'sets': report['input_integrity']['sets']}, sort_keys=True))


if __name__ == '__main__':
    main()
