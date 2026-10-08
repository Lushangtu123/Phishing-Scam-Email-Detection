"""How well a local language model labels whole messages, as a teacher for training data.

The local review only reads alerts that rest on the text model. A teacher would label every
message, so this asks the same model, with the same prompt, about each labelled message of
consented cohorts (the evaluate_serving_pipeline.py format) and compares its verdicts with
the human labels. It reads what the text model reads: the subject, the visible text and the
link hosts. The report holds counts only: verdicts and confidence by cohort and label, and
the precision, recall and coverage of labels accepted at several confidence floors. No
message text, address or per-message row is written. Ollama must run on this computer.

Given several --model, it asks each about every message and also counts their agreement as
one teacher: a verdict only when all give it, at the lowest of their confidences, so a
disagreement goes to a person.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools.evaluate_local_review import MAX_PASTE_SOURCE_BYTES, _cohort, _model_digests  # noqa: E402
import local_review as lr  # noqa: E402

# A label is used without a person only at or above a confidence floor; below it, a person decides.
FLOORS = (50, 80, 90)
THINK_LEVELS = ('low', 'medium', 'high')


def model_input(row: dict) -> tuple[str, str, list[str]]:
    """The subject, visible text and link hosts the text model (and the review) read."""
    import app

    view = {}
    if 'eml_path' in row or row.get('raw_email'):
        if 'eml_path' in row:
            raw = Path(row['eml_path']).read_bytes()
            if not raw.strip() or len(raw) > MAX_PASTE_SOURCE_BYTES:
                raise ValueError('email file must contain 1 byte to 3 MiB')
        else:
            raw = row['raw_email']
        structure = app.analyze_raw_email(raw, trusted_authserv_ids=())
        result = app.analyze_email_content(structure['subject'], structure['body'],
                                           content_parts=structure['content_parts'], _model_view=view,
                                           sender=structure['from'])
    else:
        result = app.analyze_email_content(row.get('subject', ''), row.get('body', ''), _model_view=view)
    return view.get('subject', ''), view.get('body', ''), result.get('link_hosts', [])


def agreed(readings: list) -> dict | str | None:
    """Several models as one teacher: the verdict all of them give, at the lowest of their
    confidences; 'disagree' when they differ, None when any gave no answer."""
    if any(reading is None for reading in readings):
        return None
    if len({reading['verdict'] for reading in readings}) > 1:
        return 'disagree'
    return {'verdict': readings[0]['verdict'], 'confidence': min(reading['confidence'] for reading in readings)}


def _count_key(reading) -> str:
    if reading is None:
        return 'unavailable'
    if reading == 'disagree':
        return 'disagree'
    confidence = reading['confidence']
    band = '90-100' if confidence >= 90 else '80-89' if confidence >= 80 else '70-79' if confidence >= 70 else '50-69'
    return f"{reading['verdict']}_{band}"


def label_cohort(rows: list[dict], asks: dict) -> dict:
    """Verdict counts by label for each model and, with several models, for their agreement."""
    names = [*asks, 'agreement'] if len(asks) > 1 else [*asks]
    counts = {name: {label: Counter() for label in sorted(serving.LABELS)} for name in names}
    for row in rows:
        view = model_input(row)
        readings = {name: ask(*view) for name, ask in asks.items()}
        if len(asks) > 1:
            readings['agreement'] = agreed(list(readings.values()))
        for name, reading in readings.items():
            counter = counts[name][row['label']]
            counter['messages'] += 1
            counter[_count_key(reading)] += 1
    return {name: {label: dict(counter) for label, counter in by_label.items() if counter['messages']}
            for name, by_label in counts.items()}


def floor_metrics(cohorts: dict) -> dict:
    """Precision and recall of the phishing label, and how much is labelled without a person.

    label_with_llm.py uses only legitimate readings at or above its floor without a person, so
    missed_phishing is the phishing that would enter training, and legitimate_to_person the
    genuine mail a person would have to label."""
    metrics = {}
    for floor in FLOORS:
        tp = fp = fn = tn = labelled = total = legitimate = 0
        for labels in cohorts.values():
            for truth, counter in labels.items():
                total += counter['messages']
                legitimate += counter['messages'] if truth == 'legitimate' else 0
                for key, value in counter.items():
                    if '_' not in key or key == 'messages':
                        continue
                    verdict, band = key.split('_')
                    if int(band.split('-')[0]) < floor:
                        continue  # below the floor: a person labels it
                    labelled += value
                    if verdict == 'phishing':
                        tp += value if truth == 'phishing' else 0
                        fp += value if truth == 'legitimate' else 0
                    else:
                        fn += value if truth == 'phishing' else 0
                        tn += value if truth == 'legitimate' else 0
        metrics[f'confidence>={floor}'] = {
            'labelled': labelled, 'messages': total,
            'coverage': round(labelled / total, 4) if total else None,
            'phishing_precision': round(tp / (tp + fp), 4) if tp + fp else None,
            'phishing_recall': round(tp / (tp + fn), 4) if tp + fn else None,
            'legitimate_precision': round(tn / (tn + fn), 4) if tn + fn else None,
            'errors': fp + fn, 'false_phishing': fp, 'missed_phishing': fn,
            'legitimate_to_person': legitimate - tn,
        }
    return metrics


def load_rows(path: Path, limit: int | None) -> list[dict]:
    rows = []
    for index, row in enumerate(serving._jsonl_records(path), 1):
        if limit is not None and len(rows) >= limit:
            break
        rows.append(serving._validated_record(row, index))
    return rows


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--input', action='append', type=_cohort, default=[], metavar='NAME=PATH', required=True)
    parser.add_argument('--model', action='append', required=True,
                        help='an Ollama model name; give it again to measure several models and their agreement')
    parser.add_argument('--think', action='append', default=[], metavar='MODEL=LEVEL',
                        help='reasoning level low, medium or high for a model that cannot turn it off (gpt-oss)')
    parser.add_argument('--url', default='http://127.0.0.1:11434')
    parser.add_argument('--limit', type=int, help='at most this many rows per cohort (smoke runs)')
    parser.add_argument('--output', type=Path, help='aggregate JSON report; defaults to stdout')
    args = parser.parse_args(argv)
    url = args.url.rstrip('/')
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname not in lr._LOOPBACK or parts.path:
        parser.error('--url must be http on a loopback address: mail text never leaves this computer')
    if any(lr._MODEL_NAME.fullmatch(model) is None for model in args.model) or len(set(args.model)) < len(args.model):
        parser.error('invalid or repeated --model name')
    think = dict.fromkeys(args.model, False)
    for item in args.think:
        model, _, level = item.rpartition('=')
        if model not in think or level not in THINK_LEVELS:
            parser.error(f'--think takes MODEL=LEVEL for a given --model, LEVEL one of {", ".join(THINK_LEVELS)}')
        think[model] = level

    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    env = {**profile, 'RDAP_LOOKUPS': 'false', 'SENDER_HISTORY_ENABLED': 'false', 'VERIFICATION_MODE': 'off',
           'CASE_MANAGEMENT_ENABLED': 'false', 'PHISHGUARD_JEV_ENABLED': 'false', 'TRUSTED_AUTHSERV_IDS': ''}
    with patch.dict(os.environ, env, clear=True):
        import app  # noqa: F401 -- loads the parsers model_input uses with the served profile
    samples = {model: [] for model in args.model}

    def asker(model):
        settings = lr.LocalReviewSettings(url, model, think=think[model])

        def ask(subject, body, hosts):
            start = time.perf_counter()
            try:
                return lr.review(settings, subject, body, hosts)
            finally:
                samples[model].append(time.perf_counter() - start)
        return ask

    asks = {model: asker(model) for model in args.model}
    counts = {name: label_cohort(load_rows(path, args.limit), asks) for name, path in args.input}
    by_name = {name: {cohort: result[name] for cohort, result in counts.items()} for name in next(iter(counts.values()))}
    digests = _model_digests(url)
    prompt_sha256 = hashlib.sha256((lr.PROMPT + json.dumps(lr.SCHEMA, sort_keys=True)).encode()).hexdigest()

    def seconds(values):
        return ({'calls': len(values), 'mean': round(statistics.fmean(values), 2),
                 'median': round(statistics.median(values), 2), 'max': round(max(values), 2)}
                if values else {'calls': 0})

    limitations = ('Counts only. Public corpora may be in the model\'s training data; the owner\'s consented '
                   'mail is the trustworthy part. Human labels are the reference, not the model.')
    if len(args.model) == 1:
        model = args.model[0]
        configuration = {'model': model, 'model_digest': digests.get(model), 'think': think[model],
                         'prompt_sha256': prompt_sha256, 'confidence_floors': list(FLOORS)}
        report = {'schema_version': 1, 'cohorts': by_name[model], 'metrics': floor_metrics(by_name[model]),
                  'seconds': seconds(samples[model])}
    else:
        configuration = {'models': args.model, 'model_digests': {model: digests.get(model) for model in args.model},
                         'think': think, 'prompt_sha256': prompt_sha256, 'confidence_floors': list(FLOORS),
                         'agreement': 'the verdict every model gives, at the lowest of their confidences'}
        report = {'schema_version': 2,
                  'models': {model: {'cohorts': by_name[model], 'metrics': floor_metrics(by_name[model]),
                                     'seconds': seconds(samples[model])} for model in args.model},
                  'agreement': {'cohorts': by_name['agreement'], 'metrics': floor_metrics(by_name['agreement'])}}
    report |= {'configuration': configuration, 'reproducibility': serving._evaluation_metadata(configuration),
               'limitations': limitations}
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
