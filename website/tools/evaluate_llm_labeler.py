"""How well a local language model labels whole messages, as a teacher for training data.

The local review only reads alerts that rest on the text model. A teacher would label every
message, so this asks the same model, with the same prompt, about each labelled message of
consented cohorts (the evaluate_serving_pipeline.py format) and compares its verdicts with
the human labels. It reads what the text model reads: the subject, the visible text and the
link hosts. The report holds counts only: verdicts and confidence by cohort and label, and
the precision, recall and coverage of labels accepted at several confidence floors. No
message text, address or per-message row is written. Ollama must run on this computer.
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


def label_cohort(rows: list[dict], ask) -> dict:
    counts = {label: Counter() for label in sorted(serving.LABELS)}
    for row in rows:
        counter = counts[row['label']]
        counter['messages'] += 1
        reading = ask(*model_input(row))
        if reading is None:
            counter['unavailable'] += 1
            continue
        verdict, confidence = reading['verdict'], reading['confidence']
        band = '90-100' if confidence >= 90 else '80-89' if confidence >= 80 else '70-79' if confidence >= 70 else '50-69'
        counter[f'{verdict}_{band}'] += 1
    return {label: dict(counter) for label, counter in counts.items() if counter['messages']}


def floor_metrics(cohorts: dict) -> dict:
    """Precision and recall of the phishing label, and how much is labelled without a person."""
    metrics = {}
    for floor in FLOORS:
        tp = fp = fn = tn = labelled = total = 0
        for labels in cohorts.values():
            for truth, counter in labels.items():
                total += counter['messages']
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
    parser.add_argument('--model', required=True, help='an Ollama model name')
    parser.add_argument('--url', default='http://127.0.0.1:11434')
    parser.add_argument('--limit', type=int, help='at most this many rows per cohort (smoke runs)')
    parser.add_argument('--output', type=Path, help='aggregate JSON report; defaults to stdout')
    args = parser.parse_args(argv)
    url = args.url.rstrip('/')
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname not in lr._LOOPBACK or parts.path:
        parser.error('--url must be http on a loopback address: mail text never leaves this computer')
    if lr._MODEL_NAME.fullmatch(args.model) is None:
        parser.error('invalid --model name')

    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    env = {**profile, 'RDAP_LOOKUPS': 'false', 'SENDER_HISTORY_ENABLED': 'false', 'VERIFICATION_MODE': 'off',
           'CASE_MANAGEMENT_ENABLED': 'false', 'PHISHGUARD_JEV_ENABLED': 'false', 'TRUSTED_AUTHSERV_IDS': ''}
    with patch.dict(os.environ, env, clear=True):
        import app  # noqa: F401 -- loads the parsers model_input uses with the served profile
    settings = lr.LocalReviewSettings(url, args.model)
    samples = []

    def ask(subject, body, hosts):
        start = time.perf_counter()
        try:
            return lr.review(settings, subject, body, hosts)
        finally:
            samples.append(time.perf_counter() - start)

    cohorts = {name: label_cohort(load_rows(path, args.limit), ask) for name, path in args.input}
    configuration = {
        'model': args.model, 'model_digest': _model_digests(url).get(args.model),
        'prompt_sha256': hashlib.sha256((lr.PROMPT + json.dumps(lr.SCHEMA, sort_keys=True)).encode()).hexdigest(),
        'confidence_floors': list(FLOORS),
    }
    report = {
        'schema_version': 1, 'cohorts': cohorts, 'metrics': floor_metrics(cohorts),
        'seconds': ({'calls': len(samples), 'mean': round(statistics.fmean(samples), 2),
                     'median': round(statistics.median(samples), 2), 'max': round(max(samples), 2)}
                    if samples else {'calls': 0}),
        'configuration': configuration,
        'reproducibility': serving._evaluation_metadata(configuration),
        'limitations': ('Counts only. Public corpora may be in the model\'s training data; the owner\'s consented '
                        'mail is the trustworthy part. Human labels are the reference, not the model.'),
    }
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
