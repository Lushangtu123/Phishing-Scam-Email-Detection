"""Compare local language models as reviewers of alerts that rest on the text model alone.

Runs the serving pipeline over consented JSONL cohorts (the evaluate_serving_pipeline.py
format) once per model, with the local review in shadow mode, and writes aggregate counts
only: for each cohort and label, the alerts and how many of them a model would lower, keep
or could not review, with its response times. No message text, address or per-message row
is written. A pasted cohort (--paste) turns each message into what a reader would copy into
the page: its subject and visible text, without headers. Ollama must run on this computer:
only loopback addresses are accepted, as for the served review (docs/llm-review-rollout.md).
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
from urllib.request import ProxyHandler, build_opener

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_serving_pipeline as serving  # noqa: E402
import local_review as lr  # noqa: E402

# What each review indicator says about an alert (app._apply_local_review in shadow mode).
REVIEW_OUTCOMES = {
    'content.local_review_shadow': 'would_lower',
    'content.local_review_phishing': 'kept_phishing',
    'content.local_review_unsure': 'kept_unsure',
    'content.local_review_unavailable': 'unavailable',
    'content.local_review_skipped': 'skipped',
}


def _cohort(spec: str) -> tuple[str, Path]:
    name, _, path = spec.partition('=')
    if not name or not path or not Path(path).is_absolute():
        raise argparse.ArgumentTypeError('use NAME=/absolute/path/to/cohort.jsonl')
    return name, Path(path)


def pasted(row: dict) -> dict:
    """The row as a reader would paste it: the subject and the visible text of each part."""
    import app

    if '_eml_bytes' in row or row.get('raw_email'):
        structure = app.analyze_raw_email(row.get('_eml_bytes') or row['raw_email'], trusted_authserv_ids=())
        parts = [app._visible_content_text(part['content']) if part['content_type'] == 'text/html'
                 else part['content'] for part in structure['content_parts']]
        subject, body = structure['subject'], '\n'.join(parts)
    else:
        subject, body = row.get('subject', ''), row.get('body', '')
    return {'label': row['label'], 'provider': row['provider'], 'received_at': row['received_at'],
            'subject': subject.strip()[:500], 'body': body.strip()[:50_000]}


def load_cohort(path: Path, *, paste: bool, limit: int | None = None) -> list[dict]:
    rows = []
    for index, row in enumerate(serving._jsonl_records(path), 1):
        if limit is not None and len(rows) >= limit:
            break
        prepared, _digest = serving._prepare_record(serving._validated_record(row, index))
        rows.append(pasted(prepared) if paste else prepared)
    return rows


def count_cohort(rows: list[dict], analyze) -> dict:
    counts = {label: Counter() for label in sorted(serving.LABELS)}
    for row in rows:
        result = analyze(row)
        counter = counts[row['label']]
        counter['messages'] += 1
        alert = result['risk_level'] in serving.ALERT_LEVELS
        counter['alerts'] += alert
        codes = {item.get('code') for item in result['extra_indicators']}
        for code, outcome in REVIEW_OUTCOMES.items():
            counter[outcome] += code in codes
        # In use, a legitimate reading at the threshold lowers the alert to Low.
        counter['alerts_if_applied'] += alert and 'content.local_review_shadow' not in codes
    return {label: dict(counter) for label, counter in counts.items() if counter['messages']}


def _seconds(samples: list[float]) -> dict:
    if not samples:
        return {'reviews': 0}
    return {'reviews': len(samples), 'mean': round(statistics.fmean(samples), 2),
            'median': round(statistics.median(samples), 2), 'max': round(max(samples), 2)}


def _model_digests(url: str) -> dict:
    """Installed model digests from Ollama, so a report names the exact weights."""
    try:
        with build_opener(ProxyHandler({})).open(url + '/api/tags', timeout=5) as response:
            return {item['name']: item.get('digest') for item in json.loads(response.read(1_000_000))['models']}
    except Exception:
        return {}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--input', action='append', type=_cohort, default=[], metavar='NAME=PATH',
                        help='a cohort analyzed as submitted (.eml, raw or pasted rows)')
    parser.add_argument('--paste', action='append', type=_cohort, default=[], metavar='NAME=PATH',
                        help='a cohort analyzed as pasted text: subject and visible text, no headers')
    parser.add_argument('--model', action='append', required=True, help='an Ollama model name; repeat to compare')
    parser.add_argument('--url', default='http://127.0.0.1:11434')
    parser.add_argument('--min-confidence', type=int, default=80)
    parser.add_argument('--limit', type=int, help='at most this many rows per cohort (smoke runs)')
    parser.add_argument('--output', type=Path, help='aggregate JSON report; defaults to stdout')
    args = parser.parse_args(argv)
    url = args.url.rstrip('/')
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname not in lr._LOOPBACK or parts.path:
        parser.error('--url must be http on a loopback address: mail text never leaves this computer')
    if not 50 <= args.min_confidence <= 100:
        parser.error('--min-confidence must be from 50 to 100')
    if any(lr._MODEL_NAME.fullmatch(model) is None for model in args.model):
        parser.error('invalid --model name')
    if not args.input and not args.paste:
        parser.error('give at least one --input or --paste cohort')

    from config import load_settings
    from content_inference import load_content_pipeline_artifact

    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    # The served profile, without the network lookups and stores an offline run must not touch.
    env = {**profile, 'RDAP_LOOKUPS': 'false', 'SENDER_HISTORY_ENABLED': 'false', 'VERIFICATION_MODE': 'off',
           'CASE_MANAGEMENT_ENABLED': 'false', 'PHISHGUARD_JEV_ENABLED': 'false', 'TRUSTED_AUTHSERV_IDS': ''}
    with patch.dict(os.environ, env, clear=True):
        import app
    settings = load_settings(env)
    model_sha256 = profile['CONTENT_MODEL_ARTIFACT_SHA256'].lower()
    pipeline = load_content_pipeline_artifact(PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], model_sha256)
    cohorts = ([(name, load_cohort(path, paste=False, limit=args.limit)) for name, path in args.input]
               + [(name, load_cohort(path, paste=True, limit=args.limit)) for name, path in args.paste])

    models = {}
    with patch.object(app, '_content_pipeline', pipeline), patch.object(app, 'SETTINGS', settings):
        for model in args.model:
            samples = []
            review = app.local_review

            def timed(*review_args, **review_kwargs):
                start = time.perf_counter()
                try:
                    return review(*review_args, **review_kwargs)
                finally:
                    samples.append(time.perf_counter() - start)
            shadow = lr.LocalReviewSettings(url, model, args.min_confidence, shadow=True)
            with patch.object(app, 'LOCAL_REVIEW', shadow), patch.object(app, 'local_review', timed):
                models[model] = {'cohorts': {name: count_cohort(rows, serving.analyze_record) for name, rows in cohorts},
                                 'review_seconds': _seconds(samples)}

    digests = _model_digests(url)
    configuration = {
        'min_confidence': args.min_confidence,
        'prompt_sha256': hashlib.sha256((lr.PROMPT + json.dumps(lr.SCHEMA, sort_keys=True)).encode()).hexdigest(),
        'model_digests': {model: digests.get(model) for model in args.model},
        'pasted_cohorts': [name for name, _path in args.paste],
        'content_model_sha256': model_sha256,
    }
    report = {'schema_version': 1, 'mode': 'shadow', 'models': models, 'configuration': configuration,
              'reproducibility': serving._evaluation_metadata(configuration),
              'limitations': ('Counts only. A model may have seen public corpora in training; private, '
                              'consented mail is the trustworthy part. A pasted cohort approximates what a reader copies.')}
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
