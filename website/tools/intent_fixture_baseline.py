"""Count how the serving pipeline treats the synthetic intent-rule fixtures.

Development and regression data for the two intent rules of the 2026-10-13 evaluation plan
(docs/superpowers/specs/2026-10-13-model-only-and-intent-rules-evaluation-plan.md). Each
fixture is analysed as pasted subject and body through the full content analysis with the
committed model. The rules read content, and that is what this measures: as original messages
the fixtures' reserved sender domains (.example, .test) set a sender floor of their own,
which says nothing about the rules. Original-message behaviour is measured on real downloads.
The report holds counts only, grouped by set, language, behaviour and kind. These fixtures
are never holdout data.
"""
import argparse
import asyncio
from collections import defaultdict
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
FIXTURES = WEBSITE_DIR / 'tests' / 'fixtures' / 'intent_rules'
ALERT_LEVELS = {'medium', 'high', 'critical'}


def load_fixtures(directory: Path = FIXTURES) -> list[dict]:
    rows = []
    for name in ('development.jsonl', 'regression.jsonl'):
        rows += [json.loads(line) for line in (directory / name).read_text(encoding='utf-8').splitlines() if line]
    return rows


def analyze(app, row: dict) -> dict:
    request = app.ContentRequest(subject=row['subject'], body=row['body'])
    return json.loads(asyncio.run(app._analyze_content(request, observe_sender_history=False)).body)


def baseline(rows: list[dict], analyze_row) -> dict:
    """Per set, language, behaviour and kind: rows, alerts (Medium or above), Unknown, rows
    with a sensitive-request finding, and alerts that rest on the text model alone."""
    groups = defaultdict(lambda: {'rows': 0, 'alerts': 0, 'unknown': 0, 'sensitive_request': 0, 'model_only': 0})
    for row in rows:
        result = analyze_row(row)
        group = groups['/'.join((row['set'], row['language'], row['behaviour'], row['kind']))]
        group['rows'] += 1
        group['alerts'] += result.get('risk_level') in ALERT_LEVELS
        group['unknown'] += result.get('risk_level') == 'unknown'
        group['sensitive_request'] += any(str(item.get('code', '')).startswith('content.sensitive_request.')
                                          for item in result.get('extra_indicators', []))
        group['model_only'] += result.get('risk_level') in ALERT_LEVELS and result.get('fusion_basis') == 'model_only'
    return dict(sorted(groups.items()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rules-only', action='store_true', help='Leave the text model out')
    args = parser.parse_args()
    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    environment = {**profile, 'SENDER_HISTORY_ENABLED': 'false', 'VERIFICATION_MODE': 'off',
                   'CASE_MANAGEMENT_ENABLED': 'false', 'PHISHGUARD_JEV_ENABLED': 'false', 'TRUSTED_AUTHSERV_IDS': ''}
    sys.path.insert(0, str(WEBSITE_DIR))
    with patch.dict(os.environ, environment, clear=True):
        import app
    pipeline = None if args.rules_only else app.load_content_pipeline_artifact(
        PROJECT_ROOT / profile['CONTENT_MODEL_ARTIFACT'], profile['CONTENT_MODEL_ARTIFACT_SHA256'])
    with patch.object(app, '_content_pipeline', pipeline):
        report = baseline(load_fixtures(), lambda row: analyze(app, row))
    print(json.dumps({'model': None if args.rules_only else profile['CONTENT_MODEL_ARTIFACT_SHA256'],
                      'groups': report}, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
