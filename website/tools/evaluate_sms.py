"""Measure the SMS analysis on labelled text messages, for its launch gate (counts only).

Each --input NAME=PATH is a JSONL cohort, one text per line:
  {"region": "cn" | "us", "sender": "95588", "text": "…", "label": "scam" | "legitimate"}
The sender is optional. app.analyze_sms reads each text with no network: link-domain ages,
which the endpoint adds as context only, are not looked up.

The report holds counts only: verdicts by cohort, label and region, the share at Medium or
above, and how often each rule fires on legitimate texts (where false alerts come from). No
text, sender or per-message row is written. The launch gate is in
docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

LABELS = ('scam', 'legitimate')
REGIONS = ('cn', 'us')
LEVELS = ('unknown', 'safe', 'low', 'medium', 'high', 'critical')
ALERT_LEVELS = frozenset({'medium', 'high', 'critical'})
MAX_SENDER_CHARS, MAX_TEXT_CHARS = 64, 2_000


def _cohort(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition('=')
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError('use NAME=PATH')
    return name, Path(path)


def load_rows(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        sender, text = row.get('sender', ''), row.get('text')
        if (row.get('label') not in LABELS or row.get('region') not in REGIONS or not isinstance(sender, str)
                or len(sender) > MAX_SENDER_CHARS or not isinstance(text, str) or not text.strip()
                or len(text) > MAX_TEXT_CHARS):
            # The line number only: the row may hold private text.
            raise ValueError(f'{path.name}: line {number} needs a label (scam or legitimate), a region (cn or us), '
                             f'a text of 1–{MAX_TEXT_CHARS} characters and a sender of at most {MAX_SENDER_CHARS}')
        rows.append({'label': row['label'], 'region': row['region'], 'sender': sender, 'text': text})
    return rows


def _summary(counter: Counter) -> dict:
    messages = counter['messages']
    alerts = sum(counter[level] for level in ALERT_LEVELS)
    return {'messages': messages, **{level: counter[level] for level in LEVELS if counter[level]},
            'medium_or_above': alerts, 'medium_or_above_share': round(alerts / messages, 4) if messages else None}


def evaluate(cohorts: dict[str, list[dict]], analyze) -> dict:
    by_cohort = {name: {label: Counter() for label in LABELS} for name in cohorts}
    by_region = {region: {label: Counter() for label in LABELS} for region in REGIONS}
    rules_on_legitimate = Counter()
    for name, rows in cohorts.items():
        for row in rows:
            result = analyze(row['sender'], row['text'])
            for counter in (by_cohort[name][row['label']], by_region[row['region']][row['label']]):
                counter['messages'] += 1
                counter[result['risk_level']] += 1
            if row['label'] == 'legitimate':
                fired = {item['code'] for item in result['extra_indicators'] if item.get('level') != 'info'}
                fired |= {f"category.{item['key']}" for item in result['category_results']}
                rules_on_legitimate.update(fired)
    return {
        'cohorts': {name: {label: _summary(counter) for label, counter in labels.items() if counter['messages']}
                    for name, labels in by_cohort.items()},
        'regions': {region: {label: _summary(counter) for label, counter in labels.items() if counter['messages']}
                    for region, labels in by_region.items() if any(c['messages'] for c in labels.values())},
        'rules_on_legitimate': dict(sorted(rules_on_legitimate.items())),
    }


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--input', action='append', type=_cohort, required=True, metavar='NAME=PATH')
    parser.add_argument('--output', type=Path, help='aggregate JSON report; defaults to stdout')
    args = parser.parse_args(argv)
    cohorts = {name: load_rows(path) for name, path in args.input}

    profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
    env = {**profile, 'RDAP_LOOKUPS': 'false', 'SENDER_HISTORY_ENABLED': 'false', 'VERIFICATION_MODE': 'off',
           'CASE_MANAGEMENT_ENABLED': 'false', 'PHISHGUARD_JEV_ENABLED': 'false', 'TRUSTED_AUTHSERV_IDS': ''}
    with patch.dict(os.environ, env, clear=True):
        import app
    from tools import evaluate_serving_pipeline as serving

    configuration = {'rdap_lookups': False, 'alert_levels': sorted(ALERT_LEVELS)}
    report = {'schema_version': 1, **evaluate(cohorts, app.analyze_sms), 'configuration': configuration,
              'reproducibility': serving._evaluation_metadata(configuration),
              'limitations': 'Counts only. Labels are the cohort owner\'s; public datasets are older and mostly English.'}
    text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
