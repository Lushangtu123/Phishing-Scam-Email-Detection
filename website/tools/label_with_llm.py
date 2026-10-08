"""Label a consented mailbox with a local language model, for a person to check before training.

`label` reads an mbox file (a Google Takeout export) or a directory of .eml files, asks the
model about each message (the subject, visible text and link hosts the text model reads), and
writes into an output directory outside the repository:

- review.csv: each message a person must label (every phishing reading, readings below
  --floor, no answer, and messages the provider filed as spam or a --review manifest lists),
  with an empty human_label column to fill in with phishing or legitimate;
- labelled.csv: the training rows, in the column layout content_model.py reads for CEAS_08 and
  Nazario (sender, receiver, date, subject, body, urls, label; 0 legitimate, 1 phishing): the
  legitimate readings at or above --floor and, after `merge`, every row a person labelled;
- messages.jsonl: the extracted text of each message, from which `merge` rebuilds labelled.csv;
- summary.json: counts only.

Phishing labels therefore always come from a person: the model read 10 of the owner's 92
genuine messages as phishing, all with 90% confidence or more (docs/llm-teacher.md). `merge` can run again as more rows are reviewed,
and `label` refuses a directory whose review.csv already holds a person's labels. --exclude
names manifests (JSONL with message_id) of evaluation messages, which are never labelled, and
--review manifests of messages a person must see whatever the model reads, such as those an
export without Takeout's X-Gmail-Labels header shows were in Spam.
The outputs hold private mail: keep them, and any model trained on them, out of Git.
"""
from __future__ import annotations

import argparse
import csv
import email
import json
import mailbox
import os
import sys
from collections import Counter
from datetime import date
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

import local_review as lr  # noqa: E402

COLUMNS = ['sender', 'receiver', 'date', 'subject', 'body', 'urls', 'label']
REVIEW_COLUMNS = ['id', 'date', 'sender_domain', 'subject', 'model_verdict', 'model_confidence', 'flagged',
                  'human_label']
MAX_MESSAGE_BYTES = 3 * 1024 * 1024


def messages(source: Path):
    """(id, raw bytes) for each message of an mbox file or a directory of .eml files."""
    if source.is_dir():
        for path in sorted(source.rglob('*.eml')):
            yield path.relative_to(source).as_posix(), path.read_bytes()
    else:
        box = mailbox.mbox(str(source), create=False)
        try:
            for index, message in enumerate(box):
                yield f'mbox-{index}', message.as_bytes()
        finally:
            box.close()


def extract(raw: bytes) -> dict:
    """The fields of the training layout, and the text the model reads."""
    import app

    structure = app.analyze_raw_email(raw, trusted_authserv_ids=())
    view = {}
    result = app.analyze_email_content(structure['subject'], structure['body'],
                                       content_parts=structure['content_parts'], _model_view=view,
                                       sender=structure['from'])
    receivers = structure['header_candidates'].get('To') or ['']
    return {'sender': parseaddr(structure['from'])[1], 'receiver': parseaddr(receivers[0])[1],
            'date': str(email.message_from_bytes(raw).get('Date') or '')[:100],
            'subject': view.get('subject', ''), 'body': view.get('body', ''),
            'urls': ' '.join(result.get('link_hosts', []))}


def _date(header) -> date | None:
    try:
        return parsedate_to_datetime(header['Date']).date()
    except Exception:
        return None


def _filed_as_spam(header) -> bool:
    """Whether a Google Takeout message carries Gmail's Spam label."""
    return 'spam' in {item.strip().lower() for item in str(header.get('X-Gmail-Labels') or '').split(',')}


def manifest_ids(paths) -> set[str]:
    """The Message-IDs JSONL manifests list (message_id)."""
    found = set()
    for path in paths:
        for line in Path(path).read_bytes().splitlines():
            if line.strip():
                message_id = (json.loads(line).get('message_id') or '').strip()
                if message_id:
                    found.add(message_id)
    return found


def _reviewed(path: Path) -> int:
    """How many rows of a review queue a person has labelled."""
    if not path.exists():
        return 0
    with path.open(newline='', encoding='utf-8') as source:
        return sum(bool((row.get('human_label') or '').strip()) for row in csv.DictReader(source))


def _outside_repository(path: str) -> Path:
    path = Path(path).resolve()
    if path == PROJECT_ROOT or path.is_relative_to(PROJECT_ROOT):
        raise argparse.ArgumentTypeError('the output holds private mail: choose a directory outside the repository')
    return path


def label(args) -> dict:
    settings = lr.LocalReviewSettings(args.url, args.model)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    since = args.since
    excluded, listed = manifest_ids(args.exclude), manifest_ids(args.review)
    with (out / 'review.csv').open('w', newline='', encoding='utf-8') as review_file, \
            (out / 'messages.jsonl').open('w', encoding='utf-8') as messages_file:
        review = csv.DictWriter(review_file, REVIEW_COLUMNS)
        review.writeheader()
        for message_id, raw in messages(args.source):
            if args.limit is not None and counts['messages'] >= args.limit:
                break
            if not raw.strip() or len(raw) > MAX_MESSAGE_BYTES:
                counts['skipped_size'] += 1
                continue
            header = email.message_from_bytes(raw)
            message_key = (header.get('Message-ID') or '').strip()
            if message_key in excluded:
                counts['skipped_evaluation'] += 1
                continue
            sent = _date(header) if since is not None else None
            if since is not None and (sent is None or sent < since):
                counts['skipped_date'] += 1
                continue
            counts['messages'] += 1
            fields = extract(raw)
            if not (fields['subject'] + fields['body']).strip():
                counts['skipped_empty'] += 1
                continue
            reading = lr.review(settings, fields['subject'], fields['body'], fields['urls'].split())
            flagged = 'spam folder' if _filed_as_spam(header) else 'listed for review' if message_key in listed else ''
            accepted = bool(not flagged and reading and reading['verdict'] == 'legitimate'
                            and reading['confidence'] >= args.floor)
            messages_file.write(json.dumps({'id': message_id, 'accepted': accepted, **fields}, ensure_ascii=False) + '\n')
            if accepted:
                counts['labelled_legitimate'] += 1
                continue
            counts['to_review_' + ('flagged' if flagged else 'unavailable' if reading is None else reading['verdict'])] += 1
            review.writerow({'id': message_id, 'date': fields['date'], 'sender_domain': fields['sender'].rpartition('@')[2],
                             'subject': fields['subject'][:200], 'flagged': flagged, 'human_label': '',
                             'model_verdict': reading['verdict'] if reading else 'none',
                             'model_confidence': reading['confidence'] if reading else ''})
    write_labelled(out)
    summary = {'counts': dict(counts), 'model': args.model, 'floor': args.floor,
               'note': 'Private mail: keep this directory and any model trained on it out of Git.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary


def write_labelled(out: Path) -> Counter:
    """Rebuild labelled.csv: the accepted legitimate readings and each row a person labelled."""
    with (out / 'review.csv').open(newline='', encoding='utf-8') as review_file:
        reviewed = {row['id']: row for row in csv.DictReader(review_file)}
    counts = Counter()
    with (out / 'labelled.csv').open('w', newline='', encoding='utf-8') as labelled_file:
        labelled = csv.DictWriter(labelled_file, COLUMNS)
        labelled.writeheader()
        for line in (out / 'messages.jsonl').read_bytes().splitlines():
            item = json.loads(line)
            fields = {key: item[key] for key in COLUMNS[:-1]}
            if item['accepted']:
                labelled.writerow({**fields, 'label': 0})
                counts['labelled_legitimate'] += 1
                continue
            row = reviewed.get(item['id'], {})
            human = (row.get('human_label') or '').strip().lower()
            if human not in {'phishing', 'legitimate'}:
                counts['unrecognised_human_label' if human else 'not_reviewed'] += 1
                continue
            labelled.writerow({**fields, 'label': 1 if human == 'phishing' else 0})
            counts[f'merged_{human}'] += 1
            counts['model_agreed' if human == row['model_verdict'] else 'model_disagreed'] += 1
    return counts


def merge(args) -> dict:
    return {'counts': dict(write_labelled(args.output_dir))}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest='command', required=True)
    first = commands.add_parser('label', help='ask the model about each message')
    first.add_argument('source', type=Path, help='an mbox file or a directory of .eml files')
    first.add_argument('--output-dir', type=_outside_repository, required=True)
    first.add_argument('--model', required=True)
    first.add_argument('--url', default='http://127.0.0.1:11434')
    first.add_argument('--floor', type=int, default=90, help='least confidence for a legitimate label without a person')
    first.add_argument('--since', type=date.fromisoformat, help='only messages dated on or after YYYY-MM-DD')
    first.add_argument('--limit', type=int)
    first.add_argument('--exclude', action='append', default=[], type=Path,
                       help='a JSONL manifest of evaluation messages (message_id) never to label; repeatable')
    first.add_argument('--review', action='append', default=[], type=Path,
                       help='a JSONL manifest of messages (message_id) a person must label; repeatable')
    second = commands.add_parser('merge', help='add the rows a person labelled in review.csv to labelled.csv')
    second.add_argument('--output-dir', type=_outside_repository, required=True)
    args = parser.parse_args(argv)
    if args.command == 'label':
        if _reviewed(args.output_dir / 'review.csv'):
            parser.error("review.csv in --output-dir holds a person's labels: run merge, or choose another directory")
        parts = urlsplit(args.url.rstrip('/'))
        if parts.scheme != 'http' or parts.hostname not in lr._LOOPBACK or parts.path:
            parser.error('--url must be http on a loopback address: mail text never leaves this computer')
        if lr._MODEL_NAME.fullmatch(args.model) is None or not 50 <= args.floor <= 100:
            parser.error('invalid --model or --floor')
        args.url = args.url.rstrip('/')
        profile = json.loads((PROJECT_ROOT / 'vercel.json').read_text(encoding='utf-8'))['env']
        env = {**profile, 'RDAP_LOOKUPS': 'false', 'SENDER_HISTORY_ENABLED': 'false', 'VERIFICATION_MODE': 'off',
               'CASE_MANAGEMENT_ENABLED': 'false', 'PHISHGUARD_JEV_ENABLED': 'false', 'TRUSTED_AUTHSERV_IDS': ''}
        with patch.dict(os.environ, env, clear=True):
            import app  # noqa: F401 -- the parsers extract() uses, with the served profile
        result = label(args)
    else:
        result = merge(args)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
