"""Export the texts organisations and unknown senders sent you, from the macOS Messages
database, masked, for the SMS mode's launch gate (website/tools/evaluate_sms.py).

Two steps, both on this computer:

  extract  opens ~/Library/Messages/chat.db read-only and writes review.csv to a private
           folder outside the repository. One row per text from a one-way conversation: one
           other party, and you never sent a message in it (organisations, short codes,
           unknown senders). Group chats and every conversation you replied in are not
           exported. Verification codes, card tails, your own numbers and email local parts
           are masked; a sender that looks personal is replaced by an example number of the
           same kind, so the SMS mode classifies it the same way. Identical masked texts from
           the same kind of sender are kept once. Each row is assigned to batch 1 or 2.
  finish   checks the labels a person filled in review.csv (scam, legitimate or skip) and
           writes batch1.jsonl and batch2.jsonl in evaluate_sms.py's format. Batch 2 is the
           held-out batch: score it once, after calibration on batch 1.

Read every row before labelling it: masking cannot find names or every personal detail. Only
counts are printed. Terminal needs Full Disk Access to open chat.db (System Settings →
Privacy & Security → Full Disk Access).
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import phonenumbers

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

import sms_analysis  # noqa: E402

DEFAULT_DB = Path.home() / 'Library' / 'Messages' / 'chat.db'
COLUMNS = ['id', 'batch', 'region', 'sender_kind', 'sender', 'copies', 'hint', 'text', 'label']
LABELS = ('scam', 'legitimate', 'skip')
MAX_TEXT_CHARS = 2_000
# Sender kinds that name a person's line rather than an organisation's.
PERSONAL_KINDS = frozenset({'cn_mobile', 'nanp_long_code', 'international', 'other_number'})
_APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _outside_repository(path: str) -> Path:
    path = Path(path).expanduser().resolve()
    if path == PROJECT_ROOT or path.is_relative_to(PROJECT_ROOT):
        raise argparse.ArgumentTypeError('the output holds private texts: choose a directory outside the repository')
    return path


def apple_time(value) -> datetime | None:
    """Messages stores nanoseconds since 2001-01-01 (seconds before macOS 10.13)."""
    if not value:
        return None
    seconds = value / 1e9 if value > 1e11 else value
    return datetime.fromtimestamp(_APPLE_EPOCH.timestamp() + seconds, tz=timezone.utc)


def attributed_text(blob: bytes | None) -> str:
    """The plain string in an attributedBody typedstream, where newer macOS keeps the text."""
    if not blob or b'NSString' not in blob:
        return ''
    rest = blob.split(b'NSString', 1)[1][5:]
    if not rest:
        return ''
    if rest[0] == 0x81:
        length, start = int.from_bytes(rest[1:3], 'little'), 3
    elif rest[0] == 0x82:
        length, start = int.from_bytes(rest[1:5], 'little'), 5
    else:
        length, start = rest[0], 1
    return rest[start:start + length].decode('utf-8', errors='replace')


def one_way_texts(db: Path, since: datetime | None = None) -> list[dict]:
    """Received texts from conversations with one other party in which you never wrote."""
    connection = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
    try:
        chat_columns = {row[1] for row in connection.execute('PRAGMA table_info(chat)')}
        filtered = 'c.is_filtered' if 'is_filtered' in chat_columns else '0'
        rows = connection.execute(f"""
            SELECT m.text, m.attributedBody, m.date, h.id, {filtered}
            FROM message m
            JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
            JOIN chat c ON c.ROWID = cmj.chat_id
            JOIN handle h ON h.ROWID = m.handle_id
            WHERE m.is_from_me = 0
              AND (SELECT COUNT(*) FROM chat_handle_join chj WHERE chj.chat_id = c.ROWID) = 1
              AND NOT EXISTS (SELECT 1 FROM chat_message_join j2 JOIN message m2 ON m2.ROWID = j2.message_id
                              WHERE j2.chat_id = c.ROWID AND m2.is_from_me = 1)
            ORDER BY m.date""").fetchall()
    finally:
        connection.close()
    texts = []
    for text, body, date, sender, is_filtered in rows:
        when = apple_time(date)
        if since and when and when < since:
            continue
        text = (text or attributed_text(body)).replace('￼', '').strip()
        if text:
            texts.append({'sender': sender or '', 'text': text, 'filtered': bool(is_filtered)})
    return texts


_SENTENCE_END = re.compile(r'([。！？!?\n;；])')
_CODE_WORD = re.compile(r'验证码|校验码|动态码|动态密码|随机码|口令|\b(?:code|otp|passcode|pin|verification|one[- ]time)\b',
                        re.IGNORECASE)
# Not part of a longer number or a decimal (1500.00), but a code may end a sentence.
_CODE_DIGITS = re.compile(r'(?<!\d)(?<!\d[.,])\d{4,8}(?!\d|[.,]\d)')
_GOOGLE_CODE = re.compile(r'\bG-\d{4,8}\b')
_CARD_TAIL = re.compile(r'(尾号|末四位|末4位|ending in|ending|ends in)(\s*[:：]?\s*)(\d{3,4})', re.IGNORECASE)
_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)')


def mask_text(text: str, own_numbers=()) -> str:
    """Codes and card tails become zeros of the same length; your numbers and email local
    parts are replaced. Links, amounts and other numbers are kept: the rules read them."""
    text = _GOOGLE_CODE.sub(lambda m: 'G-' + '0' * (len(m.group(0)) - 2), text)
    # A code is masked in the sentence that names it; split keeps the separators.
    text = ''.join(_CODE_DIGITS.sub(lambda m: '0' * len(m.group(0)), part) if _CODE_WORD.search(part) else part
                   for part in _SENTENCE_END.split(text))
    text = _CARD_TAIL.sub(lambda m: m.group(1) + m.group(2) + '0' * len(m.group(3)), text)
    for number in own_numbers:
        digits = re.sub(r'\D', '', number)
        # Longest first: the national form is the tail of the international one.
        for candidate in sorted({digits, digits[-11:], digits[-10:]}, key=len, reverse=True):
            if len(candidate) >= 7:
                text = re.sub(r'\+?' + r'[\s\-().]*'.join(candidate), '[your number]', text)
    return _EMAIL.sub(r'user@\1', text)


def mask_sender(sender: str) -> tuple[str, str]:
    """(kind, sender): organisations' senders as they are, a person's line as an example
    number of the same kind and country."""
    kind = sms_analysis.classify_sender(sender)
    if kind == 'email':
        return kind, 'sender@' + sender.rsplit('@', 1)[1]
    if kind not in PERSONAL_KINDS:
        return kind, sender
    if kind == 'cn_mobile':
        return kind, '13800000000'
    if kind == 'nanp_long_code':
        return kind, '+1 202 555 0100'
    if kind == 'international':
        try:
            parsed = phonenumbers.parse(sender if sender.lstrip().startswith('+') else '+' + sender.lstrip('0'))
            region = phonenumbers.region_code_for_number(parsed)
            example = (phonenumbers.example_number_for_type(region, phonenumbers.number_type(parsed))
                       or phonenumbers.example_number(region))
            masked = phonenumbers.format_number(example, phonenumbers.PhoneNumberFormat.E164) if example else ''
        except phonenumbers.NumberParseException:
            masked = ''
        return kind, masked if sms_analysis.classify_sender(masked) == 'international' else '+44 7911 123456'
    return kind, '12'


def _han_count(text: str) -> int:
    return sum(1 for character in text if '一' <= character <= '鿿')


def guess_region(kind: str, text: str) -> str:
    return 'cn' if kind in ('cn_mobile', 'cn_port_106') or _han_count(text) >= 2 else 'us'


def build_rows(texts: list[dict], own_numbers=(), seed: int = 166) -> list[dict]:
    rows, seen = [], {}
    for item in texts:
        kind, sender = mask_sender(item['sender'])
        text = mask_text(item['text'], own_numbers)[:MAX_TEXT_CHARS]
        key = (kind, text)
        if key in seen:
            seen[key]['copies'] += 1
            continue
        row = {'region': guess_region(kind, text), 'sender_kind': kind, 'sender': sender, 'copies': 1,
               'hint': 'filtered as unknown sender' if item['filtered'] else '', 'text': text, 'label': ''}
        seen[key] = row
        rows.append(row)
    # Batch 2 is held out: half of each region, chosen with a fixed seed.
    for region in ('cn', 'us'):
        members = [row for row in rows if row['region'] == region]
        random.Random(seed).shuffle(members)
        for index, row in enumerate(members):
            row['batch'] = 1 if index % 2 == 0 else 2
    for number, row in enumerate(rows, 1):
        row['id'] = number
    return rows


def _labelled(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding='utf-8-sig', newline='') as handle:
        return sum(1 for row in csv.DictReader(handle) if (row.get('label') or '').strip())


def extract(args) -> dict:
    out = args.output_dir
    review = out / 'review.csv'
    if _labelled(review):
        raise SystemExit(f'{review} already holds labels; move it away before extracting again')
    try:
        texts = one_way_texts(args.db, args.since)
    except sqlite3.OperationalError as error:
        raise SystemExit(f'cannot open {args.db} ({error}); give Terminal Full Disk Access and try again')
    rows = build_rows(texts, args.own_number, args.seed)
    out.mkdir(parents=True, exist_ok=True)
    with review.open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    summary = {'received_texts': len(texts), 'rows': len(rows),
               'rows_by_region_and_batch': dict(Counter(f"{row['region']}/batch{row['batch']}" for row in rows)),
               'sender_kinds': dict(Counter(row['sender_kind'] for row in rows))}
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def finish(args) -> dict:
    out = args.output_dir
    with (out / 'review.csv').open(encoding='utf-8-sig', newline='') as handle:
        rows = list(csv.DictReader(handle))
    problems = Counter()
    batches = {1: [], 2: []}
    for row in rows:
        label = (row.get('label') or '').strip().lower()
        if label not in LABELS:
            problems['unlabelled' if not label else 'unknown label'] += 1
            continue
        if label == 'skip':
            continue
        if row['region'] not in ('cn', 'us') or row['batch'] not in ('1', '2') or not row['text'].strip():
            problems['bad region, batch or text'] += 1
            continue
        batches[int(row['batch'])].append({'region': row['region'], 'sender': row['sender'], 'text': row['text'],
                                           'label': label})
    if problems:
        # Row ids only, never text.
        raise SystemExit(f'review.csv needs attention: {dict(problems)}; label every row scam, legitimate or skip')
    summary = {}
    for batch, items in batches.items():
        (out / f'batch{batch}.jsonl').write_text(''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in items),
                                                 encoding='utf-8')
        counts = Counter(f"{item['region']}/{item['label']}" for item in items)
        summary[f'batch{batch}'] = dict(sorted(counts.items()))
    # The launch gate's 4% needs about 50 legitimate texts per region per batch.
    summary['short_of_50_legitimate'] = sorted(f'batch{batch}/{region}' for batch in batches for region in ('cn', 'us')
                                               if summary[f'batch{batch}'].get(f'{region}/legitimate', 0) < 50)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest='command', required=True)
    first = commands.add_parser('extract', help='write review.csv from the Messages database')
    first.add_argument('--output-dir', type=_outside_repository, required=True)
    first.add_argument('--db', type=Path, default=DEFAULT_DB)
    first.add_argument('--since', type=lambda value: datetime.fromisoformat(value).replace(tzinfo=timezone.utc),
                       help='only texts received on or after this date (YYYY-MM-DD)')
    first.add_argument('--own-number', action='append', default=[], help='your number, masked wherever a text shows it')
    first.add_argument('--seed', type=int, default=166)
    second = commands.add_parser('finish', help='write batch1.jsonl and batch2.jsonl from the labelled review.csv')
    second.add_argument('--output-dir', type=_outside_repository, required=True)
    args = parser.parse_args(argv)
    extract(args) if args.command == 'extract' else finish(args)


if __name__ == '__main__':
    main()
