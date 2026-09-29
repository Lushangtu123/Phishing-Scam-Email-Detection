"""Convert a consented local mailbox export into evaluate_serving_pipeline.py JSONL.

Reads .mbox files (Google Takeout, Thunderbird), Apple Mail .mbox folders and .eml
files. Each message is written once as .eml and referenced by an eml_path row;
messages over the serving size limit become subject/body text rows unless
--oversized skip. Never follows links or uses the network. Output must live
outside the repository or under its git-ignored .evaluation-data/ directory.
stdout lists counts and sender domains only, never subjects or bodies.
"""
from __future__ import annotations

import argparse
import codecs
from collections import Counter
from datetime import timezone
import email
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
import hashlib
from html import unescape
import json
import mailbox
from pathlib import Path
import re
import sys

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from tools.evaluate_serving_pipeline import LABELS, MAX_EML_BYTES, PROVIDERS, _validated_record  # noqa: E402

_TAGS = re.compile(r'<[^>]+>')
_SCRIPT_STYLE = re.compile(r'<(script|style)\b.*?</\1>', re.I | re.S)
_SPACE = re.compile(r'\s+')


def _codec(charset: str | None) -> str:
    try:
        return codecs.lookup(charset).name if charset else 'utf-8'
    except LookupError:
        return 'utf-8'


def message_parts(message) -> tuple[str, str]:
    """Decoded subject and whitespace-collapsed text body; tags are stripped from every text part."""
    plain, html = [], []
    for part in (message.walk() if message.is_multipart() else [message]):
        if part.get_content_maintype() != 'text' or part.get_filename():
            continue
        payload = part.get_payload(decode=True) or b''
        text = payload.decode(_codec(part.get_content_charset()), errors='replace')
        subtype = part.get_content_subtype()
        (plain if subtype == 'plain' else html if subtype == 'html' else []).append(text)
    raw = ' '.join(plain) if plain else ' '.join(html)
    body = unescape(_TAGS.sub(' ', _SCRIPT_STYLE.sub(' ', raw)))
    try:
        subject = str(make_header(decode_header(message.get('Subject', '') or '')))
    except (LookupError, UnicodeError, ValueError):
        subject = str(message.get('Subject', '') or '')
    return _SPACE.sub(' ', subject).strip(), _SPACE.sub(' ', body).strip()


def iter_raw_messages(inputs: list[Path]):
    """Yield raw message bytes from .eml files, mbox files and folders (Apple Mail keeps a file named mbox inside)."""
    for path in inputs:
        if path.is_dir():
            if (path / 'mbox').is_file():
                yield from iter_raw_messages([path / 'mbox'])
            else:
                yield from iter_raw_messages(sorted(p for p in path.rglob('*')
                                                    if p.is_file() and p.suffix.lower() in ('.eml', '.mbox')
                                                    or p.is_dir() and p.suffix.lower() == '.mbox'))
        elif path.suffix.lower() == '.eml':
            yield path.read_bytes()
        elif path.is_file():
            box = mailbox.mbox(str(path), create=False)
            for key in box.iterkeys():
                yield box.get_bytes(key)


def received_date(message) -> str | None:
    try:
        parsed = parsedate_to_datetime(str(message.get('Date', '')))
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.date().isoformat()


def sender_domain(message) -> str:
    addresses = getaddresses([str(message.get('From', ''))])
    address = addresses[0][1] if addresses else ''
    return address.rsplit('@', 1)[1].lower().strip('>') if '@' in address else 'unknown'


def _inside_repository_outside_ignored(output: Path) -> bool:
    output = output.resolve()
    ignored = (PROJECT_ROOT / '.evaluation-data').resolve()
    return output.is_relative_to(PROJECT_ROOT) and not output.is_relative_to(ignored)


def convert(inputs: list[Path], output: Path, *, provider: str, label: str = 'legitimate',
            language: str | None = None, oversized: str = 'text', since: str | None = None) -> dict:
    """Write output/eml/*.eml, output/messages.jsonl and a private output/manifest.jsonl; return counts."""
    eml_dir = output / 'eml'
    eml_dir.mkdir(parents=True, exist_ok=True)
    counts: Counter = Counter()
    domains: Counter = Counter()
    dates: list[str] = []
    seen: set[str] = set()
    with (output / 'messages.jsonl').open('w', encoding='utf-8') as rows, \
            (output / 'manifest.jsonl').open('w', encoding='utf-8') as manifest:
        for raw in iter_raw_messages(inputs):
            counts['read'] += 1
            digest = hashlib.sha256(raw).hexdigest()
            if digest in seen:
                counts['duplicate'] += 1
                continue
            seen.add(digest)
            message = email.message_from_bytes(raw)
            day = received_date(message)
            if day is None:
                counts['no_date'] += 1
                continue
            if since and day < since:
                counts['before_since'] += 1
                continue
            row = {'provider': provider, 'label': label, 'received_at': day}
            if language:
                row['language'] = language
            subject, body = message_parts(message)
            if len(raw) <= MAX_EML_BYTES and raw.strip():
                path = (eml_dir / f'{digest[:24]}.eml').resolve()
                path.write_bytes(raw)
                row['eml_path'] = str(path)
                mode = 'eml'
            elif oversized == 'text' and (subject or body):
                row['subject'], row['body'] = subject, body
                mode = 'text'
            else:
                counts['oversized_skipped' if raw.strip() else 'empty'] += 1
                continue
            _validated_record(row, counts['written'] + 1)
            rows.write(json.dumps(row, ensure_ascii=False) + '\n')
            domain = sender_domain(message)
            manifest.write(json.dumps({'sha256': digest, 'sender_domain': domain, 'received_at': day,
                                       'bytes': len(raw), 'mode': mode, 'subject': subject},
                                      ensure_ascii=False) + '\n')
            counts['written'] += 1
            counts[f'mode_{mode}'] += 1
            domains[domain] += 1
            dates.append(day)
    return {'counts': dict(counts), 'sender_domains': domains.most_common(),
            'date_range': [min(dates), max(dates)] if dates else None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', type=Path, help='.mbox files or folders, .eml files, or folders of them')
    parser.add_argument('--output', required=True, type=Path,
                        help='Private output directory, e.g. .evaluation-data/own-mail')
    parser.add_argument('--provider', required=True, choices=sorted(PROVIDERS), help='Mailbox provider of the export')
    parser.add_argument('--label', default='legitimate', choices=sorted(LABELS))
    parser.add_argument('--language', help='Optional two- or three-letter language code for every message')
    parser.add_argument('--oversized', choices=('text', 'skip'), default='text',
                        help=f'Messages over {MAX_EML_BYTES:,} bytes: keep subject/body text (default) or skip')
    parser.add_argument('--since', help='Only keep messages received on or after YYYY-MM-DD')
    args = parser.parse_args(argv)
    missing = [str(path) for path in args.inputs if not path.exists()]
    if missing:
        parser.error(f'Input not found: {", ".join(missing)}')
    if _inside_repository_outside_ignored(args.output):
        parser.error('Output inside the repository must be under .evaluation-data/ so it is never committed')
    summary = convert(args.inputs, args.output, provider=args.provider, label=args.label,
                      language=args.language, oversized=args.oversized, since=args.since)
    print(json.dumps(summary, indent=2))
    jsonl = (args.output / 'messages.jsonl').resolve()
    print(f'\nNext: python website/tools/evaluate_serving_pipeline.py --input "{jsonl}"')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
