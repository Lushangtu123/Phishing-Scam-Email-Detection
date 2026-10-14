"""Split imported mail into development and holdout cohorts by family, reading headers only.

For the 2026-10-13 evaluation plan
(docs/superpowers/specs/2026-10-13-model-only-and-intent-rules-evaluation-plan.md: D10, D11's
families, and the holdout's isolation). The input is the messages.jsonl that
import_own_mailbox.py writes. Of each .eml row only the header block is read (everything before
the first blank line); bodies are copied as bytes, never parsed or shown. Text rows, which have
no headers, are skipped.

Families:
- legitimate mail: the sending organisation, that is the From address's organisational domain,
  or the whole address on a consumer mailbox (gmail.com, qq.com);
- phishing: the campaign, as far as headers show it. Messages that share a sender, a Reply-To
  or a subject template ("Invoice #### is overdue") are one family. The plan also names the
  landing host, which is in the body and is not read here: a campaign that changes its sender,
  Reply-To and subject but keeps its landing host is split, and the owner merges it by hand.
Families merge transitively, and with --previous-ledger across runs, so a family can grow but
is never split between the cohorts.

Assignment:
- a family is development if any of its messages is development data: listed with --seen,
  received on or before the cut-off (D10: 2026-10-14) by the provider's own topmost Received
  header, or without such a header;
- any other new family is drawn for holdout with --holdout-share, from a secret kept in the
  ledger, so neither a person nor a message's content chooses it;
- a holdout family contributes its 3 earliest messages; the rest are set aside, in neither cohort;
- earlier assignments are kept. A family never moves from development to holdout; a holdout
  family that joins a development one moves to development as a whole.

Output: two separate private directories outside the repository, each with messages.jsonl
(rows carry family_id and cohort_role) and its .eml copies. The ledger, which holds keyed hashes
and never a domain, address or subject, stays in the holdout directory. stdout gives counts only.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import HeaderParser
from email.utils import getaddresses, parsedate_to_datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
import unicodedata

WEBSITE_DIR = Path(__file__).resolve().parents[1]
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from email_structure import _CONSUMER_MAILBOX_DOMAINS, organizational_domain  # noqa: E402
from tools.case_archive import PROJECT_ROOT, write_private_bytes  # noqa: E402
from tools.evaluate_serving_pipeline import _read_eml, _validated_record  # noqa: E402

LEDGER_SCHEMA = 'family-split-ledger-v1'
CUTOFF = '2026-10-14'  # D10: only mail received after this date is fresh
HOLDOUT_CAP = 3        # D11: a family contributes at most 3 holdout messages
ROLES = ('development', 'holdout')

_BLANK_LINE = re.compile(rb'\r?\n\r?\n')
_REPLY_PREFIX = re.compile(r'^(?:\s*(?:re|fw|fwd|aw|sv|wg|tr|回复|答复|转发)\s*[:：]\s*)+', re.IGNORECASE)
_ADDRESS = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')
_REFERENCE = re.compile(r'\b(?=\w*\d)\w{6,}\b', re.ASCII)  # order numbers, tracking IDs
_DIGITS = re.compile(r'\d+')


def header_block(raw: bytes) -> bytes:
    """The message's headers: everything before the first blank line. The body is not parsed."""
    match = _BLANK_LINE.search(raw)
    return raw[:match.start()] + b'\n' if match else raw


def _decoded(value) -> str:
    try:
        return str(make_header(decode_header(str(value or ''))))
    except (LookupError, UnicodeError, ValueError):
        return str(value or '')


def _address_key(value) -> str | None:
    """The organisation behind an address: its organisational domain, or the address itself on a
    consumer mailbox, where every user is someone else."""
    addresses = [address for _name, address in getaddresses([_decoded(value)]) if '@' in address]
    if not addresses:
        return None
    address = addresses[0].strip().strip('<>').lower()
    domain = address.rpartition('@')[2].rstrip('.')
    if not domain:
        return None
    if domain in _CONSUMER_MAILBOX_DOMAINS:
        return f'address:{address}'
    return f'organisation:{organizational_domain(domain)}'


def subject_template(subject: str) -> str | None:
    """A subject with its numbers, references, addresses and reply prefixes taken out, or None
    when nothing is left to tell campaigns apart."""
    text = _REPLY_PREFIX.sub('', unicodedata.normalize('NFKC', subject or '').lower())
    text = _DIGITS.sub('#', _REFERENCE.sub('*', _ADDRESS.sub('@', text)))
    text = re.sub(r'\s+', ' ', text).strip(' .,:;!?-_*#[]()（）【】')
    han = sum('一' <= character <= '鿿' for character in text)
    return text if han >= 2 or re.search(r'[^\W\d_]{3,}', text) else None


def read_headers(raw: bytes, label: str) -> tuple[list[str], str | None]:
    """A message's family keys and the date its provider received it (UTC), from headers only."""
    # Headers may carry raw UTF-8 (RFC 6532) as well as encoded words (RFC 2047).
    headers = HeaderParser(policy=policy.compat32).parsestr(header_block(raw).decode('utf-8', 'replace'))
    keys = [_address_key(headers.get('From'))]
    if label == 'phishing':
        keys += [_address_key(headers.get('Reply-To')), 'subject:' + (subject_template(_decoded(headers.get('Subject'))) or '')]
    keys = [f'{label}|{key}' for key in dict.fromkeys(keys) if key and key != 'subject:']
    received = headers.get_all('Received') or []
    provider_date = None
    if received:
        try:
            stamp = parsedate_to_datetime(str(received[0]).rpartition(';')[2].strip())
        except (TypeError, ValueError, IndexError):
            stamp = None
        if stamp is not None:
            provider_date = (stamp.astimezone(timezone.utc) if stamp.tzinfo else stamp).date().isoformat()
    return keys, provider_date


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, key: str) -> str:
        self.parent.setdefault(key, key)
        while self.parent[key] != key:
            self.parent[key] = self.parent[self.parent[key]]
            key = self.parent[key]
        return key

    def union(self, keys) -> None:
        keys = list(keys)
        for key in keys[1:]:
            left, right = self.find(keys[0]), self.find(key)
            if left != right:
                self.parent[max(left, right)] = min(left, right)


def _keyed(salt: str, text: str) -> str:
    return hmac.new(bytes.fromhex(salt), text.encode('utf-8'), hashlib.sha256).hexdigest()


def _load_messages(inputs, seen, counts) -> dict[str, dict]:
    """Every unique .eml row, by the SHA-256 of its bytes; a row also listed with --seen is seen."""
    messages: dict[str, dict] = {}
    for is_seen, rows in ((True, seen), (False, inputs)):
        for index, row in enumerate(rows, 1):
            _validated_record(row, index)
            counts['input_rows'] += 1
            if 'eml_path' not in row:
                counts['skipped_text_rows'] += 1
                continue
            raw = _read_eml(row['eml_path'])
            digest = hashlib.sha256(raw).hexdigest()
            if digest in messages:
                if messages[digest]['row']['label'] != row['label']:
                    raise ValueError(f'Row {index}: the same message has two labels')
                counts['skipped_duplicates'] += 1
                continue
            keys, provider_date = read_headers(raw, row['label'])
            messages[digest] = {'row': row, 'raw': raw, 'seen': is_seen, 'provider_date': provider_date,
                                'keys': keys or [f"{row['label']}|message:{digest}"]}
    return messages


def split(inputs, *, seen=(), previous: dict | None = None, holdout_share: float = 0.5,
          cutoff: str = CUTOFF) -> tuple[dict, dict, dict]:
    """Assign each message's family to development or holdout.

    Returns the rows of each cohort (with family_id, cohort_role and the provider's date), the
    new ledger, and counts."""
    if not 0 < holdout_share < 1:
        raise ValueError('The holdout share must be between 0 and 1')
    if previous is not None:
        if previous.get('schema') != LEDGER_SCHEMA or not re.fullmatch(r'[0-9a-f]{64}', str(previous.get('salt'))):
            raise ValueError('The previous ledger is not a family-split ledger')
        if previous.get('holdout_share') != holdout_share or previous.get('cutoff') != cutoff:
            raise ValueError('The holdout share and cut-off must stay as in the previous ledger')
    previous = previous or {'families': {}, 'messages': {}}
    salt = previous.get('salt') or secrets.token_hex(32)
    counts: Counter = Counter()
    messages = _load_messages(inputs, seen, counts)

    families = _UnionFind()
    for family_id, family in previous['families'].items():
        families.union([f'family:{family_id}'] + family['keys'])
    for digest, message in messages.items():
        message['hashed'] = [_keyed(salt, key) for key in message['keys']]
        known = previous['messages'].get(digest)
        families.union(message['hashed'] + ([f"family:{known['family']}"] if known else []))
    for digest, known in previous['messages'].items():
        families.union([f"family:{known['family']}", f'message:{digest}'])

    components: dict[str, dict] = defaultdict(lambda: {'messages': [], 'previous': set(), 'keys': set(),
                                                     'held': [], 'absent': []})
    for family_id, family in previous['families'].items():
        component = components[families.find(f'family:{family_id}')]
        component['previous'].add(family_id)
        component['keys'].update(family['keys'])
    for digest, message in messages.items():
        component = components[families.find(message['hashed'][0])]
        component['messages'].append(digest)
        component['keys'].update(message['hashed'])
    for digest, known in previous['messages'].items():
        component = components[families.find(f'message:{digest}')]
        if known['role'] == 'holdout':
            component['held'].append(digest)
        if digest not in messages:
            component['absent'].append(digest)

    def received(digest):
        return messages[digest]['provider_date'] if digest in messages else previous['messages'][digest]['received_at']

    rows = {role: [] for role in ROLES}
    ledger_families, ledger_messages = {}, {}
    for component in components.values():
        earlier = sorted(component['previous'])
        family_id = earlier[0] if earlier else 'f' + _keyed(salt, 'family:' + min(component['keys']))[:16]
        earlier_roles = {previous['families'][fid]['role'] for fid in earlier}
        reasons = Counter()
        for digest in component['messages']:
            message = messages[digest]
            reasons['seen'] += message['seen']
            reasons['no_provider_date'] += message['provider_date'] is None
            reasons['not_fresh'] += message['provider_date'] is not None and message['provider_date'] <= cutoff
        reasons = +reasons
        if 'development' in earlier_roles or reasons:
            role = 'development'
        elif earlier_roles == {'holdout'}:
            role = 'holdout'
        else:
            role = 'holdout' if int(_keyed(salt, 'role:' + family_id), 16) / 2 ** 256 < holdout_share else 'development'
        if role == 'development' and 'holdout' in earlier_roles:
            counts['families_moved_to_development'] += 1
        counts[f'families_{role}'] += 1
        counts.update({f'development_because_{reason}': number for reason, number in reasons.items()})

        # Holdout members: those already held (the earliest, should two held families have
        # merged), then the earliest new messages, up to the cap.
        held = []
        if role == 'holdout':
            held = sorted(component['held'], key=lambda digest: (received(digest), digest))[:HOLDOUT_CAP]
            fresh = sorted((digest for digest in component['messages'] if digest not in component['held']),
                           key=lambda digest: (received(digest), digest))
            held += fresh[:HOLDOUT_CAP - len(held)]
        ledger_families[family_id] = {'role': role, 'keys': sorted(component['keys'])}
        for digest in component['messages'] + component['absent']:
            member = 'development' if role == 'development' else 'holdout' if digest in held else 'set_aside'
            ledger_messages[digest] = {'family': family_id, 'role': member, 'received_at': received(digest)}
            if digest not in messages:
                counts['ledger_messages_absent'] += 1
                continue
            counts[f'messages_{member}'] += 1
            if member == 'set_aside':
                continue
            message = messages[digest]
            row = {key: value for key, value in message['row'].items() if key != 'eml_path'}
            row.update({'family_id': family_id, 'cohort_role': member,
                        'received_at': message['provider_date'] or row['received_at'],
                        'date_source': 'provider_received_header' if message['provider_date'] else 'date_header'})
            rows[member].append({'row': row, 'raw': message['raw'], 'digest': digest})
    for role in ROLES:
        rows[role].sort(key=lambda item: item['digest'])
    ledger = {'schema': LEDGER_SCHEMA, 'salt': salt, 'cutoff': cutoff, 'holdout_share': holdout_share,
              'families': dict(sorted(ledger_families.items())), 'messages': dict(sorted(ledger_messages.items()))}
    return rows, ledger, dict(sorted(counts.items()))


def holdout_cells(rows: dict) -> dict:
    """Holdout messages per provider, language and label: what D10 asks for, as counts."""
    cells = Counter('/'.join((item['row']['provider'], item['row'].get('language', 'unknown'), item['row']['label']))
                    for item in rows['holdout'])
    return dict(sorted(cells.items()))


def write_split(rows: dict, ledger: dict, development_dir: Path, holdout_dir: Path) -> None:
    """Write each cohort to its own new private directory; the ledger goes with the holdout."""
    development_dir, holdout_dir = development_dir.expanduser().resolve(), holdout_dir.expanduser().resolve()
    for directory in (development_dir, holdout_dir):
        if directory.is_relative_to(PROJECT_ROOT):
            raise ValueError('Save the cohorts outside the Git repository.')
    if development_dir.is_relative_to(holdout_dir) or holdout_dir.is_relative_to(development_dir):
        raise ValueError('The development and holdout directories must be separate.')
    for role, directory in (('development', development_dir), ('holdout', holdout_dir)):
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        (directory / 'eml').mkdir(mode=0o700)
        lines = []
        for item in rows[role]:
            path = write_private_bytes(directory / 'eml' / f"{item['digest']}.eml", item['raw'])
            lines.append(json.dumps({**item['row'], 'eml_path': str(path)}, ensure_ascii=False, sort_keys=True) + '\n')
        write_private_bytes(directory / 'messages.jsonl', ''.join(lines).encode('utf-8'))
    write_private_bytes(holdout_dir / 'ledger.json', (json.dumps(ledger, indent=1, sort_keys=True) + '\n').encode('utf-8'))


def _jsonl(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            raise ValueError(f'{path.name} line {number}: invalid JSON') from None
        if not isinstance(row, dict):
            raise ValueError(f'{path.name} line {number}: expected a JSON object')
        rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', action='append', required=True, type=Path,
                        help='messages.jsonl from import_own_mailbox.py; repeat for each export')
    parser.add_argument('--seen', action='append', default=[], type=Path,
                        help='messages.jsonl of mail already looked at: development only, with its families')
    parser.add_argument('--previous-ledger', type=Path, help="The holdout directory's ledger.json from the last run")
    parser.add_argument('--development-dir', required=True, type=Path, help='New private directory outside the repository')
    parser.add_argument('--holdout-dir', required=True, type=Path, help='New private directory, apart from the development one')
    parser.add_argument('--holdout-share', type=float, default=0.5,
                        help='Share of new families drawn for holdout (default 0.5; fixed by the first ledger)')
    args = parser.parse_args(argv)
    try:
        previous = json.loads(args.previous_ledger.read_text(encoding='utf-8')) if args.previous_ledger else None
        rows, ledger, counts = split([row for path in args.input for row in _jsonl(path)],
                                     seen=[row for path in args.seen for row in _jsonl(path)],
                                     previous=previous, holdout_share=args.holdout_share)
        write_split(rows, ledger, args.development_dir, args.holdout_dir)
    except (ValueError, OSError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps({'counts': counts, 'holdout_cells': holdout_cells(rows)}, indent=2, sort_keys=True))
    print('\nHoldout rows stay unscored until the plan is frozen (D12); do not open them.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
