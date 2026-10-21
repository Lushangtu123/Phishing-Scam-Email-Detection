"""Candidate phishing groups from headers only, version 2 (phishing-candidate-groups-v2).

The design the owner approved on 2026-10-21 (docs/superpowers/specs/2026-10-21-phishing-candidate-groups-v2.md).
A separate tool: split_by_family.py (v1), its ledger and the 2026-10-13 plan's split stay as they are. This
tool reuses v1's key rules unchanged and never reads or writes a v1 ledger.

- Input: a folder of .eml files and a trusted manifest of each file's whole-file SHA-256 and size, made when
  the files were downloaded. Copies are decided by the manifest's digests: no file is read past its headers,
  so no digest is recomputed here. Original identity rests on that manifest; contents are not re-verified.
- Reading: 64 KiB blocks up to the first blank line, with at most 262,144 bytes before it. Nothing after the
  blank line is decoded or parsed.
- Groups: v1's sender, Reply-To and subject-template keys, merged transitively across fields, plus thread
  links (a Message-ID named by another message's In-Reply-To or References). A sender domain flagged as
  diffuse (at least K distinct addresses, and distinct addresses per message at least P) and confirmed by
  the confirmer no longer merges on its own, in any field: its messages join only through a full address,
  the same domain with the same subject template, a Reply-To that is not itself diffuse, or a thread link.
  Unconfirmed flags have no effect.
- Output: counts only. Flagged domain values go to a private list for the confirmer.

usage: phishing_candidate_groups_v2.py --root /abs/folder --manifest /abs/manifest.tsv --output /abs/report.json
       [--confirmations /abs/confirmations.json] [--flagged-output /abs/private-flagged.json]
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from email import policy
from email.parser import HeaderParser
from email.utils import getaddresses
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import sys

WEBSITE_DIR = Path(__file__).resolve().parents[1]
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from tools.case_archive import write_private_bytes  # noqa: E402
from tools.split_by_family import LEDGER_SCHEMA as V1_LEDGER_SCHEMA  # noqa: E402
from tools.split_by_family import _address_key, _decoded, read_headers, subject_template  # noqa: E402

SCHEMA = 'phishing-candidate-groups-v2'
CONFIRMATIONS_SCHEMA = 'phishing-candidate-groups-v2-confirmations'
# Fixed for this version (owner's approval, 2026-10-21); changing any of them is a new policy version.
K_DISTINCT_ADDRESSES = 20
P_ADDRESSES_PER_MESSAGE = Fraction(1, 2)
TEMPLATE_HUB_SENDER_KEYS = 20
HEADER_LIMIT = 262_144
BLOCK_SIZE = 65_536
REFERENCES_CAP = 100
GROUP_CAP = 10
IDENTITY_NOTE = ('Original identity rests on the download-time manifest; full contents were not re-verified '
                 'in this run.')

_BLANK_LINE = re.compile(rb'\r?\n\r?\n')
_MESSAGE_ID = re.compile(r'[^\s<>@]+@[^\s<>@]+')
_BRACKETED = re.compile(r'<([^<>]*)>')
EDGE_TYPES = ('sender_address', 'sender_key', 'reply_address', 'reply_key', 'template', 'domain_template', 'thread')
# Every count the report carries, zero included, so its fields never depend on the input.
COUNTS = ('input_files', 'valid_records', 'accepted', 'accepted_without_blank_line', 'duplicate_copies',
          'header_too_large', 'no_sender_address', 'message_id_missing', 'message_id_malformed',
          'reference_ids_malformed', 'references_truncated_messages', 'references_dropped_ids',
          'duplicate_message_ids', 'messages_with_duplicate_message_id', 'conservation_holds')


class GroupingError(RuntimeError):
    """A stopped run. Its message is fixed: no path, domain, address or subject."""


def read_header_block(path) -> tuple[str, bytes | None]:
    """('accepted', headers), ('accepted_without_blank_line', whole file) or ('header_too_large', None).
    Reads 64 KiB blocks and stops at the first blank line, or once no blank line can start within the limit."""
    buffer = b''
    with open(path, 'rb') as stream:
        while True:
            block = stream.read(BLOCK_SIZE)
            start = max(0, len(buffer) - 3)  # a blank line may span two blocks
            buffer += block
            match = _BLANK_LINE.search(buffer, start)
            if match:
                return ('accepted', buffer[:match.start()]) if match.start() <= HEADER_LIMIT else ('header_too_large', None)
            if not block:
                return ('accepted_without_blank_line', buffer) if len(buffer) <= HEADER_LIMIT else ('header_too_large', None)
            if len(buffer) > HEADER_LIMIT + 3:
                return 'header_too_large', None


def _first_address(value) -> str | None:
    """The address _address_key reads, in full and lower case."""
    addresses = [address for _name, address in getaddresses([_decoded(value)]) if '@' in address]
    if not addresses:
        return None
    address = addresses[0].strip().strip('<>').lower()
    return address if address.rpartition('@')[2].rstrip('.') else None


def _single_id(value: str) -> tuple[str | None, bool]:
    """One message ID: outer whitespace and one pair of outer angle brackets removed, nothing else.
    Returns (id, malformed); a missing value is (None, False)."""
    text = value.strip()
    if not text:
        return None, False
    if text.startswith('<') and text.endswith('>'):
        text = text[1:-1]
    return (text, False) if _MESSAGE_ID.fullmatch(text) else (None, True)


def _id_list(value: str, cap: int | None = None) -> tuple[list[str], int, int]:
    """The IDs of In-Reply-To or References: (valid ids, malformed count, ids dropped by the cap). Over the
    cap, the list's first ID and its last cap - 1 are kept (this project's choice, not RFC 5322's)."""
    text = value.strip()
    if not text:
        return [], 0, 0
    tokens = _BRACKETED.findall(text)
    # Text outside the brackets is malformed; a value with no brackets is read as one bare ID.
    malformed = 1 if tokens and _BRACKETED.sub('', text).strip() else 0
    if not tokens:
        tokens = [text]
    dropped = 0
    if cap is not None and len(tokens) > cap:
        dropped = len(tokens) - cap
        tokens = tokens[:1] + tokens[-(cap - 1):]
    valid = []
    for token in tokens:
        identifier, bad = _single_id(token)
        if identifier:
            valid.append(identifier)
        malformed += bad or not token.strip()
    return valid, malformed, dropped


def _load_manifest(manifest: Path) -> tuple[dict[str, tuple[str, int]], str]:
    raw = manifest.read_bytes()
    _refuse_v1_ledger(raw)
    entries = {}
    for line in raw.decode('utf-8').splitlines():
        if not line.strip():
            continue
        fields = line.split('\t')
        if (len(fields) != 3 or not re.fullmatch(r'[0-9a-f]{64}', fields[0]) or not fields[1].isdigit()
                or not fields[2] or Path(fields[2]).is_absolute() or '..' in Path(fields[2]).parts
                or fields[2] in entries):
            raise GroupingError('The manifest is malformed')
        entries[fields[2]] = (fields[0], int(fields[1]))
    if not entries:
        raise GroupingError('The manifest is malformed')
    # The input's version, whatever the order of the lines: confirmations are bound to it.
    canonical = ''.join(f'{digest}\t{size}\t{path}\n' for path, (digest, size) in sorted(entries.items()))
    return entries, hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _refuse_v1_ledger(raw: bytes) -> None:
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return
    if isinstance(value, dict) and (value.get('schema') == V1_LEDGER_SCHEMA or {'families', 'messages'} <= set(value)):
        raise GroupingError('A v1 family-split ledger is not an input of this tool')


def _load_confirmations(path: Path | None, manifest_sha256: str) -> dict:
    if path is None:
        return {'confirmer': None, 'basis_recorded': False, 'sha256': None, 'domains': {}}
    raw = path.read_bytes()
    _refuse_v1_ledger(raw)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise GroupingError('The confirmations are malformed') from None
    domains = value.get('domains') if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get('schema') != CONFIRMATIONS_SCHEMA
            or not isinstance(value.get('confirmer'), str) or not re.fullmatch(r'[a-z0-9-]{1,40}', value['confirmer'])
            or not isinstance(domains, dict) or any(status not in ('confirmed', 'rejected') for status in domains.values())):
        raise GroupingError('The confirmations are malformed')
    if value.get('input_manifest_sha256') != manifest_sha256:
        raise GroupingError('The confirmations belong to another input')
    return {'confirmer': value['confirmer'], 'basis_recorded': bool(str(value.get('basis', '')).strip()),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'domains': {f'organisation:{domain.lower()}': status for domain, status in domains.items()}}


def _records(root: Path, entries: dict) -> tuple[list[dict], Counter]:
    """One record per distinct original, read once, from the path that sorts first among its copies."""
    counts = Counter(input_files=len(entries))
    found = [path for path in root.rglob('*.eml')]
    if any(path.is_symlink() for path in found):
        raise GroupingError('The input folder holds a symbolic link')
    on_disk = {path.relative_to(root).as_posix() for path in found if path.is_file()}
    if on_disk != set(entries):
        raise GroupingError('The input files do not match the manifest')
    for relative, (_digest, size) in entries.items():
        if os.stat(root / relative).st_size != size:
            raise GroupingError('A file size does not match the manifest')
    copies = defaultdict(list)
    for relative, (digest, _size) in entries.items():
        copies[digest].append(relative)
    records = []
    for digest in sorted(copies):
        counts['duplicate_copies'] += len(copies[digest]) - 1
        status, header = read_header_block(root / sorted(copies[digest])[0])
        if status == 'header_too_large':
            counts['header_too_large'] += 1
            continue
        headers = HeaderParser(policy=policy.compat32).parsestr(header.decode('utf-8', 'replace') + '\n')
        sender_address, sender_key = _first_address(headers.get('From')), _address_key(headers.get('From'))
        if not sender_address or not sender_key:
            counts['no_sender_address'] += 1
            continue
        counts[status] += 1
        message_id, malformed = _single_id(str(headers.get('Message-ID') or ''))
        counts['message_id_missing'] += message_id is None and not malformed
        counts['message_id_malformed'] += malformed
        replied, malformed_reply, _dropped = _id_list(str(headers.get('In-Reply-To') or ''))
        references, malformed_references, dropped = _id_list(str(headers.get('References') or ''), REFERENCES_CAP)
        counts['reference_ids_malformed'] += malformed_reply + malformed_references
        counts['references_truncated_messages'] += dropped > 0
        counts['references_dropped_ids'] += dropped
        records.append({
            'digest': digest, 'header': header, 'status': status,
            'sender_address': sender_address, 'sender_key': sender_key,
            'reply_address': _first_address(headers.get('Reply-To')), 'reply_key': _address_key(headers.get('Reply-To')),
            'template': subject_template(_decoded(headers.get('Subject'))),
            'message_id': message_id, 'references': sorted(set(replied + references)),
        })
    counts['valid_records'] = len(records)
    return records, counts


def _flags(records: list[dict]) -> dict[str, dict]:
    """Sender organisation keys with at least K distinct addresses and at least P distinct addresses per
    message, over the deduplicated valid records."""
    addresses, messages = defaultdict(set), Counter()
    for record in records:
        if record['sender_key'].startswith('organisation:'):
            addresses[record['sender_key']].add(record['sender_address'])
            messages[record['sender_key']] += 1
    return {key: {'distinct_addresses': len(addresses[key]), 'messages': messages[key]}
            for key in sorted(addresses)
            if len(addresses[key]) >= K_DISTINCT_ADDRESSES and Fraction(len(addresses[key]), messages[key]) >= P_ADDRESSES_PER_MESSAGE}


def _link_keys(record: dict, diffuse: frozenset) -> list[tuple[str, str]]:
    """The record's (edge type, key) pairs. Keys share one space across From and Reply-To, as in v1, so a
    sender key can meet a Reply-To key; a confirmed diffuse domain contributes no domain key in either field."""
    keys = [('sender_address', 'address:' + record['sender_address'])]
    a_class = record['sender_key'] in diffuse
    if not a_class:
        keys.append(('sender_key', 'key:' + record['sender_key']))
    if record['reply_address']:
        keys.append(('reply_address', 'address:' + record['reply_address']))
    if record['reply_key'] and record['reply_key'] not in diffuse:
        keys.append(('reply_key', 'key:' + record['reply_key']))
    if record['template']:
        keys.append(('domain_template', 'domain-template:' + record['sender_key'] + '\0' + record['template']) if a_class
                    else ('template', 'template:' + record['template']))
    return keys


class _Groups:
    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left, right = self.find(left), self.find(right)
        if left != right:
            self.parent[max(left, right)] = min(left, right)

    def components(self) -> list[list[int]]:
        groups = defaultdict(list)
        for item in range(len(self.parent)):
            groups[self.find(item)].append(item)
        return sorted(groups.values())


def _thread_edges(records: list[dict]) -> tuple[list[tuple[int, int]], Counter]:
    """Pairs (reply, message it names), by Message-IDs held by exactly one original."""
    holders = defaultdict(list)
    for index, record in enumerate(records):
        if record['message_id']:
            holders[record['message_id']].append(index)
    shared = {identifier for identifier, indices in holders.items() if len(indices) > 1}
    counts = Counter(duplicate_message_ids=len(shared),
                     messages_with_duplicate_message_id=sum(len(holders[identifier]) for identifier in shared))
    owner = {identifier: indices[0] for identifier, indices in holders.items() if identifier not in shared}
    edges = sorted({(min(index, owner[identifier]), max(index, owner[identifier]))
                    for index, record in enumerate(records) for identifier in record['references']
                    if identifier in owner and owner[identifier] != index})
    return edges, counts


def _partition(records, keys, edges, without: str | None = None) -> _Groups:
    groups, first = _Groups(len(records)), {}
    for index, record_keys in enumerate(keys):
        for kind, key in record_keys:
            if kind == without:
                continue
            if key in first:
                groups.union(first[key], index)
            else:
                first[key] = index
    if without != 'thread':
        for left, right in edges:
            groups.union(left, right)
    return groups


def _v1_rule_groups(records: list[dict]) -> list[list[int]]:
    """The same records grouped by v1's read_headers keys, for comparison only."""
    groups, first = _Groups(len(records)), {}
    for index, record in enumerate(records):
        keys, _received = read_headers(record['header'], 'phishing')
        for key in keys:
            if key in first:
                groups.union(first[key], index)
            else:
                first[key] = index
    return groups.components()


def _shape(components: list[list[int]]) -> dict:
    sizes = [len(component) for component in components]
    return {'groups': len(sizes), 'largest': max(sizes, default=0), 'singletons': sum(size == 1 for size in sizes),
            'size_2_to_10': sum(2 <= size <= 10 for size in sizes), 'over_10': sum(size > 10 for size in sizes),
            'capacity_with_cap_10': sum(min(size, GROUP_CAP) for size in sizes)}


def group_candidates(root: Path, manifest: Path, confirmations: Path | None = None) -> tuple[dict, dict]:
    """(report, private). The report holds counts only. private holds the groups and the v1-rule groups (as
    manifest paths) and the flagged domain values: for the confirmer and for tests, never written whole."""
    root = Path(root).resolve()
    entries, manifest_sha256 = _load_manifest(Path(manifest))
    confirmed = _load_confirmations(Path(confirmations) if confirmations else None, manifest_sha256)
    records, counts = _records(root, entries)
    flagged = _flags(records)
    status = {key: confirmed['domains'].get(key, 'unconfirmed') for key in flagged}
    diffuse = frozenset(key for key, value in status.items() if value == 'confirmed')
    keys = [_link_keys(record, diffuse) for record in records]
    edges, thread_counts = _thread_edges(records)
    counts.update(thread_counts)
    full = _partition(records, keys, edges).components()

    # Groups whose diffuse-domain messages fall apart on same-domain edges alone were joined by a bridge.
    same_domain = _Groups(len(records))
    first = {}
    for index, record_keys in enumerate(keys):
        for kind, key in record_keys:
            if records[index]['sender_key'] in diffuse and kind in ('sender_address', 'domain_template'):
                if key in first:
                    same_domain.union(first[key], index)
                else:
                    first[key] = index
    bridged = sum(len({same_domain.find(i) for i in component if records[i]['sender_key'] in diffuse}) > 1
                  for component in full)

    holders = defaultdict(set)
    for index, record_keys in enumerate(keys):
        for _kind, key in record_keys:
            holders[key].add(index)
    evidence = {}
    for kind in EDGE_TYPES:
        if kind == 'thread':
            linking, messages = len(edges), len({index for edge in edges for index in edge})
        else:
            values = {key for record_keys in keys for k, key in record_keys if k == kind and len(holders[key]) > 1}
            linking = len(values)
            messages = len({index for index, record_keys in enumerate(keys) for k, key in record_keys if k == kind and key in values})
        reduced = _partition(records, keys, edges, without=kind)
        evidence[kind] = {'linking_keys': linking, 'messages_with_linking_key': messages,
                          'groups_split_if_removed': sum(len({reduced.find(i) for i in component}) > 1 for component in full)}

    template_senders = defaultdict(set)
    for record in records:
        if record['template']:
            template_senders[record['template']].add(record['sender_key'])
    v1_groups = _v1_rule_groups(records)
    counts['conservation_holds'] = int(counts['input_files'] == counts['valid_records'] + counts['duplicate_copies']
                                       + counts['header_too_large'] + counts['no_sender_address'])
    statuses = Counter(status.values())
    report = {
        'schema': SCHEMA,
        'parameters': {'k_distinct_addresses': K_DISTINCT_ADDRESSES, 'p_addresses_per_message': str(P_ADDRESSES_PER_MESSAGE),
                       'template_hub_sender_keys': TEMPLATE_HUB_SENDER_KEYS, 'header_limit_bytes': HEADER_LIMIT,
                       'block_size_bytes': BLOCK_SIZE, 'references_cap': REFERENCES_CAP, 'group_cap': GROUP_CAP},
        'input': {'manifest_sha256': manifest_sha256, 'identity': IDENTITY_NOTE},
        'confirmations': {'confirmer': confirmed['confirmer'], 'basis_recorded': confirmed['basis_recorded'],
                          'sha256': confirmed['sha256'],
                          'listed_but_not_flagged': sum(key not in flagged for key in confirmed['domains'])},
        'counts': {name: counts[name] for name in COUNTS},
        'diffuse_domains': {'flagged': len(flagged), 'confirmed': statuses['confirmed'],
                            'unconfirmed': statuses['unconfirmed'], 'rejected': statuses['rejected']},
        'groups': {**_shape(full), 'bridged': bridged},
        'diffuse_templates': sum(len(senders) >= TEMPLATE_HUB_SENDER_KEYS for senders in template_senders.values()),
        'evidence': evidence,
        'v1_rule_comparison': {'groups': len(v1_groups), 'largest': max(map(len, v1_groups), default=0)},
    }
    first_path = {}
    for path, (digest, _size) in sorted(entries.items()):
        first_path.setdefault(digest, path)
    private = {'groups': sorted(sorted(first_path[records[i]['digest']] for i in component) for component in full),
               'v1_rule_groups': sorted(sorted(first_path[records[i]['digest']] for i in component) for component in v1_groups),
               'flagged': {key.split(':', 1)[1]: {**value, 'status': status[key]} for key, value in flagged.items()}}
    return report, private


class _Arguments(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'Grouping stopped: invalid arguments\n')


def main(argv=None) -> None:
    parser = _Arguments(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument('--root', required=True, type=Path, help='Folder of the .eml files the manifest lists')
    parser.add_argument('--manifest', required=True, type=Path, help='Tab-separated: sha256, size, relative path')
    parser.add_argument('--confirmations', type=Path, help="The confirmer's decisions on flagged domains")
    parser.add_argument('--output', required=True, type=Path, help='The report: counts only')
    parser.add_argument('--flagged-output', type=Path, help='Private list of flagged domains, for the confirmer')
    args = parser.parse_args(argv)
    try:
        paths = [args.root, args.manifest, args.output] + [p for p in (args.confirmations, args.flagged_output) if p]
        if any(not path.is_absolute() for path in paths):
            raise GroupingError('Every path must be absolute')
        root, inputs = args.root.resolve(), [p.resolve() for p in (args.manifest, args.confirmations) if p]
        for output in (p for p in (args.output, args.flagged_output) if p):
            target = output.resolve()
            if target.is_relative_to(root) or target in inputs:
                raise GroupingError('An output would overwrite an input')
        report, private = group_candidates(args.root, args.manifest, args.confirmations)
        if args.flagged_output:
            write_private_bytes(args.flagged_output, (json.dumps(private['flagged'], indent=1, sort_keys=True) + '\n').encode())
        args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    except GroupingError as error:
        sys.stderr.write(f'Grouping stopped: {error}\n')
        raise SystemExit(1) from None
    except Exception:
        sys.stderr.write('Grouping stopped: an unexpected error\n')
        raise SystemExit(1) from None
    print(json.dumps({'valid_records': report['counts']['valid_records'], 'groups': report['groups']['groups']}, sort_keys=True))


if __name__ == '__main__':
    main()
