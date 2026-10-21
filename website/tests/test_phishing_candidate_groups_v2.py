"""phishing-candidate-groups-v2: the synthetic acceptance criteria S2-S13 of the approved design
(docs/superpowers/specs/2026-10-21-phishing-candidate-groups-v2.md). Every message is synthetic and written to
a temporary folder; S1 (v1 unchanged) and S14 (planted defects) are checked outside this file."""
import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from network_guard import blocked_network  # noqa: E402
from tools import phishing_candidate_groups_v2 as v2  # noqa: E402

DIFFUSE = 'synthetic-diffuse.com'
WORDS = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliet', 'kilo', 'lima',
         'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey',
         'xray', 'yankee', 'zulu']


def word(n: int) -> str:
    """A distinct letters-only word for subject templates (digits would be masked into one template)."""
    return WORDS[n % len(WORDS)] + ('' if n < len(WORDS) else WORDS[n // len(WORDS)])


def message(sender, subject, *, reply_to=None, message_id=None, in_reply_to=None, references=None,
            body='Synthetic body.', newline='\r\n', extra=()) -> bytes:
    headers = [f'From: {sender}', 'To: reader@synthetic-inbox.com', f'Subject: {subject}', *extra]
    for name, value in (('Reply-To', reply_to), ('Message-ID', message_id), ('In-Reply-To', in_reply_to),
                        ('References', references)):
        if value is not None:
            headers.append(f'{name}: {value}')
    return (newline.join(headers) + newline + newline + body + newline).encode()


class Batch:
    """Synthetic .eml files in a temporary folder, with their manifest and confirmations."""

    def __init__(self, test):
        self.test = test
        self.base = Path(tempfile.mkdtemp())
        test.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.root = self.base / 'mail'
        self.root.mkdir()
        self.paths = []

    def add(self, sender, subject='Synthetic notice', raw=None, **kwargs) -> str:
        relative = f'm{len(self.paths):04d}.eml'
        (self.root / relative).write_bytes(raw if raw is not None else message(sender, subject, **kwargs))
        self.paths.append(relative)
        return relative

    def fill(self, domain, count, start=0, prefix='filler'):
        """count senders on domain, each with its own address and subject template."""
        return [self.add(f'Sender <{prefix}{n}@{domain}>', f'Notice {prefix} {word(start + n)}') for n in range(count)]

    def manifest(self, order=None) -> Path:
        lines = []
        for relative in order or self.paths:
            data = (self.root / relative).read_bytes()
            lines.append(f'{hashlib.sha256(data).hexdigest()}\t{len(data)}\t{relative}\n')
        path = self.base / 'manifest.tsv'
        path.write_text(''.join(lines))
        return path

    def confirmations(self, manifest, confirmed=(), rejected=()) -> Path:
        path = self.base / 'confirmations.json'
        path.write_text(json.dumps({
            'schema': v2.CONFIRMATIONS_SCHEMA, 'confirmer': 'owner-01', 'basis': 'synthetic test decision',
            'input_manifest_sha256': v2._load_manifest(manifest)[1],
            'domains': {**{d: 'confirmed' for d in confirmed}, **{d: 'rejected' for d in rejected}}}))
        return path

    def run(self, confirmed=(), rejected=(), order=None):
        manifest = self.manifest(order)
        confirmations = self.confirmations(manifest, confirmed, rejected) if confirmed or rejected else None
        return v2.group_candidates(self.root, manifest, confirmations)


def group_of(private, relative) -> set:
    return next(set(group) for group in private['groups'] if relative in group)


def together(private, *relatives) -> bool:
    return all(relative in group_of(private, relatives[0]) for relative in relatives)


def campaigns(test):
    """S2's batch: 50 addresses on one domain, in 5 unrelated campaigns of 10 with their own subject template."""
    batch = Batch(test)
    groups = [[batch.add(f'User <user{c}x{n}@{DIFFUSE}>', f'Account {word(c)} notice') for n in range(10)]
              for c in range(5)]
    return batch, groups


class DiffuseDomainTests(unittest.TestCase):
    def test_s2_a_confirmed_domain_no_longer_merges_on_its_own(self):
        batch, groups = campaigns(self)
        report, private = batch.run()
        self.assertEqual(report['diffuse_domains'], {'flagged': 1, 'confirmed': 0, 'unconfirmed': 1, 'rejected': 0})
        self.assertEqual(report['v1_rule_comparison']['groups'], 1)
        self.assertEqual(report['groups']['groups'], 1)
        report, private = batch.run(confirmed=[DIFFUSE])
        self.assertEqual(report['groups']['groups'], 5)
        for group in groups:
            self.assertEqual(group_of(private, group[0]), set(group))

    def test_s3_one_campaign_is_not_split(self):
        batch, groups = campaigns(self)
        again = batch.add(f'User <user0x0@{DIFFUSE}>', 'Account zulu reminder')  # the same address, another template
        report, private = batch.run(confirmed=[DIFFUSE])
        self.assertEqual(report['groups']['groups'], 5)
        self.assertEqual(group_of(private, groups[0][0]), set(groups[0]) | {again})
        # Unconfirmed, the domain merges as in v1 again.
        _report, private = batch.run()
        self.assertEqual(private['groups'], private['v1_rule_groups'])
        self.assertEqual(len(private['groups']), 1)

    def test_s3b_users_of_a_consumer_mailbox_are_not_one_organisation(self):
        batch = Batch(self)
        alice = batch.add('Alice <alice.synthetic@gmail.com>', 'Invoice alpha')
        alice_again = batch.add('Alice <alice.synthetic@gmail.com>', 'Payroll bravo')
        bob = batch.add('Bob <bob.synthetic@gmail.com>', 'Delivery charlie')
        _report, private = batch.run()
        self.assertTrue(together(private, alice, alice_again))
        self.assertFalse(together(private, alice, bob))

    def test_s3c_cross_field_links(self):
        batch = Batch(self)
        corp = 'synthetic-corp.com'
        first = batch.add(f'A <a0@{corp}>', 'Ledger alpha')
        batch.fill(corp, 20, start=1)
        reply = batch.add('X <x@synthetic-other.com>', 'Invoice bravo', reply_to=f'R <r@{corp}>')
        exact = batch.add('Y <y@synthetic-third.com>', 'Delivery charlie', reply_to=f'A <a0@{corp}>')
        plain_from = batch.add('P <p@synthetic-plain.com>', 'Rota delta')
        plain_reply = batch.add('Q <q@synthetic-misc.com>', 'Shift echo', reply_to='Z <z@synthetic-plain.com>')
        _report, private = batch.run()
        self.assertTrue(together(private, first, reply))  # a sender key met a Reply-To key, as in v1
        self.assertTrue(together(private, plain_from, plain_reply))
        _report, private = batch.run(confirmed=[corp])
        self.assertFalse(together(private, first, reply))  # a diffuse domain links in no field
        self.assertTrue(together(private, first, exact))    # a full address still does
        self.assertTrue(together(private, plain_from, plain_reply))


class BypassTests(unittest.TestCase):
    def test_s4_thread_evidence_alone(self):
        batch = Batch(self)
        root = batch.add('X <x@synthetic-one.com>', 'Quarterly alpha', message_id='<root.1@synthetic-one.com>')
        reply = batch.add('Y <y@synthetic-two.com>', 'Unrelated bravo', reply_to='R <r@synthetic-three.com>',
                          in_reply_to='<root.1@synthetic-one.com>')
        report, private = batch.run()
        self.assertTrue(together(private, root, reply))
        self.assertEqual(report['evidence']['thread']['groups_split_if_removed'], 1)
        (batch.root / reply).write_bytes(message('Y <y@synthetic-two.com>', 'Unrelated bravo',
                                                 reply_to='R <r@synthetic-three.com>'))
        _report, private = batch.run()
        self.assertFalse(together(private, root, reply))

    def test_s5_reply_to_on_a_diffuse_domain_does_not_bypass(self):
        batch = Batch(self)
        replies = 'synthetic-replies.com'
        batch.fill(DIFFUSE, 16)
        batch.fill(replies, 20, prefix='reply')
        x = [batch.add(f'X <x{n}@{DIFFUSE}>', 'Payment xray', reply_to=f'XR <xr@{replies}>') for n in range(3)]
        z = [batch.add(f'Z <z{n}@{DIFFUSE}>', 'Payment yankee', reply_to=f'ZR <zr@{replies}>') for n in range(3)]
        report, private = batch.run(confirmed=[DIFFUSE, replies])
        self.assertEqual(report['diffuse_domains']['confirmed'], 2)
        self.assertTrue(together(private, *x))
        self.assertFalse(together(private, x[0], z[0]))
        (batch.root / z[0]).write_bytes(message(f'Z <z0@{DIFFUSE}>', 'Payment yankee', reply_to=f'XR <xr@{replies}>'))
        _report, private = batch.run(confirmed=[DIFFUSE, replies])
        self.assertTrue(together(private, x[0], z[0]))  # the same Reply-To address

    def test_s6_a_subject_template_does_not_cross_domains(self):
        batch = Batch(self)
        batch.fill(DIFFUSE, 20)
        x = batch.add(f'X <x@{DIFFUSE}>', 'Shared kilo notice')
        y = batch.add('Y <y@synthetic-plain.com>', 'Shared kilo notice')
        _report, private = batch.run(confirmed=[DIFFUSE])
        self.assertFalse(together(private, x, y))
        _report, private = batch.run()
        self.assertTrue(together(private, x, y))  # unconfirmed: v1's template key

    def test_s7_a_third_message_cannot_bridge_through_templates(self):
        batch = Batch(self)
        batch.fill(DIFFUSE, 20)
        x = batch.add(f'X <x@{DIFFUSE}>', 'Alpha memo')
        z = batch.add(f'Z <z@{DIFFUSE}>', 'Bravo memo')
        w1 = batch.add('W <w1@synthetic-e.com>', 'Alpha memo')
        w2 = batch.add('W <w2@synthetic-e.com>', 'Bravo memo')
        report, private = batch.run(confirmed=[DIFFUSE])
        self.assertTrue(together(private, w1, w2))
        self.assertFalse(together(private, x, w1))
        self.assertFalse(together(private, z, w1))
        self.assertFalse(together(private, x, z))
        self.assertTrue(together({'groups': private['v1_rule_groups']}, x, w1, w2, z))
        self.assertEqual(report['groups']['bridged'], 0)

    def test_s7b_an_allowed_bridge_is_reported(self):
        batch = Batch(self)
        batch.fill(DIFFUSE, 20)
        x = batch.add(f'X <x1@{DIFFUSE}>', 'Charlie memo', reply_to='R <r1@synthetic-q.com>')
        z = batch.add(f'Z <z1@{DIFFUSE}>', 'Delta memo', reply_to='R <r2@synthetic-s.com>',
                      in_reply_to='<w.1@synthetic-e.com>')
        w = batch.add('W <w@synthetic-e.com>', 'Echo memo', reply_to='R <r1@synthetic-q.com>',
                      message_id='<w.1@synthetic-e.com>')
        report, private = batch.run(confirmed=[DIFFUSE])
        self.assertTrue(together(private, x, w, z))
        self.assertEqual(report['groups']['bridged'], 1)
        (batch.root / w).unlink()
        batch.paths.remove(w)
        report, private = batch.run(confirmed=[DIFFUSE])
        self.assertFalse(together(private, x, z))
        self.assertEqual(report['groups']['bridged'], 0)


class ConfirmationTests(unittest.TestCase):
    def test_s8_unconfirmed_without_thread_links_equals_v1(self):
        batch, _groups = campaigns(self)
        batch.fill('synthetic-plain.com', 3)
        batch.add('Alice <alice.synthetic@gmail.com>', 'Account alpha notice', reply_to=f'U <user0x0@{DIFFUSE}>')
        k = batch.add('K <k@synthetic-k.com>', 'Rota kilo')  # joined to l by the subject template alone, as in v1
        l = batch.add('L <l@synthetic-l.com>', 'Rota kilo')
        report, private = batch.run()
        self.assertEqual(report['diffuse_domains']['unconfirmed'], 1)
        self.assertEqual(private['groups'], private['v1_rule_groups'])
        self.assertTrue(together(private, k, l))
        report, private = batch.run(rejected=[DIFFUSE])
        self.assertEqual(report['diffuse_domains']['rejected'], 1)
        self.assertEqual(private['groups'], private['v1_rule_groups'])

    def test_s8b_thread_links_hold_whatever_the_confirmation(self):
        batch = Batch(self)
        batch.fill(DIFFUSE, 20)
        x = batch.add(f'X <x@{DIFFUSE}>', 'Alpha memo', message_id='<x.1@synthetic-diffuse.com>')
        y = batch.add('Y <y@synthetic-plain.com>', 'Bravo notes', in_reply_to='<x.1@synthetic-diffuse.com>')
        for confirmed in ((), (DIFFUSE,)):
            with self.subTest(confirmed=confirmed):
                _report, private = batch.run(confirmed=confirmed)
                self.assertTrue(together(private, x, y))
                self.assertFalse(together({'groups': private['v1_rule_groups']}, x, y))

    def test_s9_threshold_boundaries_on_deduplicated_records(self):
        for distinct, messages, flagged in ((19, 19, 0), (20, 20, 1), (20, 40, 1), (20, 41, 0)):
            batch = Batch(self)
            for n in range(messages):
                batch.add(f'S <s{n % distinct}@{DIFFUSE}>', f'Notice {word(n)}')
            report, _private = batch.run()
            self.assertEqual(report['diffuse_domains']['flagged'], flagged, (distinct, messages))
        # Byte-identical copies are one original: 20 addresses and 21 extra copies still give 20 messages.
        batch = Batch(self)
        batch.fill(DIFFUSE, 20)
        raw = (batch.root / batch.paths[0]).read_bytes()
        for _n in range(21):
            batch.add(None, raw=raw)
        report, _private = batch.run()
        self.assertEqual(report['counts']['duplicate_copies'], 21)
        self.assertEqual(report['counts']['valid_records'], 20)
        self.assertEqual(report['diffuse_domains']['flagged'], 1)

    def test_s10_input_order_does_not_matter(self):
        batch, _groups = campaigns(self)
        batch.fill('synthetic-plain.com', 5)
        batch.add('W <w@synthetic-e.com>', 'Echo memo', message_id='<w.1@synthetic-e.com>')
        batch.add('Z <z@synthetic-f.com>', 'Delta memo', in_reply_to='<w.1@synthetic-e.com>')
        first = batch.run(confirmed=[DIFFUSE])
        order = list(batch.paths)
        random.Random(7).shuffle(order)
        for paths in (order, list(reversed(batch.paths))):
            report, private = batch.run(confirmed=[DIFFUSE], order=paths)
            self.assertEqual(json.dumps(report, sort_keys=True), json.dumps(first[0], sort_keys=True))
            self.assertEqual(private, first[1])


class ReadingTests(unittest.TestCase):
    def counted_reads(self):
        sizes = []
        real_open = builtins.open

        def counting_open(path, mode='r', *args, **kwargs):
            stream = real_open(path, mode, *args, **kwargs)
            read = stream.read

            def counted(size=-1):
                data = read(size)
                sizes.append(len(data))
                return data

            stream.read = counted
            return stream

        return sizes, patch.object(v2, 'open', counting_open, create=True)

    def test_s11_reading_boundaries(self):
        batch = Batch(self)
        normal = batch.add('A <a@synthetic-a.com>', 'Alpha memo', body='From: b@synthetic-b.com\r\nSubject: fake\r\n' * 30000)
        # A blank line split across the first two 64 KiB blocks.
        pad = v2.BLOCK_SIZE - 2 - len('From: C <c@synthetic-c.com>\r\nX-Pad: ')  # the blank line starts 2 bytes before the block's end
        spanning = batch.add(None, raw=f'From: C <c@synthetic-c.com>\r\nX-Pad: {"p" * pad}\r\n\r\nbody'.encode())
        # Exactly 262,144 bytes before the blank line, and one byte more.
        head = 'From: D <d@synthetic-d.com>\r\nX-Pad: '
        at_limit = batch.add(None, raw=(head + 'p' * (v2.HEADER_LIMIT - len(head))).encode() + b'\r\n\r\nbody')
        over = batch.add(None, raw=(head + 'p' * (v2.HEADER_LIMIT + 1 - len(head))).encode() + b'\r\n\r\nbody')
        no_blank = batch.add(None, raw=b'From: E <e@synthetic-e.com>\r\nSubject: Echo memo')
        sizes, counting = self.counted_reads()
        with counting:
            report, private = batch.run()
        counts = report['counts']
        self.assertEqual((counts['accepted'], counts['accepted_without_blank_line'], counts['header_too_large']), (3, 1, 1))
        self.assertEqual(counts['input_files'], counts['valid_records'] + counts['duplicate_copies']
                         + counts['header_too_large'] + counts['no_sender_address'])
        self.assertEqual(counts['conservation_holds'], 1)
        flat = {path for group in private['groups'] for path in group}
        self.assertTrue({normal, spanning, at_limit, no_blank} <= flat)
        self.assertNotIn(over, flat)
        # The 2 MiB body after the first blank line is never read whole: one 64 KiB block suffices.
        self.assertLessEqual(max(sizes), v2.BLOCK_SIZE)
        self.assertLess(sum(sizes), 6 * v2.BLOCK_SIZE + 2 * v2.HEADER_LIMIT)
        self.assertEqual(len(group_of(private, normal)), 1)

    def test_s11b_copies_follow_the_manifest(self):
        batch = Batch(self)
        raw = message('A <a@synthetic-a.com>', 'Alpha memo')
        first, copy = batch.add(None, raw=raw), batch.add(None, raw=raw)
        # The same headers with another body: two originals, not a copy.
        other = batch.add(None, raw=message('A <a@synthetic-a.com>', 'Alpha memo', body='Another body.'))
        report, private = batch.run()
        self.assertEqual((report['counts']['valid_records'], report['counts']['duplicate_copies']), (2, 1))
        self.assertTrue(together(private, first, other))
        self.assertNotIn(copy, {path for group in private['groups'] for path in group})
        manifest = batch.manifest()
        (batch.root / 'extra.eml').write_bytes(raw)
        with self.assertRaisesRegex(v2.GroupingError, '^The input files do not match the manifest$'):
            v2.group_candidates(batch.root, manifest)
        (batch.root / 'extra.eml').unlink()
        (batch.root / first).write_bytes(raw + b'x')
        with self.assertRaisesRegex(v2.GroupingError, '^A file size does not match the manifest$'):
            v2.group_candidates(batch.root, manifest)

    def test_s11c_odd_thread_ids_link_nothing(self):
        batch = Batch(self)
        base = batch.add('A <a@synthetic-a.com>', 'Alpha memo', message_id='<ab@synthetic-a.com>')
        spaced = batch.add('B <b@synthetic-b.com>', 'Bravo memo', in_reply_to='<a b@synthetic-a.com>')
        empty = batch.add('C <c@synthetic-c.com>', 'Charlie memo', message_id='', in_reply_to='<>')
        empty_reply = batch.add('D <d@synthetic-d.com>', 'Delta memo', in_reply_to='')
        empty_bracket = batch.add('I <i@synthetic-i.com>', 'India memo', in_reply_to='<>')
        twin1 = batch.add('E <e@synthetic-e.com>', 'Echo memo', message_id='<same@synthetic-x.com>')
        twin2 = batch.add('F <f@synthetic-f.com>', 'Foxtrot memo', message_id='<same@synthetic-x.com>')
        to_twin = batch.add('G <g@synthetic-g.com>', 'Golf memo', in_reply_to='<same@synthetic-x.com>')
        targets = [batch.add(f'T <t{n}@synthetic-t{n}.com>', f'Target {word(n)}', message_id=f'<id{n}@synthetic-t.com>')
                   for n in range(3)]
        ids = [f'<ref{n}@synthetic-r.com>' for n in range(150)]
        ids[0], ids[50], ids[149] = '<id0@synthetic-t.com>', '<id1@synthetic-t.com>', '<id2@synthetic-t.com>'
        long = batch.add('H <h@synthetic-h.com>', 'Hotel memo', references=' '.join(ids))
        report, private = batch.run()
        for relative in (spaced, empty, empty_reply, empty_bracket, to_twin, twin1, twin2):
            self.assertEqual(len(group_of(private, relative)), 1, relative)
        self.assertEqual(len(group_of(private, base)), 1)
        self.assertTrue(together(private, long, targets[0], targets[2]))  # the list's first and last are kept
        self.assertFalse(together(private, long, targets[1]))             # the middle is dropped
        counts = report['counts']
        self.assertEqual((counts['duplicate_message_ids'], counts['messages_with_duplicate_message_id']), (1, 2))
        self.assertEqual((counts['references_truncated_messages'], counts['references_dropped_ids']), (1, 50))
        self.assertEqual(counts['reference_ids_malformed'], 3)  # '<a b@…>' and two '<>'
        self.assertEqual(counts['message_id_missing'], len(batch.paths) - 6)  # an empty Message-ID is missing


class OutputTests(unittest.TestCase):
    def test_s12_reports_hold_counts_only(self):
        batch, _groups = campaigns(self)
        report, private = batch.run(confirmed=[DIFFUSE])
        text = json.dumps(report)
        for marker in ('synthetic', 'user0', 'Account', 'alpha', '@'):
            self.assertNotIn(marker, text)
        self.assertEqual(report['confirmations']['confirmer'], 'owner-01')
        self.assertTrue(report['confirmations']['basis_recorded'])
        self.assertRegex(report['confirmations']['sha256'], '^[0-9a-f]{64}$')
        self.assertEqual(report['input']['identity'], v2.IDENTITY_NOTE)
        self.assertEqual(private['flagged'], {DIFFUSE: {'distinct_addresses': 50, 'messages': 50, 'status': 'confirmed'}})
        manifest = batch.manifest()
        stale = batch.confirmations(manifest, confirmed=[DIFFUSE])
        batch.add('W <w@synthetic-e.com>', 'Echo memo')  # another input: the confirmations no longer apply
        with self.assertRaisesRegex(v2.GroupingError, '^The confirmations belong to another input$'):
            v2.group_candidates(batch.root, batch.manifest(), stale)

    def test_s12_command_line_writes_counts_and_a_private_flagged_list(self):
        batch, _groups = campaigns(self)
        manifest = batch.manifest()
        confirmations = batch.confirmations(manifest, confirmed=[DIFFUSE])
        output, flagged = batch.base / 'report.json', batch.base / 'flagged.json'
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            v2.main(['--root', str(batch.root), '--manifest', str(manifest), '--confirmations', str(confirmations),
                     '--output', str(output), '--flagged-output', str(flagged)])
        self.assertEqual(json.loads(stdout.getvalue()), {'groups': 5, 'valid_records': 50})
        self.assertNotIn('synthetic', output.read_text() + stdout.getvalue() + stderr.getvalue())
        self.assertIn(DIFFUSE, flagged.read_text())
        self.assertEqual(stat.S_IMODE(os.stat(flagged).st_mode), 0o600)
        for arguments, expected in (
                (['--root', str(batch.root)], 'Grouping stopped: invalid arguments'),
                (['--root', 'relative', '--manifest', str(manifest), '--output', str(output)],
                 'Grouping stopped: Every path must be absolute'),
                (['--root', str(batch.root), '--manifest', str(manifest), '--output', str(batch.root / 'r.json')],
                 'Grouping stopped: An output would overwrite an input'),
                (['--root', str(batch.root), '--manifest', str(manifest), '--output', str(manifest)],
                 'Grouping stopped: An output would overwrite an input')):
            with self.subTest(arguments=arguments[-1]):
                completed = subprocess.run([sys.executable, str(WEBSITE_DIR / 'tools/phishing_candidate_groups_v2.py'),
                                            *arguments], capture_output=True, text=True, timeout=120)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr.strip(), expected)

    def test_s13_a_v1_ledger_is_refused(self):
        batch, _groups = campaigns(self)
        manifest = batch.manifest()
        ledger = batch.base / 'ledger.json'
        ledger.write_text(json.dumps({'schema': 'family-split-ledger-v1', 'salt': '5a' * 32, 'families': {}, 'messages': {}}))
        for arguments in ((ledger, None), (manifest, ledger)):
            with self.subTest(input=arguments[0].name), \
                    self.assertRaisesRegex(v2.GroupingError, '^A v1 family-split ledger is not an input of this tool$'):
                v2.group_candidates(batch.root, *arguments)

    def test_no_network(self):
        batch, _groups = campaigns(self)
        batch.add('W <w@synthetic-e.com>', 'Echo memo', message_id='<w.1@synthetic-e.com>')
        with blocked_network() as attempts:
            batch.run(confirmed=[DIFFUSE])
        self.assertEqual(attempts, [])


if __name__ == '__main__':
    unittest.main()
