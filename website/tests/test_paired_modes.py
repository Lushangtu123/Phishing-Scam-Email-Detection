"""P1/P2 pairing in memory (docs/superpowers/specs/2026-10-20-p1-p2-pairing-design.md, approved
2026-10-20): the acceptance criteria on synthetic inputs only."""
import copy
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dkim  # noqa: E402

import app  # noqa: E402
import email_structure as es  # noqa: E402
from arc_test_keys import make_key  # noqa: E402
from network_guard import SITECUSTOMIZE, blocked_network  # noqa: E402
from test_arc_sealed_results import message as arc_message  # noqa: E402
from test_review_2026_10_01 import deployment_pipeline  # noqa: E402
from tools import evaluate_paired_modes as paired  # noqa: E402
from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools import pasted_cohort  # noqa: E402

CONFIG = {'trusted_authserv_ids': [], 'observe_sender_history': False, 'verification_mode': 'off',
          'content_model_enabled': True, 'auxiliary_enabled': False, 'model_only_option': 'A', 'intent_rules': 'none'}
CONFIGURATIONS = {'p1': {**CONFIG, 'mailbox_setting': 'recorded', 'input_mode': 'as_submitted'},
                  'p2': {**CONFIG, 'mailbox_setting': 'none', 'input_mode': 'pasted'}}
MARKERS = ('marker-id-', 'Marker subject', 'marker-file-')


def eml(subject, body, *, extra='', content_type='text/plain', sender='Pat <pat@example.org>'):
    return (f'From: {sender}\r\nTo: user@example.org\r\nSubject: {subject}\r\n{extra}'
            f'Content-Type: {content_type}; charset=utf-8\r\n\r\n{body}\r\n').encode()


class Sources:
    """Synthetic originals written to a temporary folder, with their JSONL rows."""

    def __init__(self, test):
        self.folder = Path(tempfile.mkdtemp())
        test.addCleanup(shutil.rmtree, self.folder, ignore_errors=True)
        self.rows, self.count = [], 0

    def add(self, raw: bytes, label='legitimate', **extra):
        self.count += 1
        path = self.folder / f'marker-file-{self.count}.eml'
        path.write_bytes(raw)
        self.rows.append({'id': f'marker-id-{self.count}', 'label': label, 'provider': 'gmail',
                          'received_at': '2026-09-01', 'eml_path': str(path), **extra})
        return path


def standard(test):
    """One source for each case of criterion 1, plus a phishing pair so both classes exist."""
    sources = Sources(test)
    sources.add(eml('Marker subject one', 'Team notes for the week.'))                          # pairs
    sources.add(eml('Request', 'Please reply with your password and verify your account today.'),
                label='phishing')                                                              # pairs
    markup = '<div style="color:#333">Team notes for the week.</div>\r\n' * 1200
    sources.add(eml('Notes', markup, content_type='text/html'))                                 # P2 only
    sources.add(eml('Long notes', 'Team notes for the week.\r\n' * 2050))                       # P1 only
    sources.add(eml('Same text', 'Shared visible text.', extra='X-Variant: 1\r\n'))             # one pair,
    sources.add(eml('Same text', 'Shared visible text.', extra='X-Variant: 2\r\n'))             # one P1 only
    twin = eml('Twin', 'Byte-identical originals.')
    sources.add(twin)
    sources.add(twin)                                                                            # neither: copy
    sources.add(b'  \r\n')                                                                       # neither: empty
    sources.add(b'x' * (pasted_cohort.MAX_SOURCE_BYTES + 1))                                     # neither: too large
    return sources


def run(rows, **kwargs):
    with patch.object(app, '_content_pipeline', None):
        return paired.evaluate_paired(rows, model_sha256='a' * 64, configurations=CONFIGURATIONS, **kwargs)


class SetTests(unittest.TestCase):
    def test_each_case_falls_in_its_set_and_the_sets_are_conserved(self):
        report = run(standard(self).rows)
        integrity = report['input_integrity']
        self.assertEqual(integrity['valid_records'], 10)
        self.assertEqual(integrity['sets'], {'pairs': 4, 'p1_only': 2, 'p2_only': 1, 'neither': 3})
        self.assertEqual(sum(integrity['sets'].values()), integrity['valid_records'])
        self.assertEqual(integrity['without_view'], {
            'p1': {'duplicate_source': 1, 'eml_too_large': 1, 'empty_source': 1, 'source_too_large': 1},
            'p2': {'body_too_long': 1, 'duplicate': 1, 'duplicate_source': 1, 'empty_source': 1,
                   'source_too_large': 1}})
        # The source over 3 MiB has no digest, so "neither" has none either.
        self.assertEqual(integrity['unhashed'], {'pairs': 0, 'p1_only': 0, 'p2_only': 0, 'neither': 1})
        self.assertIsNone(integrity['set_digests']['neither'])
        for name in ('pairs', 'p1_only', 'p2_only'):
            self.assertRegex(integrity['set_digests'][name], r'^[0-9a-f]{64}$')
        for name, modes in (('pairs', ('p1', 'p2')), ('p1_only', ('p1',)), ('p2_only', ('p2',))):
            for mode in modes:
                entry = report['reports'][name][mode]
                self.assertEqual(entry['report']['input_integrity']['evaluated_rows'], integrity['sets'][name])
                self.assertEqual(entry['set_digest'], integrity['set_digests'][name])
        table = report['decision_table']
        self.assertEqual(sum(cell for label in table.values() for row in label.values() for cell in row.values()),
                         integrity['sets']['pairs'])

    def test_the_smaller_source_digest_represents_shared_text(self):
        sources = Sources(self)
        first = sources.add(eml('Same text', 'Shared visible text.', extra='X-Variant: 1\r\n'))
        second = sources.add(eml('Same text', 'Shared visible text.', extra='X-Variant: 2\r\n'))
        report = run(sources.rows)
        self.assertEqual(report['input_integrity']['sets'], {'pairs': 1, 'p1_only': 1, 'p2_only': 0, 'neither': 0})
        import hashlib
        smaller = min((first, second), key=lambda path: hashlib.sha256(path.read_bytes()).hexdigest())
        expected = paired._set_digest([hashlib.sha256(smaller.read_bytes()).hexdigest()])
        self.assertEqual(report['input_integrity']['set_digests']['pairs'], expected)

    def test_a_holdout_row_is_refused_before_any_source_is_read(self):
        sources = standard(self)
        sources.rows[3]['cohort_role'] = 'holdout'
        reads = []
        with self.assertRaises(paired.PairedRunError) as raised:
            run(sources.rows, read=lambda path: reads.append(path) or b'')
        self.assertEqual(reads, [])
        self.assertNotRegex(str(raised.exception), r'\d|marker')


class OrderAndReadTests(unittest.TestCase):
    def test_input_order_does_not_change_the_report(self):
        sources = standard(self)
        expected = json.dumps(run(sources.rows), sort_keys=True)
        for seed in range(3):
            rows = copy.deepcopy(sources.rows)
            random.Random(seed).shuffle(rows)
            with self.subTest(seed=seed):
                self.assertEqual(json.dumps(run(rows), sort_keys=True), expected)
        self.assertEqual(json.dumps(run(list(reversed(sources.rows))), sort_keys=True), expected)

    def test_each_original_is_read_once_and_later_changes_do_not_count(self):
        sources = standard(self)
        before = json.dumps(run(sources.rows), sort_keys=True)
        reads = []

        def read(path):
            reads.append(path)
            return paired._read_snapshot(path)

        changed = []
        analyze = serving.analyze_record

        def analyze_and_change(row, **kwargs):
            if not changed:  # rewrite every original once the run has its snapshots
                for row_in in sources.rows:
                    Path(row_in['eml_path']).write_bytes(eml('Changed', 'Different text now.'))
                changed.append(True)
            return analyze(row, **kwargs)

        with (patch.object(serving, 'analyze_record', analyze_and_change),
              patch.object(serving, '_read_eml', side_effect=AssertionError('read again'))):
            after = json.dumps(run(sources.rows, read=read), sort_keys=True)
        self.assertEqual(sorted(reads), sorted(row['eml_path'] for row in sources.rows))
        self.assertTrue(changed)
        self.assertEqual(after, before)


class BoundaryTests(unittest.TestCase):
    """Criterion 6: the reports' existing part equals the existing evaluator on the same rows."""

    def test_each_mode_matches_the_existing_evaluator(self):
        sources = standard(self)
        report = run(sources.rows)
        by_path = {row['eml_path']: row for row in sources.rows}
        import hashlib
        digest = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in by_path}

        def members(paths):
            return [by_path[path] for path in sorted(paths, key=lambda path: digest[path])]

        sets = {'pairs': [sources.rows[0], sources.rows[1], sources.rows[6]],
                'p1_only': [sources.rows[3]], 'p2_only': [sources.rows[2]]}
        # The shared-text pair: the smaller digest is the pair, the other is P1 only.
        shared = sorted((sources.rows[4], sources.rows[5]), key=lambda row: digest[row['eml_path']])
        sets['pairs'].append(shared[0])
        sets['p1_only'].append(shared[1])
        with patch.object(app, '_content_pipeline', None):
            for name, mode, analyze, paste in (('pairs', 'p1', 'recorded', False), ('pairs', 'p2', 'none', True),
                                               ('p1_only', 'p1', 'recorded', False), ('p2_only', 'p2', 'none', True)):
                rows = members([row['eml_path'] for row in sets[name]])
                existing = serving.evaluate_records(
                    rows, lambda row, _analyze=analyze: serving.analyze_record(row, mailbox_setting=_analyze),
                    model_sha256='a' * 64, configuration=CONFIGURATIONS[mode], paste=paste)
                with self.subTest(set=name, mode=mode):
                    self.assertEqual(json.dumps(report['reports'][name][mode]['report'], sort_keys=True),
                                     json.dumps(existing, sort_keys=True))

    def test_empty_sets_call_no_evaluator(self):
        sources = Sources(self)
        sources.add(eml('Notes', 'Team notes for the week.'))
        sources.add(eml('Request', 'Please reply with your password and verify your account today.'),
                    label='phishing')
        calls = []
        evaluate = serving.evaluate_records

        def counted(*args, **kwargs):
            calls.append(kwargs.get('paste', False))
            return evaluate(*args, **kwargs)

        with patch.object(serving, 'evaluate_records', counted):
            report = run(sources.rows)
        self.assertEqual(report['input_integrity']['sets'], {'pairs': 2, 'p1_only': 0, 'p2_only': 0, 'neither': 0})
        self.assertEqual(calls, [False, True])  # the pairs, in P1 and in P2
        self.assertEqual(set(report['reports']), {'pairs'})

    def test_one_changed_original_changes_the_pair_digest(self):
        sources = standard(self)
        before = run(sources.rows)['input_integrity']['set_digests']['pairs']
        Path(sources.rows[0]['eml_path']).write_bytes(eml('Marker subject one', 'Team notes for the month.'))
        self.assertNotEqual(run(sources.rows)['input_integrity']['set_digests']['pairs'], before)


class PreparedRowTests(unittest.TestCase):
    """Criterion 10: the snapshots entry of evaluate_records."""

    def test_no_input_field_turns_it_on(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'original.eml'
            path.write_bytes(eml('Original', 'Team notes alpha.'))
            row = {'label': 'legitimate', 'provider': 'gmail', 'received_at': '2026-09-01', 'eml_path': str(path),
                   '_eml_bytes': 'Subject: Injected\r\n\r\nInjected.', 'snapshots': ['Injected'], '_snapshot': 'Injected',
                   'prepared': True}
            seen = []
            for paste in (False, True):
                serving.evaluate_records([row], lambda row: seen.append(row.get('_eml_bytes') or row.get('body'))
                                         or {'risk_level': 'low'}, model_sha256='a' * 64, paste=paste)
            self.assertEqual(seen, [path.read_bytes(), 'Team notes alpha.'])
        completed = subprocess.run([sys.executable, str(WEBSITE_DIR / 'tools/evaluate_serving_pipeline.py'), '--help'],
                                   capture_output=True, text=True, timeout=60)
        self.assertNotIn('snapshot', completed.stdout.lower())

    def test_the_rules_still_apply_through_it(self):
        row = {'label': 'legitimate', 'provider': 'gmail', 'received_at': '2026-09-01', 'eml_path': '/unused.eml'}
        with self.assertRaisesRegex(ValueError, 'sealed'):
            serving.evaluate_records([{**row, 'cohort_role': 'holdout'}], lambda row: {'risk_level': 'low'},
                                     model_sha256='a' * 64, snapshots=[eml('Notes', 'Team notes.')])
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            serving.evaluate_records([row, {**row, 'label': 'phishing'}], lambda row: {'risk_level': 'low'},
                                     model_sha256='a' * 64, snapshots=[eml('Notes', 'Same.'), eml('Notes', 'Same.')])
        with self.assertRaisesRegex(RuntimeError, 'could not be read'):
            serving.evaluate_records([row], lambda row: {'risk_level': 'low'}, model_sha256='a' * 64,
                                     snapshots=[b'x' * (serving.MAX_EML_BYTES + 1)])
        text_row = {key: value for key, value in row.items() if key != 'eml_path'} | {'subject': 'S', 'body': 'B'}
        with self.assertRaisesRegex(ValueError, 'belongs to an eml_path row'):
            serving.evaluate_records([text_row], lambda row: {'risk_level': 'low'}, model_sha256='a' * 64,
                                     snapshots=[eml('Notes', 'Team notes.')])
        with self.assertRaisesRegex(ValueError, 'exactly one byte snapshot'):
            serving.evaluate_records([row], lambda row: {'risk_level': 'low'}, model_sha256='a' * 64, snapshots=[])


class PrivacyTests(unittest.TestCase):
    """Criterion 8: no identifier, path, line number, subject or text leaves the process."""

    def assert_clean(self, text):
        for marker in MARKERS:
            self.assertNotIn(marker, text)
        self.assertNotIn('Row ', text)
        self.assertNotIn('Line ', text)

    def test_reports_hold_no_membership(self):
        self.assert_clean(json.dumps(run(standard(self).rows)))

    def test_failing_runs_name_no_row(self):
        sources = standard(self)
        cases = {
            'malformed': [*sources.rows[:2], {**sources.rows[2], 'label': 'spam'}],
            'unreadable': [*sources.rows[:2], {**sources.rows[2], 'eml_path': str(sources.folder / 'marker-file-missing.eml')}],
        }
        for name, rows in cases.items():
            with self.subTest(case=name), self.assertRaises(paired.PairedRunError) as raised:
                run(rows)
            self.assert_clean(str(raised.exception))
            self.assertNotRegex(str(raised.exception), r'\d')
            self.assertIsNone(raised.exception.__cause__)

        def failing(row, **kwargs):
            raise RuntimeError('marker-id-1 Marker subject one')

        with patch.object(serving, 'analyze_record', failing), self.assertRaises(paired.PairedRunError) as raised:
            run(sources.rows)
        self.assert_clean(str(raised.exception))
        self.assertNotRegex(str(raised.exception), r'\d')


class ReviewFixTests(unittest.TestCase):
    """The review of 7a4bb93 (2026-10-20): argument errors, the exception boundary, the output path,
    and one read per file."""

    def command(self, *arguments):
        return subprocess.run([sys.executable, str(WEBSITE_DIR / 'tools/evaluate_paired_modes.py'), *arguments],
                              capture_output=True, text=True, timeout=120)

    def test_argument_errors_echo_nothing(self):
        for arguments in (['--input', '/tmp/marker-file-1.jsonl', '--output', '/tmp/out.json', '--marker-id-1', 'x'],
                          ['--output', '/tmp/marker-file-1.json'], ['--inp', '/tmp/marker-file-1.jsonl']):
            with self.subTest(arguments=arguments[-2:]):
                completed = self.command(*arguments)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr.strip(), 'Paired run stopped: invalid arguments')
                self.assertNotIn('marker', completed.stdout + completed.stderr)
        completed = self.command('--input', 'marker-file-relative.jsonl', '--output', '/tmp/out.json')
        self.assertEqual(completed.stderr.strip(), 'Paired run stopped: --input and --output must be distinct absolute paths')

    def test_no_failure_carries_its_original_message(self):
        def failing(row):
            raise RuntimeError('marker-id-1 Marker subject one /tmp/marker-file-1.eml')

        sources = standard(self)
        for patcher in (patch.object(pasted_cohort, 'pasted', failing),
                        patch.object(paired, '_metadata', failing)):
            with self.subTest(target=patcher.attribute), patcher, self.assertRaises(paired.PairedRunError) as raised:
                run(sources.rows)
            self.assertEqual(str(raised.exception), 'The paired run failed')
            self.assertIsNone(raised.exception.__cause__)
            self.assertIsNone(raised.exception.__context__)
        sources.rows[0]['cohort_role'] = 'holdout'
        with self.assertRaises(paired.PairedRunError) as raised:
            run(sources.rows)
        self.assertIsNone(raised.exception.__context__)

    def test_the_report_never_overwrites_a_source(self):
        sources = Sources(self)
        original = sources.add(eml('Marker subject one', 'Team notes for the week.'))
        content = original.read_bytes()
        source_file = sources.folder / 'sources.jsonl'
        source_file.write_text(json.dumps(sources.rows[0]) + '\n')
        symbolic, hard = sources.folder / 'link.json', sources.folder / 'hard.json'
        symbolic.symlink_to(original)
        os.link(original, hard)
        for output in (original, symbolic, hard, sources.folder / '.' / original.name, source_file):
            with self.subTest(output=output.name):
                completed = self.command('--input', str(source_file), '--output', str(output))
                self.assertEqual(completed.returncode, 1)
                self.assertIn(completed.stderr.strip(), {'Paired run stopped: The output would overwrite a source file',
                                                         'Paired run stopped: --input and --output must be distinct absolute paths'})
                self.assertNotIn('marker', completed.stderr)
                self.assertEqual(original.read_bytes(), content)

    def test_a_file_named_twice_is_read_once(self):
        sources = Sources(self)
        original = sources.add(eml('Marker subject one', 'Team notes for the week.'))
        sources.add(eml('Request', 'Please reply with your password and verify your account today.'), label='phishing')
        hard = sources.folder / 'marker-file-hard.eml'
        os.link(original, hard)
        sources.rows.append({**sources.rows[0], 'id': 'marker-id-again'})            # the same path
        sources.rows.append({**sources.rows[0], 'id': 'marker-id-hard', 'eml_path': str(hard)})  # a hard link
        reads = []

        def read(path):
            reads.append(path)
            return paired._read_snapshot(path)

        report = run(sources.rows, read=read)
        self.assertEqual(len(reads), 2)  # the two files, not the four rows
        self.assertEqual(report['input_integrity']['valid_records'], 4)
        self.assertEqual(report['input_integrity']['sets'], {'pairs': 2, 'p1_only': 0, 'p2_only': 0, 'neither': 2})
        self.assertEqual(report['input_integrity']['without_view']['p1'], {'duplicate_source': 2})
        conflicting = [*sources.rows[:2], {**sources.rows[0], 'label': 'phishing'}]
        with self.assertRaisesRegex(paired.PairedRunError, 'conflicting'):
            run(conflicting)

    def test_each_set_report_names_its_commit(self):
        sources = Sources(self)
        sources.add(eml('Notes', 'Team notes for the week.'))
        sources.add(eml('Request', 'Please reply with your password and verify your account today.'),
                    label='phishing')
        metadata = {mode: {'git_commit': mode[1] * 40, 'configuration': CONFIGURATIONS[mode]} for mode in CONFIGURATIONS}
        report = run(sources.rows, reproducibility=metadata)
        for mode, entry in report['reports']['pairs'].items():
            with self.subTest(mode=mode):
                self.assertEqual(entry['report']['reproducibility'], {**metadata[mode], 'frozen_plan': None})
                for sidecar in ('counterfactual', 'attribution'):
                    self.assertEqual(entry[sidecar]['tool']['evaluated_commit'], mode[1] * 40)


class NetworkTests(unittest.TestCase):
    """Criterion 9: an ARC-sealed source makes no lookup, in process and from the command line."""

    @classmethod
    def setUpClass(cls):
        private_key, _txt = make_key()
        raw = arc_message()
        cls.sealed = b''.join(dkim.arc_sign(raw, b'arc-test', b'google.com', private_key, b'mx.google.com')) + raw

    def test_in_process(self):
        sources = Sources(self)
        sources.add(self.sealed)
        sources.add(eml('Request', 'Please reply with your password and verify your account today.'), label='phishing')
        with blocked_network() as attempts, patch.dict(es._ARC_KEY_CACHE, clear=True):
            report = run(sources.rows)
        self.assertEqual(attempts, [])
        self.assertEqual(report['input_integrity']['sets']['pairs'], 2)

    def test_from_the_command_line(self):
        deployment_pipeline(self)  # skips where the committed artifact cannot load
        sources = Sources(self)
        sources.add(self.sealed)
        sources.add(eml('Request', 'Please reply with your password and verify your account today.'), label='phishing')
        sources.add(eml('Marker subject one', 'Team notes for the week.'))
        guard = sources.folder / 'guard'
        guard.mkdir()
        (guard / 'sitecustomize.py').write_text(SITECUSTOMIZE)
        log, output = sources.folder / 'network.log', sources.folder / 'private.json'
        source_file = sources.folder / 'sources.jsonl'
        source_file.write_text(''.join(json.dumps(row) + '\n' for row in sources.rows))
        environment = {**os.environ, 'PYTHONPATH': str(guard), 'PHISHGUARD_TEST_NETWORK_LOG': str(log)}
        completed = subprocess.run([sys.executable, str(WEBSITE_DIR / 'tools/evaluate_paired_modes.py'),
                                    '--input', str(source_file), '--output', str(output)],
                                   capture_output=True, text=True, timeout=300, env=environment)
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        self.assertFalse(log.exists() and log.read_text().strip())
        for text in (completed.stdout, completed.stderr):
            for marker in MARKERS:
                self.assertNotIn(marker, text)
        self.assertEqual(json.loads(completed.stdout)['sets']['pairs'], 3)
        private = json.loads(output.read_text())
        for marker in MARKERS:
            self.assertNotIn(marker, json.dumps(private))
        self.assertIn('decision_table', private)
        # Each set report and its sidecars record the commit evaluated, as the existing command line does.
        commit = private['reproducibility']['git_commit']
        for mode, entry in private['reports']['pairs'].items():
            with self.subTest(mode=mode):
                self.assertEqual(entry['report']['reproducibility']['git_commit'], commit)
                self.assertEqual(entry['report']['reproducibility']['configuration'],
                                 private['reproducibility']['configuration'][mode])
                self.assertIsNone(entry['report']['reproducibility']['frozen_plan'])
                for sidecar in ('counterfactual', 'attribution'):
                    self.assertEqual(entry[sidecar]['tool']['evaluated_commit'], commit)
        # A failing run prints a fixed message and no row.
        source_file.write_text(json.dumps({**sources.rows[0], 'label': 'spam'}) + '\n')
        failed = subprocess.run([sys.executable, str(WEBSITE_DIR / 'tools/evaluate_paired_modes.py'),
                                 '--input', str(source_file), '--output', str(output)],
                                capture_output=True, text=True, timeout=300, env=environment)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stderr.strip(), 'Paired run stopped: An input row is invalid')


if __name__ == '__main__':
    unittest.main()
