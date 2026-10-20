"""Pasted cohorts: no ARC lookups, no truncation, metadata kept, exclusions counted (docs/evaluation.md,
"Pasted cohorts without truncation or ARC", 2026-10-20). Synthetic inputs only."""
import json
import os
from pathlib import Path
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
from test_arc_sealed_results import message  # noqa: E402
from test_review_2026_10_01 import deployment_pipeline  # noqa: E402
from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools import pasted_cohort  # noqa: E402

META = {'id': 'r1', 'label': 'legitimate', 'provider': 'gmail', 'received_at': '2026-09-01', 'language': 'en'}


def plain_eml(subject: str, body: str) -> bytes:
    return (f'From: Pat <pat@example.org>\r\nTo: user@example.org\r\nSubject: {subject}\r\n'
            f'Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n').encode()


class LimitTests(unittest.TestCase):
    def test_subjects_and_bodies_at_the_limit_are_kept_and_over_it_excluded(self):
        for subject, body, reason in (('s' * 500, 'b' * 50_000, None), ('s' * 501, 'body', 'subject_too_long'),
                                      ('subject', 'b' * 50_001, 'body_too_long'), ('', '', 'no_text')):
            for row in ({**META, 'subject': subject, 'body': body}, {**META, '_eml_bytes': plain_eml(subject, body)}):
                with self.subTest(reason=reason, source='eml' if '_eml_bytes' in row else 'text'):
                    if reason is None:
                        result = pasted_cohort.pasted(row)
                        self.assertEqual((len(result['subject']), len(result['body'])), (500, 50_000))
                    else:
                        with self.assertRaises(pasted_cohort.PasteExcluded) as raised:
                            pasted_cohort.pasted(row)
                        self.assertEqual(raised.exception.reason, reason)

    def test_source_files_are_read_up_to_a_fixed_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            for name, data, reason in (('empty.eml', b'  \r\n', 'empty_source'),
                                       ('large.eml', b'x' * (pasted_cohort.MAX_SOURCE_BYTES + 1), 'source_too_large')):
                path = Path(folder) / name
                path.write_bytes(data)
                with self.subTest(name=name), self.assertRaises(pasted_cohort.PasteExcluded) as raised:
                    pasted_cohort.pasted({**META, 'eml_path': str(path)})
                self.assertEqual(raised.exception.reason, reason)
            # Over the 60,000-byte .eml limit but within the paste limits: kept whole.
            markup = '<div style="color:#333">Team notes for the week.</div>\r\n' * 1200
            path = Path(folder) / 'notes.eml'
            path.write_bytes(plain_eml('Notes', markup).replace(b'text/plain', b'text/html'))
            self.assertGreater(path.stat().st_size, serving.MAX_EML_BYTES)
            result = pasted_cohort.pasted({**META, 'eml_path': str(path)})
            self.assertIn('Team notes for the week.', result['body'])
            self.assertNotIn('<div', result['body'])


class MetadataTests(unittest.TestCase):
    def test_every_field_but_the_content_is_kept(self):
        row = {**META, 'cohort_role': 'holdout', 'family_id': 'f' * 16, 'behaviour': 'credential_handover',
               'eml_path': '/synthetic.eml', '_eml_bytes': plain_eml('Notes', 'Team notes for the week.')}
        result = pasted_cohort.pasted(row)
        self.assertEqual({key: value for key, value in result.items() if key not in {'subject', 'body'}},
                         {key: value for key, value in row.items() if key not in {'eml_path', '_eml_bytes'}})
        self.assertEqual((result['subject'], result['body']), ('Notes', 'Team notes for the week.'))

    def test_holdout_rows_stay_refused_in_pasted_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'held.eml'
            path.write_bytes(plain_eml('Notes', 'Team notes for the week.'))
            row = {**META, 'cohort_role': 'holdout', 'eml_path': str(path)}
            with self.assertRaisesRegex(ValueError, 'sealed'):
                serving.evaluate_records([row], lambda row: {'risk_level': 'low'}, model_sha256='a' * 64, paste=True)


class ArcTests(unittest.TestCase):
    """Extracting a sealed message's text looks up no key."""

    @classmethod
    def setUpClass(cls):
        private_key, _txt = make_key()
        raw = message()
        cls.sealed = b''.join(dkim.arc_sign(raw, b'arc-test', b'google.com', private_key, b'mx.google.com')) + raw

    def test_extraction_makes_no_lookup_where_default_verification_would(self):
        # Control: read with the default ARC verification, the same message reaches for DNS.
        with blocked_network() as attempts, patch.dict(es._ARC_KEY_CACHE, clear=True):
            es.analyze_raw_email(self.sealed)
        self.assertTrue(attempts)
        with blocked_network() as attempts, patch.dict(es._ARC_KEY_CACHE, clear=True):
            result = pasted_cohort.pasted({**META, '_eml_bytes': self.sealed})
        self.assertEqual(attempts, [])
        self.assertIn('482913', result['body'])

    def test_the_serving_evaluator_in_pasted_mode_makes_no_lookup(self):
        with tempfile.TemporaryDirectory() as folder:
            rows = []
            for name, raw in (('sealed', self.sealed), ('long', plain_eml('s' * 501, 'Team notes.')),
                              ('notes', plain_eml('Notes', 'Team notes for the week.'))):
                (Path(folder) / f'{name}.eml').write_bytes(raw)
                rows.append({**META, 'id': name, 'eml_path': str(Path(folder) / f'{name}.eml')})
            with (blocked_network() as attempts, patch.dict(es._ARC_KEY_CACHE, clear=True),
                  patch.object(app, '_content_pipeline', None)):
                report = serving.evaluate_records(rows, serving.analyze_record, model_sha256='a' * 64, paste=True)
        self.assertEqual(attempts, [])
        integrity = report['input_integrity']
        self.assertEqual((integrity['input_rows'], integrity['evaluated_rows']), (3, 2))
        self.assertEqual(integrity['paste_exclusions'], {'subject_too_long': 1})
        self.assertEqual(integrity['paste_excluded_lines'], {'subject_too_long': [2]})
        self.assertEqual(integrity['input_mode'], 'pasted')


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        deployment_pipeline(self)  # skips where the committed artifact cannot load
        private_key, _txt = make_key()
        raw = message()
        self.sealed = b''.join(dkim.arc_sign(raw, b'arc-test', b'google.com', private_key, b'mx.google.com')) + raw

    def test_pasted_mode_from_the_command_line(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'guard').mkdir()
            (folder / 'guard/sitecustomize.py').write_text(SITECUSTOMIZE)
            lines = []
            for name, raw in (('sealed', self.sealed), ('long', plain_eml('Notes', 'b' * 50_001))):
                (folder / f'{name}.eml').write_bytes(raw)
                lines.append(json.dumps({**META, 'id': name, 'eml_path': str(folder / f'{name}.eml')}))
            (folder / 'input.jsonl').write_text('\n'.join(lines) + '\n')
            log = folder / 'network.log'
            environment = {**os.environ, 'PYTHONPATH': str(folder / 'guard'), 'PHISHGUARD_TEST_NETWORK_LOG': str(log)}
            command = [sys.executable, str(WEBSITE_DIR / 'tools/evaluate_serving_pipeline.py'),
                       '--input', str(folder / 'input.jsonl'), '--paste',
                       '--counterfactual-output', str(folder / 'counterfactual.json')]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=300, env=environment)
            self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
            self.assertFalse(log.exists() and log.read_text().strip())
            report = json.loads(completed.stdout)
            self.assertEqual(report['input_integrity']['paste_exclusions'], {'body_too_long': 1})
            self.assertEqual(report['reproducibility']['configuration']['input_mode'], 'pasted')
            refused = subprocess.run([*command, '--mailbox-setting', 'recorded'], capture_output=True, text=True,
                                     timeout=60, env=environment)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('recorded mailbox', refused.stderr)


if __name__ == '__main__':
    unittest.main()
