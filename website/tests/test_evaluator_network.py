"""Evaluators run without registry lookups or other services, and record the settings they used
(docs/evaluation.md, 2026-10-19). Synthetic inputs only; every outbound attempt is refused."""
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

import app  # noqa: E402
import domain_age  # noqa: E402
import email_structure  # noqa: E402
from config import load_settings  # noqa: E402
from network_guard import SITECUSTOMIZE, blocked_network  # noqa: E402
from test_hidden_text_rules import CALLBACK  # noqa: E402
from test_review_2026_10_01 import deployment_pipeline  # noqa: E402
from tools import evaluate_public_corpus as public  # noqa: E402
from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools.counterfactual_evidence import CounterfactualEvidence  # noqa: E402
from tools.evaluation_data import load_corpus  # noqa: E402
from tools.evidence_attribution import EvidenceAttribution  # noqa: E402

PROFILE = json.loads((WEBSITE_DIR.parent / 'vercel.json').read_text())['env']
# A sender and a link on domains RDAP would look up (.com and .net registries), and a request that alerts.
LINK = 'https://mailfix.example-host.net/login'
SCAM = (f'From: Billing <billing@renewals-desk.com>\r\nTo: user@example.org\r\nSubject: Renewal\r\n'
        f'Content-Type: text/html; charset=utf-8\r\n\r\n<p>{CALLBACK}</p><a href="{LINK}">Open account</a>\r\n').encode()
LUNCH = (b'From: Pat <pat@renewals-desk.com>\r\nTo: user@example.org\r\nSubject: Lunch\r\n\r\n'
         b'The team lunch is on Friday at noon in the main hall.\r\n')


class ExternalServiceTests(unittest.TestCase):
    def test_the_evaluation_environments_turn_the_services_off(self):
        self.assertEqual(PROFILE['RDAP_LOOKUPS'], 'true')  # the deployment keeps its lookups
        for environment in (serving.evaluation_environment(PROFILE), public.public_evaluation_environment(PROFILE)):
            with self.subTest(trusted=environment['TRUSTED_AUTHSERV_IDS']):
                for key in ('RDAP_LOOKUPS', 'SENDER_HISTORY_ENABLED', 'PHISHGUARD_JEV_ENABLED', 'LOCAL_LLM_REVIEW_ENABLED'):
                    self.assertEqual(environment[key], 'false', key)

    def test_the_recorded_services_are_read_from_the_run(self):
        environment = serving.evaluation_environment(PROFILE)
        found = serving.external_services(app, load_settings(environment), environment)
        self.assertEqual(found['external_services'], {
            'rdap_lookups': False, 'sender_history': False, 'jev': False, 'local_llm_review': False,
            'arc_key_lookups': ['google.com'], 'email_verification_mode': 'off'})
        # ARC verification still looks up the keys of known sealers, so the run is not free of network use.
        self.assertIs(found['network_services_enabled'], True)
        with patch.dict(email_structure.ARC_SEALERS, clear=True):
            self.assertIs(serving.external_services(app, load_settings(environment), environment)
                          ['network_services_enabled'], False)
        on = {**environment, 'RDAP_LOOKUPS': 'true'}
        self.assertIs(serving.external_services(app, load_settings(on), on)['external_services']['rdap_lookups'], True)


class InProcessTests(unittest.TestCase):
    """Baseline, identity replay, every counterfactual family and attribution, with the network refused."""

    def run_serving(self, settings):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: [path.unlink() for path in folder.iterdir()])
        rows = []
        for name, raw, label in (('scam', SCAM, 'phishing'), ('lunch', LUNCH, 'legitimate')):
            (folder / f'{name}.eml').write_bytes(raw)
            rows.append({'id': name, 'label': label, 'provider': 'gmail', 'received_at': '2026-09-01',
                         'eml_path': str(folder / f'{name}.eml')})
        attribution, counterfactual = EvidenceAttribution(), CounterfactualEvidence(analyze=serving.analyze_record)
        with (blocked_network() as attempts, patch.dict(domain_age._cache, clear=True),
              patch.object(app, 'SETTINGS', settings), patch.object(app, '_content_pipeline', None)):
            report = serving.evaluate_records(rows, serving.analyze_record, model_sha256='a' * 64,
                                              evidence_observer=attribution.add, counterfactual_observer=counterfactual.add)
        return attempts, counterfactual.snapshot(report), attribution.snapshot(report)

    def test_the_serving_evaluation_makes_no_outbound_call(self):
        environment = serving.evaluation_environment(PROFILE)
        attempts, counterfactual, _attribution = self.run_serving(load_settings(environment))
        self.assertEqual(attempts, [])
        alerts = counterfactual['baseline_outcomes']['phishing_alerted'] + counterfactual['baseline_outcomes']['legitimate_alerted']
        self.assertGreater(alerts, 0)
        self.assertEqual(counterfactual['identity_verified_alerts'], alerts)
        self.assertEqual(len(counterfactual['families']), 12)  # every family but the intent rules
        # Control: with RDAP on, the same inputs reach for the network, and the guard sees it.
        attempts, _counterfactual, _attribution = self.run_serving(load_settings({**environment, 'RDAP_LOOKUPS': 'true'}))
        self.assertTrue(attempts)

    def test_the_public_evaluation_makes_no_outbound_call(self):
        environment = public.public_evaluation_environment(PROFILE)
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / 'records.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in (
                {'id': 'scam', 'source_id': 'fixture', 'label': 'phishing', 'subject': 'Renewal',
                 'body': f'{CALLBACK} Open your account: {LINK}'},
                {'id': 'lunch', 'source_id': 'fixture', 'label': 'legitimate', 'subject': 'Lunch',
                 'body': 'The team lunch is on Friday at noon. Menu: https://menu.renewals-desk.com/friday'})))
            (folder / 'manifest.json').write_text(json.dumps({'schema_version': 1, 'records': 'records.jsonl', 'sources': [
                {'id': 'fixture', 'url': 'https://example.org/fixture', 'revision': 'v1', 'license': 'CC0-1.0',
                 'label_basis': 'Synthetic regression fixture'}]}))
            corpus = load_corpus(folder / 'manifest.json')
        for rdap, expect_attempts in (('false', False), ('true', True)):
            with self.subTest(rdap=rdap):
                attribution, counterfactual = EvidenceAttribution(), CounterfactualEvidence(analyze=serving.analyze_record)
                with (blocked_network() as attempts, patch.dict(domain_age._cache, clear=True),
                      patch.object(app, 'SETTINGS', load_settings({**environment, 'RDAP_LOOKUPS': rdap})),
                      patch.object(app, '_content_pipeline', None)):
                    report = public.evaluate_corpus(corpus, serving.analyze_record, model_sha256='a' * 64,
                                                    evidence_observer=attribution.add,
                                                    counterfactual_observer=counterfactual.add)
                self.assertEqual(bool(attempts), expect_attempts)
                snapshot = counterfactual.snapshot(report)
                alerts = snapshot['baseline_outcomes']['phishing_alerted'] + snapshot['baseline_outcomes']['legitimate_alerted']
                self.assertGreater(alerts, 0)
                self.assertEqual(snapshot['identity_verified_alerts'], alerts)


class CommandLineTests(unittest.TestCase):
    """Both evaluators as commands, with every outbound attempt refused from the process's start."""

    def setUp(self):
        deployment_pipeline(self)  # skips where the committed artifact cannot load
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: [path.unlink() for path in self.folder.rglob('*') if path.is_file()])
        (self.folder / 'guard').mkdir()
        (self.folder / 'guard/sitecustomize.py').write_text(SITECUSTOMIZE)
        self.log = self.folder / 'network.log'

    def run_guarded(self, command):
        environment = {**os.environ, 'PYTHONPATH': str(self.folder / 'guard'),
                       'PHISHGUARD_TEST_NETWORK_LOG': str(self.log)}
        return subprocess.run(command, capture_output=True, text=True, timeout=300, env=environment)

    def attempts(self):
        return self.log.read_text().split() if self.log.exists() else []

    def test_the_guard_sees_an_outbound_call(self):
        completed = self.run_guarded([sys.executable, '-c',
                                      "import socket; socket.create_connection(('example.org', 80), timeout=1)"])
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(self.attempts(), ['create_connection'])

    def test_the_serving_evaluator_makes_no_outbound_call(self):
        lines = []
        for name, raw, label in (('scam', SCAM, 'phishing'), ('lunch', LUNCH, 'legitimate')):
            (self.folder / f'{name}.eml').write_bytes(raw)
            lines.append(json.dumps({'id': name, 'label': label, 'provider': 'gmail', 'received_at': '2026-09-01',
                                     'eml_path': str(self.folder / f'{name}.eml')}))
        (self.folder / 'input.jsonl').write_text('\n'.join(lines) + '\n')
        completed = self.run_guarded(
            [sys.executable, str(WEBSITE_DIR / 'tools/evaluate_serving_pipeline.py'), '--input', str(self.folder / 'input.jsonl'),
             '--counterfactual-output', str(self.folder / 'counterfactual.json'),
             '--attribution-output', str(self.folder / 'attribution.json')])
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        self.assertEqual(self.attempts(), [])
        configuration = json.loads(completed.stdout)['reproducibility']['configuration']
        self.assertIs(configuration['external_services']['rdap_lookups'], False)
        self.assertIs(configuration['network_services_enabled'], True)  # ARC key lookups remain possible
        self.assertGreater(json.loads((self.folder / 'counterfactual.json').read_text())['identity_verified_alerts'], 0)

    def test_the_public_evaluator_makes_no_outbound_call(self):
        (self.folder / 'records.jsonl').write_text(json.dumps(
            {'id': 'scam', 'source_id': 'fixture', 'label': 'phishing', 'subject': 'Renewal',
             'body': f'{CALLBACK} Open your account: {LINK}'}) + '\n')
        (self.folder / 'manifest.json').write_text(json.dumps({'schema_version': 1, 'records': 'records.jsonl', 'sources': [
            {'id': 'fixture', 'url': 'https://example.org/fixture', 'revision': 'v1', 'license': 'CC0-1.0',
             'label_basis': 'Synthetic regression fixture'}]}))
        completed = self.run_guarded(
            [sys.executable, str(WEBSITE_DIR / 'tools/evaluate_public_corpus.py'), '--manifest', str(self.folder / 'manifest.json'),
             '--output', str(self.folder / 'report.json'), '--counterfactual-output', str(self.folder / 'counterfactual.json'),
             '--attribution-output', str(self.folder / 'attribution.json')])
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        self.assertEqual(self.attempts(), [])
        configuration = json.loads((self.folder / 'report.json').read_text())['reproducibility']['configuration']
        self.assertIs(configuration['external_services']['rdap_lookups'], False)
        self.assertIs(configuration['network_services_enabled'], True)


if __name__ == '__main__':
    unittest.main()
