"""Evaluation-only options for model-only alerts on original messages, and the evaluator's
plan measures (docs/superpowers/specs/2026-10-13-model-only-and-intent-rules-evaluation-plan.md)."""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import email_structure as es  # noqa: E402
from tools import evaluate_serving_pipeline as evaluator  # noqa: E402

PROFILE = json.loads((WEBSITE_DIR.parent / 'vercel.json').read_text())['env']
NOTE = 'Low Risk — Text Model Signal Only'


def note_result(**extra):
    return {'risk_level': 'low', 'risk_label': NOTE, 'fusion_basis': 'model_only',
            'ml_phishing_probability': 91.5, 'combined_phishing_score': 29.0, **extra}


def relabel(result, structure, *, option, raw_message=True):
    token = app.MODEL_ONLY_OPTION.set(option)
    try:
        app._apply_model_only_option(result, structure, raw_message)
    finally:
        app.MODEL_ONLY_OPTION.reset(token)
    return result


class ModelOnlyOptionTests(unittest.TestCase):
    unauthenticated = {'authenticated_sender': None, 'verified_official_sender': None}

    def test_the_served_option_is_a_and_changes_nothing(self):
        self.assertEqual(app.MODEL_ONLY_OPTION.get(), 'A')
        self.assertEqual(relabel(note_result(), self.unauthenticated, option='A'), note_result())

    def test_b_raises_an_unauthenticated_note_to_medium(self):
        result = relabel(note_result(), self.unauthenticated, option='B')
        self.assertEqual((result['risk_level'], result['risk_label']), ('medium', 'Medium Risk — Model Signal Needs Review'))
        self.assertEqual(result['combined_phishing_score'], 91.5)

    def test_b_keeps_an_authenticated_or_official_sender_at_the_note(self):
        for structure in ({'authenticated_sender': {'domain': 'shop.example'}, 'verified_official_sender': None},
                          {'authenticated_sender': None, 'verified_official_sender': {'organization': 'Shop'}}):
            self.assertEqual(relabel(note_result(), structure, option='B'), note_result())

    def test_c_marks_the_note_for_review_without_raising_it(self):
        result = relabel(note_result(), {'authenticated_sender': {'domain': 'shop.example'}}, option='C')
        self.assertEqual(result['risk_level'], 'low')
        self.assertIs(result['model_only_review'], True)
        self.assertIn('Needs Review', result['risk_label'])

    def test_abstentions_verified_senders_and_pasted_text_are_left_alone(self):
        for option in ('B', 'C'):
            unknown = note_result(risk_level='unknown', risk_label='Analysis Incomplete — Risk Undetermined')
            self.assertEqual(relabel(dict(unknown), self.unauthenticated, option=option), unknown)
            verified = note_result(risk_label='Low Risk — Verified Official Sender')
            self.assertEqual(relabel(dict(verified), self.unauthenticated, option=option), verified)
            self.assertEqual(relabel(note_result(), self.unauthenticated, option=option, raw_message=False), note_result())
            other = note_result(fusion_basis='model_led')
            self.assertEqual(relabel(dict(other), self.unauthenticated, option=option), other)


class ModelOnlyOptionPipelineTests(unittest.TestCase):
    """The full pipeline, with the served model, on a message A shows as the model-only note."""

    @classmethod
    def setUpClass(cls):
        cls.pipeline = app.load_content_pipeline_artifact(
            WEBSITE_DIR.parent / PROFILE['CONTENT_MODEL_ARTIFACT'], PROFILE['CONTENT_MODEL_ARTIFACT_SHA256'])

    def analyze(self, option, raw):
        token = app.MODEL_ONLY_OPTION.set(option)
        try:
            with patch.object(app, '_content_pipeline', self.pipeline):
                return json.loads(asyncio.run(app._analyze_content(
                    app.ContentRequest(), es.analyze_raw_email(raw), observe_sender_history=False)).body)
        finally:
            app.MODEL_ONLY_OPTION.reset(token)

    def test_options_on_a_model_only_original_message(self):
        raw = (b'From: Alex Chen <alex.chen@gmail.com>\r\nTo: reader@example.org\r\nSubject: Complete verification\r\n'
               b'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
               b'Your verification code is 482913. It expires in 10 minutes. Never share this code with anyone.\r\n')
        current = self.analyze('A', raw)
        self.assertEqual((current['fusion_basis'], current['risk_label']), ('model_only', NOTE))
        b, c = self.analyze('B', raw), self.analyze('C', raw)
        self.assertEqual(b['risk_level'], 'medium')
        self.assertEqual((c['risk_level'], c['model_only_review']), ('low', True))
        # Everything but the label is the same run.
        for result in (b, c):
            self.assertEqual(result['ml_phishing_probability'], current['ml_phishing_probability'])
            self.assertEqual(result['total_score'], current['total_score'])


def outcome_row(label, **extra):
    return {'label': label, 'provider': 'gmail', 'received_at': '2026-10-20', 'language': 'en',
            'subject': 'Synthetic', 'body': f'Synthetic {label} {extra}'}


class PlanEvaluatorTests(unittest.TestCase):
    def evaluate(self, rows, results, **kwargs):
        answers = iter(results)
        return evaluator.evaluate_records(rows, lambda _row: next(answers), model_sha256='a' * 64, **kwargs)

    def test_alerts_reviews_false_passes_and_unknown_are_kept_apart(self):
        rows = [outcome_row('phishing', n=n) for n in range(5)] + [outcome_row('legitimate', n=n) for n in range(4)]
        results = [{'risk_level': 'high'}, {'risk_level': 'low', 'model_only_review': True},
                   {'risk_level': 'low'}, {'risk_level': 'unknown'},
                   {'risk_level': 'low', 'model_only_review': True, 'fusion_basis': 'model_only',
                    '_evaluation': {'authenticated': True, 'official': False}},
                   {'risk_level': 'medium'}, {'risk_level': 'low', 'model_only_review': True},
                   {'risk_level': 'safe'}, {'risk_level': 'unknown'}]
        plan = self.evaluate(rows, results)['model_only_plan']
        self.assertEqual({key: plan['phishing'][key] for key in ('alerted', 'reviewed', 'passed', 'undetermined')},
                         {'alerted': 1, 'reviewed': 2, 'passed': 1, 'undetermined': 1})
        self.assertEqual((plan['legitimate']['alerted'], plan['legitimate']['reviewed'], plan['legitimate']['attention']),
                         (1, 1, 2))
        self.assertEqual(plan['authenticated_phishing']['n'], 1)
        self.assertEqual(plan['authenticated_phishing_decisive']['reviewed'], 1)
        self.assertEqual(plan['authentication_known'], 1)

    def test_holdout_rows_are_refused_before_any_analysis(self):
        rows = [outcome_row('phishing'), {**outcome_row('legitimate'), 'cohort_role': 'holdout'}]
        analyzed = []

        def analyze(row):
            analyzed.append(row)
            return {'risk_level': 'low'}
        with self.assertRaisesRegex(ValueError, 'sealed'):
            evaluator.evaluate_records(rows, analyze, model_sha256='a' * 64)
        self.assertEqual(len(analyzed), 1)
        report = evaluator.evaluate_records(rows, analyze, model_sha256='a' * 64, holdout_authorized=True)
        self.assertEqual(report['input_integrity']['evaluated_rows'], 2)

    def test_the_recorded_mailbox_setting_reads_eml_as_downloaded_from_its_provider(self):
        calls = []

        def parse(raw, **kwargs):
            calls.append(kwargs.get('mailbox_provider'))
            return es.analyze_raw_email(raw, trusted_authserv_ids=kwargs.get('trusted_authserv_ids'))
        raw = b'From: a@example.com\r\nTo: b@example.org\r\nSubject: Hi\r\n\r\nHello there.\r\n'
        row = {**outcome_row('legitimate'), 'eml_path': '/synthetic.eml', '_eml_bytes': raw}
        del row['subject'], row['body']
        with patch.object(app, 'analyze_raw_email', parse), patch.object(app, '_content_pipeline', None):
            for setting in ('none', 'recorded'):
                result = evaluator.analyze_record(row, mailbox_setting=setting)
                self.assertEqual(result['_evaluation'], {'authenticated': False, 'official': False})
        self.assertEqual(calls, [None, 'gmail'])
        with self.assertRaisesRegex(ValueError, 'needs .eml'):
            evaluator.analyze_record(outcome_row('legitimate'), mailbox_setting='recorded')

    def test_configurations_with_and_without_the_plan_settings_validate(self):
        base = {'trusted_authserv_ids': [], 'observe_sender_history': False, 'verification_mode': 'off',
                'content_model_enabled': True, 'auxiliary_enabled': False}
        self.assertEqual(evaluator._validated_configuration(base), base)
        planned = {**base, 'model_only_option': 'C', 'mailbox_setting': 'recorded'}
        self.assertEqual(evaluator._validated_configuration(planned), planned)
        for bad in ({**base, 'model_only_option': 'D'}, {**base, 'mailbox_setting': 'all'}, {**base, 'extra': 1}):
            with self.assertRaises(ValueError):
                evaluator._validated_configuration(bad)

    def test_a_holdout_needs_a_commit_where_the_plan_is_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / evaluator.PLAN_PATH
            plan.parent.mkdir(parents=True)

            def commit(text):
                plan.write_text(text)
                subprocess.run(['git', 'add', '-A'], cwd=root, check=True, capture_output=True)
                subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.org', 'commit', '-qm', 'plan'],
                               cwd=root, check=True, capture_output=True)
                return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, check=True,
                                      capture_output=True, text=True).stdout.strip()
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True, capture_output=True)
            pending = commit('D12: to be determined and not yet assigned. The plan as a whole is not frozen.\n')
            frozen = commit('D12: assigned to a teacher, reviewer-01.\n')
            with patch.object(evaluator, 'PROJECT_ROOT', root):
                with self.assertRaisesRegex(SystemExit, 'not frozen'):
                    evaluator._frozen_plan(pending)
                self.assertEqual(evaluator._frozen_plan(frozen)['commit'], frozen)
                with self.assertRaises(SystemExit):
                    evaluator._frozen_plan('not-a-commit')


if __name__ == '__main__':
    unittest.main()
