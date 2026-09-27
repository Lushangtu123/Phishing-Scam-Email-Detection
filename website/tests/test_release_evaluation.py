"""Synthetic data tests the release contract, never supplies release evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.evaluate_serving_pipeline import evaluate_records
from tools.release_evaluation import ATTESTATIONS, compare_release


def reports_and_review(size=50, *, missed_threat=False):
    rows = [dict(provider=provider, language=language, received_at='2026-09-01',
                 label=label, body=f'Synthetic {provider} {language} {label} {index}')
            for provider in ('gmail', 'outlook') for language in ('en', 'zh')
            for label in ('phishing', 'legitimate') for index in range(size)]
    baseline = evaluate_records(rows, lambda row: {
        'risk_level': 'high' if row['label'] == 'phishing' else 'safe',
        'analysis_complete': True, 'ml_status': 'available'}, model_sha256='a' * 64,
        configuration={'trusted_authserv_ids': [], 'observe_sender_history': False,
                       'verification_mode': 'off', 'content_model_enabled': True,
                       'auxiliary_enabled': False})
    baseline['reproducibility']['source_sha256'] = 'b' * 64
    candidate = copy.deepcopy(baseline)
    if missed_threat:
        candidate = evaluate_records(rows, lambda row: {
            'risk_level': ('safe' if row['body'] == 'Synthetic gmail en phishing 0' else
                           'high' if row['label'] == 'phishing' else 'safe'),
            'analysis_complete': True, 'ml_status': 'available'}, model_sha256='c' * 64,
            configuration=baseline['reproducibility']['configuration'])
    candidate['model_artifact_sha256'] = 'c' * 64
    candidate['reproducibility']['source_sha256'] = 'd' * 64
    review = {
        'schema_version': 1,
        'dataset_sha256': baseline['input_integrity']['dataset_sha256'],
        'evaluated_cohort_sha256': baseline['input_integrity']['evaluated_cohort_sha256'],
        'baseline': {'model_artifact_sha256': 'a' * 64, 'source_sha256': 'b' * 64},
        'candidate': {'model_artifact_sha256': 'c' * 64, 'source_sha256': 'd' * 64},
        'minimum_per_class_per_provider_language': 50,
        'independent_reviewer': 'reviewer-b', 'cohort_preparer': 'reviewer-a',
        'reviewed_at': '2026-09-05', 'training_cutoff': '2026-08-31',
        'cohort_frozen_at': '2026-09-02', 'candidate_development_started_at': '2026-09-03',
        'evidence_reference': 'private-audit-2026-09',
        'attestations': {key: True for key in ATTESTATIONS},
    }
    return baseline, candidate, review


class ReleaseEvaluationTests(unittest.TestCase):
    def test_reviewed_coverage_contract_accepts_distinct_code_and_model(self):
        result = compare_release(*reports_and_review())
        self.assertTrue(result['passed'], result['errors'])
        self.assertEqual(result['release_review']['minimum_per_class_per_provider_language'], 50)
        self.assertIn('self-attested', result['release_review']['limitation'])

    def test_small_cohort_and_higher_declared_minimum_fail(self):
        self.assertFalse(compare_release(*reports_and_review(49))['passed'])
        a, b, review = reports_and_review()
        review['minimum_per_class_per_provider_language'] = 51
        self.assertFalse(compare_release(a, b, review)['passed'])
        for invalid in (0, 49, True, '50'):
            review['minimum_per_class_per_provider_language'] = invalid
            with self.subTest(invalid=invalid):
                self.assertFalse(compare_release(a, b, review)['passed'])

    def test_all_human_attestations_required_and_true(self):
        for field in ATTESTATIONS:
            a, b, review = reports_and_review()
            review['attestations'][field] = False
            with self.subTest(field=field):
                self.assertFalse(compare_release(a, b, review)['passed'])
        a, b, review = reports_and_review()
        review['independent_reviewer'] = review['cohort_preparer']
        self.assertFalse(compare_release(a, b, review)['passed'])

    def test_missing_review_public_controls_and_unlabeled_cohort_fail(self):
        a, b, review = reports_and_review()
        for invalid in (None, {}, [], True):
            self.assertFalse(compare_release(a, b, invalid)['passed'])
        a['evaluation_scope'] = b['evaluation_scope'] = 'public_corpus_local_serving_pipeline'
        self.assertFalse(compare_release(a, b, review)['passed'])
        a, b, review = reports_and_review()
        for report in (a, b):
            report['by_provider_language']['gmail']['unlabeled'] = report['by_provider_language']['gmail'].pop('zh')
        self.assertFalse(compare_release(a, b, review)['passed'])

    def test_review_cannot_be_reused_for_other_dataset_code_or_model(self):
        for field in ('dataset_sha256', 'evaluated_cohort_sha256'):
            a, b, review = reports_and_review()
            review[field] = 'f' * 64
            with self.subTest(field=field):
                self.assertFalse(compare_release(a, b, review)['passed'])
        for role in ('baseline', 'candidate'):
            for field in ('model_artifact_sha256', 'source_sha256'):
                a, b, review = reports_and_review()
                review[role][field] = 'f' * 64
                with self.subTest(role=role, field=field):
                    self.assertFalse(compare_release(a, b, review)['passed'])

    def test_temporal_and_holdout_declarations_fail_closed(self):
        for field, value in (('training_cutoff', '2026-09-01'),
                             ('cohort_frozen_at', '2026-09-04'),
                             ('reviewed_at', '2026-08-01'),
                             ('reviewed_at', '2026-09-99'),
                             ('evidence_reference', '')):
            a, b, review = reports_and_review()
            review[field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(compare_release(a, b, review)['passed'])

    def test_release_mode_retains_exact_count_regression_gate(self):
        result = compare_release(*reports_and_review(missed_threat=True))
        self.assertFalse(result['passed'])
        self.assertIn('Regression overall.phishing.alerted', result['errors'])
        self.assertIn('Regression by_provider_language.gmail.en.phishing.alerted', result['errors'])
        a, b, review = reports_and_review()
        b['reproducibility']['configuration']['content_model_enabled'] = False
        self.assertFalse(compare_release(a, b, review)['passed'])

    def test_cli_opt_in_missing_review_fails_and_does_not_echo_evidence(self):
        a, b, review = reports_and_review()
        review['evidence_reference'] = 'private-evidence-do-not-echo'
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ('baseline.json', 'candidate.json', 'review.json')]
            for path, data in zip(paths, (a, b, review)):
                path.write_text(json.dumps(data))
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/compare_evaluations.py'),
                       '--baseline', str(paths[0]), '--candidate', str(paths[1]), '--release-review', str(paths[2])]
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)['passed'])
            self.assertNotIn('private-evidence', completed.stdout)
            for path in paths:
                original = path.read_bytes()
                completed = subprocess.run(command + ['--output', str(path)], capture_output=True, text=True)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(path.read_bytes(), original)
            paths[2].write_text('null')
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertFalse(json.loads(completed.stdout)['passed'])
            paths[2].unlink()
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn(str(paths[2]), completed.stderr)


if __name__ == '__main__':
    unittest.main()
