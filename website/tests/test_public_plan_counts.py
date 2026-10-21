"""The public evaluator's alerts, reviews, passes and Unknown (the 2026-10-20 calibration criteria draft,
section 6.1): the analysis's own review mark, classified as the serving evaluator classifies it. Synthetic
analysis results only."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_public_corpus as public  # noqa: E402
from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools.evaluation_data import load_corpus  # noqa: E402

CLASSES = ('n', 'alerted', 'reviewed', 'passed', 'undetermined')
RATES = tuple(f'{name}_rate{suffix}' for name in CLASSES[1:] for suffix in ('', '_95_ci'))
ATTENTION = ('attention', 'attention_rate', 'attention_rate_95_ci')
DERIVED = ('attention_with_undetermined', 'attention_with_undetermined_rate',
           'attention_with_undetermined_rate_95_ci')
REPORT_KEYS = {'alert_policy', 'by_language', 'by_month', 'by_provider', 'by_source', 'confidence_intervals',
               'counts', 'dataset_sha256', 'evaluated_cohort_sha256', 'evaluation_scope', 'exploratory_only',
               'limitations', 'manifest_sha256', 'model_artifact_sha256', 'overall', 'overlap_check',
               'records_sha256', 'schema_version', 'scoring_sha256', 'sources', 'temporal_isolation',
               'training_independence', 'plan_counts', 'plan_scoring_sha256'}

# (label, risk level, review mark): every order of the classification is covered on both labels.
CASES = [
    ('legitimate', 'medium', True),     # an alert with a review mark is an alert
    ('legitimate', 'unknown', True),    # Unknown with a review mark is Unknown
    ('legitimate', 'low', True),        # reviewed
    ('legitimate', 'safe', True),       # reviewed
    ('legitimate', 'low', False),       # passed
    ('legitimate', 'high', False),      # alerted
    ('phishing', 'high', False),
    ('phishing', 'critical', True),
    ('phishing', 'low', True),
    ('phishing', 'low', False),
    ('phishing', 'unknown', False),
]


def results(cases):
    """One synthetic analysis result per subject."""
    return {f'Synthetic case {index}': {'risk_level': risk, 'model_only_review': review}
            for index, (_label, risk, review) in enumerate(cases)}


class PlanCountTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def public_report(self, cases, analyze):
        (self.root / 'records.jsonl').write_text(''.join(
            json.dumps({'id': f'r{index}', 'source_id': 'fixture', 'label': label,
                        'subject': f'Synthetic case {index}', 'body': 'Synthetic body.'}) + '\n'
            for index, (label, _risk, _review) in enumerate(cases)))
        (self.root / 'manifest.json').write_text(json.dumps({'schema_version': 1, 'records': 'records.jsonl', 'sources': [
            {'id': 'fixture', 'url': 'https://example.org/fixture', 'revision': 'v1', 'license': 'CC0-1.0',
             'label_basis': 'Synthetic regression fixture'}]}))
        return public.evaluate_corpus(load_corpus(self.root / 'manifest.json'), analyze, model_sha256='a' * 64)

    def serving_report(self, cases, analyze):
        rows = [{'label': label, 'provider': 'gmail', 'received_at': '2026-09-01',
                 'subject': f'Synthetic case {index}', 'body': 'Synthetic body.'}
                for index, (label, _risk, _review) in enumerate(cases)]
        return serving.evaluate_records(rows, analyze, model_sha256='a' * 64)

    def assert_same_counts(self, cases):
        answers = results(cases)
        analyze = lambda row: dict(answers[row['subject']])  # noqa: E731
        ours = self.public_report(cases, analyze)['plan_counts']
        theirs = self.serving_report(cases, analyze)['model_only_plan']
        for label in ('legitimate', 'phishing'):
            with self.subTest(label=label):
                keys = CLASSES + RATES + (ATTENTION if label == 'legitimate' else ())
                self.assertEqual({key: ours[label][key] for key in keys}, {key: theirs[label][key] for key in keys})
        return ours

    def test_counts_match_the_serving_evaluator(self):
        ours = self.assert_same_counts(CASES)
        self.assertEqual({key: ours['legitimate'][key] for key in CLASSES},
                         {'n': 6, 'alerted': 2, 'reviewed': 2, 'passed': 1, 'undetermined': 1})
        self.assertEqual({key: ours['phishing'][key] for key in CLASSES},
                         {'n': 5, 'alerted': 2, 'reviewed': 1, 'passed': 1, 'undetermined': 1})
        legitimate = ours['legitimate']
        self.assertEqual(legitimate['attention'], 4)
        self.assertEqual(legitimate['attention_with_undetermined'], 5)
        self.assertEqual(legitimate['attention_with_undetermined_rate'], round(5 / 6, 4))
        self.assertEqual(legitimate['attention_with_undetermined_rate_95_ci'], serving._rate_with_interval(5, 6)[1])

    def test_no_review_and_an_empty_label(self):
        cases = [('legitimate', 'low', False), ('legitimate', 'medium', False), ('legitimate', 'unknown', False)]
        ours = self.assert_same_counts(cases)
        self.assertEqual(ours['legitimate']['reviewed'], 0)
        self.assertEqual(ours['legitimate']['attention'], 1)
        self.assertEqual(ours['legitimate']['attention_with_undetermined'], 2)
        self.assertEqual({key: ours['phishing'][key] for key in CLASSES},
                         {'n': 0, 'alerted': 0, 'reviewed': 0, 'passed': 0, 'undetermined': 0})
        self.assertIsNone(ours['phishing']['reviewed_rate'])

    def test_a_failed_analysis_is_undetermined_and_never_reviewed(self):
        cases = [('legitimate', 'low', True), ('legitimate', 'low', False)]
        answers = results(cases)

        def analyze(row):
            if row['subject'] == 'Synthetic case 0':
                raise RuntimeError('synthetic analysis failure')
            return dict(answers[row['subject']])

        report = self.public_report(cases, analyze)
        self.assertEqual(report['counts']['failures'], 1)  # recorded, so M6 cannot pass
        self.assertEqual({key: report['plan_counts']['legitimate'][key] for key in CLASSES},
                         {'n': 2, 'alerted': 0, 'reviewed': 0, 'passed': 1, 'undetermined': 1})
        # The serving evaluator stops instead; that difference between the two is kept.
        with self.assertRaisesRegex(RuntimeError, 'analysis failed'):
            self.serving_report(cases, analyze)

    def test_new_statistics_are_versioned_apart(self):
        report = self.public_report(CASES, lambda row: dict(results(CASES)[row['subject']]))
        baseline = json.loads((WEBSITE_DIR / 'tests/fixtures/evaluation/baseline.json').read_text())
        self.assertEqual(report['scoring_sha256'], baseline['scoring_sha256'])
        self.assertRegex(report['plan_scoring_sha256'], r'^[0-9a-f]{64}$')
        self.assertNotEqual(report['plan_scoring_sha256'], report['scoring_sha256'])

    def test_reports_hold_counts_only(self):
        report = self.public_report(CASES, lambda row: dict(results(CASES)[row['subject']]))
        self.assertEqual(set(report), REPORT_KEYS)
        self.assertEqual(set(report['plan_counts']), {'legitimate', 'phishing'})
        self.assertEqual(set(report['plan_counts']['legitimate']), set(CLASSES + RATES + ATTENTION + DERIVED))
        self.assertEqual(set(report['plan_counts']['phishing']), set(CLASSES + RATES))
        self.assertNotIn('Synthetic case', json.dumps(report))


if __name__ == '__main__':
    unittest.main()
