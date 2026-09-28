"""Aggregate diagnostic evidence stays tied to the evaluated cohort and private."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.evidence_attribution import EvidenceAttribution
from tools.evaluate_serving_pipeline import evaluate_records


class EvidenceAttributionTests(unittest.TestCase):
    def test_reports_fixed_signals_without_echoing_message_or_indicator_text(self):
        collector = EvidenceAttribution()
        private = 'secret.example/private-client'
        collector.add('legitimate', 'alerted', {
            'risk_level': 'high', 'fusion_basis': 'model_led', 'ml_status': 'available',
            'risk_floor': 'medium', 'sender_score': 3, 'structure_score': 0,
            'category_results': [{'key': 'urgency', 'matched': [private]},
                                 {'key': private, 'matched': [private]}],
            'extra_indicators': [{'level': 'high', 'msg': private}],
            'remote_image_coverage': {'count': 1},
        })
        report = collector.snapshot({'evaluation_scope': 'public_corpus_local_serving_pipeline',
                                     'model_artifact_sha256': 'a' * 64,
                                     'evaluated_cohort_sha256': 'b' * 64,
                                     'counts': {'evaluated': 1}})
        self.assertEqual(report['outcomes']['legitimate_alerted']['n'], 1)
        signals = report['outcomes']['legitimate_alerted']['signals']
        self.assertEqual(signals['category.urgency'], 1)
        self.assertEqual(signals['category.unrecognized'], 1)
        self.assertEqual(signals['sender_signal'], 1)
        self.assertEqual(signals['remote_image_uninspected'], 1)
        self.assertNotIn(private, json.dumps(report))
        self.assertNotIn('extra_indicators', json.dumps(report))

    def test_observer_tracks_only_included_rows_and_keeps_failures_in_denominator(self):
        collector = EvidenceAttribution()
        rows = [
            {'provider': 'gmail', 'received_at': '2026-08-02', 'label': 'legitimate',
             'subject': 'private subject', 'body': 'private body'},
            {'provider': 'gmail', 'received_at': '2026-08-02', 'label': 'legitimate',
             'subject': 'private subject', 'body': 'private body'},
        ]

        def analyze(row):
            return {'risk_level': 'high', 'fusion_basis': 'model_only',
                    'category_results': [{'key': 'financial'}]}

        # The private evaluator aborts on analysis failures. A successful paired
        # run establishes that duplicate rows cannot inflate attribution counts.
        report = evaluate_records(rows, analyze, model_sha256='a' * 64,
                                  evidence_observer=collector.add)
        diagnosis = collector.snapshot(report)
        self.assertEqual(report['overall']['n'], 1)
        self.assertEqual(diagnosis['outcomes']['legitimate_alerted']['n'], 1)
        self.assertEqual(diagnosis['outcomes']['legitimate_alerted']['signals']['category.financial'], 1)
        self.assertNotIn('private body', json.dumps(diagnosis))

    def test_public_failure_is_counted_as_unattributed_unknown(self):
        collector = EvidenceAttribution()
        collector.add('phishing', 'undetermined', None)
        report = collector.snapshot({'evaluation_scope': 'public_corpus_local_serving_pipeline',
                                     'model_artifact_sha256': 'a' * 64,
                                     'evaluated_cohort_sha256': 'b' * 64,
                                     'counts': {'evaluated': 1}})
        self.assertEqual(report['outcomes']['phishing_undetermined']['n'], 1)
        self.assertEqual(report['outcomes']['phishing_undetermined']['signals'],
                         {'analysis_failed': 1})

    def test_link_rules_have_stable_ids_that_the_diagnostic_counts(self):
        import app
        result = app.analyze_email_content(
            'Shared document',
            '<a href="https://paypa1.example/login">https://paypal.com</a>',
        )
        ids = {item.get('rule_id') for item in result['extra_indicators']}
        self.assertIn('link.display_mismatch', ids)
        self.assertIn('link.brand_lookalike', ids)
        collector = EvidenceAttribution()
        collector.add('legitimate', 'alerted', result)
        signals = collector.snapshot({'evaluation_scope': 'public_corpus_local_serving_pipeline',
            'model_artifact_sha256': 'a' * 64, 'evaluated_cohort_sha256': 'b' * 64,
            'counts': {'evaluated': 1}})['outcomes']['legitimate_alerted']['signals']
        self.assertEqual(signals['rule.link.display_mismatch'], 1)
        self.assertEqual(signals['rule.link.brand_lookalike'], 1)

    def test_report_identity_cannot_echo_arbitrary_scope_or_digest(self):
        collector = EvidenceAttribution()
        collector.add('legitimate', 'not_alerted', {})
        report = {'evaluation_scope': 'public_corpus_local_serving_pipeline',
                  'model_artifact_sha256': 'a' * 64,
                  'evaluated_cohort_sha256': 'b' * 64,
                  'counts': {'evaluated': 1}}
        with self.assertRaises(ValueError):
            collector.snapshot({**report, 'evaluation_scope': 'private.example'})
        with self.assertRaises(ValueError):
            collector.snapshot({**report, 'model_artifact_sha256': 'private.example'})


if __name__ == '__main__':
    unittest.main()
