"""Counterfactual diagnostics must remain paired, bounded and aggregate-only."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.counterfactual_evidence import CounterfactualEvidence, FAMILIES, reanalyze_without
from tools.evaluate_serving_pipeline import analyze_record, evaluate_records


class CounterfactualEvidenceTests(unittest.TestCase):
    def report(self, n):
        return {'evaluation_scope': 'local_serving_pipeline',
                'model_artifact_sha256': 'a' * 64,
                'input_integrity': {'evaluated_rows': n, 'evaluated_cohort_sha256': 'b' * 64}}

    def test_paired_alert_transitions_hide_input_and_keep_unknown_separate(self):
        private = 'private-client@example.com https://secret.example/path'
        calls = []

        def replay(row, family):
            calls.append((row['id'], family))
            if family == 'sender_analysis':
                return {'risk_level': 'low' if row['id'] == 'legitimate' else 'unknown'}
            if family == 'content_model':
                raise RuntimeError(private)
            return {'risk_level': 'high'}

        collector = CounterfactualEvidence(replay)
        collector.add({'id': 'legitimate', 'body': private}, 'legitimate', 'alerted', {'risk_level': 'high'})
        collector.add({'id': 'phishing', 'body': private}, 'phishing', 'alerted', {'risk_level': 'high'})
        collector.add({'id': 'untouched', 'body': private}, 'legitimate', 'not_alerted', {'risk_level': 'low'})
        report = collector.snapshot(self.report(3))
        self.assertEqual(len(calls), 2 * len(FAMILIES))
        self.assertEqual(report['baseline_outcomes']['legitimate_not_alerted'], 1)
        legitimate = report['after_removal']['sender_analysis']['legitimate_alerted']
        phishing = report['after_removal']['sender_analysis']['phishing_alerted']
        self.assertEqual(legitimate['not_alerted'], 1)
        self.assertEqual(phishing['undetermined'], 1)
        self.assertEqual(report['after_removal']['content_model']['phishing_alerted']['analysis_failed'], 1)
        self.assertEqual(collector.failure_count, 2)
        self.assertNotIn(private, json.dumps(report))
        self.assertNotIn('untouched', json.dumps(report))

    def test_denominator_identity_and_baseline_decision_are_verified(self):
        collector = CounterfactualEvidence(lambda row, family: {'risk_level': 'low'})
        with self.assertRaises(ValueError):
            collector.add({}, 'legitimate', 'alerted', {'risk_level': 'low'})
        collector.add({}, 'legitimate', 'alerted', {'risk_level': 'high'})
        with self.assertRaises(ValueError):
            collector.snapshot(self.report(2))
        with self.assertRaises(ValueError):
            collector.snapshot({**self.report(1), 'model_artifact_sha256': 'private.example'})

    def test_absent_specific_link_rule_skips_only_that_replay(self):
        called = []

        def replay(row, family):
            called.append(family)
            return {'risk_level': 'low'}

        collector = CounterfactualEvidence(replay)
        collector.add({}, 'legitimate', 'alerted', {
            'risk_level': 'high', 'extra_indicators': [
                {'rule_id': 'link.display_mismatch'}],
        })
        self.assertIn('link_display_mismatch', called)
        self.assertNotIn('link_brand_lookalike', called)
        report = collector.snapshot(self.report(1))
        self.assertEqual(report['after_removal']['link_brand_lookalike']
                         ['legitimate_alerted']['alerted'], 1)

    def test_private_evaluator_observes_only_included_rows(self):
        collector = CounterfactualEvidence(lambda row, family: {'risk_level': 'low'})
        rows = [{'provider': 'gmail', 'received_at': '2026-09-01', 'label': 'legitimate',
                 'subject': 'Note', 'body': 'Private message content'},
                {'provider': 'gmail', 'received_at': '2026-09-01', 'label': 'legitimate',
                 'subject': 'Note', 'body': 'Private message content'}]
        report = evaluate_records(rows, lambda row: {'risk_level': 'high'},
                                  model_sha256='a' * 64,
                                  counterfactual_observer=collector.add)
        summary = collector.snapshot(report)
        self.assertEqual(report['overall']['n'], 1)
        self.assertEqual(summary['baseline_outcomes']['legitimate_alerted'], 1)
        self.assertNotIn('Private message content', json.dumps(summary))

    def test_real_replay_removes_sender_or_link_evidence_independently(self):
        import app
        sender_row = {'eml_path': 'unused', '_eml_bytes':
                      b'From: Alice <notice@paypa1.example>\nSubject: Notes\n\nMeeting notes.'}
        link_row = {'subject': 'Document',
                    'body': '<a href="https://paypa1.example/view">Review document</a>'}
        with patch.object(app, '_content_pipeline', None):
            self.assertEqual(analyze_record(sender_row)['risk_level'], 'high')
            self.assertEqual(reanalyze_without(sender_row, 'sender_analysis')['risk_level'], 'safe')
            self.assertEqual(reanalyze_without(sender_row, 'link_destinations')['risk_level'], 'high')
            self.assertEqual(analyze_record(sender_row)['risk_level'], 'high')
            self.assertEqual(analyze_record(link_row)['risk_level'], 'high')
            self.assertEqual(reanalyze_without(link_row, 'link_destinations')['risk_level'], 'safe')
            self.assertEqual(reanalyze_without(link_row, 'sender_analysis')['risk_level'], 'high')
            self.assertEqual(analyze_record(link_row)['risk_level'], 'high')
        with self.assertRaises(ValueError):
            reanalyze_without({}, 'unrecognized')

    def test_keyword_replay_preserves_rule_registry_shape(self):
        import app
        row = {'subject': 'Action required',
               'body': 'Your account has been suspended. Enter your password immediately.'}
        with patch.object(app, '_content_pipeline', None):
            self.assertEqual(analyze_record(row)['risk_level'], 'high')
            candidate = reanalyze_without(row, 'content_keywords')
            self.assertIn(candidate['risk_level'], {'safe', 'low', 'medium', 'high', 'critical', 'unknown'})

    def test_specific_link_rule_replay_keeps_other_link_rules(self):
        import app
        brand = {'subject': 'Document',
                 'body': '<a href="https://paypa1.example/view">Review document</a>'}
        mismatch = {'subject': 'Document',
                    'body': '<a href="https://other.example/view">https://docs.google.com</a>'}
        with patch.object(app, '_content_pipeline', None):
            self.assertEqual(analyze_record(brand)['risk_level'], 'high')
            self.assertEqual(reanalyze_without(brand, 'link_brand_lookalike')['risk_level'], 'safe')
            self.assertEqual(reanalyze_without(brand, 'link_display_mismatch')['risk_level'], 'high')
            self.assertEqual(analyze_record(mismatch)['risk_level'], 'high')
            self.assertEqual(reanalyze_without(mismatch, 'link_display_mismatch')['risk_level'], 'safe')
            self.assertEqual(reanalyze_without(mismatch, 'link_brand_lookalike')['risk_level'], 'high')


if __name__ == '__main__':
    unittest.main()
