"""The serving evaluator's intent-rule switch and report (Part 2 of the 2026-10-13 evaluation plan).
Both rules are implemented, off by default; these tests use synthetic results and a stand-in for the
analysis (test_intent_rules_wiring.py runs the rules themselves)."""
import contextvars
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import intent_rules  # noqa: E402
from tools import evaluate_serving_pipeline as evaluator  # noqa: E402

CREDENTIAL, PAYMENT = evaluator.INTENT_RULE_CODES['credential'], evaluator.INTENT_RULE_CODES['payment']
BASE = {'trusted_authserv_ids': [], 'observe_sender_history': False, 'verification_mode': 'off',
        'content_model_enabled': True, 'auxiliary_enabled': False}


def row(label, n, language='en', **tags):
    return {'label': label, 'provider': 'gmail', 'received_at': '2026-10-20', 'language': language,
            'subject': 'Synthetic', 'body': f'Synthetic {label} {language} {n}', **tags}


def result(level, *codes, without=None):
    found = {'risk_level': level, 'extra_indicators': [{'code': code} for code in codes]}
    if without:
        found['_evaluation'] = {'without_intent_rules': {'risk_level': without}}
    return found


class IntentRuleReportTests(unittest.TestCase):
    def evaluate(self, rows, results, rules='none'):
        answers = iter(results)
        return evaluator.evaluate_records(rows, lambda _row: next(answers), model_sha256='a' * 64,
                                          configuration={**BASE, 'intent_rules': rules})['intent_rules']

    def test_matches_new_alerts_and_added_detections_per_rule_and_language(self):
        rows = [row('legitimate', 1, control_type='password_reset'),
                row('legitimate', 2, control_type='unchanged_invoice'),
                row('legitimate', 3),
                row('legitimate', 4),
                row('phishing', 5, behaviour='credential_handover'),
                row('phishing', 6, behaviour=['credential_handover', 'payment_redirection']),
                row('phishing', 7, behaviour='payment_redirection'),
                row('phishing', 8, language='zh', behaviour='credential_handover')]
        results = [result('medium', CREDENTIAL, without='low'),       # a control matched, and raised
                   result('low', PAYMENT, without='low'),             # matched, not raised
                   result('high', CREDENTIAL, PAYMENT, without='low'),  # both rules: one new alert
                   result('medium', without='medium'),                # already an alert
                   result('high', CREDENTIAL, without='low'),         # added
                   result('high', CREDENTIAL, PAYMENT, without='high'),
                   result('unknown', without='unknown'),
                   result('medium', CREDENTIAL, without='unknown')]   # Unknown without the rule: added
        report = self.evaluate(rows, results, rules='both')
        self.assertEqual((report['enabled'], report['paired_without_rules']), (['credential', 'payment'], True))
        credential, payment = report['by_rule']['credential']['en'], report['by_rule']['payment']['en']
        self.assertEqual({key: credential['legitimate'][key] for key in ('n', 'matched', 'new_alerts')},
                         {'n': 4, 'matched': 2, 'new_alerts': 2})
        self.assertEqual({key: payment['legitimate'][key] for key in ('n', 'matched', 'new_alerts')},
                         {'n': 4, 'matched': 2, 'new_alerts': 1})
        self.assertEqual(credential['controls']['password_reset'], {'n': 1, 'matched': 1})
        self.assertEqual(payment['controls']['unchanged_invoice'], {'n': 1, 'matched': 1})
        self.assertEqual({key: credential['behaviour_phishing'][key] for key in ('n', 'alerted', 'added')},
                         {'n': 2, 'alerted': 2, 'added': 1})
        self.assertEqual({key: payment['behaviour_phishing'][key] for key in ('n', 'alerted', 'added')},
                         {'n': 2, 'alerted': 1, 'added': 0})
        self.assertEqual(report['by_rule']['credential']['zh']['behaviour_phishing']['added'], 1)
        # A message raised by both rules counts once for the configuration.
        self.assertEqual((report['combined']['en']['legitimate_new_alerts'], report['combined']['en']['phishing_added']),
                         (2, 1))

    def test_with_no_rule_on_matches_are_counted_and_additions_are_not_measured(self):
        report = self.evaluate([row('legitimate', 1), row('phishing', 2, behaviour='payment_redirection')],
                               [result('low'), result('medium')])
        self.assertEqual((report['enabled'], report['paired_without_rules']), ([], False))
        payment = report['by_rule']['payment']['en']
        self.assertEqual((payment['legitimate']['matched'], payment['legitimate']['new_alerts']), (0, None))
        self.assertEqual((payment['behaviour_phishing']['alerted'], payment['behaviour_phishing']['added']), (1, None))
        self.assertIsNone(report['combined']['en']['legitimate_new_alerts'])

    def test_tags_are_validated_and_join_the_duplicate_check(self):
        for bad in (row('phishing', 1, behaviour='invoice_fraud'), row('phishing', 1, behaviour=[]),
                    row('phishing', 1, control_type='password_reset'),
                    row('legitimate', 1, control_type='newsletter')):
            with self.assertRaises(ValueError):
                evaluator._validated_record(bad, 1)
        same = [row('phishing', 1, behaviour='credential_handover'), row('phishing', 1, behaviour='payment_redirection')]
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            self.evaluate(same, [result('high'), result('high')])
        # Untagged rows keep their digests: main (b29cab5) gives this value.
        plain = evaluator.evaluate_records([row('phishing', 1), row('legitimate', 2)], lambda _row: result('low'),
                                           model_sha256='a' * 64)
        self.assertEqual(plain['input_integrity']['dataset_sha256'],
                         '5e9a3ccfb42f56da535faf2a4c4bc1a9f386014e7877b76b6802c27f0c714a81')

    def test_the_configuration_records_the_rules(self):
        self.assertEqual(evaluator._validated_configuration({**BASE, 'intent_rules': 'both'})['intent_rules'], 'both')
        with self.assertRaises(ValueError):
            evaluator._validated_configuration({**BASE, 'intent_rules': 'all'})


class IntentRuleSwitchTests(unittest.TestCase):
    def test_both_rules_are_implemented_behind_the_rules_own_switch(self):
        self.assertEqual(app.IMPLEMENTED_INTENT_RULES, frozenset({'credential', 'payment'}))
        # One context variable: the evaluator's switch is what the rules read.
        self.assertIs(app.INTENT_RULES, intent_rules.ENABLED)
        self.assertEqual(app.INTENT_RULES.get(), frozenset())
        self.assertEqual(evaluator.INTENT_RULE_CODES, intent_rules.CODES)

    def test_rules_a_build_lacks_are_refused_before_any_analysis(self):
        with patch.object(app, 'IMPLEMENTED_INTENT_RULES', frozenset()), \
                patch.object(app, '_analyze_content') as analyze:
            with self.assertRaisesRegex(ValueError, 'does not implement'):
                evaluator.analyze_record(row('phishing', 1), intent_rules=('credential',))
            analyze.assert_not_called()
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'rows.jsonl'
                source.write_text(json.dumps(row('phishing', 1)) + '\n')
                with patch.object(sys, 'argv', ['evaluate', '--input', str(source), '--intent-rules', 'payment']), \
                        patch.object(evaluator, 'evaluate_records') as evaluate:
                    with self.assertRaisesRegex(SystemExit, 'does not implement'):
                        evaluator.main()
                evaluate.assert_not_called()

    def test_an_implemented_rule_runs_with_its_switch_and_once_without(self):
        switch = contextvars.ContextVar('intent_rules', default=frozenset())
        seen = []

        class Response:
            def __init__(self, level):
                self.body = json.dumps({'risk_level': level, 'extra_indicators': []})

        async def analyze_content(request, structure, observe_sender_history):
            seen.append(switch.get())
            return Response('medium' if switch.get() else 'low')
        with patch.object(app, 'INTENT_RULES', switch), patch.object(app, '_analyze_content', analyze_content):
            found = evaluator.analyze_record(row('phishing', 1), intent_rules=('credential',))
            self.assertEqual(evaluator.analyze_record(row('phishing', 2)), {'risk_level': 'low', 'extra_indicators': []})
        self.assertEqual(seen, [frozenset({'credential'}), frozenset(), frozenset()])
        self.assertEqual(found['risk_level'], 'medium')
        self.assertEqual(found['_evaluation'], {'without_intent_rules': {'risk_level': 'low'}})
        self.assertEqual(switch.get(), frozenset())


if __name__ == '__main__':
    unittest.main()
