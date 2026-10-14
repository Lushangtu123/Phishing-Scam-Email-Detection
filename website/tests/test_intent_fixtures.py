"""The synthetic intent-rule fixtures: development and regression data for the 2026-10-13
evaluation plan, never holdout data. Their shape, coverage and domains are checked here; the
rules they are for do not exist yet (tools/intent_fixture_baseline.py counts today's results)."""
from collections import Counter, defaultdict
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools.intent_fixture_baseline import baseline, load_fixtures  # noqa: E402

BEHAVIOURS = {'credential_handover', 'payment_redirection'}
CONTROL_TYPES = {'password_reset', 'otp_notice', 'supplier_change_known_channel', 'payroll_confirmation',
                 'unchanged_invoice', 'quoted_warning'}
# The plan's required tests, in each language.
REQUIRED_SCENARIOS = {'cross_sentence', 'link_other_paragraph', 'scoped_negation', 'quoted_warning'}
INSTRUCTED_QUOTES = {'quoted_instruction', 'forwarded_instruction'}
# Reserved names only (RFC 2606, RFC 6761), and the #60 reproduction's consumer address.
RESERVED_HOST = re.compile(r'(?:^|\.)(?:example|test)$|(?:^|\.)example\.(?:com|net|org)$')


class IntentFixtureTests(unittest.TestCase):
    rows = load_fixtures()

    def test_every_row_is_well_formed_and_unique(self):
        self.assertEqual(len({row['id'] for row in self.rows}), len(self.rows))
        for row in self.rows:
            with self.subTest(row=row['id']):
                self.assertIn(row['set'], {'development', 'regression'})
                self.assertIn(row['language'], {'en', 'zh'})
                self.assertIn(row['behaviour'], BEHAVIOURS)
                self.assertIn(row['kind'], {'positive', 'control'})
                self.assertEqual('control_type' in row, row['kind'] == 'control')
                if row['kind'] == 'control':
                    self.assertIn(row['control_type'], CONTROL_TYPES)
                self.assertTrue(row['subject'].strip() and row['body'].strip() and row['from'].strip())
                self.assertIsInstance(row['scenarios'], list)

    def test_a_family_has_one_set_language_behaviour_and_kind(self):
        families = defaultdict(set)
        for row in self.rows:
            families[row['family']].add((row['set'], row['language'], row['behaviour'], row['kind']))
        self.assertEqual({family: values for family, values in families.items() if len(values) > 1}, {})

    def test_the_required_scenarios_are_covered_in_both_languages(self):
        development = [row for row in self.rows if row['set'] == 'development']
        for language in ('en', 'zh'):
            scenarios = {scenario for row in development if row['language'] == language for scenario in row['scenarios']}
            with self.subTest(language=language):
                self.assertLessEqual(REQUIRED_SCENARIOS, scenarios)
                self.assertTrue(scenarios & INSTRUCTED_QUOTES)
                for behaviour in BEHAVIOURS:
                    kinds = Counter(row['kind'] for row in development
                                    if row['language'] == language and row['behaviour'] == behaviour)
                    self.assertGreater(kinds['positive'], 0, behaviour)
                    self.assertGreater(kinds['control'], 0, behaviour)

    def test_quoted_warnings_are_controls_and_quoted_instructions_are_positives(self):
        for row in self.rows:
            if 'quoted_warning' in row['scenarios']:
                self.assertEqual(row['kind'], 'control', row['id'])
            if set(row['scenarios']) & INSTRUCTED_QUOTES:
                self.assertEqual(row['kind'], 'positive', row['id'])

    def test_only_reserved_domains_appear(self):
        for row in self.rows:
            hosts = {urlsplit(url).hostname for url in re.findall(r'https?://[^\s)>]+', row['body'])}
            hosts.add(row['from'].rsplit('@', 1)[1].rstrip('>').lower())
            for host in hosts:
                with self.subTest(row=row['id'], host=host):
                    self.assertTrue(RESERVED_HOST.search(host) or (row['id'] == 'reg-pr60-six-digit'
                                                                  and host == 'gmail.com'))

    def test_the_baseline_counts_by_group(self):
        rows = [row for row in self.rows if row['id'] in {'cred-en-01', 'cred-en-02', 'ctl-en-05'}]
        answers = {'cred-en-01': {'risk_level': 'high', 'fusion_basis': 'corroborated',
                                  'extra_indicators': [{'code': 'content.sensitive_request.password_pin'}]},
                   'cred-en-02': {'risk_level': 'medium', 'fusion_basis': 'model_only', 'extra_indicators': []},
                   'ctl-en-05': {'risk_level': 'unknown', 'extra_indicators': []}}
        report = baseline(rows, lambda row: answers[row['id']])
        self.assertEqual(report['development/en/credential_handover/positive'],
                         {'rows': 2, 'alerts': 2, 'unknown': 0, 'sensitive_request': 1, 'model_only': 1})
        self.assertEqual(report['development/en/credential_handover/control']['unknown'], 1)


if __name__ == '__main__':
    unittest.main()
