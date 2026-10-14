"""The intent rules wired into the content analysis, off by default: an experimental evaluation
wiring for Part 2 of the 2026-10-13 evaluation plan. The messages are the committed synthetic
fixtures (#64); these tests add no message text of their own."""
import asyncio
import json
import os
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import intent_rules  # noqa: E402
from tools import evaluate_serving_pipeline as evaluator  # noqa: E402
from tools.intent_fixture_baseline import load_fixtures  # noqa: E402

FIXTURES = {row['id']: row for row in load_fixtures()}
CODES = intent_rules.CODES
BOTH = frozenset({'credential', 'payment'})


def analyze(row, rules=None, body=None):
    token = app.INTENT_RULES.set(frozenset(rules)) if rules is not None else None
    try:
        return app.analyze_email_content(row['subject'], row['body'] if body is None else body)
    finally:
        if token is not None:
            app.INTENT_RULES.reset(token)


def intent_codes(result):
    return [item['code'] for item in result['extra_indicators'] if str(item.get('code', '')).startswith('content.intent.')]


class Response:
    def __init__(self, level):
        self.body = json.dumps({'risk_level': level, 'extra_indicators': []})


def text_row():
    return {'label': 'phishing', 'provider': 'gmail', 'received_at': '2026-10-20', 'language': 'en',
            'subject': 'Synthetic', 'body': 'Synthetic body'}


class OffByDefaultTests(unittest.TestCase):
    def test_no_fixture_gets_an_intent_finding_while_the_switch_is_empty(self):
        self.assertEqual(app.INTENT_RULES.get(), frozenset())
        for row in FIXTURES.values():
            with self.subTest(row=row['id']):
                self.assertEqual(intent_codes(analyze(row)), [])

    def test_no_request_setting_or_environment_variable_turns_a_rule_on(self):
        self.assertFalse(any('intent' in field for field in app.ContentRequest.model_fields))
        self.assertNotIn('INTENT_RULES.set(', (WEBSITE_DIR / 'app.py').read_text(encoding='utf-8'))
        rules_source = (WEBSITE_DIR / 'intent_rules.py').read_text(encoding='utf-8')
        self.assertFalse(any(word in rules_source for word in ('os.environ', 'getenv', '.set(')))
        self.assertNotIn('INTENT', (WEBSITE_DIR / 'config.py').read_text(encoding='utf-8'))
        from fastapi.testclient import TestClient
        row = FIXTURES['cred-en-01']
        with patch.object(app, '_content_pipeline', None), \
                patch.dict(os.environ, {'INTENT_RULES': 'credential,payment', 'PHISHGUARD_INTENT_RULES': 'both'}):
            response = TestClient(app.app).post('/api/analyze-content?intent_rules=both',
                                                json={'subject': row['subject'], 'body': row['body'],
                                                      'intent_rules': ['credential', 'payment']})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('content.intent.', response.text)


class SwitchTests(unittest.TestCase):
    def test_a_rule_adds_three_points_and_a_medium_floor_once(self):
        for fixture, rule in (('cred-en-01', 'credential'), ('pay-en-01', 'payment')):
            with self.subTest(fixture=fixture):
                row = FIXTURES[fixture]
                off, on = analyze(row), analyze(row, BOTH)
                self.assertEqual(intent_codes(on), [CODES[rule]])
                self.assertEqual(on['total_score'], off['total_score'] + 3)
                self.assertIn(on['risk_floor'], {'medium', 'high'})
                self.assertIn(on['risk_level'], {'medium', 'high', 'critical'})
                # Nothing else changes: the same indicators, with the rule's finding added.
                added = [item for item in on['extra_indicators'] if item not in off['extra_indicators']]
                self.assertEqual([item['code'] for item in added], [CODES[rule]])
                self.assertEqual(added[0]['level'], 'medium')
                # The other rule alone finds nothing here.
                self.assertEqual(intent_codes(analyze(row, BOTH - {rule})), [])

    def test_text_that_styles_hide_is_not_read(self):
        # The documented coverage limit: the rules read the renderings and labelled links the
        # lures read, not hidden text.
        row = FIXTURES['cred-en-01']
        hidden = f'<div style="display:none">{row["body"]}</div><p>Hello.</p>'
        self.assertEqual(intent_codes(analyze(row, BOTH, body=hidden)), [])

    def test_the_evaluator_restores_the_switch_when_an_analysis_fails(self):
        calls = []

        async def fails_without_rules(request, structure, observe_sender_history):
            calls.append(app.INTENT_RULES.get())
            if len(calls) == 2:
                raise RuntimeError('synthetic failure')
            return Response('medium')

        def fails_at_once(*args, **kwargs):
            raise RuntimeError('synthetic failure')
        # The run with rules fails, or the paired run without them does.
        for fake in (fails_at_once, fails_without_rules):
            with self.subTest(fake=fake.__name__), patch.object(app, '_analyze_content', fake):
                with self.assertRaises(RuntimeError):
                    evaluator.analyze_record(text_row(), intent_rules=('credential', 'payment'))
                self.assertEqual(app.INTENT_RULES.get(), frozenset())
        self.assertEqual(calls, [BOTH, frozenset()])

    def test_a_switch_set_in_one_context_stays_there(self):
        row = FIXTURES['cred-en-01']

        async def with_rules():
            app.INTENT_RULES.set(frozenset({'credential'}))  # this task's own context
            await asyncio.sleep(0)
            return intent_codes(app.analyze_email_content(row['subject'], row['body']))

        async def without_rules():
            await asyncio.sleep(0)
            return intent_codes(app.analyze_email_content(row['subject'], row['body']))

        async def concurrently():
            return await asyncio.gather(asyncio.create_task(with_rules()), asyncio.create_task(without_rules()))
        self.assertEqual(asyncio.run(concurrently()), [[CODES['credential']], []])
        self.assertEqual(app.INTENT_RULES.get(), frozenset())
        # A thread starts with the default, whatever the thread that started it had set.
        seen = []
        token = app.INTENT_RULES.set(BOTH)
        try:
            thread = threading.Thread(target=lambda: seen.append(intent_codes(analyze(row))))
            thread.start()
            thread.join()
        finally:
            app.INTENT_RULES.reset(token)
        self.assertEqual(seen, [[]])


if __name__ == '__main__':
    unittest.main()
