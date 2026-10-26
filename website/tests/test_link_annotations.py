"""Link annotations in a body declared text (A1): a plain-text part writes a link as "<https://...>", which the html
reading dropped as a tag. Only the copy the text model scores leaves them out; the rules, the subject, original
messages, OCR and QR text, and the html reading are unchanged."""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import app
from case_api import build_case_service
from test_case_api import TOKEN, request

LINK = '<https://portal.example.net/verify>'
BODY = f'Confirm your details here {LINK} today or the account closes.'
STRIPPED = 'Confirm your details here today or the account closes.'
HEAD = ('From: Portal <notice@portal.example.net>\r\nTo: reader@example.org\r\nSubject: Account notice\r\n'
        'Date: Thu, 01 Oct 2026 12:00:00 +0000\r\nMIME-Version: 1.0\r\n')
RAW_PLAIN = HEAD + 'Content-Type: text/plain; charset=utf-8\r\n\r\n' + BODY + '\r\n'
# Each boundary of the approved list (fixed-lists-a1.json) and the text the model must score.
BOUNDARIES = {
    'https': ('See <https://a.example/x> for details.', 'See for details.'),
    'http': ('See <http://a.example/x> for details.', 'See for details.'),
    'mailto': ('Write to <mailto:desk@a.example> today.', 'Write to today.'),
    'upper case': ('See <HTTPS://A.EXAMPLE/X> or <Mailto:desk@a.example> or <hTtP://a.example>.', 'See or or .'),
    'adjacent text': ('word<https://a.example/x>word', 'word word'),
    'several annotations': ('Read <https://a.example/1> and <https://a.example/2>, then <mailto:desk@a.example> today.',
                            'Read and , then today.'),
    'nesting': ('See <<https://a.example/x>> for details.', 'See < > for details.'),
    'unclosed': ('See <https://a.example/x for details.', 'See <https://a.example/x for details.'),
    'empty address': ('Write to <mailto:> or open <https://> for details.',
                      'Write to <mailto:> or open <https://> for details.'),
    'inner whitespace': ('See <https:// a.example> for details.', 'See <https:// a.example> for details.'),
    'leading whitespace': ('See < https://a.example> for details.', 'See < https://a.example> for details.'),
    'URL: wrapper': ('See <URL:https://a.example> for details.', 'See <URL:https://a.example> for details.'),
    'other scheme': ('See <ftp://a.example> or <www.a.example> for details.',
                     'See <ftp://a.example> or <www.a.example> for details.'),
    'other link forms': ('See (https://a.example) and [1] https://a.example or https://a.example.',
                         'See (https://a.example) and [1] https://a.example or https://a.example.'),
    'HTML source': ('Sign in <a href="https://a.example/x">here</a> now.', 'Sign in <a href="https://a.example/x">here</a> now.'),
}


def prediction(_pipeline, _subject, _body, **_kwargs):
    return {'ml_status': 'available', 'ml_phishing_probability': 10.0, '_phishing_probability': 0.1,
            'ml_legitimate_probability': 90.0, 'ml_label': None, 'ml_prediction': 0, 'ml_top_contributors': []}


class ModelInputTests(unittest.TestCase):
    """What the stand-in model receives: (subject, body) for each call, in order."""

    def setUp(self):
        app._rate_limit_buckets.clear()
        self.patches = [patch.object(app, '_content_pipeline', {'decision_threshold': 0.35, 'metrics': {}}),
                        patch.object(app, 'predict_content', side_effect=prediction)]
        self.predict = [item.start() for item in self.patches][1]

    def tearDown(self):
        for item in self.patches:
            item.stop()

    def calls(self, path, payload):
        self.predict.reset_mock()
        app._rate_limit_buckets.clear()
        status, result, _ = asyncio.run(request('POST', path, payload=payload))
        self.assertEqual(status, 200, result)
        return result, [(call.args[1], call.args[2]) for call in self.predict.call_args_list]

    def content(self, body, subject='Account notice', **payload):
        return self.calls('/api/analyze-content', {'subject': subject, 'body': body, **payload})

    def test_a_text_body_is_scored_once_without_its_annotations(self):
        for name, (body, expected) in BOUNDARIES.items():
            with self.subTest(name):
                _result, calls = self.content(body, body_format='text')
                self.assertEqual(calls, [('Account notice', expected)])

    def test_the_rules_still_read_the_annotation(self):
        text, _calls = self.content(BODY, body_format='text')
        self.assertEqual(text['url_count'], 1)
        ip, _calls = self.content('Sign in at <https://192.0.2.10/login> today.', body_format='text')
        self.assertTrue(ip['has_ip_url'])

    def test_the_subject_is_unchanged(self):
        _result, calls = self.content('Hello, the notice is attached.', subject=f'Confirm your details {LINK}',
                                      body_format='text')
        self.assertEqual(calls, [(f'Confirm your details {LINK}', 'Hello, the notice is attached.')])

    def test_the_html_reading_and_a_request_without_the_field_are_unchanged(self):
        # Escaped in HTML, the annotation is visible text the html reading gives the model as before.
        body = '<p>Confirm your details here &lt;https://portal.example.net/verify&gt; today.</p>'
        for extra in ({}, {'body_format': 'html'}):
            with self.subTest(extra):
                _result, calls = self.content(body, **extra)
                self.assertEqual(calls, [('Account notice', f'Confirm your details here {LINK} today.')])

    def test_an_original_message_is_unchanged_whatever_the_field_says(self):
        for extra in ({}, {'body_format': 'text'}, {'body_format': 'html'}):
            with self.subTest(extra):
                result, calls = self.content('ignored', raw_email=RAW_PLAIN, **extra)
                self.assertEqual(result['body_reading'], 'mime')
                self.assertEqual(calls, [('Account notice', BODY)])
        _result, calls = self.calls('/api/analyze-visual', {'eml_base64': base64.b64encode(RAW_PLAIN.encode()).decode(),
                                                             'body_format': 'text'})
        self.assertEqual(calls, [('Account notice', BODY)])

    def test_ocr_and_qr_text_are_unchanged(self):
        observation = {'name': 'screenshot.png', 'mime_type': 'image/png', 'source': 'upload', 'sha256': '0' * 64,
                       'status': 'processed', 'ocr_language': 'eng', 'ocr_text': BODY, 'ocr_confidence': 90,
                       'qr_payloads': [f'Scan {LINK} now']}
        _result, calls = self.calls('/api/analyze-visual', {'subject': 'Account notice', 'body': BODY,
                                                            'body_format': 'text', 'observations': [observation]})
        self.assertEqual(calls, [('Account notice', STRIPPED), ('', BODY), ('', f'Scan {LINK} now')])


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        env = {'CASE_MANAGEMENT_ENABLED': 'true', 'CASE_DB_PATH': str(Path(self.temp.name) / 'cases.sqlite3'),
               'CASE_ANALYST_TOKEN_HASHES': json.dumps({'alice': hashlib.sha256(TOKEN.encode()).hexdigest()})}
        self.previous = getattr(app.app.state, 'case_service', None)
        self.previous_error = getattr(app.app.state, 'case_configuration_error', False)
        app.app.state.case_configuration_error = False
        app.app.state.case_service = build_case_service(env)
        app._rate_limit_buckets.clear()
        self.patches = [patch.object(app, '_content_pipeline', {'decision_threshold': 0.35, 'metrics': {}}),
                        patch.object(app, 'predict_content', side_effect=prediction)]
        self.predict = [item.start() for item in self.patches][1]

    def tearDown(self):
        for item in self.patches:
            item.stop()
        app.app.state.case_service = self.previous
        app.app.state.case_configuration_error = self.previous_error
        self.temp.cleanup()

    def test_a_text_case_is_scored_without_annotations_and_saves_them(self):
        status, record, _ = asyncio.run(request('POST', '/api/cases', key='00000000-0000-4000-8000-000000000001',
                                                payload={'subject': 'Account notice', 'body': BODY, 'body_format': 'text'}))
        self.assertEqual(status, 201, record)
        self.assertEqual([(call.args[1], call.args[2]) for call in self.predict.call_args_list],
                         [('Account notice', STRIPPED)])
        self.assertIn(LINK, app.app.state.case_service.store.get(record['id'])['source']['auxiliary_text'])


class PatternTests(unittest.TestCase):
    def test_each_annotation_becomes_exactly_one_space(self):
        self.assertEqual(app._LINK_ANNOTATION.sub(' ', 'a<https://x.example>b<mailto:y@x.example>c'), 'a b c')

    def test_a_long_address_is_linear(self):
        for text in ('See <https://a.example/' + 'x' * 50_000 + '> now', 'See <https://a.example/' + 'x' * 50_000,
                     '<https://' * 10_000):
            started = time.perf_counter()
            app._without_link_annotations(text)
            self.assertLess(time.perf_counter() - started, 0.1)


if __name__ == '__main__':
    unittest.main()
