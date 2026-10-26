"""The declared reading of a manual body (body_format): text as pasted, html as before, an original message by its
MIME types. The page's text boxes send text; a request without the field keeps the html reading."""
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import app
from case_api import build_case_service
from jev import prepare_case_input
from test_case_api import TOKEN, request

OTP = 'content.sensitive_request.one_time_code'
LEAD = 'Please use the link for the scheduled project activity. '
REQUEST = 'Please reply with the one-time verification code from the sign-in message so I can finish the scheduled setup.'
LITERAL_STYLE = LEAD + '<style>' + REQUEST + '</style>'
INVALID = ['TEXT', 'Text', 'plain', 'markdown', 'mime', '', ' text', 'text ', None, 1, True, ['text'], {'v': 'text'}]
HEAD = ('From: Project Team <sender@example.org>\r\nTo: reader@example.org\r\nSubject: Project update\r\n'
        'Date: Thu, 01 Oct 2026 12:00:00 +0000\r\nMIME-Version: 1.0\r\n')
RAW_PLAIN = HEAD + 'Content-Type: text/plain; charset=utf-8\r\n\r\n' + LITERAL_STYLE + '\r\n'
RAW_HTML = HEAD + 'Content-Type: text/html; charset=utf-8\r\n\r\n<p>' + LEAD + '</p><style>' + REQUEST + '</style>\r\n'
OBSERVATION = {'name': 'screenshot.png', 'mime_type': 'image/png', 'source': 'upload', 'sha256': '0' * 64,
               'status': 'processed', 'ocr_language': 'eng', 'ocr_text': 'The meeting notes are attached.',
               'ocr_confidence': 90}


def codes(result):
    return {item.get('code') for item in result['extra_indicators']}


def without_reading(result):
    return {key: value for key, value in result.items() if key != 'body_reading'}


class BodyFormatTests(unittest.TestCase):
    def setUp(self):
        app._rate_limit_buckets.clear()
        self.model = patch.object(app, '_content_pipeline', None)
        self.model.start()

    def tearDown(self):
        self.model.stop()

    def post(self, path, payload, token=None):
        app._rate_limit_buckets.clear()  # many requests per test; the limits are tested elsewhere
        return asyncio.run(request('POST', path, payload=payload, token=token))

    def content(self, **payload):
        status, result, _ = self.post('/api/analyze-content', {'subject': 'Project update', **payload})
        self.assertEqual(status, 200, result)
        return result

    def test_text_reads_literal_markup_and_the_default_reads_html_as_before(self):
        text = self.content(body=LITERAL_STYLE, body_format='text')
        self.assertIn(OTP, codes(text))
        self.assertEqual((text['risk_level'], text['risk_floor'], text['body_reading']), ('high', 'high', 'text'))
        default = self.content(body=LITERAL_STYLE)
        self.assertNotIn(OTP, codes(default))
        self.assertEqual((default['risk_floor'], default['body_reading']), ('safe', 'html'))
        self.assertEqual(without_reading(self.content(body=LITERAL_STYLE, body_format='html')), without_reading(default))

    def test_every_filtered_element_is_literal_text_when_declared_text(self):
        for wrap in ('<style>{}</style>', '<script>{}</script>', '<!-- {} -->', '<title>{}</title>',
                     '<noscript>{}</noscript>', '<template>{}</template>'):
            with self.subTest(wrap=wrap):
                result = self.content(body=LEAD + wrap.format(REQUEST), body_format='text')
                self.assertIn(OTP, codes(result))
                self.assertEqual(result['risk_floor'], 'high')

    def test_real_html_declared_html_keeps_hidden_content_hidden(self):
        hidden = '<html><body><p>The meeting notes are attached.</p><script>var reply = "send your password";</script></body></html>'
        self.assertNotIn('content.sensitive_request.password_pin', codes(self.content(body=hidden, body_format='html')))
        anchor = LEAD + '<a href="https://portal.example.net/login">Sign in: example.org</a>'
        self.assertIn('link.display_mismatch', codes(self.content(body=anchor, body_format='html')))
        self.assertNotIn('link.display_mismatch', codes(self.content(body=anchor, body_format='text')))

    def test_the_subject_is_literal_in_every_reading(self):
        for fmt in (None, 'html', 'text'):
            with self.subTest(fmt=fmt):
                payload = {'subject': '<style>' + REQUEST + '</style>', 'body': 'Hello.'}
                status, result, _ = self.post('/api/analyze-content', {**payload, **({'body_format': fmt} if fmt else {})})
                self.assertEqual(status, 200)
                self.assertIn(OTP, codes(result))

    def test_an_original_message_ignores_body_format_and_is_read_by_its_mime_types(self):
        for raw, expect_request in ((RAW_PLAIN, True), (RAW_HTML, False)):
            plain = self.content(raw_email=raw)
            self.assertEqual(plain['body_reading'], 'mime')
            self.assertEqual(OTP in codes(plain), expect_request)
            for fmt in ('text', 'html'):
                with self.subTest(raw=raw[-30:], fmt=fmt):
                    declared = self.content(raw_email=raw, body='ignored', body_format=fmt)
                    self.assertEqual(without_reading(declared), without_reading(plain))
                    self.assertEqual(declared['body_reading'], 'mime')
        app._rate_limit_buckets.clear()
        status, eml, _ = asyncio.run(request('POST', '/api/analyze-eml', raw=RAW_PLAIN.encode(), token=None))
        self.assertEqual((status, eml['body_reading']), (200, 'mime'))

    def test_invalid_values_are_rejected_by_every_endpoint(self):
        for value in INVALID:
            with self.subTest(value=value):
                self.assertEqual(self.post('/api/analyze-content', {'body': 'Hello', 'body_format': value})[0], 422)
                self.assertEqual(self.post('/api/analyze-visual', {'body': 'Hello', 'body_format': value})[0], 422)

    def test_a_subject_alone_may_be_read_as_text_and_empty_input_is_still_refused(self):
        result = self.content(body='', body_format='text')
        self.assertEqual(result['body_reading'], 'text')
        self.assertEqual(self.post('/api/analyze-content', {'subject': '', 'body': '', 'body_format': 'text'})[0], 400)

    def test_the_visual_request_carries_body_format_to_the_body_reading(self):
        status, text, _ = self.post('/api/analyze-visual', {'subject': 'Project update', 'body': LITERAL_STYLE,
                                                             'body_format': 'text'})
        self.assertEqual(status, 200)
        self.assertIn(OTP, codes(text))
        self.assertEqual((text['risk_floor'], text['body_reading']), ('high', 'text'))
        status, default, _ = self.post('/api/analyze-visual', {'subject': 'Project update', 'body': LITERAL_STYLE})
        self.assertNotIn(OTP, codes(default))
        self.assertEqual(default['body_reading'], 'html')
        self.assertEqual(self.post('/api/analyze-visual', {'body': LITERAL_STYLE, 'bodyformat': 'text'})[0], 422)
        status, eml, _ = self.post('/api/analyze-visual', {'eml_base64': base64.b64encode(RAW_PLAIN.encode()).decode(),
                                                            'body_format': 'text'})
        self.assertEqual((status, eml['body_reading']), (200, 'mime'))


class CaseBodyFormatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        env = {'CASE_MANAGEMENT_ENABLED': 'true', 'CASE_DB_PATH': str(Path(self.temp.name) / 'cases.sqlite3'),
               'CASE_ANALYST_TOKEN_HASHES': json.dumps({'alice': hashlib.sha256(TOKEN.encode()).hexdigest()})}
        self.previous = getattr(app.app.state, 'case_service', None)
        self.previous_error = getattr(app.app.state, 'case_configuration_error', False)
        app.app.state.case_configuration_error = False
        app.app.state.case_service = build_case_service(env)
        app._rate_limit_buckets.clear()
        self.model = patch.object(app, '_content_pipeline', None)
        self.model.start()
        self.keys = iter(f'00000000-0000-4000-8000-{index:012d}' for index in range(1, 1000))

    def tearDown(self):
        self.model.stop()
        app.app.state.case_service = self.previous
        app.app.state.case_configuration_error = self.previous_error
        self.temp.cleanup()

    def create(self, payload, path='/api/cases'):
        app._rate_limit_buckets.clear()
        status, record, _ = asyncio.run(request('POST', path, payload=payload, key=next(self.keys)))
        self.assertEqual(status, 201, record)
        return app.app.state.case_service.store.get(record['id'])

    def stored_digest(self, case_id):
        with app.app.state.case_service.store.connection() as db:
            return db.execute('SELECT input_sha256 FROM cases WHERE id=?', (case_id,)).fetchone()[0]

    @staticmethod
    def prepared(case):
        return prepare_case_input(case['source'], case['analysis'], visible_text=app._visible_content_text,
                                  mask_inline_data=app._mask_inline_data_payloads)['body']

    def test_a_text_case_keeps_the_literal_body_for_the_analysis_and_the_external_opinion(self):
        case = self.create({'subject': 'Project update', 'body': LITERAL_STYLE, 'body_format': 'text'})
        self.assertIn(OTP, codes(case['analysis']))
        self.assertEqual((case['analysis']['risk_floor'], case['analysis']['body_reading']), ('high', 'text'))
        self.assertIn('<style>' + REQUEST, case['source']['auxiliary_text'])
        self.assertIn('<style>' + REQUEST, self.prepared(case))

    def test_default_and_html_cases_save_what_they_saved_before(self):
        default = self.create({'subject': 'Project update', 'body': LITERAL_STYLE})
        html = self.create({'subject': 'Project update', 'body': LITERAL_STYLE, 'body_format': 'html'})
        self.assertEqual(default['source'], html['source'])
        self.assertEqual(default['source']['auxiliary_text'], app._visible_content_text(LITERAL_STYLE))
        self.assertNotIn('<style>', self.prepared(default))
        self.assertEqual(default['analysis']['body_reading'], 'html')

    def test_an_image_case_keeps_a_text_body_literally_in_both_saved_texts(self):
        payload = {'subject': 'Project update', 'body': LITERAL_STYLE, 'observations': [OBSERVATION]}
        text = self.create({**payload, 'body_format': 'text'}, '/api/cases/visual')
        self.assertIn('<style>' + REQUEST, text['source']['body'])
        self.assertIn('<style>' + REQUEST, text['source']['auxiliary_text'])
        self.assertIn(OTP, codes(text['analysis']))
        default = self.create(payload, '/api/cases/visual')
        self.assertNotIn('<style>', default['source']['body'])
        self.assertNotIn('<style>', default['source']['auxiliary_text'])

    def test_inline_image_data_is_masked_in_a_text_case(self):
        payload = 'iVBORw0KGgo' + 'A' * 240
        case = self.create({'subject': 'Chart', 'body': 'The chart is below.\ndata:image/png;base64,' + payload,
                            'body_format': 'text'})
        self.assertNotIn(payload, case['source']['auxiliary_text'])
        self.assertIn('data:image/opaque', case['source']['auxiliary_text'])

    def test_an_original_message_case_ignores_body_format(self):
        plain = self.create({'raw_email': RAW_PLAIN})
        declared = self.create({'raw_email': RAW_PLAIN, 'body_format': 'text'})
        self.assertEqual(plain['source'], declared['source'])
        self.assertEqual(declared['analysis']['body_reading'], 'mime')

    def test_the_idempotency_digest_is_unchanged_without_a_text_reading(self):
        fields = {'subject': 'Project update', 'body': LITERAL_STYLE, 'raw_email': ''}
        old = hashlib.sha256(b'json\0' + json.dumps(fields, sort_keys=True).encode()).hexdigest()
        for extra in ({}, {'body_format': 'html'}):
            case = self.create({**fields, **extra})
            self.assertEqual(self.stored_digest(case['id']), old)
        text = self.create({**fields, 'body_format': 'text'})
        self.assertNotEqual(self.stored_digest(text['id']), old)

    def test_invalid_values_are_rejected(self):
        for path in ('/api/cases', '/api/cases/visual'):
            for value in INVALID:
                with self.subTest(path=path, value=value):
                    app._rate_limit_buckets.clear()
                    status, _, _ = asyncio.run(request('POST', path, payload={'body': 'Hello', 'body_format': value},
                                                       key=next(self.keys)))
                    self.assertEqual(status, 422)

    def test_a_stored_case_without_auxiliary_text_is_prepared_as_before(self):
        source = {'subject': 'Project update', 'body': LITERAL_STYLE, 'input_mode': 'subject-body'}
        prepared = prepare_case_input(source, {'analysis_complete': True}, visible_text=app._visible_content_text,
                                      mask_inline_data=app._mask_inline_data_payloads)
        self.assertEqual(prepared['body'], app._visible_content_text(LITERAL_STYLE))


if __name__ == '__main__':
    unittest.main()
