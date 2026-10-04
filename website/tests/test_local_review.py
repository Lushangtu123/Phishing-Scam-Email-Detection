"""The optional review of model-only alerts by a language model on this computer:
configuration, the Ollama client against a stub server, and its place in the analysis
(synthetic inputs; no model is run)."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import local_review as lr  # noqa: E402

DEVELOPMENT = {'LOCAL_LLM_REVIEW_ENABLED': 'true', 'LOCAL_LLM_REVIEW_MODEL': 'qwen3.8:27b-mlx', 'APP_ENV': 'development'}


class SettingsTests(unittest.TestCase):
    def test_off_by_default(self):
        self.assertFalse(lr.load_local_review_settings({}).enabled)
        self.assertFalse(lr.load_local_review_settings({'LOCAL_LLM_REVIEW_MODEL': 'x'}).enabled)

    def test_loopback_in_development(self):
        settings = lr.load_local_review_settings(DEVELOPMENT)
        self.assertEqual((settings.url, settings.model, settings.min_confidence),
                         ('http://127.0.0.1:11434', 'qwen3.8:27b-mlx', 80))
        for url in ('http://localhost:11434', 'http://[::1]:8080/'):
            with self.subTest(url=url):
                self.assertTrue(lr.load_local_review_settings({**DEVELOPMENT, 'LOCAL_LLM_REVIEW_URL': url}).enabled)

    def test_rejected(self):
        for change in ({'APP_ENV': 'production'}, {'APP_ENV': 'demo'}, {'APP_ENV': ''},
                       {'LOCAL_LLM_REVIEW_URL': 'http://example.com:11434'},
                       {'LOCAL_LLM_REVIEW_URL': 'http://192.168.1.2:11434'},
                       {'LOCAL_LLM_REVIEW_URL': 'https://127.0.0.1:11434'},
                       {'LOCAL_LLM_REVIEW_URL': 'http://127.0.0.1:11434/api'},
                       {'LOCAL_LLM_REVIEW_URL': 'http://user:pass@127.0.0.1:11434'},
                       {'LOCAL_LLM_REVIEW_URL': 'http://127.0.0.1:0'},
                       {'LOCAL_LLM_REVIEW_URL': 'http://127.0.0.1:99999'},
                       {'LOCAL_LLM_REVIEW_MODEL': ''}, {'LOCAL_LLM_REVIEW_MODEL': 'qwen 3'},
                       {'LOCAL_LLM_REVIEW_MIN_CONFIDENCE': '49'}, {'LOCAL_LLM_REVIEW_MIN_CONFIDENCE': '101'},
                       {'LOCAL_LLM_REVIEW_MIN_CONFIDENCE': 'high'}):
            environ = {**DEVELOPMENT, **change}
            if change.get('APP_ENV') == '':
                del environ['APP_ENV']  # the profile defaults to production
            with self.subTest(change=change), self.assertRaises(ValueError):
                lr.load_local_review_settings(environ)


class StubOllama(BaseHTTPRequestHandler):
    reply = (200, {'message': {'content': json.dumps({'verdict': 'legitimate', 'confidence': 90})}})
    delay = 0
    requests = []

    def do_POST(self):
        self.requests.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
        time.sleep(self.delay)
        status, body = self.reply
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        if status == 302:
            self.send_header('Location', 'http://127.0.0.1:9/api/chat')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), StubOllama)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.settings = lr.LocalReviewSettings(f'http://127.0.0.1:{cls.server.server_port}', 'stub-model', 80, 2.0)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        StubOllama.requests = []
        StubOllama.delay = 0
        StubOllama.reply = (200, {'message': {'content': json.dumps({'verdict': 'legitimate', 'confidence': 90})}})

    def test_request_and_answer(self):
        hosts = [f'h{i}.example.org' for i in range(20)]
        self.assertEqual(lr.review(self.settings, 'Weekly notes', 'x' * 5000, hosts),
                         {'verdict': 'legitimate', 'confidence': 90})
        path, payload = StubOllama.requests[0]
        self.assertEqual(path, '/api/chat')
        self.assertEqual((payload['model'], payload['stream'], payload['think'], payload['format']),
                         ('stub-model', False, False, lr.SCHEMA))
        self.assertEqual(payload['options']['temperature'], 0)
        system, user = payload['messages']
        self.assertEqual((system['role'], system['content']), ('system', lr.PROMPT))
        content = user['content']
        self.assertTrue(content.startswith('Subject: Weekly notes\n\nBody (between the markers):\n<<<EMAIL\n'))
        self.assertIn('<<<EMAIL\n' + 'x' * 4000 + '\n\n[Link destinations: ', content)
        self.assertIn('[Link destinations: ' + ', '.join(hosts[:15]) + ']', content)
        self.assertNotIn('h15.example.org', content)
        self.assertTrue(content.endswith('\nEMAIL>>>'))

    def test_out_of_form_answers(self):
        for reply in ((200, {'message': {'content': json.dumps({'verdict': 'unsure', 'confidence': 90})}}),
                      (200, {'message': {'content': json.dumps({'verdict': 'legitimate', 'confidence': 30})}}),
                      (200, {'message': {'content': json.dumps({'verdict': 'legitimate', 'confidence': '90'})}}),
                      (200, {'message': {'content': json.dumps({'verdict': 'legitimate', 'confidence': True})}}),
                      (200, {'message': {'content': 'not json'}}), (200, b'not json'), (200, {'error': 'x'}),
                      (500, {'message': {'content': json.dumps({'verdict': 'legitimate', 'confidence': 90})}}),
                      (302, b'')):
            StubOllama.reply = reply
            with self.subTest(reply=reply):
                self.assertIsNone(lr.review(self.settings, 'Subject', 'Body', []))

    def test_slow_or_absent_model(self):
        StubOllama.delay = 3
        self.assertIsNone(lr.review(self.settings, 'Subject', 'Body', []))
        self.assertIsNone(lr.review(lr.LocalReviewSettings('http://127.0.0.1:9', 'stub-model', 80, 1.0), 'Subject', 'Body', []))


class ConstantClassifier:
    def __init__(self, probability):
        self.probability = probability

    def predict_proba(self, features):
        return np.array([[1 - self.probability, self.probability]] * features.shape[0])


BODY = ('Please review the regular project planning notes for our meeting tomorrow at '
        'https://notes.example.org/plan and https://files.example.net/agenda.')


class AnalysisTests(unittest.TestCase):
    def analyze(self, readings, body=BODY, subject='Planning notes', probability=0.6):
        pipeline = {'vectorizer': TfidfVectorizer().fit([subject + ' ' + body]), 'clf': ConstantClassifier(probability),
                    'decision_threshold': 0.3736, 'metrics': {}}
        calls = []

        def stub(settings, subject, body, hosts):
            calls.append((subject, body, list(hosts)))
            return readings
        settings = lr.LocalReviewSettings('http://127.0.0.1:11434', 'stub-model', 80)
        with patch.object(app, '_content_pipeline', pipeline), patch.object(app, 'LOCAL_REVIEW', settings), \
                patch.object(app, 'local_review', stub):
            result = json.loads(asyncio.run(app._analyze_content(app.ContentRequest(subject=subject, body=body),
                                                                 observe_sender_history=False)).body)
        return result, calls

    @staticmethod
    def review_codes(result):
        return [(item['code'], item.get('params')) for item in result['extra_indicators']
                if item['code'].startswith('content.local_review')]

    def test_a_legitimate_reading_lowers_the_alert(self):
        result, calls = self.analyze({'verdict': 'legitimate', 'confidence': 90})
        self.assertEqual((result['risk_level'], result['risk_label']), ('low', 'Low Risk — Read as Legitimate by a Local Model'))
        self.assertEqual(self.review_codes(result),
                         [('content.local_review_legitimate', {'model': 'stub-model', 'confidence': 90})])
        self.assertEqual(calls, [('Planning notes', BODY, ['notes.example.org', 'files.example.net'])])
        self.assertFalse(result['requested_question'])

    def test_other_answers_keep_the_alert(self):
        for readings, code in (({'verdict': 'legitimate', 'confidence': 79}, 'content.local_review_unsure'),
                               ({'verdict': 'phishing', 'confidence': 95}, 'content.local_review_phishing'),
                               (None, 'content.local_review_unavailable')):
            with self.subTest(readings=readings):
                result, calls = self.analyze(readings)
                self.assertEqual(result['risk_level'], 'medium')
                self.assertEqual([found for found, _params in self.review_codes(result)], [code])
                self.assertEqual(len(calls), 1)

    def test_only_model_only_alerts_are_reviewed(self):
        # The model reads it as legitimate: no alert, nothing to review.
        result, calls = self.analyze({'verdict': 'legitimate', 'confidence': 99}, probability=0.1)
        self.assertEqual((result['risk_level'], calls), ('low', []))
        # A rule finding stands behind the alert: a callback request.
        lure = BODY + (' Your subscription renewal of $499 is complete. If you did not authorize this charge, '
                       'call 1-888-555-0199 immediately.')
        result, calls = self.analyze({'verdict': 'legitimate', 'confidence': 99}, body=lure)
        self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})
        self.assertEqual(calls, [])

    def test_hidden_text_is_not_sent(self):
        body = '<p>' + BODY + '</p><div style="display:none">secret filler words</div>'
        _result, calls = self.analyze({'verdict': 'legitimate', 'confidence': 90}, body=body)
        self.assertEqual(len(calls), 1)
        self.assertNotIn('secret filler', calls[0][1])

    def test_off_by_default(self):
        self.assertFalse(app.LOCAL_REVIEW.enabled)


if __name__ == '__main__':
    unittest.main()
