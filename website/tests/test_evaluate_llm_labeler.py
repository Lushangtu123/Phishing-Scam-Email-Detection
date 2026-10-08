"""Measuring a local language model as a labeller: verdict counts, floors, no message text."""
import io
import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_llm_labeler as tool  # noqa: E402


class StubOllama(BaseHTTPRequestHandler):
    """Reads "invoice" as phishing (95), anything else as legitimate (85)."""

    def do_GET(self):
        self.reply({'models': [{'name': 'stub-model', 'digest': 'stub-digest'}]})

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        text = request['messages'][1]['content'].lower()
        answer = {'verdict': 'phishing', 'confidence': 95} if 'invoice' in text else {'verdict': 'legitimate', 'confidence': 85}
        self.reply({'message': {'content': json.dumps(answer)}})

    def reply(self, body):
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def row(label, subject, body):
    return {'provider': 'gmail', 'received_at': '2026-10-01', 'label': label, 'subject': subject, 'body': body}


class LabellerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), StubOllama)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_counts_floors_and_privacy(self):
        rows = [row('phishing', 'Overdue invoice', 'Pay the attached invoice today.'),
                row('phishing', 'Account notice', 'Confirm your mailbox password here.'),  # missed: read as legitimate
                row('legitimate', 'Team lunch', 'Lunch on Friday at noon.'),
                row('legitimate', 'Your invoice from Acme', 'Thanks for your order.')]  # read as phishing
        with tempfile.TemporaryDirectory() as directory:
            cohort = Path(directory) / 'cohort.jsonl'
            cohort.write_text(''.join(json.dumps(item) + '\n' for item in rows), encoding='utf-8')
            output = Path(directory) / 'report.json'
            tool.main(['--model', 'stub-model', '--url', self.url, '--input', f'mixed={cohort}', '--output', str(output)])
            text = output.read_text(encoding='utf-8')
        report = json.loads(text)
        self.assertEqual(report['cohorts']['mixed'], {
            'phishing': {'messages': 2, 'phishing_90-100': 1, 'legitimate_80-89': 1},
            'legitimate': {'messages': 2, 'legitimate_80-89': 1, 'phishing_90-100': 1}})
        every = report['metrics']['confidence>=50']
        self.assertEqual((every['labelled'], every['coverage'], every['phishing_precision'], every['phishing_recall'],
                          every['false_phishing'], every['missed_phishing']), (4, 1.0, 0.5, 0.5, 1, 1))
        # At 90 only the two phishing readings are used without a person.
        strict = report['metrics']['confidence>=90']
        self.assertEqual((strict['labelled'], strict['coverage'], strict['phishing_precision']), (2, 0.5, 0.5))
        self.assertEqual(report['seconds']['calls'], 4)
        self.assertEqual(report['configuration']['model_digest'], 'stub-digest')
        for item in rows:
            self.assertNotIn(item['subject'], text)
            self.assertNotIn(item['body'], text)

    def test_mail_text_never_leaves_this_computer(self):
        with tempfile.TemporaryDirectory() as directory:
            cohort = Path(directory) / 'cohort.jsonl'
            cohort.write_text(json.dumps(row('legitimate', 'a', 'b')) + '\n', encoding='utf-8')
            for url in ('http://example.com:11434', 'https://127.0.0.1:11434'):
                with self.subTest(url=url), self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                    tool.main(['--model', 'stub-model', '--url', url, '--input', f'c={cohort}'])


if __name__ == '__main__':
    unittest.main()
