"""The local-review comparison tool: shadow counts per cohort, pasted cohorts, no message text."""
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_requested_notice import NOTICES  # noqa: E402
from tools import evaluate_local_review as tool  # noqa: E402


class StubOllama(BaseHTTPRequestHandler):
    chats = 0

    def do_GET(self):
        self.reply({'models': [{'name': 'stub-model', 'digest': 'stub-digest'}]})

    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        type(self).chats += 1
        self.reply({'message': {'content': json.dumps({'verdict': 'legitimate', 'confidence': 90})}})

    def reply(self, body):
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class ComparisonToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if f'{sys.version_info.major}.{sys.version_info.minor}' != (WEBSITE_DIR.parent / '.python-version').read_text().strip():
            raise unittest.SkipTest('Committed artifact targets another Python version')
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), StubOllama)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_tool(self, directory, *args):
        output = Path(directory) / 'report.json'
        tool.main(['--model', 'stub-model', '--url', self.url, '--output', str(output), *args])
        return output.read_text(encoding='utf-8')

    def test_shadow_counts_by_cohort(self):
        # The committed model reads both notices as phishing with no rule finding beside it:
        # an alert on pasted text, a note in an original message (2026-10-05).
        notices = (NOTICES[1], NOTICES[3])
        with tempfile.TemporaryDirectory() as directory:
            pasted = Path(directory) / 'pasted.jsonl'
            originals = Path(directory) / 'originals.jsonl'
            rows = [{'provider': 'gmail', 'received_at': '2026-10-01', 'label': 'legitimate',
                     'subject': subject, 'body': body} for subject, body in notices]
            rows.append({'provider': 'gmail', 'received_at': '2026-10-01', 'label': 'legitimate',
                         'subject': 'Lunch on Friday', 'body': 'Are we still on for lunch on Friday at noon?'})
            pasted.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
            lines = []
            for index, (subject, body) in enumerate(notices):
                eml = Path(directory) / f'notice-{index}.eml'
                eml.write_bytes((f'From: Alex Chen <alex.chen@gmail.com>\r\nTo: sam@example.org\r\nSubject: {subject}\r\n'
                                 f'Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n').encode())
                lines.append(json.dumps({'provider': 'gmail', 'received_at': '2026-10-01', 'label': 'legitimate',
                                         'eml_path': str(eml)}))
            originals.write_text('\n'.join(lines) + '\n', encoding='utf-8')
            StubOllama.chats = 0
            text = self.run_tool(directory, '--input', f'pasted={pasted}', '--input', f'eml={originals}',
                                 '--paste', f'eml_pasted={originals}')
        report = json.loads(text)
        cohorts = report['models']['stub-model']['cohorts']
        self.assertEqual(cohorts['pasted']['legitimate'],
                         {'messages': 3, 'alerts': 2, 'would_lower': 2, 'alerts_if_applied': 0, 'kept_phishing': 0,
                          'kept_unsure': 0, 'unavailable': 0, 'skipped': 0})
        # As .eml files the two notices are notes, not alerts: nothing to review.
        self.assertEqual((cohorts['eml']['legitimate']['alerts'], cohorts['eml']['legitimate']['would_lower']), (0, 0))
        # Pasted from the same files, they alert again and are reviewed.
        self.assertEqual((cohorts['eml_pasted']['legitimate']['alerts'],
                          cohorts['eml_pasted']['legitimate']['would_lower']), (2, 2))
        self.assertEqual(report['models']['stub-model']['review_seconds']['reviews'], 4)
        self.assertEqual(StubOllama.chats, 4)
        self.assertEqual(report['mode'], 'shadow')
        self.assertEqual(report['configuration']['model_digests'], {'stub-model': 'stub-digest'})
        self.assertEqual(report['configuration']['pasted_cohorts'], ['eml_pasted'])
        # Aggregates only: no subject, body or address reaches the report.
        for subject, body in notices:
            self.assertNotIn(subject, text)
            self.assertNotIn(body[:40], text)
        self.assertNotIn('alex.chen', text)

    def test_a_pasted_cohort_is_not_bound_by_the_upload_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            eml = Path(directory) / 'large.eml'
            eml.write_bytes(b'From: Alex Chen <alex.chen@gmail.com>\r\nSubject: Long notes\r\n'
                            b'Content-Type: text/plain; charset=utf-8\r\n\r\n' + b'Team notes for the week. ' * 4000)
            cohort = Path(directory) / 'cohort.jsonl'
            cohort.write_text(json.dumps({'provider': 'gmail', 'received_at': '2026-10-01', 'label': 'legitimate',
                                          'eml_path': str(eml)}) + '\n', encoding='utf-8')
            report = json.loads(self.run_tool(directory, '--paste', f'big={cohort}'))
            self.assertEqual(report['models']['stub-model']['cohorts']['big']['legitimate']['messages'], 1)
            # As an upload the same file is over the 60,000-byte .eml limit.
            with self.assertRaises(ValueError):
                self.run_tool(directory, '--input', f'big={cohort}')

    def test_mail_text_never_leaves_this_computer(self):
        with tempfile.TemporaryDirectory() as directory:
            cohort = Path(directory) / 'cohort.jsonl'
            cohort.write_text('{}\n', encoding='utf-8')
            for url in ('http://example.com:11434', 'https://127.0.0.1:11434', 'http://192.168.1.2:11434',
                        'http://127.0.0.1:11434/api'):
                with self.subTest(url=url), self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                    tool.main(['--model', 'stub-model', '--url', url, '--input', f'c={cohort}'])
            for args in (['--model', 'bad model'], ['--model', 'stub-model', '--min-confidence', '49'],
                         ['--model', 'stub-model']):
                with self.subTest(args=args), self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                    tool.main([*args, '--url', 'http://127.0.0.1:11434']
                              + ([] if args == ['--model', 'stub-model'] else ['--input', f'c={cohort}']))


if __name__ == '__main__':
    unittest.main()
