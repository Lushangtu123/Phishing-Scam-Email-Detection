"""Labelling a consented mailbox for training: legitimate readings, a review queue, the merge."""
import csv
import io
import json
import mailbox
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import label_with_llm as tool  # noqa: E402


class StubOllama(BaseHTTPRequestHandler):
    """"invoice" reads as phishing, "maybe" as an unsure legitimate, anything else as legitimate."""

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        text = request['messages'][1]['content'].lower()
        answer = ({'verdict': 'phishing', 'confidence': 95} if 'invoice' in text
                  else {'verdict': 'legitimate', 'confidence': 70} if 'maybe' in text
                  else {'verdict': 'legitimate', 'confidence': 95})
        payload = json.dumps({'message': {'content': json.dumps(answer)}}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def message(subject, body, date='Mon, 05 Oct 2026 10:00:00 +0000'):
    item = EmailMessage()
    item['From'] = 'Team <team@example.org>'
    item['To'] = 'sam@example.org'
    item['Subject'] = subject
    item['Date'] = date
    item.set_content(body)
    return item


class LabelWithModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), StubOllama)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_tool(self, *args):
        with redirect_stdout(io.StringIO()) as output:
            tool.main(list(args))
        return json.loads(output.getvalue())

    def test_label_review_and_merge(self):
        with tempfile.TemporaryDirectory() as directory:
            box = mailbox.mbox(str(Path(directory) / 'inbox.mbox'))
            box.add(message('Weekly planning notes', 'The planning notes for this week are ready for the team meeting.'))
            box.add(message('Overdue invoice', 'Please pay the attached invoice for the services delivered today.'))
            box.add(message('Quick question', 'Can you maybe look at the draft before the meeting on Friday afternoon?'))
            box.add(message('Old notice', 'This message predates the window and must not be read at all.',
                            date='Mon, 01 Jan 2024 10:00:00 +0000'))
            box.flush()
            box.close()
            out = Path(directory) / 'labels'
            summary = self.run_tool('label', str(Path(directory) / 'inbox.mbox'), '--output-dir', str(out),
                                    '--model', 'stub-model', '--url', self.url, '--since', '2026-01-01')
            self.assertEqual(summary['counts'], {'messages': 3, 'skipped_date': 1, 'labelled_legitimate': 1,
                                                 'to_review_phishing': 1, 'to_review_legitimate': 1})
            with (out / 'labelled.csv').open(newline='', encoding='utf-8') as source:
                rows = list(csv.DictReader(source))
            self.assertEqual([(row['subject'], row['label'], row['sender']) for row in rows],
                             [('Weekly planning notes', '0', 'team@example.org')])
            with (out / 'review.csv').open(newline='', encoding='utf-8') as source:
                review = list(csv.DictReader(source))
            self.assertEqual([(row['subject'], row['model_verdict'], row['human_label']) for row in review],
                             [('Overdue invoice', 'phishing', ''), ('Quick question', 'legitimate', '')])
            # A person labels the queue; only labelled rows are merged.
            for row, human in zip(review, ('phishing', 'legitimate')):
                row['human_label'] = human
            with (out / 'review.csv').open('w', newline='', encoding='utf-8') as target:
                writer = csv.DictWriter(target, tool.REVIEW_COLUMNS)
                writer.writeheader()
                writer.writerows(review)
            merged = self.run_tool('merge', '--output-dir', str(out))
            self.assertEqual(merged['counts'], {'labelled_legitimate': 1, 'merged_phishing': 1,
                                                'merged_legitimate': 1, 'model_agreed': 2})
            # Merging again rebuilds the file instead of adding the rows twice.
            self.assertEqual(self.run_tool('merge', '--output-dir', str(out)), merged)
            # The result loads as a corpus of the training pipeline.
            import content_model
            texts, labels, groups = content_model._load_one_corpus(out / 'labelled.csv', 'champa_csv')
            self.assertEqual(sorted(labels), [0, 0, 1])
            self.assertEqual(len(groups), 3)
            # Labelling into the same directory again would overwrite the person's labels.
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                tool.main(['label', str(Path(directory) / 'inbox.mbox'), '--output-dir', str(out),
                           '--model', 'stub-model', '--url', self.url])

    def test_evaluation_messages_are_never_labelled(self):
        with tempfile.TemporaryDirectory() as directory:
            box = mailbox.mbox(str(Path(directory) / 'inbox.mbox'))
            for index, subject in enumerate(('Weekly planning notes', 'Held-out notice')):
                item = message(subject, 'The planning notes for this week are ready for the team meeting.')
                item['Message-ID'] = f'<message-{index}@example.org>'
                box.add(item)
            box.flush()
            box.close()
            manifest = Path(directory) / 'evaluation.jsonl'
            manifest.write_text(json.dumps({'message_id': '<message-1@example.org>', 'label': 'genuine'}) + '\n',
                                encoding='utf-8')
            summary = self.run_tool('label', str(Path(directory) / 'inbox.mbox'), '--output-dir', str(Path(directory) / 'out'),
                                    '--model', 'stub-model', '--url', self.url, '--exclude', str(manifest))
            self.assertEqual(summary['counts'], {'messages': 1, 'skipped_evaluation': 1, 'labelled_legitimate': 1})

    def test_spam_folder_and_listed_messages_go_to_a_person(self):
        with tempfile.TemporaryDirectory() as directory:
            box = mailbox.mbox(str(Path(directory) / 'inbox.mbox'))
            for index, labels in enumerate(('Spam,Category Promotions', 'Inbox', 'Inbox,Opened')):
                item = message(f'Digest {index}', 'The planning notes for this week are ready for the team meeting.')
                item['Message-ID'] = f'<message-{index}@example.org>'
                item['X-Gmail-Labels'] = labels
                box.add(item)
            box.flush()
            box.close()
            manifest = Path(directory) / 'review.jsonl'
            manifest.write_text(json.dumps({'message_id': '<message-1@example.org>'}) + '\n', encoding='utf-8')
            out = Path(directory) / 'out'
            summary = self.run_tool('label', str(Path(directory) / 'inbox.mbox'), '--output-dir', str(out),
                                    '--model', 'stub-model', '--url', self.url, '--review', str(manifest))
            self.assertEqual(summary['counts'], {'messages': 3, 'to_review_flagged': 2, 'labelled_legitimate': 1})
            with (out / 'review.csv').open(newline='', encoding='utf-8') as source:
                review = list(csv.DictReader(source))
            # The model's reading is kept for the person to see.
            self.assertEqual([(row['subject'], row['flagged'], row['model_verdict']) for row in review],
                             [('Digest 0', 'spam folder', 'legitimate'), ('Digest 1', 'listed for review', 'legitimate')])

    def test_the_output_never_lands_in_the_repository(self):
        for target in (tool.PROJECT_ROOT, tool.PROJECT_ROOT / 'website' / 'labels'):
            with self.subTest(target=target), self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                tool.main(['merge', '--output-dir', str(target)])


if __name__ == '__main__':
    unittest.main()
