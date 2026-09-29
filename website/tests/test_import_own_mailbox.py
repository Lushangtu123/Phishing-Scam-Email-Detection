import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools import import_own_mailbox as importer  # noqa: E402


def message(subject, sender='Netflix <info@account.netflix.com>', date='Tue, 03 Jun 2025 23:30:00 -0700',
            body='We noticed a new sign-in to your account.'):
    headers = f'From: {sender}\nSubject: {subject}\n' + (f'Date: {date}\n' if date else '')
    return headers + f'Content-Type: text/plain; charset=utf-8\n\n{body}\n'


def mbox(path, messages):
    path.write_text(''.join(f'From MAILER-DAEMON Tue Jun  3 23:30:00 2025\n{m}\n' for m in messages))


class ImportOwnMailboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.out = self.dir / 'out'

    def tearDown(self):
        self.tmp.cleanup()

    def rows(self):
        text = (self.out / 'messages.jsonl').read_text(encoding='utf-8')
        return [json.loads(line) for line in text.splitlines()]

    def test_takeout_apple_and_eml_inputs_become_valid_serving_rows(self):
        mbox(self.dir / 'Takeout.mbox', [message('New sign-in'), message('New sign-in'), message('No date', date='')])
        apple = self.dir / 'Receipts.mbox'
        apple.mkdir()
        mbox(apple / 'mbox', [message('Your receipt', sender='Apple <no_reply@email.apple.com>')])
        (self.dir / 'single.eml').write_text(message('Verify your email', sender='noreply@steampowered.com'))
        summary = importer.convert([self.dir / 'Takeout.mbox', apple, self.dir / 'single.eml'], self.out,
                                   provider='gmail', language='en')
        self.assertEqual(summary['counts'], {'read': 5, 'duplicate': 1, 'no_date': 1, 'written': 3, 'mode_eml': 3})
        self.assertEqual(dict(summary['sender_domains']),
                         {'account.netflix.com': 1, 'email.apple.com': 1, 'steampowered.com': 1})
        rows = self.rows()
        for index, row in enumerate(rows, 1):
            self.assertIs(serving._validated_record(row, index), row)
            self.assertEqual(row['label'], 'legitimate')
            self.assertTrue(Path(row['eml_path']).is_absolute())
            self.assertIn(b'Subject:', serving._read_eml(row['eml_path']))
        self.assertEqual(rows[0]['received_at'], '2025-06-04')  # converted to UTC
        manifest = [json.loads(line) for line in (self.out / 'manifest.jsonl').read_text().splitlines()]
        self.assertEqual([m['subject'] for m in manifest], ['New sign-in', 'Your receipt', 'Verify your email'])

    def test_oversized_messages_become_text_rows_or_are_skipped(self):
        html = '<html><style>' + 'p{} ' * importer.MAX_EML_BYTES + '</style><p>Your invoice</p><p>x x</p></html>'
        raw = message('Invoice', body=html).replace('text/plain', 'text/html')
        (self.dir / 'big.eml').write_text(raw)
        importer.convert([self.dir / 'big.eml'], self.out, provider='outlook')
        [row] = self.rows()
        self.assertNotIn('eml_path', row)
        self.assertEqual(row['subject'], 'Invoice')
        self.assertEqual(row['body'], 'Your invoice x x')
        serving._validated_record(row, 1)
        summary = importer.convert([self.dir / 'big.eml'], self.out, provider='outlook', oversized='skip')
        self.assertEqual(summary['counts'], {'read': 1, 'oversized_skipped': 1})
        self.assertEqual(self.rows(), [])

    def test_text_rows_respect_the_content_api_limits(self):
        import app
        fields = app.ContentRequest.model_fields
        limits = {name: next(m.max_length for m in fields[name].metadata if hasattr(m, 'max_length'))
                  for name in ('subject', 'body')}
        self.assertEqual(limits, {'subject': importer.MAX_TEXT_SUBJECT, 'body': importer.MAX_TEXT_BODY})
        body = 'word ' * (importer.MAX_TEXT_BODY // 4)
        (self.dir / 'long.eml').write_text(message('Long', body=body))
        summary = importer.convert([self.dir / 'long.eml'], self.out, provider='gmail')
        self.assertEqual(summary['counts'], {'read': 1, 'text_too_long': 1})
        self.assertEqual(self.rows(), [])

    def test_oversized_copies_with_the_same_text_are_kept_once(self):
        html = '<style>' + 'p{} ' * importer.MAX_EML_BYTES + '</style><p>Your invoice</p>'
        for day, name in (('Tue, 03 Jun 2025 10:00:00 +0000', 'a.eml'), ('Wed, 04 Jun 2025 10:00:00 +0000', 'b.eml')):
            (self.dir / name).write_text(message('Invoice', date=day, body=html).replace('text/plain', 'text/html'))
        summary = importer.convert([self.dir], self.out, provider='gmail')
        self.assertEqual(summary['counts'], {'read': 2, 'duplicate': 1, 'written': 1, 'mode_text': 1})
        rows = self.rows()
        self.assertEqual(len({serving._prepare_record(row)[1] for row in rows}), len(rows))

    def test_since_filter_and_folder_recursion(self):
        folder = self.dir / 'export'
        (folder / 'nested').mkdir(parents=True)
        (folder / 'nested' / 'old.eml').write_text(message('Old', date='Mon, 06 Jan 2020 10:00:00 +0000'))
        (folder / 'new.eml').write_text(message('New'))
        (folder / 'notes.txt').write_text('not mail')
        summary = importer.convert([folder], self.out, provider='gmail', since='2025-01-01')
        self.assertEqual(summary['counts'], {'read': 2, 'before_since': 1, 'written': 1, 'mode_eml': 1})
        self.assertEqual(summary['date_range'], ['2025-06-04', '2025-06-04'])

    def test_output_must_not_be_committed(self):
        (self.dir / 'a.eml').write_text(message('Hi'))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            importer.main([str(self.dir / 'a.eml'), '--output', str(importer.PROJECT_ROOT / 'website'),
                           '--provider', 'gmail'])
        self.assertFalse(importer._inside_repository_outside_ignored(importer.PROJECT_ROOT / '.evaluation-data' / 'x'))
        self.assertFalse(importer._inside_repository_outside_ignored(self.out))
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(importer.main([str(self.dir / 'a.eml'), '--output', str(self.out),
                                            '--provider', 'gmail']), 0)
        self.assertNotIn('Hi', stdout.getvalue().split('Next:')[0].replace('"', ' '))


if __name__ == '__main__':
    unittest.main()
