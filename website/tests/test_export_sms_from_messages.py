"""Exporting texts from a Messages database for the SMS launch gate (a synthetic chat.db only)."""
import argparse
import csv
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_sms  # noqa: E402
from tools import export_sms_from_messages as tool  # noqa: E402

NS = 10 ** 9


def typedstream(text: str) -> bytes:
    """A minimal attributedBody as newer macOS writes it: the string after NSString."""
    data = text.encode('utf-8')
    length = bytes([len(data)]) if len(data) < 0x80 else b'\x81' + len(data).to_bytes(2, 'little')
    return (b'\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject\x00'
            b'\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+' + length + data + b'\x86\x84\x02iI\x01')


def build_db(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
        CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_identifier TEXT, is_filtered INTEGER);
        CREATE TABLE chat_handle_join (chat_id INTEGER, handle_id INTEGER);
        CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB, handle_id INTEGER,
                              is_from_me INTEGER, date INTEGER);
    """)
    chats = [  # (handle, filtered, [(text, attributedBody, from_me, day)])
        ('95588', 0, [('【工商银行】您的验证码为 482913，请勿泄露。尾号6521的卡今日入账100元。', None, 0, 10),
                      ('【工商银行】您的验证码为 771204，请勿泄露。尾号6521的卡今日入账100元。', None, 0, 11)]),
        ('+12125550199', 0, [('Dinner at 7?', None, 0, 12), ('Sure!', None, 1, 12)]),  # a friend: replied
        ('+639171234567', 1, [(None, typedstream('USPS: your parcel is held. Pay the fee at usps-fee.top/x'), 0, 13)]),
        ('28777', 0, [('USPS: Your code is 381920. Call 13912345678 if this was not you.', None, 0, 14)]),
        ('promo.x9@icloud.com', 1, [('Congratulations! You won a gift card. Text WIN to 55123.', None, 0, 15)]),
        ('+8613800001111', 0, [('Old text', None, 0, 1)]),  # before --since
    ]
    message_id = 0
    for chat_id, (handle, filtered, messages) in enumerate(chats, 1):
        db.execute('INSERT INTO handle VALUES (?, ?)', (chat_id, handle))
        db.execute('INSERT INTO chat VALUES (?, ?, ?)', (chat_id, handle, filtered))
        db.execute('INSERT INTO chat_handle_join VALUES (?, ?)', (chat_id, chat_id))
        for text, body, from_me, day in messages:
            message_id += 1
            db.execute('INSERT INTO message VALUES (?, ?, ?, ?, ?, ?)',
                       (message_id, text, body, chat_id, from_me, (700_000_000 + day * 86400) * NS))
            db.execute('INSERT INTO chat_message_join VALUES (?, ?)', (chat_id, message_id))
    # A group chat with two other people.
    db.execute('INSERT INTO handle VALUES (99, ?)', ('+12125550123',))
    db.execute('INSERT INTO chat VALUES (99, ?, 0)', ('chat-group',))
    db.executemany('INSERT INTO chat_handle_join VALUES (99, ?)', [(1,), (99,)])
    db.execute('INSERT INTO message VALUES (999, ?, NULL, 99, 0, ?)', ('Group plans', 700_000_000 * NS))
    db.execute('INSERT INTO chat_message_join VALUES (99, 999)')
    db.commit()
    db.close()


class ExportSmsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.db = self.root / 'chat.db'
        build_db(self.db)
        self.out = self.root / 'sms-eval'

    def tearDown(self):
        self.directory.cleanup()

    def run_tool(self, *arguments):
        with redirect_stdout(io.StringIO()) as printed:
            tool.main(list(arguments))
        return printed.getvalue()

    def extract(self):
        before = self.db.read_bytes()
        printed = self.run_tool('extract', '--output-dir', str(self.out), '--db', str(self.db), '--since', '2023-03-12',
                                '--own-number', '+86 139 1234 5678')
        self.assertEqual(self.db.read_bytes(), before)  # opened read-only
        with (self.out / 'review.csv').open(encoding='utf-8-sig', newline='') as handle:
            return printed, list(csv.DictReader(handle))

    def test_only_one_way_conversations_masked(self):
        printed, rows = self.extract()
        texts = [row['text'] for row in rows]
        self.assertEqual(len(rows), 4)
        self.assertFalse(any('Dinner' in text or 'Sure' in text or 'Group' in text or 'Old text' in text for text in texts))
        bank = next(row for row in rows if row['sender'] == '95588')
        self.assertEqual(bank['text'], '【工商银行】您的验证码为 000000，请勿泄露。尾号0000的卡今日入账100元。')
        self.assertEqual((bank['copies'], bank['region'], bank['sender_kind']), ('2', 'cn', 'short_code'))
        usps = next(row for row in rows if row['sender'] == '28777')
        self.assertEqual(usps['text'], 'USPS: Your code is 000000. Call [your number] if this was not you.')
        parcel = next(row for row in rows if row['sender_kind'] == 'international')
        self.assertIn('usps-fee.top/x', parcel['text'])  # read from attributedBody; links are kept
        self.assertNotEqual(parcel['sender'], '+639171234567')
        self.assertEqual(parcel['hint'], 'filtered as unknown sender')
        email = next(row for row in rows if row['sender_kind'] == 'email')
        self.assertEqual(email['sender'], 'sender@icloud.com')
        self.assertEqual({row['batch'] for row in rows if row['region'] == 'us'}, {'1', '2'})
        self.assertTrue(all(row['label'] == '' for row in rows))
        for secret in ('482913', '771204', '6521', '381920', '13912345678', 'promo.x9', '+639171234567', 'Dinner'):
            self.assertNotIn(secret, printed)
            self.assertNotIn(secret, '\n'.join(texts) + ''.join(row['sender'] for row in rows))

    def test_finish_writes_the_two_batches(self):
        _printed, rows = self.extract()
        with self.assertRaises(SystemExit):  # unlabelled rows
            self.run_tool('finish', '--output-dir', str(self.out))
        labels = {'95588': 'legitimate', '28777': 'legitimate'}
        for row in rows:
            row['label'] = labels.get(row['sender'], 'scam' if row['sender_kind'] != 'email' else 'skip')
        with (self.out / 'review.csv').open('w', encoding='utf-8-sig', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=tool.COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        summary = json.loads(self.run_tool('finish', '--output-dir', str(self.out)))
        written = [row for batch in (1, 2) for row in evaluate_sms.load_rows(self.out / f'batch{batch}.jsonl')]
        self.assertEqual(sorted(row['label'] for row in written), ['legitimate', 'legitimate', 'scam'])  # skip left out
        self.assertIn('batch1/cn', summary['short_of_50_legitimate'])

    def test_a_labelled_review_is_not_overwritten(self):
        _printed, rows = self.extract()
        rows[0]['label'] = 'scam'
        with (self.out / 'review.csv').open('w', encoding='utf-8-sig', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=tool.COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        with self.assertRaises(SystemExit):
            self.extract()

    def test_the_output_stays_outside_the_repository(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            tool._outside_repository(str(WEBSITE_DIR / 'private'))

    def test_attributed_body_lengths(self):
        self.assertEqual(tool.attributed_text(typedstream('短信' * 100)), '短信' * 100)  # two-byte length
        self.assertEqual(tool.attributed_text(None), '')


if __name__ == '__main__':
    unittest.main()
