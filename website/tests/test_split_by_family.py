"""split_by_family.py: header-only family keys and the development/holdout split of the
2026-10-13 evaluation plan. Every message here is synthetic, in a temporary directory."""
from collections import Counter
import contextlib
import io
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_serving_pipeline as serving  # noqa: E402
from tools import split_by_family as splitter  # noqa: E402

FRESH = 'Thu, 15 Oct 2026 09:00:00 +0000'


def eml(sender, subject, received=FRESH, reply_to=None, body='Synthetic body.'):
    headers = ([f'Received: from relay.example.net by mx.example.org with ESMTPS id synthetic; {received}']
               if received else [])
    headers += [f'From: {sender}', 'To: reader@example.org', f'Subject: {subject}', 'Date: Wed, 14 Oct 2026 08:00:00 +0000']
    if reply_to:
        headers.append(f'Reply-To: {reply_to}')
    return ('\r\n'.join(headers) + '\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n' + body + '\r\n').encode()


class SplitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.count = 0
        # A fixed ledger secret makes each holdout draw repeatable.
        secret = patch.object(splitter.secrets, 'token_hex', lambda size: '5a' * size)
        secret.start()
        self.addCleanup(secret.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def row(self, raw, label='legitimate', provider='gmail', language='en'):
        self.count += 1
        path = self.dir / f'{self.count}.eml'
        path.write_bytes(raw)
        return {'provider': provider, 'label': label, 'language': language, 'received_at': '2026-10-15',
                'eml_path': str(path)}

    def families(self, rows, **kwargs):
        cohorts, ledger, counts = splitter.split(rows, **kwargs)
        by_path = {}
        for role in splitter.ROLES:
            for item in cohorts[role]:
                by_path[item['digest']] = (item['row']['family_id'], role)
        return cohorts, ledger, counts, by_path

    def test_only_the_header_block_is_read(self):
        raw = eml('Billing <billing@shop.example>', 'Invoice 4471',
                  body='From: someone@elsewhere.example\r\nReply-To: x@elsewhere.example\r\nSubject: other')
        self.assertEqual(splitter.header_block(raw).count(b'From:'), 1)
        self.assertEqual(splitter.read_headers(raw, 'phishing'),
                         (['phishing|organisation:shop.example', 'phishing|subject:invoice'], '2026-10-15'))

    def test_legitimate_mail_is_one_family_per_organisation(self):
        # Sibling hosts of one registrable domain (here under the reserved example.com).
        rows = [self.row(eml('Shop <news@example.com>', 'Weekly offers')),
                self.row(eml('Shop <orders@mail.example.com>', 'Your order shipped')),
                self.row(eml('Alex <alex@gmail.com>', 'Lunch?')),
                self.row(eml('Sam <sam@gmail.com>', 'Lunch?'))]
        *_, families = self.families(rows)
        family_ids = [family for family, _role in families.values()]
        self.assertEqual(len(set(family_ids)), 3)

    def test_phishing_campaigns_merge_on_sender_reply_to_and_subject_template(self):
        rows = [self.row(eml('Desk <a@one.example>', 'Mailbox 88213 is full'), 'phishing'),
                self.row(eml('Desk <b@two.example>', 'Mailbox 10456 is FULL', reply_to='keep@three.example'), 'phishing'),
                self.row(eml('Desk <c@four.example>', 'Final notice', reply_to='keep@three.example'), 'phishing'),
                self.row(eml('邮件中心 <d@five.example>', '回复：您的邮箱 8 小时后停用'), 'phishing'),
                self.row(eml('邮件中心 <e@six.example>', '您的邮箱 12 小时后停用'), 'phishing'),
                # Legitimate mail with the same subject is another family: templates join campaigns only.
                self.row(eml('Host <ops@seven.example>', 'Mailbox 1 is full'))]
        *_, families = self.families(rows)
        ids = list(dict.fromkeys(family for family, _role in families.values()))
        self.assertEqual(len(ids), 3)
        self.assertEqual(splitter.subject_template('RE: Fwd: Invoice INV20261015 for 3 items'), 'invoice * for # items')
        self.assertIsNone(splitter.subject_template('Re: 12345'))

    def test_development_data_keeps_its_whole_family_out_of_holdout(self):
        seen_row = self.row(eml('Ops <ops@seen.example>', 'Status'))
        rows = [self.row(eml('Ops <ops@seen.example>', 'Status again')),
                self.row(eml('Shop <a@stale.example>', 'Old', received='Tue, 13 Oct 2026 23:00:00 -0700')),
                self.row(eml('Shop <b@stale.example>', 'New')),
                self.row(eml('News <a@undated.example>', 'No header', received=None)),
                self.row(eml('News <b@undated.example>', 'Fresh')),
                self.row(eml('Fresh <a@fresh.example>', 'Hello'))]
        # A share near 1 sends every family that may be holdout there.
        cohorts, _ledger, counts, families = self.families(rows, seen=[seen_row], holdout_share=0.999999)
        roles = Counter(role for _family, role in families.values())
        self.assertEqual(roles, {'development': 6, 'holdout': 1})
        self.assertEqual(counts['families_holdout'], 1)
        self.assertEqual((counts['development_because_seen'], counts['development_because_not_fresh'],
                          counts['development_because_no_provider_date']), (1, 1, 1))
        # The provider's Received date (UTC) replaces the Date header's.
        stale = next(item['row'] for item in cohorts['development'] if item['row']['received_at'] == '2026-10-14')
        self.assertEqual(stale['date_source'], 'provider_received_header')

    def test_a_holdout_family_contributes_its_three_earliest_messages(self):
        rows = [self.row(eml('Bank <alerts@bank.example>', f'Alert {day}', received=f'{day} Oct 2026 09:00:00 +0000'))
                for day in (19, 15, 18, 16, 17)]
        cohorts, _ledger, counts, _families = self.families(rows, holdout_share=0.999999)
        self.assertEqual(sorted(item['row']['received_at'] for item in cohorts['holdout']),
                         ['2026-10-15', '2026-10-16', '2026-10-17'])
        self.assertEqual((counts['messages_holdout'], counts['messages_set_aside'], len(cohorts['development'])), (3, 2, 0))

    def test_the_ledger_keeps_assignments_and_never_returns_a_family_to_holdout(self):
        held = self.row(eml('Desk <a@held.example>', 'Account review pending'), 'phishing')
        seen = self.row(eml('Desk <b@dev.example>', 'Quota exceeded notice'), 'phishing')
        _cohorts, ledger, _counts, first = self.families([held], seen=[seen], holdout_share=0.999999)
        self.assertEqual(sorted(role for _family, role in first.values()), ['development', 'holdout'])
        # Again with the ledger: nothing changes, and new mail of the held family joins it.
        again = self.row(eml('Desk <c@held.example>', 'Account review pending'), 'phishing')
        cohorts, ledger2, counts, second = self.families([held, again], seen=[seen], previous=ledger, holdout_share=0.999999)
        self.assertEqual(counts['messages_holdout'], 2)
        self.assertEqual({family for family, role in second.values() if role == 'holdout'},
                         {family for family, role in first.values() if role == 'holdout'})
        # The development family stays there when its mail comes back without --seen.
        _cohorts, _ledger, _counts, returned = self.families([seen], previous=ledger, holdout_share=0.999999)
        self.assertEqual([role for _family, role in returned.values()], ['development'])
        # A message that joins both families (the held sender, the development subject) moves
        # the held family to development as a whole.
        bridge = self.row(eml('Desk <d@held.example>', 'Quota exceeded notice'), 'phishing')
        cohorts, _ledger3, counts, third = self.families([held, again, bridge], seen=[seen], previous=ledger2,
                                                         holdout_share=0.999999)
        self.assertEqual((len(cohorts['holdout']), counts['families_moved_to_development']), (0, 1))
        self.assertEqual(len({family for family, _role in third.values()}), 1)
        with self.assertRaisesRegex(ValueError, 'stay as in the previous ledger'):
            splitter.split([held], previous=ledger2, holdout_share=0.5)

    def test_text_rows_and_duplicates_are_skipped_and_label_conflicts_refused(self):
        raw = eml('Shop <a@shop.example>', 'Hello')
        text = {'provider': 'gmail', 'label': 'legitimate', 'received_at': '2026-10-15', 'subject': 'S', 'body': 'B'}
        _cohorts, _ledger, counts = splitter.split([self.row(raw), self.row(raw), text])
        self.assertEqual((counts['input_rows'], counts['skipped_duplicates'], counts['skipped_text_rows']), (3, 1, 1))
        with self.assertRaisesRegex(ValueError, 'two labels'):
            splitter.split([self.row(raw), self.row(raw, label='phishing')])

    def test_written_cohorts_are_private_separate_and_reported_as_counts(self):
        rows = [self.row(eml('Bank <alerts@bank.example>', 'Sign-in alert')),
                self.row(eml('Shop <a@shop.example>', 'Receipt'), language='zh'),
                self.row(eml('Desk <x@desk.example>', 'Mailbox full'), 'phishing', provider='outlook')]
        source = self.dir / 'messages.jsonl'
        source.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        development, holdout = self.dir / 'development', self.dir / 'holdout'
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            splitter.main(['--input', str(source), '--development-dir', str(development), '--holdout-dir', str(holdout)])
        printed = output.getvalue()
        for secret in ('bank.example', 'shop.example', 'desk.example', 'Sign-in', 'Receipt', 'Mailbox'):
            self.assertNotIn(secret, printed)
        summary = json.loads(printed[:printed.rindex('}') + 1])
        self.assertEqual(summary['counts']['input_rows'], 3)
        self.assertEqual(sum(summary['holdout_cells'].values()), summary['counts'].get('messages_holdout', 0))
        written = 0
        for role, directory in (('development', development), ('holdout', holdout)):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for index, line in enumerate((directory / 'messages.jsonl').read_text().splitlines(), 1):
                row = json.loads(line)
                self.assertIs(serving._validated_record(row, index), row)
                self.assertEqual(row['cohort_role'], role)
                self.assertTrue(Path(row['eml_path']).is_relative_to(directory.resolve()))
                self.assertEqual(stat.S_IMODE(Path(row['eml_path']).stat().st_mode), 0o600)
                written += 1
        self.assertEqual(written, 3)
        ledger = (holdout / 'ledger.json').read_text()
        self.assertFalse((development / 'ledger.json').exists())
        for secret in ('bank.example', 'shop.example', 'desk.example', 'Mailbox', 'alerts@'):
            self.assertNotIn(secret, ledger)
        # Separate directories, outside the repository.
        cohorts, ledger_data, _counts = splitter.split(rows)
        with self.assertRaisesRegex(ValueError, 'separate'):
            splitter.write_split(cohorts, ledger_data, self.dir / 'h2' / 'dev', self.dir / 'h2')
        with self.assertRaisesRegex(ValueError, 'outside the Git repository'):
            splitter.write_split(cohorts, ledger_data, WEBSITE_DIR.parent / '.evaluation-data' / 'dev', self.dir / 'h3')


if __name__ == '__main__':
    unittest.main()
