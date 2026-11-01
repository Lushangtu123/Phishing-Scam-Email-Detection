"""ARC lowers the risk only for the header instances its newest seal signed, in a header block both parsers read
alike (ARC review E1). Real seals with a throwaway key and a stand-in DNS answer; nothing is looked up."""
import sys
import unittest
from email import errors
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dkim  # noqa: E402

import email_structure as es  # noqa: E402
from arc_test_keys import make_key  # noqa: E402
from server_messages import text as message_text  # noqa: E402

GMAIL_SIGNS = (b'to', b'subject', b'message-id', b'date', b'from', b'reply-to', b'cc')


def results(domain='paypal.com', dmarc='pass', spf='pass', dkim_result='pass', with_dmarc=True):
    clauses = [f'dkim={dkim_result} header.d={domain}', f'spf={spf} smtp.mailfrom={domain}']
    if with_dmarc:
        clauses.append(f'dmarc={dmarc} header.from={domain}')
    return 'Authentication-Results: mx.google.com; ' + '; '.join(clauses) + '\r\n'


def message(sender='"PayPal" <service@paypal.com>', domain='paypal.com', extra='', auth=None) -> bytes:
    return ((auth or results(domain))
            + f'From: {sender}\r\nTo: member@example.org\r\n{extra}Subject: Receipt for your payment\r\n'
              'Date: Thu, 29 Oct 2026 10:00:00 +0000\r\nMessage-ID: <receipt@example.org>\r\nMIME-Version: 1.0\r\n'
              'Content-Type: text/plain; charset=utf-8\r\n\r\nYou sent $25.00 USD to Example Store.\r\n').encode()


def prepend(raw: bytes, lines: str) -> bytes:
    return lines.encode() + raw


class Sealing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.txt_record = make_key()

    def setUp(self):
        es._ARC_KEY_CACHE.clear()

    def dns(self, name, timeout=5):
        return self.txt_record

    def seal(self, raw: bytes, leave_out=()) -> bytes:
        """As Gmail signs: each of these headers the message has, once, and its own ARC-Authentication-Results."""
        head = raw.split(b'\r\n\r\n', 1)[0]
        names = {line.split(b':', 1)[0].lower() for line in head.split(b'\r\n') if b':' in line and line[:1] != b' '}
        include = [name for name in GMAIL_SIGNS if name in names and name not in leave_out]
        return b''.join(dkim.arc_sign(raw, b'arc-test', b'google.com', self.private_key, b'mx.google.com',
                                      include_headers=include + [b'arc-authentication-results'])) + raw

    def reseal(self, raw: bytes, domain='paypal.com') -> bytes:
        """A second google.com set over the first, as Gmail forwarding to Gmail adds."""
        return self.seal(prepend(raw, f'Authentication-Results: mx.google.com; arc=pass (i=1); dkim=pass '
                                      f'header.d={domain}; spf=pass smtp.mailfrom={domain}; dmarc=pass '
                                      f'header.from={domain}\r\n'))

    def analyze(self, raw: bytes) -> dict:
        with patch.object(es, '_arc_dns_txt', self.dns):
            return es.analyze_raw_email(raw)


def codes(structure):
    return [item['code'] for item in structure['indicators']]


class SignedHeaders(Sealing):
    def test_a_fully_signed_message_still_lowers(self):
        structure = self.analyze(self.seal(message()))
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertEqual(structure['verified_official_sender'], {'organization': 'PayPal', 'domain': 'paypal.com'})
        self.assertIs(structure['arc_downgrade_allowed'], True)
        self.assertIsNone(structure['arc_downgrade_blocked_by'])
        self.assertFalse({'structure.arc_headers_unsigned', 'structure.arc_headers_unmatched'} & set(codes(structure)))

    def test_each_header_added_above_the_seal_blocks_the_downgrade(self):
        for line, label in (('Subject: Call +1 888 555 0199 now\r\n', 'Subject'), ('To: all@example.org\r\n', 'To'),
                            ('Cc: desk@paypal-help.example.net\r\n', 'Cc'),
                            ('Reply-To: desk@paypal-help.example.net\r\n', 'Reply-To')):
            with self.subTest(label):
                structure = self.analyze(prepend(self.seal(message()), line))
                self.assertEqual(structure['authentication_source'], 'arc')
                self.assertEqual(structure['auth_results'].get('dmarc'), 'pass')
                self.assertIsNone(structure['verified_official_sender'])
                self.assertIsNone(structure['authenticated_sender'])
                self.assertIs(structure['arc_downgrade_allowed'], False)
                self.assertEqual(structure['arc_downgrade_blocked_by'], {'reason': 'unsigned', 'headers': [label]})
                notes = [item for item in structure['indicators'] if item['code'] == 'structure.arc_headers_unsigned']
                self.assertEqual(len(notes), 1)
                self.assertEqual(notes[0]['level'], 'info')
                self.assertEqual(notes[0]['params'], {'headers': label})
                self.assertEqual(notes[0]['msg'], message_text('structure.arc_headers_unsigned', headers=label))
                self.assertEqual(codes(structure).count('structure.arc_sealed_results'), 1)

    def test_the_notice_adds_no_points(self):
        sealed = self.seal(message())
        blocked = self.analyze(prepend(sealed, 'Subject: Receipt for your payment\r\n'))
        unsealed = es.analyze_raw_email(prepend(message(), 'Subject: Receipt for your payment\r\n'), arc_result=None)
        self.assertEqual(blocked['structure_score'], unsealed['structure_score'])
        self.assertEqual(blocked['risk_floor'], unsealed['risk_floor'])

    def test_unsigned_headers_are_listed_in_order(self):
        structure = self.analyze(prepend(self.seal(message()), 'Subject: Hold\r\nCc: desk@example.net\r\n'))
        self.assertEqual(structure['arc_downgrade_blocked_by'], {'reason': 'unsigned', 'headers': ['Cc', 'Subject']})

    def test_a_header_there_when_sealed_but_not_signed_blocks(self):
        raw = self.seal(message(extra='Cc: joint@example.org\r\n'), leave_out=(b'cc',))
        self.assertEqual(self.analyze(raw)['arc_downgrade_blocked_by'], {'reason': 'unsigned', 'headers': ['Cc']})

    def test_an_authenticated_sender_is_blocked_too(self):
        sender, domain = '"Northwind Billing" <billing@northwind-traders.example>', 'northwind-traders.example'
        sealed = self.seal(message(sender, domain))
        self.assertIsNotNone(self.analyze(sealed)['authenticated_sender'])
        structure = self.analyze(prepend(sealed, 'Subject: Overdue - call +1 888 555 0199\r\n'))
        self.assertIsNone(structure['authenticated_sender'])
        self.assertIs(structure['arc_downgrade_allowed'], False)

    def test_sealed_failures_still_raise_when_blocked(self):
        decisive = message(auth=results(dmarc='fail', spf='fail', dkim_result='fail'))
        partial = message(auth=results(spf='fail', with_dmarc=False))
        for raw, code, floor in ((decisive, 'structure.auth_failed', 'high'),
                                 (partial, 'structure.auth_partial_failure', 'safe')):
            with self.subTest(code):
                structure = self.analyze(prepend(self.seal(raw), 'Subject: Hold\r\n'))
                self.assertIs(structure['arc_downgrade_allowed'], False)
                self.assertIn(code, codes(structure))
                self.assertEqual(structure['risk_floor'], floor)

    def test_the_newest_seal_decides(self):
        between = prepend(self.seal(message()), 'Reply-To: "PayPal" <service@paypal.com>\r\n')
        structure = self.analyze(self.reseal(between))
        self.assertIs(structure['arc_downgrade_allowed'], True)
        self.assertEqual(structure['verified_official_sender']['organization'], 'PayPal')
        after = prepend(self.reseal(self.seal(message())), 'Subject: Hold\r\n')
        self.assertEqual(self.analyze(after)['arc_downgrade_blocked_by'], {'reason': 'unsigned', 'headers': ['Subject']})


class HeaderBlocksReadAlike(Sealing):
    def assert_unmatched(self, raw):
        structure = self.analyze(raw)
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertIs(structure['arc_downgrade_allowed'], False)
        self.assertEqual(structure['arc_downgrade_blocked_by'], {'reason': 'unmatched', 'headers': []})
        notes = [item for item in structure['indicators'] if item['code'] == 'structure.arc_headers_unmatched']
        self.assertEqual(len(notes), 1)
        self.assertEqual((notes[0]['level'], notes[0]['params']), ('info', {}))
        self.assertEqual(notes[0]['msg'], message_text('structure.arc_headers_unmatched'))

    def test_same_counts_with_different_instances(self):
        """A lone CR in unsigned X- headers gives Python its own From, To and Subject and ends its header block
        early; each D header still appears once to each parser."""
        raw = prepend(self.seal(message()), 'X-A: a\rFrom: "PayPal" <service@paypal.com>\rTo: member@example.org\r'
                                             'Subject: Call +1 888 555 0199\r\nX-B: b\r\r\nX-C: Your account is on '
                                             'hold. Call +1 888 555 0199.\r\n')
        self.assert_unmatched(raw)

    def test_a_subject_only_python_reads(self):
        self.assert_unmatched(prepend(self.seal(message()), 'X-Ref: 7\rSubject: Call +1 888 555 0199\r\n'))

    def test_a_lone_cr_that_leaves_both_header_lists_alike(self):
        """Just before the blank line: both parsers list the same headers, but Python's block ends a line early."""
        head, body = self.seal(message()).split(b'\r\n\r\n', 1)
        self.assert_unmatched(head + b'\r\nX-Tail: v\r\r\n\r\n' + body)

    def test_an_mbox_from_line_in_the_header_block(self):
        self.assert_unmatched(prepend(self.seal(message()), 'X-Ref: 1\r\nFrom someone@example.org Thu Oct 29 2026\r\n'))


class SealViewContract(unittest.TestCase):
    """The parts of the view and the decision that no message can show apart (they are redundant on purpose)."""

    def test_the_bottom_instance_is_the_signed_one(self):
        data = b'Subject: added\r\nFrom: a@example.org\r\nSubject: original\r\n\r\nbody\r\n'
        view = es._seal_view(data, [b'subject', b'from'])
        self.assertEqual(view.signed, frozenset({1, 2}))

    def test_an_mbox_from_line_makes_the_view_unclean(self):
        data = b'X-Ref: 1\r\nFrom someone@example.org Thu Oct 29 2026\r\nFrom: a@example.org\r\n\r\nbody\r\n'
        self.assertFalse(es._seal_view(data, [b'from']).clean)
        self.assertTrue(es._seal_view(b'From: a@example.org\r\n\r\nbody\r\n', [b'from']).clean)

    def test_a_structural_defect_in_pythons_parse_means_unmatched(self):
        data = b'From: a@example.org\r\nSubject: s\r\n\r\nbody\r\n'
        view = es._seal_view(data, [b'from', b'subject'])

        class Parsed:
            defects = [errors.MissingHeaderBodySeparatorDefect()]

            @staticmethod
            def raw_items():
                return [('From', 'a@example.org'), ('Subject', 's')]
        self.assertEqual(es._arc_downgrade_block(Parsed, view), {'reason': 'unmatched', 'headers': []})
        Parsed.defects = []
        self.assertIsNone(es._arc_downgrade_block(Parsed, view))

    def test_an_answer_without_a_view_never_lowers(self):
        raw = message()
        structure = es.analyze_raw_email(raw, arc_result=('google.com', results().split(': ', 1)[1].strip()))
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertEqual(structure['arc_downgrade_blocked_by'], {'reason': 'unmatched', 'headers': []})


if __name__ == '__main__':
    unittest.main()
