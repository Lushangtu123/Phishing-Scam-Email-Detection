"""Account-hold lures in PDF attachments: the body is empty, the PDF says the account or a
payment is held and links off the sender's domain (synthetic inputs, text rules only)."""
import asyncio
import base64
import json
import sys
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

import content_rules  # noqa: E402
import email_structure as es  # noqa: E402


def pdf(lines, links=()) -> bytes:
    """A one-page PDF with the lines as text and the links as link annotations."""
    content = b'BT /F1 11 Tf 72 720 Td ' + b' 0 -14 Td '.join(b'(%s) Tj' % line.encode() for line in lines) + b' ET'
    stream = zlib.compress(content)
    annotations = b''.join(b'%d 0 obj << /Type /Annot /Subtype /Link /A << /S /URI /URI (%s) >> >> endobj\n'
                           % (10 + index, link.encode()) for index, link in enumerate(links))
    return b''.join([
        b'%PDF-1.4\n',
        b'1 0 obj << /Type /Page /Resources << /Font << /F1 3 0 R >> >> /Contents 2 0 R >> endobj\n',
        b'2 0 obj << /Length ', str(len(stream)).encode(), b' /Filter /FlateDecode >> stream\n', stream,
        b'\nendstream endobj\n',
        b'3 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n', annotations, b'%%EOF'])


def analyze(document: bytes, sender='Member Services <alerts@member-notice.com>', body='') -> dict:
    encoded = base64.encodebytes(document).decode()
    raw = (f'From: {sender}\r\nTo: user@example.org\r\nSubject: Account notice\r\nMIME-Version: 1.0\r\n'
           'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
           f'{body}\r\n--b\r\nContent-Type: application/pdf; name="notice.pdf"\r\n'
           'Content-Disposition: attachment; filename="notice.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
           f'{encoded}\r\n--b--\r\n').encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def finding(result):
    return next((item for item in result['extra_indicators'] if item.get('code') == 'content.attachment_account_lure'),
                None)


RESTRICTED = ['Dear Member, for security reasons your online account has been', 'temporarily restricted.',
              'Click below to verify your account information.']


class AccountHoldWordingTests(unittest.TestCase):
    def test_lures(self):
        for text in ('Your login access has been compromised. Please verify your information immediately.',
                     'We have temporarily prevented access to your account. Sign-On to confirm your identity.',
                     'For security reasons your payment has been put on hold. Kindly logon below to verify.',
                     'Your account has expired. Kindly use the button below to update your account.',
                     'Failure to update your account within 48 hours will result in suspension. Log on now.',
                     # A negation elsewhere in the sentence.
                     'If your account is not updated now, it will be temporarily restricted. Log in to update.',
                     # A line break inside the sentence, as PDF text has.
                     'your access to online banking\nis limited. You are required to verify your details.'):
            with self.subTest(text=text):
                self.assertTrue(content_rules._account_hold_lure(text))

    def test_genuine_wording(self):
        for text in ('Your card expired last month. Update your payment method to keep your plan.',
                     'Your account has not been compromised. You can log in as usual.',
                     "Your payment hasn't been put on hold. Log in to see it.",
                     'Restricted data center access is required for this role. Log in to the portal to apply.',
                     'Your account is active. Log in to view your statement.',
                     # A held account with nothing to do about it.
                     'Your account has been closed as you requested. Thank you for banking with us.'):
            with self.subTest(text=text):
                self.assertFalse(content_rules._account_hold_lure(text))


class AttachmentAccountLureTests(unittest.TestCase):
    def test_an_empty_body_and_a_lure_in_the_pdf(self):
        result = analyze(pdf(RESTRICTED, ['https://www.examplebank.com/', 'http://secure-check.example.net/x.htm']))
        item = finding(result)
        self.assertIsNotNone(item)
        self.assertEqual(item['params']['domain'], 'www.examplebank.com')
        self.assertEqual([prefix['code'] for prefix in item['prefixes']], ['prefix.pdf_text'])
        self.assertEqual(result['risk_level'], 'high')
        self.assertIn('credential', result['mail_type']['tactics'])

    def test_links_to_the_senders_own_or_an_official_domain(self):
        own = analyze(pdf(RESTRICTED, ['https://secure.examplebank.com/logon']), sender='Bank <alerts@examplebank.com>')
        self.assertIsNone(finding(own))
        official = analyze(pdf(RESTRICTED, ['https://www.wellsfargo.com/']))
        self.assertIsNone(finding(official))

    def test_the_wording_and_a_link_are_both_needed(self):
        self.assertIsNone(finding(analyze(pdf(RESTRICTED))))
        statement = ['Your monthly statement is ready.', 'Log in to view your account activity.']
        self.assertIsNone(finding(analyze(pdf(statement, ['https://portal.example.net/']))))


if __name__ == '__main__':
    unittest.main()
