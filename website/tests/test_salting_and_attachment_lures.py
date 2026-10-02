"""Hidden-text salting, attachment names Windows reads differently, mailbox lures in Word and
PDF attachments, and further file-sharing and account-hold wording (synthetic inputs, text
rules only)."""
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
import email_structure as es  # noqa: E402

FILLER = ('The first game was played on November 6, 1869, between Rutgers and Princeton, two college teams. '
          'They consisted of 25 players per team and used a round ball that could not be picked up. ') * 2


def analyze_raw(raw: bytes) -> dict:
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def html_mail(body, sender='Package Notification <track@parcel-notice.example.com>'):
    return (f'From: {sender}\r\nTo: user@example.org\r\nSubject: Delivery\r\n'
            'Content-Type: text/html; charset=utf-8\r\n\r\n' + body).encode()


def codes(result):
    return {item.get('code') for item in result['extra_indicators']}


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


def with_attachment(data: bytes, filename: str, content_type: str, sender='Admin <help@desk-notice.com>') -> bytes:
    encoded = base64.encodebytes(data).decode()
    return (f'From: {sender}\r\nTo: user@example.org\r\nSubject: Notice\r\nMIME-Version: 1.0\r\n'
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            f'\r\n--b\r\nContent-Type: {content_type}; name="{filename}"\r\n'
            f'Content-Disposition: attachment; filename="{filename}"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
            f'{encoded}\r\n--b--\r\n').encode()


class HiddenPaddingTests(unittest.TestCase):
    """Text in its background's colour, padding the message for filters."""

    def test_white_filler_under_a_lure(self):
        body = ('<a href="https://parcel-notice.example.com/r"><b>Sorry we missed you! Schedule your next delivery '
                f'date.</b></a><p style="color:#FFFFFF;font-size:8px;">{FILLER}</p>')
        result = analyze_raw(html_mail(body))
        item = next(item for item in result['extra_indicators'] if item.get('code') == 'content.hidden_padding')
        self.assertEqual(item['level'], 'medium')
        self.assertGreaterEqual(item['params']['letters'], 200)
        self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})

    def test_text_that_is_no_padding(self):
        for body in (
                # A short preheader.
                '<span style="color:#ffffff;font-size:1px">Your weekly summary is here</span><p>Hello</p>',
                # White text on a dark background is visible.
                f'<div style="background:#222"><p style="color:#fff">{FILLER}</p></div>',
                f'<p>{FILLER}</p>'):
            with self.subTest(body=body[:60]):
                self.assertNotIn('content.hidden_padding', codes(analyze_raw(html_mail(body))))


class AttachmentNameTests(unittest.TestCase):
    """Windows drops trailing dots and spaces: "vm.htm." opens as a web page."""

    def test_trailing_dots_and_spaces(self):
        page = b'<script>window.location.href = "https://voice.example.net/play";</script>'
        for filename in ('vm_0526.htm.', 'vm_0526.htm. .', 'invoice.html '):
            with self.subTest(filename=filename):
                result = analyze_raw(with_attachment(page, filename, 'application/octet-stream'))
                self.assertIn('structure.dangerous_attachment', codes(result))
        self.assertNotIn('structure.dangerous_attachment',
                         codes(analyze_raw(with_attachment(b'%PDF-1.4\n%%EOF', 'statement.pdf.', 'application/pdf'))))


class AttachmentMailboxLureTests(unittest.TestCase):
    """A mailbox lure in a document attachment, linking off the sender's domain."""

    def test_a_quota_notice_in_a_pdf(self):
        document = pdf(['Dear User, your email account mailbox requires immediate update.',
                        'Click here for reactivation of your web-mail account.'], ['http://mailfix.example-host.net/'])
        result = analyze_raw(with_attachment(document, 'notice.pdf', 'application/pdf'))
        item = next(item for item in result['extra_indicators'] if item.get('code') == 'content.attachment_mailbox_lure')
        self.assertEqual(item['params'], {'domain': 'mailfix.example-host.net'})
        self.assertEqual(result['risk_level'], 'high')
        self.assertIn('credential', result['mail_type']['tactics'])

    def test_no_mailbox_lure(self):
        for lines, links in (
                # "This email" beside "pending" says nothing about a mailbox.
                (['This email is to notify you that there is a payment pending on your account.'],
                 ['http://pay.example-host.net/']),
                # The wording, with a link to the sender's own domain.
                (['Your mailbox is almost full. Upgrade your storage.'], ['https://desk-notice.com/storage'])):
            with self.subTest(lines=lines):
                result = analyze_raw(with_attachment(pdf(lines, links), 'notice.pdf', 'application/pdf'))
                self.assertNotIn('content.attachment_mailbox_lure', codes(result))


class WordingTests(unittest.TestCase):
    def test_file_share_notices(self):
        for text in ('Remittance Document Shared With You. Open it in Google Drive.',
                     'A file located in Google Drive was shared with you.',
                     'You have pending docs shared with you via Google Drive.'):
            with self.subTest(text=text):
                self.assertTrue(app._FILE_SHARE_NOTICE.search(text))
        self.assertEqual(app._file_share_elsewhere(
            'Remittance Document Shared With You. You have received this email because a file located in Google '
            'Drive was shared with you.', '', [('Open', 'https://keap.example.app/contact-us/1')]),
            ('Google Drive', 'keap.example.app'))

    def test_account_hold(self):
        self.assertTrue(app._account_hold_lure(
            'Due to recent fraudulent activities, to regain full access to your account kindly log in below.'))
        # A genuine reset: "regain access" without the threat.
        self.assertFalse(app._account_hold_lure(
            'To complete this process and regain access to your account, please click the secure link below to log in.'))

    def test_mailbox_states(self):
        for text in ('Your email account mailbox requires immediate update.',
                     'Click here for reactivation of your web-mail account.'):
            with self.subTest(text=text):
                self.assertTrue(app._MAILBOX_LURE_OTHER.search(text))


if __name__ == '__main__':
    unittest.main()
