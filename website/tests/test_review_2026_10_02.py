"""Regressions from the review of 2026-10-02 at 06dfbb7: gradient stops this reader cannot
compute, backgrounds browsers reject, lure rules in every rendering view, published
documents under a claimed platform From, PDF fonts scoped by page, and malformed PDF fonts
(synthetic inputs, text rules only)."""
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
import html_visibility  # noqa: E402
from hidden_findings import hidden_codes, shown_codes  # noqa: E402
import email_structure as es  # noqa: E402

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
MAILBOX = ('<p>Your mailbox storage is full and incoming messages are on hold.</p>'
           '<a href="{link}">Release messages</a>')


def analyze(body, subject='Project update'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def analyze_eml(raw: bytes):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def eml(sender, html):
    return (f'From: {sender}\r\nTo: user@example.org\r\nSubject: Project update\r\n'
            'Content-Type: text/html; charset=utf-8\r\n\r\n' + html).encode()


def codes(result):
    # Findings in what the message shows; hidden_codes lists those only text it may hide makes.
    return shown_codes(result)


def styled_callback(background):
    return (f'<style>.unused{{display:none}}.attack{{color:black;background:{background}}}</style>'
            f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>')


class GradientTests(unittest.TestCase):
    """S1: a stop this reader cannot compute is unknown, never dropped."""

    def test_an_unresolved_stop_keeps_the_text(self):
        result = analyze(styled_callback('linear-gradient(black 0%,color-mix(in srgb,white,white) 0%)'))
        self.assertEqual(result['risk_level'], 'high')
        self.assertEqual(html_visibility._gradient_stops('linear-gradient(black 0%,color-mix(in srgb,white,white) 0%)'),
                         ['black', None])

    def test_a_one_colour_gradient_still_paints_that_colour(self):
        # Browsers accept linear-gradient(black): black text on it cannot be read.
        self.assertEqual(html_visibility._background_parts('linear-gradient(black)'), (None, False, 'black'))

    def test_backgrounds_browsers_reject_are_dropped(self):
        # Each value below was checked with Chromium's CSS.supports('background', value).
        for value in ('linear-gradient(banana,black,black)', 'linear-gradient(black banana,black)',
                      'left left black', 'repeat repeat repeat black', 'none none black'):
            with self.subTest(value=value):
                self.assertFalse(html_visibility._background_valid(value))
                self.assertEqual(analyze(styled_callback(value))['risk_level'], 'high')

    def test_what_browsers_accept(self):
        valid = ('#fff url(x.png) no-repeat center / cover', 'transparent none repeat scroll 0 0',
                 'url(x) no-repeat center center / 100% auto #fff', 'url(x) top left / contain no-repeat',
                 'url(x) no-repeat right 10px bottom 20px', 'linear-gradient(to right, #fff 0%, #000 100%)',
                 'radial-gradient(circle at center, red 0, blue 100%)', 'conic-gradient(from 90deg at 50% 50%, red, blue)',
                 'linear-gradient(in oklch longer hue, red, blue)', 'linear-gradient(red, 30%, blue)',
                 'repeating-linear-gradient(45deg, #000 0 10px, #fff 10px 20px)', 'url(x) border-box padding-box')
        invalid = ('url(x) 10px left', 'url(x) left right', 'url(x) / cover', 'url(x) 0 0 0 0 0',
                   'url(x) border-box padding-box content-box', 'linear-gradient(red blue)', 'linear-gradient()',
                   'linear-gradient(top, red, blue)', 'url(x) 10px fixed 20px', 'url(a b)')
        for value in valid:
            with self.subTest(value=value):
                self.assertTrue(html_visibility._background_valid(value))
        for value in invalid:
            with self.subTest(value=value):
                self.assertFalse(html_visibility._background_valid(value))

    def test_whitespace_inside_a_value(self):
        # CSS reads any run of whitespace as one space; the colour stays white.
        self.assertEqual(html_visibility._style_values('color: rgb(255,\n255,255)')['color'][0], 'rgb(255, 255,255)')


class RenderingViewTests(unittest.TestCase):
    """R1: a lure the screen shows is read even when print hides it."""

    def test_print_only_hiding(self):
        for body, code in (
                (MAILBOX.format(link='https://portal.example.org/review'), 'content.mailbox_lure'),
                ('<p>Your parcel could not be delivered due to incorrect address details. Please update your shipping '
                 'address.</p><a href="https://parcel-check.example.org/review">Update Address</a>', 'content.delivery_lure'),
                ('<p>Ana shared a file with you using OneDrive.</p><a href="https://files.example.org/open">Open</a>',
                 'link.file_share_elsewhere'),
                ('<p>Your payment method is no longer valid.</p>'
                 '<a href="https://docs.google.com/document/d/x/view">Update payment</a>', 'link.user_content_action')):
            with self.subTest(code=code):
                html = f'<style>@media print{{.attack{{display:none}}}}</style><div class="attack">{body}</div><p>{PADDING}</p>'
                result = analyze(html)
                self.assertIn(code, codes(result))
                self.assertEqual(result['risk_level'], 'high')

    def test_a_label_hidden_on_every_view_is_not_read(self):
        html = ('<style>.x{display:none}</style><p>Your mailbox storage is full and incoming messages are on hold.</p>'
                '<a class="x" href="https://portal.example.org/review">Release messages</a>')
        result = analyze(html)
        self.assertNotIn('content.mailbox_lure', codes(result))
        # The hidden label is still read as text the message may hide (2026-10-05).
        self.assertIn('content.mailbox_lure', hidden_codes(result))


class ClaimedPlatformSenderTests(unittest.TestCase):
    """R2: a From on the platform's domain does not make a published document its own."""

    def test_a_document_link_under_a_google_from(self):
        body = MAILBOX.format(link='https://docs.google.com/document/d/local-test/view') + f'<p>{PADDING}</p>'
        for sender in ('Test Sender <test.sender@gmail.com>', 'Account Team <test.sender@google.com>'):
            with self.subTest(sender=sender):
                self.assertIn('content.mailbox_lure', codes(analyze_eml(eml(sender, body))))
        self.assertEqual(app._unlisted_off_sender_host('https://docs.google.com/document/d/x/view', 'google.com'),
                         'docs.google.com')
        # The platform's own pages stay the sender's.
        self.assertIsNone(app._unlisted_off_sender_host('https://accounts.google.com/', 'google.com'))

    def test_an_encoded_path(self):
        self.assertTrue(app._user_content_location('https://docs.google.com/%64ocument/d/x/view', actions=True))


def two_page_pdf(first_font_name: bytes) -> bytes:
    """Page 1 defines a font with a scrambling ToUnicode map and draws nothing; page 2
    defines its own /F1 (Helvetica) and draws the callback."""
    content = zlib.compress(b'BT /F1 11 Tf 72 720 Td (If you did not authorize this charge, call 1-888-555-0199.) Tj ET')
    cmap = b'begincmap 1 begincodespacerange <00> <FF> endcodespacerange 1 beginbfrange <20> <7E> <0058> endbfrange endcmap'
    return b''.join([
        b'%PDF-1.4\n',
        b'1 0 obj << /Type /Pages /Kids [2 0 R 3 0 R] /Count 2 >> endobj\n',
        b'2 0 obj << /Type /Page /Parent 1 0 R /Resources << /Font << /' + first_font_name + b' 5 0 R >> >> >> endobj\n',
        b'3 0 obj << /Type /Page /Parent 1 0 R /Resources << /Font << /F1 6 0 R >> >> /Contents 4 0 R >> endobj\n',
        b'4 0 obj << /Length ', str(len(content)).encode(), b' /Filter /FlateDecode >> stream\n', content, b'\nendstream endobj\n',
        b'5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier /ToUnicode 7 0 R >> endobj\n',
        b'6 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n',
        b'7 0 obj << /Length ', str(len(cmap)).encode(), b' >> stream\n', cmap, b'\nendstream endobj\n', b'%%EOF'])


def font_pdf(font_extra: bytes, cmap: bytes | None = None) -> bytes:
    content = zlib.compress(b'BT /F1 11 Tf 72 720 Td (If you did not authorize this charge, call 1-888-555-0199.) Tj ET')
    unicode = b' /ToUnicode 4 0 R' if cmap is not None else b''
    return b''.join([
        b'%PDF-1.4\n',
        b'1 0 obj << /Type /Page /Resources << /Font << /F1 3 0 R >> >> /Contents 2 0 R >> endobj\n',
        b'2 0 obj << /Length ', str(len(content)).encode(), b' /Filter /FlateDecode >> stream\n', content, b'\nendstream endobj\n',
        b'3 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica' + unicode + font_extra + b' >> endobj\n',
        (b'4 0 obj << /Length ' + str(len(cmap)).encode() + b' >> stream\n' + cmap + b'\nendstream endobj\n') if cmap else b'',
        b'%%EOF'])


def pdf_eml(document: bytes) -> bytes:
    encoded = base64.encodebytes(document).decode()
    return ('From: Billing <billing@example.net>\r\nTo: user@example.org\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n'
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            'Please see the attached invoice.\r\n--b\r\nContent-Type: application/pdf; name="invoice.pdf"\r\n'
            'Content-Disposition: attachment; filename="invoice.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
            f'{encoded}\r\n--b--\r\n').encode()


class PdfFontTests(unittest.TestCase):
    """R3 and R4."""

    def test_each_page_uses_its_own_fonts(self):
        for name in (b'F1', b'F0'):
            with self.subTest(first_page_font=name):
                self.assertIn('call 1-888-555-0199', es.pdf_text(two_page_pdf(name)))

    def test_malformed_widths_and_cmap_ranges(self):
        bad_width = font_pdf(b' /FirstChar 32 /LastChar 34 /Widths [.]')
        overflow = font_pdf(b'', b'1 beginbfrange <00> <01> <FFFF> endbfrange')
        huge = font_pdf(b' /FirstChar 32 /Widths [' + b'9' * 400 + b' 500]')
        for document in (bad_width, overflow, huge):
            with self.subTest(document=document[-80:]):
                self.assertIn('1-888-555-0199', es.pdf_text(document))
                result = analyze_eml(pdf_eml(document))
                self.assertIn('content.callback_request', codes(result))

    def test_an_unreadable_document_leaves_the_rest_of_the_message(self):
        with patch.object(es, 'pdf_text', side_effect=RuntimeError('broken')):
            structure = es.analyze_raw_email(pdf_eml(font_pdf(b'')))
        self.assertEqual(structure['attachments'][0]['inspection_status'], 'metadata_only')
        self.assertNotIn('extracted_text', structure['attachments'][0])
        self.assertIn(es.message_text('warning.attachment_unreadable'), structure['parse_warnings'])


if __name__ == '__main__':
    unittest.main()
