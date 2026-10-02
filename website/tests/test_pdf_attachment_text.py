"""PDF attachment text: read like a Word attachment's, and checked only for strong requests."""
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


def pdf(content: bytes, font: bytes = b'/Subtype /Type1 /BaseFont /Helvetica', extra: bytes = b'') -> bytes:
    """A one-page PDF whose page content is compressed, with font /F1."""
    stream = zlib.compress(content)
    return b''.join([
        b'%PDF-1.4\n',
        b'1 0 obj << /Type /Page /Resources << /Font << /F1 3 0 R >> >> /Contents 2 0 R >> endobj\n',
        b'2 0 obj << /Length ', str(len(stream)).encode(), b' /Filter /FlateDecode >> stream\n', stream,
        b'\nendstream endobj\n',
        b'3 0 obj << /Type /Font ', font, b' >> endobj\n', extra, b'%%EOF'])


def stream_object(number: int, data: bytes, compressed: bool = False) -> bytes:
    if compressed:
        data = zlib.compress(data)
    return b''.join([str(number).encode(), b' 0 obj << /Length ', str(len(data)).encode(),
                     b' /Filter /FlateDecode' if compressed else b'', b' >> stream\n', data, b'\nendstream endobj\n'])


CALLBACK = (b'BT /F1 11 Tf 72 720 Td (Your Geek Squad subscription was renewed for $399.99.) Tj '
            b'0 -14 Td (If you did not authorize this charge, call 1-888-555-0199 to cancel.) Tj ET')


class PdfTextTests(unittest.TestCase):
    def test_text_operators(self):
        self.assertEqual(es.pdf_text(pdf(CALLBACK)), 'Your Geek Squad subscription was renewed for $399.99.\n'
                                                     'If you did not authorize this charge, call 1-888-555-0199 to cancel.')
        # A shift of a quarter em or more inside TJ is a word space.
        self.assertEqual(es.pdf_text(pdf(b'BT /F1 12 Tf 72 700 Td [(Hel) 20 (lo) -300 (World)] TJ ET')), 'Hello World')
        self.assertEqual(es.pdf_text(b'not a pdf'), '')

    def test_glyphs_placed_one_by_one_are_joined_by_their_widths(self):
        # A wide "m" (833) and a narrow "i" (222) placed at their real advances, then a gap.
        widths = {ord('D'): 722, ord('e'): 556, ord('a'): 556, ord('r'): 333, ord('M'): 833, ord('m'): 833, ord('b'): 556}
        first, last = 65, 122
        font = (b'/Subtype /Type1 /BaseFont /Helvetica /FirstChar 65 /LastChar 122 /Widths ['
                + b' '.join(str(widths.get(code, 500)).encode() for code in range(first, last + 1)) + b']')
        content, x = [], 72.0
        for word in (b'Dear', b'Member'):
            for character in word:
                content.append(b'1 0 0 1 %.2f 700 Tm (%s) Tj' % (x, bytes([character])))
                x += widths.get(character, 500) * 12 / 1000
            x += 278 * 12 / 1000  # a space
        self.assertEqual(es.pdf_text(pdf(b'BT /F1 12 Tf ' + b' '.join(content) + b' ET', font)), 'Dear Member')

    def test_fonts_with_a_tounicode_map_in_an_object_stream(self):
        cmap = (b'begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange 2 beginbfchar <0001> <0048> '
                b'<0002> <0069> endbfchar 1 beginbfrange <0003> <0004> <0041> endbfrange endcmap')
        # The font dictionary sits in a compressed object stream (PDF 1.5).
        font = b'<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /ToUnicode 4 0 R >>'
        header = b'3 0 '
        objstm = b'5 0 obj << /Type /ObjStm /N 1 /First ' + str(len(header)).encode() + b' /Length '
        body = zlib.compress(header + font)
        objstm += str(len(body)).encode() + b' /Filter /FlateDecode >> stream\n' + body + b'\nendstream endobj\n'
        document = pdf(b'BT /F1 12 Tf 72 700 Td <00010002> Tj 0 -14 Td <00030004> Tj ET', extra=stream_object(4, cmap) + objstm)
        document = document.replace(b'3 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n', b'')
        self.assertEqual(es.pdf_text(document), 'Hi\nAB')

    def test_bounded(self):
        long_text = b'BT /F1 12 Tf 72 700 Td ' + b' '.join(b'(%s) Tj 0 -14 Td' % (b'word ' * 40) for _ in range(400)) + b' ET'
        self.assertLessEqual(len(es.pdf_text(pdf(long_text))), 20_000)


def eml_with_pdf(document: bytes, body: str = 'Please see the attached invoice.') -> bytes:
    encoded = base64.encodebytes(document).decode()
    return ('From: Billing <billing@example.net>\r\nTo: user@example.org\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n'
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            f'{body}\r\n--b\r\nContent-Type: application/pdf; name="invoice.pdf"\r\n'
            'Content-Disposition: attachment; filename="invoice.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
            f'{encoded}\r\n--b--\r\n').encode()


def analyze_eml(raw: bytes) -> dict:
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


class PdfAttachmentAnalysisTests(unittest.TestCase):
    def test_a_callback_invoice_in_a_pdf(self):
        raw = eml_with_pdf(pdf(CALLBACK))
        attachment = es.analyze_raw_email(raw)['attachments'][0]
        self.assertIn('1-888-555-0199', attachment['extracted_text'])
        self.assertEqual(attachment['inspection_status'], 'metadata_only')
        result = analyze_eml(raw)
        self.assertEqual(result['risk_level'], 'high')
        finding = next(item for item in result['extra_indicators'] if item.get('code') == 'content.callback_request')
        self.assertEqual([prefix['code'] for prefix in finding['prefixes']], ['prefix.pdf_text'])
        self.assertIn('callback', result['mail_type']['tactics'])

    def test_a_genuine_invoice_is_not_a_request(self):
        invoice = (b'BT /F1 11 Tf 72 720 Td (Invoice 2025-104. Total due: $399.99. Payment due within 30 days.) Tj '
                   b'0 -14 Td (Questions about this invoice? Call us at 1-888-555-0199.) Tj ET')
        result = analyze_eml(eml_with_pdf(pdf(invoice)))
        self.assertNotIn('content.callback_request', {item.get('code') for item in result['extra_indicators']})


if __name__ == '__main__':
    unittest.main()
