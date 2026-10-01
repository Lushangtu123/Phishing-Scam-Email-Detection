import asyncio
import base64
import io
import json
import sys
import time
import unittest
import zipfile
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import email_structure as es  # noqa: E402

DOCX_TYPE = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
HYPERLINK = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink'
SUBSIDY = ('关于财务部2023年个人劳动补贴申领通知。根据国家财政部、国家税务总局联合下发的通知，'
           '请扫描下方二维码申领，当天未完成视为放弃申领。')


def docx(paragraphs=(), links=(), extra=None, compression=zipfile.ZIP_DEFLATED) -> bytes:
    body = ''.join(f'<w:p><w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>' for text in paragraphs)
    rels = ''.join(f'<Relationship Id="rId{i}" Type="{HYPERLINK}" Target="{url}" TargetMode="External"/>'
                   for i, url in enumerate(links))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression) as archive:
        archive.writestr('[Content_Types].xml', '<Types/>')
        archive.writestr('word/document.xml', f'<w:document><w:body>{body}</w:body></w:document>')
        archive.writestr('word/_rels/document.xml.rels', f'<Relationships>{rels}</Relationships>')
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


def message(attachment: bytes, body='请查收附件', subject='通知：2023年个人劳动补贴', filename='notice.docx',
            content_type=DOCX_TYPE) -> str:
    return (f'From: Finance <finance@example.org>\nTo: user@example.com\nSubject: {subject}\nMIME-Version: 1.0\n'
            'Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain; charset=utf-8\n'
            'Content-Transfer-Encoding: base64\n\n' + base64.b64encode(body.encode()).decode() + '\n'
            f'--b\nContent-Type: {content_type}; name={filename}\nContent-Disposition: attachment; filename={filename}\n'
            'Content-Transfer-Encoding: base64\n\n' + base64.b64encode(attachment).decode() + '\n--b--\n')


def prefixes(item):
    return [prefix['code'] for prefix in item.get('prefixes', [])]


def analyze(raw):
    return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)


class DocxExtractionTests(unittest.TestCase):
    def test_paragraph_text_and_external_hyperlinks_are_read(self):
        text, links = es.docx_text_and_links(docx(['第一段 &amp; 说明', '第二段'],
                                                  ['https://subsidy-claim.example/a?x=1&amp;y=2', 'mailto:a@b.example']))
        self.assertEqual(text, '第一段 & 说明\n第二段')
        self.assertEqual(links, ['https://subsidy-claim.example/a?x=1&y=2'])

    def test_macros_images_and_other_parts_are_never_read(self):
        text, links = es.docx_text_and_links(docx(['正文'], extra={
            'word/vbaProject.bin': b'Sub AutoOpen()', 'word/media/image1.png': b'\x89PNG',
            'word/header1.xml': '<w:t>页眉不读</w:t>'}))
        self.assertEqual((text, links), ('正文', []))

    def test_malformed_oversized_and_bomb_documents_yield_nothing(self):
        self.assertEqual(es.docx_text_and_links(b'not a zip'), ('', []))
        self.assertEqual(es.docx_text_and_links(b'PK\x03\x04broken'), ('', []))
        bomb = io.BytesIO()
        with zipfile.ZipFile(bomb, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('word/document.xml', '<w:t>' + 'A' * 50_000_000 + '</w:t>')
        started = time.perf_counter()
        self.assertEqual(es.docx_text_and_links(bomb.getvalue()), ('', []))
        self.assertLess(time.perf_counter() - started, 2)
        many = io.BytesIO()
        with zipfile.ZipFile(many, 'w') as archive:
            for index in range(es._MAX_DOCX_ENTRIES + 1):
                archive.writestr(f'x/{index}', '')
        self.assertEqual(es.docx_text_and_links(many.getvalue()), ('', []))

    def test_text_is_bounded(self):
        text, _ = es.docx_text_and_links(docx(['字' * 30_000]))
        self.assertEqual(len(text), es._MAX_DOCX_TEXT_CHARS)


class SubsidyLureTests(unittest.TestCase):
    def test_subsidy_or_refund_with_pressure_matches(self):
        for text in ('2023年个人劳动补贴，当天未完成视为放弃申领！', '《高温补助-请今日立即申请》',
                     '一般纳税人退税申请：请扫码办理', '劳 动 补 贴 已下发，扫 码 领取'):
            with self.subTest(text=text):
                self.assertTrue(app._subsidy_lure(text))

    def test_genuine_allowance_notices_do_not(self):
        for text in ('关于发放2023年高温补贴的通知：高温补贴将随7月工资一并发放。',
                     '个人所得税年度汇算可在个人所得税App办理退税。', '本月工资条已发送，请登录内网查看。'):
            with self.subTest(text=text):
                self.assertFalse(app._subsidy_lure(text))


class DocxAttachmentAnalysisTests(unittest.TestCase):
    def test_a_lure_in_the_attachment_alone_raises_a_high_signal(self):
        result = analyze(message(docx([SUBSIDY]), body='请查收附件', subject='财政通知'))
        item = next(item for item in result['extra_indicators'] if item.get('code') == 'content.subsidy_lure')
        self.assertIn('prefix.docx_text', prefixes(item))
        self.assertIn(result['risk_level'], {'high', 'critical'})

    def test_attachment_callbacks_and_links_are_checked(self):
        callback = 'Your subscription renewed for $499. If you did not authorize this charge, call 1-888-555-0199.'
        result = analyze(message(docx([callback]), body='See attached.', subject='Receipt'))
        self.assertIn('content.callback_request', [item.get('code') for item in result['extra_indicators']])
        result = analyze(message(docx(['Open the portal'], ['https://192.0.2.10/login']), body='See attached.',
                                 subject='Portal'))
        linked = [item for item in result['extra_indicators'] if 'prefix.docx_attachment' in prefixes(item)]
        self.assertTrue(linked)
        self.assertEqual(result['docx_link_count'], 1)

    def test_ordinary_business_wording_in_an_attachment_scores_nothing(self):
        ordinary = ('Quotation 2023-114. Payment due within 30 days of invoice. Urgent orders ship next day. '
                    'Please verify the delivery address before confirming the purchase order.')
        plain = analyze(message(docx([]), body='Please find the quotation attached.', subject='Quotation'))
        quoted = analyze(message(docx([ordinary]), body='Please find the quotation attached.', subject='Quotation'))
        self.assertEqual(quoted['total_score'], plain['total_score'])
        self.assertEqual(quoted['risk_level'], plain['risk_level'])

    def test_a_docx_named_attachment_with_a_generic_type_is_read(self):
        raw = message(docx([SUBSIDY]), content_type='application/octet-stream')
        self.assertIn('content.subsidy_lure', [item.get('code') for item in analyze(raw)['extra_indicators']])


if __name__ == '__main__':
    unittest.main()
