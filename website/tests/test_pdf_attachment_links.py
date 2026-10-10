import asyncio
import base64
import json
import sys
import time
import unittest
import zlib
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import link_analysis  # noqa: E402
import email_structure as es  # noqa: E402


def annotation(target: bytes) -> bytes:
    return b'<</Type/Annot/Subtype/Link/A<</S/URI/URI' + target + b'>>>>'


def object_stream(body: bytes) -> bytes:
    return (b'%PDF-1.5\n2 0 obj<</Type/ObjStm/Filter/FlateDecode/Length 99>>stream\n'
            + zlib.compress(body) + b'\nendstream endobj\n')


def message_with_pdf(pdf: bytes, content_type='application/pdf', filename='invoice.pdf') -> str:
    return ('From: Billing <billing@example.org>\nTo: user@example.com\nSubject: Invoice\nMIME-Version: 1.0\n'
            'Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nSee the attached invoice.\n'
            f'--b\nContent-Type: {content_type}; name={filename}\nContent-Disposition: attachment; filename={filename}\n'
            'Content-Transfer-Encoding: base64\n\n' + base64.b64encode(pdf).decode() + '\n--b--\n')


class PdfLinkExtractionTests(unittest.TestCase):
    def test_literal_hex_escaped_and_compressed_targets_are_read(self):
        pdf = b'%PDF-1.4\n' + annotation(b'(https://paypal-verify.top/login)') + annotation(b'<68747470733A2F2F612E6578616D706C652F>')
        self.assertEqual(es.pdf_link_targets(pdf), ['https://paypal-verify.top/login', 'https://a.example/'])
        escaped = b'%PDF-1.4\n' + annotation(rb'(https://b.example/\(x\)\057y)')
        self.assertEqual(es.pdf_link_targets(escaped), ['https://b.example/(x)/y'])
        self.assertEqual(es.pdf_link_targets(object_stream(annotation(b'(https://192.0.2.10/a)'))),
                         ['https://192.0.2.10/a'])

    def test_only_web_targets_are_kept_and_counts_are_bounded(self):
        pdf = b'%PDF-1.4\n' + annotation(b'(mailto:a@b.example)') + annotation(b'(javascript:alert(1))')
        self.assertEqual(es.pdf_link_targets(pdf), [])
        many = b'%PDF-1.4\n' + b''.join(annotation(f'(https://h{i}.example/)'.encode()) for i in range(80))
        self.assertEqual(len(es.pdf_link_targets(many)), es._MAX_PDF_LINKS)
        self.assertEqual(es.pdf_link_targets(many + many)[:2], ['https://h0.example/', 'https://h1.example/'])

    def test_decompression_bombs_and_broken_streams_are_bounded(self):
        bomb = b'%PDF-1.5\n<</Filter/FlateDecode>>stream\n' + zlib.compress(b'A' * 50_000_000) + b'\nendstream'
        started = time.perf_counter()
        self.assertEqual(es.pdf_link_targets(bomb), [])
        self.assertLess(time.perf_counter() - started, 2)
        broken = b'%PDF-1.5\n<</Filter/FlateDecode>>stream\nnot zlib\nendstream\n' + annotation(b'(https://c.example/)')
        self.assertEqual(es.pdf_link_targets(broken), ['https://c.example/'])


class PdfAttachmentAnalysisTests(unittest.TestCase):
    def analyze(self, raw):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)

    def test_pdf_links_are_scored_with_a_prefix_and_the_pdf_stays_uninspected(self):
        pdf = object_stream(annotation(b'(https://paypal-verify.top/login)'))
        result = self.analyze(message_with_pdf(pdf))
        pdf_findings = [item for item in result['extra_indicators'] if item['msg'].startswith('PDF attachment link:')]
        self.assertIn('link.brand_lookalike', [item['code'] for item in pdf_findings])
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['pdf_link_count'], 1)
        attachment = result['message_structure']['attachments'][0]
        self.assertEqual(attachment['inspection_status'], 'metadata_only')
        self.assertIn('warning.attachments_uninspected', [item.get('code') for item in result['extra_indicators']])

    def test_benign_or_non_pdf_attachments_add_no_link_findings(self):
        benign = self.analyze(message_with_pdf(b'%PDF-1.4\n' + annotation(b'(https://www.irs.gov/forms)')))
        self.assertFalse([item for item in benign['extra_indicators'] if item['msg'].startswith('PDF attachment link:')])
        self.assertEqual(benign['pdf_link_count'], 1)
        disguised = self.analyze(message_with_pdf(b'not a pdf ' + annotation(b'(https://paypal-verify.top/)')))
        self.assertNotIn('pdf_link_count', disguised)



class IpfsGatewayLinkTests(unittest.TestCase):
    def test_public_gateways_subdomain_gateways_and_ipfs_paths_are_recognized(self):
        cid = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
        for host, path in (('ipfs.io', f'/ipfs/{cid}/login.html'), ('cloudflare-ipfs.com', '/ipfs/x'),
                           (f'{cid}.ipfs.dweb.link', '/'), ('abc.mypinata.cloud', '/'),
                           (f'{cid}.ipfs.w3s.link', '/'), ('files.example.net', f'/ipfs/{cid}')):
            with self.subTest(host=host, path=path):
                self.assertTrue(link_analysis._is_ipfs_gateway(host, path))
        for host, path in (('ipfsnews.com', '/'), ('example.com', '/ipfs-guide'), ('docs.ipfs.tech', '/concepts'),
                           ('example.com', '/ipfs/short')):
            with self.subTest(host=host, path=path):
                self.assertFalse(link_analysis._is_ipfs_gateway(host, path))

    def test_ipfs_links_raise_a_high_floor_in_messages_and_pdfs(self):
        body = '<p>Review the shared document.</p><a href="https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi">Open</a>'
        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(subject='Document', body=body))).body)
        self.assertIn('link.ipfs_gateway', [item['code'] for item in result['extra_indicators']])
        self.assertIn(result['risk_level'], {'high', 'critical'})
        pdf = b'%PDF-1.4\n' + annotation(b'(https://gateway.pinata.cloud/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi)')
        pdf_result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(raw_email=message_with_pdf(pdf)))).body)
        self.assertIn('link.ipfs_gateway', [item['code'] for item in pdf_result['extra_indicators']
                                            if item['msg'].startswith('PDF attachment link:')])


if __name__ == '__main__':
    unittest.main()
