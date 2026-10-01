"""ARC (RFC 8617): trusting a mailbox service's sealed checks without a mailbox choice."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dkim  # noqa: E402

import app  # noqa: E402
import email_structure as es  # noqa: E402
from arc_test_keys import make_key  # noqa: E402

RESULTS = ('{srv}; dkim=pass header.d=dropbox.com; spf=pass smtp.mailfrom=dropbox.com; '
           'dmarc=pass header.from=dropbox.com')
BODY = b'Your Dropbox code is 482913. It expires in 10 minutes.\r\n'


def message(srv='mx.google.com', body=BODY) -> bytes:
    return (f'Authentication-Results: {RESULTS.format(srv=srv)}\r\n'.encode()
            + b'From: Dropbox <no-reply@dropbox.com>\r\nTo: user@example.com\r\nSubject: Your code\r\n'
              b'Date: Thu, 01 Oct 2026 10:00:00 +0000\r\nMessage-ID: <code@dropbox.com>\r\n\r\n' + body)


class ArcSealedResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.txt_record = make_key()

    def setUp(self):
        self.lookups = []
        es._ARC_KEY_CACHE.clear()

    def dns(self, name, timeout=5):
        self.lookups.append(name)
        return self.txt_record

    def seal(self, raw, domain=b'google.com', srv=b'mx.google.com'):
        return b''.join(dkim.arc_sign(raw, b'arc-test', domain, self.private_key, srv)) + raw

    def analyze(self, raw, mailbox=None):
        with patch.object(es, '_arc_dns_txt', self.dns):
            return es.analyze_raw_email(raw, mailbox_provider=mailbox)

    def test_a_valid_gmail_seal_is_trusted_without_a_mailbox_choice(self):
        structure = self.analyze(self.seal(message()))
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertEqual(structure['verified_official_sender'], {'organization': 'Dropbox', 'domain': 'dropbox.com'})
        self.assertIn('structure.arc_sealed_results', [item['code'] for item in structure['indicators']])
        self.assertEqual(structure['untrusted_authentication_claims'], [])
        self.assertEqual({name.rstrip(b'.') for name in self.lookups}, {b'arc-test._domainkey.google.com'})

    def test_a_changed_message_or_a_failed_lookup_is_not_trusted(self):
        sealed = self.seal(message())
        self.assertIsNone(self.analyze(sealed.replace(b'482913', b'000000'))['authentication_source'])
        with patch.object(es, '_arc_dns_txt', lambda name, timeout=5: None):
            self.assertIsNone(es.analyze_raw_email(sealed)['authentication_source'])

    def test_other_sealers_are_never_looked_up(self):
        sealed = self.seal(message(), domain=b'evil.example')
        self.assertIsNone(self.analyze(sealed)['authentication_source'])
        self.assertEqual(self.lookups, [])

    def test_a_google_seal_over_another_services_results_is_not_trusted(self):
        sealed = self.seal(message(srv='mx.evil.example'), srv=b'mx.evil.example')
        self.assertIsNone(es.arc_sealed_results(sealed, dnsfunc=self.dns))
        self.assertIsNone(self.analyze(sealed)['authentication_source'])

    def test_a_chosen_mailbox_keeps_its_own_path(self):
        structure = self.analyze(self.seal(message()), mailbox='gmail')
        self.assertEqual(structure['authentication_source'], 'mailbox')
        self.assertEqual(self.lookups, [])

    def test_a_sealed_message_inside_an_attachment_is_not_trusted(self):
        inner = self.seal(message())
        outer = (b'From: Someone <someone@example.org>\r\nTo: user@example.com\r\nSubject: Fwd\r\nMIME-Version: 1.0\r\n'
                 b'Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n'
                 b'--b\r\nContent-Type: message/rfc822\r\n\r\n' + inner + b'\r\n--b--\r\n')
        structure = self.analyze(outer)
        self.assertIsNone(structure['authentication_source'])
        self.assertTrue(all(nested.get('authentication_source') is None
                            for nested in structure.get('nested_messages', [])))

    def test_the_content_result_says_the_seal_was_used(self):
        with patch.object(es, '_arc_dns_txt', self.dns), patch.object(app, '_content_pipeline', None):
            result = json.loads(asyncio.run(app._analyze_content(
                app.ContentRequest(), es.analyze_raw_email(self.seal(message())))).body)
        self.assertIn('structure.arc_sealed_results', [item.get('code') for item in result['extra_indicators']])
        self.assertEqual(result['verified_official_sender']['organization'], 'Dropbox')


if __name__ == '__main__':
    unittest.main()
