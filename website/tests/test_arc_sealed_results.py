"""ARC (RFC 8617): trusting a mailbox service's sealed checks, the only authentication that can lower the risk."""
import asyncio
import dataclasses
import json
import sys
import threading
import time
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

    def test_a_direct_caller_naming_a_mailbox_looks_nothing_up_and_verifies_nothing(self):
        # Without the caller's ARC answer, a named mailbox keeps the old rule of no lookup here (offline
        # evaluators); its header is only shown. The web app always passes its own answer.
        structure = self.analyze(self.seal(message()), mailbox='gmail')
        self.assertIsNone(structure['authentication_source'])
        self.assertIsNone(structure['verified_official_sender'])
        self.assertEqual(structure['unverified_authentication']['authserv_id'], 'mx.google.com')
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


    def test_the_request_path_checks_arc_first_on_the_arc_threads(self):
        # The analysis worker never waits on DNS: the chain is verified before it starts.
        threads = []

        def dns(name, timeout=5):
            threads.append(threading.current_thread().name)
            return self.txt_record

        def waiting(*_args, **_kwargs):
            raise AssertionError('the analysis thread waited for ARC')
        with patch.object(es, '_arc_dns_txt', dns), patch.object(es, 'arc_sealed_results', waiting):
            structure = asyncio.run(app._parse_raw_email(self.seal(message())))
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertTrue(threads)
        self.assertTrue(all(name.startswith('arc') for name in threads))

    def test_the_request_path_gives_no_trust_to_a_changed_message(self):
        with patch.object(es, '_arc_dns_txt', self.dns):
            structure = asyncio.run(app._parse_raw_email(self.seal(message()).replace(b'482913', b'000000')))
        self.assertIsNone(structure['authentication_source'])

    def test_a_mailbox_choice_is_checked_by_arc_first_too(self):
        with patch.object(es, '_arc_dns_txt', self.dns):
            structure = asyncio.run(app._parse_raw_email(self.seal(message()), mailbox_provider='gmail'))
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertEqual(structure['verified_official_sender'], {'organization': 'Dropbox', 'domain': 'dropbox.com'})
        # Gmail's own header repeats the sealed results: shown once, through the seal.
        self.assertIsNone(structure['unverified_authentication'])
        self.assertTrue(self.lookups)

    def test_a_slow_chain_stops_waiting_at_its_deadline(self):
        def slow(name, timeout=5):
            time.sleep(min(timeout, 0.4))
            return None
        start = time.perf_counter()
        with patch.object(es, '_arc_dns_txt', slow), patch.object(app, '_ARC_VERIFY_SECONDS', 0.2), \
                patch.object(es, '_ARC_VERIFY_SECONDS', 0.2):
            structure = asyncio.run(app._parse_raw_email(self.seal(message())))
        self.assertIsNone(structure['authentication_source'])
        self.assertLess(time.perf_counter() - start, 2.0)



STAMP = (b'Authentication-Results: mx.google.com; arc=pass; dkim=pass header.d=dropbox.com; '
         b'spf=pass smtp.mailfrom=dropbox.com; dmarc=pass header.from=dropbox.com\r\n')


class NewEntryArcLimitTests(unittest.TestCase):
    """K11-K14: a chosen mailbox or a configured ID now also has its ARC verified first, under the same limits."""
    ENTRIES = (('mailbox', 'gmail', frozenset()), ('configured ID', None, frozenset({'mx.example.org'})))

    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.txt_record = make_key()

    def setUp(self):
        self.lookups = []
        es._ARC_KEY_CACHE.clear()

    def dns(self, name, timeout=5):
        self.lookups.append(name)
        return self.txt_record

    def chain(self, count, domain=b'google.com'):
        """count ARC sets over message(), each receiver writing one arc=pass stamp; dkimpy verifies them all."""
        raw = message()
        for instance in range(1, count + 1):
            if instance > 1:
                raw = STAMP + raw.replace(STAMP, b'')
            raw = b''.join(dkim.arc_sign(raw, b'arc-%d' % instance, domain, self.private_key, b'mx.google.com')) + raw
        return raw

    def parse(self, raw, mailbox, ids, dnsfunc=None):
        with patch.object(es, '_arc_dns_txt', dnsfunc or self.dns), \
                patch.object(app, 'SETTINGS', dataclasses.replace(app.SETTINGS, trusted_authserv_ids=ids)):
            return asyncio.run(app._parse_raw_email(raw, mailbox_provider=mailbox))

    def test_k11_another_sealer_is_never_looked_up(self):
        for label, mailbox, ids in self.ENTRIES:
            with self.subTest(entry=label):
                self.lookups.clear()
                structure = self.parse(self.chain(1, domain=b'evil.example'), mailbox, ids)
                self.assertIsNone(structure['authentication_source'])
                self.assertEqual(self.lookups, [])

    def test_k12_slow_dns_stops_at_the_deadline(self):
        def slow(name, timeout=5):
            time.sleep(min(timeout, 0.4))
            return None
        for label, mailbox, ids in self.ENTRIES:
            with self.subTest(entry=label):
                start = time.perf_counter()
                with patch.object(app, '_ARC_VERIFY_SECONDS', 0.2), patch.object(es, '_ARC_VERIFY_SECONDS', 0.2):
                    structure = self.parse(self.chain(1), mailbox, ids, dnsfunc=slow)
                self.assertIsNone(structure['authentication_source'])
                self.assertLess(time.perf_counter() - start, 2.0)

    def test_k13_busy_verification_threads_mean_no_trust_without_waiting(self):
        for label, mailbox, ids in self.ENTRIES:
            with self.subTest(entry=label):
                self.lookups.clear()
                start = time.perf_counter()
                with patch.object(es._arc_pool, 'submit', return_value=None):
                    structure = self.parse(self.chain(1), mailbox, ids)
                self.assertIsNone(structure['authentication_source'])
                self.assertLess(time.perf_counter() - start, 0.5)
                self.assertEqual(self.lookups, [])

    def test_k14_the_eleventh_lookup_is_refused(self):
        six = self.chain(6)
        self.assertEqual(dkim.arc_verify(six, dnsfunc=lambda name, timeout=5: self.txt_record)[0], dkim.CV_Pass)
        for label, mailbox, ids in self.ENTRIES:
            with self.subTest(entry=label):
                self.lookups.clear()
                es._ARC_KEY_CACHE.clear()
                self.assertIsNone(self.parse(six, mailbox, ids)['authentication_source'])
                self.assertEqual(len(self.lookups), es._ARC_MAX_LOOKUPS)
                # Five sets need ten lookups: within the limit, the same chain is trusted.
                self.lookups.clear()
                self.assertEqual(self.parse(self.chain(5), mailbox, ids)['authentication_source'], 'arc')
                self.assertEqual(len(self.lookups), es._ARC_MAX_LOOKUPS)


if __name__ == '__main__':
    unittest.main()
