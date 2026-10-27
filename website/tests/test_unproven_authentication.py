"""An uploaded file's Authentication-Results, read through the mailbox choice or a configured ID, is unproven: it can
raise the risk but never lower it. Only ARC, verified with the sealing service's key, can lower it, and only when no
source shows a failure. (认证头-修复方案与通过条件-审定版.md C1-C3; the unit tests named by AH-8.)"""
import asyncio
import base64
import json
import sys
import threading
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
from visual_evidence import VisualRequest  # noqa: E402


def header(authserv, domain='paypal.com', dmarc='pass', dkim_result='pass', spf='pass'):
    return (f'Authentication-Results: {authserv}; dkim={dkim_result} header.i=@{domain}; '
            f'spf={spf} smtp.mailfrom={domain}; dmarc={dmarc} header.from={domain}\r\n')


def message(*headers, sender='service@paypal.com', name='PayPal', body='Your account needs attention.') -> bytes:
    return (''.join(headers) + f'From: {name} <{sender}>\r\nTo: user@example.com\r\nSubject: Account notice\r\n'
            f'Date: Thu, 01 Oct 2026 10:00:00 +0000\r\nMessage-ID: <n@example.com>\r\n\r\n{body}\r\n').encode()


GOOGLE_PASS, GOOGLE_FAIL = header('mx.google.com'), header('mx.google.com', dmarc='fail', dkim_result='none', spf='fail')
CONFIGURED = frozenset({'mx.example.org'})


def sealed(results_header: str):
    """ARC's verified answer, as app._parse_raw_email passes it once Google's seal verifies."""
    return 'google.com', results_header.split(':', 1)[1].strip()


def respond(structure):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), structure)).body)


def codes(result):
    return [item['code'] for item in result['extra_indicators']]


class NoDowngradeFromUnprovenPassTests(unittest.TestCase):
    def test_a_mailbox_pass_neither_verifies_nor_zeroes_the_sender(self):
        raw = message(GOOGLE_PASS)
        twin = respond(es.analyze_raw_email(raw, arc_result=None))
        chosen = respond(es.analyze_raw_email(raw, mailbox_provider='gmail', arc_result=None))
        self.assertIsNone(chosen['verified_official_sender'])
        self.assertEqual((chosen['risk_level'], chosen['risk_label'], chosen['sender_score'], chosen['total_score']),
                         (twin['risk_level'], twin['risk_label'], twin['sender_score'], twin['total_score']))
        self.assertGreater(chosen['sender_score'], 0)
        self.assertIn('structure.unverified_auth_pass', codes(chosen))

    def test_a_mailbox_pass_does_not_relax_the_address(self):
        raw = message(header('mx.google.com', domain='secure-login.example.net'), sender='alerts@secure-login.example.net',
                      name='Example Security')
        twin = respond(es.analyze_raw_email(raw, arc_result=None))
        chosen = respond(es.analyze_raw_email(raw, mailbox_provider='gmail', arc_result=None))
        sender = {item['code']: item['level'] for item in chosen['extra_indicators'] if item['code'].startswith('sender.')}
        self.assertNotIn('sender.authenticated_domain', sender)
        self.assertEqual(sender, {item['code']: item['level'] for item in twin['extra_indicators']
                                  if item['code'].startswith('sender.')})
        self.assertEqual((chosen['risk_floor'], chosen['sender_score']), (twin['risk_floor'], twin['sender_score']))

    def test_a_configured_id_pass_does_not_verify(self):
        raw = message(header('mx.other.example', dmarc='fail', dkim_result='none', spf='fail'), header('mx.example.org'))
        structure = es.analyze_raw_email(raw, trusted_authserv_ids=CONFIGURED, arc_result=None)
        self.assertIsNone(structure['verified_official_sender'])
        self.assertEqual(structure['unverified_authentication']['source'], 'server')
        twin = respond(es.analyze_raw_email(raw, arc_result=None))
        result = respond(structure)
        self.assertEqual((result['risk_level'], result['sender_score']), (twin['risk_level'], twin['sender_score']))


class FailuresStillRaiseTests(unittest.TestCase):
    def test_an_unproven_failure_raises_through_either_entry(self):
        for label, raw, kwargs in (
                ('mailbox', message(GOOGLE_FAIL), {'mailbox_provider': 'gmail'}),
                ('configured ID', message(header('mx.example.org', dmarc='fail', dkim_result='none', spf='fail')),
                 {'trusted_authserv_ids': CONFIGURED})):
            with self.subTest(entry=label):
                structure = es.analyze_raw_email(raw, arc_result=None, **kwargs)
                self.assertEqual(structure['risk_floor'], 'high')
                self.assertIn('structure.auth_failed', [item['code'] for item in structure['indicators']])

    def test_an_arc_pass_does_not_cancel_an_unproven_failure(self):
        structure = es.analyze_raw_email(message(GOOGLE_FAIL), mailbox_provider='gmail', arc_result=sealed(GOOGLE_PASS))
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertEqual(structure['risk_floor'], 'high')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertIsNone(structure['authenticated_sender'])

    def test_an_unproven_pass_does_not_stop_arcs_failure(self):
        structure = es.analyze_raw_email(message(GOOGLE_PASS), mailbox_provider='gmail', arc_result=sealed(GOOGLE_FAIL))
        self.assertEqual(structure['risk_floor'], 'high')
        self.assertIsNone(structure['verified_official_sender'])
        # The file's pass differs from the sealed result: it is shown, as unverified.
        self.assertEqual(structure['unverified_authentication']['results']['dmarc'], 'pass')


class ArcWithAMailboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.txt_record = make_key()

    def test_the_request_path_verifies_arc_on_its_own_threads_with_a_mailbox_chosen(self):
        raw = message(GOOGLE_PASS)
        raw = b''.join(dkim.arc_sign(raw, b'arc-test', b'google.com', self.private_key, b'mx.google.com')) + raw
        threads = []

        def dns(name, timeout=5):
            threads.append(threading.current_thread().name)
            return self.txt_record

        def waiting(*_args, **_kwargs):
            raise AssertionError('the analysis thread waited for ARC')
        es._ARC_KEY_CACHE.clear()
        with patch.object(es, '_arc_dns_txt', dns), patch.object(es, 'arc_sealed_results', waiting):
            structure = asyncio.run(app._parse_raw_email(raw, mailbox_provider='gmail'))
        self.assertEqual(structure['authentication_source'], 'arc')
        self.assertEqual(structure['verified_official_sender'], {'organization': 'PayPal', 'domain': 'paypal.com'})
        self.assertTrue(threads)
        self.assertTrue(all(name.startswith('arc') for name in threads))


class ScopeTests(unittest.TestCase):
    def test_the_case_workspace_ignores_the_mailbox(self):
        payload = VisualRequest(eml_base64=base64.b64encode(message(GOOGLE_PASS)).decode(), mailbox='gmail')
        with patch.object(app, '_content_pipeline', None), patch.object(app, 'start_arc_verification', lambda raw: None):
            _source, analysis, _provenance = asyncio.run(app._analyze_case(payload, None))
        self.assertNotIn('unverified_authentication', analysis['message_structure'])
        self.assertIsNone(analysis['verified_official_sender'])

    def test_an_attached_message_never_gets_a_header_read(self):
        inner = message(GOOGLE_PASS)
        outer = (b'From: Someone <someone@example.org>\r\nTo: user@example.com\r\nSubject: Fwd\r\nMIME-Version: 1.0\r\n'
                 b'Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n'
                 b'--b\r\nContent-Type: message/rfc822\r\n\r\n' + inner + b'\r\n--b--\r\n')
        nested = es.analyze_raw_email(outer, mailbox_provider='gmail', arc_result=None)['nested_messages']
        self.assertEqual(len(nested), 1)
        self.assertIsNone(nested[0]['unverified_authentication'])
        self.assertIsNone(nested[0]['verified_official_sender'])

    def test_a_message_with_only_an_unproven_header_is_still_a_message(self):
        raw = (GOOGLE_PASS + 'MIME-Version: 1.0\r\n\r\n').encode()
        structure = es.analyze_raw_email(raw, mailbox_provider='gmail', arc_result=None)
        self.assertEqual((structure['subject'], structure['body'], structure['from']), ('', '', ''))
        self.assertIsNotNone(structure['unverified_authentication'])
        with patch.object(app, '_content_pipeline', None):
            result = json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), structure)).body)
        self.assertEqual(result['message_structure']['unverified_authentication']['source'], 'mailbox')

    def test_without_a_header_to_read_the_new_field_is_left_out(self):
        result = respond(es.analyze_raw_email(message(), mailbox_provider='gmail', arc_result=None))
        self.assertNotIn('unverified_authentication', result['message_structure'])
        result = respond(es.analyze_raw_email(message(GOOGLE_PASS), arc_result=None))
        self.assertNotIn('unverified_authentication', result['message_structure'])
        result = respond(es.analyze_raw_email(message(GOOGLE_PASS), mailbox_provider='gmail', arc_result=None))
        self.assertIn('unverified_authentication', result['message_structure'])


if __name__ == '__main__':
    unittest.main()
