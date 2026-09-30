import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from email_structure import analyze_raw_email  # noqa: E402
from test_authenticated_sender import GMAIL_AUTH, upload  # noqa: E402


def message(sender='account-security-noreply@alerts.spotify.com', name='Spotify', *, auth='',
            subject='Your Spotify login code'):
    return (auth + f'From: {name} <{sender}>\r\nTo: user@example.com\r\nSubject: {subject}\r\n'
            'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            'Here is the code you asked for: 482913. It expires in 15 minutes.\r\n').encode()


def service_domain(raw, mailbox=None):
    return analyze_raw_email(raw, mailbox_provider=mailbox)['service_domain_sender']


def sender_findings(result):
    return {item['code']: item['level'] for item in result['extra_indicators'] if item['code'].startswith('sender.')}


class ServiceDomainStructureTests(unittest.TestCase):
    def test_a_sender_only_service_domain_without_authentication_is_named(self):
        self.assertEqual(service_domain(message()), {'organization': 'Spotify', 'domain': 'alerts.spotify.com',
                                                     'organizational_domain': 'spotify.com'})
        # A mailbox with no Authentication-Results from it is the same as no mailbox.
        self.assertIsNotNone(service_domain(message(), mailbox='gmail'))

    def test_payment_brands_relays_lookalikes_and_failures_are_not(self):
        for raw in (message('service@paypal.com', 'PayPal'),
                    message('no-reply@alerts.spotify-account.com'),
                    message(name='IT Support'),
                    message('notifications@github.com', 'GitHub'),
                    message(subject='Alex shared a playlist with you')):
            with self.subTest(raw=raw[:60]):
                self.assertIsNone(service_domain(raw))
        failed = GMAIL_AUTH.format(domain='alerts.spotify.com', dkim='alerts.spotify.com').replace(
            'dmarc=pass', 'dmarc=fail')
        self.assertIsNone(service_domain(message(auth=failed), mailbox='gmail'))

    def test_a_verified_sender_is_not_also_a_service_domain_sender(self):
        passed = GMAIL_AUTH.format(domain='alerts.spotify.com', dkim='alerts.spotify.com')
        structure = analyze_raw_email(message(auth=passed), mailbox_provider='gmail')
        self.assertIsNotNone(structure['verified_official_sender'])
        self.assertIsNone(structure['service_domain_sender'])


class ServiceDomainScoringTests(unittest.TestCase):
    def test_address_shape_findings_are_shown_but_not_scored(self):
        result = upload(message(), b'')
        findings = sender_findings(result)
        self.assertEqual(findings['sender.username_keywords'], 'info')
        self.assertEqual(findings['sender.domain_keywords'], 'info')
        self.assertEqual(findings['sender.service_domain'], 'info')
        self.assertEqual(result['sender_analysis']['verdict'], 'low')
        self.assertIsNone(result['verified_official_sender'])

    def test_other_senders_keep_their_address_findings(self):
        for raw in (message('account-security-noreply@alerts.spotify-account.com'),
                    message(name='IT Support')):
            with self.subTest(raw=raw[:80]):
                findings = sender_findings(upload(raw, b''))
                self.assertNotEqual(findings['sender.username_keywords'], 'info')
                self.assertNotIn('sender.service_domain', findings)


if __name__ == '__main__':
    unittest.main()
