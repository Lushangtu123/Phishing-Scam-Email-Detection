"""Registry entries added on 2026-10-05: WeTransfer, Navy Federal Credit Union, Standard Bank and
Absa by name, and Epic Games and Twitch as services that verify their own mail (synthetic
inputs)."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import email_structure as es  # noqa: E402

GMAIL_PASS = ('Authentication-Results: mx.google.com;\r\n'
              '       dkim=pass header.i=@{domain} header.s=s1;\r\n'
              '       spf=pass (google.com: domain of bounce@{domain} designates 192.0.2.1 as permitted sender)'
              ' smtp.mailfrom=bounce@{domain};\r\n'
              '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={domain}\r\n')


def received(sender, name, subject, body='Your verification code is 482913. It expires in 15 minutes.'):
    domain = sender.rpartition('@')[2]
    raw = (GMAIL_PASS.format(domain=domain) + f'From: {name} <{sender}>\r\nTo: user@example.com\r\n'
           f'Subject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n')
    return es.analyze_raw_email(raw.encode(), mailbox_provider='gmail')


class RegistryAdditionTests(unittest.TestCase):
    def test_names_shown_from_other_domains(self):
        for display, domain, brand in (
                ('WeTransfer', 'wetransfer-secure.com', 'WeTransfer'),
                ('Navy Federal Credit Union', 'nfcu-alerts.com', 'Navy Federal Credit Union'),
                ('Navy Federal', 'mail.example.net', 'Navy Federal'),
                ('Standard Bank', 'sbsa-online.co', 'Standard Bank'),
                ('Absa', 'absa.co.za.example.com', 'Absa'),
                ('ABSA Alerts', 'secure-alerts.example', 'Absa')):
            with self.subTest(display=display, domain=domain):
                self.assertEqual(es._registry_brand_claim(display, domain), brand)

    def test_their_own_domains(self):
        for display, domain in (
                ('WeTransfer', 'wetransfer.com'), ('WeTransfer', 'mail.wetransfer.com'),
                ('Navy Federal', 'navyfederal.org'), ('Navy Federal Credit Union', 'email.navyfederal.org'),
                ('Standard Bank', 'standardbank.co.za'), ('Standard Bank', 'email.standardbank.com'),
                ('Absa', 'absa.co.za'), ('Absa', 'absa.africa')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_other_names(self):
        for display in ('Absalom Smith', 'Standard Chartered', 'Navy SEAL Foundation', 'Federal Navy Supplies',
                        'Transfer Wise'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.net'))

    def test_services_verify_their_own_mail(self):
        for sender, name, organization in (('help@acct-auth.epicgames.com', 'Epic Games', 'Epic Games'),
                                           ('no-reply@twitch.tv', 'Twitch', 'Twitch')):
            with self.subTest(sender=sender):
                structure = received(sender, name, 'Your sign-in code')
                self.assertEqual(structure['verified_official_sender']['organization'], organization)
        # amazon.com, which Twitch also uses, stays Amazon's.
        self.assertEqual(es._official_sender('amazon.com'), 'Amazon')

    def test_transfer_notices_are_relays(self):
        structure = received('noreply@wetransfer.com', 'WeTransfer', 'alex@example.org sent you some files',
                             body='alex@example.org sent you 2 files. Download them before they expire.')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertIn('structure.platform_relay', {item['code'] for item in structure['indicators']})
        account = received('noreply@wetransfer.com', 'WeTransfer', 'Your WeTransfer verification code')
        self.assertEqual(account['verified_official_sender']['organization'], 'WeTransfer')


if __name__ == '__main__':
    unittest.main()
