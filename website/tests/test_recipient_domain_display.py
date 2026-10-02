"""A From display name showing the recipient's own domain, sent from another domain."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import email_structure as es  # noqa: E402


def finding(sender: str, to: str = 'jose@monkey.org'):
    raw = f'From: {sender}\r\nTo: {to}\r\nSubject: Notice\r\n\r\nHello'.encode()
    structure = es.analyze_raw_email(raw)
    found = [item for item in structure['indicators'] if item['code'] == 'structure.recipient_domain_display']
    return (found[0]['params']['domain'], structure['risk_floor']) if found else None


class RecipientDomainDisplayTests(unittest.TestCase):
    def test_the_recipients_domain_from_elsewhere(self):
        for sender in ('"monkey.org" <vic@infinitextil.com>',
                       '"monkey.org Delivery System" <noreply@mailer.example.net>',
                       '"Mail Admin jose@monkey.org" <admin@example.net>',
                       '"警报|讯息传递。monkey.org （同 步）" <alerts@example.net>'):
            with self.subTest(sender=sender):
                self.assertEqual(finding(sender), ('monkey.org', 'medium'))

    def test_senders_that_are_no_claim(self):
        for sender, to in (
                ('"monkey.org IT" <it@monkey.org>', 'jose@monkey.org'),            # the recipient's own domain
                ('"IT" <it@mail.monkey.org>', 'jose@monkey.org'),
                ('"Jane jane@monkey.org via Dropbox" <no-reply@dropbox.com>', 'jose@monkey.org'),  # a relay
                ('"jane@monkey.org" <calendar-notification@google.com>', 'jose@monkey.org'),     # a registered service
                ('"gmail.com team" <team@example.net>', 'someone@gmail.com'),     # a mail provider is no organization
                ('"Notmonkey.org" <a@example.net>', 'jose@monkey.org'),           # not the domain itself
                ('"Billing" <billing@example.net>', 'jose@monkey.org')):
            with self.subTest(sender=sender):
                self.assertIsNone(finding(sender, to))


if __name__ == '__main__':
    unittest.main()
