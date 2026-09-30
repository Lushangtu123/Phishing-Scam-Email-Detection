import asyncio
import json
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
from email_structure import _dkim_pass_domains, analyze_raw_email, display_name_matches_domain  # noqa: E402

GMAIL_AUTH = ('Authentication-Results: mx.google.com;\r\n'
              '       dkim=pass header.i=@{dkim} header.s=s1 header.b=abc;\r\n'
              '       dkim=pass header.i=@sendgrid.info header.s=smtpapi;\r\n'
              '       spf=pass (google.com: domain of bounce@{domain} designates 192.0.2.1) smtp.mailfrom={domain};\r\n'
              '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={domain}\r\n')


def message(sender='confirm@account.acmecloud.com', name='Acme Cloud', *, dkim=None, auth=None):
    domain = sender.rpartition('@')[2]
    auth = GMAIL_AUTH.format(domain=domain, dkim=dkim or domain) if auth is None else auth
    return (auth + f'From: {name} <{sender}>\r\nTo: user@example.com\r\nSubject: Confirm your email\r\n'
            'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            'Welcome to Acme Cloud. Your workspace is ready.\r\n').encode()


def authenticated(raw, mailbox='gmail'):
    return analyze_raw_email(raw, mailbox_provider=mailbox)['authenticated_sender']


def upload(raw, query=b'mailbox=gmail'):
    chunks = iter([raw])

    async def receive():
        chunk = next(chunks, None)
        return {'type': 'http.request', 'body': chunk or b'', 'more_body': chunk is not None}
    request = app.Request({'type': 'http', 'query_string': query,
                           'headers': [(b'content-type', b'message/rfc822')]}, receive)
    return json.loads(asyncio.run(app.analyze_eml_endpoint(request)).body)


class DisplayNameMatchTests(unittest.TestCase):
    def test_names_of_the_domains_organization_match(self):
        for name, domain in (('Dropbox', 'txn.dropbox.com'), ('Notion Team', 'updates.notion.com'),
                             ('Steam', 'steampowered.com'), ('EA', 'e.ea.com'),
                             ('Epic Games', 'acct-auth.epicgames.com'), ('"=?utf-8?q?Acme?="', 'account.acme.com'),
                             ('Stripe (stripe.com)', 'stripe.com'), ('', 'mail.acme.com')):
            with self.subTest(name=name):
                self.assertTrue(display_name_matches_domain(name, domain))

    def test_generic_unrelated_or_foreign_domain_names_do_not_match(self):
        for name, domain, local in (('IT Support', 'tukachinamt.example', 'account'),
                                    ('Track & Trace', 'septifix.best', 'notice'),
                                    ('NTFX', 'ntfix.clientportal.com', 'notifications'),
                                    ('monkey.org Portal Notification', 'mobliityworks.com', 'no-reply'),
                                    ('abdullahis@hotmail.com', 'acme.com', 'x'),
                                    ('', 'tirnorport.com', 'monkey.org accounting'),
                                    ('support.apple.com', 'evil.example', 'x')):
            with self.subTest(name=name, local=local):
                self.assertFalse(display_name_matches_domain(name, domain, local))


class AuthenticatedSenderStructureTests(unittest.TestCase):
    def test_dkim_domains_come_from_passing_clauses_only(self):
        header = ('mx.google.com; dkim=pass header.i=@mg.acme.com; dkim=pass (comment header.d=evil.example)'
                  ' header.d=acme.net; dkim=fail header.d=forged.example; spf=pass smtp.mailfrom=acme.com')
        self.assertEqual(_dkim_pass_domains(header), {'mg.acme.com', 'acme.net'})

    def test_aligned_dmarc_and_dkim_from_the_trusted_header_authenticate(self):
        self.assertEqual(authenticated(message()), {'domain': 'account.acmecloud.com',
                                                    'organizational_domain': 'acmecloud.com',
                                                    'display_name_matches': True})
        # A signature from a parent or sibling domain of the same organization aligns.
        self.assertIsNotNone(authenticated(message(dkim='mail.acmecloud.com')))
        self.assertFalse(authenticated(message(name='IT Support'))['display_name_matches'])

    def test_untrusted_unaligned_or_consumer_senders_are_not_authenticated(self):
        self.assertIsNone(authenticated(message(), mailbox=None))
        self.assertIsNone(authenticated(message(dkim='sendgrid.net')))
        for sender in ('someone@gmail.com', 'someone@mail.ru', 'someone@yandex.ru'):
            with self.subTest(sender=sender):
                self.assertIsNone(authenticated(message(sender)))
        misaligned = GMAIL_AUTH.format(domain='other.example', dkim='account.acmecloud.com')
        self.assertIsNone(authenticated(message(auth=misaligned)))


class AuthenticatedSenderScoringTests(unittest.TestCase):
    def sender_findings(self, result):
        return {item['code']: item['level'] for item in result['extra_indicators'] if item['code'].startswith('sender.')}

    def test_address_shape_findings_are_shown_but_not_scored(self):
        result = upload(message())
        self.assertEqual(result['sender_analysis']['verdict'], 'low')
        findings = self.sender_findings(result)
        self.assertEqual(findings['sender.username_keywords'], 'info')
        self.assertEqual(findings['sender.domain_keywords'], 'info')
        self.assertEqual(findings['sender.unrecognized_provider'], 'info')
        self.assertIn('sender.authenticated_domain', findings)
        self.assertIsNone(result['verified_official_sender'])

    def test_without_a_mailbox_or_a_matching_name_the_findings_still_count(self):
        for raw, query in ((message(), b''), (message(name='IT Support'), b'mailbox=gmail'),
                           (message(dkim='sendgrid.net'), b'mailbox=gmail')):
            with self.subTest(query=query):
                result = upload(raw, query)
                self.assertEqual(result['sender_analysis']['verdict'], 'high')
                self.assertNotIn('sender.authenticated_domain', self.sender_findings(result))

    def test_keywords_in_the_registrable_domain_are_still_scored(self):
        result = upload(message('hello@account.secure-login-acme.com', name='Secure Login Acme'))
        self.assertEqual(self.sender_findings(result)['sender.domain_keywords'], 'high')
        self.assertEqual(self.sender_findings(result)['sender.unrecognized_provider'], 'info')
        self.assertEqual(result['sender_analysis']['verdict'], 'medium')


if __name__ == '__main__':
    unittest.main()
