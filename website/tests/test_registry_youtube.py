"""YouTube in the official registry (2026-10-05): its mail comes only from @youtube.com or
@google.com, per YouTube Help. The pattern is a phishing exercise's "YouTube" sender on an
unrelated domain (synthetic inputs)."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import email_structure as es  # noqa: E402

GMAIL_PASS = ('Authentication-Results: mx.google.com;\r\n'
              '       dkim=pass header.i=@{domain} header.s=s1;\r\n'
              '       spf=pass (google.com: domain of bounce@{domain} designates 192.0.2.1 as permitted sender)'
              ' smtp.mailfrom=bounce@{domain};\r\n'
              '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={domain}\r\n')
SUSPENDED = ('<p>Dear member,</p><p>We have detected suspicious activity on your account. For your protection, '
             'we have temporarily suspended your account. Please sign in using the link below to reactivate your '
             'YouTube account and restore access.</p><p><a href="https://platform-example.co/v1/cs/1234">Reactivate '
             'account</a></p><p>The YouTube Team</p>')


def message(sender, *, name='YouTube', auth='', body=SUSPENDED, subject='Your YouTube Account Has Been Suspended'):
    return (auth + f'From: {name} <{sender}>\r\nTo: member@example.edu\r\nSubject: {subject}\r\n'
            f'MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}\r\n').encode()


def analyze(raw, mailbox=None):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(
            app.ContentRequest(), es.analyze_raw_email(raw, mailbox_provider=mailbox), observe_sender_history=False)).body)


class YouTubeRegistryTests(unittest.TestCase):
    def test_claimed_from_other_domains(self):
        for display, domain in (('YouTube', 'youtube.platform-example.co'), ('YouTube Team', 'secure-login.example'),
                                ('YouTube Security', 'mail.example.net')):
            with self.subTest(display=display, domain=domain):
                self.assertEqual(es._registry_brand_claim(display, domain), 'YouTube')

    def test_its_own_domains(self):
        for domain in ('youtube.com', 'no-reply.youtube.com', 'google.com', 'accounts.google.com'):
            with self.subTest(domain=domain):
                self.assertIsNone(es._registry_brand_claim('YouTube', domain))

    def test_other_names(self):
        for display in ('YouTubers Weekly', 'My Tube', 'Tube Times'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.net'))

    def test_the_exercise_pattern(self):
        for mailbox in (None, 'gmail'):
            with self.subTest(mailbox=mailbox):
                result = analyze(message('no-reply@youtube.platform-example.co'), mailbox)
                self.assertIn(result['risk_level'], {'high', 'critical'})
                claims = [item['params'] for item in result['extra_indicators']
                          if item['code'] == 'structure.brand_display_name']
                self.assertEqual(claims, [{'brand': 'YouTube', 'domain': 'youtube.platform-example.co'}])
                channel = next(item for item in result['official_channels'] if item['organization'] == 'YouTube')
                self.assertEqual(channel['website'], 'youtube.com')
                self.assertIn('never', channel['statement'])

    def test_youtube_own_mail_is_verified(self):
        notice = ('<p>Your video has been published.</p><p><a href="https://www.youtube.com/watch?v=abc">Watch '
                  'it</a></p>')
        result = analyze(message('no-reply@youtube.com', auth=GMAIL_PASS.format(domain='youtube.com'), body=notice,
                                 subject='Your video is live'), 'gmail')
        self.assertEqual(result['verified_official_sender'], {'organization': 'YouTube', 'domain': 'youtube.com'})
        self.assertNotIn('structure.brand_display_name', {item['code'] for item in result['extra_indicators']})


if __name__ == '__main__':
    unittest.main()
