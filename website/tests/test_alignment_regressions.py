import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
from email_structure import analyze_raw_email  # noqa: E402

AUTH = ('Authentication-Results: mx.google.com;\r\n'
        '       dkim=pass header.i=@{dkim} header.s=s1;\r\n'
        '       spf=pass smtp.mailfrom=bounce@em.{dkim};\r\n'
        '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={header_from}\r\n')


def message(sender, name, header_from, dkim):
    return (AUTH.format(dkim=dkim, header_from=header_from)
            + f'From: {name} <{sender}>\r\nTo: user@example.com\r\nSubject: Your login code\r\n'
              'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour code is 273066.\r\n').encode()


class DmarcOrganizationalHeaderFromTests(unittest.TestCase):
    def test_gmail_reporting_the_organizational_domain_still_aligns(self):
        # Gmail reported header.from=spotify.com for no-reply@alerts.spotify.com.
        structure = analyze_raw_email(message('no-reply@alerts.spotify.com', 'Spotify', 'spotify.com', 'spotify.com'),
                                      mailbox_provider='gmail')
        self.assertEqual(structure['authenticated_sender']['domain'], 'alerts.spotify.com')
        official = analyze_raw_email(message('noreply@notify.github.com', 'GitHub', 'github.com', 'github.com'),
                                     mailbox_provider='gmail')
        self.assertEqual(official['verified_official_sender'], {'organization': 'GitHub', 'domain': 'notify.github.com'})

    def test_another_domain_or_a_child_domain_does_not_align(self):
        for sender, header_from in (('no-reply@alerts.spotify.com', 'evil.example'),
                                    ('no-reply@spotify.com', 'alerts.spotify.com'),
                                    ('no-reply@spotify.com.evil.example', 'spotify.com')):
            with self.subTest(sender=sender, header_from=header_from):
                structure = analyze_raw_email(message(sender, 'Spotify', header_from, header_from),
                                              mailbox_provider='gmail')
                self.assertIsNone(structure['authenticated_sender'])
                self.assertIsNone(structure['verified_official_sender'])


class DisplayHostWwwTests(unittest.TestCase):
    def mismatch(self, text, href):
        _score, findings, _floor = app._analyze_link_destinations(f'<a href="{href}">{text}</a>')
        return 'link.display_mismatch' in [finding.get('code') for finding in findings]

    def test_www_display_matches_the_same_sites_subdomains(self):
        self.assertFalse(self.mismatch('www.spotify.com', 'https://wl.spotify.com/ls/click?upn=abc'))
        self.assertFalse(self.mismatch('www.bbc.co.uk', 'https://news.bbc.co.uk/'))

    def test_other_destinations_and_shared_hosts_still_mismatch(self):
        self.assertTrue(self.mismatch('www.paypal.com', 'https://paypal.com.login.example/'))
        self.assertTrue(self.mismatch('www.spotify.com', 'https://spotify-account.example/'))
        # Subdomains of a shared host (a private public suffix) belong to different users.
        self.assertTrue(self.mismatch('www.github.io', 'https://evil.github.io/'))
        self.assertTrue(self.mismatch('www.co.uk', 'https://evil.co.uk/'))


if __name__ == '__main__':
    unittest.main()
