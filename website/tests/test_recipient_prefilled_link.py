"""Links that carry the recipient's own address to an unlisted site off the sender's domain
(synthetic inputs, text rules only)."""
import asyncio
import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import email_structure as es  # noqa: E402

ME = ['jose@example.org']


class PrefilledLinkTests(unittest.TestCase):
    def test_links_that_carry_the_address(self):
        encoded = base64.b64encode(b'jose@example.org').decode()
        for link in ('https://royalgarden.example.shop/cn/?email=jose@example.org',
                     'https://raik.example.ir/?email=jose%40example.org',
                     'https://glitch-page.example.me/har.html#jose@example.org',
                     f'https://portal.example.top/index.php?u={encoded}'):
            with self.subTest(link=link):
                self.assertIsNotNone(app._recipient_prefilled_link([('Open', link)], ME))

    def test_links_that_are_no_lure(self):
        for label, link, sender in (
                ('Unsubscribe', 'https://news.example.net/unsubscribe?email=jose@example.org', ''),
                ('', 'https://news.example.net/preferences?email=jose@example.org', ''),
                ('Verify', 'https://app.example.net/verify?email=jose@example.org', 'noreply@example.net'),  # the sender's own
                ('Sign in', 'https://accounts.google.com/?Email=jose@example.org', ''),                    # a listed provider
                ('Reply', 'mailto:jose@example.org', ''),
                ('Open', 'https://portal.example.top/index.php?u=someone-else', '')):
            with self.subTest(link=link):
                self.assertIsNone(app._recipient_prefilled_link([(label, link)], ME, sender.rpartition('@')[2]))
        self.assertIsNone(app._recipient_prefilled_link([('Open', 'https://x.example.top/?email=jose@example.org')], []))

    def test_analysis(self):
        raw = ('From: Joyt Master <billing@vps-mailer.example.com>\r\nTo: jose@example.org\r\nSubject: Document\r\n'
               'Content-Type: text/html; charset=utf-8\r\n\r\n<p>A document was shared with you.</p>'
               '<a href="https://royalgarden.example.shop/cn/?email=jose@example.org">View document</a>').encode()
        with patch.object(app, '_content_pipeline', None):
            result = json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                                 observe_sender_history=False)).body)
        item = next(item for item in result['extra_indicators'] if item.get('code') == 'link.recipient_prefilled')
        self.assertEqual(item['params'], {'host': 'royalgarden.example.shop'})
        self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})
        self.assertIn('credential', result['mail_type']['tactics'])


if __name__ == '__main__':
    unittest.main()
