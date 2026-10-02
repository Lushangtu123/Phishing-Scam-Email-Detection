"""Account-hold lures in a message body with a link off the sender's domain (synthetic inputs,
text rules only)."""
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

LURE = ('<p>During our regular update we noticed unusual activities on your online account. Your online account '
        'has been temporarily suspended. You are required to login below to verify your details.</p>')


def analyze_eml(sender, body):
    raw = (f'From: {sender}\r\nTo: user@example.org\r\nSubject: Security Update\r\n'
           'Content-Type: text/html; charset=utf-8\r\n\r\n' + body).encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def finding(result):
    return next((item for item in result['extra_indicators'] if item.get('code') == 'content.account_hold_lure'), None)


class AccountHoldBodyTests(unittest.TestCase):
    def test_a_lure_linking_elsewhere(self):
        result = analyze_eml('Online Banking <alerts@notice-mailer.example.com>',
                             LURE + '<a href="https://2your.example.gq/update/security">Log in</a>')
        self.assertEqual(finding(result)['params'], {'host': '2your.example.gq'})
        self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})

    def test_genuine_notices(self):
        # The service's own domain, and an official one.
        self.assertIsNone(finding(analyze_eml('Bank <alerts@examplebank.com>',
                                              LURE + '<a href="https://secure.examplebank.com/login">Log in</a>')))
        self.assertIsNone(finding(analyze_eml('Wells Fargo <alerts@notify.wellsfargo.com>',
                                              LURE + '<a href="https://www.wellsfargo.com/">Sign on</a>')))
        # A notice without the request, or an account that is fine.
        self.assertIsNone(finding(analyze_eml('Shop <news@shop.example.com>',
                                              '<p>Your account is active. Enjoy 10% off.</p>'
                                              '<a href="https://deals.example.net/">Shop now</a>')))


if __name__ == '__main__':
    unittest.main()
