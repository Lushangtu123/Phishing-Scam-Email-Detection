"""Buttons that lead to content anyone can publish on a trusted platform (synthetic inputs,
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

PRIME = ('<p>Your Amazon Prime Membership is set to renew on Wed, June 19. However, the payment method associated '
         'with your membership is no longer valid.</p><a href="{url}">{label}</a>')


def analyze(body, subject='Your Prime membership is renewing'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def codes(result):
    return {item.get('code') for item in result['extra_indicators']}


class UserContentButtonTests(unittest.TestCase):
    def test_an_account_or_payment_button_on_a_published_document(self):
        for url, label in (('https://docs.google.com/drawings/d/1KSXopH/edit', 'Update Information'),
                           ('https://forms.office.com/r/x1y2', 'Verify your account'),
                           ('https://sites.google.com/view/prime-billing', 'Update payment'),
                           ('https://www.dropbox.com/s/abc/statement.pdf', 'Log in to view')):
            with self.subTest(url=url):
                result = analyze(PRIME.format(url=url, label=label))
                self.assertEqual(result['risk_level'], 'high')
                self.assertIn('link.user_content_action', codes(result))
                self.assertIn('credential', result['mail_type']['tactics'])

    def test_ordinary_shares_and_forms(self):
        for url, label in (('https://docs.google.com/forms/d/e/x/viewform', 'Confirm attendance'),
                           ('https://docs.google.com/document/d/x/edit', 'View document'),
                           ('https://acme.sharepoint.com/sites/hr/Shared%20Documents/x', 'Log in'),
                           ('https://www.amazon.com/gp/primecentral', 'Update Information')):
            with self.subTest(url=url):
                self.assertNotIn('link.user_content_action', codes(analyze(PRIME.format(url=url, label=label))))

    def test_a_mailbox_lure_on_a_trusted_platforms_form_is_not_exempt(self):
        lure = '<p>Your mailbox storage is full and incoming messages are on hold.</p><a href="{}">Release messages</a>'
        self.assertTrue(app._mailbox_lure('Your mailbox storage is full and incoming messages are on hold.',
                                          [('Release messages', 'https://forms.office.com/r/abc')]))
        self.assertIn('content.mailbox_lure', codes(analyze(lure.format('https://forms.office.com/r/abc'), 'Mailbox')))
        # The provider's own sign-in stays exempt.
        self.assertNotIn('content.mailbox_lure', codes(analyze(lure.format('https://outlook.office.com/mail/'), 'Mailbox')))


if __name__ == '__main__':
    unittest.main()
