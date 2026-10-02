"""Brand names and lure words written with a capital I for l ("PayPaI", "Trust WaIIet"),
in the text or the sender's display name (synthetic inputs, text rules only)."""
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


def analyze_eml(sender, body, subject='Notice'):
    raw = (f'From: {sender}\r\nTo: user@example.org\r\nSubject: {subject}\r\n'
           'Content-Type: text/plain; charset=utf-8\r\n\r\n' + body).encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def obfuscation(result):
    return next((item for item in result['extra_indicators'] if item.get('code') == 'content.obfuscation'), None)


class LetterSwapTests(unittest.TestCase):
    def test_swapped_words(self):
        self.assertEqual(app._letter_swaps('Trust WaIIet Support'), ['Wallet'])
        self.assertEqual(app._letter_swaps('PayPaI Service'), ['PayPal'])
        self.assertEqual(app._letter_swaps('AppIe ltunes receipt'), ['Apple', 'iTunes'])
        self.assertEqual(app._letter_swaps('WeIIs Fargo: biIIing alert, DeIivery FaiIed'),
                         ['Billing', 'Delivery', 'Failed', 'Wells'])
        self.assertEqual(app._letter_swaps('Your lnvoice is ready'), ['Invoice'])

    def test_words_that_are_not_swaps(self):
        for text in ('LinkedIn', 'McIntyre', 'TransactionId', 'TicketInfo', 'PayPal', 'WALLET', 'MAIL',
                     'large label', 'iTunes and iCloud', 'loan claim', 'OpenID Connect', 'CanIt PRO'):
            with self.subTest(text=text):
                self.assertEqual(app._letter_swaps(text), [])

    def test_leetspeak_is_still_found(self):
        self.assertEqual(app._detect_obfuscation('Your P@yP@l account'), ['PayPal'])
        self.assertEqual(app._detect_obfuscation('Your P@yP@l and PayPaI account'), ['PayPal'])


class AnalysisTests(unittest.TestCase):
    def test_a_swap_in_the_display_name(self):
        result = analyze_eml('PayPaI <service@notice-center.com>', 'Please review the attached notice.')
        item = obfuscation(result)
        self.assertIsNotNone(item)
        self.assertEqual(item['params']['brands'], 'PayPal')
        self.assertIn('impersonation', result['mail_type']['tactics'])

    def test_a_swap_in_the_body_is_reported_once(self):
        result = analyze_eml('Trust WaIIet <support@wallet-help.com>',
                             'Provide your WaIIet address to receive your transaction.')
        self.assertEqual([item.get('code') for item in result['extra_indicators']].count('content.obfuscation'), 1)

    def test_a_genuine_display_name(self):
        self.assertIsNone(obfuscation(analyze_eml('LinkedIn <messages-noreply@linkedin.com>', 'You have a new message.')))


if __name__ == '__main__':
    unittest.main()
