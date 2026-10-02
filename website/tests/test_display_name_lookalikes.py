"""Brand names in display names written with lookalike letters: Greek and Cyrillic
capitals ("Βank oϝ Αmerica") and a capital I for l ("PayPaI")."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import email_structure as es  # noqa: E402


def brand_findings(sender: str):
    raw = f'From: {sender}\r\nTo: user@example.org\r\nSubject: Notice\r\n\r\nHello'.encode()
    return [item['params'] for item in es.analyze_raw_email(raw)['indicators']
            if item['code'] == 'structure.brand_display_name']


class LookalikeDisplayNameTests(unittest.TestCase):
    def test_registry_brands(self):
        for display, brand in (('Βank oϝ Αmerica', 'Bank of America'),   # Greek capitals and digamma
                               ('Сhase Bank', 'Chase Bank'),              # Cyrillic С
                               ('WeIIs Fargo', 'Wells Fargo'),            # capital I for l
                               ('Wells Fargo', 'Wells Fargo')):
            with self.subTest(display=display):
                self.assertEqual(es._registry_brand_claim(display, 'example.net'), brand)
                self.assertEqual(brand_findings(f'{display} <alerts@example.net>'),
                                 [{'brand': brand, 'domain': 'example.net'}])

    def test_protected_brands(self):
        self.assertEqual(brand_findings('PayPaI <service@example.net>'), [{'brand': 'paypal', 'domain': 'example.net'}])
        self.assertEqual(brand_findings('ΡayΡal <service@example.net>'), [{'brand': 'paypal', 'domain': 'example.net'}])

    def test_names_that_are_no_claim(self):
        for display in ('LinkedIn', 'McIntyre Bank', 'Chase', 'Сбербанк', 'Ivan Petrov'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.net'))
        # The brand's own domain is no impersonation, whatever the letters.
        self.assertIsNone(es._registry_brand_claim('Βank oϝ Αmerica', 'bankofamerica.com'))

    def test_skeleton(self):
        self.assertEqual(es._confusable_skeleton('ΒΗΜ'), 'bhm')
        self.assertEqual(es._capital_i_as_l('PayPaI WeIIs ICBC LinkedIn'), 'PayPal Wells ICBC Linkedln')


if __name__ == '__main__':
    unittest.main()
