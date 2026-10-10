"""Delivery lures: an unpaid shipping fee or a wrong address to correct, with the button on an
unrelated host (synthetic inputs, text rules only)."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

import content_rules  # noqa: E402
import email_structure as es  # noqa: E402

OFF = 'https://parcel-check.example.net/pay'


def analyze_eml(sender, body, subject='Your parcel'):
    raw = (f'From: {sender}\r\nTo: user@example.org\r\nSubject: {subject}\r\n'
           'Content-Type: text/html; charset=utf-8\r\n\r\n' + body).encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


class DeliveryLureTests(unittest.TestCase):
    def test_lures(self):
        for text, label in (
                ('Your package is stopped at our post. R 25.00 shipping cost have not been paid.', 'Continue'),
                ('Your package is ready for delivery. Confirm the shipping fee 50 ZAR by clicking below.', 'CONFIRM'),
                ('Your parcel could not be delivered due to incorrect address details. '
                 'Please update your shipping address.', 'Click Here'),
                ('We are unable to locate you due to a mix up in your address. Kindly fill your correct address '
                 'to deliver your package.', 'Update Address'),
                ('Your shipment is held. Pay the customs duty of $2.99 to release it.', 'Pay now')):
            with self.subTest(text=text):
                self.assertEqual(content_rules._delivery_lure(text, [(label, OFF)]), 'parcel-check.example.net')

    def test_genuine_notices(self):
        address = 'We could not deliver your package: incomplete address. Please update your delivery address.'
        # A carrier's official site, the sender's own, and a retailer's tracking platform.
        self.assertIsNone(content_rules._delivery_lure(address, [('Update address', 'https://www.ups.com/track')]))
        self.assertIsNone(content_rules._delivery_lure(address, [('Update address', 'https://shop.example.org/a')],
                                             'orders@example.org'))
        self.assertIsNone(content_rules._delivery_lure(address, [('Update address', 'https://shop.narvar.com/x')]))
        # A missed delivery, a paid order, and an order total that mentions shipping.
        for text in ('Sorry we missed you! Schedule your next delivery date.',
                     'Your order has shipped. Shipping fee: paid. Track your package below.',
                     'Order total $54.00 including shipping costs. Your delivery arrives Tuesday.'):
            with self.subTest(text=text):
                self.assertIsNone(content_rules._delivery_lure(text, [('Track package', OFF)]))

    def test_analysis(self):
        result = analyze_eml('South African post office <7011870@notice-mail.com>',
                             '<p>Your package is ready for delivery. Confirm the shipping fee 50 ZAR by clicking on the '
                             f'button below.</p><a href="{OFF}">CONFIRM</a>')
        item = next(item for item in result['extra_indicators'] if item.get('code') == 'content.delivery_lure')
        self.assertEqual(item['params'], {'host': 'parcel-check.example.net'})
        self.assertEqual(result['risk_level'], 'high')
        self.assertIn('payment', result['mail_type']['tactics'])


if __name__ == '__main__':
    unittest.main()
