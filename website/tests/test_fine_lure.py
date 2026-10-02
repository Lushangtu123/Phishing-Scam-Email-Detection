"""Unpaid fine and toll lures with a link off the sender's and government domains
(synthetic inputs, text rules only)."""
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

OFF = 'https://pay-toll-now.example.net/p'


class FineLureTests(unittest.TestCase):
    def test_lures(self):
        for text in ('Your vehicle has an unpaid toll balance of $4.15. Pay now to avoid a late fee.',
                     'Final notice: your parking ticket is overdue.',
                     'Tienes una multa pendiente. Se ha identificado una multa de trafico no pagada.',
                     'Avis de contravention : votre amende impayée sera majorée.',
                     '您有一条交通违法记录未处理，请尽快缴纳罚款。',
                     '您的ETC已失效，请及时认证。'):
            with self.subTest(text=text):
                self.assertEqual(app._fine_lure(text, [('', OFF)]), 'pay-toll-now.example.net')

    def test_genuine_notices(self):
        toll = 'Your unpaid toll balance is due on 10 October.'
        # The operator's own site, a government site, and no link at all.
        self.assertIsNone(app._fine_lure(toll, [('Pay', 'https://pay.tolloperator.example.org/')], 'billing@tolloperator.example.org'))
        self.assertIsNone(app._fine_lure(toll, [('Pay', 'https://www.cityofexample.gov/parking')]))
        self.assertIsNone(app._fine_lure(toll, [('Pay', 'https://www.dgt.gob.es/multas')]))
        self.assertIsNone(app._fine_lure(toll, []))
        # Fines in another sense, or tolls that are paid.
        for text in ('The library waives fines for overdue books this month.', 'Thanks, your toll balance is paid in full.'):
            with self.subTest(text=text):
                self.assertIsNone(app._fine_lure(text, [('Read more', OFF)]))

    def test_analysis(self):
        raw = ('From: Ministerio del Interior <notificaciones@interior.gob.es>\r\nTo: user@example.org\r\n'
               'Subject: Multa no pagada\r\nContent-Type: text/html; charset=utf-8\r\n\r\n'
               '<p>Tienes una multa pendiente. Se ha identificado en nuestro sistema una multa de trafico no pagada.</p>'
               '<p>Para ver la notificacion visite: <a href="https://infraccion.eastus.cloudapp.azure.com/">aqui</a></p>').encode()
        with patch.object(app, '_content_pipeline', None):
            result = json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                                 observe_sender_history=False)).body)
        item = next(item for item in result['extra_indicators'] if item.get('code') == 'content.fine_lure')
        self.assertEqual(item['params'], {'host': 'infraccion.eastus.cloudapp.azure.com'})
        self.assertEqual(result['risk_level'], 'high')
        self.assertIn('payment', result['mail_type']['tactics'])


if __name__ == '__main__':
    unittest.main()
