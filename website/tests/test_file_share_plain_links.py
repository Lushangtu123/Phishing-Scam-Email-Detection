"""File-sharing notices in plain text: "sent using Dropbox" wording, and a bare address whose
instruction stands just before it (synthetic inputs, text rules only)."""
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


def analyze_plain(body, sender='Finance <finance@trading-co.example.com>'):
    raw = (f'From: {sender}\r\nTo: user@example.org\r\nSubject: Revised agreements\r\n'
           'Content-Type: text/plain; charset=utf-8\r\n\r\n' + body).encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def finding(result):
    return next((item for item in result['extra_indicators'] if item.get('code') == 'link.file_share_elsewhere'), None)


class PlainTextFileShareTests(unittest.TestCase):
    def test_a_bare_link_after_the_instruction(self):
        result = analyze_plain('Hi Signed revised agreements has been sent using Dropbox file viewer. Press Here sign in '
                               'with your email to view the message. http://files.example-host.ca/camp/dropbox')
        self.assertEqual(finding(result)['params'], {'service': 'Dropbox', 'host': 'files.example-host.ca'})
        self.assertEqual(result['risk_level'], 'high')

    def test_genuine_notices(self):
        # The service's own link.
        self.assertIsNone(finding(analyze_plain(
            'The contract has been shared with you via Dropbox. Open it here: https://www.dropbox.com/s/abc/contract.pdf')))
        # The sender's own site.
        self.assertIsNone(finding(analyze_plain(
            'Your statement has been sent using Dropbox. View it at https://portal.trading-co.example.com/statements')))
        # A bare link with no instruction before it.
        self.assertIsNone(finding(analyze_plain(
            'The minutes have been uploaded to OneDrive by the secretary. Questions? http://help.example-host.net/contact')))

    def test_wording(self):
        for text in ('Signed revised agreements has been sent using Dropbox file viewer.',
                     'The invoice has been shared via OneDrive.', 'Documents have been uploaded through Google Drive.'):
            with self.subTest(text=text):
                self.assertTrue(content_rules._FILE_SHARE_NOTICE.search(text))
        self.assertFalse(content_rules._FILE_SHARE_NOTICE.search('The parcel has been sent using our courier.'))


if __name__ == '__main__':
    unittest.main()
