"""File-sharing notices whose button leaves the service they name (synthetic inputs, text
rules only)."""
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

WETRANSFER = ('<p>info@partner-co.com sent you some files</p><p>3 items, 3.6 MB in total. Expires on 8 August.</p>'
              '<a href="{link}">Download</a><p>About WeTransfer</p>')
ONEDRIVE = '<p>info@example.org shared a file with you using OneDrive.</p><a href="{link}">Open</a>'


def analyze_eml(sender, body, subject='You have received files'):
    raw = (f'From: {sender}\r\nTo: user@example.org\r\nSubject: {subject}\r\n'
           'Content-Type: text/html; charset=utf-8\r\n\r\n' + body).encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def finding(result):
    return next((item for item in result['extra_indicators'] if item.get('code') == 'link.file_share_elsewhere'), None)


class FileShareElsewhereTests(unittest.TestCase):
    def test_a_download_button_on_another_host(self):
        result = analyze_eml('WeTransfer <info@dental-office.com.au>',
                             WETRANSFER.format(link='https://files-review.workers.dev/get'))
        item = finding(result)
        self.assertEqual(item['params'], {'service': 'WeTransfer', 'host': 'files-review.workers.dev'})
        self.assertEqual(result['risk_level'], 'high')
        self.assertIn('impersonation', result['mail_type']['tactics'])

    def test_the_service_named_only_by_the_display_name(self):
        result = analyze_eml('OneDrive <share@mimeld.com>',
                             '<p>info@example.org sent you a file.</p><a href="https://vine-360.netserver.info/s">Open</a>')
        self.assertEqual(finding(result)['params']['service'], 'OneDrive')

    def test_genuine_notices(self):
        for sender, body in (
                ('WeTransfer <noreply@wetransfer.com>', WETRANSFER.format(link='https://we.tl/t-AbC123')),
                ('Ana via OneDrive <no-reply@onedrive.com>', ONEDRIVE.format(link='https://1drv.ms/b/s!Abc')),
                ('Ana via SharePoint <no-reply@sharepointonline.com>',
                 ONEDRIVE.format(link='https://contoso-my.sharepoint.com/:b:/p/ana/Ebc')),
                ('Ana (via Google Drive) <drive-shares-dm-noreply@google.com>',
                 '<p>Ana shared a document with you via Google Drive.</p>'
                 '<a href="https://drive.google.com/file/d/1abc/view">Open</a>'),
                ('Dropbox Sign <noreply@mail.hellosign.com>',
                 '<p>Ana sent you a document to review and sign with Dropbox.</p>'
                 '<a href="https://app.hellosign.com/sign/abc">Review document</a>'),
                # A company's own file portal.
                ('Files <files@contoso.com>', '<p>Ana sent you some files. Unlike Dropbox, nothing expires.</p>'
                                              '<a href="https://share.contoso.com/d/abc">Download</a>')):
            with self.subTest(sender=sender):
                self.assertIsNone(finding(analyze_eml(sender, body)))

    def test_the_notice_wording_and_an_action_label_are_both_needed(self):
        self.assertIsNone(finding(analyze_eml('Newsletter <news@shop.example.com>',
                                              '<p>Back up your photos to Dropbox this summer.</p>'
                                              '<a href="https://shop.example.net/sale">Download the guide</a>')))
        self.assertIsNone(finding(analyze_eml('WeTransfer <info@dental-office.com.au>',
                                              WETRANSFER.replace('Download', 'Unsubscribe').format(
                                                  link='https://files-review.workers.dev/u'))))


if __name__ == '__main__':
    unittest.main()
