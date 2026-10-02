"""The sending server's address from the receiving service's Received lines, and the
checked-in Tor exit and Spamhaus DROP lists (synthetic inputs; no network)."""
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(WEBSITE_DIR / 'tools'))

import email_structure as es  # noqa: E402
import ip_reputation  # noqa: E402
import update_ip_reputation  # noqa: E402

TOR_EXIT = '185.220.101.1'
DROP_ADDRESS = '1.10.16.9'


def payload(**changes):
    data = {
        'schema': ip_reputation.REPUTATION_SCHEMA,
        'tor_exits': {'source': 'test', 'fetched': '2026-10-02T16:50Z',
                      'addresses': [TOR_EXIT] + [f'198.18.0.{index}' for index in range(1, 120)]},
        'spamhaus_drop': {'source': 'test', 'fetched': '2026-10-02T16:50Z', 'copyright': '(c) 2026 The Spamhaus Project SLU',
                          'terms': 'https://www.spamhaus.org/drop/terms/',
                          'networks': [['1.10.16.0/20', 'SBL256894'], ['2001:db8::/32', 'SBL1']]
                          + [[f'100.{index}.0.0/16', f'SBL{index}'] for index in range(100, 220)]},
    }
    data.update(changes)
    return data


REPUTATION = ip_reputation.IpReputation(payload())

GMAIL = """Received: by 2002:a05:7300:5c8b:b0:1a2:3b4c:5d6e with SMTP id x11csp123456dyc;
        Fri, 2 Oct 2026 08:00:01 -0700 (PDT)
Received: from mail.sender.example (mail.sender.example. [{server}])
        by mx.google.com with ESMTPS id abc123; Fri, 02 Oct 2026 08:00:00 -0700 (PDT)
Received: from forged.example ([{forged}]) by mail.sender.example; Fri, 02 Oct 2026 07:59:00 -0700
From: A <a@sender.example>
To: user@gmail.com
Subject: Notice

Hello
"""
OUTLOOK = """Received: from BN8PR04MB1234.namprd04.prod.outlook.com (2603:10b6:408:70::12) by SA1PR04MB5678.namprd04.prod.outlook.com with HTTPS; Fri, 2 Oct 2026 15:00:02 +0000
Received: from BN1PEPF00004683.namprd03.prod.outlook.com (2603:10b6:408:e1::4) by BN8PR04MB1234.namprd04.prod.outlook.com (2603:10b6:408:70::12) with Microsoft SMTP Server; Fri, 2 Oct 2026 15:00:01 +0000
Received: from mail.sender.example ({server}) by BN1PEPF00004683.mail.protection.outlook.com (10.167.243.75) with Microsoft SMTP Server; Fri, 2 Oct 2026 15:00:00 +0000
X-Originating-IP: [{origin}]
From: A <a@sender.example>
To: user@outlook.com
Subject: Notice

Hello
"""


def structure(raw: str, mailbox=None):
    with patch.object(es, 'load_ip_reputation', return_value=REPUTATION):
        return es.analyze_raw_email(raw.encode(), mailbox_provider=mailbox)


def found(result):
    return {item['code']: item.get('params') for item in result['indicators']
            if item['code'].startswith(('structure.sending_server', 'structure.originating_ip'))}


class ReputationTests(unittest.TestCase):
    def test_lookups(self):
        self.assertTrue(REPUTATION.tor_exit(TOR_EXIT))
        self.assertFalse(REPUTATION.tor_exit('93.184.216.34'))
        self.assertEqual(REPUTATION.drop_listing(DROP_ADDRESS), 'SBL256894')
        self.assertEqual(REPUTATION.drop_listing('2001:db8::5'), 'SBL1')
        self.assertIsNone(REPUTATION.drop_listing('1.10.32.1'))
        self.assertIsNone(REPUTATION.drop_listing('not an address'))

    def test_a_snapshot_must_keep_spamhaus_terms_and_enough_entries(self):
        broken = payload()
        del broken['spamhaus_drop']['copyright']
        with self.assertRaises(ValueError):
            ip_reputation.validate_ip_reputation(broken)
        with self.assertRaises(ValueError):
            ip_reputation.validate_ip_reputation(payload(tor_exits={'source': 't', 'fetched': 'x', 'addresses': [TOR_EXIT]}))

    def test_the_checked_in_snapshot(self):
        snapshot = json.loads(ip_reputation.DEFAULT_REPUTATION_PATH.read_text())
        ip_reputation.validate_ip_reputation(snapshot)
        self.assertIn('Spamhaus', snapshot['spamhaus_drop']['copyright'])
        self.assertIsNotNone(ip_reputation.load_ip_reputation())


class SendingServerTests(unittest.TestCase):
    def test_gmail(self):
        result = structure(GMAIL.format(server='93.184.216.34', forged=TOR_EXIT), 'gmail')
        self.assertEqual(result['sending_server'], {'address': '93.184.216.34', 'verified': True})
        # A line below Gmail's own was written by the sender: its Tor address is not read.
        self.assertEqual(found(result), {'structure.sending_server': {'ip': '93.184.216.34'}})

    def test_outlook_skips_its_internal_hops(self):
        result = structure(OUTLOOK.format(server=DROP_ADDRESS, origin=TOR_EXIT), 'outlook')
        self.assertEqual(result['sending_server'], {'address': DROP_ADDRESS, 'verified': True})
        self.assertEqual(found(result)['structure.sending_server_drop'],
                         {'ip': DROP_ADDRESS, 'listing': 'SBL256894', 'date': '2026-10-02'})
        self.assertEqual(found(result)['structure.originating_ip_tor'], {'ip': TOR_EXIT, 'date': '2026-10-02'})

    def test_without_a_chosen_mailbox_the_address_is_unverified(self):
        for raw, address in ((GMAIL.format(server='93.184.216.34', forged=TOR_EXIT), '93.184.216.34'),
                             (OUTLOOK.format(server='93.184.216.34', origin='93.184.216.35'), '93.184.216.34')):
            with self.subTest(address=address):
                result = structure(raw)
                self.assertEqual(result['sending_server'], {'address': address, 'verified': False})
                self.assertIn('structure.sending_server_unverified', found(result))

    def test_mail_sent_from_the_service_itself(self):
        raw = GMAIL.format(server='209.85.220.41', forged='93.184.216.34').replace(
            'from mail.sender.example (mail.sender.example.', 'from mail-sor-f41.google.com (mail-sor-f41.google.com.')
        self.assertEqual(structure(raw, 'gmail')['sending_server'], {'address': '209.85.220.41', 'verified': True})

    def test_private_and_missing_addresses(self):
        self.assertIsNone(structure(GMAIL.format(server='10.0.0.5', forged='192.168.1.1'), 'gmail')['sending_server'])
        self.assertIsNone(structure('From: a@b.example\r\nSubject: x\r\n\r\nhi')['sending_server'])


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class UpdateToolTests(unittest.TestCase):
    def test_build_from_downloaded_files(self):
        tor = '\n'.join([TOR_EXIT] + [f'198.18.1.{index}' for index in range(1, 120)])
        drop_v4 = '\n'.join(json.dumps({'cidr': f'100.{index}.0.0/16', 'sblid': f'SBL{index}', 'rir': 'arin'})
                            for index in range(100, 220))
        drop_v4 += '\n' + json.dumps({'type': 'metadata', 'timestamp': 1790000000,
                                      'copyright': '(c) 2026 The Spamhaus Project SLU'})
        drop_v6 = json.dumps({'cidr': '2001:db8::/32', 'sblid': 'SBL1', 'rir': 'ripencc'})
        bodies = {update_ip_reputation.TOR_URL: tor, update_ip_reputation.DROP_URLS[0]: drop_v4,
                  update_ip_reputation.DROP_URLS[1]: drop_v6}

        def opener(request, timeout):
            return _Response(bodies[request.full_url].encode())
        built = update_ip_reputation.build(opener)
        self.assertEqual(len(built['tor_exits']['addresses']), 120)
        self.assertEqual(len(built['spamhaus_drop']['networks']), 121)
        self.assertEqual(built['spamhaus_drop']['copyright'], '(c) 2026 The Spamhaus Project SLU')
        self.assertTrue(ip_reputation.IpReputation(built).tor_exit(TOR_EXIT))

    def test_an_error_page_is_rejected(self):
        bodies = {update_ip_reputation.TOR_URL: '<html>error</html>'}

        def opener(request, timeout):
            return _Response(bodies.get(request.full_url, '').encode())
        with self.assertRaises(ValueError):
            update_ip_reputation.build(opener)


if __name__ == '__main__':
    unittest.main()
