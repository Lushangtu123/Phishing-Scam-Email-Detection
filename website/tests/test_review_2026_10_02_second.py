"""Regressions from the review of 2026-10-02 at ca047e5: gradients and background sizes
browsers reject, backgrounds clipped to the text, the RDAP lookups' admission, a peer's
claimed name at the receiving boundary, link labels in each rendering view, and
government suffixes (synthetic inputs, text rules only, no network)."""
import asyncio
from email.parser import Parser
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
import html_visibility  # noqa: E402
from hidden_findings import hidden_codes, shown_codes  # noqa: E402
import domain_age  # noqa: E402
import email_structure as es  # noqa: E402

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30


def analyze(body, subject='Project update'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def codes(result):
    # Findings in what the message shows; hidden_codes lists those only text it may hide makes.
    return shown_codes(result)


def styled_callback(declarations):
    return (f'<style>.unused{{display:none}}.attack{{{declarations}}}</style>'
            f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>')


class GradientGrammarTests(unittest.TestCase):
    """S1: each gradient type has its own first argument and stop units (as Chromium
    reads them), and a background size is never negative."""

    REJECTED = ('linear-gradient(to circle,black,black)', 'linear-gradient(black 1deg,black)',
                'conic-gradient(black 10px,black)', 'linear-gradient(black,10px)',
                'linear-gradient(to left right,black,black)', 'linear-gradient(black 1px,2px,3px,black)',
                'black -1px / -2px', 'black 0 0 / 10px -2px', 'linear-gradient(10px black,black)',
                'radial-gradient(at banana,black,black)', 'radial-gradient(circle 10px 20px,black,black)',
                'radial-gradient(ellipse 10px,black,black)', 'radial-gradient(circle 10%,black,black)',
                'conic-gradient(from 10px,black,black)', 'linear-gradient(in banana,black,black)',
                'black 1 2', 'black text text')
    ACCEPTED = ('linear-gradient(to left top,black,black)', 'linear-gradient(in oklch longer hue,black,black)',
                'linear-gradient(black calc(10px),black)', 'linear-gradient(black 1px,2px,black)',
                'radial-gradient(circle 10px at left 10px top 5px,black 10%,black)',
                'radial-gradient(10px 20px,black,black)', 'conic-gradient(from 45deg at 10px 20px,black 10deg,black)',
                'conic-gradient(from calc(1deg),black 10%,black)', 'black -1px -2px', 'black 0 0 / 10px 20px',
                'black text', 'black border-box text')

    def test_backgrounds_browsers_reject(self):
        for value in self.REJECTED:
            with self.subTest(value=value):
                self.assertFalse(html_visibility._background_valid(value))

    def test_backgrounds_browsers_accept(self):
        for value in self.ACCEPTED:
            with self.subTest(value=value):
                self.assertTrue(html_visibility._background_valid(value))

    def test_rejected_gradients_leave_the_text_visible(self):
        for value in self.REJECTED[:7]:
            with self.subTest(value=value):
                result = analyze(styled_callback(f'color:black;background:{value}'))
                self.assertEqual(result['risk_level'], 'high')
                self.assertIn('content.callback_request', codes(result))

    def test_a_valid_one_colour_gradient_still_hides(self):
        result = analyze(styled_callback('color:black;background:linear-gradient(to left top,black,black)'))
        self.assertNotIn('content.callback_request', codes(result))
        # Hidden, it is still read as text the message may hide: a Medium finding, not High.
        self.assertIn('content.callback_request', hidden_codes(result))


class BackgroundClipTests(unittest.TestCase):
    """A background clipped to the text paints inside the glyphs only: no backdrop behind
    them, and transparent text shows it (gradient text)."""

    def test_text_shows(self):
        for declarations in ('color:black;background:black text',
                             'color:black;background:black;background-clip:text',
                             'color:transparent;background:#c00 text',
                             'background:linear-gradient(#c00,#c00);-webkit-background-clip:text;color:transparent'):
            with self.subTest(declarations=declarations):
                result = analyze(styled_callback(declarations))
                self.assertIn('content.callback_request', codes(result))
        inline = (f'<p style="background:linear-gradient(red,red);-webkit-background-clip:text;color:transparent">'
                  f'{CALLBACK}</p><p>{PADDING}</p>')
        self.assertIn('content.callback_request', codes(analyze(inline)))

    def test_text_that_stays_hidden(self):
        # Nothing paints inside transparent glyphs; an unclipped black background hides black text.
        for declarations in ('-webkit-background-clip:text;color:transparent', 'color:black;background:black'):
            with self.subTest(declarations=declarations):
                result = analyze(styled_callback(declarations))
                self.assertNotIn('content.callback_request', codes(result))
                self.assertIn('content.callback_request', hidden_codes(result))

    def test_clip_values(self):
        self.assertEqual(html_visibility._background_clip('text'), 'all')
        self.assertEqual(html_visibility._background_clip('border-box, text'), 'some')
        self.assertEqual(html_visibility._background_clip('black'), 'none')
        self.assertFalse(html_visibility._background_clip_valid('text text'))
        self.assertTrue(html_visibility._background_clip_valid('padding-box, text'))


class RdapAdmissionTests(unittest.TestCase):
    """S2: lookups are admitted up to a bound, one per domain in flight, and those nobody
    waits for any more are cancelled before they start."""

    SERVERS = {'com': 'https://rdap.invalid/'}

    def setUp(self):
        self.release = threading.Event()
        self.calls = []

    def tearDown(self):
        self.release.set()
        deadline = time.monotonic() + 3
        while domain_age._pending and time.monotonic() < deadline:
            time.sleep(0.01)
        with domain_age._cache_lock:
            domain_age._cache.clear()

    def blocked(self, url, timeout):
        self.calls.append(url)
        self.release.wait(2)
        return {}

    def test_timed_out_lookups_do_not_pile_up(self):
        async def run():
            for group in range(4):
                dates = await domain_age.lookup_many_async([f'case{group}-{index}.com' for index in range(5)],
                                                           fetch=self.blocked, servers=self.SERVERS, deadline=0.01)
                self.assertEqual(set(dates.values()), {None})
        asyncio.run(run())
        # Lookups nobody waits for keep their slot until the pool reaches and skips them.
        self.assertLessEqual(domain_age._admitted, domain_age.MAX_PENDING_LOOKUPS)
        self.release.set()
        time.sleep(0.2)
        self.assertLessEqual(len(self.calls), domain_age._pool._max_workers)

    def test_admission_is_bounded(self):
        for group in range(6):
            domain_age.lookup_many([f'bound{group}-{index}.com' for index in range(5)],
                                   fetch=self.blocked, servers=self.SERVERS, deadline=0)
        self.assertLessEqual(len(domain_age._pending), domain_age.MAX_PENDING_LOOKUPS)

    def test_one_lookup_per_domain(self):
        def slow(url, timeout):
            self.calls.append(url)
            time.sleep(0.05)
            return {'events': [{'eventAction': 'registration', 'eventDate': '2026-09-01T00:00:00Z'}]}

        async def run():
            return await asyncio.gather(*[domain_age.lookup_many_async(['shared-domain.com'], fetch=slow,
                                                                       servers=self.SERVERS, deadline=2)
                                          for _ in range(5)])
        results = asyncio.run(run())
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(all(result['shared-domain.com'] and result['shared-domain.com'].year == 2026
                            for result in results))


class ReceivingBoundaryTests(unittest.TestCase):
    """S3: a peer is the mail service's own server by the address the receiving server
    recorded, never by the name it gives itself."""

    HEADERS = ('Received: by 2002:a05:7300:5c8b:b0:1a2:3b4c:5d6e with SMTP id x;\n'
               'Received: from {helo} (attacker.example. [185.220.101.1]) by mx.google.com with ESMTPS id y;\n'
               'Received: from innocent.example ([8.8.8.8]) by mail.google.com with ESMTPS id z;\n'
               'From: A <a@sender.example>\nTo: user@gmail.com\nSubject: Notice\n\nHello\n')

    def test_a_claimed_name_does_not_cross_the_boundary(self):
        for helo in ('mail.google.com', 'attacker.example'):
            with self.subTest(helo=helo):
                message = Parser().parsestr(self.HEADERS.format(helo=helo))
                self.assertEqual(es._sending_server(message, 'gmail'), ('185.220.101.1', True))
        structure = es.analyze_raw_email(self.HEADERS.format(helo='mail.google.com').encode(), mailbox_provider='gmail')
        self.assertEqual(structure['sending_server'], {'address': '185.220.101.1', 'verified': True})

    def test_the_services_own_hops(self):
        gmail = Parser().parsestr(
            'Received: by 2002:a05:7300:5c8b:b0:1a2:3b4c:5d6e with SMTP id x;\n'
            'Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com;\n'
            'Received: by 2002:a17:906:1234:b0:1a2:3b4c:5d6e with SMTP id z;\nFrom: a@gmail.com\n\nhi\n')
        self.assertEqual(es._sending_server(gmail, 'gmail'), ('209.85.220.41', True))
        outlook = (
            'Received: from DM6PR12MB3456.namprd12.prod.outlook.com (2603:10b6:5:1c0::12) by '
            'SN6PR01MB1234.namprd01.prod.outlook.com with HTTPS;\n'
            'Received: from BN1NAM02FT012.eop-nam02.prod.protection.outlook.com (2603:10b6:408:e1:cafe::5) by '
            'DM6PR12MB3456.namprd12.prod.outlook.com (2603:10b6:5:1c0::12) with Microsoft SMTP Server;\n'
            'Received: from {helo} ({address}) by BN1NAM02FT012.mail.protection.outlook.com (10.13.2.1);\n'
            'Received: from forged.example (8.8.8.8) by x.prod.outlook.com;\nFrom: a@sender.example\n\nhi\n')
        self.assertEqual(es._sending_server(Parser().parsestr(
            outlook.format(helo='mail.sender.example', address='192.0.4.1')), 'outlook'), ('192.0.4.1', True))
        self.assertEqual(es._sending_server(Parser().parsestr(
            outlook.format(helo='x.prod.outlook.com', address='185.220.101.1')), 'outlook'), ('185.220.101.1', True))

    def test_the_recorded_address_comes_before_a_literal_name(self):
        message = Parser().parsestr('Received: from [8.8.8.8] (attacker.example. [185.220.101.1]) by mx.google.com;\n'
                                    'From: a@sender.example\n\nhi\n')
        self.assertEqual(es._sending_server(message, 'gmail'), ('185.220.101.1', True))


class ViewLabelTests(unittest.TestCase):
    """R1: a link's label in each view is the text that view shows inside it."""

    LURE = '<p>Your mailbox storage is full and incoming messages are on hold.</p>'

    def test_hidden_children_inside_a_label(self):
        link = '<a href="https://portal.example.org/review">{label}</a>'
        for style, label in (
                ('.decoy{display:none}', 'Release<span class="decoy">decoy</span> messages'),
                ('.decoy{display:none}', 'Release<span class="wrap"><b class="decoy">decoy</b> messages</span>'),
                ('@media screen{.decoy{display:none}}', 'Release<span class="decoy">decoy</span> messages'),
                ('.decoy{display:none}', 'Release<span class="decoy">x</span> <img alt="messages" src="cid:a">')):
            with self.subTest(style=style, label=label):
                result = analyze(f'<style>{style}</style>{self.LURE}{link.format(label=label)}<p>{PADDING}</p>')
                self.assertIn('content.mailbox_lure', codes(result))
                self.assertEqual(result['risk_level'], 'high')


class GovernmentSuffixTests(unittest.TestCase):
    """Government suffixes come from the Public Suffix List: go.to is anyone's."""

    def test_suffixes(self):
        for host in ('www.go.jp', 'tax.service.gov.uk', 'x.gc.ca', 'x.nsw.gov.au', 'x.gob.mx', 'irs.gov', 'www.admin.ch'):
            with self.subTest(host=host):
                self.assertTrue(app._government_host(host))
        for host in ('local-test.go.to', 'pay.go.com', 'tolls.example.com'):
            with self.subTest(host=host):
                self.assertFalse(app._government_host(host))

    def test_a_toll_notice_linking_to_a_registrable_go_domain(self):
        result = analyze('<p>Your unpaid toll balance is due on 10 October.</p>'
                         f'<a href="https://local-test.go.to/pay">Pay balance</a><p>{PADDING}</p>')
        self.assertIn('content.fine_lure', codes(result))


if __name__ == '__main__':
    unittest.main()
