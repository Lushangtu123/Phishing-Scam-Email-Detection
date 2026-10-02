"""Regressions from the review of 2026-10-02 at 9abbad5: CSS math in backgrounds, gradients
that do not cover the box, the RDAP pool's queue, link labels past the per-view budget, and
the subscription-link exemption (synthetic inputs, text rules only, no network)."""
import asyncio
import json
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import domain_age  # noqa: E402
import email_structure as es  # noqa: E402

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30


def analyze(body, subject='Project update'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def analyze_eml(raw: bytes):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def codes(result):
    return {item.get('code') for item in result['extra_indicators']}


def callback_shown(declarations):
    return 'content.callback_request' in codes(analyze(
        f'<style>.unused{{display:none}}.attack{{color:black;{declarations}}}</style>'
        f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>'))


class CssMathTests(unittest.TestCase):
    """S1: a math function's result type decides where it is valid (checked against Chromium)."""

    def test_types(self):
        for word, kind in (('calc(1px)', 'length'), ('calc(1px + 10%)', 'length-percentage'), ('calc(2 * 3px)', 'length'),
                           ('calc(1turn / 2)', 'angle'), ('calc(10px / 2px)', 'number'), ('min(1px, 2px, 3%)',
                                                                                         'length-percentage'),
                           ('atan2(1, 2)', 'angle'), ('sin(45deg)', 'number'), ('calc(pi * 1deg)', 'angle'),
                           ('calc(var(--x) + 1px)', 'unknown'), ('calc(banana)', None), ('calc(1px + 1deg)', None),
                           ('calc(1px+1px)', None), ('calc(1px * 2px)', None), ('round(1px)', None),
                           ('clamp(1px, 2px)', None), ('calc(1px + 1)', None)):
            with self.subTest(word=word):
                self.assertEqual(app._css_math_type(word), kind)

    def test_gradients_browsers_reject(self):
        for value in ('linear-gradient(calc(1px),black,black)', 'linear-gradient(black calc(1deg),black)',
                      'linear-gradient(black calc(banana),black)', 'conic-gradient(from calc(1px),black,black)',
                      'conic-gradient(black calc(10% + 1deg),black)', 'radial-gradient(circle calc(10px + 5%),black,black)',
                      'linear-gradient(clamp(1px, 2px),black,black)'):
            with self.subTest(value=value):
                self.assertFalse(app._background_valid(value))
                self.assertTrue(callback_shown(f'background:{value}'))

    def test_gradients_browsers_accept(self):
        for value in ('linear-gradient(calc(45deg),black,black)', 'linear-gradient(black calc(10px + 5%),black)',
                      'conic-gradient(from calc(10px / 2px * 1deg),black,black)', 'linear-gradient(black calc(1px)calc(2px),black)'):
            with self.subTest(value=value):
                self.assertTrue(app._background_valid(value))
        # A valid one-colour gradient still hides black text.
        self.assertFalse(callback_shown('background:linear-gradient(calc(45deg),black,black)'))

    def test_an_untyped_function_leaves_the_colours_unknown(self):
        self.assertIn(None, app._gradient_stops('linear-gradient(black calc(env(x)),black)'))
        self.assertTrue(callback_shown('background:linear-gradient(black calc(env(x)),black)'))

    def test_words_end_at_a_closing_bracket(self):
        self.assertEqual(app._css_words('calc(1px)calc(2px) url(a.png)no-repeat'),
                         ['calc(1px)', 'calc(2px)', 'url(a.png)', 'no-repeat'])


class CoverageTests(unittest.TestCase):
    """A one-colour gradient paints that colour only where its tiles cover the box."""

    def test_partial_gradients_leave_the_text_visible(self):
        for declarations in ('background:linear-gradient(black,black) no-repeat 0 0 / 1px 1px',
                             'background:linear-gradient(black,black) 0 0 / 0 0',
                             'background:linear-gradient(black,black) repeat-x 0 0 / 10px 1px',
                             'background:linear-gradient(black,black) space',
                             'background-image:linear-gradient(black,black);background-size:0 0',
                             'background-image:linear-gradient(black,black);background-repeat:no-repeat;'
                             'background-size:1px 1px'):
            with self.subTest(declarations=declarations):
                self.assertTrue(callback_shown(declarations))

    def test_covering_gradients_still_hide(self):
        for declarations in ('background:linear-gradient(black,black) 0 0 / 10px 10px',
                             'background:linear-gradient(black,black) round',
                             # The shorthand resets the earlier repeat.
                             'background-repeat:no-repeat;background:linear-gradient(black,black)'):
            with self.subTest(declarations=declarations):
                self.assertFalse(callback_shown(declarations))

    def test_longhand_validity(self):
        for name, value, valid in (('background-size', '0 0', True), ('background-size', '-1px', False),
                                   ('background-size', 'cover contain', False), ('background-size', '1px, auto', True),
                                   ('background-repeat', 'repeat-x repeat', False), ('background-repeat', 'space round', True),
                                   ('background-repeat', 'repeat repeat repeat', False)):
            with self.subTest(name=name, value=value):
                self.assertEqual(app._background_tiling_valid(name, value), valid)


class RdapQueueTests(unittest.TestCase):
    """S2: a lookup nobody waits for keeps its slot until the pool reaches and skips it, so
    the pool's queue stays bounded too."""

    SERVERS = {'com': 'https://rdap.invalid/'}

    def setUp(self):
        self.release = threading.Event()
        self.calls = []

    def tearDown(self):
        self.release.set()
        deadline = time.monotonic() + 5
        while domain_age._admitted and time.monotonic() < deadline:
            time.sleep(0.01)
        with domain_age._cache_lock:
            domain_age._cache.clear()

    def blocked(self, url, timeout):
        self.calls.append(url)
        self.release.wait(5)
        return {}

    def test_the_queue_is_bounded(self):
        async def run():
            for group in range(20):
                await domain_age.lookup_many_async([f'queue{group}-{index}.com' for index in range(5)],
                                                   fetch=self.blocked, servers=self.SERVERS, deadline=0.005)
        asyncio.run(run())
        self.assertLessEqual(domain_age._admitted, domain_age.MAX_PENDING_LOOKUPS)
        self.assertLessEqual(domain_age._pool._work_queue.qsize(), domain_age.MAX_PENDING_LOOKUPS)
        self.release.set()
        time.sleep(0.3)
        self.assertLessEqual(len(self.calls), domain_age._pool._max_workers)
        self.assertEqual(domain_age._admitted, 0)

    def test_a_queued_lookup_is_taken_up_again(self):
        domain_age.lookup_many([f'busy-{index}.com' for index in range(5)], fetch=self.blocked, servers=self.SERVERS,
                               deadline=0)
        domain_age.lookup_many([f'busy-{index}.com' for index in range(5, 8)] + ['again.com'], fetch=self.blocked,
                               servers=self.SERVERS, deadline=0)
        admitted = domain_age._admitted
        domain_age.lookup_many(['again.com'], fetch=self.blocked, servers=self.SERVERS, deadline=0)
        self.assertEqual(domain_age._admitted, admitted)  # the same queued work item, not another


class LinkBudgetTests(unittest.TestCase):
    """R1: links past the per-view budget never discard the labels already read."""

    LURE = ('<p>Your mailbox storage is full and incoming messages are on hold.</p>'
            '<a href="https://portal.example.org/review">Release<span class="decoy">decoy</span> messages</a>')

    def body(self, before, after=0):
        return ('<style>.decoy{display:none}</style>' + '<a href="https://portal.example.org/review">.</a>' * before
                + self.LURE + '<a href="https://portal.example.org/review">.</a>' * after + f'<p>{PADDING}</p>')

    def test_two_hundred_links(self):
        for before in (198, 199, 200, 400):
            with self.subTest(before=before):
                self.assertIn('content.mailbox_lure', codes(analyze(self.body(before))))

    def test_past_the_budget(self):
        with patch.object(app, '_MAX_VIEW_ANCHORS', 5):
            # The lure's label was read before the budget ran out.
            self.assertIn('content.mailbox_lure', codes(analyze(self.body(2, after=10))))
            # Past it, the rendering is unresolved: never Safe or Low.
            result = analyze(self.body(10))
            self.assertNotIn(result['risk_level'], {'safe', 'low'})


class SubscriptionLinkTests(unittest.TestCase):
    """R2: a word anywhere in the URL is no unsubscribe link."""

    ME = ['recipient@example.org']

    def test_still_prefilled(self):
        for link in ('https://portal.example.net/view?email=recipient%40example.org&preferences=0',
                     'https://portal.example.net/view?email=recipient%40example.org#unsubscribe',
                     'https://list-manage-login.example.top/view?email=recipient@example.org'):
            with self.subTest(link=link):
                self.assertIsNotNone(app._recipient_prefilled_link([('Open document', link)], self.ME))

    def test_unsubscribe_links(self):
        for label, link in (('', 'https://news.example.net/email/preferences?email=recipient@example.org'),
                            ('Unsubscribe', 'https://click.example.net/u?email=recipient@example.org'),
                            ('Manage preferences', 'https://click.example.net/p?email=recipient@example.org'),
                            ('', 'https://us1.list-manage.com/profile?e=recipient@example.org')):
            with self.subTest(link=link):
                self.assertIsNone(app._recipient_prefilled_link([(label, link)], self.ME))

    def test_analysis(self):
        raw = ('From: Docs <share@portal-mailer.example.com>\r\nTo: recipient@example.org\r\nSubject: Document\r\n'
               'Content-Type: text/html; charset=utf-8\r\n\r\n<p>Please review this document.</p><a href="https://portal.'
               'example.net/view?email=recipient%40example.org&amp;preferences=0">Open document</a>').encode()
        self.assertIn('link.recipient_prefilled', codes(analyze_eml(raw)))


if __name__ == '__main__':
    unittest.main()
