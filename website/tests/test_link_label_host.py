"""A link's label read as the address it presents (F3): compatibility forms, format controls and look-alike letters
inside Latin words do not hide it, and a separator may follow the navigation words ("Sign in: example.org").
Criteria fixed before the change: security-audit F3 pass criteria, approved 2026-10-24."""
import asyncio
import json
import random
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

import link_analysis  # noqa: E402

# (label, host the label presents); '' when it presents none.
LABEL_CASES = [
    ('Sign in to example.org', 'example.org'),
    ('Sign in: example.org', 'example.org'),
    ('Sign in - example.org', 'example.org'),
    ('Sign in → example.org', 'example.org'),
    ('Sign in — example.org', 'example.org'),
    ('Sign-in: example.org', 'example.org'),
    ('Log in: example.org', 'example.org'),
    ('Login: example.org', 'example.org'),
    ('Visit: example.org', 'example.org'),
    ('Go to: example.org', 'example.org'),
    ('Sign in | example.org', 'example.org'),
    ('Sign in » example.org', 'example.org'),
    ('Visit -> example.org', 'example.org'),
    ('SIGN IN: EXAMPLE.ORG', 'example.org'),
    ('Sign in to ｅxample.org', 'example.org'),
    ('Sign in to \U0001d5f2xample.org', 'example.org'),
    ('Ｓｉｇｎ ｉｎ ｔｏ ｅｘａｍｐｌｅ．ｏｒｇ', 'example.org'),
    ('Sign in to example．org', 'example.org'),
    ('Sign in to еxample.org', 'example.org'),
    ('Sign in to exa​mple.org', 'example.org'),
    ('登录：example.org', 'example.org'),
    ('请登录：example.org', 'example.org'),
    ('ｅxample.org', 'example.org'),
    ('https://ｅxample.org', 'example.org'),
    ('Sign in: https://example.org/login', 'example.org'),
    ('Sign in: invoice.pdf', 'invoice.pdf'),
    ('Sign in to exαmple.org', 'example.org'),
    ('Source: example.org', ''),
    ('News.com: Weekly review', ''),
    ('Read more on example.org', ''),
    ('Log in here: example.org', ''),
    ('Visit us at example.org', ''),
    ('invoice.pdf', ''),
    ('ｉｎｖｏｉｃｅ．ｐｄｆ', ''),
    ('Visit bücher.de', ''),
    ('Sign in: bücher.de', ''),
    ('Release 2.4.1: notes', ''),
    ('Topic: sign in to your account', ''),
    ('Signed in: example.org', ''),
    ('Opened: example.org', ''),
    ('已登录到我的账户', ''),
    ('Sign in to пример.рф', ''),
    ('Sign in to παράδειγμα.gr', ''),
    ('Sign in to сосо.org', ''),
]
MISMATCH = 'link.display_mismatch'


def analyze(subject, body):
    return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def mismatches(result):
    return [item['params'] for item in result['extra_indicators'] if item.get('code') == MISMATCH]


class LabelHostTests(unittest.TestCase):
    def test_each_label_presents_the_expected_host(self):
        for label, host in LABEL_CASES:
            with self.subTest(label=label):
                self.assertEqual(link_analysis._visible_link_host(label), host)

    def test_the_label_itself_is_not_changed(self):
        self.assertEqual(link_analysis._link_label_copy('Sign in to ｅxa​mple.org'), 'Sign in to example.org')
        self.assertEqual(link_analysis._link_label_copy('пример.рф'), 'пример.рф')

    def test_forms_of_any_length_are_read(self):
        # A fixed look-back of eight words once cut "Sign" off these (review of 24c8fd5).
        for label in ('Sign' + ' -' * 8 + ' in: example.org', 'Log' + ' -' * 8 + ' in: example.org',
                      'Sign' + ' -' * 20 + ' in: example.org', 'Sign in:' + ' ' * 300 + 'example.org'):
            with self.subTest(label=label[:30]):
                self.assertEqual(link_analysis._visible_link_host(label), 'example.org')
        self.assertEqual(link_analysis._visible_link_host('x' + ' -' * 8 + ' in: example.org'), '')

    def test_the_backwards_reading_finds_what_the_forward_search_finds(self):
        # Every end position of fixed and seeded random texts: the reversed forms against the approved forms
        # searched over all of text[:end].
        texts = ['Sign in to example.org', 'Sign in:' + ' ' * 300 + 'example.org', 'sign  -  in  :  example.org',
                 'Sign' + ' -' * 20 + ' in: x', 'Log' + ' -' * 9 + ' in: x', 'xsign in: y', 'Sign in - - x',
                 'Please log in to example.org now, or go to: other.org', '请登录：example.org 或 访问 other.org',
                 'log in to\nexample.org', 'Visit -> a.org | open » b.org — sign-in – c.org', 'a.org:' * 20]
        pieces = ['sign', 'Sign', 'SIGN', 'log', 'Log', 'in', 'In', 'to', 'at', 'go', 'visit', 'Visit', 'open', 'opened',
                  'signed', 'login', 'signin', 'x', 'a.org', 'example.org', 'word', '_', '1', ' ', ' ', '  ', '\t', '\n',
                  '-', '-', '–', '—', ':', '->', '>', '→', '»', '|', '访问', '打开', '登录', '登陆', '请', '已', '：', 'é']
        generator = random.Random(20261024)
        texts += [''.join(generator.choice(pieces) for _ in range(generator.randint(1, 12))) for _ in range(2000)]
        for text in texts:
            backwards = text[::-1]
            for end in range(len(text) + 1):
                if link_analysis._navigation_before(backwards, end) != bool(
                        link_analysis._NAVIGATION_BEFORE_HOST.search(text[:end])):
                    self.fail(f'differs at {end} in {text!r}')

    def test_long_labels_take_linear_time(self):
        # On main, 50,000 characters of words or dotted names took 9 to 15 seconds; at 24c8fd5, names with no
        # space between them ("a.org:a.org:…") still took over 4 seconds.
        for label in ('a.b ' * 12500, 'word ' * 10000, '1.2.3 ' * 8300, 'x.pdf ' * 8300, 'sign in: ' * 5555,
                      'Sign in to' + ' ' * 49980 + 'example.org', 'a.org:' * 8333 + 'zz', 'a.b.' * 12500,
                      'in:a.org' * 6250, 'Sign' + ' -' * 24990 + ' in: example.org',
                      ('x' + ' -' * 50 + ' in: a.org ') * 450, ('x' + ' -' * 500 + ' in: a.org ') * 49):
            with self.subTest(label=label[:12]):
                start = time.perf_counter()
                link_analysis._visible_link_host(label)
                self.assertLess(time.perf_counter() - start, 1.0)

    def test_either_import_order_gives_the_same_reading(self):
        script = ('import json, sys; sys.path.insert(0, {path!r}); {imports}; import link_analysis; '
                  'print(json.dumps([link_analysis._visible_link_host(label) for label, _ in {cases!r}]))')
        outputs = []
        for imports in ('import link_analysis; import content_rules', 'import content_rules; import link_analysis'):
            code = script.format(path=str(WEBSITE_DIR), imports=imports, cases=LABEL_CASES)
            outputs.append(subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True).stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(json.loads(outputs[0]), [host for _, host in LABEL_CASES])


class LinkMismatchTests(unittest.TestCase):
    TEXT = 'Please use the link for the scheduled project activity. <a href="{target}">{label}</a>'

    def test_reported_label_forms_are_high_with_the_mismatch(self):
        for label in ('Sign in: example.org', 'Sign in to ｅxample.org', 'Sign in to \U0001d5f2xample.org'):
            with self.subTest(label=label):
                result = analyze('Project update', self.TEXT.format(target='https://portal.example.net/login', label=label))
                self.assertEqual(mismatches(result), [{'display_host': 'example.org', 'host': 'portal.example.net'}])
                self.assertIn(result['risk_level'], {'high', 'critical'})
                result = analyze('Project update', self.TEXT.format(target='https://portal.example.org/login', label=label))
                self.assertEqual(mismatches(result), [])

    def test_the_finding_names_the_label_of_the_mismatched_link(self):
        links = [('https://portal.example.org/login', 'Sign in: example.org'),
                 ('https://portal.example.net/login', 'Sign in: ｒeports.example.com')]
        for order in (links, links[::-1]):
            body = 'Please use the links. ' + ' and '.join(f'<a href="{target}">{label}</a>' for target, label in order)
            with self.subTest(first=order[0][1]):
                self.assertEqual(mismatches(analyze('Project update', body)),
                                 [{'display_host': 'reports.example.com', 'host': 'portal.example.net'}])

    def test_a_disguised_brand_behind_a_tracker_is_not_advertising(self):
        text = ('Spring sale: 20% off and free shipping on all orders this week. '
                '<a href="https://click.mailer.example.net/c/abc123">{label}</a> Unsubscribe')
        for label in ('Visit: ｐａｙｐａｌ.com', 'Visit: pаypal.com', 'Visit: paypal.com'):
            with self.subTest(label=label):
                result = analyze('Spring sale', text.format(label=label))
                self.assertEqual(mismatches(result), [{'display_host': 'paypal.com', 'host': 'click.mailer.example.net'}])
                self.assertEqual(result['mail_type']['type'], 'phishing')
        result = analyze('Spring sale', text.format(label='www.conference-2023.org'))
        self.assertEqual(result['mail_type']['type'], 'advertising')

    def test_mentions_and_filenames_are_not_addresses(self):
        for label in ('Source: example.org', 'Read more on example.org', 'invoice.pdf', 'ｉｎｖｏｉｃｅ．ｐｄｆ'):
            with self.subTest(label=label):
                result = analyze('Project update', self.TEXT.format(target='https://portal.example.net/login', label=label))
                self.assertEqual(mismatches(result), [])
                self.assertFalse(re.search(r'\bdoes not match\b', ' '.join(i['msg'] for i in result['extra_indicators'])))


if __name__ == '__main__':
    unittest.main()
