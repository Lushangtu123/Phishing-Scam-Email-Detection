"""Regressions from the review of 2026-10-02 at e02355e: atan2() with percentages, clamp()
with a missing bound, deeply nested math, and the background checks against what two
Chromium builds accept (synthetic inputs, text rules only)."""
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

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
VERDICTS = json.loads((Path(__file__).parent / 'fixtures/css/background_browser_verdicts.json').read_text())


def analyze(body, subject='Project update'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def callback_shown(declarations):
    result = analyze(f'<style>.unused{{display:none}}.attack{{{declarations}}}</style>'
                     f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>')
    return 'content.callback_request' in {item.get('code') for item in result['extra_indicators']}


def accepted(name, value):
    if name in ('background-size', 'background-repeat'):
        return app._background_tiling_valid(name, value)
    if name == 'background-clip':
        return app._background_clip_valid(value)
    return app._background_valid(value, name)


def paints_nothing_known(value):
    """Whether the value's colour and gradients are unknown, so it can hide no text."""
    colour, _painted, solid = app._background_parts(value)
    return colour is None and solid is None


class BrowserVerdictTests(unittest.TestCase):
    """What Chromium 154 and 148 accept, against this reader: it never drops a background a
    browser accepts (white text on it would read as hidden), and a background it accepts
    that a browser drops leaves its colours unknown (it would hide text the browser shows)."""

    def test_never_drops_what_a_browser_accepts(self):
        wrong = [(name, value) for name, value, *browsers in VERDICTS['values']
                 if any(browsers) and not accepted(name, value)]
        self.assertEqual(wrong, [])

    def test_what_a_browser_drops_hides_nothing(self):
        wrong = [(name, value) for name, value, *browsers in VERDICTS['values']
                 if not all(browsers) and accepted(name, value) and name == 'background'
                 and not paints_nothing_known(value)]
        self.assertEqual(wrong, [])

    def test_mostly_agrees(self):
        # Accepting everything with unknown colours would pass both tests above. The fixture
        # keeps every generated value this reader and Chromium 154 disagree on, so it agrees
        # less often than on all 5,545 values compared (94%).
        same = sum(accepted(name, value) == chrome154 for name, value, chrome154, _chrome148 in VERDICTS['values'])
        self.assertGreater(same / len(VERDICTS['values']), 0.8)


class Atan2Tests(unittest.TestCase):
    """R1: an angle mixed with a percentage in atan2() is invalid wherever it stands."""

    def test_types(self):
        self.assertIsNone(app._css_math_type('atan2(1deg, 1%)'))
        self.assertIsNone(app._css_math_type('atan2(1deg, calc(1deg + 1%))'))
        self.assertIsNone(app._css_math_type('atan2(1px, 1%)'))
        self.assertEqual(app._css_math_type('atan2(1px, 2px)'), 'angle')
        # Two percentages resolve against the place's basis: none in a direction.
        self.assertEqual(app._css_math_type('atan2(1%, 1%)'), 'angle-percentage')
        self.assertFalse(app._background_valid('linear-gradient(atan2(1%, 1%), black, black)'))

    def test_the_callback_stays_visible(self):
        for value in ('linear-gradient(atan2(1deg,1%),black,black)', 'linear-gradient(atan2(1deg,calc(1deg + 1%)),black,black)'):
            with self.subTest(value=value):
                self.assertTrue(callback_shown(f'color:black;background:{value}'))


class ClampNoneTests(unittest.TestCase):
    """R2: clamp() takes none for either bound, never for its value."""

    def test_types(self):
        for word in ('clamp(none, 10px, none)', 'clamp(0px, 10px, none)', 'clamp(none, 10px, 20px)', 'clamp(none, 1px + 2px, none)'):
            with self.subTest(word=word):
                self.assertEqual(app._css_math_type(word), 'length')
        for word in ('clamp(none, none, 10px)', 'max(none, 1px)', 'calc(none + 1px)', 'clamp(none, 10px)'):
            with self.subTest(word=word):
                self.assertIsNone(app._css_math_type(word))

    def test_white_text_on_the_black_gradient_is_read(self):
        for value in ('linear-gradient(black clamp(none,10px,none),black)', 'linear-gradient(black clamp(0px,10px,none),black)'):
            with self.subTest(value=value):
                self.assertTrue(app._background_valid(value))
                self.assertTrue(callback_shown(f'color:white;background:{value}'))


class MathTypeTests(unittest.TestCase):
    def test_powers_and_percentages(self):
        for word, kind in (('calc(1px * 1px / 1px)', 'length'), ('calc(1px * 10% / 10%)', 'length-percentage'),
                           ('calc(10% * 1px / 1px)', 'percentage'), ('calc(10em / 1% * 1vw)', 'length-percentage'),
                           ('calc(1px * 1px)', None), ('calc(1px / 10%)', None), ('calc(10% / 10%)', 'number'),
                           ('calc(sign(10%) * 1px)', 'length-percentage'), ('sqrt(1vw)', 'unknown'),
                           ('calc(sin(10%) * 1px)', 'unknown')):
            with self.subTest(word=word):
                self.assertEqual(app._css_math_type(word), kind)

    def test_substitution_functions(self):
        # env() is accepted when the declaration is parsed, like var(); its colours are unknown.
        for value in ('black env(safe-area-inset-top) 0', 'linear-gradient(black env(safe-area-inset-top), black)'):
            with self.subTest(value=value):
                self.assertTrue(app._background_valid(value))
                self.assertTrue(paints_nothing_known(value))
        self.assertTrue(callback_shown('color:white;background:black env(safe-area-inset-top) 0'))

    def test_mixed_conic_stops_leave_the_colours_unknown(self):
        # Chromium 154 accepts calc(1deg + 1%) in a conic stop; 148 does not.
        self.assertIn(None, app._gradient_stops('conic-gradient(black calc(1deg + 1%), black)'))


class NestingTests(unittest.TestCase):
    """S1: deep nesting is left unknown, never an exception (and so a 500)."""

    def test_deep_math(self):
        for depth in (40, 250, 3000):
            word = 'calc(' * depth + '45deg' + ')' * depth
            with self.subTest(depth=depth):
                self.assertEqual(app._css_math_type(word), 'unknown')
                self.assertTrue(callback_shown(f'color:black;background:linear-gradient({word},black,black)'))
        self.assertEqual(app._css_math_type('calc(' * 20 + '45deg' + ')' * 20), 'angle')

    def test_other_deep_structures(self):
        for body in ('<p style="color:' + ''.join(f'var(--v{i}, ' for i in range(1000)) + 'black' + ')' * 1000 + '">x</p>',
                     '<style>' + ':not(' * 1000 + '.x' + ')' * 1000 + '{display:none}</style><p>x</p>',
                     '<style>' + '@media screen{' * 500 + 'p{display:none}' + '}' * 500 + '</style><p>x</p>',
                     '<p style="color:' + 'color-mix(in srgb, ' * 1000 + 'black' + ', white)' * 1000 + '">x</p>',
                     '<div>' * 10000 + 'x'):
            with self.subTest(body=body[:40]):
                self.assertIn('risk_level', analyze(body[:50000]))

    def test_the_endpoints(self):
        from fastapi.testclient import TestClient
        client = TestClient(app.app)
        word = 'calc(' * 250 + '45deg' + ')' * 250
        body = '<style>.a{background:linear-gradient(' + word + ',black,black);color:black}</style><p class=a>Hello</p>'
        with patch.object(app, '_content_pipeline', None):
            self.assertEqual(client.post('/api/analyze-content', json={'subject': 'x', 'body': body}).status_code, 200)
            raw = ('From: a@example.com\r\nTo: b@example.org\r\nSubject: x\r\nContent-Type: text/html\r\n\r\n' + body).encode()
            self.assertEqual(client.post('/api/analyze-eml', content=raw,
                                         headers={'content-type': 'message/rfc822'}).status_code, 200)
            self.assertIsNotNone(es.analyze_raw_email(raw))


if __name__ == '__main__':
    unittest.main()
