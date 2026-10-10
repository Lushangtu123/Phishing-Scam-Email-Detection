"""Regressions from the review of 2026-10-02 at 3351c72: a clip from env(), percentages with
no basis, clamp() with a bracketed none, and backgrounds browsers may keep or drop (synthetic
inputs, text rules only). Browser results are Chromium 154's, from the review's evidence."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
import html_visibility  # noqa: E402
from hidden_findings import hidden_codes, shown_codes  # noqa: E402

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30


def callback_result(declarations):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(
            subject='Project update', body=f'<style>.unused{{display:none}}.attack{{{declarations}}}</style>'
                                           f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>'))).body)


def callback_shown(declarations):
    return 'content.callback_request' in shown_codes(callback_result(declarations))


class VisibleTextTests(unittest.TestCase):
    """Each shows its text in Chromium 154, or may in another build: it must be read."""

    def test_a_clip_from_env(self):
        # S1: env() falls back to text; the black gradient paints inside the glyphs only.
        self.assertTrue(callback_shown('color:black;background:linear-gradient(black,black);background-clip:text;'
                                       'background-clip:env(no-such-env,text)'))

    def test_a_percentage_with_no_basis(self):
        # S2: 1s + 1% has no basis, though the units cancel later.
        self.assertIsNone(html_visibility._css_math_type('calc((1s + 1%) * 1px / 1s)'))
        self.assertTrue(callback_shown('color:black;background:linear-gradient(black calc((1s + 1%) * 1px / 1s),black)'))

    def test_a_bracketed_none(self):
        # R1: only a bare none is a missing bound.
        for word in ('clamp((none), 10px, none)', 'clamp((none),10deg,(none))', 'calc((none))'):
            with self.subTest(word=word):
                self.assertIsNone(html_visibility._css_math_type(word))
        self.assertEqual(html_visibility._css_math_type('clamp(none, 10px, none)'), 'length')
        for value in ('linear-gradient(black clamp((none),10px,none),black)', 'linear-gradient(clamp((none),10deg,(none)),black,black)'):
            with self.subTest(value=value):
                self.assertTrue(callback_shown(f'color:black;background:{value}'))

    def test_a_background_browsers_may_drop(self):
        # R2: Chromium drops the second declaration, so the black one stays under the white text.
        self.assertTrue(callback_shown('color:white;background:black;background:linear-gradient(sqrt(4px),black,black) text'))
        self.assertTrue(callback_shown('color:black;background:white;background:linear-gradient(sqrt(4px),black,black)'))
        # Chromium 154 keeps a mixed conic stop, 148 drops it: either may hold.
        self.assertTrue(callback_shown('color:white;background:black;background:conic-gradient(black calc(1deg + 1%),black) text'))

    def test_uncertain_values(self):
        for value in ('linear-gradient(sqrt(4px),black,black) text', 'black env(safe-area-inset-top) 0',
                      'conic-gradient(black calc(1deg + 1%),black)'):
            with self.subTest(value=value):
                self.assertTrue(html_visibility._background_uncertain(value))
        for value in ('linear-gradient(black,black) text', 'black 0 0 / 10px', 'conic-gradient(black 10%,black)'):
            with self.subTest(value=value):
                self.assertFalse(html_visibility._background_uncertain(value))


class HiddenTextTests(unittest.TestCase):
    """The review's other probes: Chromium 154 shows none of these texts."""

    def test_still_hidden(self):
        for declarations in (
                # Accepted: black text on a black gradient.
                'color:black;background:linear-gradient(atan2(calc(1px * 1px),calc(1px * 1px)),black,black)',
                # Dropped: white text on the white page.
                'color:white;background:linear-gradient(calc(1deg * (1% / 1%)),black,black)',
                'color:white;background:linear-gradient(atan2(calc(1% / 1%),calc(1% / 1%)),black,black)',
                'color:white;background:linear-gradient(atan2(sign(1%),sign(1%)),black,black)'):
            with self.subTest(declarations=declarations):
                self.assertFalse(callback_shown(declarations))
                # Still read as text the message may hide (2026-10-05).
                self.assertIn('content.callback_request', hidden_codes(callback_result(declarations)))


class PercentBasisTests(unittest.TestCase):
    def test_bases(self):
        for word, kind in (('calc(1px + 10%)', 'length-percentage'), ('calc(1deg + 1%)', 'angle-percentage'),
                           ('calc(10em / 1% * 1vw)', 'length-percentage'), ('calc(1% + 2%)', 'percentage'),
                           ('calc((1px + 1%) * (1deg + 1%))', None), ('calc((1px + 1%) / 1px * 1deg)', None),
                           ('calc(sign(1px + 1%) * 1deg)', None), ('calc(1x + 1%)', None)):
            with self.subTest(word=word):
                self.assertEqual(html_visibility._css_math_type(word), kind)


if __name__ == '__main__':
    unittest.main()
