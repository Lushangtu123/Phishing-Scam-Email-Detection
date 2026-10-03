"""Regressions from the offline recheck of 2026-10-02 at 9162549: words that only hold a math
function are no colours, and a background a browser drops leaves the declaration before it
in force, checked through the whole cascade with the stored Chromium verdicts (synthetic
inputs, text rules only).

PHISHGUARD_FULL_CASCADE=1 checks every stored value a build drops (about a minute);
otherwise every tenth is checked, with the recheck's three."""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
VERDICTS = json.loads((Path(__file__).parent / 'fixtures/css/background_browser_verdicts.json').read_text())
RECHECK = ('linear-gradient((12.5 + 3ms + .5q/ 1deg - clamp(none, sign(1ms), -2q)), black, black)',
           'linear-gradient((min(atan2(0px, 3rem))/ 3grad), black, black)',
           'linear-gradient(12.5grad-calc(banana - 1x), black, black)')
# The declaration before the value, the text's colour against it, and how the value is set.
SCENARIOS = ('color:white;background:black;background:{} text', 'color:black;background:white;background:{}',
             'color:white;background:black;background:{}')


def callback_shown(declarations):
    with patch.object(app, '_content_pipeline', None):
        result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(
            subject='Project update', body=f'<style>.unused{{display:none}}.attack{{{declarations}}}</style>'
                                           f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>'))).body)
    return 'content.callback_request' in {item.get('code') for item in result['extra_indicators']}


class ColourWordTests(unittest.TestCase):
    def test_no_colours(self):
        for word in ('(min(atan2(0px, 3rem))/ 3grad)', '12.5grad-calc(banana - 1x)', 'calc(1px)', 'foo(bar)'):
            with self.subTest(word=word):
                self.assertEqual(app._color_class(word), 'invalid')

    def test_colours_this_reader_cannot_compute(self):
        for word in ('color-mix(in srgb, white, white)', 'light-dark(white, black)', 'rgb(calc(255) 0 0)',
                     'rgb(from red r g b)', 'var(--x)'):
            with self.subTest(word=word):
                self.assertEqual(app._color_class(word), 'unresolved')

    def test_uncertain_backgrounds(self):
        for value in ('-moz-linear-gradient(top, black, black) text', 'linear-gradient(black, color-mix(in srgb, white, white))',
                      'color-mix(in srgb, black, black)', 'image-set(url(a.png) 1x) text'):
            with self.subTest(value=value):
                self.assertTrue(app._background_uncertain(value))
        for value in ('linear-gradient(black, black) text', 'url(a.png) text', 'black'):
            with self.subTest(value=value):
                self.assertFalse(app._background_uncertain(value))


class CascadeTests(unittest.TestCase):
    """A value some Chromium build drops leaves the background before it in force, so text
    in contrast with that background is visible and must be read."""

    def test_recheck_values(self):
        for value in RECHECK:
            with self.subTest(value=value):
                self.assertFalse(app._background_valid(value))
                self.assertTrue(callback_shown(SCENARIOS[0].format(value)))

    def test_dropped_values_through_the_cascade(self):
        dropped = [value for name, value, chrome154, chrome148 in VERDICTS['values']
                   if name == 'background' and not (chrome154 and chrome148)]
        if not os.environ.get('PHISHGUARD_FULL_CASCADE'):
            dropped = sorted(set(dropped[::10]) | set(RECHECK))
        hidden = [(scenario, value) for value in dropped for scenario in SCENARIOS
                  if not callback_shown(scenario.format(value))]
        self.assertEqual(hidden, [])


if __name__ == '__main__':
    unittest.main()
