"""Regressions from the review of 2026-10-02 at 362eb8f: a url() browsers read as a bad URL
drops its background declaration, so the background before it stays (synthetic inputs, text
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

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
BAD = ('url(a"b") text', 'url(a(b)) text', 'url("a" "b") text', 'url("a", "b") text', 'url(a b.png) text')
GOOD = ('url(a.png) text', 'url("a.png") text', "url('a b.png')", 'url(a\\ b.png)', 'url( a.png )', 'url()',
        'url("a\\"b.png")', 'url(https://cdn.example.com/a.png?x=1&y=2) no-repeat',
        'black url(data:image/png;base64,iVBORw0KGgo=)')


def callback_shown(declarations):
    with patch.object(app, '_content_pipeline', None):
        result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(
            subject='Project update', body=f'<style>.unused{{display:none}}.attack{{{declarations}}}</style>'
                                           f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>'))).body)
    return 'content.callback_request' in {item.get('code') for item in result['extra_indicators']}


class UrlTokenTests(unittest.TestCase):
    def test_bad_urls_drop_the_declaration(self):
        for value in BAD:
            with self.subTest(value=value):
                self.assertFalse(app._background_valid(value))

    def test_valid_urls(self):
        for value in GOOD:
            with self.subTest(value=value):
                self.assertTrue(app._background_valid(value))

    def test_the_background_before_stays(self):
        # The black background stays under the white text, which browsers show.
        for value in BAD:
            with self.subTest(value=value):
                self.assertTrue(callback_shown(f'color:white;background:black;background:{value}'))


if __name__ == '__main__':
    unittest.main()
