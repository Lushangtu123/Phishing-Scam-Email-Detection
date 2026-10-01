"""Hidden-text salting: padding a reader cannot see must not dilute visible scam text."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

FIRST, SECOND = 'Your subscription renewal of $499 is complete. If you did not authorize this charge,', \
    'call 1-888-555-0199 immediately.'
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30


def analyze(body, subject='Invoice problem - call support'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def salted(style='', css=''):
    return f'<style>{css}</style><p>{FIRST} <span class="pad" style="{style}">{PADDING}</span> {SECOND}</p>'


def geometry(style):
    values = app._style_values(style)
    return app._geometry_hidden(lambda name: values.get(name, ('', False))[0])


class SaltingTests(unittest.TestCase):
    def test_padding_hidden_by_any_technique_leaves_the_callback_visible(self):
        for name, html in (
                ('zero height that clips', salted('display:block;max-height:0;overflow:hidden')),
                ('zero height in a stylesheet', salted(css='.pad{display:block;max-height:0;overflow:hidden}')),
                ('zero height inline, clipped by the stylesheet', salted('display:block;height:0', '.pad{overflow:hidden}')),
                ('1px font', salted('font-size:1px')),
                ('near-zero opacity', salted('opacity:0.05')),
                ('off screen', salted('position:absolute;left:-9999px')),
                ('negative text-indent', salted('display:block;text-indent:-9999px')),
                ('zero clip rectangle', salted('position:absolute;clip:rect(0 0 0 0)')),
                ('zero scale', salted('display:inline-block;transform:scale(0)')),
                ('hidden in Outlook', salted('mso-hide:all'))):
            with self.subTest(technique=name):
                result = analyze(html)
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def test_visible_padding_is_still_read_as_written(self):
        self.assertNotIn(analyze(salted())['risk_level'], {'high', 'critical'})


class GeometryTests(unittest.TestCase):
    def test_box_geometry_that_hides_content(self):
        for style in ('max-height:0;overflow:hidden', 'height:0px;overflow:hidden', 'overflow:hidden;width:0',
                      'position:absolute;left:-9999px', 'position:relative;top:-100%', 'text-indent:-9999px',
                      'position:absolute;clip:rect(1px,1px,1px,1px)', 'clip-path:inset(50%)', 'transform:scale(0)'):
            with self.subTest(style=style):
                self.assertIs(geometry(style), True)

    def test_box_geometry_that_does_not(self):
        for style in ('max-height:0', 'overflow:hidden', 'transform:scale(1)', 'position:absolute;left:10px',
                      'clip:rect(0 0 0 0)'):
            with self.subTest(style=style):
                self.assertIs(geometry(style), False)
        # Padding keeps a zero-height box open; an uncomputed size cannot be decided.
        self.assertEqual(geometry('height:0;overflow:hidden;padding-bottom:50%'), 'unresolved')
        self.assertEqual(geometry('max-height:calc(0px);overflow:hidden'), 'unresolved')

    def test_tiny_fonts_and_near_zero_opacity_are_possibly_invisible(self):
        for value, expected in (('1px', 'tiny'), ('2.9px', 'tiny'), ('0.1rem', 'tiny'), ('3px', 'visible'),
                                ('max(1px,2px)', 'tiny'), ('max(-1px,0px)', 'zero'), ('max(16px,1rem)', 'visible'),
                                ('1em', 'inherit')):
            with self.subTest(value=value):
                self.assertEqual(app._font_size_class(value), expected)
        for style, expected in (('opacity:0', True), ('opacity:0.05', 'faint'), ('opacity:5%', 'faint'),
                                ('opacity:0.5', False)):
            with self.subTest(style=style):
                self.assertEqual(app._declared_values(style), [('opacity', expected, False)])
        # Unlike a zero size, they are not inline uncertainty: the text stays in the visible reading.
        self.assertFalse(app._inline_text_state('font-size:1px')[0])
        self.assertFalse(app._inline_text_state('opacity:0.05')[2])


if __name__ == '__main__':
    unittest.main()
