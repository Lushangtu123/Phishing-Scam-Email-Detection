"""Hidden-text salting with padding the colour of its background (synthetic inputs, text rules only)."""
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


def analyze(body, subject='Project update'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def readings(html):
    found = {}
    app._visible_content_text(html, [], readings=found)
    return found


def salted(style='', css='', around=('', '')):
    """The callback with padding between its halves."""
    return (f'<style>{css}</style>{around[0]}<p>{FIRST}<span class="pad"{style}>{PADDING}</span>{SECOND}</p>'
            f'{around[1]}')


class CallbackTestCase(unittest.TestCase):
    def assert_callback(self, html):
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'}, html[:160])
        self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def assert_padding_read(self, html):
        # Padding a reader sees separates the halves of the callback.
        self.assertNotIn(analyze(html)['risk_level'], {'high', 'critical'}, html[:160])


class SameColourTests(CallbackTestCase):
    def test_padding_the_colour_of_its_background_leaves_the_callback_visible(self):
        for name, html in (
                ('white on the white canvas', salted(' style="color:#ffffff"')),
                ('near white', salted(' style="color:#fafafa"')),
                ('a named colour', salted(' style="color:white"')),
                ('rgb()', salted(' style="color:rgb(255, 255, 255)"')),
                ('hsl()', salted(' style="color:hsl(0 0% 100%)"')),
                ('nearly transparent text', salted(' style="color:rgba(0,0,0,0.02)"')),
                ('in a stylesheet', salted(css='.pad{color:#fff}')),
                ('on a coloured background', salted(' style="color:#f4f4f4"',
                                                    around=('<div style="background:#f4f4f4">', '</div>'))),
                ('black on black', salted(' style="color:#000"',
                                          around=('<div style="background-color:#000;color:#fff">', '</div>'))),
                ('legacy attributes', f'<table bgcolor="#336699"><tr><td><p>{FIRST}<font color="336699">{PADDING}'
                                      f'</font>{SECOND}</p></td></tr></table>'),
                ('from a variable', salted(' style="color:var(--bg)"', ':root{--bg:#fff}')),
                ('a background in the text colour', salted(' style="color:#c00;background-color:currentcolor"'))):
            with self.subTest(technique=name):
                self.assert_callback(html)

    def test_readable_text_is_read_as_written(self):
        for name, html in (
                ('white on a blue cell', f'<table><tr><td bgcolor="#1a73e8"><p>{FIRST}<span style="color:#fff">'
                                         f'{PADDING}</span>{SECOND}</p></td></tr></table>'),
                ('light grey on white', salted(' style="color:#999"')),
                ('white over a background image', salted(' style="color:#fff"', around=(
                    '<div style="background:url(https://example.com/hero.png) #fff">', '</div>'))),
                ('a child with its own background', f'<p>{FIRST}<span style="color:#fff"><span style="background:#222">'
                                                    f'{PADDING}</span></span>{SECOND}</p>'),
                ('legacy "fff", which is near black', f'<p>{FIRST}<font color="fff">{PADDING}</font>{SECOND}</p>'),
                ('white text on a black body', f'<body bgcolor="#000" text="#fff"><p>{FIRST}<span>{PADDING}</span>'
                                               f'{SECOND}</p></body>'),
                # A client in dark mode paints its own canvas; Outlook's recolours the message.
                ('white text in dark mode', salted(css='@media (prefers-color-scheme: dark){.pad{color:#fff}}')),
                ("white text in Outlook's dark mode", salted(css='[data-ogsc] .pad{color:#fff !important}')),
                ('white text on an Outlook VML button', f'<p>{FIRST}<v:roundrect fillcolor="#1a73e8">'
                                                        f'<center style="color:#fff">{PADDING}</center></v:roundrect>'
                                                        f'{SECOND}</p>')):
            with self.subTest(case=name):
                self.assert_padding_read(html)

    def test_a_rule_this_reader_cannot_match_may_give_text_its_backgrounds_colour(self):
        # Possibly invisible, as a tiny font is: left out of the views, and read by the
        # text rules both ways.
        self.assert_callback(salted(css='p:not(.x) .pad{color:#fff}'))
        found = readings(salted(css='p:not(.x) .pad{color:#fff}'))
        self.assertTrue(found['resolved'])
        self.assertNotIn('Please review', found['certain'])
        # A readable colour changes nothing, nor does white text with the dark background
        # its rule gives it.
        self.assert_padding_read(salted(css='p:not(.x) .pad{color:#333} .y{color:#fff}'))
        self.assert_padding_read(salted(css='p:not(.x) .pad{color:#fff;background:#222}'))

    def test_colours_alone_change_nothing_where_no_text_has_its_backgrounds_colour(self):
        # The views are dropped: the model reads the message as before.
        found = readings(f'<p style="color:#fff;background:#1a73e8">{FIRST} {SECOND}</p>')
        self.assertNotIn('resolved', found)
        self.assertNotIn('certain', found)

    def test_colour_rules_beyond_the_modelled_conditions_leave_the_rest_modelled(self):
        # Five contexts that hide, and a sixth that only colours: rendered without colours.
        css = ''.join(f'@media (max-width:{width}px){{.m{width}{{display:none}}}}' for width in (300, 400, 500, 600, 700))
        html = (f'<style>{css}@media (min-width:900px){{.pad{{color:#fff}}}}</style>'
                + ''.join(f'<p class="m{width}">{width}</p>' for width in (300, 400, 500, 600, 700)) + salted())
        self.assertIsNone(app._stylesheet_cascade(html[7:html.index('</style>')], html, colours=True))
        self.assertTrue(readings(html)['resolved'])

    def test_a_short_preheader_is_read_by_the_model_and_left_out_for_the_text_rules(self):
        html = (f'<div style="color:#ffffff">Your weekly summary is here</div><p>{FIRST} '
                f'ca<span style="color:#fff">zq</span>ll 1-888-555-0199 immediately.</p>')
        warnings, found = [], {}
        app._visible_content_text(html, warnings, readings=found)
        self.assertEqual(warnings, [])
        self.assertNotIn('resolved', found)
        self.assertIn('call 1-888-555-0199', found['certain'])
        self.assert_callback(html)

    def test_link_states(self):
        features = app._document_features('<a href="https://example.com">x</a>')
        self.assertEqual(app._parse_selector('a:link', features)[1]['specificity'], (0, 0, 1, 1))
        # :visited styles only links the reader followed: never this message's padding.
        self.assertEqual(app._parse_selector('a:visited', features), ('skip',))
        self.assert_padding_read(f'<style>a:visited{{color:#fff}}</style><p>{FIRST}<a href="https://example.com/notes">'
                                 f'{PADDING}</a>{SECOND}</p>')
        self.assert_callback(f'<style>a:link{{color:#fff}}</style><p>{FIRST}<a href="https://example.com/notes">'
                             f'{PADDING}</a>{SECOND}</p>')


class ColourTests(unittest.TestCase):
    def test_css_colours(self):
        for value, expected in (('white', (255, 255, 255, 1.0)), ('#fff', (255, 255, 255, 1.0)),
                                ('#ffffff80', (255, 255, 255, 128 / 255)), ('rgb(100% 0% 0% / 50%)', (255, 0, 0, 0.5)),
                                ('hsl(120deg 100% 25%)', (0, 128, 0, 1.0)), ('hwb(0 100% 0%)', (255, 255, 255, 1.0)),
                                ('transparent', (0, 0, 0, 0.0))):
            with self.subTest(value=value):
                self.assertEqual(app._colour_rgba(value), expected)
        for value in ('canvas', 'lab(50% 0 0)', 'color(srgb 1 1 1)'):
            with self.subTest(value=value):
                self.assertIsNone(app._colour_rgba(value))

    def test_legacy_colours_as_browsers_parse_them(self):
        for value, expected in (('ffffff', '#ffffff'), ('fff', '#0f0f0f'), ('#fff', '#ffffff'), ('White', '#ffffff'),
                                ('chucknorris', '#c00000'), ('transparent', None), ('', None)):
            with self.subTest(value=value):
                self.assertEqual(app._legacy_colour(value), expected)

    def test_the_contrast_that_counts_as_the_same_colour(self):
        self.assertTrue(app._same_colour((250, 250, 250, 1.0), (255, 255, 255)))
        self.assertFalse(app._same_colour((240, 240, 240, 1.0), (255, 255, 255)))
        self.assertFalse(app._same_colour((255, 255, 255, 1.0), (26, 115, 232)))
        self.assertTrue(app._same_colour((0, 0, 0, 0.0), (26, 115, 232)))
        self.assertFalse(app._same_colour((255, 255, 255, 1.0), None))

    def test_the_background_shorthand(self):
        self.assertEqual(app._background_parts('#fff url(x.png) no-repeat'), ('#fff', True))
        self.assertEqual(app._background_parts('url(a.png), url(b.png) red'), ('red', True))
        self.assertEqual(app._background_parts('none'), (None, False))
        # The shorthand resets the colour it does not give: nothing behind the image.
        values = app._style_values('background-color:#000; background:url(x.png)')
        self.assertEqual(app._background_parts(values['background-color'][0]), (None, True))

    def test_colours_that_cannot_match_need_no_colour_views(self):
        self.assertFalse(app._colours_may_match({'#333'}, {'#f4f4f4', '#1a73e8'}))
        self.assertTrue(app._colours_may_match({'#fefefe'}, set()))
        self.assertTrue(app._colours_may_match(set(), {'#000'}))
        self.assertTrue(app._colours_may_match({'var(--text)'}, set()))


if __name__ == '__main__':
    unittest.main()
