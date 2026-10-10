"""Regressions from the review of 2026-10-01 at 1d9206d, and the CSS a browser drops that
the exact cascade must not apply (synthetic inputs, text rules only)."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import html_visibility  # noqa: E402

FIRST, SECOND = 'Your subscription renewal of $499 is complete. If you did not authorize this charge,', \
    'call 1-888-555-0199 immediately.'
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
SCAM = f'<p class="scam">{FIRST} {SECOND}</p>'


def analyze(body, subject='Invoice problem - call support'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def readings(html):
    found = {}
    app._visible_content_text(html, [], readings=found)
    return found


class CallbackTestCase(unittest.TestCase):
    def assert_callback(self, html, subject='Invoice problem - call support'):
        result = analyze(html, subject)
        self.assertIn(result['risk_level'], {'high', 'critical'}, html[:120])
        self.assertEqual(result['mail_type']['tactics'], ['callback'])


class FontSizeMathTests(CallbackTestCase):
    """S1: math functions check argument types and compute signs, then clamp at zero."""

    def test_a_number_is_no_length_so_the_declaration_is_dropped(self):
        for value in ('max(16px,1)', 'max(16px,0)', 'clamp(16px,1,32px)', 'max(16px,garbage)'):
            with self.subTest(value=value):
                self.assertEqual(html_visibility._font_size_class(value), 'invalid')
                self.assert_callback(f'<p>{FIRST}<span style="font-size:0"><span style="font-size:{value}">'
                                     f'{PADDING}</span></span>{SECOND}</p>')

    def test_negative_arguments_are_computed(self):
        for value in ('max(-1px,0px)', 'min(-1px,16px)', 'clamp(-1px,0px,1px)'):
            with self.subTest(value=value):
                self.assertEqual(html_visibility._font_size_class(value), 'zero')
                self.assert_callback(f'<p>{FIRST}<span><span style="font-size:{value}">{PADDING}</span></span>'
                                     f'{SECOND}</p>')

    def test_lengths_relative_to_the_parent_follow_it(self):
        for value, expected in (('max(16px,1rem)', 'visible'), ('clamp(14px,2vw,18px)', 'visible'),
                                ('max(1em,0px)', 'inherit'), ('min(1em,16px)', 'inherit'),
                                ('max(1lh,0px)', 'unresolved'), ('max(16px, 1rem + 2px)', 'unresolved')):
            with self.subTest(value=value):
                self.assertEqual(html_visibility._font_size_class(value), expected)


class ExactMatchingTests(CallbackTestCase):
    """R1, R2: rules apply to the elements they select, under independent conditions."""

    def test_a_rule_on_a_descendant_leaves_its_parent_text(self):
        self.assert_callback(f'<style>.wrap span{{display:none}}</style><p>{PADDING[:60]}</p>'
                             f'<div class="wrap">{FIRST}<span>{PADDING}</span>{SECOND}</div>')

    def test_two_controls_and_two_states_are_four_conditions(self):
        self.assert_callback('<style>.a~.attack{display:none}.a:checked~.attack{display:block}'
                             '.b~.attack .pad{display:none}.b:checked~.attack .pad{display:block}</style>'
                             '<input class="a" type="checkbox" checked><input class="b" type="checkbox">'
                             f'<div class="attack">{FIRST}<span class="pad">{PADDING}</span>{SECOND}</div>')
        self.assert_callback('<style>.trigger .attack{display:none}.trigger:hover .attack{display:block}'
                             '.trigger .pad{display:none}.trigger:focus .pad{display:block}</style>'
                             f'<div class="trigger" tabindex="0"><div class="attack">{FIRST} <span class="pad">'
                             f'{PADDING}</span> {SECOND}</div></div>')

    def test_client_hooks_are_one_condition_per_client_and_unused_classes_none(self):
        html = ('<style>[data-ogsc] .x{display:none} [data-ogsb] .y{display:none} u + .body .z{display:none}'
                ' .card .x{display:none}</style><div class="body"><p class="x">x</p><p class="y">y</p>'
                '<p class="z">z</p></div>')
        found = html_visibility._stylesheet_cascade(html[7:html.index('</style>')], html)
        self.assertEqual(found['conditions'], ['outlook-dark', 'gmail'])
        self.assertEqual(len(found['views']), 3)

    def test_a_client_rule_sharing_a_selector_with_a_plain_rule_stays_a_client(self):
        html = '<style>.x{display:none} [data-ogsc] .x{display:block}</style><p class="x">x</p>'
        found = html_visibility._stylesheet_cascade(html[7:html.index('</style>')], html)
        self.assertEqual(found['conditions'], ['outlook-dark'])
        self.assertEqual(len(found['views']), 2)


class ImageFallbackTests(CallbackTestCase):
    """R3: the text rules read fallback text in place; it sets floors, not keyword scores."""

    def test_a_callback_in_alt_text_is_found(self):
        self.assert_callback(f'<p>{PADDING}</p><img src="https://example.com/i.png" alt="{FIRST} {SECOND}">',
                             subject='Project update')

    def test_button_labels_do_not_raise_the_keyword_score(self):
        body = '<p>Thanks for signing up.</p><img src="https://example.com/b.png" alt="Verify your email address now">'
        self.assertEqual(analyze(body, 'Welcome')['total_score'], analyze(body.replace('Verify', 'View'), 'Welcome')['total_score'])


class DroppedCssTests(CallbackTestCase):
    """CSS a browser does not apply must not hide visible text from the reader."""

    def html(self, style, scam=SCAM):
        return f'{style}{scam}<div class="pad">{PADDING}</div><p>{PADDING}</p>'

    def test_a_list_with_a_selector_this_reader_cannot_match_may_be_dropped_whole(self):
        self.assert_callback(self.html('<style>.pad{display:none} .scam, p:nonsense-state{display:none}</style>'))

    def test_style_elements_apply_only_as_css_and_for_their_media(self):
        for style in ('<style>.pad{display:none}</style><style media="print">.scam{display:none}</style>',
                      '<style>.pad{display:none}</style><style type="text/plain">.scam{display:none}</style>'):
            with self.subTest(style=style[40:]):
                self.assert_callback(self.html(style))

    def test_cascade_layers_are_not_modelled(self):
        css = '.scam{display:block} @layer x { .scam{display:none} .pad{display:none} }'
        self.assertIsNone(html_visibility._stylesheet_cascade(css, '<p class="scam">s</p><div class="pad">p</div>'))
        self.assertNotIn(analyze(self.html(f'<style>{css}</style>'))['risk_level'], {'safe', 'low'})

    def test_content_a_browser_moves_out_of_a_table_inherits_from_outside_it(self):
        self.assert_callback(self.html('<style>.pad{display:none}</style>',
                                       f'<table style="display:none"><p>{FIRST} {SECOND}</p><tr><td>x</td></tr></table>'))
        self.assert_callback(self.html('<style>.pad{display:none} table .scam{display:none}</style>',
                                       f'<table><p class="scam">{FIRST} {SECOND}</p><tr><td>x</td></tr></table>'))
        # A stray element in a table row of a plain template stays decidable.
        found = readings('<style>.hide{display:none}</style><table><tr><div>Order shipped</div><td>Total</td></tr></table>')
        self.assertTrue(found['resolved'])

    def test_custom_properties_take_the_values_the_element_has(self):
        custom = {'--body': '#0f1111', '--clear': 'transparent'}

        def color(value):
            winners = {'color': (False, (0, 0, 1, 0), 1, ('var', value))}
            return html_visibility._with_custom_properties(winners, custom)[0]['color'][3]
        self.assertEqual(color('var(--body)'), 'visible')
        self.assertEqual(color('var(--clear)'), 'transparent')
        self.assertEqual(color('var(--missing)'), 'inherit')
        self.assertEqual(color('var(--missing, transparent)'), 'transparent')
        found = readings('<style>:root{--c:#111} body{color:var(--c)} .pad{font-size:0}</style>'
                         '<p>Visible</p><p class="pad">x</p>')
        self.assertTrue(found['resolved'])


if __name__ == '__main__':
    unittest.main()
