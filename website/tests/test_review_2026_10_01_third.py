"""Regressions from the review of 2026-10-01 at 8f6aca6: custom properties per element, the
implied html and body, selectors on decoded attribute values, unrendered siblings, and tiny
or faint text from a stylesheet (synthetic inputs, text rules only)."""
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


def salted(css='', outer='', inner=''):
    """The callback with padding between its halves, in a span inside a span."""
    return (f'<style>{css}</style><p>{FIRST}<span{outer}><span class="pad"{inner}>{PADDING}</span></span>'
            f'{SECOND}</p>')


class CallbackTestCase(unittest.TestCase):
    def assert_callback(self, html):
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'}, html[:160])
        self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def assert_padding_read(self, html):
        # Padding a reader sees separates the halves of the callback.
        self.assertNotIn(analyze(html)['risk_level'], {'high', 'critical'}, html[:160])


class CustomPropertyTests(CallbackTestCase):
    """S1: custom properties cascade and inherit element by element, inline ones too."""

    def test_a_value_set_on_other_elements_does_not_reach_this_one(self):
        self.assert_callback(salted('.absent{--z:16px}.pad{font-size:var(--z)}', ' style="font-size:0"'))

    def test_inline_custom_properties_apply_to_their_element_and_its_descendants(self):
        self.assert_callback(salted(inner=' style="--z:0px;font-size:var(--z)"'))
        self.assert_callback(salted('.pad{font-size:var(--z)}', ' style="--z:0"'))

    def test_custom_properties_inherit_and_descendants_can_set_their_own(self):
        self.assert_callback(salted('.wrap{--c:transparent}.pad{color:var(--c)}', ' class="wrap"'))
        self.assert_padding_read(salted('.wrap{--c:transparent}.pad{--c:#111;color:var(--c)}', ' class="wrap"'))

    def test_root_custom_properties_reach_every_element(self):
        self.assert_callback(salted(':root{--z:transparent}.pad{color:var(--z)}'))
        self.assert_callback(salted(':root{--off:-9999px}.pad{position:absolute;left:var(--off)}'))
        self.assert_callback(salted(':root{--off:-9999px}', inner=' style="position:absolute;left:var(--off)"'))
        self.assertTrue(app._hiding_value('left', 'var(--off)'))

    def test_a_variable_that_cannot_be_substituted_unsets_the_declaration(self):
        # Invalid at computed-value time: the size inherits, as in browsers.
        self.assert_callback(salted('.pad{font-size:var(--missing)}', ' style="font-size:0"'))
        self.assert_callback(salted('.pad{--a:var(--a);font-size:var(--a)}', ' style="font-size:0"'))
        self.assert_callback(salted('.pad{font-size:var(--missing, 0)}'))

    def test_substitution_reads_the_elements_own_values_first(self):
        winners = {'--a': (False, (0, 0, 1, 0), 1, 'var(--b)'), '--b': (False, (0, 0, 1, 0), 2, '0px'),
                   'font-size': (False, (0, 0, 1, 0), 3, ('var', 'var(--a)'))}
        resolved, custom = app._with_custom_properties(winners, {'--b': '16px'})
        self.assertEqual(resolved['font-size'][3], 'zero')
        self.assertEqual(custom, {'--a': '0px', '--b': '0px'})
        # A box value without a value to substitute is unset.
        self.assertEqual(app._with_custom_properties({'left': (False, (0, 0, 1, 0), 1, 'var(--x)')}, {})[0], {})

    def test_a_rule_this_reader_cannot_match_that_sets_a_variable_in_use_is_undecidable(self):
        found = readings('<style>.pad{color:var(--c)} p:not(.x){--c:transparent}</style>'
                         '<p>Visible <span class="pad">text</span></p>')
        self.assertFalse(found['resolved'])
        found = readings('<style>.pad{color:var(--c)} p:not(.x){--unused:transparent}</style>'
                         '<p>Visible <span class="pad">text</span></p>')
        self.assertTrue(found['resolved'])


class ImpliedRootTests(CallbackTestCase):
    """Rules on the html and body elements a document leaves implied apply to its root."""

    @staticmethod
    def split(css, body=False):
        """The callback's halves in readable blocks, padding between them inheriting from the root."""
        blocks = (f'<div class="scam">{FIRST}</div><div>{PADDING}</div><div class="scam">{SECOND}</div>')
        return f'<style>{css}.scam{{font-size:16px;color:#111}}</style>' + (f'<body>{blocks}</body>' if body else blocks)

    def test_rules_on_the_implied_root_reach_every_element(self):
        for css in ('body{font-size:0}', 'html{font-size:0}', ':root{font-size:0}', 'body{color:transparent}'):
            with self.subTest(css=css):
                self.assert_callback(self.split(css))
        self.assert_padding_read(self.split(''))

    def test_an_explicit_body_is_matched_as_an_element(self):
        self.assert_callback(self.split('body{font-size:0}', body=True))

    def test_root_outranks_html(self):
        self.assertEqual(readings('<style>:root{font-size:16px} html{font-size:0}</style><p>Hello</p>')['certain'],
                         'Hello')
        self.assertEqual(readings('<style>html{font-size:16px} :root{font-size:0}</style><p>Hello</p>')['certain'], '')

    def test_a_rule_this_reader_cannot_match_on_the_root_is_undecidable(self):
        self.assertFalse(readings('<style>body:not(.x){font-size:0}</style><p>Hello</p>')['resolved'])
        self.assertFalse(readings('<style>html, p:nonsense{font-size:0}</style><p>Hello</p>')['resolved'])


class DecodedAttributeTests(CallbackTestCase):
    """S2: selectors match attribute values after character references are decoded."""

    def test_class_id_and_attribute_values_are_decoded(self):
        for css, attribute in (('.pad', 'class="p&#97;d"'), ('#pad', 'id="p&#97;d"'),
                               ('[data-x="yes"]', 'data-x="y&#101;s"')):
            with self.subTest(attribute=attribute):
                self.assert_callback(f'<style>{css}{{display:none}}</style>'
                                     f'<p>{FIRST}<span {attribute}>{PADDING}</span>{SECOND}</p>')
        features = app._document_features('<p class="p&#97;d" id="&#x41;" data-x="y&amp;s">x</p>')
        self.assertEqual((features['classes'], features['ids']), ({'pad'}, {'a'}))
        self.assertEqual(features['nodes'][0][3]['data-x'], 'y&s')

    def test_the_first_of_a_repeated_attribute_counts(self):
        features = app._document_features('<p class="pad" class="other">x</p>')
        self.assertEqual(features['classes'], {'pad'})


class UnrenderedSiblingTests(CallbackTestCase):
    """R1: style and script elements render nothing but are siblings all the same."""

    def test_an_unrendered_element_separates_adjacent_siblings(self):
        self.assert_callback(f'<style>.pad{{display:none}}p+p{{display:none}}</style><p>{PADDING[:62]}</p>'
                             f'<style>.x{{color:red}}</style><p class="attack">{FIRST} {SECOND}</p><p>{PADDING}</p>')

    def test_selectors_match_unrendered_elements(self):
        for html in (f'{FIRST}<style>style+.pad{{display:none}}</style><span class="pad">{PADDING}</span>{SECOND}',
                     f'<style>script+.pad{{display:none}}</style>{FIRST}<script></script>'
                     f'<span class="pad">{PADDING}</span>{SECOND}'):
            with self.subTest(html=html[:60]):
                self.assert_callback(html)


class StylesheetTinyFaintTests(CallbackTestCase):
    """R2: tiny or faint text is found whether its style is inline, in a stylesheet, or both."""

    def test_every_source_of_the_same_style(self):
        for name, value in (('font-size', '1px'), ('font-size', '0.1rem'), ('opacity', '0.05'), ('opacity', '5%')):
            for source, html in (('inline', salted(inner=f' style="{name}:{value}"')),
                                 ('stylesheet', salted(f'.pad{{{name}:{value}}}')),
                                 ('with an unrelated hiding rule', salted(f'.pad{{{name}:{value}}}.unused{{display:none}}')),
                                 ('with an unrelated zero size', salted(f'.pad{{{name}:{value}}}.unused{{font-size:0}}')),
                                 ('from a variable', salted(f':root{{--v:{value}}}.pad{{{name}:var(--v)}}'))):
                with self.subTest(style=f'{name}:{value}', source=source):
                    self.assert_callback(html)

    def test_declarations_split_between_inline_and_stylesheet(self):
        self.assert_callback(salted('.pad{left:-9999px}', inner=' style="position:absolute"'))
        self.assert_callback(salted('.pad{position:absolute}', inner=' style="left:-9999px"'))

    def test_readable_text_stays_read(self):
        for css in ('.pad{font-size:3px}', '.pad{opacity:0.5}', ':root{--v:14px}.pad{font-size:var(--v)}'):
            with self.subTest(css=css):
                self.assert_padding_read(salted(css))


class DroppedListTests(CallbackTestCase):
    def test_an_unknown_pseudo_element_makes_its_list_undecidable(self):
        self.assert_callback(f'<style>.pad{{display:none}} .attack, p::unknown{{display:none}}</style>'
                             f'<p class="attack">{FIRST} {SECOND}</p><p>{PADDING}</p>')
        features = app._document_features('<p>x</p>')
        self.assertEqual(app._parse_selector('p::unknown', features)[0], 'maybe')
        self.assertEqual(app._parse_selector('p::-webkit-scrollbar', features)[0], 'maybe')
        self.assertEqual(app._parse_selector('p::before', features), ('skip',))


if __name__ == '__main__':
    unittest.main()
