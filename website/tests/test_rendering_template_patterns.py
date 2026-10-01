"""Mail-template CSS and markup patterns that used to leave genuine HTML undetermined."""
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


def readings(html):
    found = {}
    app._visible_content_text(html, [], readings=found)
    return found


class AncestorScopedSelectorTests(unittest.TestCase):
    def test_a_tag_inside_a_class_is_reached_through_that_class(self):
        for selector, token in (('.inline-button table', ('class', 'inline-button')),
                                ('.desktop_hide table', ('class', 'desktop_hide')),
                                ('.image_block img+div', ('class', 'image_block')),
                                ('.x .a + b c', ('class', 'x')), ('#wrap > td', ('id', 'wrap'))):
            with self.subTest(selector=selector):
                self.assertEqual(app._hidden_selector_targets(selector), [token])
        # A sibling of the class is not inside it, and a bare tag can be anything.
        for selector in ('.a + div', '.a ~ p', 'div', ':not(.x) td'):
            with self.subTest(selector=selector):
                self.assertIsNone(app._hidden_selector_targets(selector))

    def test_padding_hidden_through_an_ancestor_cannot_dilute_a_callback(self):
        html = (f'<style>.pad span{{display:none}}</style><p>{FIRST} <span class="pad"><span>{PADDING}</span></span>'
                f' {SECOND}</p>')
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def test_showing_a_child_does_not_show_its_hidden_parent(self):
        css = '.pad{display:none} @media(max-width:600px){.pad span{display:block}}'
        self.assertEqual(app._stylesheet_hidden_targets(css)['views'], [frozenset({('class', 'pad')})])
        html = (f'<style>{css}</style><p>{FIRST} <span class="pad"><span>{PADDING}</span></span> {SECOND}</p>')
        self.assertIn(analyze(html)['risk_level'], {'high', 'critical'})


class InteractionStateTests(unittest.TestCase):
    MENU = ('@media only screen and (max-width:480px){'
            '.mj-menu-checkbox[type="checkbox"]~.mj-inline-links{display:none!important}'
            '.mj-menu-checkbox[type="checkbox"]:checked~.mj-inline-links{display:block!important}'
            '.mj-menu-checkbox[type="checkbox"]~.mj-inline-links > a{display:block!important}}')

    def test_a_ticked_menu_is_a_context_not_an_ambiguity(self):
        targets = app._stylesheet_hidden_targets(self.MENU)
        self.assertEqual(targets['ambiguous'], frozenset())
        self.assertIn(frozenset({('class', 'mj-inline-links')}), targets['views'])
        self.assertIn(frozenset(), targets['views'])
        html = (f'<style>{self.MENU}</style><input class="mj-menu-checkbox" type="checkbox">'
                '<div class="mj-inline-links"><a href="https://example.com/orders">Orders</a></div>'
                '<p>Your order has shipped and is on its way.</p>')
        self.assertTrue(readings(html)['resolved'])


class FallbackAndConditionalTests(unittest.TestCase):
    def test_descriptive_image_text_is_scored_as_an_images_off_view(self):
        html = ('<p>Your weekly summary is ready.</p>'
                '<img src="https://example.com/banner.png" alt="Three people reviewing a summer product catalogue">')
        found = readings(html)
        self.assertTrue(found['resolved'])
        self.assertIn('summer product catalogue', found['images_off'])

    def test_fallback_instructions_stay_unresolved(self):
        html = ('<p>Your weekly summary is ready.</p>'
                '<img src="https://example.com/b.png" alt="Enter your password to view the summary">')
        self.assertFalse(readings(html)['resolved'])

    def test_a_wrapped_endif_closes_an_office_settings_block(self):
        html = ('<html><head><!--[if gte mso 9\r\n ]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96'
                '</o:PixelsPerInch></o:OfficeDocumentSettings></xml><!\r\n [endif]--></head>'
                '<body><p>Your weekly summary is ready.</p></body></html>')
        unresolved = []
        app._expand_mso_comments(html, [], mark=True, unresolved=unresolved)
        self.assertEqual(unresolved, [])


if __name__ == '__main__':
    unittest.main()
