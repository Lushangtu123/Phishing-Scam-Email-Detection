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


class ExactSelectorTests(unittest.TestCase):
    def test_combinators_select_exactly_the_matching_elements(self):
        for css, body, shown in (
                ('.wrap span{display:none}', '<div class="wrap">kept <span>gone</span></div><span>also kept</span>',
                 'kept also kept'),
                ('.desktop_hide table{display:none}',
                 '<div class="desktop_hide">kept<table><tr><td>gone</td></tr></table></div>', 'kept'),
                ('.image_block img+div{display:none}',
                 '<div class="image_block"><div>first</div><img src="https://example.com/i.png"><div>gone</div>'
                 '<div>last</div></div>', 'first last'),
                ('.a + div{display:none}', '<p class="a">a</p><div>gone</div><div>kept</div>', 'a kept'),
                ('.a ~ p{display:none}', '<p>before</p><span class="a">a</span><p>gone</p><b>kept</b><p>gone too</p>',
                 'before a kept'),
                ('#wrap > td{display:none}',
                 '<table><tr id="wrap"><td>gone</td></tr><tr><td>kept</td></tr></table>', 'kept')):
            with self.subTest(css=css):
                found = readings(f'<style>{css}</style>{body}')
                self.assertTrue(found['resolved'])
                self.assertEqual(found['strict'], shown)

    def test_padding_hidden_through_an_ancestor_cannot_dilute_a_callback(self):
        html = (f'<style>.pad span{{display:none}}</style><p>{FIRST} <span class="pad"><span>{PADDING}</span></span>'
                f' {SECOND}</p>')
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def test_showing_a_child_does_not_show_its_hidden_parent(self):
        css = '.pad{display:none} @media(max-width:600px){.pad span{display:block}}'
        found = readings(f'<style>{css}</style><p>kept</p><span class="pad"><span>gone</span></span>')
        self.assertEqual(found['media'], ['kept', 'kept'])
        html = (f'<style>{css}</style><p>{FIRST} <span class="pad"><span>{PADDING}</span></span> {SECOND}</p>')
        self.assertIn(analyze(html)['risk_level'], {'high', 'critical'})

    def test_padding_inside_a_class_beside_visible_scam_text_cannot_dilute_it(self):
        html = (f'<style>.wrap span{{display:none}}</style><p>Please review the agenda.</p><div class="wrap">'
                f'{FIRST} <span>{PADDING}</span> {SECOND}</div>')
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['mail_type']['tactics'], ['callback'])


class InteractionStateTests(unittest.TestCase):
    MENU = ('@media only screen and (max-width:480px){'
            '.mj-menu-checkbox[type="checkbox"]~.mj-inline-links{display:none!important}'
            '.mj-menu-checkbox[type="checkbox"]:checked~.mj-inline-links{display:block!important}'
            '.mj-menu-checkbox[type="checkbox"]~.mj-inline-links > a{display:block!important}}')

    def test_a_ticked_menu_is_a_condition_of_its_own(self):
        html = (f'<style>{self.MENU}</style><input class="mj-menu-checkbox" type="checkbox">'
                '<div class="mj-inline-links"><a href="https://example.com/orders">Orders</a></div>'
                '<p>Your order has shipped and is on its way.</p>')
        found = app._stylesheet_cascade(self.MENU, html)
        self.assertTrue(any(isinstance(condition, tuple) and condition[1] == 'checked'
                            for condition in found['conditions']))
        views = readings(html)
        self.assertTrue(views['resolved'])
        self.assertTrue(any('Orders' in text for text in views['media']))
        self.assertTrue(any('Orders' not in text for text in views['media']))

    def test_each_control_and_state_is_its_own_condition(self):
        for css, body in (
                ('.a~.attack{display:none}.a:checked~.attack{display:block}'
                 '.b~.attack .pad{display:none}.b:checked~.attack .pad{display:block}',
                 '<input class="a" type="checkbox" checked><input class="b" type="checkbox">'
                 f'<div class="attack">{FIRST} <span class="pad">{PADDING}</span> {SECOND}</div>'),
                ('.trigger .attack{display:none}.trigger:hover .attack{display:block}'
                 '.trigger .pad{display:none}.trigger:focus .pad{display:block}',
                 f'<div class="trigger" tabindex="0"><div class="attack">{FIRST} <span class="pad">{PADDING}</span>'
                 f' {SECOND}</div></div>')):
            with self.subTest(css=css[:30]):
                html = f'<style>{css}</style><p>Please review the agenda.</p>{body}'
                self.assertEqual(len(app._stylesheet_cascade(css, html)['views']), 4)
                result = analyze(html)
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def test_a_state_several_elements_share_is_not_one_condition(self):
        html = ('<style>.a~.attack{display:none}.a:checked~.attack{display:block}</style>'
                '<input class="a" type="checkbox"><input class="a" type="checkbox" checked><div class="attack">text</div>')
        self.assertFalse(readings(html)['resolved'])


class FallbackAndConditionalTests(unittest.TestCase):
    def test_fallback_text_is_read_in_place_by_the_text_rules(self):
        for html in (f'<p>{PADDING}</p><img src="https://example.com/i.png" alt="{FIRST} {SECOND}">',
                     f'<style>.pad{{display:none}}</style><div class="pad">{PADDING}</div>'
                     f'<img src="https://example.com/i.png" alt="{FIRST} {SECOND}">'):
            with self.subTest(html=html[:20]):
                result = analyze(html, subject='Project update')
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertEqual(result['mail_type']['tactics'], ['callback'])
        found = readings('<p>Before</p><img src="https://example.com/i.png" alt="the image text here"><p>After</p>')
        self.assertEqual(found['images_off'], 'Before the image text here After')

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
