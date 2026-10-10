"""Regressions from the review of 2026-10-01, at b84c605 (synthetic inputs)."""
import asyncio
import json
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import html_visibility  # noqa: E402
import email_structure as es  # noqa: E402

FIRST, SECOND = 'Your subscription renewal of $499 is complete. If you did not authorize this charge,', \
    'call 1-888-555-0199 immediately.'
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
RESET = ('We received a request to reset the password for your account. Click the link below to choose a new '
         'password. This link will expire in 24 hours.')


def analyze(body, subject='Invoice problem - call support'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def readings(html):
    found = {}
    app._visible_content_text(html, [], readings=found)
    return found


def deployment_pipeline(test):
    from content_inference import load_content_pipeline_artifact
    root = WEBSITE_DIR.parent
    if f'{sys.version_info.major}.{sys.version_info.minor}' != (root / '.python-version').read_text().strip():
        test.skipTest('Committed artifact targets another Python version')
    profile = json.loads((root / 'vercel.json').read_text())['env']
    return load_content_pipeline_artifact(root / profile['CONTENT_MODEL_ARTIFACT'], profile['CONTENT_MODEL_ARTIFACT_SHA256'])


class InvalidDeclarationTests(unittest.TestCase):
    """S1: a declaration CSS drops must not undo the inherited or earlier valid one."""

    def assert_callback_alerts(self, wrapper, inner):
        html = (f'<p>{FIRST} <span style="{wrapper}"><span style="{inner}">{PADDING}</span></span> {SECOND}</p>')
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'}, (wrapper, inner))
        self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def test_colour_functions_with_bad_arguments_keep_the_inherited_transparent_colour(self):
        for inner in ('color:rgb(nope)', 'color:hsl(bogus)', 'color:color(nope)', 'color:rgb(1,2)',
                      'color:rgb(1, 2%, 3)', 'color:lab(1 2)', 'color:rgb(0 0 0 / x)'):
            with self.subTest(inner=inner):
                self.assert_callback_alerts('color:transparent', inner)

    def test_size_functions_with_bad_arguments_keep_the_inherited_zero_size(self):
        for inner in ('font-size:max(16px,garbage)', 'font-size:clamp(16px,garbage,32px)',
                      'font-size:min(16px)foo', 'font-size:16pz'):
            with self.subTest(inner=inner):
                self.assert_callback_alerts('font-size:0', inner)

    def test_an_invalid_later_declaration_keeps_the_earlier_one(self):
        for style in ('color:transparent;color:rgb(nope)', 'font-size:0;font-size:max(16px,garbage)'):
            with self.subTest(style=style):
                self.assert_callback_alerts('', style)

    def test_unknown_display_visibility_or_opacity_values_leave_the_text_unresolved(self):
        for style in ('display:none;display:garbage', 'visibility:hidden;visibility:garbage',
                      'opacity:0;opacity:garbage'):
            with self.subTest(style=style):
                self.assert_callback_alerts('', style)
                self.assertTrue(html_visibility._inline_text_state(style)[2])

    def test_valid_functions_still_show_text(self):
        self.assertFalse(html_visibility._color_state('rgb(0,0,0)'))
        self.assertFalse(html_visibility._color_state('rgb(0 0 0 / 50%)'))
        self.assertFalse(html_visibility._color_state('hsl(120deg 50% 50%)'))
        self.assertFalse(html_visibility._color_state('color(display-p3 1 0 0)'))
        self.assertFalse(html_visibility._color_state('buttonface'))
        self.assertEqual(html_visibility._font_size_state('max(16px,1rem)'), (False, False))
        self.assertEqual(html_visibility._font_size_state('clamp(14px,2vw,18px)'), (False, False))
        self.assertEqual(html_visibility._font_size_state('0'), (True, False))
        # A missing or negative alpha computes to zero.
        self.assertTrue(html_visibility._color_state('rgb(0 0 0 / none)'))
        self.assertTrue(html_visibility._color_state('rgba(0,0,0,-1)'))
        self.assertIsNone(html_visibility._color_state('rgb(nope)'))
        self.assertEqual(html_visibility._inline_text_state('display:none;display:inline-block'), (None, None, False))


class MediaSourceOrderTests(unittest.TestCase):
    """S2: a repeated @media condition keeps each of its positions in source order."""

    CSS = ('.attack{display:none}'
           '@media(min-width:400px){.attack{display:block}.padding1{display:none}}'
           '@media(max-width:600px){.attack{display:none}.padding2{display:none}}'
           '@media(min-width:400px){.attack{display:block}}')

    def test_the_view_where_both_conditions_hold_shows_the_last_rule(self):
        views = readings(f'<style>{self.CSS}</style><div class="attack">attack <span class="padding1">one</span>'
                         '<span class="padding2">two</span></div>')
        self.assertIn('attack', views['media'])

    def test_the_callback_in_that_view_alerts(self):
        html = (f'<style>{self.CSS}</style><p>Our meeting is moved to Thursday.</p>'
                f'<div class="attack">{FIRST} <span class="padding1">{PADDING}</span>'
                f'<span class="padding2">{PADDING}</span> {SECOND}</div>')
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def test_important_beats_a_later_normal_rule_and_a_later_base_rule_wins(self):
        views = readings('<style>.m{display:none!important} @media(max-width:600px){.m{display:block}} .d{display:block}'
                         ' @media(max-width:600px){.d{display:none}} .d{display:block}</style>'
                         '<p class="m">m</p><p class="d">d</p>')
        self.assertEqual(views['media'], ['d', 'd'])

    def test_specificity_inline_styles_and_order_decide_as_css_does(self):
        for html, shown in (
                ('<style>.wrap .pad{display:none} .pad{display:block}</style>'
                 '<div class="wrap"><span class="pad">hidden</span></div><span class="pad">shown</span>', 'shown'),
                ('<style>.attack{display:none} .show{display:block}</style><div class="attack show">shown</div>', 'shown'),
                ('<style>.show{display:block} .attack{display:none}</style><div class="attack show">gone</div>', ''),
                ('<style>.pad{display:none}</style><span class="pad" style="display:inline">shown</span>', 'shown'),
                ('<style>.pad{display:none!important}</style><span class="pad" style="display:inline">gone</span>', ''),
                ('<style>.pad{display:block}</style><div class="pad" hidden>shown</div>', 'shown')):
            with self.subTest(html=html):
                views = readings(html)
                self.assertTrue(views['resolved'])
                self.assertEqual(views['strict'], shown)

    def test_a_dark_mode_logo_swap_and_a_client_wrapper_resolve(self):
        swap = ('.logo .light{display:block} @media (prefers-color-scheme:dark){.logo .light{display:none}}'
                ' [data-ogsc] .logo .light{display:none}')
        views = readings(f'<style>{swap}</style><p>Your order shipped.</p>'
                         '<div class="logo"><img class="light" src="https://example.com/l.png" alt="Logo"></div>')
        self.assertTrue(views['resolved'])


class RequestedAnswerTests(unittest.TestCase):
    """R1–R3: the own-action answer settles only an alert that rests on the text model alone."""

    def analyze(self, requested='', **fields):
        with patch.object(app, '_content_pipeline', deployment_pipeline(self)):
            return json.loads(asyncio.run(app._analyze_content(
                app.ContentRequest(requested=requested, **fields.get('request', {})), fields.get('structure'),
                observe_sender_history=False)).body)

    def test_a_high_indicator_without_a_floor_is_never_answered_away(self):
        request = {'subject': 'Reset your password', 'body': RESET + ' Reset it here: https://bit.ly/3reset'}
        unanswered, yes = self.analyze(request=request), self.analyze('yes', request=request)
        self.assertIn('content.shortened_urls', {item['code'] for item in unanswered['extra_indicators']})
        self.assertFalse(unanswered['requested_question'])
        self.assertEqual(yes['risk_level'], unanswered['risk_level'])
        self.assertIn(yes['risk_level'], {'medium', 'high', 'critical'})

    def test_a_delivery_notice_with_an_order_number_is_not_asked(self):
        request = {'subject': 'Your UPS delivery', 'body': 'Your UPS package delivery is on hold. Confirm your address '
                   'to reschedule. Order number 114-2876549. View the details at https://parcel-records.example.org/'}
        unanswered, yes = self.analyze(request=request), self.analyze('yes', request=request)
        self.assertFalse(unanswered['requested_question'])
        self.assertEqual(yes['risk_level'], unanswered['risk_level'])

    def test_a_confirmed_notice_with_unchecked_renderings_is_unknown_not_low(self):
        message = EmailMessage()
        message['Subject'] = 'Reset your password'
        message.set_content(RESET)
        message.add_alternative(f'<html><head><style>div{{display:none; .x{{color:red}}}}</style></head><body><p>{RESET}</p>'
                                '<div>Your document is ready. Open the attachment for details.</div></body></html>',
                                subtype='html')
        structure = es.analyze_raw_email(message.as_bytes())
        unanswered = self.analyze(structure=structure)
        self.assertTrue(unanswered['requested_question'])
        self.assertFalse(unanswered['analysis_complete'])
        yes = self.analyze('yes', structure=structure)
        self.assertEqual(yes['risk_level'], 'unknown')
        self.assertIn('content.requested_notice', {item['code'] for item in yes['extra_indicators']})

    def test_a_plain_notice_is_still_asked_and_settled(self):
        request = {'subject': 'Reset your password', 'body': RESET}
        self.assertTrue(self.analyze(request=request)['requested_question'])
        self.assertEqual(self.analyze('yes', request=request)['risk_level'], 'low')


if __name__ == '__main__':
    unittest.main()
