"""Regressions from the review of 2026-10-01 at 0f17def: custom property names keep their
case, an invalid background is dropped, translucent backgrounds blend with what is behind
them, and the mailbox-lure rule reads reliable link labels (synthetic inputs, text rules
only)."""
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
        self.assertNotIn(analyze(html)['risk_level'], {'high', 'critical'}, html[:160])


class CustomPropertyCaseTests(CallbackTestCase):
    """S1: custom property names are case-sensitive, in definitions and in var()."""

    def test_var_reads_the_name_as_written(self):
        self.assert_callback(salted(css='.pad{--ZERO:0px;font-size:var(--ZERO,16px)}'))
        self.assertEqual(app._style_values('font-size:VAR(--Zero, 16PX)')['font-size'][0], 'var(--Zero, 16px)')

    def test_names_differing_in_case_are_different_properties(self):
        self.assert_callback(salted(css='.pad{--size:16px;--SIZE:0px;font-size:var(--SIZE)}'))
        self.assert_padding_read(salted(css='.pad{--size:16px;--SIZE:0px;font-size:var(--size)}'))
        # A chain of variables keeps each name's case.
        self.assert_callback(salted(css=':root{--Zero:0px;--Size:var(--Zero)}.pad{font-size:var(--Size, 16px)}'))


class InvalidBackgroundTests(CallbackTestCase):
    """S2: browsers drop an invalid background whole; it changes nothing."""

    def test_an_invalid_background_leaves_visible_text_visible(self):
        visible = f'<style>.unused{{display:none}}.attack{{color:black;background:banana black}}</style>' \
                  f'<p class="attack">{FIRST} {SECOND}</p><p>{PADDING}</p>'
        self.assert_callback(visible)
        self.assert_callback(f'<style>.unused{{display:none}}.attack{{background:black;color:white;'
                             f'background:banana white}}</style><p class="attack">{FIRST} {SECOND}</p><p>{PADDING}</p>')

    def test_an_invalid_background_does_not_reveal_hidden_text(self):
        self.assert_callback(salted(' style="color:white;background:white;background:garbage black"'))

    def test_what_a_background_may_hold(self):
        for value in ('black', '#fff url(x.png) no-repeat center / cover', 'url(a.png), url(b.png) red', 'none',
                      'linear-gradient(white, white)', 'inherit', 'var(--bg)', 'red url(x) 10px 20px'):
            with self.subTest(value=value):
                self.assertTrue(app._background_valid(value))
        for value in ('banana black', 'garbage black', 'black white', 'url(x) banana', 'red, url(x)'):
            with self.subTest(value=value):
                self.assertFalse(app._background_valid(value))
        self.assertFalse(app._background_valid('red', 'background-image'))


class TranslucentBackgroundTests(CallbackTestCase):
    """R1: a translucent background takes the colour of what is behind it."""

    def test_translucent_white_over_red_is_pink(self):
        self.assert_callback(salted(' style="color:#ff8080;background:rgba(255,255,255,.5)"',
                                    around=('<div style="background:red">', '</div>')))
        self.assertTrue(app._colours_may_match({'#ff8080'}, {'rgba(255,255,255,.5)'}))


class MailboxLureLabelTests(unittest.TestCase):
    """A stylesheet with no bearing on a mailbox lure leaves its visible link label readable."""

    def test_an_unrelated_stylesheet_keeps_the_rule(self):
        lure = ('<p>亲爱的用户：为了提高邮件系统的安全性，用户需登录新邮件系统将原有数据备案进行升级，逾期将停止服务。</p>'
                '<a href="https://account-review.example.org/x">点此登录完成本次升级</a>')
        for html in (lure, '<style>.unused{display:none}</style>' + lure):
            with self.subTest(styled=html.startswith('<style>')):
                result = analyze(html, '邮箱系统升级')
                self.assertEqual(result['risk_level'], 'high')
                self.assertIn('content.mailbox_lure', {item.get('code') for item in result['extra_indicators']})
        # A label the stylesheet hides is not read.
        hidden = ('<style>.x{display:none}</style><p>为了提高邮件系统的安全性，用户需登录新邮件系统进行升级。</p>'
                  '<a class="x" href="https://account-review.example.org/x">点此登录</a>')
        self.assertNotIn('content.mailbox_lure', {item.get('code') for item in analyze(hidden, '通知')['extra_indicators']})


class ColourBoundaryTests(CallbackTestCase):
    """Colours the review probed at the edge of what was modelled."""

    def test_a_one_colour_gradient_and_wide_gamut_colours(self):
        self.assert_callback(salted(' style="color:white;background:linear-gradient(white,white)"'))
        self.assert_callback(salted(' style="color:color(srgb 1 1 1)"'))
        self.assert_callback(salted(' style="color:oklch(1 0 0)"'))

    def test_colour_only_contexts_beyond_the_limit_may_apply(self):
        css = ''.join(f'@media (min-width:{width}px){{.pad{{color:white}}}}' for width in range(6))
        self.assert_callback(salted(css=css))


if __name__ == '__main__':
    unittest.main()
