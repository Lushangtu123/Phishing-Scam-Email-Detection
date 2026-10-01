"""Regressions from the second independent review of 2026-09-30, at 06f4522 (synthetic inputs)."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import email_structure as es  # noqa: E402

FIRST, SECOND = 'Your subscription renewal of $499 is complete. If you did not authorize this charge,', \
    'call 1-888-555-0199 immediately.'
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30


def analyze(body, subject='Invoice problem - call support'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def raw_result(raw, mailbox='gmail'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(
            app.ContentRequest(), es.analyze_raw_email(raw, mailbox_provider=mailbox))).body)


class InlineStyleInheritanceTests(unittest.TestCase):
    def test_an_invalid_colour_does_not_undo_an_inherited_transparent_colour(self):
        html = (f'<p>{FIRST} <span style="color:transparent"><span style="color:not-a-color">{PADDING}'
                f'</span></span> {SECOND}</p>')
        result = analyze(html)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['mail_type']['tactics'], ['callback'])

    def test_initial_restores_the_initial_font_size(self):
        html = (f'<div style="font-size:0"><p style="font-size:initial">{FIRST} {SECOND}</p>'
                f'<span>{PADDING}</span></div>')
        self.assertIn(analyze(html)['risk_level'], {'high', 'critical'})

    def test_colour_and_size_values_are_read_as_css_does(self):
        self.assertIsNone(app._color_state('not-a-color'))
        self.assertIsNone(app._color_state('currentcolor'))
        self.assertFalse(app._color_state('red'))
        self.assertFalse(app._color_state('#112233'))
        self.assertFalse(app._color_state('rgba(0,0,0,.5)'))
        for transparent in ('transparent', '#0000', '#11223300', 'rgb(0 0 0 / 0)', 'hsl(0 0% 0% / 0%)'):
            with self.subTest(colour=transparent):
                self.assertTrue(app._color_state(transparent))
        # Values the parser cannot compute leave the text unresolved, whatever the parent.
        for style in ('color:color-mix(in srgb, red, blue)', 'color:rgb(var(--x))', 'font-size:calc(1em + 10px)',
                      'font-size:min(1em, 16px)'):
            with self.subTest(style=style):
                self.assertTrue(app._inline_text_state(style)[2])
        # min(), max() and clamp() over plain lengths are computed.
        self.assertEqual(app._font_size_state('max(16px,1rem)'), (False, False))
        self.assertEqual(app._font_size_state('clamp(0px, 0px, 0px)'), (True, False))
        self.assertEqual(app._font_size_state('min(0px, 16px)'), (True, False))


class MediaCombinationTests(unittest.TestCase):
    def test_conditions_that_hold_together_are_scored_together(self):
        css = ('@media(max-width:600px){.padding1{display:none}} @media(min-width:400px){.padding2{display:none}}'
               ' @media(min-width:601px){.attack{display:none}}')
        html = (f'<style>{css}</style><p>{FIRST}</p><div class="padding1">{PADDING}</div>'
                f'<div class="padding2">{PADDING}</div><p class="attack">{SECOND}</p>')
        targets = app._stylesheet_hidden_targets(css)
        self.assertIn(frozenset({('class', 'padding1'), ('class', 'padding2')}), targets['views'])
        self.assertIn(analyze(html)['risk_level'], {'high', 'critical'})

    def test_too_many_media_contexts_are_not_modelled(self):
        css = ' '.join(f'@media (min-width:{w}px){{.c{w}{{display:none}}}}' for w in range(100, 100 * (app._MAX_MEDIA_CONTEXTS + 2), 100))
        self.assertIsNone(app._stylesheet_hidden_targets(css))


class AuthenticationPropertyTests(unittest.TestCase):
    def test_a_reason_value_or_a_repeated_identity_names_no_dmarc_identity(self):
        self.assertEqual(es._dmarc_header_from('mx.google.com; dmarc=pass reason=header.from=github.com '
                                               'header.from=evil.example'), 'evil.example')
        self.assertEqual(es._dmarc_header_from('mx.google.com; dmarc=pass header.from=github.com '
                                               'header.from=evil.example'), '')
        self.assertEqual(es._dmarc_header_from('mx.google.com; dmarc=pass (p=REJECT) header.from="GitHub.com"'),
                         'github.com')
        self.assertEqual(es._dkim_pass_domains('mx.google.com; dkim=pass reason=header.d=github.com header.d=evil.example'),
                         {'evil.example'})
        self.assertEqual(es._dkim_pass_domains('mx.google.com; dkim=pass header.d=github.com header.d=evil.example'), set())

    def test_such_headers_never_verify_an_official_sender(self):
        for clause in ('dmarc=pass reason=header.from=github.com header.from=evil.example',
                       'dmarc=pass header.from=github.com header.from=evil.example'):
            raw = (f'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=evil.example; '
                   f'dkim=pass header.d=evil.example; {clause}\r\nFrom: GitHub <noreply@github.com>\r\n'
                   'To: user@example.net\r\nSubject: Security notice\r\n\r\nSign in to view your document.\r\n').encode()
            with self.subTest(clause=clause):
                self.assertIsNone(raw_result(raw)['verified_official_sender'])


class DisplayNameNormalizationTests(unittest.TestCase):
    def test_invisible_characters_cannot_hide_another_organizations_name(self):
        self.assertTrue(es._display_name_claims('Git​Hub', 'GitHub'))
        auth = ('Authentication-Results: mx.google.com; dkim=pass header.d=githubdocuments.com; '
                'spf=pass smtp.mailfrom=githubdocuments.com; dmarc=pass header.from=githubdocuments.com\r\n')
        for name in ('GitHub', '=?utf-8?b?R2l04oCLSHVi?='):
            raw = (auth + f'From: {name} <confirm@githubdocuments.com>\r\nTo: user@example.net\r\n'
                   'Subject: Welcome\r\n\r\nContinue at https://records.example.org/\r\n').encode()
            with self.subTest(name=name):
                self.assertFalse(es.analyze_raw_email(raw, mailbox_provider='gmail')['authenticated_sender']
                                 ['display_name_matches'])


class MailTypeLinkTests(unittest.TestCase):
    def test_sales_words_never_turn_a_disguised_account_link_into_advertising(self):
        result = analyze('<p>Special offer. Discount.</p>'
                         '<a href="https://records.example.org/continue">https://accounts.google.com</a>',
                         subject='Your special offer')
        self.assertEqual(result['mail_type'], {'type': 'phishing', 'tactics': ['deceptive_link']})


if __name__ == '__main__':
    unittest.main()
