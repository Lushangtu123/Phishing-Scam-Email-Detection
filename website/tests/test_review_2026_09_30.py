"""Regressions from the independent review of 2026-09-30 (synthetic inputs)."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
from email_structure import analyze_raw_email  # noqa: E402

SCAM = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
        'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
GMAIL = ('Authentication-Results: mx.google.com; dkim=pass header.d={domain}; spf=pass smtp.mailfrom={domain};'
         ' dmarc=pass header.from={domain}\r\n')


def analyze(subject, body):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def message(sender, name, subject, body, *, auth=None, content_type='text/plain', reply_to=None):
    domain = sender.rpartition('@')[2]
    head = (auth if auth is not None else GMAIL.format(domain=domain))
    head += f'From: {name} <{sender}>\r\n' + (f'Reply-To: {reply_to}\r\n' if reply_to else '')
    return (head + f'To: user@example.net\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n'
            f'Content-Type: {content_type}; charset=utf-8\r\n\r\n{body}\r\n').encode()


class RenderingReviewTests(unittest.TestCase):
    def test_a_comment_opener_inside_a_css_string_does_not_hide_the_following_rule(self):
        targets = app._stylesheet_hidden_targets('.decoration::before{content:"/*"} .padding{display:none}')
        self.assertEqual(targets['union'][0], frozenset({'padding'}))
        self.assertIsNone(app._stylesheet_hidden_targets('.a{content:"unclosed} .padding{display:none}'))
        result = analyze('Invoice problem - call support',
                         '<style>.decoration::before{content:"/*"} .padding{display:none}</style>'
                         f'<p>{SCAM}</p><div class="padding">{PADDING}</div>')
        self.assertIn(result['risk_level'], {'high', 'critical'})

    def test_each_media_context_is_its_own_rendering(self):
        html = ('<style>@media (max-width:600px){.padding{display:none}} @media (min-width:601px){.attack{display:none}}'
                f'</style><p>Please review the project notes.</p><p class="attack">{SCAM}</p>'
                f'<div class="padding">{PADDING}</div>')
        targets = app._stylesheet_hidden_targets(html[7:html.index('</style>')])
        self.assertEqual(len(targets['views']), 3)
        # The narrow-screen view shows the scam without the padding.
        self.assertIn(analyze('Invoice problem - call support', html)['risk_level'], {'high', 'critical'})

    def test_too_many_rendering_contexts_are_not_modelled(self):
        css = ' '.join(f'@media (min-width:{width}px){{.c{width}{{display:none}}}}' for width in range(100, 1000, 100))
        self.assertIsNone(app._stylesheet_hidden_targets(css))


class SenderReviewTests(unittest.TestCase):
    def verified(self, raw):
        return analyze_raw_email(raw, mailbox_provider='gmail')['verified_official_sender']

    def test_invoices_and_money_requests_from_payment_platforms_are_relays(self):
        for subject in ('Invoice from Billing department', 'You have a new money request',
                        "Don't recognize the seller? Quickly let us know"):
            with self.subTest(subject=subject):
                self.assertIsNone(self.verified(message('service@paypal.com', 'PayPal', subject, SCAM)))
        self.assertEqual(self.verified(message('service@paypal.com', 'PayPal', 'Receipt for your payment', 'Thanks.')),
                         {'organization': 'PayPal', 'domain': 'paypal.com'})

    def test_registered_relay_addresses_are_never_official(self):
        for sender, name in (('notifications@github.com', 'GitHub'), ('dse_na4@docusign.net', 'Docusign'),
                             ('drive-shares-dm-noreply@google.com', 'Google')):
            with self.subTest(sender=sender):
                self.assertIsNone(self.verified(message(sender, name, 'A new update', 'Hello.')))
        self.assertEqual(self.verified(message('noreply@github.com', 'GitHub', '[GitHub] Please reset your password',
                                               'Reset link inside.'))['organization'], 'GitHub')

    def test_dmarc_identity_comes_from_the_dmarc_clause_itself(self):
        for auth in (
                'Authentication-Results: mx.google.com; spf=pass (dmarc=pass header.from=github.com) '
                'smtp.mailfrom=evil.example; dkim=pass header.d=evil.example; dmarc=pass header.from=evil.example\r\n',
                'Authentication-Results: mx.google.com; spf=pass reason="dmarc=pass header.from=github.com" '
                'smtp.mailfrom=evil.example; dkim=pass header.d=evil.example; dmarc=pass header.from=evil.example\r\n',
                'Authentication-Results: mx.google.com; dkim=pass header.d=evil.example; '
                'dmarc=pass header.from=github.com; dmarc=pass header.from=evil.example\r\n'):
            with self.subTest(auth=auth[40:90]):
                raw = message('noreply@github.com', 'GitHub', 'Security notice', 'Hello.', auth=auth)
                self.assertIsNone(self.verified(raw))

    def test_a_display_name_claiming_another_organization_does_not_relax_the_address(self):
        structure = analyze_raw_email(message('confirm@githubdocuments.com', 'GitHub', 'Confirm', 'Hello.'),
                                      mailbox_provider='gmail')
        self.assertFalse(structure['authenticated_sender']['display_name_matches'])
        own = analyze_raw_email(message('confirm@acmedocs.com', 'Acme Docs', 'Confirm', 'Hello.'), mailbox_provider='gmail')
        self.assertTrue(own['authenticated_sender']['display_name_matches'])

    def test_a_services_image_only_mail_stays_undetermined(self):
        html = '<p>A new invoice is ready.</p><img src="https://images.example.org/invoice.png" width="600" height="800">'
        raw = message('no-reply@dropbox.com', 'Dropbox', 'Your weekly summary', html, content_type='text/html')
        with patch.object(app, '_content_pipeline', None):
            result = json.loads(asyncio.run(app._analyze_content(
                app.ContentRequest(), analyze_raw_email(raw, mailbox_provider='gmail'))).body)
        self.assertEqual(result['risk_level'], 'unknown')


if __name__ == '__main__':
    unittest.main()
