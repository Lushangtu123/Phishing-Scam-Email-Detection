import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
from content_inference import load_content_pipeline_artifact  # noqa: E402
from email_structure import analyze_raw_email  # noqa: E402
from visual_evidence import VisualRequest  # noqa: E402

GMAIL_PASS = ('Authentication-Results: mx.google.com;\r\n'
              '       dkim=pass header.i=@{domain} header.s=s1;\r\n'
              '       spf=pass (google.com: domain of bounce@{domain} designates 192.0.2.1 as permitted sender)'
              ' smtp.mailfrom=bounce@{domain};\r\n'
              '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={header_from}\r\n')
# Outlook.com's layout: Microsoft's own result sits above an ARC set and the
# outbound relay's X-MS-Exchange-Authentication-Results header.
OUTLOOK_PASS = ('Received: from mailbox.prod.outlook.com by mailbox.prod.outlook.com with HTTPS\r\n'
                'ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is 192.0.2.1)\r\n'
                ' smtp.mailfrom={domain}; dmarc=pass action=none header.from={header_from}; dkim=pass\r\n'
                'Authentication-Results: mx.microsoft.com 1; spf=pass (sender IP is\r\n'
                ' 192.0.2.1) smtp.mailfrom={domain}; dkim=pass\r\n'
                ' (signature was verified) header.d={domain};dmarc={dmarc}\r\n'
                ' action=none header.from={header_from};compauth=pass reason=100\r\n'
                'X-MS-Exchange-Authentication-Results: mx.microsoft.com 1; spf=none; dkim=none;\r\n'
                ' dmarc=none action=none header.from={header_from};\r\n')
RECEIPT = 'You sent a payment of $29.99 USD to Netflix. View the transaction details in your account.'


def message(sender='service@paypal.com', *, auth=None, domain='paypal.com', header_from=None, body=RECEIPT,
            html=False, name='PayPal', subject='Receipt for your payment', reply_to=None):
    auth = GMAIL_PASS.format(domain=domain, header_from=header_from or domain) if auth is None else auth
    content_type = 'text/html; charset=utf-8' if html else 'text/plain; charset=utf-8'
    reply = f'Reply-To: {reply_to}\r\n' if reply_to else ''
    return (auth + f'From: {name} <{sender}>\r\n{reply}To: user@example.com\r\nSubject: {subject}\r\n'
            f'MIME-Version: 1.0\r\nContent-Type: {content_type}\r\n\r\n{body}\r\n').encode()


def verified(raw, mailbox='gmail'):
    return analyze_raw_email(raw, mailbox_provider=mailbox)['verified_official_sender']


class VerifiedOfficialSenderTests(unittest.TestCase):
    def test_topmost_gmail_dmarc_pass_on_an_official_domain_verifies_the_sender(self):
        self.assertEqual(verified(message()), {'organization': 'PayPal', 'domain': 'paypal.com'})
        self.assertEqual(verified(message('alerts@notify.wellsfargo.com', domain='notify.wellsfargo.com',
                                          name='Wells Fargo Online')),
                         {'organization': 'Wells Fargo', 'domain': 'notify.wellsfargo.com'})
        structure = analyze_raw_email(message(), mailbox_provider='gmail')
        self.assertIn('structure.verified_official_sender', [item['code'] for item in structure['indicators']])

    def test_nothing_is_trusted_without_a_named_mailbox(self):
        self.assertIsNone(verified(message(), mailbox=None))
        self.assertIsNone(verified(message(), mailbox='yahoo'))

    def test_a_forged_gmail_header_below_the_receiving_services_header_is_ignored(self):
        forged = ('Authentication-Results: mx.other-provider.example; none\r\n'
                  + GMAIL_PASS.format(domain='paypal.com', header_from='paypal.com'))
        structure = analyze_raw_email(message(auth=forged), mailbox_provider='gmail')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertEqual(structure['auth_results'], {})
        self.assertTrue(structure['untrusted_authentication_claims'])

    def test_misaligned_consumer_or_failing_senders_are_not_verified(self):
        self.assertIsNone(verified(message(header_from='evil.example')))
        self.assertIsNone(verified(message('someone@qq.com', domain='qq.com')))
        self.assertIsNone(verified(message('someone@icloud.com', domain='icloud.com')))
        self.assertIsNone(verified(message('billing@paypal-help.top', domain='paypal-help.top')))
        failing = ('Authentication-Results: mx.google.com; dkim=fail header.i=@paypal.com; '
                   'spf=fail smtp.mailfrom=paypal.com; dmarc=fail header.from=paypal.com\r\n')
        structure = analyze_raw_email(message(auth=failing), mailbox_provider='gmail')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertIn('structure.auth_failed', [item['code'] for item in structure['indicators']])


    def test_topmost_outlook_dmarc_pass_verifies_the_sender_only_for_outlook(self):
        outlook = OUTLOOK_PASS.format(domain='paypal.com', header_from='paypal.com', dmarc='pass')
        self.assertEqual(verified(message(auth=outlook), mailbox='outlook'),
                         {'organization': 'PayPal', 'domain': 'paypal.com'})
        self.assertIsNone(verified(message(auth=outlook), mailbox='gmail'))
        self.assertIsNone(verified(message(), mailbox='outlook'))
        guess = OUTLOOK_PASS.format(domain='paypal.com', header_from='paypal.com', dmarc='bestguesspass')
        self.assertIsNone(verified(message(auth=guess), mailbox='outlook'))

    def test_a_forged_microsoft_header_below_outlooks_result_is_ignored(self):
        failing = OUTLOOK_PASS.format(domain='paypal-help.top', header_from='paypal.com', dmarc='fail')
        forged = failing + ('Authentication-Results: mx.microsoft.com 1; spf=pass smtp.mailfrom=paypal.com;'
                            ' dkim=pass header.d=paypal.com; dmarc=pass action=none header.from=paypal.com\r\n')
        structure = analyze_raw_email(message(auth=forged), mailbox_provider='outlook')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertEqual(structure['auth_results']['dmarc'], 'fail')
        self.assertIn('structure.auth_failed', [item['code'] for item in structure['indicators']])

    def test_mailbox_parameter_is_validated(self):
        self.assertEqual(VisualRequest(mailbox='gmail').mailbox, 'gmail')
        self.assertEqual(VisualRequest(mailbox='outlook').mailbox, 'outlook')
        with self.assertRaises(ValidationError):
            VisualRequest(mailbox='yahoo')

        def upload(query):
            chunks = iter([message()])

            async def receive():
                chunk = next(chunks, None)
                return {'type': 'http.request', 'body': chunk or b'', 'more_body': chunk is not None}
            request = app.Request({'type': 'http', 'query_string': query,
                                   'headers': [(b'content-type', b'message/rfc822')]}, receive)
            return json.loads(asyncio.run(app.analyze_eml_endpoint(request)).body)

        with self.assertRaises(HTTPException) as caught:
            upload(b'mailbox=yahoo')
        self.assertEqual(caught.exception.status_code, 400)
        self.assertEqual(upload(b'mailbox=gmail')['verified_official_sender'],
                         {'organization': 'PayPal', 'domain': 'paypal.com'})
        self.assertIsNone(upload(b'')['verified_official_sender'])


class PlatformRelayTests(unittest.TestCase):
    def relay(self, raw):
        structure = analyze_raw_email(raw, mailbox_provider='gmail')
        codes = [item['code'] for item in structure['indicators']]
        return structure['verified_official_sender'], 'structure.platform_relay' in codes

    def test_notifications_carrying_another_users_content_are_not_official(self):
        drive = message('drive-shares-dm-noreply@google.com', domain='google.com', name='Invoice Dept (via Google Drive)',
                        subject='Document shared with you: "Invoice"', reply_to='someone@example.net')
        docusign = message('dse@docusign.net', domain='docusign.net', name='Accounts via Docusign',
                           subject='Please review and sign', reply_to='billing@example.net')
        github = message('notifications@github.com', domain='github.com', name='Jane Doe',
                         subject='[org/repo] Urgent security notice (Issue #12)')
        canva = message('no-reply@canva.com', domain='canva.com', name='Canva', subject='A design has been shared with you!')
        zoom = message('no-reply@zoom.us', domain='zoom.us', name='Zoom',
                       subject='Jane Doe is inviting you to a scheduled Zoom meeting')
        reply_elsewhere = message(reply_to='refunds@example.net')
        for raw in (drive, docusign, github, canva, zoom, reply_elsewhere):
            with self.subTest(raw=raw[raw.index(b'From:'):][:60]):
                self.assertEqual(self.relay(raw), (None, True))

    def test_the_services_own_account_mail_is_still_official(self):
        cases = (
            (message('no-reply@canva.com', domain='canva.com', name='Canva', subject='Your Canva code is 980028'), 'Canva'),
            (message('noreply@github.com', domain='github.com', name='GitHub', subject='[GitHub] Please reset your password'),
             'GitHub'),
            (message('noreply@id.atlassian.com', domain='id.atlassian.com', name='Trello',
                     subject='18ZN4F is your verification code'), 'Atlassian'),
            (message('EA@e.ea.com', domain='e.ea.com', name='EA', subject='Your EA Security Code is: 131088'),
             'Electronic Arts'),
            (message(name='service@paypal.com'), 'PayPal'),
            (message('security-noreply@linkedin.com', domain='linkedin.com', name='LinkedIn',
                     subject='Your LinkedIn verification code'), 'LinkedIn'),
            (message('noreply@redditmail.com', domain='redditmail.com', name='Reddit', subject='Your weekly digest'),
             'Reddit'),
            (message('noreply@steampowered.com', domain='steampowered.com', name='Steam',
                     subject='Your Steam account: Access from new web or mobile device'), 'Steam (Valve)'),
            (message('noreply@bsky.social', domain='bsky.social', name='Bluesky',
                     subject='Reset your password'), 'Bluesky'),
            (message('no-reply@alerts.spotify.com', domain='spotify.com', name='Spotify',
                     subject='273066 - Your Spotify login code'), 'Spotify'),
            (message(reply_to='help@paypal.com'), 'PayPal'),
        )
        for raw, organization in cases:
            with self.subTest(organization=organization):
                sender, relayed = self.relay(raw)
                self.assertFalse(relayed)
                self.assertEqual(sender['organization'], organization)

    def test_customer_controlled_platform_domains_are_not_registered(self):
        for sender in ('jira@evil-corp.atlassian.net', 'support@evil.zendesk.com'):
            with self.subTest(sender=sender):
                domain = sender.rpartition('@')[2]
                self.assertEqual(self.relay(message(sender, domain=domain, name='Atlassian')), (None, False))


class VerifiedSenderIncompleteAnalysisTests(unittest.TestCase):
    # Hidden preheader text and an Outlook-only block: rendering the model cannot verify.
    HTML = ('<div style="display:none">Your receipt is ready</div><p>Thanks for your payment to Netflix.</p>'
            '<!--[if mso]><table><tr><td>Receipt table</td></tr></table><![endif]-->')

    def analyze(self, raw, mailbox='gmail'):
        with patch.object(app, '_content_pipeline', None):
            structure = analyze_raw_email(raw, mailbox_provider=mailbox)
            return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), structure)).body)

    def test_a_verified_service_is_low_rather_than_undetermined(self):
        raw = message('no-reply@dropbox.com', domain='dropbox.com', name='Dropbox', subject='Verify your email',
                      body=self.HTML, html=True)
        result = self.analyze(raw)
        self.assertEqual((result['risk_level'], result['risk_label']), ('low', 'Low Risk — Verified Official Sender'))
        self.assertFalse(result['analysis_complete'])
        self.assertTrue(any('conditional' in warning.lower() for warning in result['analysis_warnings']))

    def test_payment_brands_keep_abstaining_on_incomplete_analysis(self):
        # Scams sent through genuine PayPal invoices or Microsoft billing are verified too.
        self.assertEqual(self.analyze(message(body=self.HTML, html=True))['risk_level'], 'unknown')

    def test_unverified_or_relayed_mail_stays_undetermined(self):
        relay = message('drive-shares-dm-noreply@google.com', domain='google.com', name='Billing (via Google Drive)',
                        subject='Document shared with you', body=self.HTML, html=True)
        for raw, mailbox in ((message(body=self.HTML, html=True), None), (relay, 'gmail')):
            with self.subTest(mailbox=mailbox):
                self.assertEqual(self.analyze(raw, mailbox)['risk_level'], 'unknown')


class VerifiedSenderRiskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deployment_python = (WEBSITE_DIR.parent / '.python-version').read_text().strip()
        current_python = f'{sys.version_info.major}.{sys.version_info.minor}'
        if current_python != deployment_python:
            raise unittest.SkipTest(f'Committed artifact targets Python {deployment_python}, not {current_python}')
        profile = json.loads((WEBSITE_DIR.parent / 'vercel.json').read_text())['env']
        cls.pipeline = load_content_pipeline_artifact(WEBSITE_DIR.parent / profile['CONTENT_MODEL_ARTIFACT'],
                                                      profile['CONTENT_MODEL_ARTIFACT_SHA256'])

    def analyze(self, raw, mailbox='gmail'):
        structure = analyze_raw_email(raw, mailbox_provider=mailbox)
        with patch.object(app, '_content_pipeline', self.pipeline):
            return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), structure)).body)

    def test_model_led_alert_on_a_verified_official_receipt_becomes_low(self):
        unverified = self.analyze(message(), mailbox=None)
        self.assertIn(unverified['risk_level'], {'medium', 'high'})
        result = self.analyze(message())
        self.assertEqual(result['risk_level'], 'low')
        self.assertEqual(result['risk_label'], 'Low Risk — Verified Official Sender')
        self.assertEqual(result['verified_official_sender']['organization'], 'PayPal')
        self.assertEqual(result['sender_score'], 0)

    def test_strong_evidence_still_alerts_for_a_verified_sender(self):
        lookalike = self.analyze(message(html=True, body='<p>Review your payment.</p>'
                                         '<a href="https://paypal.com.account-review.top/login">Open</a>'))
        self.assertIn(lookalike['risk_level'], {'high', 'critical'})
        code_request = self.analyze(message(body='Reply to this email with the 6-digit verification code we sent.'))
        self.assertIn(code_request['risk_level'], {'high', 'critical'})


if __name__ == '__main__':
    unittest.main()
