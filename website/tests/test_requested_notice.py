"""Asking whether a model-driven account notice was requested, and applying the answer."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

NOTICES = [
    ('Verify your email address', 'Hi Alex, please confirm your email address to finish setting up your account. '
     'Click the button below to verify your email. If you did not create an account, ignore this message.'),
    ('Your security code', 'Use this security code to sign in to your account: 482913. This code expires in 10 '
     'minutes. If you did not request this code, someone may be trying to access your account.'),
    ('Reset your password', 'We received a request to reset the password for your account. Click the link below '
     'to choose a new password. This link will expire in 24 hours.'),
    ('New sign-in to your account', 'We noticed a new sign-in to your account from a new device. If this was you, '
     'you can ignore this email. If not, please secure your account.'),
]


def deployment_pipeline(test):
    from content_inference import load_content_pipeline_artifact
    root = WEBSITE_DIR.parent
    if f'{sys.version_info.major}.{sys.version_info.minor}' != (root / '.python-version').read_text().strip():
        test.skipTest('Committed artifact targets another Python version')
    profile = json.loads((root / 'vercel.json').read_text())['env']
    return load_content_pipeline_artifact(root / profile['CONTENT_MODEL_ARTIFACT'], profile['CONTENT_MODEL_ARTIFACT_SHA256'])


class RequestedNoticeTests(unittest.TestCase):
    def analyze(self, subject, body, requested=''):
        with patch.object(app, '_content_pipeline', deployment_pipeline(self)):
            return json.loads(asyncio.run(app.analyze_content_endpoint(
                app.ContentRequest(subject=subject, body=body, requested=requested))).body)

    def analyze_raw(self, raw):
        with patch.object(app, '_content_pipeline', deployment_pipeline(self)):
            return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)

    def codes(self, result):
        return [item.get('code') for item in result['extra_indicators']]

    def test_model_driven_account_notices_ask_and_keep_their_alert_until_answered(self):
        for subject, body in NOTICES:
            with self.subTest(subject=subject):
                result = self.analyze(subject, body)
                self.assertIn(result['risk_level'], {'medium', 'high'})
                self.assertIn(result['fusion_basis'], {'model_only', 'model_led'})
                self.assertTrue(result['requested_question'])
                self.assertNotIn('account_notice', result)

    def test_an_original_messages_model_only_notice_is_a_low_note_with_nothing_to_ask(self):
        # Since 2026-10-05 the text model alone is a note in an original message (.eml), not an
        # alert to settle; the same notices pasted as text still ask (above).
        for subject, body in (NOTICES[1], NOTICES[3]):
            with self.subTest(subject=subject):
                raw = (f'From: Alex Chen <alex.chen@gmail.com>\nTo: sam@example.org\nSubject: {subject}\n'
                       f'Content-Type: text/plain; charset=utf-8\n\n{body}\n')
                result = self.analyze_raw(raw)
                self.assertEqual((result['risk_level'], result['risk_label'], result['fusion_basis']),
                                 ('low', 'Low Risk — Text Model Signal Only', 'model_only'))
                self.assertFalse(result['requested_question'])

    def test_yes_lowers_to_low_and_no_keeps_the_alert_with_a_reason(self):
        subject, body = NOTICES[2]
        before = self.analyze(subject, body)
        yes = self.analyze(subject, body, 'yes')
        self.assertEqual((yes['risk_level'], yes['risk_label']), ('low', 'Low Risk — Confirmed as Your Own Action'))
        self.assertIn('content.requested_notice', self.codes(yes))
        self.assertFalse(yes['requested_question'])
        no = self.analyze(subject, body, 'no')
        self.assertEqual(no['risk_level'], before['risk_level'])
        self.assertIn('content.unrequested_notice', self.codes(no))
        self.assertFalse(no['requested_question'])

    def test_independent_evidence_is_never_answered_away(self):
        body = NOTICES[2][1] + ' Reset it here: http://192.0.2.10/reset'
        result = self.analyze('Reset your password', body, 'yes')
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertFalse(result['requested_question'])
        self.assertNotIn('content.requested_notice', self.codes(result))

    def test_notices_of_other_own_actions_are_asked_but_deliveries_and_payments_are_not(self):
        for text in ('Thank you for creating a Netflix account! Your account is ready.',
                     'Order Confirmation: thank you for your order #114-2876549. View your order details.',
                     'Your application for the position of Data Annotator has been received.',
                     'We have received your request 238212 and our team will reply soon.',
                     '您的账号注册成功，欢迎加入。'):
            with self.subTest(text=text[:30]):
                self.assertTrue(app._ACCOUNT_NOTICE.search(text))
        for text in ('Your UPS package delivery is on hold. Confirm your address to reschedule.',
                     'You have received a payment of $250.00. Log in to accept it.',
                     'Your membership has expired. Renew now to keep your benefits.',
                     'Your June statement is now available.'):
            with self.subTest(text=text[:30]):
                self.assertFalse(app._ACCOUNT_NOTICE.search(text))

    def test_other_mail_is_not_asked(self):
        result = self.analyze('Lunch on Friday', 'Are we still on for lunch on Friday at noon? Let me know.')
        self.assertFalse(result['requested_question'])

    def test_the_rule_reads_only_model_driven_alerts(self):
        base = {'risk_level': 'high', 'fusion_basis': 'model_led', 'risk_floor': 'safe', 'extra_indicators': [],
                'account_notice': True, 'risk_label': 'High Risk — Model Signal Needs Review'}
        for change in ({'fusion_basis': 'corroborated'}, {'risk_floor': 'high'}, {'risk_level': 'critical'},
                       {'risk_level': 'unknown'}, {'account_notice': False}):
            with self.subTest(change=change):
                result = {**base, **change, 'extra_indicators': []}
                app._apply_requested_answer(result, 'yes')
                self.assertFalse(result['requested_question'])
                self.assertEqual(result['extra_indicators'], [])

    def test_the_eml_endpoint_validates_the_answer(self):
        raw = (b'From: Dropbox <no-reply@dropbox.com>\r\nTo: user@example.com\r\nSubject: Your security code\r\n'
               b'\r\n' + NOTICES[1][1].encode() + b'\r\n')

        def upload(query):
            chunks = iter([raw])

            async def receive():
                chunk = next(chunks, None)
                return {'type': 'http.request', 'body': chunk or b'', 'more_body': chunk is not None}
            request = app.Request({'type': 'http', 'query_string': query,
                                   'headers': [(b'content-type', b'message/rfc822')]}, receive)
            return asyncio.run(app.analyze_eml_endpoint(request))
        with self.assertRaises(app.HTTPException):
            upload(b'requested=maybe')
        with patch.object(app, '_content_pipeline', deployment_pipeline(self)):
            result = json.loads(upload(b'requested=yes').body)
        self.assertEqual(result['risk_level'], 'low')


if __name__ == '__main__':
    unittest.main()
