"""Stable codes for server-generated English messages (server_messages.py).

The English text is unchanged; these tests check that every message also
carries a registered code and bounded parameters that re-render it exactly.
static/server-messages.test.mjs checks the registry against the homepage
dictionary.
"""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import server_messages as sm  # noqa: E402

FAMILIES = ('sender.', 'content.', 'link.', 'structure.', 'sms.', 'warning.', 'safety.', 'prefix.', 'verify.')
CONTENT_EXAMPLES = {
    key: re.search(r"'" + key + r"': \{\s*subject: '([^']*)',\s*body: `([^`]*)`", (WEBSITE_DIR / 'static' / 'app-content.js')
                   .read_text(encoding='utf-8')).groups()
    for key in ('phishing-account', 'phishing-lottery', 'legit-newsletter')
}
SENDER_EXAMPLES = sorted(set(re.findall(r'data-action="set-example" data-arg="([^"]+)"',
                                        (WEBSITE_DIR / 'static' / 'index.html').read_text(encoding='utf-8'))))
AUTH_FAILURE_EML = b'''Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1.com; dkim=fail; dmarc=fail
From: "PayPal Security" <security@paypa1-verify.xyz>
Reply-To: attacker@evil.example
To: victim@example.com
Subject: Verify your account
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/html

<p>Your account is suspended. <a href="http://192.168.1.1/login">https://paypal.com/signin</a></p>
<img src="https://img.example/logo.png">
--b
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"

AAAA
--b--
'''


def render(entry):
    """Re-render an entry from the registry, applying prefixes innermost first."""
    rendered = sm.TEMPLATES[entry['code']].format(**entry['params'])
    for prefix in reversed(entry.get('prefixes', [])):
        rendered = sm.TEMPLATES[prefix['code']].format(text=rendered, **prefix['params'])
    return rendered


def sample_params(code):
    return {name: f'<{name}-{index}>' for index, name in enumerate(sm.fields(sm.TEMPLATES[code]))}


class RegistryTests(unittest.TestCase):
    def test_codes_and_templates_are_well_formed_and_unambiguous(self):
        self.assertGreater(len(sm.TEMPLATES), 150)
        for code, template in sm.TEMPLATES.items():
            with self.subTest(code=code):
                self.assertRegex(code, sm.CODE_PATTERN)
                self.assertTrue(code.startswith(FAMILIES))
                # Only {field} placeholders: no other braces, format specs or conversions.
                self.assertNotIn('{', sm._FIELD.sub('', template))
                self.assertNotIn('}', sm._FIELD.sub('', template))
                self.assertEqual(len(sm.fields(template)), len(set(sm.fields(template))))
                self.assertEqual(template, template.strip())
                if code.startswith('prefix.'):
                    self.assertEqual(sm.fields(template)[-1], 'text')
        self.assertEqual(len(set(sm.TEMPLATES.values())), len(sm.TEMPLATES), 'English templates must be unique')

    def test_every_template_renders_and_describable_ones_round_trip(self):
        for code in sm.TEMPLATES:
            with self.subTest(code=code):
                params = sample_params(code)
                rendered = sm.text(code, **params)
                for value in params.values():
                    self.assertIn(value, rendered)
                if code.startswith(('warning.', 'safety.')):
                    self.assertEqual(sm.describe(rendered), {'code': code, 'params': params, 'msg': rendered})

    def test_prefixed_and_unknown_strings(self):
        inner = sm.text('warning.remote_images')
        nested = sm.text('prefix.attached_message', text=sm.text('prefix.image', name='a (1).png', text=inner))
        self.assertEqual(sm.describe(nested), {
            'code': 'warning.remote_images', 'params': {}, 'msg': nested,
            'prefixes': [{'code': 'prefix.attached_message', 'params': {}},
                         {'code': 'prefix.image', 'params': {'name': 'a (1).png'}}]})
        browser = sm.text('prefix.image_recognition', text='scan.png: decoder crashed')
        self.assertEqual(sm.describe(browser), {'code': 'prefix.image_recognition',
                                                'params': {'text': 'scan.png: decoder crashed'}, 'msg': browser})
        self.assertEqual(sm.describe('Something new'), {'code': None, 'params': {}, 'msg': 'Something new'})
        # Indicator families are never guessed from free text.
        hyphen = sm.text('sender.domain_hyphen', domain='a-b.com')
        self.assertIsNone(sm.describe(hyphen)['code'])

    def test_params_are_bounded_scalars_while_msg_keeps_the_full_value(self):
        long_name = 'x' * 400 + '.exe'
        item = sm.indicator('high', 'structure.dangerous_attachment', filename=long_name)
        self.assertEqual(item['msg'], f'Potentially dangerous attachment: {long_name}.')
        self.assertEqual(len(item['params']['filename']), sm.PARAM_MAX_CHARS)
        self.assertTrue(item['params']['filename'].endswith('…'))
        self.assertEqual(sm.clean_params({'a': 3, 'b': 2.5, 'c': True, 'd': None, 'e': float('nan')}),
                         {'a': 3, 'b': 2.5, 'c': 'True', 'd': 'None', 'e': 'nan'})

    def test_every_code_literal_in_the_backend_is_registered_and_every_code_is_used(self):
        sources = {path.name: path.read_text(encoding='utf-8') for path in WEBSITE_DIR.glob('*.py')}
        literal = re.compile(r"""['"]((?:%s)[a-z0-9_.]*[a-z0-9_])['"]""" % '|'.join(re.escape(f) for f in FAMILIES))
        used = {match for text in sources.values() for match in literal.findall(text)}
        # Codes built at runtime: safety.<name>, sender.factor.<name> and verify.dmarc_<policy>[_partial].
        dynamic = set()
        for keyword, code in re.findall(r'\("([^"]+)", "([a-z_]+)"\)',
                                        sources['app.py'][sources['app.py'].index('CONTENT_SAFETY_SIGNALS'):]):
            dynamic.add('safety.' + code)
        dynamic |= {'sender.factor.' + name for name in ('entropy', 'vowel', 'digits', 'unique', 'no_word', 'word_combo')}
        dynamic |= {f'verify.dmarc_{policy}{suffix}' for policy in ('reject', 'quarantine') for suffix in ('', '_partial')}
        dynamic.add('verify.dmarc_none')
        referenced = {code for code in used if code in sm.TEMPLATES} | dynamic
        not_codes = {'verify.phishguard.local'}  # the SMTP HELO name
        self.assertEqual(sorted(code for code in used - not_codes if code not in sm.TEMPLATES), [])
        self.assertEqual(sorted(set(sm.TEMPLATES) - referenced), [])
        self.assertTrue(dynamic <= set(sm.TEMPLATES))


class ResponseCodeTests(unittest.TestCase):
    def assert_coded(self, entry, text=None):
        text = entry['msg'] if text is None else text
        self.assertIn(entry.get('code'), sm.TEMPLATES, text)
        for prefix in entry.get('prefixes', []):
            self.assertIn(prefix['code'], sm.TEMPLATES)
        for value in [*entry['params'].values(), *(v for p in entry.get('prefixes', []) for v in p['params'].values())]:
            self.assertIsInstance(value, (int, float, str))
            if isinstance(value, str):
                self.assertLessEqual(len(value), sm.PARAM_MAX_CHARS)
        self.assertEqual(render(entry), text)

    def content(self, subject='', body='', structure=None):
        return json.loads(asyncio.run(app._analyze_content(
            app.ContentRequest(subject=subject, body=body), structure, observe_sender_history=False)).body)

    def assert_content_coded(self, result):
        for item in result['extra_indicators']:
            self.assert_coded(item)
        self.assertEqual([item['msg'] for item in result['analysis_warning_details']], result['analysis_warnings'])
        self.assertEqual([item['msg'] for item in result['safety_signal_details']], result['safety_signals'])
        for item in result['analysis_warning_details'] + result['safety_signal_details']:
            self.assert_coded(item)
        for item in (result.get('sender_analysis') or {}).get('risk_indicators', []):
            self.assert_coded(item)

    def test_homepage_sender_examples(self):
        self.assertIn('security-alert@paypa1-verify.xyz', SENDER_EXAMPLES)
        for address in SENDER_EXAMPLES:
            with self.subTest(address=address):
                result = json.loads(asyncio.run(app.analyze_email(app.EmailRequest(email=address))).body)
                for item in result['risk_indicators']:
                    self.assertEqual(set(item), {'level', 'msg', 'code', 'params'})
                    self.assert_coded(item)
        result = json.loads(asyncio.run(app.analyze_email(app.EmailRequest(email='security-alert@paypa1-verify.xyz'))).body)
        hyphen = next(item for item in result['risk_indicators'] if item['code'] == 'sender.domain_hyphen')
        self.assertEqual(hyphen, {
            'level': 'low', 'code': 'sender.domain_hyphen', 'params': {'domain': 'paypa1-verify.xyz'},
            'msg': 'Domain contains a hyphen (paypa1-verify.xyz) — major providers typically do not use hyphens in their domains'})

    def test_random_username_factors_are_individually_coded(self):
        result = json.loads(asyncio.run(app.analyze_email(app.EmailRequest(email='oncw3kjobqxb@randominbox.net'))).body)
        item = next(item for item in result['risk_indicators'] if item['code'] == 'sender.random_username')
        params = item['params']
        names = params['factor_codes'].split(',')
        self.assertTrue(names)
        self.assertEqual(params['factors'], ', '.join(sm.text('sender.factor.' + name, value=params['entropy'],
                                                              percent=params[f'{name}_percent'] if name in {'vowel', 'unique'} else 0)
                                                      for name in names))
        self.assertIn(f"matches {params['score']}/6 randomness factors ({params['factors']})", item['msg'])

    def test_homepage_content_examples(self):
        for key, (subject, body) in CONTENT_EXAMPLES.items():
            with self.subTest(example=key):
                result = self.content(subject, body)
                self.assert_content_coded(result)
        phishing = self.content(*CONTENT_EXAMPLES['phishing-account'])
        self.assertIn({'level': 'high', 'msg': 'Contains shortened URLs (bit.ly, tinyurl, etc.) — hides the true destination domain',
                       'code': 'content.shortened_urls', 'params': {}}, phishing['extra_indicators'])
        newsletter = self.content(*CONTENT_EXAMPLES['legit-newsletter'])
        self.assertIn({'code': 'safety.unsubscribe', 'params': {},
                       'msg': 'Contains unsubscribe link — typical of legitimate bulk emails'},
                      newsletter['safety_signal_details'])
        self.assertIsInstance(newsletter['safety_signals'][0], str)

    def test_eml_with_authentication_failures_and_wrapped_sender_evidence(self):
        structure = app.analyze_raw_email(AUTH_FAILURE_EML, trusted_authserv_ids={'mx.example.com'})
        result = self.content(structure=structure)
        self.assert_content_coded(result)
        by_code = {item['code']: item for item in result['extra_indicators']}
        self.assertEqual(by_code['structure.auth_failed']['msg'], 'Message authentication failed: DKIM, DMARC, SPF.')
        self.assertEqual(by_code['structure.auth_failed']['params'], {'mechanisms': 'DKIM, DMARC, SPF'})
        self.assertEqual(by_code['structure.dangerous_attachment']['params'], {'filename': 'invoice.exe'})
        self.assertEqual(by_code['link.ip_host']['rule_id'], 'link.ip_host')
        sender = [item for item in result['extra_indicators'] if item.get('prefixes') == [{'code': 'prefix.sender', 'params': {}}]]
        self.assertTrue(sender)
        self.assertTrue(all(item['msg'].startswith('Sender: ') for item in sender))
        self.assertIn('warning.remote_images', [item['code'] for item in result['analysis_warning_details']])
        self.assertIn('warning.attachments_uninspected', [item['code'] for item in result['analysis_warning_details']])

    def test_attached_messages_and_image_evidence_keep_inner_codes(self):
        nested = (b'From: a@example.com\nSubject: outer\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="b"\n\n'
                  b'--b\nContent-Type: text/plain\n\nsee attached\n--b\nContent-Type: message/rfc822\n\n'
                  b'From: x@paypa1-verify.xyz\nSubject: inner\nContent-Type: text/html\n\n'
                  b'<a href="https://bit.ly/x">verify</a> urgent password <img src="https://i.example/a.png">\n--b--\n')
        result = self.content(structure=app.analyze_raw_email(nested))
        self.assert_content_coded(result)
        attached = [item for item in result['extra_indicators']
                    if item.get('prefixes', [{}])[0].get('code') == 'prefix.attached_message']
        self.assertIn('content.shortened_urls', [item['code'] for item in attached])
        self.assertIn('content.nested_category', [item['code'] for item in attached])

        sha = hashlib.sha256(b'img').hexdigest()
        visual = app.VisualRequest(warnings=['Worker note'], observations=[{
            'name': 'scan.png', 'mime_type': 'image/png', 'source': 'upload', 'sha256': sha, 'status': 'partial',
            'ocr_text': 'URGENT verify your password at http://192.168.1.1/login', 'ocr_confidence': 80,
            'warnings': ['OCR confidence is low; verify the extracted text.']}])
        result = json.loads(asyncio.run(app._analyze_visual(visual, observe_sender_history=False)).body)
        self.assert_content_coded(result)
        image = [item for item in result['extra_indicators'] if item['msg'].startswith('Image (scan.png): ')]
        self.assertTrue(image)
        self.assertTrue(all(item['prefixes'][0] == {'code': 'prefix.image', 'params': {'name': 'scan.png'}} for item in image))
        record = result['visual_analysis']['observations'][0]
        self.assertEqual([item['msg'] for item in record['assessment_warning_details']], record['assessment_warnings'])
        self.assertIn('warning.ocr_verify_urls', [item['code'] for item in record['assessment_warning_details']])
        browser = next(item for item in result['analysis_warning_details'] if item['msg'] == 'Image recognition: Worker note')
        self.assertEqual(browser['code'], 'prefix.image_recognition')

    def test_case_storage_keeps_indicator_codes_but_not_detail_lists(self):
        subject, body = CONTENT_EXAMPLES['legit-newsletter']
        source, analysis, _provenance = asyncio.run(app._analyze_case(
            app.ContentRequest(subject=subject, body=body), None))
        self.assertNotIn('analysis_warning_details', analysis)
        self.assertNotIn('safety_signal_details', analysis)
        self.assertTrue(analysis['safety_signals'])
        self.assertTrue(all('code' in item for item in analysis['extra_indicators']))
        self.assertIn('input_mode', source)


class VerificationCodeTests(unittest.TestCase):
    def endpoint(self, email='user@example.com', *, mode='lite', **mocks):
        with patch.object(app, 'SETTINGS', replace(app.SETTINGS, verification_mode=mode)):
            patches = [patch.object(app, name, value) for name, value in mocks.items()]
            for item in patches:
                item.start()
            try:
                return json.loads(app.verify_email_endpoint(app.VerifyRequest(email=email)).body)
            finally:
                for item in patches:
                    item.stop()

    def assert_message(self, holder, key, code, text):
        prefix = '' if key == 'message' else key + '_'
        self.assertEqual(holder[key], text)
        self.assertEqual(holder[prefix + 'code'], code)
        self.assertEqual(sm.TEMPLATES[code].format(**holder[prefix + 'params']), text)

    def test_skipped_unavailable_and_failed_paths(self):
        invalid = self.endpoint('not an address')
        self.assert_message(invalid, 'smtp_message', 'verify.format_invalid',
                            'Enter a single supported email address with an unquoted ASCII local part and a valid domain.')
        self.assertEqual(invalid['mailbox_verification']['reason_code'], 'verify.smtp_disabled_reason')

        def lookup_failure(domain, deadline):
            raise RuntimeError('resolver down')
        unavailable = self.endpoint(_lookup_mail_domain=lookup_failure)
        self.assert_message(unavailable, 'smtp_message', 'verify.dns_unavailable', 'DNS lookup was unavailable.')

        def raising(*args):
            raise RuntimeError('check failed')
        lite = self.endpoint(_lookup_mail_domain=lambda domain, deadline: {'mx_found': True, 'mx_records': [[10, 'mx.example.com']]},
                             _check_spf=raising, _check_dmarc=raising, _check_domain_age=raising, _check_mx_ptr=raising)
        self.assert_message(lite, 'smtp_message', 'verify.smtp_disabled',
                            'SMTP mailbox probing is unavailable on this deployment.')
        for key in ('spf', 'dmarc', 'domain_age', 'mx_ptr'):
            self.assert_message(lite[key], 'message', 'verify.check_failed', 'Verification check failed; result unavailable.')
        self.assert_message(lite['mailbox_verification'], 'reason', 'verify.smtp_disabled_reason',
                            'SMTP mailbox probing is unavailable on this deployment; domain evidence does not prove that the mailbox exists.')

        busy = replace(app.SETTINGS, verification_mode='lite')
        with patch.object(app, 'SETTINGS', busy), \
                patch.object(app._verification_pool, 'submit', side_effect=[
                    type('F', (), {'result': lambda self, timeout=None: {'mx_found': True, 'mx_records': [[0, 'example.com']],
                                                                         **app._verify_message('verify.address_record_fallback', 'note', record_type='A')},
                                   'cancel': lambda self: None})(), None, None, None, None]):
            result = json.loads(app.verify_email_endpoint(app.VerifyRequest(email='user@example.com')).body)
        self.assert_message(result['spf'], 'message', 'verify.check_busy', 'Verification capacity is busy; this check was not run.')
        self.assert_message(result, 'note', 'verify.address_record_fallback',
                            'No MX record found; domain has an A record — using domain directly.')

    def test_blocked_port_and_probe_results(self):
        found = lambda domain, deadline: {'mx_found': True, 'mx_records': [[10, 'mx.example.com']]}
        ok = {'found': False, 'message': 'x', 'code': None, 'params': {}, 'status': 'not_found'}
        blocked = self.endpoint(mode='full', _lookup_mail_domain=found, _check_spf=lambda d: ok, _check_dmarc=lambda d: ok,
                                _check_domain_age=lambda d: ok, _check_mx_ptr=lambda h: ok,
                                _smtp_probe=lambda email, host: {'connectable': False, 'result': 'unverifiable',
                                                                 'message': '', 'status': 'error'})
        self.assert_message(blocked, 'smtp_message', 'verify.smtp_port_blocked',
                            'Port 25 appears blocked by your network. MX records exist, so the domain is real, '
                            'but mailbox existence cannot be confirmed.')
        self.assertEqual(blocked['mailbox_verification']['reason_code'], 'verify.smtp_port_blocked')
        # A probe result without a code keeps its message and reports no code.
        legacy = self.endpoint(mode='full', _lookup_mail_domain=found, _check_spf=lambda d: ok, _check_dmarc=lambda d: ok,
                               _check_domain_age=lambda d: ok, _check_mx_ptr=lambda h: ok,
                               _smtp_probe=lambda email, host: {'connectable': True, 'result': 'exists',
                                                                'message': '250 OK', 'status': 'ok'})
        self.assertEqual((legacy['smtp_message'], legacy['smtp_message_code']), ('250 OK', None))

        import smtplib

        class FakeSMTP:
            def __init__(self, timeout=None):
                self.sock = type('Sock', (), {'settimeout': lambda self, seconds: None})()

            def connect(self, host, port):
                pass

            def helo(self, name):
                pass

            def mail(self, sender):
                pass

            def rcpt(self, address):
                return 550, b'5.1.1 ' + b'u' * 300

            def quit(self):
                pass

            def close(self):
                pass

        with patch.object(smtplib, 'SMTP', FakeSMTP):
            probe = app._smtp_probe('user@example.com', 'mx.example.com', smtp_address='8.8.8.8')
        self.assertEqual(probe['code'], 'verify.smtp_no_such_mailbox')
        self.assertEqual(probe['params']['smtp_code'], 550)
        self.assertEqual(len(probe['params']['response']), 120)
        self.assertEqual(probe['message'], 'Mail server reports no such mailbox (SMTP 550): ' + ('5.1.1 ' + 'u' * 300)[:120])
        private = app._smtp_probe('user@example.com', 'mx.example.com', smtp_address='10.0.0.1')
        self.assert_message(private, 'message', 'verify.smtp_non_public_target',
                            'SMTP target for mx.example.com is non-public or could not be validated.')

    def test_dns_policy_and_age_messages(self):
        import dns.resolver

        class Record:
            def __init__(self, text):
                self.strings = [text.encode()]

        def txt(value):
            return lambda name, kind='A', lifetime=None: [Record(value)]
        cases = [
            (app._check_spf, 'v=spf1 ~all', 'verify.spf_softfail', 'Soft-fail policy (~all): unauthorized senders are flagged but not blocked.'),
            (app._check_dmarc, 'v=DMARC1; p=reject; pct=40', 'verify.dmarc_reject_partial',
             'p=reject (requested for 40% of messages): domain requests rejection of DMARC-failing messages.'),
            (app._check_dmarc, 'v=DMARC1; p=none; pct=40', 'verify.dmarc_none', 'p=none: monitoring only — no enforcement requested.'),
            (app._check_dmarc, 'unrelated', 'verify.dmarc_missing', 'No DMARC record at _dmarc.example.com — no anti-spoofing policy set.'),
        ]
        for check, record, code, text in cases:
            with self.subTest(code=code), patch.object(dns.resolver, 'resolve', txt(record)):
                self.assert_message(check('example.com'), 'message', code, text)

        from datetime import datetime, timedelta, timezone

        class Whois:
            def __init__(self, days):
                self.creation_date = datetime.now(timezone.utc) - timedelta(days=days)
                self.registrar = 'Registrar'
        for days, code in ((10, 'verify.age_very_new'), (90, 'verify.age_new'), (200, 'verify.age_under_year'),
                           (400, 'verify.age_established_one'), (1200, 'verify.age_established')):
            with self.subTest(days=days), patch('whois.whois', lambda domain, timeout=5, days=days: Whois(days)):
                result = app._check_domain_age('example.com')
                self.assertEqual(result['code'], code)
                self.assertEqual(sm.TEMPLATES[code].format(**result['params']), result['message'])


if __name__ == '__main__':
    unittest.main()
