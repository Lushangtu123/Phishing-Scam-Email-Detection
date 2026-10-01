import asyncio
import json
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402


def pasted(subject, body):
    return json.loads(asyncio.run(app.analyze_content_endpoint(
        app.ContentRequest(subject=subject, body=body))).body)


def raw(headers, body):
    message = ('From: Shop <news@shop.example>\nTo: user@example.com\nSubject: Spring sale\n' + headers
               + 'MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n' + body)
    return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=message))).body)


class MailTypeTests(unittest.TestCase):
    def test_an_alert_with_scam_findings_names_its_tactics(self):
        result = pasted('Payment receipt', 'Your McAfee plan has been renewed and you have been charged $349.99. '
                        "If this wasn't you, call our billing team at 1 (877) 555-0123 to cancel the renewal.")
        self.assertIn(result['risk_level'], {'high', 'critical'})
        self.assertEqual(result['mail_type']['type'], 'phishing')
        self.assertIn('callback', result['mail_type']['tactics'])

    def test_sales_mail_is_advertising_and_keeps_its_verdict(self):
        result = pasted('三八妇女节礼品', '您好，我们专门为企业提供商务礼品和员工福利，现推出节日优惠，欢迎来电咨询报价。')
        self.assertEqual(result['mail_type'], {'type': 'advertising'})
        self.assertNotIn('advertising_terms', result)

    def test_scam_wording_is_never_called_advertising(self):
        result = pasted('Exclusive offer ends today', 'Act now! 90% off your renewal with this exclusive offer. '
                        'Your account will be suspended unless you verify your password immediately.')
        self.assertNotEqual((result['mail_type'] or {}).get('type'), 'advertising')

    def test_ordinary_account_mail_has_no_type(self):
        result = pasted('Your verification code', 'Your verification code is 482913. It expires in 10 minutes.')
        self.assertIsNone(result['mail_type'])

    def test_one_sales_term_needs_an_opt_out_or_bulk_header(self):
        body = 'Our spring catalogue is here, with free shipping on every order.\n'
        self.assertIsNone(raw('', body)['mail_type'])
        self.assertEqual(raw('List-Unsubscribe: <mailto:unsubscribe@shop.example>\n', body)['mail_type'],
                         {'type': 'advertising'})
        self.assertEqual(raw('', body + 'Unsubscribe from these emails.')['mail_type'], {'type': 'advertising'})

    def test_a_model_only_alert_is_not_called_phishing(self):
        result = {'risk_level': 'medium', 'extra_indicators': [], 'category_results': [], 'advertising_terms': []}
        self.assertIsNone(app._mail_type(result, False))
        result['extra_indicators'] = [{'code': 'link.ip_host', 'level': 'info'}]
        self.assertIsNone(app._mail_type(result, False))
        result['extra_indicators'] = [{'code': 'link.ip_host', 'level': 'high'}]
        self.assertEqual(app._mail_type(result, False), {'type': 'phishing', 'tactics': ['deceptive_link']})


    def test_bulk_sales_mail_whose_only_finding_is_a_tracked_link_is_advertising(self):
        link = {'code': 'link.display_mismatch', 'level': 'high'}
        result = {'risk_level': 'high', 'extra_indicators': [link], 'category_results': [],
                  'advertising_terms': ['征稿', '期刊']}
        self.assertEqual(app._mail_type(result, False), {'type': 'advertising'})
        # One sales phrase with an unsubscribe footer is not enough to set the link aside.
        result['advertising_terms'] = ['special offer', 'unsubscribe']
        self.assertEqual(app._mail_type(result, True), {'type': 'phishing', 'tactics': ['deceptive_link']})
        # Any other scam finding keeps it phishing.
        result['advertising_terms'] = ['征稿', '期刊']
        result['extra_indicators'] = [link, {'code': 'content.callback_request', 'level': 'high'}]
        self.assertEqual(app._mail_type(result, False)['type'], 'phishing')

if __name__ == '__main__':
    unittest.main()
