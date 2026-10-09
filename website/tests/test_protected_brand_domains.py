"""The protected brands' own domains are not their lookalikes (synthetic messages only)."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
from email_structure import _PROTECTED_BRAND_DOMAINS  # noqa: E402

OFFICIAL_HOSTS = (
    'apple.co', 'apple.news', 'cdn-apple.com',
    'www.amazon.ca', 'www.amazon.fr', 'www.amazon.co.jp', 'www.amazon.com.au', 'www.amazon.in',
    'www.google.ca', 'www.google.de', 'www.google.co.jp', 'www.google.com.au',
    'login.microsoftonline.com', 'www.microsoft365.com',
    'paypal.me', 'www.paypalobjects.com',
    # The brands' own top-level domains
    'blog.google', 'outlook.cloud.microsoft', 'developer-docs.amazon', 'token.safebrowsing.apple',
)
LOOKALIKE_HOSTS = (
    'paypa1.com', 'amazon.ca.verify-account.example', 'apple.co.signin.example', 'secure-paypal.me',
    'google.evil.example', 'microsoft365-login.example', 'apple-id.cloud.example',
    # Hosts anyone with an account can get
    'phish.s3.amazonaws.com', 'contoso.onmicrosoft.com',
)


def rule_ids(result):
    return {item.get('rule_id') for item in result['extra_indicators']}


class LinkTests(unittest.TestCase):
    def test_official_hosts_are_not_lookalikes(self):
        for host in OFFICIAL_HOSTS:
            with self.subTest(host=host):
                result = app.analyze_email_content('Notice', f'<a href="https://{host}/x">Open</a>')
                self.assertFalse(rule_ids(result) & {'link.brand_lookalike', 'link.idn_confusable'})

    def test_lookalikes_stay_high(self):
        for host in LOOKALIKE_HOSTS:
            with self.subTest(host=host):
                result = app.analyze_email_content('Notice', f'<a href="https://{host}/x">Open</a>')
                self.assertIn('link.brand_lookalike', rule_ids(result))
                self.assertIn(result['risk_level'], {'high', 'critical'})

    def test_a_text_with_an_official_short_link(self):
        result = app.analyze_sms('', 'Apple Music: 3 months free for new subscribers. Details: https://apple.co/3xYz')
        self.assertNotIn('link.brand_lookalike', rule_ids(result))
        self.assertNotIn(result['risk_level'], {'high', 'critical'})
        self.assertIn('link.brand_lookalike',
                      rule_ids(app.analyze_sms('', 'Apple: your ID is locked. Verify at apple.co.signin.top/a')))


class SenderTests(unittest.TestCase):
    def test_a_brand_name_from_its_own_domain(self):
        for name, address in (('Amazon', 'store-news@amazon.ca'), ('Google', 'no-reply@google.de'),
                              ('Microsoft', 'no-reply@microsoft365.com'), ('PayPal', 'service@paypal.me')):
            with self.subTest(address=address):
                structure = app.analyze_raw_email(f'From: {name} <{address}>\nSubject: Notice\n\nHello.')
                self.assertFalse(any(item['code'] == 'structure.brand_display_name' for item in structure['indicators']))

    def test_a_brand_name_from_another_domain(self):
        for name, address in (('Amazon', 'billing@s3.amazonaws.com'), ('Microsoft', 'admin@contoso.onmicrosoft.com'),
                              ('PayPal', 'service@paypal.me.example')):
            with self.subTest(address=address):
                structure = app.analyze_raw_email(f'From: {name} <{address}>\nSubject: Notice\n\nHello.')
                self.assertTrue(any(item['code'] == 'structure.brand_display_name' for item in structure['indicators']))


class ListTests(unittest.TestCase):
    def test_list_sizes(self):
        # Google's 187 search domains, Amazon's 23 stores and 2 more Vendor Central domains, and the brand TLDs
        self.assertEqual(sum(domain.startswith('google.') for domain in _PROTECTED_BRAND_DOMAINS['google']), 187)
        self.assertEqual(sum(domain.startswith('amazon.') for domain in _PROTECTED_BRAND_DOMAINS['amazon']), 25)
        for brand in ('apple', 'amazon', 'google', 'microsoft'):
            self.assertIn(brand, _PROTECTED_BRAND_DOMAINS[brand])
        self.assertNotIn('paypal', _PROTECTED_BRAND_DOMAINS['paypal'])  # no .paypal top-level domain

    def test_shared_hosts_are_not_listed(self):
        listed = {domain for domains in _PROTECTED_BRAND_DOMAINS.values() for domain in domains}
        self.assertFalse(listed & {'amazonaws.com', 'onmicrosoft.com', 'microsoftusercontent.com'})


if __name__ == '__main__':
    unittest.main()
