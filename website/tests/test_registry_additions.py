"""Registry entries added on 2026-10-02: USAA, Fifth Third Bank, PNC Bank, Charles Schwab,
MetaMask, Tinder, 三井住友銀行 and Alibaba.com."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import email_structure as es  # noqa: E402


class RegistryAdditionTests(unittest.TestCase):
    def test_brands_shown_from_other_domains(self):
        for display, domain, brand in (
                ('USAA', 'virginia.edu', 'USAA'),
                ('Fifth Third Bank', 'arab-egypt.com', 'Fifth Third Bank'),
                ('PNC Alerts', 'windstream.net', 'PNC Alerts'),
                ('C​h​a​r​l​es S‍chwa​b & Co.', 'example.net', 'Charles Schwab'),
                ('MetaMask', 'nucleuspos.com', 'MetaMask'),
                ('Tinder', 'allufa.ru', 'Tinder'),
                ('三井住友銀行', 'wvbflyh.cn', '三井住友銀行')):
            with self.subTest(display=display):
                self.assertEqual(es._registry_brand_claim(display, domain), brand)

    def test_their_own_domains(self):
        for display, domain in (
                ('USAA', 'mailcenter.usaa.com'), ('Fifth Third Bank', '53.com'), ('PNC Alerts', 'pnc.com'),
                ('Charles Schwab', 'email.schwab.com'), ('MetaMask', 'metamask.io'), ('MetaMask', 'cl-cards.com'),
                ('MetaMask', 'metamask.discoursemail.com'), ('Tinder', 'gotinder.com'), ('Tinder', 'mail.gotinder.com'),
                ('三井住友銀行', 'smbc.co.jp')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_names_left_out(self):
        # Shared names are not claims: Schwab Charitable, SMBC group companies, another
        # community's Discourse mail.
        for display, domain in (('Schwab Charitable', 'schwabcharitable.org'), ('SMBC日興証券', 'smbcnikko.co.jp'),
                                ('SMBC Card', 'smbc-card.com')):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, domain))
        self.assertEqual(es._registry_brand_claim('MetaMask', 'other.discoursemail.com'), 'MetaMask')

    def test_alibaba(self):
        for display, domain in (('Alibaba Trade Center', 'noreply.com'), ('Alibaba trade Centre', 'kbss.sk'),
                                ('Alibaba.com Team', 'notice-alibaba.top')):
            with self.subTest(display=display):
                self.assertIsNotNone(es._registry_brand_claim(display, domain))
        for display, domain in (('Alibaba.com', 'service.alibaba.com'), ('Alibaba Cloud', 'alibabacloud.com'),
                                ('AliExpress', 'aliexpress.com')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))


if __name__ == '__main__':
    unittest.main()
