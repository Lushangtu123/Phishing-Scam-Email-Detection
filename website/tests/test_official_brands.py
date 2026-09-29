import asyncio
import json
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import email_structure as es  # noqa: E402

REGISTRIES = {name: json.loads((WEBSITE_DIR / 'data' / f'official_brands_{name}.json').read_text(encoding='utf-8'))
              for name in ('cn', 'intl')}
REGISTRY = REGISTRIES['cn']


def claim(display_name, domain):
    return es._brand_identity_signals(display_name, domain)


class OfficialBrandRegistryTests(unittest.TestCase):
    def test_registry_entries_are_complete_and_sourced(self):
        brands = [brand for registry in REGISTRIES.values() for brand in registry['brands']]
        ids = [brand['id'] for brand in brands]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(es._OFFICIAL_BRANDS), sum(bool(brand['display_names']) for brand in brands))
        statements = [s for registry in REGISTRIES.values() for s in registry.get('regulatory_statements', [])]
        for brand in brands:
            with self.subTest(brand=brand['id']):
                self.assertTrue(brand['official_domains'])
                # Brands without names rely on the existing protected-brand rule.
                self.assertTrue(brand['display_names'] or brand.get('display_check') == 'protected_brand_rule')
                for domain in brand['official_domains']:
                    self.assertEqual(es.normalize_domain(domain), domain)
                    self.assertIn('.', domain)
                self.assertTrue(set(brand['gov_suffixes']) <= {'gov.cn', 'gov', 'gov.uk', 'gc.ca', 'gov.au'})
                statements += brand['verified_statements']
                # Ambiguous acronyms, common words and first names would match unrelated senders.
                self.assertFalse({'ABC', 'BOC', 'CCB', 'CMB', 'CIB', 'EMS', 'QQ', 'Chase', 'Citi', 'Meta', 'UPS',
                                  'Apple', 'CRA', 'ATO', 'SSA'} & set(brand['display_names']))
        for statement in statements:
            self.assertTrue(statement['quote'])
            self.assertTrue(statement['source'].startswith(('https://', 'http://')))
            self.assertIn(statement['source_type'], {'official', 'government', 'media'})

    def test_brand_displayed_from_an_unrelated_domain_is_flagged(self):
        for display_name, domain, brand in (
                ('中国工商银行', 'icbc-secure.top', '中国工商银行'),
                ('工商银行客服中心', 'icbc.com.cn.evil.com', '工商银行'),
                ('招商银行信用卡', 'cmbchina-card.com', '招商银行'),
                ('China Mobile Team', 'b.com', 'China Mobile'),
                ('12306', 'rail-ticket.cn', '12306'),
                ('税务局', 'tax-cn.com', '税务局'),
                ('顺丰速运', 'sf-expres.com', '顺丰速运')):
            with self.subTest(display_name=display_name, domain=domain):
                score, indicators = claim(display_name, domain)
                self.assertEqual(score, 4)
                self.assertEqual(indicators[0]['code'], 'structure.brand_display_name')
                self.assertEqual(indicators[0]['params']['brand'], brand)

    def test_official_domains_subdomains_and_gov_cn_are_not_flagged(self):
        for display_name, domain in (
                ('中国工商银行', 'icbc.com.cn'), ('工商银行', 'mail.icbc.com.cn'), ('中国银联', '95516.com'),
                ('国家税务总局', 'shanghai.chinatax.gov.cn'), ('北京市税务局', 'tax.bj.gov.cn'),
                ('某某区人民法院', 'court.gov.cn'), ('中国工商银行', 'icbc.com.cn.invalid')):
            with self.subTest(display_name=display_name, domain=domain):
                self.assertEqual(claim(display_name, domain), (0, []))

    def test_parent_domains_and_boundaries_do_not_count(self):
        self.assertEqual(claim('工行客服', 'com.cn')[0], 4)  # a public suffix is not icbc.com.cn
        for display_name in ('ICBCX Ltd', '123067', '中通客车', '南航校友会', '张三'):
            with self.subTest(display_name=display_name):
                self.assertEqual(claim(display_name, 'example.com'), (0, []))

    def test_existing_protected_brands_still_work(self):
        self.assertEqual(claim('PayPal Support', 'paypal-help.top')[0], 4)
        self.assertEqual(claim('PayPal', 'paypal.com'), (0, []))

    def test_international_brands_follow_their_published_domains(self):
        flagged = (('Wells Fargo Online', 'wellsfargo-secure.com'), ('HMRC Tax Refund', 'hmrc-refund.co.uk'),
                   ('IRS', 'irs-gov.us'), ('DHL Express', 'dhl-parcel.info'), ('Chase Bank Alerts', 'chase-alerts.net'),
                   ('Canada Post', 'canadapost.delivery'), ('Instagram', 'instagram-support.help'))
        for display_name, domain in flagged:
            with self.subTest(display_name=display_name, domain=domain):
                self.assertEqual(claim(display_name, domain)[0], 4)
        official = (('Wells Fargo', 'notify.wellsfargo.com'), ('HMRC', 'notifications.service.gov.uk'),
                    ('IRS', 'irs.gov'), ('Social Security', 'ssa.gov'), ('DHL', 'express.dhl.com'), ('DHL', 'mail.dhl'),
                    ('Instagram', 'mail.instagram.com'), ('Facebook', 'facebookmail.com'),
                    ('American Express', 'welcome.aexp.com'), ('Canada Revenue Agency', 'cra-arc.gc.ca'),
                    ('Australian Taxation Office', 'ato.gov.au'), ('Canada Post', 'notifications.canadapost-postescanada.ca'))
        for display_name, domain in official:
            with self.subTest(display_name=display_name, domain=domain):
                self.assertEqual(claim(display_name, domain), (0, []))

    def test_common_names_and_protected_brands_are_not_double_counted(self):
        for display_name in ('Chase Miller', 'Citi Bike', 'The UPS Store', 'Meta Analysis Group'):
            with self.subTest(display_name=display_name):
                self.assertEqual(claim(display_name, 'example.com'), (0, []))
        score, indicators = claim('PayPal Service', 'paypal-help.top')
        self.assertEqual((score, len(indicators)), (4, 1))

    def test_raw_message_impersonating_a_chinese_bank_is_high_risk(self):
        raw = ('From: =?utf-8?b?5Lit5Zu95bel5ZWG6ZO26KGM?= <service@icbc-verify.top>\n'
               'To: user@example.com\nSubject: =?utf-8?b?6LSm5oi35a6J5YWo5o+Q6YaS?=\n\n'
               'Please review your account.\n')
        result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=raw))).body)
        codes = [item.get('code') for item in result['extra_indicators']]
        self.assertIn('structure.brand_display_name', codes)
        self.assertIn(result['risk_level'], {'high', 'critical'})
        genuine = raw.replace('service@icbc-verify.top', 'webmaster@icbc.com.cn')
        result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(raw_email=genuine))).body)
        self.assertNotIn('structure.brand_display_name', [item.get('code') for item in result['extra_indicators']])


if __name__ == '__main__':
    unittest.main()
