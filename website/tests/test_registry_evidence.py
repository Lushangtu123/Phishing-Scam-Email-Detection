"""Every official domain in the brand registries needs recorded evidence (docs/official-registry.md).

A trusted DMARC pass on an official domain makes a verified official sender, which the text
model and weak rules alone cannot raise above Low, so a domain nobody checked is an unexamined
trust anchor. Evidence here is any of: `domain_sources` on the entry, a `verified_statements`
page on the domain, or an official contact address there. PENDING lists the domains recorded
before evidence was required (2026-10-05); it may only shrink.
"""
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import email_structure as es  # noqa: E402

REGISTRIES = {'intl': WEBSITE_DIR / 'data' / 'official_brands_intl.json',
              'cn': WEBSITE_DIR / 'data' / 'official_brands_cn.json'}

# (registry, entry id) -> official domains without recorded evidence, as of 2026-10-05.
PENDING = {
    ('intl', 'usps'): {'usps.com'},
    ('intl', 'ups'): {'theupsstore.com'},
    ('intl', 'dhl'): {'dpdhl.com', 'dhl-news.com', 'dhl.de', 'dhl.fr', 'dhl.ae', 'dhl'},
    ('intl', 'apple'): {'icloud.com'},
    ('intl', 'meta'): {'fb.com', 'facebookmail.com', 'instagram.com', 'meta.com', 'metamail.com'},
    ('intl', 'chase'): {'jpmorganchase.com'},
    ('intl', 'wells_fargo'): {'wf.com'},
    ('intl', 'citi'): {'citibank.com'},
    ('intl', 'american_express'): {'aexp.com', 'americanexpress.co.uk', 'aexpfeedback.com'},
    ('intl', 'cash_app'): {'square.com', 'squareup.com'},
    ('intl', 'zelle'): {'zelle.com', 'zellepay.com'},
    ('intl', 'docusign'): {'docusign.com', 'docusign.net'},
    ('intl', 'cra'): {'cra-arc.gc.ca'},
    ('intl', 'canada_post'): {'canadapost.ca'},
    ('intl', 'ato'): {'my.gov.au'},
    ('intl', 'hsbc'): {'hsbc.com', 'hsbc.co.uk', 'hsbc.com.hk'},
    ('intl', 'barclays'): {'barclays.co.uk', 'barclays.com'},
    ('intl', 'metamask'): {'metamask.discoursemail.com', 'cl-cards.com'},
    ('cn', 'ccb'): {'ccb.cn', 'ccb.com.cn'},
    ('cn', 'abc'): {'abchina.com', 'abchina.com.cn'},
    ('cn', 'boc'): {'bankofchina.com'},
    ('cn', 'psbc'): {'psbc.com'},
    ('cn', 'spdb'): {'spdb.com.cn'},
    ('cn', 'citic'): {'citicbank.com', 'ecitic.com'},
    ('cn', 'cmbc'): {'cmbc.com.cn'},
    ('cn', 'alipay'): {'alipay.com'},
    ('cn', 'wechat_pay'): {'wechatpay.cn', 'tenpay.com', 'weixin.qq.com'},
    ('cn', 'unionpay'): {'unionpay.com'},
    ('cn', 'china_mobile'): {'10086.cn', 'chinamobile.com'},
    ('cn', 'china_unicom'): {'10010.com', 'chinaunicom.com'},
    ('cn', 'china_telecom'): {'189.cn', 'chinatelecom.com.cn'},
    ('cn', 'sf_express'): {'sf-express.com'},
    ('cn', 'china_post'): {'chinapost.com.cn', 'ems.com.cn'},
    ('cn', 'jd'): {'jdl.com'},
    ('cn', 'zto'): {'zto.com'},
    ('cn', 'yto'): {'yto.net.cn'},
    ('cn', 'yunda'): {'yundaex.com'},
    ('cn', 'sto'): {'sto.cn'},
    ('cn', 'taobao'): {'taobao.com', 'tmall.com'},
    ('cn', 'pinduoduo'): {'pinduoduo.com', 'yangkeduo.com'},
    ('cn', 'tencent'): {'weixin.qq.com', 'tencent.com'},
    ('cn', 'social_security'): {'12333.gov.cn', 'mohrss.gov.cn'},
    ('cn', 'traffic_12123'): {'122.gov.cn'},
    ('cn', 'police_procuratorate_courts'): {'mps.gov.cn'},
    ('cn', 'customs'): {'customs.gov.cn'},
    ('cn', 'china_eastern'): {'ceair.com'},
    ('cn', 'air_china'): {'airchina.com.cn'},
    ('cn', 'chsi'): {'chsi.com.cn'},
}


def _on(host, domain):
    host = (host or '').lower().rstrip('.')
    return host == domain or host.endswith('.' + domain)


def unsourced_domains():
    found = {}
    for registry, path in REGISTRIES.items():
        for brand in json.loads(path.read_text(encoding='utf-8'))['brands']:
            if brand.get('domain_sources'):
                continue
            hosts = [urlsplit(statement['source']).hostname for statement in brand['verified_statements']]
            mailboxes = [address.rpartition('@')[2].lower() for address in brand.get('official_contact_emails', [])]
            for domain in (*brand['official_domains'], *brand.get('brand_tlds', ())):
                domain = es.normalize_domain(domain)
                if not any(_on(host, domain) for host in (*hosts, *mailboxes)):
                    found.setdefault((registry, brand['id']), set()).add(domain)
    return found


class RegistryEvidenceTests(unittest.TestCase):
    def test_official_domains_have_recorded_evidence(self):
        # A new unsourced domain fails here, and so does a confirmed one left on the list.
        self.assertEqual(unsourced_domains(), PENDING)

    def test_domain_sources_are_https_pages(self):
        for path in REGISTRIES.values():
            for brand in json.loads(path.read_text(encoding='utf-8'))['brands']:
                for url in brand.get('domain_sources', ()):
                    with self.subTest(brand=brand['id'], url=url):
                        parts = urlsplit(url)
                        self.assertEqual(parts.scheme, 'https')
                        self.assertTrue(parts.hostname)

    def test_the_pending_list_counts_seventy_nine_domains(self):
        self.assertEqual(sum(len(domains) for domains in PENDING.values()), 79)


if __name__ == '__main__':
    unittest.main()
