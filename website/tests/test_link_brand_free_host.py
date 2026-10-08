"""Links to a site on a free hosting service named after a registered organization (synthetic inputs)."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import email_structure as es  # noqa: E402


def link_findings(url):
    score, findings, floor = app._analyze_link_destinations(f'<a href="{url}">Open</a>')
    return score, [item for item in findings if item['rule_id'] == 'link.brand_on_free_host'], floor


class BrandOnFreeHostTests(unittest.TestCase):
    def test_sites_named_after_an_organization(self):
        # The first three are hosts from 2023-24 phishing (Nazario) and PhishNChips.
        for url, brand, service in (
                ('https://s-wellsfargo-online.cyclic.app/login', 'Wells Fargo', 'cyclic.app'),
                ('https://docusign2494816330289u1outlook9957422344.glitch.me/', 'Docusign', 'glitch.me'),
                ('https://www.netflix-gamma-orpin.vercel.app/', 'Netflix', 'vercel.app'),
                ('https://we11sfarg0-login.netlify.app/', 'Wells Fargo', 'netlify.app'),
                ('https://icbc-zhuanzhang.pages.dev/', '中国工商银行', 'pages.dev'),
                ('https://12306-tuipiao.workers.dev/refund', '中国铁路 12306', 'workers.dev')):
            with self.subTest(url=url):
                _score, findings, _floor = link_findings(url)
                self.assertEqual([(item['params']['brand'], item['params']['service']) for item in findings],
                                 [(brand, service)])

    def test_supporting_evidence_without_a_floor(self):
        # A tool named after a platform is ordinary in developers' mail, so the finding alone
        # stays below an alert: 4 points and no risk floor.
        score, findings, floor = link_findings('https://youtube-summarizer.vercel.app/')
        self.assertEqual((score, len(findings), floor), (4, 1, 'safe'))

    def test_other_sites_are_not_flagged(self):
        for url in (
                'https://netflix-clone-abc.vercel.app/',      # a developer's practice copy
                'https://delta-dashboard.vercel.app/',        # a common word
                'https://purchase-portal.netlify.app/',       # "chase" inside another word
                'https://mybakery.wixsite.com/home',          # no organization named
                'https://pub-0a8952aeed314c3e88b3319fff3a5ae5.r2.dev/index.html',
                'https://netflix.github.io/',                 # code hosts are left out
                'https://googleblog.blogspot.com/',           # blog hosts are left out
                'https://wellsfargo.com/', 'https://s-wellsfargo-online.example.com/'):
            with self.subTest(url=url):
                self.assertEqual(link_findings(url)[1], [])

    def test_labels_come_from_distinctive_registry_names(self):
        labels = es.BRAND_SITE_LABELS
        self.assertEqual(labels['wellsfargo'], 'Wells Fargo')
        self.assertEqual(labels['ctrip'], '携程旅行')
        # Common words, the five protected brands (link.brand_lookalike covers them),
        # services that only verify their own mail, and shared-service subdomains.
        for label in ('delta', 'canada', 'trip', 'meta', 'paypal', 'google', 'slack', 'target', 'discoursemail'):
            with self.subTest(label=label):
                self.assertNotIn(label, labels)

    def test_one_finding_per_message(self):
        text = ('<a href="https://wellsfargo-a.glitch.me/">One</a> '
                '<a href="https://wellsfargo-b.glitch.me/">Two</a>')
        _score, findings, _floor = app._analyze_link_destinations(text)
        self.assertEqual(sum(item['rule_id'] == 'link.brand_on_free_host' for item in findings), 1)


if __name__ == '__main__':
    unittest.main()
