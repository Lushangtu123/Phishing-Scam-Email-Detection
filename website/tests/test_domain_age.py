"""Domain registration dates from RDAP: bootstrap, lookups, what is asked, and what is
reported (fake fetchers only; no network)."""
import asyncio
import dataclasses
import json
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(WEBSITE_DIR / 'tools'))

import app  # noqa: E402

import content_rules  # noqa: E402
import config  # noqa: E402
import domain_age  # noqa: E402
import email_structure as es  # noqa: E402
import update_rdap_bootstrap  # noqa: E402

SERVERS = {'com': 'https://rdap.example-registry.net/com/v1/', 'uk': 'https://rdap.example-registry.net/uk/'}
NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def record(registered: str) -> dict:
    return {'objectClassName': 'domain', 'events': [{'eventAction': 'last changed', 'eventDate': '2026-09-01T00:00:00Z'},
                                                     {'eventAction': 'registration', 'eventDate': registered}]}


class Fetcher:
    def __init__(self, records=None, delay=0.0):
        self.records, self.delay, self.urls = records or {}, delay, []

    def __call__(self, url, timeout):
        self.urls.append(url)
        if self.delay:
            time.sleep(self.delay)
        domain = url.rpartition('/')[2]
        if domain not in self.records:
            raise OSError('not found')
        return self.records[domain]


class LookupTests(unittest.TestCase):
    def setUp(self):
        domain_age._cache.clear()

    def test_the_checked_in_bootstrap(self):
        self.assertTrue(domain_age.rdap_base('example.com').startswith('https://'))
        self.assertTrue(domain_age.rdap_base('example.co.uk').startswith('https://'))
        # Many country domains publish no RDAP service; those dates stay unknown.
        self.assertIsNone(domain_age.rdap_base('example.cn'))

    def test_a_lookup_asks_the_tlds_registry_once(self):
        fetch = Fetcher({'new-login.com': record('2026-09-28T10:00:00Z')})
        for _ in range(2):
            date = domain_age.lookup('New-Login.com', fetch=fetch, servers=SERVERS)
        self.assertEqual(date, datetime(2026, 9, 28, 10, tzinfo=timezone.utc))
        self.assertEqual(fetch.urls, ['https://rdap.example-registry.net/com/v1/domain/new-login.com'])

    def test_unknown_dates(self):
        fetch = Fetcher()
        self.assertIsNone(domain_age.lookup('missing.com', fetch=fetch, servers=SERVERS))
        self.assertIsNone(domain_age.lookup('example.cn', fetch=fetch, servers=SERVERS))  # no RDAP server
        self.assertIsNone(domain_age.lookup('not a domain', fetch=fetch, servers=SERVERS))
        self.assertEqual(fetch.urls, ['https://rdap.example-registry.net/com/v1/domain/missing.com'])
        self.assertIsNone(domain_age.registration_date({'events': [{'eventAction': 'registration', 'eventDate': 'x'}]}))

    def test_the_deadline(self):
        slow = Fetcher({'slow.com': record('2026-09-28T10:00:00Z')}, delay=0.5)
        fast = Fetcher({'fast.com': record('2020-01-01T00:00:00Z')})
        self.assertEqual(domain_age.lookup_many(['slow.com'], fetch=slow, servers=SERVERS, deadline=0.05), {'slow.com': None})
        result = asyncio.run(domain_age.lookup_many_async(['fast.com', 'fast.com'], fetch=fast, servers=SERVERS))
        self.assertEqual(result, {'fast.com': datetime(2020, 1, 1, tzinfo=timezone.utc)})

    def test_redirects_stay_on_https(self):
        handler = domain_age._HttpsOnly()
        self.assertIsNone(handler.redirect_request(None, None, 302, 'Found', {}, 'http://rdap.example.net/domain/x.com'))


class CandidateTests(unittest.TestCase):
    def test_what_is_asked(self):
        hosts = ['login.secure-verify.com', 'www.paypal.com', 'mail.google.com', 'alice.github.io', '93.184.216.34',
                 'drive.google.com', 'cdn.secure-verify.com', 'a.one.net', 'b.two.net', 'c.three.net', 'd.four.net']
        self.assertEqual(content_rules._registration_candidates('Billing <billing@notice-center.co.uk>', hosts),
                         [('sender', 'notice-center.co.uk'), ('link', 'secure-verify.com'), ('link', 'one.net'),
                          ('link', 'two.net'), ('link', 'three.net')])
        # A consumer mailbox or an official sender is not asked about.
        self.assertEqual(content_rules._registration_candidates('A <a@gmail.com>', []), [])
        self.assertEqual(content_rules._registration_candidates('PayPal <service@paypal.com>', []), [])

    def test_what_is_reported(self):
        candidates = [('sender', 'new-sender.com'), ('link', 'new-link.com'), ('link', 'old-link.com'), ('link', 'unknown.com')]
        dates = {'new-sender.com': NOW - timedelta(days=3), 'new-link.com': NOW - timedelta(days=89),
                 'old-link.com': NOW - timedelta(days=400), 'unknown.com': None}
        findings = content_rules._registration_findings(candidates, dates, now=NOW)
        self.assertEqual([(item['code'], item['params']) for item in findings], [
            ('sender.recently_registered', {'domain': 'new-sender.com', 'date': '2026-09-29', 'days': 3}),
            ('link.recently_registered', {'domain': 'new-link.com', 'date': '2026-07-05', 'days': 89})])
        self.assertTrue(all(item['level'] == 'info' for item in findings))


def analyze_eml(raw: bytes, enabled: bool, dates=None):
    async def fake_lookups(domains):
        fake_lookups.asked = list(domains)
        return {domain: (dates or {}).get(domain) for domain in domains}
    fake_lookups.asked = None
    settings = dataclasses.replace(app.SETTINGS, rdap_lookups_enabled=enabled)
    with patch.object(app, '_content_pipeline', None), patch.object(app, 'SETTINGS', settings), \
            patch.object(domain_age, 'lookup_many_async', fake_lookups):
        result = json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                             observe_sender_history=False)).body)
    return result, fake_lookups.asked


RAW = ('From: Account Team <alerts@notice-center.com>\r\nTo: user@example.org\r\nSubject: Account notice\r\n'
       'Content-Type: text/html; charset=utf-8\r\n\r\n'
       '<p>Please review your account.</p><a href="https://login.secure-verify.com/x">Review</a>').encode()


class AnalysisTests(unittest.TestCase):
    def test_off_by_default(self):
        self.assertFalse(config.load_settings({}).rdap_lookups_enabled)
        self.assertTrue(config.load_settings({'RDAP_LOOKUPS': 'true'}).rdap_lookups_enabled)
        result, asked = analyze_eml(RAW, enabled=False)
        self.assertIsNone(asked)
        self.assertNotIn('link_hosts', result)
        self.assertNotIn('domain_registrations', result)

    def test_enabled(self):
        recent = datetime.now(timezone.utc) - timedelta(days=5)
        result, asked = analyze_eml(RAW, enabled=True, dates={'secure-verify.com': recent})
        self.assertEqual(asked, ['notice-center.com', 'secure-verify.com'])
        self.assertEqual(result['domain_registrations'], {'notice-center.com': None,
                                                          'secure-verify.com': recent.date().isoformat()})
        codes = {item.get('code') for item in result['extra_indicators']}
        self.assertIn('link.recently_registered', codes)
        self.assertNotIn('link_hosts', result)


class BootstrapToolTests(unittest.TestCase):
    def test_build(self):
        services = [[[f'tld{index}'], [f'https://rdap.example.net/{index}/']] for index in range(120)]
        services.append([['plain'], ['http://insecure.example.net/']])

        class Response:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, limit):
                return self.body
        body = json.dumps({'publication': '2026-09-30T23:00:03Z', 'services': services}).encode()
        built = update_rdap_bootstrap.build(lambda request, timeout: Response(body))
        self.assertEqual(len(built['services']), 120)  # the http-only service is dropped
        domain_age.validate_bootstrap(built)


if __name__ == '__main__':
    unittest.main()
