"""POST /api/analyze-sms: the flag, validation, the response and link-domain ages (synthetic texts)."""
import asyncio
import dataclasses
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import http_policy  # noqa: E402
from config import load_settings  # noqa: E402

PARCEL = ('USPS: Your package could not be delivered due to an incomplete address. '
          'Update your address at usps-redelivery.top/a')


def post(path, payload=None, method='post'):
    async def send():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url='http://localhost') as client:
            return await getattr(client, method)(path, **({'json': payload} if payload is not None else {}))
    return asyncio.run(send())


def settings(**changes):
    return dataclasses.replace(app.SETTINGS, **changes)


class SmsEndpointTests(unittest.TestCase):
    def setUp(self):
        app._rate_limit_buckets.clear()

    def test_off_by_default(self):
        self.assertFalse(load_settings({'APP_ENV': 'production'}).sms_analysis_enabled)
        self.assertTrue(load_settings({'APP_ENV': 'production', 'SMS_ANALYSIS_ENABLED': 'true'}).sms_analysis_enabled)
        with patch.object(app, 'SETTINGS', settings(sms_analysis_enabled=False)):
            self.assertEqual(post('/api/analyze-sms', {'text': PARCEL}).status_code, 404)
            self.assertIs(post('/api/config', method='get').json()['sms_analysis_enabled'], False)
        with patch.object(app, 'SETTINGS', settings(sms_analysis_enabled=True)):
            self.assertIs(post('/api/config', method='get').json()['sms_analysis_enabled'], True)

    def test_validation(self):
        with patch.object(app, 'SETTINGS', settings(sms_analysis_enabled=True, rdap_lookups_enabled=False)):
            self.assertEqual(post('/api/analyze-sms', {'sender': '95588', 'text': '  '}).status_code, 400)
            self.assertEqual(post('/api/analyze-sms', {'text': 'x' * 2001}).status_code, 422)
            self.assertEqual(post('/api/analyze-sms', {'sender': '1' * 65, 'text': 'hello'}).status_code, 422)
            self.assertEqual(post('/api/analyze-sms', {'text': 'See you at lunch.'}).status_code, 200)

    def test_response(self):
        with patch.object(app, 'SETTINGS', settings(sms_analysis_enabled=True, rdap_lookups_enabled=False)):
            body = post('/api/analyze-sms', {'sender': 'toll@example.com', 'text': PARCEL}).json()
        self.assertEqual((body['sender_kind'], body['claimed_brand']), ('email', 'United States Postal Service'))
        self.assertIn(body['risk_level'], {'high', 'critical'})
        found = {item['code']: item for item in body['extra_indicators']}
        self.assertIn('sms.sender_mismatch', found)
        self.assertEqual(found['sms.delivery_lure']['params'], {'host': 'usps-redelivery.top'})
        self.assertNotIn('link_hosts', body)
        self.assertNotIn('domain_registrations', body)
        # The sender itself is never echoed.
        self.assertNotIn('toll@example.com', str(body))

    def test_link_domain_ages(self):
        recent = datetime.now(timezone.utc) - timedelta(days=3)
        lookup = AsyncMock(return_value={'usps-redelivery.top': recent})
        with patch.object(app, 'SETTINGS', settings(sms_analysis_enabled=True, rdap_lookups_enabled=True)), \
                patch.object(app.domain_age, 'lookup_many_async', lookup):
            body = post('/api/analyze-sms', {'text': PARCEL}).json()
        lookup.assert_awaited_once_with(['usps-redelivery.top'])
        self.assertEqual(body['domain_registrations'], {'usps-redelivery.top': recent.date().isoformat()})
        self.assertIn('link.recently_registered', [item['code'] for item in body['extra_indicators']])

    def test_rate_and_size_limits_cover_the_endpoint(self):
        self.assertIn('/api/analyze-sms', http_policy._RATE_LIMIT_PATHS)


if __name__ == '__main__':
    unittest.main()
