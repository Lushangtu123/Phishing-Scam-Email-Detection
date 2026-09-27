"""A bounded limiter must preserve live limits under untrusted key churn."""
from collections import deque
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from sender_history import DisabledSenderHistoryStore, RateLimitDecision


class RateLimitSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_distributed_limit_is_enforced_with_sender_history_disabled(self):
        class BlockedLimiter:
            async def check_rate_limit(self, identity, *, limit, window_seconds):
                return RateLimitDecision(allowed=False, retry_after=17)

        with patch.object(app, '_rate_limit_buckets', {}), \
             patch.object(app, '_sender_history_store', DisabledSenderHistoryStore()), \
             patch.object(app, '_rate_limit_store', BlockedLimiter(), create=True):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app),
                                         base_url='http://localhost') as client:
                response = await client.post('/api/analyze-email',
                                             json={'email': 'alice@gmail.com'})
                self.assertEqual(response.status_code, 429)
                self.assertEqual(response.headers['retry-after'], '17')

    async def test_unknown_api_paths_cannot_reset_an_exhausted_analysis_limit(self):
        with patch.object(app, '_rate_limit_buckets', {}), \
             patch.object(app, 'RATE_LIMIT_PER_MINUTE', 2), \
             patch.object(app, 'RATE_LIMIT_BUCKET_CAPACITY', 4):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app),
                                         base_url='http://localhost') as client:
                for _ in range(2):
                    self.assertEqual((await client.post('/api/analyze-email',
                        json={'email': 'alice@gmail.com'})).status_code, 200)
                self.assertEqual((await client.post('/api/analyze-email',
                    json={'email': 'alice@gmail.com'})).status_code, 429)
                for index in range(10):
                    await client.post(f'/api/nonexistent-{index}', json={})
                response = await client.post('/api/analyze-email',
                                             json={'email': 'alice@gmail.com'})
                self.assertEqual(response.status_code, 429)
                self.assertIn('retry-after', response.headers)
                self.assertLessEqual(len(app._rate_limit_buckets), 4)

    async def test_capacity_pressure_keeps_existing_limits_and_releases_expired_slots(self):
        buckets = {'first': deque([10.0, 11.0]), 'second': deque([20.0])}
        self.assertFalse(app._record_rate_limit_hit('third', now=30, buckets=buckets,
            limit=2, capacity=2, window_seconds=60))
        self.assertEqual(set(buckets), {'first', 'second'})
        self.assertFalse(app._record_rate_limit_hit('first', now=31, buckets=buckets,
            limit=2, capacity=2, window_seconds=60))
        self.assertTrue(app._record_rate_limit_hit('second', now=32, buckets=buckets,
            limit=2, capacity=2, window_seconds=60))
        self.assertTrue(app._record_rate_limit_hit('third', now=72, buckets=buckets,
            limit=2, capacity=2, window_seconds=60))
        self.assertNotIn('first', buckets)

    async def test_minute_requests_cannot_expire_the_hourly_feedback_budget(self):
        buckets = {}
        feedback = '203.0.113.9:/api/feedback:feedback'
        for instant in range(5):
            self.assertTrue(app._record_rate_limit_hit(feedback, now=instant,
                buckets=buckets, limit=5, capacity=16, window_seconds=3600))
        self.assertFalse(app._record_rate_limit_hit(feedback, now=5,
            buckets=buckets, limit=5, capacity=16, window_seconds=3600))
        self.assertTrue(app._record_rate_limit_hit('203.0.113.9:/api/analyze-email', now=65,
            buckets=buckets, limit=10, capacity=16, window_seconds=60))
        self.assertFalse(app._record_rate_limit_hit(feedback, now=66,
            buckets=buckets, limit=5, capacity=16, window_seconds=3600))
        self.assertTrue(app._record_rate_limit_hit(feedback, now=3605,
            buckets=buckets, limit=5, capacity=16, window_seconds=3600))

    async def test_hourly_feedback_limit_survives_minute_requests_at_the_api(self):
        clock = [0.0]
        with patch.object(app, '_rate_limit_buckets', {}), \
             patch.object(app, 'RATE_LIMIT_PER_MINUTE', 20), \
             patch.object(app, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app),
                                         base_url='http://localhost') as client:
                # Validation failures still consume the public request budget;
                # no real feedback is saved by this local abuse control.
                for _ in range(5):
                    self.assertEqual((await client.post('/api/feedback', json={})).status_code, 422)
                self.assertEqual((await client.post('/api/feedback', json={})).status_code, 429)
                clock[0] = 61.0
                self.assertEqual((await client.post('/api/analyze-email',
                    json={'email': 'alice@gmail.com'})).status_code, 200)
                self.assertEqual((await client.post('/api/feedback', json={})).status_code, 429)
                clock[0] = 3601.0
                self.assertEqual((await client.post('/api/feedback', json={})).status_code, 422)

    async def test_case_ids_and_unknown_routes_share_bounded_route_groups(self):
        def key(path):
            return app._rate_limit_key(app.Request({'type': 'http', 'method': 'POST',
                'path': path, 'headers': [], 'client': ('203.0.113.9', 1),
                'server': ('localhost', 80), 'scheme': 'http', 'query_string': b''}))
        self.assertEqual(key('/api/cases/one/auxiliary'), key('/api/cases/two/auxiliary'))
        self.assertEqual(key('/api/unrecognized-one'), key('/api/unrecognized-two'))
        self.assertNotEqual(key('/api/analyze-content'), key('/api/feedback'))


if __name__ == '__main__':
    unittest.main()
