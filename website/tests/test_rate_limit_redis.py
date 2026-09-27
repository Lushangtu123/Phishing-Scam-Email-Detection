"""Run the production distributed limiter Lua against CI's isolated Redis.

The synthetic Upstash HTTP adapter only translates the production /pipeline
request into localhost RESP. No external service or credential is contacted.
"""
import asyncio
import io
import json
import os
from pathlib import Path
import sys
import unittest
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import load_settings
from rate_limits import build_rate_limit_store
from sender_history import _rate_limit_key
from test_jev_redis import LocalRedis


@unittest.skipUnless(os.environ.get('PHISHGUARD_TEST_REDIS_PORT'),
                     'Local Redis integration service is not configured')
class DistributedRateLimitRedisTests(unittest.TestCase):
    def setUp(self):
        self.local = LocalRedis('https://synthetic.upstash.io', 'synthetic',
                                'test-rate-limit-' + uuid4().hex)
        self.secret = 'synthetic-rate-limit-secret-' + uuid4().hex
        self.namespace = uuid4().hex
        self.keys = []
        settings = {'APP_ENV': 'test', 'SENDER_HISTORY_ENABLED': 'false',
                    'DISTRIBUTED_RATE_LIMIT_ENABLED': 'true',
                    'RATE_LIMIT_REDIS_REST_URL': 'https://test.upstash.io',
                    'RATE_LIMIT_REDIS_REST_TOKEN': 'synthetic-token',
                    'RATE_LIMIT_HMAC_KEY': self.secret}
        self.shared = build_rate_limit_store(settings, load_settings(settings),
                                             opener=self.local_pipeline)
        self.assertEqual(self.shared.status, 'configured')

    def tearDown(self):
        if self.keys:
            self.local.execute('DEL', *self.keys)

    def identity(self, route):
        identity = self.namespace + ':' + route
        self.keys.append(_rate_limit_key(identity, self.secret))
        return identity

    def local_pipeline(self, request, timeout):
        self.assertEqual(request.full_url, 'https://test.upstash.io/pipeline')
        self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
        self.assertLessEqual(timeout, 3.0)
        commands = json.loads(request.data)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0], 'EVAL')
        self.assertNotIn(self.namespace, request.data.decode())
        result = self.local.execute(*commands[0])
        return io.BytesIO(json.dumps([{'result': result}]).encode())

    def test_real_lua_atomic_budget_expiry_and_independent_routes(self):
        minute = self.identity('/api/analyze-email')
        hour = self.identity('/api/feedback:feedback')

        async def burst():
            return await asyncio.gather(*(self.shared.check_rate_limit(
                minute, limit=3, window_seconds=60) for _ in range(12)))

        decisions = asyncio.run(burst())
        self.assertTrue(all(decision is not None for decision in decisions))
        self.assertEqual(sum(decision.allowed for decision in decisions), 3)
        self.assertEqual(sum(not decision.allowed for decision in decisions), 9)
        self.assertTrue(all(1 <= decision.retry_after <= 60 for decision in decisions
                            if not decision.allowed))
        minute_key, hour_key = self.keys
        self.assertEqual(self.local.execute('GET', minute_key), '12')
        before = self.local.execute('PTTL', minute_key)
        self.assertTrue(0 < before <= 60000)

        hour_decisions = [asyncio.run(self.shared.check_rate_limit(
            hour, limit=5, window_seconds=3600)) for _ in range(6)]
        self.assertEqual([decision.allowed for decision in hour_decisions],
                         [True] * 5 + [False])
        self.assertTrue(0 < self.local.execute('TTL', hour_key) <= 3600)
        self.assertEqual(self.local.execute('GET', hour_key), '6')
        self.assertEqual(self.local.execute('GET', minute_key), '12')

        retry = asyncio.run(self.shared.check_rate_limit(minute, limit=3,
                                                          window_seconds=60))
        self.assertFalse(retry.allowed)
        self.assertLessEqual(self.local.execute('PTTL', minute_key), before)

        other = self.identity('/api/analyze-content')
        self.assertTrue(asyncio.run(self.shared.check_rate_limit(
            other, limit=3, window_seconds=60)).allowed)
        self.assertEqual(self.local.execute('GET', self.keys[-1]), '1')
