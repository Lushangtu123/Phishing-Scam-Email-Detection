"""Dedicated limiter configuration and its privacy-preserving Redis contract."""
import asyncio
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from config import load_settings
from rate_limits import build_rate_limit_store
from sender_history import UpstashRateLimitStore


class DistributedRateLimitTests(unittest.TestCase):
    def environment(self, **changes):
        return {'APP_ENV': 'test', 'SENDER_HISTORY_ENABLED': 'false',
                'DISTRIBUTED_RATE_LIMIT_ENABLED': 'true',
                'RATE_LIMIT_REDIS_REST_URL': 'https://test.upstash.io',
                'RATE_LIMIT_REDIS_REST_TOKEN': 'synthetic-token',
                'RATE_LIMIT_HMAC_KEY': 'k' * 32, **changes}

    def build(self, env, **kwargs):
        return build_rate_limit_store(env, load_settings(env), **kwargs)

    def test_dedicated_shared_budget_never_enables_sender_observations(self):
        captured = []
        def opener(request, timeout):
            captured.append((request, timeout))
            return io.BytesIO(b'[{"result":[3,17]}]')
        store = self.build(self.environment(), opener=opener)
        self.assertIsInstance(store, UpstashRateLimitStore)
        self.assertFalse(hasattr(store, 'observe'))
        decision = asyncio.run(store.check_rate_limit('203.0.113.9:/api/analyze-content',
                                                      limit=2, window_seconds=60))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.retry_after, 17)
        request, timeout = captured[0]
        command = json.loads(request.data)[0]
        self.assertEqual(command[0], 'EVAL')
        self.assertTrue(command[3].startswith('rate-limit:v1:'))
        self.assertNotIn('203.0.113.9', request.data.decode())
        self.assertNotIn('analyze-content', request.data.decode())
        self.assertEqual(timeout, 1.0)

    def test_enabled_invalid_configuration_blocks_without_network_or_secrets(self):
        for change in ({'RATE_LIMIT_HMAC_KEY': ''},
                       {'RATE_LIMIT_REDIS_REST_URL': 'https://test.upstash.io.evil.example'},
                       {'RATE_LIMIT_REDIS_REST_URL': 'https://user@test.upstash.io'},
                       {'RATE_LIMIT_TIMEOUT_SECONDS': 'nan'},
                       {'DISTRIBUTED_RATE_LIMIT_ENABLED': 'maybe'}):
            with self.subTest(change=change):
                store = self.build(self.environment(**change))
                self.assertEqual(store.status, 'configuration_error')
                decision = asyncio.run(store.check_rate_limit('client', limit=2, window_seconds=60))
                self.assertFalse(decision.allowed)

    def test_transport_failure_preserves_local_fallback(self):
        def unavailable(*args, **kwargs):
            raise TimeoutError('synthetic-token')
        store = self.build(self.environment(), opener=unavailable)
        self.assertIsNone(asyncio.run(store.check_rate_limit('client', limit=2, window_seconds=60)))

    def test_legacy_history_configuration_preserves_shared_limits(self):
        env = {'APP_ENV': 'test', 'SENDER_HISTORY_ENABLED': 'true',
               'UPSTASH_REDIS_REST_URL': 'https://test.upstash.io',
               'UPSTASH_REDIS_REST_TOKEN': 'synthetic-token',
               'SENDER_HISTORY_HMAC_KEY': 'k' * 32}
        self.assertEqual(self.build(env).status, 'configured')
        env['DISTRIBUTED_RATE_LIMIT_ENABLED'] = 'false'
        self.assertEqual(self.build(env).status, 'disabled')
