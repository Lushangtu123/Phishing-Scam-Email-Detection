"""Slow synchronous analysis must not monopolize the ASGI event loop."""
import asyncio
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from verification_runtime import BoundedExecutor


class AnalysisConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_remains_responsive_during_raw_sender_selection(self):
        started, release = threading.Event(), threading.Event()
        original = app._analyze_sender_address
        def slow_sender(address):
            started.set()
            release.wait(2)
            return original(address)
        raw = ('From: Alice <alice@example.com>\nTo: team@example.com\n'
               'Subject: Project meeting\n\nThe scheduled team meeting is tomorrow afternoon.')
        with patch.object(app, '_analyze_sender_address', slow_sender), \
             patch.object(app, '_rate_limit_buckets', {}), \
             patch.object(app, '_content_pipeline', None):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app),
                                         base_url='http://localhost') as client:
                before = time.monotonic()
                analysis = asyncio.create_task(client.post('/api/analyze-content',
                    json={'raw_email': raw}))
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait, 1))
                    self.assertEqual((await client.get('/health')).status_code, 200)
                    self.assertLess(time.monotonic() - before, 1.0)
                    self.assertFalse(analysis.done())
                finally:
                    release.set()
                    response = await analysis
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['sender_analysis']['email'], 'alice@example.com')

    async def test_full_analysis_pool_returns_retryable_503_and_recovers(self):
        release, started = threading.Event(), threading.Event()
        pool = BoundedExecutor(workers=1)
        def occupied():
            started.set()
            release.wait(3)
        held = pool.submit(occupied)
        self.assertTrue(started.wait(1))
        try:
            with patch.object(app, '_analysis_pool', pool), \
                 patch.object(app, '_rate_limit_buckets', {}), \
                 patch.object(app, '_content_pipeline', None):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app),
                                             base_url='http://localhost') as client:
                    response = await client.post('/api/analyze-content',
                        json={'body': 'Our scheduled project meeting is tomorrow afternoon.'})
                    self.assertEqual(response.status_code, 503)
                    self.assertEqual(response.headers['retry-after'], '1')
                    self.assertEqual((await client.get('/health')).status_code, 200)
                    release.set()
                    await asyncio.wrap_future(held)
                    response = await client.post('/api/analyze-content',
                        json={'body': 'Our scheduled project meeting is tomorrow afternoon.'})
                    self.assertEqual(response.status_code, 200)
        finally:
            release.set()
            await asyncio.wrap_future(held)
            pool.shutdown()

    async def test_health_remains_responsive_while_message_rules_are_running(self):
        started, release = threading.Event(), threading.Event()
        original = app.analyze_email_content
        def slow_rules(*args, **kwargs):
            started.set()
            release.wait(2)
            return original(*args, **kwargs)

        with patch.object(app, 'analyze_email_content', slow_rules), \
             patch.object(app, '_rate_limit_buckets', {}), \
             patch.object(app, '_content_pipeline', None):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app),
                                         base_url='http://localhost') as client:
                before = time.monotonic()
                analysis = asyncio.create_task(client.post('/api/analyze-content',
                    json={'subject': 'Meeting', 'body': 'The project meeting is tomorrow afternoon.'}))
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait, 1))
                    health = await client.get('/health')
                    self.assertEqual(health.status_code, 200)
                    self.assertLess(time.monotonic() - before, 1.0)
                    self.assertFalse(analysis.done())
                finally:
                    release.set()
                    response = await analysis
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(response.json()['risk_level'], {'high', 'critical'})


if __name__ == '__main__':
    unittest.main()
