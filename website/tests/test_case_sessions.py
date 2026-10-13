"""Case workspace sessions: the access token only signs in; sessions expire, end at sign-out
and end when the analyst's credential changes (ASVS 7.2.2, 7.2.4, 7.3.1, 7.3.2, 7.4.1)."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from uuid import uuid4

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
from case_api import build_case_service  # noqa: E402
from case_sessions import ABSOLUTE_SECONDS, IDLE_SECONDS, CaseSessions, session_digest  # noqa: E402
from case_store import CaseStore  # noqa: E402
from test_case_api import TOKEN, _send  # noqa: E402
from test_jev_redis import LocalRedis  # noqa: E402

OTHER = 'synthetic-bob-token-with-at-least-32-characters-x'


class Clock:
    def __init__(self, now=1_790_000_000):
        self.now = now

    def __call__(self):
        return self.now


class CaseSessionApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'cases.sqlite3'
        self.env = {'CASE_MANAGEMENT_ENABLED': 'true', 'CASE_DB_PATH': str(self.path),
                    'CASE_ANALYST_TOKEN_HASHES': json.dumps({'alice': hashlib.sha256(TOKEN.encode()).hexdigest(),
                                                             'bob': hashlib.sha256(OTHER.encode()).hexdigest()})}
        self.previous = getattr(app.app.state, 'case_service', None)
        self.previous_error = getattr(app.app.state, 'case_configuration_error', False)
        app.app.state.case_configuration_error = False
        self.service = app.app.state.case_service = build_case_service(self.env)
        self.clock = Clock()
        self.service.sessions = CaseSessions(self.service.store, clock=self.clock)
        app._rate_limit_buckets.clear()

    def tearDown(self):
        app.app.state.case_service = self.previous
        app.app.state.case_configuration_error = self.previous_error
        self.temp.cleanup()

    def call(self, method, path, token):
        return asyncio.run(_send(method, path, token=token))

    def sign_in(self, token=TOKEN):
        status, body, _ = self.call('POST', '/api/cases/session', token)
        self.assertEqual(status, 201, body)
        return body

    def test_the_access_token_signs_in_and_is_not_a_session(self):
        opened = self.sign_in()
        self.assertEqual((opened['actor'], opened['idle_seconds']), ('alice', IDLE_SECONDS))
        self.assertEqual(opened['expires_at'], self.clock.now + ABSOLUTE_SECONDS)
        self.assertNotEqual(opened['session'], TOKEN)
        status, me, _ = self.call('GET', '/api/cases/me', opened['session'])
        self.assertEqual((status, me['actor']), (200, 'alice'))
        status, body, headers = self.call('GET', '/api/cases/me', TOKEN)
        self.assertEqual(status, 401)
        self.assertIn('session has ended', body['detail'])
        self.assertEqual(headers[b'www-authenticate'], b'Bearer')

    def test_a_wrong_access_token_cannot_sign_in(self):
        status, body, _ = self.call('POST', '/api/cases/session', 'wrong-token-that-is-long-enough-to-check-00')
        self.assertEqual(status, 401)
        self.assertIn('valid analyst access token', body['detail'])
        self.assertEqual(self.call('POST', '/api/cases/session', None)[0], 401)

    def test_sign_out_revokes_the_session_on_the_server(self):
        session = self.sign_in()['session']
        self.assertEqual(self.call('GET', '/api/cases/me', session)[0], 200)
        self.assertEqual(self.call('DELETE', '/api/cases/session', session)[0], 204)
        self.assertEqual(self.call('GET', '/api/cases/me', session)[0], 401)
        self.assertEqual(self.call('DELETE', '/api/cases/session', session)[0], 204)  # already ended

    def test_each_sign_in_is_its_own_session(self):
        first, second = self.sign_in()['session'], self.sign_in()['session']
        self.assertNotEqual(first, second)
        self.call('DELETE', '/api/cases/session', first)
        self.assertEqual(self.call('GET', '/api/cases/me', first)[0], 401)
        self.assertEqual(self.call('GET', '/api/cases/me', second)[0], 200)

    def test_idle_sessions_end_and_activity_keeps_them(self):
        session = self.sign_in()['session']
        self.clock.now += IDLE_SECONDS - 1
        self.assertEqual(self.call('GET', '/api/cases/me', session)[0], 200)
        self.clock.now += IDLE_SECONDS - 1
        self.assertEqual(self.call('GET', '/api/cases/me', session)[0], 200)
        self.clock.now += IDLE_SECONDS
        self.assertEqual(self.call('GET', '/api/cases/me', session)[0], 401)

    def test_active_sessions_still_end_after_eight_hours(self):
        session = self.sign_in()['session']
        for _ in range(ABSOLUTE_SECONDS // 600 - 1):
            self.clock.now += 600
            self.assertEqual(self.call('GET', '/api/cases/me', session)[0], 200)
        self.clock.now += 600
        self.assertEqual(self.call('GET', '/api/cases/me', session)[0], 401)

    def test_replacing_or_removing_a_credential_ends_its_sessions(self):
        alice, bob = self.sign_in()['session'], self.sign_in(OTHER)['session']
        self.service.analysts = {**self.service.analysts, 'alice': hashlib.sha256(b'a-new-token-for-alice-0123456789').hexdigest()}
        self.assertEqual(self.call('GET', '/api/cases/me', alice)[0], 401)
        self.assertEqual(self.call('GET', '/api/cases/me', bob)[0], 200)
        self.service.analysts = {'alice': self.service.analysts['alice']}
        self.assertEqual(self.call('GET', '/api/cases/me', bob)[0], 401)

    def test_only_digests_of_session_ids_are_stored(self):
        session = self.sign_in()['session']
        stored = self.path.read_bytes()
        self.assertNotIn(session.encode(), stored)
        self.assertNotIn(TOKEN.encode(), stored)
        self.assertIn(session_digest(session).encode(), stored)

    def test_case_requests_need_a_session(self):
        self.assertEqual(self.call('GET', '/api/cases', None)[0], 401)
        self.assertEqual(self.call('GET', '/api/cases', 'x' * 43)[0], 401)
        session = self.sign_in()['session']
        self.assertEqual(self.call('GET', '/api/cases', session)[0], 200)


class CaseSessionStoreTests(unittest.TestCase):
    def test_sessions_of_another_environment_are_not_valid_here(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / 'cases.sqlite3')
            preview, production = CaseSessions(store, 'preview'), CaseSessions(store, 'production')
            session = preview.open('alice', 'a' * 64)['session']
            self.assertIsNone(production.resume(session))
            self.assertEqual(preview.resume(session)['actor'], 'alice')

    def test_malformed_session_ids_are_never_looked_up(self):
        with tempfile.TemporaryDirectory() as directory:
            sessions = CaseSessions(CaseStore(Path(directory) / 'cases.sqlite3'))
            for value in ('', 'short', 'x' * 44, 'a' * 42 + '!', TOKEN):
                self.assertIsNone(sessions.resume(value))
                sessions.close(value)


@unittest.skipUnless(os.environ.get('PHISHGUARD_TEST_REDIS_PORT'), 'Local Redis integration service is not configured')
class CaseSessionRedisTests(unittest.TestCase):
    """The production Lua, against an isolated local Redis (CI)."""

    def setUp(self):
        self.store = LocalRedis('https://synthetic.upstash.io', 'synthetic', 'test-sessions-' + uuid4().hex)
        self.sessions = CaseSessions(self.store, 'preview')

    def tearDown(self):
        keys = self.store.execute('KEYS', self.sessions.prefix + '*') or []
        if keys:
            self.store.execute('DEL', *keys)

    def key(self, session):
        return self.sessions.prefix + session_digest(session)

    def test_sessions_open_resume_and_close_with_an_idle_expiry(self):
        opened = self.sessions.open('alice', 'a' * 64)
        session = opened['session']
        self.assertEqual(self.sessions.resume(session), {'actor': 'alice', 'credential': 'a' * 64})
        self.assertTrue(0 < self.store.execute('TTL', self.key(session)) <= IDLE_SECONDS)
        self.sessions.close(session)
        self.assertIsNone(self.sessions.resume(session))

    def test_the_absolute_limit_holds_on_the_server_clock(self):
        session = self.sessions.open('alice', 'a' * 64)['session']
        stored = json.loads(self.store.execute('GET', self.key(session)))
        stored['created_at'] -= ABSOLUTE_SECONDS
        self.store.execute('SET', self.key(session), json.dumps(stored), 'EX', IDLE_SECONDS)
        self.assertIsNone(self.sessions.resume(session))
        self.assertIsNone(self.store.execute('GET', self.key(session)))

    def test_the_idle_renewal_never_outlives_the_absolute_limit(self):
        session = self.sessions.open('alice', 'a' * 64)['session']
        stored = json.loads(self.store.execute('GET', self.key(session)))
        stored['created_at'] -= ABSOLUTE_SECONDS - 60
        self.store.execute('SET', self.key(session), json.dumps(stored), 'EX', IDLE_SECONDS)
        self.assertIsNotNone(self.sessions.resume(session))
        self.assertLessEqual(self.store.execute('TTL', self.key(session)), 60)

    def test_only_the_digest_is_a_key_and_environments_are_separate(self):
        session = self.sessions.open('alice', 'a' * 64)['session']
        keys = self.store.execute('KEYS', self.sessions.prefix + '*')
        self.assertEqual(keys, [self.key(session)])
        self.assertNotIn(session, self.store.execute('GET', self.key(session)))
        self.assertIsNone(CaseSessions(self.store, 'production').resume(session))


if __name__ == '__main__':
    unittest.main()
