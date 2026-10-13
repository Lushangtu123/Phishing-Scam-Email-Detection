"""Short-lived, revocable analyst sessions for the case workspace.

An analyst's long-lived access token is used only to sign in, where it is exchanged
for a random session ID that the browser keeps in memory. The server keeps each
session, by the SHA-256 of its ID, with its analyst and the credential digest it was
opened with. A session ends 30 minutes after its last request, 8 hours after sign-in,
at sign-out, or as soon as the analyst's configured credential changes or is removed.
Upstash keeps sessions for every instance of a deployment, so a sign-out anywhere
holds everywhere; SQLite keeps them for one persistent installation.
"""
import hashlib
import json
import re
import secrets
import time

from case_cloud import UpstashCaseStore, CaseUnavailable

IDLE_SECONDS = 30 * 60
ABSOLUTE_SECONDS = 8 * 3600
# secrets.token_urlsafe(32): 43 URL-safe characters.
SESSION_ID = re.compile(r'[A-Za-z0-9_-]{43}')

# Redis keeps time: every instance reads the same clock.
OPEN = '''
local now = tonumber(redis.call('TIME')[1])
redis.call('SET', KEYS[1], cjson.encode({actor=ARGV[1], credential=ARGV[2], created_at=now}), 'EX', ARGV[3])
return now
'''
RESUME = '''
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local now = tonumber(redis.call('TIME')[1])
local session = cjson.decode(raw)
local left = session.created_at + tonumber(ARGV[2]) - now
if left <= 0 then
  redis.call('DEL', KEYS[1])
  return false
end
redis.call('EXPIRE', KEYS[1], math.min(tonumber(ARGV[1]), left))
return raw
'''


def session_digest(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


class CaseSessions:
    def __init__(self, store, environment='local', *, clock=time.time):
        self.store, self.scope, self.clock = store, environment, clock
        if isinstance(store, UpstashCaseStore):
            self.prefix = store.key.replace('phishguard:cases:v1:', 'phishguard:sessions:v1:', 1) + ':' + environment + ':'
        else:
            with store.connection(write=True) as db:
                db.execute('CREATE TABLE IF NOT EXISTS case_sessions (digest TEXT PRIMARY KEY, scope TEXT NOT NULL, '
                           'actor TEXT NOT NULL, credential TEXT NOT NULL, created_at INTEGER NOT NULL, '
                           'last_seen INTEGER NOT NULL)')

    def open(self, actor: str, credential: str) -> dict:
        """A new session for actor, signed in with the credential whose digest is credential."""
        session_id = secrets.token_urlsafe(32)
        digest = session_digest(session_id)
        if isinstance(self.store, UpstashCaseStore):
            created = self.store.execute('EVAL', OPEN, 1, self.prefix + digest, actor, credential, IDLE_SECONDS)
            if type(created) is not int or created <= 0:
                raise CaseUnavailable('Invalid session response')
        else:
            created = int(self.clock())
            with self.store.connection(write=True) as db:
                db.execute('DELETE FROM case_sessions WHERE last_seen<=? OR created_at<=?',
                           (created - IDLE_SECONDS, created - ABSOLUTE_SECONDS))
                db.execute('INSERT INTO case_sessions VALUES (?, ?, ?, ?, ?, ?)',
                           (digest, self.scope, actor, credential, created, created))
        return {'session': session_id, 'idle_seconds': IDLE_SECONDS, 'expires_at': created + ABSOLUTE_SECONDS}

    def resume(self, session_id: str) -> dict | None:
        """The live session's actor and credential, renewing its idle time, or None."""
        if not SESSION_ID.fullmatch(session_id):
            return None
        digest = session_digest(session_id)
        if isinstance(self.store, UpstashCaseStore):
            raw = self.store.execute('EVAL', RESUME, 1, self.prefix + digest, IDLE_SECONDS, ABSOLUTE_SECONDS)
            if raw is None or raw is False:
                return None
            try:
                session = json.loads(raw)
                if not (isinstance(session['actor'], str) and isinstance(session['credential'], str)):
                    raise ValueError()
                return {'actor': session['actor'], 'credential': session['credential']}
            except (ValueError, TypeError, KeyError):
                raise CaseUnavailable('Invalid stored session') from None
        now = int(self.clock())
        with self.store.connection(write=True) as db:
            row = db.execute('SELECT * FROM case_sessions WHERE digest=? AND scope=?', (digest, self.scope)).fetchone()
            if row is None:
                return None
            if now - row['last_seen'] >= IDLE_SECONDS or now - row['created_at'] >= ABSOLUTE_SECONDS:
                db.execute('DELETE FROM case_sessions WHERE digest=?', (digest,))
                return None
            db.execute('UPDATE case_sessions SET last_seen=? WHERE digest=?', (now, digest))
            return {'actor': row['actor'], 'credential': row['credential']}

    def close(self, session_id: str) -> None:
        """End a session (sign-out). Ending an unknown or expired one is not an error."""
        if not SESSION_ID.fullmatch(session_id):
            return
        digest = session_digest(session_id)
        if isinstance(self.store, UpstashCaseStore):
            self.store.execute('DEL', self.prefix + digest)
            return
        with self.store.connection(write=True) as db:
            db.execute('DELETE FROM case_sessions WHERE digest=? AND scope=?', (digest, self.scope))
