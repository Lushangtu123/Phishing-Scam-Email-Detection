"""Optional distributed budgets without enabling sender observation storage."""
import math
from urllib.parse import urlsplit

from config import Settings, TRUE_VALUES, FALSE_VALUES
from sender_history import RateLimitDecision, UpstashRateLimitStore


class DisabledRateLimitStore:
    def __init__(self, status='disabled'):
        self.status = status

    async def check_rate_limit(self, identity, *, limit, window_seconds):
        # An explicitly enabled but malformed limiter must not silently disable
        # the administrator's shared-budget requirement. No configuration leaks.
        if self.status == 'configuration_error':
            return RateLimitDecision(allowed=False, retry_after=60)
        return None


def build_rate_limit_store(source, settings: Settings, *, opener=None):
    raw = source.get('DISTRIBUTED_RATE_LIMIT_ENABLED')
    if raw is None:
        # Preserve prior deployments that used sender history for shared limits.
        if not settings.sender_history_ready:
            return DisabledRateLimitStore()
        return UpstashRateLimitStore(settings.sender_history_rest_url,
            settings.sender_history_rest_token, settings.sender_history_hmac_key,
            timeout=settings.sender_history_timeout_seconds, opener=opener)
    value = raw.strip().lower()
    if value in FALSE_VALUES:
        return DisabledRateLimitStore()
    if value not in TRUE_VALUES:
        return DisabledRateLimitStore('configuration_error')

    url = (source.get('RATE_LIMIT_REDIS_REST_URL')
           or source.get('UPSTASH_REDIS_REST_URL', '')).strip().rstrip('/')
    token = (source.get('RATE_LIMIT_REDIS_REST_TOKEN')
             or source.get('UPSTASH_REDIS_REST_TOKEN', '')).strip()
    secret = source.get('RATE_LIMIT_HMAC_KEY') or source.get('SENDER_HISTORY_HMAC_KEY', '')
    try:
        parsed = urlsplit(url)
        timeout = float(source.get('RATE_LIMIT_TIMEOUT_SECONDS', '1.0'))
        valid = (parsed.scheme == 'https' and parsed.hostname
                 and parsed.hostname.lower().endswith('.upstash.io')
                 and parsed.username is None and parsed.password is None
                 and parsed.port in (None, 443) and parsed.path in ('', '/')
                 and not parsed.query and not parsed.fragment
                 and token and '\r' not in token and '\n' not in token
                 and len(secret.encode('utf-8')) >= 32
                 and math.isfinite(timeout) and 0.1 <= timeout <= 3.0)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        return DisabledRateLimitStore('configuration_error')
    return UpstashRateLimitStore(url, token, secret, timeout=timeout, opener=opener)
