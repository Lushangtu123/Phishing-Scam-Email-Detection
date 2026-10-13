"""Check a saved analyst token against the stable Production site without printing it."""

from getpass import getpass
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


PRODUCTION_SESSION = 'https://phishguard-email-analyzer.vercel.app/api/cases/session'


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def verify_token(token, *, opener=None):
    """Sign in with the token, confirm the analyst, and sign out again at once: the check
    leaves no session behind. Returns the analyst's name."""
    if not isinstance(token, str) or not 32 <= len(token) <= 256 or not token.isascii() or any(c.isspace() for c in token):
        raise ValueError('Paste the token only, without quotes or spaces.')
    open_url = opener or build_opener(_NoRedirect()).open
    request = Request(PRODUCTION_SESSION, data=b'', method='POST',
                      headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
    try:
        with open_url(request, timeout=10) as response:
            if response.geturl() != PRODUCTION_SESSION:
                raise ValueError('The site redirected away from the Production sign-in endpoint.')
            if not response.headers.get('Content-Type', '').lower().startswith('application/json'):
                raise ValueError('The site returned a non-JSON response.')
            raw = response.read(4097)
    except HTTPError as exc:
        if exc.code == 401:
            raise ValueError('Production rejected this token (HTTP 401).') from None
        if exc.code == 404:
            raise ValueError('Case management is disabled on Production (HTTP 404).') from None
        if exc.code == 503:
            raise ValueError('Production case configuration or storage is unavailable (HTTP 503).') from None
        raise ValueError(f'Production sign-in check failed (HTTP {exc.code}).') from None
    except (OSError, URLError):
        raise ValueError('Could not reach the Production sign-in endpoint.') from None
    if len(raw) > 4096:
        raise ValueError('Production returned an oversized sign-in response.')
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Production returned invalid sign-in JSON.') from None
    actor = payload.get('actor') if isinstance(payload, dict) else None
    session = payload.get('session') if isinstance(payload, dict) else None
    if not isinstance(actor, str) or not actor or not isinstance(session, str):
        raise ValueError('Production did not confirm an analyst identity.')
    try:  # sign out; a session left open still ends after 30 idle minutes
        with open_url(Request(PRODUCTION_SESSION, method='DELETE',
                              headers={'Authorization': 'Bearer ' + session}), timeout=10):
            pass
    except (OSError, URLError, HTTPError):
        pass
    return actor


def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit('Run in your own interactive terminal; do not redirect token input.')
    print('Production token check. Input is hidden; pasted characters will not appear.')
    token = getpass('Paste your saved analyst token: ').strip()
    try:
        actor = verify_token(token)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    print(f'Production login succeeded for analyst {actor}.')


if __name__ == '__main__':
    main()
