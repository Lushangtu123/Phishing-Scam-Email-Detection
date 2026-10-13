import io
import json
from pathlib import Path
import sys
import unittest
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.verify_case_login import PRODUCTION_SESSION, verify_token


TOKEN = 'synthetic-analyst-token-with-at-least-32-characters'


class _Response(io.BytesIO):
    def __init__(self, body, *, url=PRODUCTION_SESSION, content_type='application/json'):
        super().__init__(body)
        self.url = url
        self.headers = {'Content-Type': content_type}

    def geturl(self):
        return self.url


class VerifyCaseLoginTests(unittest.TestCase):
    def test_signs_in_at_the_fixed_endpoint_and_signs_out_at_once(self):
        requests = []
        session = 'synthetic-session-from-sign-in-0123456789ab'
        def opener(request, timeout):
            requests.append((request, timeout))
            if request.get_method() == 'DELETE':
                return _Response(b'', content_type='')
            return _Response(json.dumps({'actor': 'analyst', 'session': session}).encode())
        self.assertEqual(verify_token(TOKEN, opener=opener), 'analyst')
        (sign_in, timeout), (sign_out, _) = requests
        self.assertEqual((sign_in.get_method(), sign_in.full_url), ('POST', PRODUCTION_SESSION))
        self.assertEqual(sign_in.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertEqual(timeout, 10)
        self.assertNotIn(TOKEN, sign_in.full_url)
        # The check leaves no session behind, and the token is not sent again.
        self.assertEqual((sign_out.get_method(), sign_out.full_url), ('DELETE', PRODUCTION_SESSION))
        self.assertEqual(sign_out.get_header('Authorization'), 'Bearer ' + session)

    def test_rejected_token_is_reported_without_secret(self):
        def opener(request, timeout):
            raise HTTPError(request.full_url, 401, 'rejected ' + TOKEN, {}, None)
        with self.assertRaisesRegex(ValueError, 'HTTP 401') as raised:
            verify_token(TOKEN, opener=opener)
        self.assertNotIn(TOKEN, str(raised.exception))

    def test_redirect_and_unexpected_payload_are_rejected(self):
        for response in (
            _Response(b'{}', url='https://vercel.com/login'),
            _Response(b'<html>login</html>', content_type='text/html'),
            _Response(b'{}'),
        ):
            with self.subTest(response=response):
                with self.assertRaises(ValueError):
                    verify_token(TOKEN, opener=lambda *_args, **_kwargs: response)

    def test_invalid_token_never_contacts_site(self):
        with self.assertRaisesRegex(ValueError, 'token only'):
            verify_token(' short ', opener=lambda *_args, **_kwargs: self.fail('network'))


if __name__ == '__main__':
    unittest.main()
