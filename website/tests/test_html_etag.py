"""The homepage revalidates by content: a deployment that changes it without changing its size
must not be answered 304 (Vercel gives every deployed file the same modification time)."""
import asyncio
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from starlette.responses import FileResponse

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

VERCEL_MTIME = 1540000000  # one fixed time for every file, as Vercel deploys them


def get(path, headers=None):
    async def fetch():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url='http://localhost') as client:
            return await client.get(path, headers=headers or {})
    return asyncio.run(fetch())


class HomepageRevalidationTests(unittest.TestCase):
    def test_the_etag_is_the_hash_of_the_page(self):
        body = app.INDEX_PAGE.read_bytes()
        response = get('/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, body)
        self.assertEqual(response.headers['etag'], '"' + hashlib.sha256(body).hexdigest() + '"')
        self.assertEqual(response.headers['cache-control'], 'no-cache')
        self.assertNotIn('last-modified', response.headers)
        self.assertTrue(response.headers['content-type'].startswith('text/html'))
        # The security middleware still applies.
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        self.assertIn('content-security-policy', response.headers)

    def test_revalidation(self):
        etag = get('/').headers['etag']
        for sent in (etag, 'W/' + etag, '"other", ' + etag):
            with self.subTest(sent=sent):
                response = get('/', {'If-None-Match': sent})
                self.assertEqual((response.status_code, response.content), (304, b''))
                self.assertEqual(response.headers['etag'], etag)
        self.assertEqual(get('/', {'If-None-Match': '"' + '0' * 64 + '"'}).status_code, 200)

    def test_a_same_size_change_is_a_new_page(self):
        with tempfile.TemporaryDirectory() as directory:
            old, new = Path(directory) / 'old.html', Path(directory) / 'new.html'
            old.write_text('<script src="/static/i18n.js?v=111"></script>', encoding='utf-8')
            new.write_text('<script src="/static/i18n.js?v=115"></script>', encoding='utf-8')
            for page in (old, new):
                os.utime(page, (VERCEL_MTIME, VERCEL_MTIME))
            # The cause: FileResponse gives both the same ETag.
            tags = [FileResponse(str(page), stat_result=page.stat()).headers['etag'] for page in (old, new)]
            self.assertEqual(tags[0], tags[1])
            with patch.object(app, 'INDEX_PAGE', old):
                stale = get('/').headers['etag']
            with patch.object(app, 'INDEX_PAGE', new):
                response = get('/', {'If-None-Match': stale})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'v=115', response.content)
        self.assertNotEqual(response.headers['etag'], stale)

    def test_the_favicon_too(self):
        response = get('/favicon.ico')
        self.assertEqual((response.status_code, response.headers['content-type']), (200, 'image/svg+xml'))
        self.assertEqual(response.headers['etag'], '"' + hashlib.sha256(app.FAVICON.read_bytes()).hexdigest() + '"')
        self.assertEqual(get('/favicon.ico', {'If-None-Match': response.headers['etag']}).status_code, 304)


if __name__ == '__main__':
    unittest.main()
