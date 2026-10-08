"""On Vercel the CDN serves /static without the app's middleware, so vercel.json "headers" must
give each static file the headers the middleware gives it, and pyproject.toml must keep the
CDN on (docs/deployment.md, "Vercel Hobby deployment")."""
import asyncio
import json
import re
import sys
import tomllib
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

WEBSITE_DIR = Path(__file__).resolve().parents[1]
ROOT = WEBSITE_DIR.parent
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

MANAGED = ('cache-control', 'content-security-policy', 'permissions-policy', 'referrer-policy',
           'x-content-type-options', 'x-frame-options')
SAMPLES = ('/static/app.js', '/static/app.js?v=54', '/static/style.css?v=59', '/static/favicon.svg',
           '/static/vision-worker.mjs', '/static/vision-worker.mjs?v=3', '/static/vendor/vision/worker.min.js',
           '/static/cases.html', '/static/app.js?v=')


def source_regex(source: str) -> re.Pattern:
    """The subset of Vercel's path-to-regexp sources used here: literals, (regex) and :name(regex)."""
    pattern, index = '', 0
    while index < len(source):
        named = re.match(r':\w+(?=\()', source[index:])
        if named:
            index += named.end()
            continue
        if source[index] == '(':
            depth, end = 0, index
            while True:
                depth += {'(': 1, ')': -1}.get(source[end], 0)
                if depth == 0:
                    break
                end += 1
            pattern += source[index:end + 1]
            index = end + 1
        else:
            pattern += re.escape(source[index])
            index += 1
    return re.compile(pattern)


def vercel_headers(url: str) -> dict:
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    config = json.loads((ROOT / 'vercel.json').read_text(encoding='utf-8'))
    headers = {}
    for rule in config['headers']:
        if not source_regex(rule['source']).fullmatch(parts.path):
            continue
        satisfied = True
        for condition in rule.get('has', []):
            assert condition['type'] == 'query'
            values = query.get(condition['key'])
            expected = condition.get('value')
            satisfied &= bool(values) and (expected is None or bool(re.search(expected['re'], values[0])))
        if not satisfied:
            continue
        for header in rule['headers']:
            key = header['key'].lower()
            # Vercel's order for two rules setting one header is not documented: never rely on it.
            assert key not in headers, f'{key} set twice for {url}'
            headers[key] = header['value']
    return headers


def app_headers(url: str) -> dict:
    async def fetch():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url='http://localhost') as client:
            return await client.get(url)
    response = asyncio.run(fetch())
    assert response.status_code == 200, (url, response.status_code)
    return {key: value for key, value in response.headers.items() if key in MANAGED}


class VercelStaticHeaderTests(unittest.TestCase):
    def test_the_cdn_gives_static_files_the_middleware_headers(self):
        for url in SAMPLES:
            with self.subTest(url=url):
                self.assertEqual(vercel_headers(url), app_headers(url))

    def test_rules_cover_only_static_files(self):
        for url in ('/', '/cases', '/api/config', '/statics/app.js'):
            with self.subTest(url=url):
                self.assertEqual(vercel_headers(url), {})

    def test_the_cdn_serves_static_files(self):
        config = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        self.assertIs(config['tool']['vercel']['fastapi']['static']['cdn'], True)

    def test_vercel_installs_the_serving_pins(self):
        # With a pyproject.toml present Vercel installs from [project] (uv lock), while local
        # and CI installs read requirements.txt: the two must name the same pins.
        config = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        pins = [line.split('#', 1)[0].strip() for line in (ROOT / 'requirements.txt').read_text().splitlines()]
        self.assertEqual(sorted(config['project']['dependencies']), sorted(pin for pin in pins if pin))
        self.assertEqual(config['project']['requires-python'],
                         f"~={(ROOT / '.python-version').read_text().strip()}.0")


if __name__ == '__main__':
    unittest.main()
