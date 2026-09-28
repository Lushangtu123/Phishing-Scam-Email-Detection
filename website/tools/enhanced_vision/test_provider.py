"""Optional loopback provider: image validation and literal output boundaries."""
import base64
import hashlib
import http.client
import io
import json
from pathlib import Path
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from website.tools.enhanced_vision.provider import (MAX_IMAGE_BYTES, MAX_REQUEST_BYTES,
    LoopbackServer, OllamaReader, ProviderError, RapidExtractor, RecognitionService,
    decode_request)


def stuck_worker(connection):
    connection.send({'ready': True, 'provenance': {}})
    connection.recv()
    time.sleep(10)


def fake_worker(connection):
    connection.send({'ready': True, 'provenance': {'runtime_version': 'fake'}})
    while True:
        connection.recv()
        connection.send({'ocr': {'engine': 'fake', 'version': 'test', 'text': 'paypa1',
                                'confidence': 50}, 'provenance': {'runtime_version': 'fake'}})


def fake_ocr(image, language):
    return {'engine': 'fake', 'version': 'test', 'text': 'https://paypa1.example/0O', 'confidence': 99}


class ImageFixtures:
    @staticmethod
    def image_bytes(size=(20, 10), image_format='PNG'):
        from PIL import Image
        image = Image.new('RGB', size, 'white')
        output = io.BytesIO()
        image.save(output, format=image_format)
        return output.getvalue()

    @classmethod
    def request_bytes(cls, raw=None, **changes):
        value = {'image_base64': base64.b64encode(raw or cls.image_bytes()).decode(),
                 'language': 'eng', 'include_semantics': False}
        value.update(changes)
        return json.dumps(value).encode()


class EnhancedProviderTests(ImageFixtures, unittest.TestCase):
    def test_bad_images_and_unknown_fields_are_rejected_before_extractor(self):
        for payload in (self.request_bytes(b'not an image'),
                        self.request_bytes(image_base64='https://example.com/x.png'),
                        self.request_bytes(image_url='http://127.0.0.1/private'),
                        self.request_bytes(include_semantics='true'),
                        self.request_bytes(language='auto'),
                        self.request_bytes(language=[]),
                        b'{"image_base64":"x","image_base64":"y"}'):
            with self.subTest(payload=payload[:100]):
                with self.assertRaises(ProviderError):
                    decode_request(payload)

    def test_valid_images_hash_original_bytes_and_preserve_literal_ocr(self):
        for image_format in ('PNG', 'JPEG', 'WEBP'):
            raw = self.image_bytes(image_format=image_format)
            service = RecognitionService(extractor=lambda image, language: {
                'engine': 'fake', 'version': 'test',
                'text': 'https://paypa1.example/0O?q=lI1', 'confidence': 99})
            result = service.recognize(self.request_bytes(raw))
            self.assertEqual(result['schema'], 'phishguard-enhanced-vision/v1')
            self.assertEqual(result['image_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result['ocr']['text'], 'https://paypa1.example/0O?q=lI1')
            self.assertEqual(result['semantic']['status'], 'disabled')
            self.assertNotIn('verdict', result)

    def test_bundled_rapidocr_reads_literal_lookalike_url(self):
        raw = (Path(__file__).resolve().parents[2] /
               'tests/fixtures/vision/synthetic-phishing.png').read_bytes()
        extractor = RapidExtractor()
        try:
            result = RecognitionService(extractor=extractor).recognize(self.request_bytes(raw))
            self.assertEqual(result['ocr']['engine'], 'RapidOCR/PP-OCRv4')
            self.assertIn('https://paypa1.example/login', result['ocr']['text'])
            self.assertEqual(result['image_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(len(result['provenance']['model_sha256']), 3)
        finally:
            extractor.close()

    def test_encoded_and_decoded_file_limits_and_pixel_limits(self):
        for body in (b' ' * (MAX_REQUEST_BYTES + 1),
                     self.request_bytes(b'x' * (MAX_IMAGE_BYTES + 1)),
                     self.request_bytes(self.image_bytes(size=(4097, 1))),
                     self.request_bytes(self.image_bytes(size=(3000, 3000)))):
            with self.subTest(length=len(body)):
                with self.assertRaises(ProviderError) as caught:
                    decode_request(body)
                self.assertEqual(caught.exception.status, 413)

    def test_supported_formats_require_real_complete_single_frame_decode(self):
        from PIL import Image
        animated = io.BytesIO()
        Image.new('RGB', (20, 10), 'red').save(animated, format='PNG', save_all=True,
                    append_images=[Image.new('RGB', (20, 10), 'blue')], duration=100)
        for raw in (animated.getvalue(), self.image_bytes(image_format='BMP'),
                    self.image_bytes()[:45], self.image_bytes(image_format='JPEG')[:-20]):
            with self.subTest(length=len(raw)):
                with self.assertRaises(ProviderError) as caught:
                    decode_request(self.request_bytes(raw))
                self.assertEqual(caught.exception.status, 422)

    def test_extractor_failure_and_invalid_confidence_are_generic(self):
        def broken(image, language):
            raise RuntimeError('private image text or token')
        for extractor in (broken, lambda image, language: {**fake_ocr(image, language),
                                                         'confidence': float('nan')}):
            with self.assertRaises(ProviderError) as caught:
                RecognitionService(extractor=extractor).recognize(self.request_bytes())
            self.assertEqual(caught.exception.status, 503)
            self.assertEqual(str(caught.exception), 'OCR engine unavailable')

    def test_empty_ocr_is_valid_and_long_text_is_bounded_with_warning(self):
        for text in ('', 'a' * 6001):
            service = RecognitionService(extractor=lambda image, language: {
                **fake_ocr(image, language), 'text': text, 'confidence': None})
            result = service.recognize(self.request_bytes())
            self.assertEqual(result['ocr']['text'], text[:6000])
            self.assertEqual(bool(result['warnings']), len(text) > 6000)

    def test_semantic_failure_never_loses_ocr_or_returns_a_model_verdict(self):
        class Reader:
            model = 'qwen2.5vl:7b'
            def __call__(self, image):
                return {'observations': [], 'visible_urls': [], 'verdict': 'safe'}
        service = RecognitionService(extractor=fake_ocr, semantic_reader=Reader())
        result = service.recognize(self.request_bytes(include_semantics=True))
        self.assertEqual(result['semantic']['status'], 'unavailable')
        self.assertEqual(result['ocr']['text'], 'https://paypa1.example/0O')
        self.assertNotIn('verdict', result['semantic'])
        self.assertTrue(result['warnings'])

    def test_semantic_lists_are_bounded_and_preserve_unverified_strings(self):
        class Reader:
            model = 'qwen2.5vl:7b'
            result = {'observations': ['Login form'], 'visible_urls': ['https://paypa1.example/0O']}
            def __call__(self, image):
                return self.result
        reader = Reader()
        service = RecognitionService(extractor=fake_ocr, semantic_reader=reader)
        result = service.recognize(self.request_bytes(include_semantics=True))
        self.assertEqual(result['semantic']['status'], 'available')
        self.assertEqual(result['semantic']['visible_urls'], ['https://paypa1.example/0O'])
        self.assertTrue(any('unverified' in item for item in result['warnings']))
        for invalid in ({'observations': ['x'] * 9, 'visible_urls': []},
                        {'observations': ['x' * 301], 'visible_urls': []},
                        {'observations': [], 'visible_urls': ['x' * 2049]},
                        {'observations': [], 'visible_urls': ['x\ny']}):
            reader.result = invalid
            self.assertEqual(service.recognize(self.request_bytes(include_semantics=True))['semantic']['status'],
                             'unavailable')

    def test_no_semantics_request_never_calls_configured_model(self):
        class Reader:
            model = 'test'
            def __call__(self, image):
                raise AssertionError('Model must not run')
        service = RecognitionService(extractor=fake_ocr, semantic_reader=Reader())
        self.assertEqual(service.recognize(self.request_bytes())['semantic']['status'], 'disabled')
        result = RecognitionService(extractor=fake_ocr).recognize(self.request_bytes(include_semantics=True))
        self.assertEqual(result['semantic']['status'], 'unavailable')

    def test_process_deadline_kills_stuck_engine_and_normal_engine_is_resident(self):
        image, _, _, _ = decode_request(self.request_bytes())
        extractor = RapidExtractor(timeout=2, worker_target=fake_worker)
        try:
            self.assertEqual(extractor(image, 'eng')['text'], 'paypa1')
            process = extractor.process
            self.assertEqual(extractor(image, 'chi_sim')['text'], 'paypa1')
            self.assertIs(extractor.process, process)
            self.assertEqual(extractor.provenance['runtime_version'], 'fake')
        finally:
            extractor.close()
        stuck = RapidExtractor(timeout=0.5, worker_target=stuck_worker)
        started = time.monotonic()
        with self.assertRaises(ProviderError) as caught:
            stuck(image, 'eng')
        self.assertEqual(caught.exception.status, 504)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertIsNone(stuck.process)


class EnhancedHTTPTests(ImageFixtures, unittest.TestCase):
    def setUp(self):
        self.server = LoopbackServer(0, RecognitionService(extractor=fake_ocr),
                                   token='test-secret', allowed_origins=('http://127.0.0.1:8000',))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def call(self, body=None, **headers):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request('POST', '/recognize', self.request_bytes() if body is None else body,
                               {'Content-Type': 'application/json', 'Authorization': 'Bearer test-secret', **headers})
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.getheaders())
        finally:
            connection.close()

    def test_loopback_authorized_json_and_origin_allowlist(self):
        status, body, headers = self.call(Origin='http://127.0.0.1:8000')
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        self.assertEqual(status, 200)
        self.assertEqual(body['ocr']['text'], 'https://paypa1.example/0O')
        self.assertEqual(headers['Access-Control-Allow-Origin'], 'http://127.0.0.1:8000')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        for changes, expected in (({'Host': 'evil.example'}, 403),
                                  ({'Host': f'127.0.0.1:{self.server.server_port}@evil.example'}, 403),
                                  ({'Origin': 'null'}, 403), ({'Origin': 'https://evil.example'}, 403),
                                  ({'Authorization': 'Bearer wrong'}, 401),
                                  ({'Content-Type': 'text/plain'}, 415),
                                  ({'Content-Length': str(MAX_REQUEST_BYTES + 1)}, 413)):
            with self.subTest(changes=changes):
                status, body, headers = self.call(**changes)
                self.assertEqual(status, expected)
                self.assertNotIn('test-secret', json.dumps(body))

    def test_busy_service_is_rejected_without_another_extraction(self):
        self.server.service.lock.acquire()
        try:
            self.assertEqual(self.call()[0], 503)
        finally:
            self.server.service.lock.release()


class OllamaHTTPTests(unittest.TestCase):
    def test_fixed_loopback_payload_and_model_generated_url_is_literal(self):
        captured = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                captured.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                body = json.dumps({'done': True, 'response': json.dumps({
                    'observations': ['Login form'], 'visible_urls': ['https://paypa1.example/0O']})}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            reader = OllamaReader('qwen2.5vl:7b', port=server.server_port)
            image, _, _, _ = decode_request(ImageFixtures.request_bytes())
            with patch.dict('os.environ', {'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1'}):
                result = reader(image)
            self.assertEqual(result['visible_urls'], ['https://paypa1.example/0O'])
            path, payload = captured[0]
            self.assertEqual(path, '/api/generate')
            self.assertEqual(payload['model'], 'qwen2.5vl:7b')
            self.assertFalse(payload['stream'])
            self.assertNotIn('tools', payload)
            self.assertEqual(payload['format']['additionalProperties'], False)
            self.assertEqual(payload['options']['num_predict'], 768)
            self.assertEqual(len(payload['images']), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
