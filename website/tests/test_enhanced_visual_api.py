"""Opt-in image processing must preserve literal browser evidence and privacy."""
import asyncio
import base64
import hashlib
import json
import unittest
from unittest.mock import patch

from test_case_api import request
from test_visual_analysis import observation
import app


IMAGE = (app.BASE_DIR / 'tests/fixtures/vision/synthetic-qr.png').read_bytes()


def payload(**changes):
    value = {'observations': [observation(sha256=hashlib.sha256(IMAGE).hexdigest())],
             'enhancement': {'image_base64': base64.b64encode(IMAGE).decode(), 'consent': True}}
    return {**value, **changes}


class EnhancedVisualAPITests(unittest.TestCase):
    def setUp(self):
        app._rate_limit_buckets.clear()
        self.model = patch.object(app, '_content_pipeline', None)
        self.model.start()

    def tearDown(self):
        self.model.stop()

    def call(self, body):
        return asyncio.run(request('POST', '/api/analyze-visual', token=None, payload=body))

    def test_image_upload_is_unavailable_by_default(self):
        status, data, _ = self.call(payload())
        self.assertEqual(status, 503)
        self.assertNotIn(base64.b64encode(IMAGE).decode(), json.dumps(data))

    def test_explicit_boolean_consent_is_required_and_validation_is_private(self):
        for consent in (None, False, 1, 'true'):
            body = payload()
            body['enhancement']['consent'] = consent
            status, data, _ = self.call(body)
            self.assertEqual(status, 422)
            self.assertNotIn('image_base64', json.dumps(data))
            self.assertNotIn(base64.b64encode(IMAGE).decode(), json.dumps(data))

    def test_additional_recognition_preserves_original_and_cannot_lower_risk(self):
        from enhanced_vision import EnhancedResult
        result = EnhancedResult.model_validate({
            'schema': 'phishguard-enhanced-vision/v1', 'image_sha256': hashlib.sha256(IMAGE).hexdigest(),
            'ocr': {'engine': 'test-control', 'version': '1', 'text': 'https://paypal.example/login'},
            'semantic': {'status': 'disabled'}, 'warnings': []})
        with patch.object(app, 'recognize_image', return_value=result):
            status, data, _ = self.call(payload())
        self.assertEqual(status, 200)
        self.assertIn(data['risk_level'], {'high', 'critical'})
        visual = data['visual_analysis']
        self.assertEqual(visual['observations'][0]['qr_payloads'], ['https://paypa1.example/login'])
        self.assertTrue(visual['enhancement']['url_disagreement'])
        self.assertEqual(visual['enhancement']['ocr']['text'], 'https://paypal.example/login')
        self.assertNotIn(base64.b64encode(IMAGE).decode(), json.dumps(data))

    def test_service_failure_keeps_browser_result_and_explains_coverage(self):
        from fastapi import HTTPException
        with patch.object(app, 'recognize_image', side_effect=HTTPException(502, 'private-upstream')):
            status, data, _ = self.call(payload())
        self.assertEqual(status, 200)
        self.assertIn(data['risk_level'], {'high', 'critical'})
        self.assertEqual(data['visual_analysis']['enhancement']['status'], 'unavailable')
        self.assertNotIn('private-upstream', json.dumps(data))

    def test_public_configuration_exposes_availability_without_service_credentials(self):
        from enhanced_vision import EnhancedVisionSettings
        settings = EnhancedVisionSettings('https://private.example/recognize', 'private-token', True)
        with patch.object(app, 'ENHANCED_VISION', settings):
            status, data, _ = asyncio.run(request('GET', '/api/config', token=None))
        self.assertEqual(status, 200)
        self.assertTrue(data['enhanced_vision_enabled'])
        self.assertTrue(data['enhanced_vision_semantics_enabled'])
        self.assertNotIn('private', json.dumps(data))

    def test_configuration_requires_https_and_token_for_public_deployment(self):
        from enhanced_vision import load_enhanced_vision_settings
        base = {'ENHANCED_VISION_ENABLED': 'true', 'APP_ENV': 'production'}
        for url in ('http://127.0.0.1:8914/recognize', 'https://user:pass@private.example/recognize',
                    'https://private.example/recognize?secret=x', 'https://private.example/other'):
            with self.assertRaises(ValueError):
                load_enhanced_vision_settings({**base, 'ENHANCED_VISION_URL': url, 'ENHANCED_VISION_TOKEN': 'test'})
        with self.assertRaises(ValueError):
            load_enhanced_vision_settings({**base, 'ENHANCED_VISION_URL': 'https://private.example/recognize'})
        settings = load_enhanced_vision_settings({**base, 'APP_ENV': 'development',
            'ENHANCED_VISION_URL': 'http://127.0.0.1:8914/recognize'})
        self.assertTrue(settings.enabled)

    def test_mismatched_image_is_rejected_before_contacting_service(self):
        from enhanced_vision import EnhancedVisionSettings
        value = payload()
        value['observations'][0]['sha256'] = 'a' * 64
        with patch.object(app, 'ENHANCED_VISION', EnhancedVisionSettings('http://127.0.0.1:1/recognize')):
            status, data, _ = self.call(value)
        self.assertEqual(status, 422)
        self.assertNotIn('image_base64', json.dumps(data))

    def test_enhanced_case_keeps_readings_but_never_original_image_bytes(self):
        from test_case_api import CaseAPITests
        from enhanced_vision import EnhancedResult
        result = EnhancedResult.model_validate({'schema': 'phishguard-enhanced-vision/v1',
            'image_sha256': hashlib.sha256(IMAGE).hexdigest(),
            'ocr': {'engine': 'test-control', 'version': '1', 'text': 'Additional text'},
            'semantic': {'status': 'disabled'}})
        fixture = CaseAPITests(); fixture.setUp()
        try:
            with patch.object(app, 'recognize_image', return_value=result):
                status, data, _ = fixture.call('POST', '/api/cases/visual',
                    key='00000000-0000-4000-8000-000000000105', payload=payload())
            self.assertEqual(status, 201)
            self.assertEqual(data['analysis']['visual_analysis']['enhancement']['ocr']['text'], 'Additional text')
            self.assertNotIn('image_base64', json.dumps(data))
            self.assertNotIn(base64.b64encode(IMAGE).decode(), json.dumps(data))
        finally:
            fixture.tearDown()
