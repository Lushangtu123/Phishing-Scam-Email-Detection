"""Browser-extracted evidence must be rescored and never certify image safety."""
import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from test_case_api import request
import app


def observation(**changes):
    value = dict(name='synthetic.png', mime_type='image/png', source='upload',
                sha256='a' * 64, status='processed', qr_payloads=['https://paypa1.example/login'],
                ocr_text='', ocr_confidence=0, warnings=[])
    return {**value, **changes}


class VisualAPITests(unittest.TestCase):
    def setUp(self):
        app._rate_limit_buckets.clear()
        self.model = patch.object(app, '_content_pipeline', None)
        self.model.start()

    def tearDown(self):
        self.model.stop()

    def test_qr_evidence_is_rescored_with_provenance_and_incomplete_coverage(self):
        status, data, _ = asyncio.run(request('POST', '/api/analyze-visual', token=None,
            payload={'observations': [observation()]}))
        self.assertEqual(status, 200)
        self.assertIn(data['risk_level'], {'high', 'critical'})
        self.assertFalse(data['analysis_complete'])
        self.assertEqual(data['visual_analysis']['provenance'], 'browser_extracted_unverified')
        self.assertEqual(data['visual_analysis']['observations'][0]['qr_payloads'],
                         ['https://paypa1.example/login'])

    def call(self, payload, path='/api/analyze-visual'):
        return asyncio.run(request('POST', path, token=None, payload=payload))

    def test_actual_ocr_language_is_preserved_without_trusting_it_as_a_verdict(self):
        for language in ('eng', 'chi_sim', 'eng+chi_sim', None):
            status, data, _ = self.call({'observations': [observation(ocr_language=language)]})
            self.assertEqual(status, 200)
            evidence = data['visual_analysis']
            self.assertEqual(evidence['observations'][0]['ocr_language'], language)
            self.assertNotIn('(eng+chi_sim)', evidence['extractors'])
            self.assertEqual(evidence['provenance'], 'browser_extracted_unverified')
            self.assertFalse(data['analysis_complete'])
        self.assertEqual(self.call({'observations': [observation(ocr_language='unknown-language') ]})[0], 422)

    def test_high_confidence_ocr_does_not_certify_url_spelling(self):
        for text in ('https://paypal.example/login', 'httbs:/ /baybal.example/login'):
            status, data, _ = self.call({'observations': [observation(
                qr_payloads=[], ocr_text=text, ocr_confidence=99)]})
            self.assertEqual(status, 200)
            record = data['visual_analysis']['observations'][0]
            self.assertEqual(record['ocr_text'], text)
            self.assertTrue(any('character by character' in warning
                                for warning in record['assessment_warnings']))
            self.assertFalse(data['analysis_complete'])
            self.assertNotEqual(data['risk_level'], 'safe')

    def test_url_line_confidence_is_bounded_retained_and_cannot_change_risk(self):
        outputs = []
        for confidence in (0, 48, 100):
            status, data, _ = self.call({'observations': [observation(
                qr_payloads=[], ocr_text='https://paypal.example/login',
                ocr_confidence=92, ocr_url_line_confidence=confidence)]})
            self.assertEqual(status, 200)
            self.assertEqual(data['visual_analysis']['observations'][0]['ocr_url_line_confidence'], confidence)
            outputs.append((data['risk_level'], data['combined_phishing_score'], data['total_score']))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])
        for confidence in (-1, 101, float('nan')):
            self.assertEqual(self.call({'observations': [observation(ocr_url_line_confidence=confidence)]})[0], 422)

    def test_benign_blank_or_failed_extraction_never_certifies_safety(self):
        for item in [observation(qr_payloads=[], ocr_text='Team meeting on Thursday.'),
                     observation(qr_payloads=[], status='failed', warnings=['OCR failed']),
                     observation(qr_payloads=['https://example.com/meeting'])]:
            with self.subTest(item=item):
                status, data, _ = self.call({'observations': [item]})
                self.assertEqual(status, 200)
                self.assertNotIn(data['risk_level'], {'safe', 'high', 'critical'})
                self.assertFalse(data['analysis_complete'])

    def test_original_email_is_authoritative_and_benign_ocr_cannot_lower_risk(self):
        raw = b'Subject: Real\nContent-Type: text/plain; charset=iso-8859-1\n\nH\xe9llo https://paypa1.example/login'
        status, data, _ = self.call({'subject': 'stale', 'body': 'stale',
            'eml_base64': base64.b64encode(raw).decode(),
            'observations': [observation(qr_payloads=[], ocr_text='Have a nice day')]})
        self.assertEqual(status, 200)
        self.assertEqual(data['input_mode'], 'raw-email')
        self.assertIn(data['risk_level'], {'high', 'critical'})

    def test_ocr_is_text_not_html_and_no_links_are_requested(self):
        with patch('socket.create_connection', side_effect=AssertionError('no network')):
            status, data, _ = self.call({'observations': [observation(qr_payloads=[],
                ocr_text='<style>URGENT</style> Your account will be suspended. Enter your password now https://paypa1.example/login')]})
        self.assertEqual(status, 200)
        self.assertIn(data['risk_level'], {'high', 'critical'})

    def test_independent_visual_sources_cannot_negate_a_dangerous_qr(self):
        dangerous = 'enter your password. Urgent account suspended.'
        for ocr, qr in [('Do not', [dangerous]),
                        ('', ['Do not', dangerous])]:
            with self.subTest(ocr=ocr, qr=qr):
                _, data, _ = self.call({'observations': [observation(
                    ocr_text=ocr, qr_payloads=qr)]})
                self.assertEqual(data['risk_level'], 'high')
                self.assertTrue(any('Direct credential request' in item['msg']
                                    for item in data['extra_indicators']))
                record = data['visual_analysis']['observations'][0]
                self.assertEqual(record['ocr_text'], ocr)
                self.assertEqual(record['qr_payloads'], qr)

    def test_independent_visual_sources_cannot_create_a_credential_request(self):
        prefix = 'Urgent account suspended. Enter your'
        for ocr, qr in [(prefix, ['password']),
                        ('', [prefix, 'password'])]:
            with self.subTest(ocr=ocr, qr=qr):
                _, data, _ = self.call({'observations': [observation(
                    ocr_text=ocr, qr_payloads=qr)]})
                self.assertNotIn(data['risk_level'], {'high', 'critical'})
                self.assertFalse(any('Direct credential request' in item['msg']
                                     for item in data['extra_indicators']))
                record = data['visual_analysis']['observations'][0]
                self.assertFalse(any('enter your password' in cat['matched']
                                     for cat in record['categories']))

    def test_visual_source_boundaries_preserve_complete_positive_and_negative_sentences(self):
        for text, expected in [
            ('Urgent account suspended. Enter your password.', 'high'),
            ('Urgent account suspended. Do not enter your password.', 'low'),
        ]:
            for ocr, qr in [(text, []), ('', [text])]:
                with self.subTest(text=text, qr=qr):
                    _, data, _ = self.call({'observations': [observation(
                        ocr_text=ocr, qr_payloads=qr)]})
                    self.assertEqual(data['risk_level'], expected)

    def test_visual_sources_retain_distinct_findings_without_adding_scores(self):
        _, data, _ = self.call({'observations': [observation(
            ocr_text='Urgent immediately', qr_payloads=['asap deadline'])]})
        record = data['visual_analysis']['observations'][0]
        category = next(cat for cat in record['categories'] if cat['key'] == 'urgency')
        self.assertEqual(set(category['matched']), {'urgent', 'immediately', 'asap', 'deadline'})
        self.assertEqual(category['score'], 2)
        self.assertEqual(data['total_score'], 2)
        self.assertEqual(data['risk_level'], 'low')
        self.assertEqual(record['assessment_method'], 'independent-source-max')
        self.assertEqual(record['assessed_source_count'], 2)

        _, data, _ = self.call({'observations': [observation(
            ocr_text='Please review the document.',
            qr_payloads=['https://paypa1.example/login', 'https://paypa1.example/login'])]})
        self.assertTrue(any(item.get('rule_id') == 'link.brand_lookalike'
                            for item in data['extra_indicators']))
        record = data['visual_analysis']['observations'][0]
        self.assertEqual(record['assessed_source_count'], 2)
        self.assertEqual(len([item for item in record['indicators']
                              if item.get('rule_id') == 'link.brand_lookalike']), 1)

    def test_visual_model_scores_each_source_separately_and_retains_highest_probability(self):
        caption = 'Team meeting agenda for next Thursday.'
        qr = 'Review the attached document before tomorrow.'
        seen = []

        def predict(pipeline, subject, body, *, canonical_text):
            seen.append(body)
            probability = 0.94 if body == qr else 0.03
            return {'_phishing_probability': probability, 'ml_status': 'available',
                    'ml_phishing_probability': probability * 100,
                    'ml_legitimate_probability': (1 - probability) * 100,
                    'ml_label': 'Likely Phishing' if probability > 0.5 else 'Likely Legitimate'}

        with patch.object(app, '_content_pipeline', {'metrics': {}, 'decision_threshold': 0.5}), \
                patch.object(app, 'predict_content', side_effect=predict):
            _, data, _ = self.call({'observations': [observation(
                ocr_text=caption, qr_payloads=[qr, '', qr, '  '])]})
        self.assertEqual(seen, ['', caption, qr])
        self.assertEqual(data['risk_level'], 'high')
        record = data['visual_analysis']['observations'][0]
        self.assertEqual(record['ml_status'], 'available')
        self.assertEqual(record['ml_phishing_probability'], 94)
        self.assertEqual(record['assessed_source_count'], 2)
        self.assertTrue(any('highest individual source score' in warning
                            for warning in record['assessment_warnings']))

    def test_maximum_visual_request_keeps_each_of_36_sources_separate(self):
        observations = [observation(name=f'image-{image}.png',
            ocr_text=f'Team agenda number {image}.',
            qr_payloads=[f'Meeting document {image} number {qr}.' for qr in range(8)])
            for image in range(4)]
        original = app._analyze_content
        seen = []

        async def analyze(content, *args, **kwargs):
            seen.append((content.body, kwargs))
            return await original(content, *args, **kwargs)

        with patch.object(app, '_analyze_content', side_effect=analyze):
            status, data, _ = self.call({'observations': observations})
        self.assertEqual(status, 200)
        expected = [text for item in observations for text in [item['ocr_text'], *item['qr_payloads']]]
        self.assertEqual([text for text, _ in seen], ['', *expected])
        self.assertTrue(all(options['plain_text'] and not options['observe_sender_history']
                            for _, options in seen[1:]))
        self.assertEqual([item['assessed_source_count'] for item in data['visual_analysis']['observations']],
                         [9] * 4)

    def test_visual_input_validation_and_existing_small_endpoint_limit(self):
        for payload in [{'observations': [observation(risk_level='safe')]},
                        {'observations': [observation(ocr_confidence=float('nan'))]},
                        {'observations': [observation(ocr_text='x'*6001)]},
                        {'observations': [observation()]*5},
                        {'eml_base64': 'not base64!'}, {'risk_level': 'safe'}]:
            app._rate_limit_buckets.clear()
            self.assertEqual(self.call(payload)[0], 422)
        self.assertEqual(self.call({})[0], 400)
        self.assertEqual(self.call({'body': 'x'*70000}, '/api/analyze-content')[0], 413)

    def test_larger_image_email_keeps_text_bounded(self):
        raw = b'Subject: Large\n\n' + b'normal text ' * 10000
        status, data, _ = self.call({'eml_base64': base64.b64encode(raw).decode()})
        self.assertEqual(status, 200)
        self.assertFalse(data['analysis_complete'])
        self.assertTrue(any('text limit' in warning for warning in data['analysis_warnings']))

    def test_visual_case_auth_and_persisted_provenance(self):
        from test_case_api import CaseAPITests
        fixture = CaseAPITests(); fixture.setUp()
        try:
            payload = {'observations': [observation(ocr_text='https://paypa1.example/login',
                ocr_url_line_confidence=48)]}
            key = '00000000-0000-4000-8000-000000000099'
            self.assertEqual(asyncio.run(request('POST', '/api/cases/visual', payload=payload, token=None, key=key))[0], 401)
            status, case, _ = fixture.call('POST', '/api/cases/visual', payload=payload, key=key)
            self.assertEqual(status, 201)
            self.assertIn(case['risk'], {'high', 'critical'})
            self.assertEqual(case['analysis']['visual_analysis']['provenance'], 'browser_extracted_unverified')
            self.assertEqual(case['analysis']['visual_analysis']['observations'][0]['ocr_url_line_confidence'], 48)
            self.assertEqual(fixture.call('GET', '/api/cases/' + case['id'])[1]
                             ['analysis']['visual_analysis']['observations'][0]['ocr_url_line_confidence'], 48)
            self.assertNotIn('eml_base64', case['source'])
            self.assertEqual(fixture.call('POST', '/api/cases/visual', payload=payload, key=key)[1]['id'], case['id'])
            payload['observations'][0]['ocr_text'] = 'changed'
            self.assertEqual(fixture.call('POST', '/api/cases/visual', payload=payload, key=key)[0], 409)
        finally:
            fixture.tearDown()

    def test_visual_case_retains_text_but_not_inline_image_bytes(self):
        from email.message import EmailMessage
        from test_case_api import CaseAPITests
        image = base64.b64encode((app.BASE_DIR / 'tests/fixtures/vision/synthetic-qr.png').read_bytes()).decode()
        mail = EmailMessage()
        mail['Subject'] = 'Inline image'
        mail.set_content('Literal <style>URGENT</style> text. data:image/png;base64,' + image)
        mail.add_alternative('<p>Visible message</p><img src="data:image/png;base64,' + image + '">', subtype='html')
        fixture = CaseAPITests(); fixture.setUp()
        try:
            status, case, _ = fixture.call('POST', '/api/cases/visual', key='00000000-0000-4000-8000-000000000100', payload={
                'eml_base64': base64.b64encode(mail.as_bytes()).decode(),
                'observations': [observation(source='data-uri')]})
            self.assertEqual(status, 201)
            self.assertNotIn(image, json.dumps(case))
            self.assertIn('Literal <style>URGENT</style> text.', case['source']['body'])
            self.assertIn('Visible message', case['source']['body'])
            self.assertNotIn('<img', case['source']['body'])
            self.assertEqual(case['analysis']['visual_analysis']['observations'][0]['qr_payloads'],
                             ['https://paypa1.example/login'])
        finally:
            fixture.tearDown()

    def test_visual_case_marks_previously_truncated_text(self):
        raw = b'Subject: Large\n\n' + b'normal text ' * 10000
        source, _, _ = asyncio.run(app._analyze_case(app.VisualRequest(
            eml_base64=base64.b64encode(raw).decode()), None))
        self.assertTrue(source['text_truncated'])


if __name__ == '__main__':
    unittest.main()
