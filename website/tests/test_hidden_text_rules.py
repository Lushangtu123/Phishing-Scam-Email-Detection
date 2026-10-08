"""The request and lure rules that set a floor also read text that styles may hide (2026-10-05).

Eleven reviews from 2026-10-01 to 10-03 each found a style this reader misjudged (a gradient,
calc(), clamp(), atan2(), color-mix(), a custom property's case, print-only CSS), so that a
visible callback scam read as hidden text and came out Safe or Low. Whatever the styles, a
scam request is now found: in what the message shows, or marked as text it may hide, with a
Medium floor. The model and the keyword score still never read hidden text (synthetic inputs).
"""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
from hidden_findings import hidden_codes, shown_codes  # noqa: E402

CALLBACK = ('Your subscription renewal of $499 is complete. If you did not authorize this charge, '
            'call 1-888-555-0199 immediately.')
PADDING = 'Please review the project notes before our meeting tomorrow. ' * 30
MAILBOX = ('<p>Your mailbox storage is full and incoming messages are on hold.</p>'
           '<a {attributes} href="https://portal.example.org/review">Release messages</a>')

# Styles the reviews used, styles that hide text for certain, and styles that never do.
DECLARATIONS = (
    'color:black;background:linear-gradient(black,black)',
    'color:black;background:linear-gradient(to left top,black,black)',
    'color:black;background:linear-gradient(calc(45deg),black,black)',
    'color:black;background:linear-gradient(atan2(calc(1px * 1px),calc(1px * 1px)),black,black)',
    'color:white;background:linear-gradient(calc(1deg * (1% / 1%)),black,black)',
    'color:black;background:linear-gradient(black,black);background-clip:text;background-clip:env(no-such-env,text)',
    'color:black;background:linear-gradient(black calc((1s + 1%) * 1px / 1s),black)',
    'color:black;background:banana black',
    'color:black;background:black',
    '-webkit-background-clip:text;color:transparent',
    'color:transparent',
    'font-size:0',
    'font-size:max(-1px,0px)',
    'opacity:0',
    'display:none',
    'visibility:hidden',
    'position:absolute;left:-9999px',
    'color:red',
)


def analyze(body, subject='Project update'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(subject=subject, body=body))).body)


def found(result, code):
    return [item for item in result['extra_indicators'] if item.get('code') == code]


class FailClosedTests(unittest.TestCase):
    def test_no_style_clears_a_scam_request(self):
        for declarations in DECLARATIONS:
            for body in (f'<style>.unused{{display:none}}.attack{{{declarations}}}</style>'
                         f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>',
                         f'<p style="{declarations}">{CALLBACK}</p><p>{PADDING}</p>',
                         f'<style>@media print{{.attack{{{declarations}}}}}</style>'
                         f'<p class="attack">{CALLBACK}</p><p>{PADDING}</p>'):
                with self.subTest(body=body[:90]):
                    result = analyze(body)
                    self.assertIn('content.callback_request', shown_codes(result) | hidden_codes(result))
                    self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})

    def test_a_finding_only_hidden_text_makes_is_a_marked_medium_alert(self):
        result = analyze(f'<p>Team lunch on Friday at noon.</p><div style="display:none">{CALLBACK}</div>')
        [item] = found(result, 'content.callback_request')
        self.assertEqual(item['level'], 'medium')
        self.assertEqual([prefix['code'] for prefix in item['prefixes']], ['prefix.hidden_text'])
        self.assertTrue(item['msg'].startswith('In text the message may hide: '))
        self.assertEqual((result['risk_level'], result['risk_label']), ('medium', 'Medium Risk — Suspicious Content'))
        self.assertEqual(result['mail_type'], {'type': 'phishing', 'tactics': ['callback']})

    def test_a_shown_finding_is_not_repeated_as_hidden(self):
        result = analyze(f'<p>{CALLBACK}</p><div style="display:none">{CALLBACK}</div>')
        self.assertEqual(len(found(result, 'content.callback_request')), 1)
        self.assertEqual(hidden_codes(result), set())
        self.assertIn(result['risk_level'], {'high', 'critical'})

    def test_hidden_lure_labels_are_read_as_hidden_text(self):
        result = analyze(MAILBOX.format(attributes='style="display:none"'))
        self.assertNotIn('content.mailbox_lure', shown_codes(result))
        self.assertIn('content.mailbox_lure', hidden_codes(result))
        self.assertEqual(result['risk_level'], 'medium')
        # Shown, the same lure keeps its High finding.
        shown = analyze(MAILBOX.format(attributes='class="button"'))
        self.assertIn('content.mailbox_lure', shown_codes(shown))
        self.assertIn(shown['risk_level'], {'high', 'critical'})

    def test_hidden_keywords_add_no_points(self):
        # Only the floor-setting request and lure rules read hidden text, not keyword categories.
        result = analyze('<p>Team lunch on Friday at noon.</p><div style="display:none">'
                         'URGENT: verify your account immediately or it will be suspended.</div>')
        self.assertEqual(result['category_results'], [])
        self.assertEqual(hidden_codes(result), set())
        self.assertEqual(result['total_score'], 0)

    def test_text_nothing_hides_has_no_hidden_reading(self):
        for body in ('<p>Team lunch on Friday at noon.</p>', 'Team lunch on Friday at noon.'):
            with self.subTest(body=body):
                self.assertEqual(hidden_codes(analyze(body)), set())

    def test_a_hidden_finding_never_lets_the_model_score_hidden_text(self):
        # A stand-in model that reads the hidden padding as phishing: the renderings disagree,
        # so it abstains as before, and the hidden request alone makes the alert Medium.
        def predict(_pipeline, _subject, body, **_kwargs):
            probability = 0.95 if 'password' in body else 0.05
            return {'ml_status': 'available', 'ml_phishing_probability': probability * 100,
                    '_phishing_probability': probability, 'ml_legitimate_probability': 100 - probability * 100,
                    'ml_label': None, 'ml_prediction': int(probability > 0.5), 'ml_top_contributors': []}
        padding = 'Urgent: enter your password now or your account will be suspended. ' * 5
        with patch.object(app, '_content_pipeline', {'decision_threshold': 0.35, 'metrics': {}}), \
                patch.object(app, 'predict_content', side_effect=predict):
            result = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(
                subject='Project notes', body='<style>.pad{display:none}</style><p>Please review the agenda.</p>'
                                              f'<div class="pad">{padding}</div>'))).body)
        self.assertEqual(result['ml_status'], 'unverified_rendering')
        self.assertEqual(result['risk_level'], 'medium')
        self.assertEqual(hidden_codes(result), {'content.pressured_credential_request'})

    def test_the_prefix_message(self):
        self.assertEqual(app.message_text('prefix.hidden_text', text='Callback request'),
                         'In text the message may hide: Callback request')


if __name__ == '__main__':
    unittest.main()
