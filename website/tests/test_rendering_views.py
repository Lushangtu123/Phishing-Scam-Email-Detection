import asyncio
import json
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402


def readings(html):
    views = {}
    app._visible_content_text(html, [], readings=views)
    return views


def stand_in_model(flagged):
    """A model that flags any text containing one of the given words."""
    def predict(_pipeline, _subject, body, **_kwargs):
        probability = 0.9 if any(word in body for word in flagged) else 0.05
        return {'ml_status': 'available', 'ml_phishing_probability': probability * 100,
                '_phishing_probability': probability, 'ml_legitimate_probability': 100 - probability * 100,
                'ml_label': None, 'ml_prediction': int(probability > 0.5), 'ml_top_contributors': []}
    return predict


def analyze(subject, body):
    return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


class StylesheetTargetTests(unittest.TestCase):
    def test_hiding_rules_are_reduced_to_the_classes_and_ids_they_can_reach(self):
        css = ('.preheader{display:none!important;max-height:0} .mobile{display:none}'
               ' @media (max-width:600px){.mobile{display:block}} u + .body .gmail-hide{display:none} #promo{visibility:hidden}'
               ' *[class="gmail-fix"]{display:none} table[class~="a,b"]{display:none} a::before{display:none}'
               ' span.tiny:hover{font-size:0} .pad{content:"}"; display:none} p{color:red}')
        targets = app._stylesheet_hidden_targets(css)
        self.assertEqual(targets['union'], (
            frozenset({'preheader', 'mobile', 'gmail-hide', 'tiny', 'pad'}), frozenset({'promo'}),
            frozenset({'gmail-fix', 'a,b'})))
        # The base view hides .mobile; the (max-width:600px) view shows it again, and
        # hovering .tiny is an interaction context of its own.
        base, *others = targets['views']
        self.assertIn(('class', 'mobile'), base)
        self.assertNotIn(('class', 'tiny'), base)
        self.assertTrue(any(('class', 'mobile') not in view and ('class', 'preheader') in view for view in others))
        self.assertTrue(any(('class', 'tiny') in view for view in others))

    def test_rules_that_could_hide_any_element_are_not_modelled(self):
        for css in ('div{display:none}', '*{opacity:0}', 'div:not(.show){display:none}',
                    '.a { display:none; .b { color:red } }', '@page{display:none}', '.\\31 x{display:none}'):
            with self.subTest(css=css):
                self.assertIsNone(app._stylesheet_hidden_targets(css))


class RenderingReadingTests(unittest.TestCase):
    def test_strict_and_outlook_views_drop_uncertain_and_client_specific_text(self):
        views = readings(
            '<style>.pre{display:none}</style><div class="pre">Preheader <b>line</b></div><p>Your code is 123456.</p>'
            '<!--[if mso]><p>Outlook table text</p><![endif]-->'
            '<!--[if !mso]><!--><p>Web-only button</p><!--<![endif]-->'
            '<span style="font-size:0">tiny</span><div style="display:none">hidden note</div>')
        self.assertTrue(views['resolved'])
        self.assertEqual(views['strict'], 'Your code is 123456. Web-only button')
        self.assertEqual(views['outlook'], 'Your code is 123456. Outlook table text')
        self.assertIn('hidden note', views['hidden'])
        self.assertIn('Preheader line', views['hidden'])

    def test_plain_html_needs_no_views_and_unmodelled_markup_stays_unresolved(self):
        self.assertEqual(readings('<p>Ordinary visible text.</p>'), {})
        for html in ('<style>div{display:none}</style><p>Text</p><div>More</div>',
                     '<p>Text</p><!--[if mso]><p>Branch without its closing condition</p>-->',
                     '<p>Text</p><img src="https://img.example/x.png" alt="Enter your password to continue here">'):
            with self.subTest(html=html[:30]):
                self.assertFalse(readings(html)['resolved'])

    def test_sentinel_characters_in_the_message_cannot_forge_client_branches(self):
        views = readings('<p>Visible to everyone</p><!--[if mso]><p>Outlook</p><![endif]-->')
        self.assertEqual(views['strict'], 'Visible to everyone')


class RenderingDecisionTests(unittest.TestCase):
    pipeline = {'decision_threshold': 0.35, 'metrics': {}}

    def run_with(self, flagged, html, subject='Update'):
        with patch.object(app, '_content_pipeline', self.pipeline), \
                patch.object(app, 'predict_content', side_effect=stand_in_model(flagged)):
            return analyze(subject, html)

    def test_agreeing_views_give_a_verdict_and_keep_the_warnings_listed(self):
        html = ('<style>.pre{display:none}</style><div class="pre">Your receipt</div>'
                '<p>Thanks for your order of the blue notebook.</p><!--[if mso]><p>Order table</p><![endif]-->')
        result = self.run_with(('payout',), html)
        self.assertEqual(result['ml_status'], 'available')
        self.assertIn(result['risk_level'], {'safe', 'low'})
        self.assertFalse(result['analysis_complete'])
        self.assertIn('content.rendering_views_agree', [item['code'] for item in result['extra_indicators']])

    def test_class_hidden_text_that_changes_the_decision_abstains_both_ways(self):
        for html in ('<style>.pad{display:none}</style><p>Confirm the payout now.</p><div class="pad">padding</div>',
                     '<style>.pad{display:none}</style><p>Team lunch on Friday.</p><div class="pad">payout</div>'):
            with self.subTest(html=html[40:70]):
                flagged = ('payout',) if 'padding' not in html else ()
                predict = stand_in_model(('payout',))

                def diluted(pipeline, subject, body, **kwargs):
                    # Padding dilutes the flagged words, as benign filler does for a real model.
                    return predict(pipeline, subject, '' if 'padding' in body else body, **kwargs)
                with patch.object(app, '_content_pipeline', self.pipeline), \
                        patch.object(app, 'predict_content', side_effect=diluted if not flagged else predict):
                    result = analyze('Update', html)
                self.assertEqual(result['ml_status'], 'unverified_rendering')
                self.assertEqual(result['risk_level'], 'unknown')

    def test_definitely_hidden_text_blocks_a_clean_verdict_only_if_it_would_alert(self):
        benign = self.run_with(('payout',), '<div style="display:none">Your receipt</div><p>Thanks for your order.</p>')
        self.assertEqual(benign['risk_level'], 'safe')
        flagged = self.run_with(('payout',), '<div style="display:none">payout</div><p>Thanks for your order.</p>')
        self.assertEqual(flagged['risk_level'], 'unknown')

    def test_an_alert_only_from_a_newly_scored_rendering_keeps_the_earlier_abstention(self):
        html = '<p>Please confirm the payout details.</p><!--[if mso]><p>Payout table</p><![endif]-->'
        result = self.run_with(('payout',), html)
        self.assertEqual(result['ml_status'], 'unverified_rendering')
        self.assertEqual(result['risk_level'], 'unknown')
        self.assertNotIn('content.rendering_views_agree', [item['code'] for item in result['extra_indicators']])

    def test_an_alert_the_earlier_scoring_already_had_is_kept(self):
        message = EmailMessage()
        message['Subject'] = 'Update'
        message.set_content('Please confirm the payout details today.')
        message.add_alternative('<p>Please confirm the payout details.</p><!--[if mso]><p>Table</p><![endif]-->',
                                subtype='html')
        with patch.object(app, '_content_pipeline', self.pipeline), \
                patch.object(app, 'predict_content', side_effect=stand_in_model(('payout',))):
            result = json.loads(asyncio.run(app.analyze_content_endpoint(
                app.ContentRequest(raw_email=message.as_string()))).body)
        self.assertEqual(result['ml_status'], 'available')
        self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})

    def test_without_a_model_nothing_is_resolved(self):
        html = '<p>Thanks for your order.</p><!--[if mso]><p>Order table</p><![endif]-->'
        with patch.object(app, '_content_pipeline', None):
            result = analyze('Update', html)
        self.assertEqual(result['risk_level'], 'unknown')


if __name__ == '__main__':
    unittest.main()
