"""Presentation cues (many links, exclamation marks, capitals, repeated calls to action, a
doubled question mark) back a model alert but never outweigh a model reading below the
threshold. With no model reading they count as before (synthetic inputs)."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

SUBJECT = 'Your weekly community digest'
LINKS = ' '.join(f'https://community.example.org/story/{i}' for i in range(8))
# Two keyword categories and a large amount (4 points), with exclamation marks and eight
# links (2 presentation points): the pattern of a genuine community digest.
DIGEST = ('Top stories from your community this week! One reader explains how a small bakery grew to '
          '$4,500,000 in yearly sales. Another shares what she learned selling handmade lamps on Amazon. '
          'A volunteer writes on behalf of the local library about the reading club! Join the discussion! '
          + LINKS)
THRESHOLD = 0.3736


class ConstantClassifier:
    def __init__(self, probability):
        self.probability = probability

    def predict_proba(self, features):
        return np.array([[1 - self.probability, self.probability]] * features.shape[0])


def analyze(body, probability=None):
    pipeline = None if probability is None else {
        'vectorizer': TfidfVectorizer().fit([SUBJECT + ' ' + body]), 'clf': ConstantClassifier(probability),
        'decision_threshold': THRESHOLD, 'metrics': {}}
    with patch.object(app, '_content_pipeline', pipeline):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(subject=SUBJECT, body=body),
                                                           observe_sender_history=False)).body)


def fuse(**kwargs):
    return app.fuse_content_risk(ml_decision_threshold=THRESHOLD, **kwargs)


class FusionTests(unittest.TestCase):
    def test_cues_make_no_alert_against_a_legitimate_reading(self):
        for probability in (0.0, 0.10, 0.30):
            with self.subTest(probability=probability):
                self.assertEqual(fuse(ml_phishing_probability=probability, heuristic_score=6,
                                      presentation_score=2)['risk_level'], 'low')
        # The same points from findings alert, and a floor holds.
        self.assertEqual(fuse(ml_phishing_probability=0.10, heuristic_score=6)['risk_level'], 'medium')
        self.assertEqual(fuse(ml_phishing_probability=0.10, heuristic_score=6, presentation_score=2,
                              minimum_level='medium')['risk_level'], 'medium')

    def test_cues_count_without_a_reading(self):
        # The model abstained (too little text, no coverage) or is off: rules decide as before.
        self.assertEqual(fuse(ml_phishing_probability=None, heuristic_score=6, presentation_score=2)['risk_level'],
                         'medium')

    def test_cues_back_a_model_alert(self):
        result = fuse(ml_phishing_probability=0.45, heuristic_score=1, presentation_score=1)
        self.assertEqual((result['risk_level'], result['fusion_basis']), ('high', 'model_led'))
        result = fuse(ml_phishing_probability=0.45, heuristic_score=0)
        self.assertEqual((result['risk_level'], result['fusion_basis']), ('medium', 'model_only'))


class MessageTests(unittest.TestCase):
    def test_the_digest_scores(self):
        rules = app.analyze_email_content(SUBJECT, DIGEST)
        self.assertEqual((rules['total_score'], rules['presentation_score'], rules['risk_floor']), (6, 2, 'safe'))

    def test_a_legitimate_reading(self):
        result = analyze(DIGEST, 0.10)
        self.assertEqual(result['risk_level'], 'low')
        self.assertNotIn('presentation_score', result)

    def test_a_phishing_reading(self):
        result = analyze(DIGEST, 0.45)
        self.assertEqual((result['risk_level'], result['fusion_basis']), ('high', 'model_led'))

    def test_without_the_model(self):
        self.assertEqual(analyze(DIGEST)['risk_level'], 'medium')

    def test_findings_still_alert(self):
        lure = DIGEST.replace('Join the discussion!', 'Act now: your account suspended, respond within 24 hours!')
        self.assertEqual(analyze(lure, 0.10)['risk_level'], 'medium')


if __name__ == '__main__':
    unittest.main()
