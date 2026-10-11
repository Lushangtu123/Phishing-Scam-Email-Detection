"""Training on a reviewed private mailbox (docs/llm-teacher.md): its rows join the training side
only, the model is marked private, and a private model stays out of the repository and out of
public services (synthetic rows standing in for private mail)."""
import csv
import dataclasses
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import content_inference  # noqa: E402
import content_model  # noqa: E402

MARKER = 'quokkazephyr'  # a word that exists only in the private rows


TOPICS = ['garden', 'chess', 'choir', 'hiking', 'pottery', 'cycling', 'baking', 'rowing', 'poetry', 'tennis',
          'quilting', 'birding', 'climbing', 'sailing', 'origami', 'painting', 'running', 'fishing', 'knitting',
          'yoga', 'cinema', 'robotics', 'astronomy', 'karate', 'dancing', 'debate', 'theatre', 'kayaking',
          'archery', 'fencing', 'juggling', 'calligraphy', 'beekeeping', 'woodwork', 'skating', 'surfing',
          'gardening', 'photography', 'volunteering', 'tutoring']
PLACES = ['library', 'school hall', 'community centre', 'park pavilion', 'church annex', 'town square']
BANKS = ['northwind', 'contoso', 'fabrikam', 'tailspin', 'woodgrove', 'litware']


def write_private_corpus(directory: Path) -> Path:
    """40 legitimate and 6 phishing rows, each about a different thing (no near-duplicates)."""
    path = directory / 'labelled.csv'
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, ['sender', 'receiver', 'date', 'subject', 'body', 'urls', 'label'])
        writer.writeheader()
        for index, topic in enumerate(TOPICS):
            place = PLACES[index % len(PLACES)]
            writer.writerow({'sender': f'{topic}@example.org', 'receiver': 'me@example.net', 'date': '2026-09-01',
                             'subject': f'The {topic} club this week',
                             'body': f'Hi, the {MARKER} {topic} club meets at the {place} this week. '
                                     f'Bring your {topic} gear and a friend who likes {TOPICS[index - 1]}.',
                             'urls': '', 'label': 0})
        for bank in BANKS:
            writer.writerow({'sender': f'alerts@{bank}-secure.test', 'receiver': 'me@example.net', 'date': '2026-09-02',
                             'subject': f'{bank.title()} account locked',
                             'body': f'Your {MARKER} {bank} account is locked. Verify your password at '
                                     f'https://{bank}-secure.test/verify within a day or it will be closed.',
                             'urls': '', 'label': 1})
    return path


def build(private_corpus=None, use_cache=False):
    return content_model.build_content_pipeline(use_real=False, n_variants=4, auto_download=False,
                                                use_cache=use_cache, fast_mode=True,
                                                private_corpus=private_corpus)


class PrivateTrainingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.corpus = write_private_corpus(Path(cls.directory.name))
        cls.cache = Path(cls.directory.name) / 'cache.pkl'
        with patch.object(content_model, '_cache_path', return_value=cls.cache):
            # use_cache=True asks for the cache: a private build must neither read nor write it.
            cls.private = build(cls.corpus, use_cache=True)
        cls.public = build()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_private_rows_join_the_training_side_only(self):
        metrics = self.private['metrics']
        self.assertEqual(metrics['source_sample_counts']['private-mailbox'], 46)
        self.assertEqual(metrics['n_train'], self.public['metrics']['n_train'] + 46)
        # The split is drawn before private rows are added, so the test side is unchanged.
        self.assertEqual(metrics['n_test'], self.public['metrics']['n_test'])
        self.assertEqual(metrics['group_overlap'], 0)

    def test_the_model_card_has_counts_and_a_digest_but_no_private_text(self):
        metrics = self.private['metrics']
        self.assertTrue(metrics['private_training'])
        self.assertIn('Private mailbox rows, training side only (n=46: 6 phishing / 40 legitimate',
                      metrics['data_source'])
        self.assertEqual(metrics['build_provenance']['private_corpus_sha256'],
                         hashlib.sha256(self.corpus.read_bytes()).hexdigest())
        self.assertNotIn(MARKER, json.dumps(metrics))
        self.assertNotIn('private_training', self.public['metrics'])

    def test_a_private_build_does_not_use_the_cache(self):
        self.assertFalse(self.cache.exists())

    def test_the_private_corpus_and_the_artifact_stay_outside_the_repository(self):
        with self.assertRaisesRegex(ValueError, 'outside the repository'):
            build(WEBSITE_DIR.parent / 'phishing-detection' / 'data' / 'labelled.csv')
        target = WEBSITE_DIR / 'model' / 'private.pkl'
        self.addCleanup(target.unlink, missing_ok=True)  # should the guard ever fail
        with self.assertRaisesRegex(ValueError, 'outside the repository'):
            content_model.save_content_pipeline_artifact(self.private, target)
        self.assertFalse(target.exists())

    def test_loaders_refuse_a_private_model_unless_allowed(self):
        path = Path(self.directory.name) / 'private.pkl'
        digest = content_model.save_content_pipeline_artifact(self.private, path)
        for loader in (content_model.load_content_pipeline_artifact, content_inference.load_content_pipeline_artifact):
            with self.subTest(loader=loader.__module__):
                with self.assertRaisesRegex(ValueError, 'trained on private mail'):
                    loader(path, digest)
                self.assertTrue(loader(path, digest, allow_private=True)['metrics']['private_training'])

    def test_only_a_development_server_loads_a_private_model(self):
        path = Path(self.directory.name) / 'served.pkl'
        digest = content_model.save_content_pipeline_artifact(self.private, path)
        for app_env, allowed in (('development', True), ('demo', False), ('production', False)):
            with self.subTest(app_env=app_env), \
                    patch.object(app, 'SETTINGS', dataclasses.replace(app.SETTINGS, app_env=app_env)):
                if allowed:
                    self.assertTrue(app.load_content_pipeline_artifact(path, digest)['metrics']['private_training'])
                else:
                    with self.assertRaisesRegex(ValueError, 'trained on private mail'):
                        app.load_content_pipeline_artifact(path, digest)

    def test_a_public_model_still_loads_everywhere(self):
        path = Path(self.directory.name) / 'public.pkl'
        digest = content_model.save_content_pipeline_artifact(self.public, path)
        with patch.object(app, 'SETTINGS', dataclasses.replace(app.SETTINGS, app_env='production')):
            self.assertNotIn('private_training', app.load_content_pipeline_artifact(path, digest)['metrics'])


if __name__ == '__main__':
    unittest.main()
