"""The committed text model may come from public corpora only (docs/llm-teacher.md).

The model artifact is in a public repository, and a TF-IDF vocabulary keeps words from its
training mail (names, order numbers, addresses). A model trained on the owner's mail, even with
labels a language model proposed, must stay private: this fails if the committed artifact
names a training source outside the public corpora below.
"""
import json
import re
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

PUBLIC_CORPUS_FILES = {
    'Phishing_Email.csv', 'CEAS_08.csv', 'Nazario.csv', 'phishnchips_core.csv', 'phishnchips_legit_v5.csv',
    'phishnchips_infra.csv', 'phishfuzzer_train.csv', 'phishfuzzer_val.csv', 'phishfuzzer_test.csv', 'SpaPhish.csv',
}
PUBLIC_SAMPLE_SOURCES = {'real-corpus', 'SpaPhish-training', 'hard-negative-synthetic'}


class ArtifactProvenanceTests(unittest.TestCase):
    def test_the_committed_model_was_trained_on_public_corpora_only(self):
        root = WEBSITE_DIR.parent
        if f'{sys.version_info.major}.{sys.version_info.minor}' != (root / '.python-version').read_text().strip():
            self.skipTest('Committed artifact targets another Python version')
        from content_inference import load_content_pipeline_artifact

        profile = json.loads((root / 'vercel.json').read_text())['env']
        metrics = load_content_pipeline_artifact(
            root / profile['CONTENT_MODEL_ARTIFACT'], profile['CONTENT_MODEL_ARTIFACT_SHA256'])['metrics']
        files = set(re.findall(r'[\w.-]+\.csv\b', metrics['data_source']))
        self.assertTrue(files)
        self.assertLessEqual(files, PUBLIC_CORPUS_FILES)
        self.assertLessEqual(set(metrics['source_sample_counts']), PUBLIC_SAMPLE_SOURCES)
        self.assertNotRegex(metrics['data_source'], r'(?i)private|own[-_ ]mail|mailbox|teacher|mbox')


if __name__ == '__main__':
    unittest.main()
