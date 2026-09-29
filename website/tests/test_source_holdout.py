import json
import sys
import unittest
from pathlib import Path

import numpy as np

WEBSITE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = WEBSITE_DIR.parent
sys.path.insert(0, str(WEBSITE_DIR))

import content_model  # noqa: E402
from tools import evaluate_source_holdout as holdout  # noqa: E402


class RecordingModel:
    """Scores 'urgent' text as phishing and records every training set it sees."""
    fits: list = []

    def fit(self, texts, labels):
        RecordingModel.fits.append(list(texts))
        return self

    def predict_proba(self, texts):
        scores = np.array([0.9 if "urgent" in text else 0.1 for text in texts])
        return np.column_stack([1 - scores, scores])


def corpus(prefix, phishing, legitimate):
    texts = [f"{prefix} urgent verify account {i}x" for i in range(phishing)]
    texts += [f"{prefix} meeting notes agenda {i}y" for i in range(legitimate)]
    labels = [1] * phishing + [0] * legitimate
    return texts, labels, [f"{prefix}-{i}" for i in range(len(texts))]


class SourceHoldoutTests(unittest.TestCase):
    def setUp(self):
        RecordingModel.fits = []

    def test_a_held_out_corpus_is_never_part_of_its_training_set(self):
        sources = {"alpha": corpus("alpha", 3, 3), "beta": corpus("beta", 2, 4), "gamma": corpus("gamma", 0, 5)}
        report = holdout.evaluate(sources, make_model=RecordingModel, thresholds=(0.5,),
                                  in_distribution=False, progress=lambda _message: None)
        self.assertEqual(list(report["sources"]), ["alpha", "beta", "gamma"])
        for name, training_texts in zip(sources, RecordingModel.fits):
            self.assertTrue(training_texts)
            self.assertFalse(set(training_texts) & set(sources[name][0]), name)
            self.assertEqual(len(training_texts), sum(len(s[0]) for n, s in sources.items() if n != name))

    def test_metrics_follow_the_threshold_and_omit_rates_without_a_denominator(self):
        metrics = holdout.score_metrics([1, 1, 0, 0], [0.9, 0.2, 0.6, 0.1], (0.5,))
        at = metrics["at_threshold"]["0.5"]
        self.assertEqual((at["phishing_recall"]["count"], at["phishing_recall"]["of"]), (1, 2))
        self.assertEqual((at["false_positive_rate"]["count"], at["false_positive_rate"]["of"]), (1, 2))
        self.assertEqual(metrics["pr_auc"], 0.8333)
        self.assertEqual(metrics["roc_auc"], 0.75)

        phishing_only = holdout.score_metrics([1, 1, 1], [0.9, 0.4, 0.8], (0.5,))
        self.assertIsNone(phishing_only["pr_auc"])
        self.assertIsNone(phishing_only["at_threshold"]["0.5"]["false_positive_rate"])
        self.assertEqual(phishing_only["at_threshold"]["0.5"]["phishing_recall"]["value"], 0.6667)

    def test_a_corpus_is_skipped_when_the_others_lack_a_label(self):
        sources = {"phish_only": corpus("p", 4, 0), "legit_only": corpus("l", 0, 4)}
        report = holdout.evaluate(sources, make_model=RecordingModel, thresholds=(0.5,),
                                  in_distribution=False, progress=lambda _message: None)
        self.assertIsNone(report["sources"]["phish_only"]["held_out"])
        self.assertIn("lack one of the two labels", report["sources"]["phish_only"]["skipped"])
        self.assertEqual(RecordingModel.fits, [])

    def test_in_distribution_baseline_scores_every_row_once(self):
        sources = {"alpha": corpus("alpha", 6, 6), "beta": corpus("beta", 6, 6)}
        report = holdout.evaluate(sources, make_model=RecordingModel, thresholds=(0.5,), folds=2,
                                  progress=lambda _message: None)
        self.assertEqual(report["pooled_in_distribution"]["rows"], 24)
        self.assertEqual(report["sources"]["alpha"]["in_distribution"]["rows"], 12)
        self.assertEqual(len(RecordingModel.fits), 2 + 2)

    def test_duplicates_are_kept_once_and_label_conflicts_are_dropped_everywhere(self):
        sources = {
            "first": (["Reset code 123 now", "shared family", "Only here"], [1, 0, 0], ["a", "b", "c"]),
            "second": (["reset code 456 now", "Shared family", "Unique"], [1, 1, 1], ["d", "e", "f"]),
        }
        result, stats = holdout.deduplicate_across_sources(sources)
        self.assertEqual(result["first"][0], ["Reset code 123 now", "Only here"])
        self.assertEqual(result["second"][0], ["Unique"])
        self.assertEqual(result["first"][2], ["first:a", "first:c"])
        self.assertEqual(stats, {"input_rows": 6, "duplicate_rows_removed": 1, "label_conflict_rows_removed": 2,
                                 "label_conflict_families": 1, "output_rows": 3})

    def test_normalized_model_only_adds_the_normalization_step(self):
        normalized = holdout.make_normalized_model()
        production = holdout.make_production_model()
        self.assertEqual(normalized.steps[0][1].transform(["Meet 10:30 PM, 2005 at http://x.example"]),
                         ["Meet zztime , zzyear at zzurl"])
        self.assertEqual([type(step).__name__ for _name, step in normalized.steps[1:]],
                         [type(step).__name__ for _name, step in production.steps])
        self.assertEqual(normalized.steps[-1][1].get_params(), production.steps[-1][1].get_params())

    def test_evaluated_configuration_matches_the_committed_artifact(self):
        deployment_python = (PROJECT_ROOT / ".python-version").read_text().strip()
        current_python = f"{sys.version_info.major}.{sys.version_info.minor}"
        if current_python != deployment_python:
            self.skipTest(f"committed artifact targets Python {deployment_python}, not {current_python}")
        from content_inference import load_content_pipeline_artifact
        profile = json.loads((PROJECT_ROOT / "vercel.json").read_text())["env"]
        artifact = load_content_pipeline_artifact(PROJECT_ROOT / profile["CONTENT_MODEL_ARTIFACT"],
                                                  profile["CONTENT_MODEL_ARTIFACT_SHA256"])

        keys = ("C", "solver", "class_weight", "max_iter")
        deployed = artifact["clf"].get_params()
        evaluated = holdout.production_classifier().get_params()
        self.assertEqual({k: deployed[k] for k in keys}, {k: evaluated[k] for k in keys})
        self.assertEqual(round(artifact["decision_threshold"], 4), holdout.DEPLOYED_THRESHOLD)

        vectorizer_keys = ("analyzer", "ngram_range", "min_df", "max_df", "max_features", "sublinear_tf", "lowercase")
        fresh = dict(content_model._build_vectorizer().transformer_list)
        for name, transformer in artifact["vectorizer"].transformer_list:
            with self.subTest(vectorizer=name):
                self.assertEqual({k: transformer.get_params()[k] for k in vectorizer_keys},
                                 {k: fresh[name].get_params()[k] for k in vectorizer_keys})


if __name__ == "__main__":
    unittest.main()
