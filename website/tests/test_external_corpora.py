import json
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_external_corpora as external  # noqa: E402


class RecordingModel:
    trained: list = []

    def fit(self, texts, labels):
        RecordingModel.trained = list(texts)
        return self

    def predict_proba(self, texts):
        scores = np.array([0.9 if "urgent" in text else 0.1 for text in texts])
        return np.column_stack([1 - scores, scores])


def seed(number, kind, source, subject="Hello", body="Body"):
    return {"No.": number, "Type": kind, "Source": source, "Subject": subject, "Body": body}


class ExternalCorporaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_difraud_splits_are_combined(self):
        (self.dir / "train.jsonl").write_text('{"text": "a", "label": 1}\n{"text": "b", "label": 0}\n')
        (self.dir / "test.jsonl").write_text('{"text": "c", "label": 0}\n\n')
        self.assertEqual(external.load_difraud(self.dir), {"difraud": (["a", "b", "c"], [1, 0, 0])})
        self.assertEqual(external.load_difraud(self.dir / "missing"), {})

    def test_phishfuzzer_is_split_by_seed_provenance_and_spam_is_kept_apart(self):
        seeds = [seed(1, "Phishing", "Manual", "Urgent", "verify"), seed(2, "Valid", "Manual"),
                 seed(3, "Spam", "Manual", "Sale", "buy"), seed(4, "Valid", "SpamAssassin.csv")]
        rephrased = [{"Original_ID": 1, "Type": "Phishing", "Subject": "S1", "Body": "B1"},
                     {"Original_ID": 4, "Type": "Valid", "Subject": "S4", "Body": "B4"},
                     {"Original_ID": 3, "Type": "Spam", "Subject": "S3", "Body": "B3"}]
        (self.dir / external.PHISHFUZZER_SEEDS).write_text(json.dumps(seeds))
        (self.dir / external.PHISHFUZZER_REPHRASED).write_text(json.dumps(rephrased))
        labelled, spam = external.load_phishfuzzer(self.dir)
        self.assertEqual(labelled["phishfuzzer_recent_seed"], (["Urgent\n\nverify", "Hello\n\nBody"], [1, 0]))
        self.assertEqual(labelled["phishfuzzer_llm_from_recent_seed"], (["S1\n\nB1"], [1]))
        self.assertEqual(labelled["phishfuzzer_llm_from_legacy_seed"], (["S4\n\nB4"], [0]))
        self.assertEqual(spam["phishfuzzer_recent_seed_spam"], (["Sale\n\nbuy"], [1]))
        self.assertEqual(spam["phishfuzzer_llm_from_recent_seed_spam"], (["S3\n\nB3"], [1]))

    def test_messages_already_in_training_are_removed_and_counted(self):
        from content_model import _normalized_text_family
        families = {_normalized_text_family("Your code is 123")}
        kept, removed = external.remove_training_overlap(
            {"set": (["your code is 999", "New message"], [0, 0])}, families)
        self.assertEqual(kept["set"], (["New message"], [0]))
        self.assertEqual(removed["set"], {"input": 2, "overlap_removed": 1})

    def test_external_messages_are_never_trained_on(self):
        training = {"corpus": (["urgent pay", "team lunch"], [1, 0], ["g1", "g2"])}
        sets = {"ext": (["urgent verify", "weekly notes"], [1, 0]), "empty": ([], [])}
        results = external.evaluate(training, sets, make_model=RecordingModel, thresholds=(0.5,))
        self.assertEqual(RecordingModel.trained, ["urgent pay", "team lunch"])
        self.assertEqual(results["ext"]["at_threshold"]["0.5"]["phishing_recall"]["value"], 1.0)
        self.assertEqual(results["ext"]["at_threshold"]["0.5"]["false_positive_rate"]["value"], 0.0)
        self.assertIsNone(results["empty"])

    def test_augmentation_never_trains_on_the_tested_seed_family(self):
        fits = []

        class Recorder(RecordingModel):
            def fit(self, texts, labels):
                fits.append(list(texts))
                return self

        seeds = ([f"seed urgent {i}" if i % 2 else f"seed notes {i}" for i in range(10)],
                 [i % 2 for i in range(10)], [str(i) for i in range(10)])
        variants = ([f"variant {i}-{k}" for i in range(10) for k in range(2)],
                    [i % 2 for i in range(10) for _ in range(2)], [str(i) for i in range(10) for _ in range(2)])
        training = {"corpus": (["urgent pay", "team lunch"], [1, 0], ["g1", "g2"])}
        extra = {"difraud": (["extra urgent", "extra notes"], [1, 0])}
        results = external.augmentation_experiment(training, extra, seeds, variants, make_model=Recorder,
                                                   folds=5, thresholds=(0.5,), progress=lambda _m: None)
        self.assertEqual(set(results), {"C0_training_corpora", "C1_plus_difraud_and_legacy_llm",
                                        "C2_plus_recent_llm_variants_grouped"})
        self.assertEqual(fits[0], ["urgent pay", "team lunch"])
        self.assertEqual(fits[1], ["urgent pay", "team lunch", "extra urgent", "extra notes"])
        self.assertEqual(len(fits), 2 + 5)
        seen_variant_ids = set()
        for training_texts in fits[2:]:
            trained_ids = {text.split()[1].split("-")[0] for text in training_texts if text.startswith("variant")}
            self.assertEqual(len(trained_ids), 8)  # 2 of 10 seed families held out per fold
            seen_variant_ids |= trained_ids
            self.assertTrue(all(not text.startswith("seed") for text in training_texts))
        self.assertEqual(seen_variant_ids, {str(i) for i in range(10)})
        self.assertEqual(results["C2_plus_recent_llm_variants_grouped"]["rows"], 10)

    def test_mbox_messages_become_plain_subject_and_body_even_when_malformed(self):
        from email import message_from_string
        plain_with_html = message_from_string(
            "Subject: Billing\n information\nContent-Type: text/plain; charset=utf-8\n\n"
            "<p><strong>HELLO,</strong></p>\n<p>Pay&amp;go now</p>\n")
        self.assertEqual(external._message_text(plain_with_html), "Billing information\n\nHELLO, Pay&go now")
        html_only = message_from_string(
            "Subject: Reset\nContent-Type: text/html\n\n<html><body><a href='x'>Click</a> here</body></html>\n")
        self.assertEqual(external._message_text(html_only), "Reset\n\nClick here")
        broken = message_from_string(
            'Subject: Hi\nContent-Type: text/plain; charset="utf-8x-priority: 3"\n\nBody text\n')
        self.assertEqual(external._message_text(broken), "Hi\n\nBody text")
        self.assertEqual(external._codec("definitely-not-a-codec"), "utf-8")

    def test_marketing_rows_and_templates_are_parsed(self):
        csv_path = self.dir / "train.csv"
        csv_path.write_text('0\n"Subject: Spring sale\n\nHi Ana,\nSave 20% today."\n"No subject line here"\n')
        self.assertEqual(external.load_marketing(csv_path), ["Spring sale\n\nHi Ana,\nSave 20% today.", "No subject line here"])
        self.assertEqual(external.fill_template("Hi {{name}}, {{#each items}}{{description}}{{/each}} at {{{action_url}}}"),
                         "Hi Alex,  details  at https://app.example.com/account")
        for style, kind in (("basic", "password-reset"), ("basic-full", "password-reset"), ("basic", "example")):
            folder = self.dir / "postmark-templates" / "templates" / style / kind
            folder.mkdir(parents=True)
            (folder / "content.txt").write_text("Reset for {{name}}")
        self.assertEqual(external.load_templates(self.dir), ["Password reset\n\nReset for Alex"])

    def test_uniquedata_rows_split_into_legitimate_and_spam(self):
        csv_path = self.dir / "email_spam.csv"
        csv_path.write_text('title,text,type\n"New  login\nto Instagram","We noticed a login.",not spam\n'
                            '"Win now","Claim your prize",spam\n')
        self.assertEqual(external.load_uniquedata(csv_path),
                         (["New login to Instagram\n\nWe noticed a login."], ["Win now\n\nClaim your prize"]))

    def test_apache_mboxes_are_grouped_deduplicated_and_capped(self):
        def mbox(name, subjects):
            with (self.dir / name).open("w") as handle:
                for subject in subjects:
                    handle.write(f"From x@example.org Mon Jun  2 10:00:00 2025\nSubject: {subject}\n\n"
                                 "Please review the attached change before the release vote closes.\n\n")
        mbox("issues_iceberg_2025-06.mbox", ["[PR] Bump 1", "[PR] Bump 2", "[PR] Fix docs", "[PR] Add API"])
        mbox("users_tomcat_2025-06.mbox", ["Problem accessing https"])
        mbox("user_flink_2025-06.mbox", ["State size question"])
        mbox("private_x_2025-06.mbox", ["Ignored"])
        (self.dir / "short.mbox").write_text("From x Mon Jun  2 10:00:00 2025\nSubject: unsubscribe\n\nbye\n")
        loaded = external.load_apache(self.dir, seed=1, per_category=2)
        self.assertEqual(set(loaded), {"apache_github_notifications", "apache_user_discussion"})
        self.assertEqual(len(loaded["apache_github_notifications"]), 2)  # "Bump 1"/"Bump 2" share a family
        self.assertEqual(loaded, external.load_apache(self.dir, seed=1, per_category=2))
        self.assertEqual(len(loaded["apache_user_discussion"]), 2)

    def test_family_split_is_deterministic_and_keeps_families_together(self):
        texts = [f"message about topic {word}" for word in "abcdefghijklmnopqrstuvwxyz"]
        texts += ["Your code is 123", "your code is 999"]
        train, test = external.split_by_family(texts, 0.3, 42)
        self.assertEqual((train, test), external.split_by_family(texts, 0.3, 42))
        self.assertEqual(sorted(train + test), sorted(texts))
        self.assertTrue(test and train)
        self.assertEqual(("Your code is 123" in test), ("your code is 999" in test))

    def test_extended_experiment_keeps_tested_seed_families_out_of_fold_training(self):
        fits = []

        class Recorder(RecordingModel):
            def fit(self, texts, labels):
                fits.append(list(texts))
                return self

        seeds = ([f"seed urgent {i}" if i % 2 else f"seed notes {i}" for i in range(10)],
                 [i % 2 for i in range(10)], [str(i) for i in range(10)])
        variants = ([f"variant {i}" for i in range(10)], [i % 2 for i in range(10)], [str(i) for i in range(10)])
        training = {"corpus": (["urgent pay", "team lunch"], [1, 0], ["g1", "g2"])}
        extra = {"marketing_train": (["spring sale"], [0])}
        tests = {"nazario_2023_2025": (["urgent verify now"], [1]), "templates": (["receipt"], [0])}
        conditions = {"plain": ({}, False), "with_variants": (extra, True)}
        results = external.extended_experiment(training, conditions, seeds, variants, tests, make_model=Recorder,
                                               folds=5, thresholds=(0.5,), progress=lambda _m: None)
        self.assertEqual(len(fits), 1 + (1 + 5))
        self.assertEqual(fits[0], ["urgent pay", "team lunch"])
        self.assertIn("spring sale", fits[1])
        self.assertEqual(sum(t.startswith("variant") for t in fits[1]), 10)  # full model sees every variant
        for fold_texts in fits[2:]:
            self.assertEqual(sum(t.startswith("variant") for t in fold_texts), 8)
            self.assertFalse(any(t.startswith("seed") for t in fold_texts))
        self.assertEqual(set(results["with_variants"]), {"recent_seeds", "nazario_2023_2025", "templates"})
        self.assertEqual(results["plain"]["nazario_2023_2025"]["at_threshold"]["0.5"]["phishing_recall"]["value"], 1.0)
        self.assertEqual(results["plain"]["templates"]["at_threshold"]["0.5"]["false_positive_rate"]["value"], 0.0)


if __name__ == "__main__":
    unittest.main()
