import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import content_model  # noqa: E402
from tools.model_text import normalize_for_model, normalize_texts  # noqa: E402


class ModelTextNormalizationTests(unittest.TestCase):
    def test_corpus_and_era_details_become_fixed_tokens(self):
        cases = {
            "Verify at http://paypa1.example/login?id=7 now": "Verify at zzurl now",
            "Go to www.example.com/reset": "Go to zzurl",
            "Contact vince.kaminski@enron.com today": "Contact zzemail today",
            "Meeting at 10:30 PM on March 3, 2005": "Meeting at zztime on March zznum , zzyear",
            "Call 14:05:59 or 9:00 a.m. tomorrow": "Call zztime or zztime tomorrow",
            "Invoice 2026-01-15 total 1,299.00 USD": "Invoice zzyear - zznum - zznum total zznum USD",
            "Order #112-4455 ships in 3 days": "Order # zznum - zznum ships in zznum days",
            "Reply by 5pm, or 11 AM.": "Reply by zztime , or zztime",
            "Visit http://site.example/path.": "Visit zzurl .",
            "See (https://x.example/a) now": "See ( zzurl ) now",
            "Get 5 amazing deals": "Get zznum amazing deals",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_for_model(raw), expected)

    def test_quoted_reply_markers_are_removed_but_quoted_words_are_kept(self):
        raw = "Thanks!\n> On Monday Tony wrote:\n>> see attached\n  > > final\nBest"
        self.assertEqual(normalize_for_model(raw), "Thanks! On Monday Tony wrote: see attached final Best")
        self.assertEqual(normalize_for_model("a > b and 3 > 2"), "a > b and zznum > zznum")

    def test_normalization_is_idempotent_and_leaves_other_text_alone(self):
        samples = [
            "Your account at https://bank.example/a?b=1 was locked on 2025-12-01 at 23:59.",
            "> quoted\nReply to someone@example.org by 5pm, ticket 42",
            "您的验证码为 482913，5分钟内有效。",
            "Su cuenta será suspendida el 3 de mayo de 2024.",
            "",
        ]
        for text in samples:
            once = normalize_for_model(text)
            with self.subTest(text=text):
                self.assertEqual(normalize_for_model(once), once)
        self.assertEqual(normalize_for_model("Plain words stay: Hello, Team!"), "Plain words stay: Hello, Team!")
        self.assertEqual(normalize_texts(["a 1", "b"]), ["a zznum", "b"])

    def test_tokens_survive_the_production_vectorizers(self):
        vectorizer = content_model._build_vectorizer()
        # Tokens appear in 6 of 10 documents: above min_df (3 word, 5 char), below max_df 0.95.
        documents = [normalize_for_model(f"visit http://x{i}.example on 2005-01-0{i} at 10:0{i} pm") for i in range(1, 7)]
        documents += [f"plain message about the weekly team update number {word}" for word in ("one", "two", "three", "four")]
        vectorizer.fit(documents)
        words = set(dict(vectorizer.transformer_list)["word"].get_feature_names_out())
        self.assertTrue({"zzurl", "zzyear", "zznum", "zztime"} <= words)
        self.assertFalse({"2005", "http", "pm"} & words)


if __name__ == "__main__":
    unittest.main()
