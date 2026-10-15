"""Words that mix Latin letters with Cyrillic or Greek look-alikes ("pаssword" with a Cyrillic а):
the text rules read them as Latin and report them (criteria in docs/evaluation.md, 2026-10-15).
Synthetic inputs only."""
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import content_rules  # noqa: E402
import email_structure as es  # noqa: E402

CYRILLIC_A = 'а'
GREEK_O = 'ο'
REQUEST = 'Please reply with your password and verify your account today.'
OFF = 'https://mail-portal.workers.dev/x'
# The mailbox lure of test_mailbox_lure_gaps.py.
LURE_TEXT, LURE_LABEL = 'You are unable to send and receive messages from your account.', 'Activate My Account Now'


def cyrillic(text):
    return text.replace('a', CYRILLIC_A)


def codes(found):
    return sorted(item['code'] for item in found)


def rule_codes(text):
    rules = content_rules._text_rule_findings(text)
    return codes(rules['requests'] + rules['style'] + rules['wording']), rules


def eml(sender, body):
    raw = (f'From: {sender}\r\nTo: reader@example.org\r\nSubject: Account notice\r\nMIME-Version: 1.0\r\n'
           f'Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n').encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw, arc_result=None),
                                                           observe_sender_history=False)).body)


class MixedScriptWordTests(unittest.TestCase):
    def test_mixed_words_are_found_and_read_as_latin(self):
        for text, words, folded in (
                (cyrillic('your password'), [cyrillic('password')], 'your password'),
                ('l' + GREEK_O + 'gin', ['l' + GREEK_O + 'gin'], 'login'),
                ('P' + CYRILLIC_A.upper() + 'YPAL', ['P' + CYRILLIC_A.upper() + 'YPAL'], 'PAYPAL'),
                # A zero-width space does not split the word around the look-alike.
                ('p​' + CYRILLIC_A + '​ssword', ['p​' + CYRILLIC_A + '​ssword'], 'p​a​ssword')):
            with self.subTest(text=text):
                self.assertEqual(content_rules._mixed_script_words(text), words)
                self.assertEqual(content_rules._fold_mixed_script(text), folded)
                self.assertEqual(len(content_rules._fold_mixed_script(text)), len(text))

    def test_cyrillic_greek_and_symbols_of_their_own_are_left_alone(self):
        for text in ('Привет, как дела? Встреча завтра в 10:00.', 'Καλημέρα, η συνάντηση είναι αύριο.',
                     'Add 5 μg of α-amylase; TGF-β levels rose.', 'Hello Москва team, see you in Αθήνα.', '', REQUEST,
                     # Tightened after the first corpus run (docs/evaluation.md): Chinese ends a word, two
                     # letters are too few, and a Cyrillic word with a stray Latin letter is Cyrillic.
                     'α变N公司和', 'Площадь 5 mс в квартире', 'Пpивет, коллеги'):
            with self.subTest(text=text):
                self.assertEqual(content_rules._mixed_script_words(text), [])
                self.assertEqual(content_rules._fold_mixed_script(text), text)
                found, _rules = rule_codes(text)
                self.assertNotIn('content.mixed_script_words', found)

    def test_rules_find_what_the_latin_text_shows_and_report_the_mixing(self):
        latin, latin_rules = rule_codes(REQUEST)
        mixed, mixed_rules = rule_codes(cyrillic(REQUEST))
        self.assertIn('content.sensitive_request.password_pin', latin)
        self.assertEqual(mixed, sorted(latin + ['content.mixed_script_words']))
        self.assertEqual(mixed_rules['floor'], latin_rules['floor'])
        self.assertEqual(mixed_rules['score'], latin_rules['score'] + 3)
        self.assertEqual(mixed_rules['categories'], latin_rules['categories'])
        item = next(entry for entry in mixed_rules['wording'] if entry['code'] == 'content.mixed_script_words')
        self.assertEqual((item['level'], item['params']['count']), ('medium', 5))  # Ple_se, p_ssword, _nd, _ccount, tod_y

    def test_mixing_alone_sets_a_medium_floor(self):
        _found, rules = rule_codes('Hello ' + cyrillic('team') + ', lunch is at noon.')
        self.assertEqual(rules['floor'], 'medium')

    def test_an_uploaded_message_with_mixed_words_keeps_its_request(self):
        # Before the change, the Cyrillic version lost the request rule (Critical became Low).
        for body in (REQUEST, cyrillic(REQUEST)):
            with self.subTest(body=body):
                result = eml('Alex Chen <alex.chen@gmail.com>', body)
                found = codes(result['extra_indicators'])
                self.assertIn('content.sensitive_request.password_pin', found)
                self.assertIn(result['risk_level'], {'high', 'critical'})
                self.assertEqual('content.mixed_script_words' in found, body != REQUEST)

    def test_the_lure_rules_and_button_labels_read_mixed_words_as_latin(self):
        for text, label in ((LURE_TEXT, LURE_LABEL), (cyrillic(LURE_TEXT), cyrillic(LURE_LABEL))):
            with self.subTest(text=text):
                body = f'<p>{text}</p><p><a href="{OFF}">{label}</a></p>'
                self.assertIn('content.mailbox_lure', codes(app.analyze_email_content('Mailbox', body)['extra_indicators']))

    def test_attachment_text_and_text_messages_read_mixed_words_as_latin(self):
        self.assertIn('content.sensitive_request.password_pin',
                      codes(content_rules._attachment_text_findings(cyrillic(REQUEST))))
        self.assertIn('content.sensitive_request.password_pin',
                      codes(app.analyze_sms('+15550100', cyrillic(REQUEST))['extra_indicators']))


if __name__ == '__main__':
    unittest.main()
