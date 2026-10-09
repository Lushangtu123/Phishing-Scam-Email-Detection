"""The SMS evaluation tool: counts by cohort and region, rules on legitimate texts, no text in the report."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

from tools import evaluate_sms as tool  # noqa: E402

ROWS = [
    {'region': 'us', 'label': 'scam', 'sender': '+63 917 555 0123',
     'text': 'E-ZPass: Your unpaid toll balance of $4.15 is past due. Pay at ezpass-tollpay.top/x to avoid a late fee.'},
    {'region': 'us', 'label': 'legitimate', 'sender': '28777',
     'text': 'USPS: Your package was delivered at 2:15 pm. Track it at https://tools.usps.com/go/x'},
    {'region': 'us', 'label': 'legitimate', 'sender': '(833) 555-0100',
     'text': 'Your dental appointment is confirmed for Monday at 9. Details: bit.ly/3abcde'},
    {'region': 'cn', 'label': 'scam', 'sender': '13800000000',
     'text': '【工商银行】您的账户存在异常已被冻结，请回复Y后退出短信重新打开，点击 icbc-verify.top/a 解冻。'},
    {'region': 'cn', 'label': 'legitimate', 'sender': '95588', 'text': '【工商银行】您尾号0000的账户于今日入账100元。'},
]


class EvaluateSmsTests(unittest.TestCase):
    def run_tool(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            cohort = Path(directory) / 'texts.jsonl'
            cohort.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows), encoding='utf-8')
            output = Path(directory) / 'report.json'
            tool.main(['--input', f'owner={cohort}', '--output', str(output)])
            return output.read_text(encoding='utf-8')

    def test_counts_rates_and_rules_on_legitimate_texts(self):
        text = self.run_tool(ROWS)
        report = json.loads(text)
        owner = report['cohorts']['owner']
        self.assertEqual((owner['scam']['messages'], owner['scam']['medium_or_above'], owner['scam']['medium_or_above_share']),
                         (2, 2, 1.0))
        # Only the appointment text with a short link is Low; the genuine USPS text names the
        # organisation it signs as, which is no impersonation keyword.
        self.assertEqual((owner['legitimate']['messages'], owner['legitimate']['medium_or_above'],
                          owner['legitimate'].get('unknown'), owner['legitimate'].get('low')), (3, 0, 2, 1))
        self.assertEqual(report['regions']['cn']['legitimate'], {'messages': 1, 'unknown': 1, 'medium_or_above': 0,
                                                                  'medium_or_above_share': 0.0})
        self.assertEqual(report['rules_on_legitimate'], {'content.shortened_urls': 1})
        self.assertFalse(report['configuration']['rdap_lookups'])
        for row in ROWS:
            self.assertNotIn(row['text'], text)
            self.assertNotIn(row['sender'], text)

    def test_rows_are_checked_without_echoing_them(self):
        for bad in ({'region': 'us', 'label': 'spam', 'text': 'secret text'},
                    {'region': 'uk', 'label': 'scam', 'text': 'secret text'},
                    {'region': 'us', 'label': 'scam', 'text': '   '},
                    {'region': 'us', 'label': 'scam', 'text': 'x' * 2001},
                    {'region': 'us', 'label': 'scam', 'text': 'secret text', 'sender': '1' * 65}):
            with self.subTest(bad=str(bad)[:60]), self.assertRaises(ValueError) as raised:
                self.run_tool([bad])
            self.assertNotIn('secret text', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
