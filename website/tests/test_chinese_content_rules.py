import asyncio
import json
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402


def categories(subject, body):
    result = json.loads(asyncio.run(app.analyze_content_endpoint(
        app.ContentRequest(subject=subject, body=body))).body)
    return {item['key']: item['matched'] for item in result['category_results']}


class ChineseKeywordMatchingTests(unittest.TestCase):
    def test_phrases_match_inside_running_text_and_across_inserted_spaces(self):
        self.assertTrue(app._keyword_matches('您的邮箱配额已满，请处理', '邮箱配额已满'))
        self.assertTrue(app._keyword_matches('确 认有效账户', '确认有效账户'))
        self.assertTrue(app._keyword_matches('保持\n相同的密码', '保持相同的密码'))
        self.assertFalse(app._keyword_matches('您的邮箱空间充足', '邮箱配额已满'))

    def test_english_keywords_keep_their_word_boundaries(self):
        self.assertTrue(app._keyword_matches('please act now', 'act now'))
        self.assertFalse(app._keyword_matches('react nowhere', 'act now'))


class ChineseContentRuleTests(unittest.TestCase):
    def test_mailbox_credential_lures_match_in_simplified_and_traditional(self):
        found = categories('验证您的电子邮件帐户', '我们今天将关闭所有不活跃的账户。请确认有效账户，否则您的帐户可能会丢失。')
        self.assertIn('credential', found)
        self.assertIn('threats', found)
        found = categories('⚠️ 警告', '您的郵箱存儲空間已滿！傳入郵件無法傳送到收件箱，立即增加空間。')
        self.assertIn('deception', found)
        self.assertIn('urgency', found)

    def test_ordinary_chinese_notices_match_nothing(self):
        for subject, body in (
            ('您的验证码', '您的验证码是 482913，10 分钟内有效。请勿将验证码告诉他人。'),
            ('订单已发货', '您的订单已发货，快递单号 SF1234567890，预计明天送达，可在 App 中查看物流。'),
            ('账单提醒', '您本月的信用卡账单已出，应还金额 1,280.00 元，到期还款日 10 月 25 日。'),
            ('安全提示', '我们不会通过邮件要求您提供密码。如有疑问，请通过官方 App 联系客服。'),
            ('会员即将到期', '您的会员将于 10 月 31 日到期，可在“我的-会员”中续费。'),
        ):
            with self.subTest(subject=subject):
                found = categories(subject, body)
                zh = {key: [kw for kw in kws if app._HAN.match(kw)] for key, kws in found.items()}
                self.assertEqual({key: kws for key, kws in zh.items() if kws}, {})


if __name__ == '__main__':
    unittest.main()
