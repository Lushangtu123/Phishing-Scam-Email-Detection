"""Text messages: sender kinds, brand claims, links and the SMS rules (synthetic texts only)."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402
import sms_analysis as sms  # noqa: E402


def codes(result):
    return [item['code'] for item in result['extra_indicators']]


class SenderKindTests(unittest.TestCase):
    def test_kinds(self):
        for sender, kind in (
                ('95588', 'short_code'), ('10086', 'short_code'), ('12306', 'short_code'), ('28777', 'short_code'),
                ('+86 95588', 'short_code'), ('１０６９８８８８１２３４', 'cn_port_106'), ('10690000123456', 'cn_port_106'),
                ('13812345678', 'cn_mobile'), ('+86 138 1234 5678', 'cn_mobile'), ('0086-138-1234-5678', 'cn_mobile'),
                ('8613812345678', 'cn_mobile'), ('(833) 555-0100', 'nanp_toll_free'), ('+1 800 555 0100', 'nanp_toll_free'),
                ('+1 (212) 555-0100', 'nanp_long_code'), ('212-555-0100', 'nanp_long_code'),
                ('12125550100', 'nanp_long_code'), ('+63 917 123 4567', 'international'), ('+44 7911 123456', 'international'),
                ('+44 7700 900123', 'other_number'), ('+1 900 555 0100', 'premium_rate'), ('+44 909 879 0000', 'premium_rate'),
                ('+86 10 1234 5678', 'other_number'), ('12', 'other_number'), ('toll.notice@example.com', 'email'),
                ('USPS', 'alphanumeric'), ('Mom', 'alphanumeric'), ('', 'none'), ('  ', 'none'),
                ('1​38​1234​5678', 'cn_mobile')):
            with self.subTest(sender=sender):
                self.assertEqual(sms.classify_sender(sender), kind)

    def test_every_kind_is_listed(self):
        self.assertEqual(len(set(sms.SENDER_KINDS)), len(sms.SENDER_KINDS))


class ClaimTests(unittest.TestCase):
    def claim(self, text):
        brand = sms.claimed_brand(text)
        return brand and brand['name']

    def test_signatures_and_openings(self):
        self.assertEqual(self.claim('【工商银行】您尾号0000的账户于今日入账100元。'), '中国工商银行')
        self.assertEqual(self.claim('您的验证码为000000，请勿泄露。【中国工商银行】'), '中国工商银行')
        self.assertEqual(self.claim('工商银行提醒您：请勿向他人透露验证码。'), '中国工商银行')
        self.assertEqual(self.claim('USPS: Your package is out for delivery.'), 'United States Postal Service')
        self.assertEqual(self.claim('[USPS] Your package is out for delivery.'), 'United States Postal Service')

    def test_a_later_mention_is_no_claim(self):
        self.assertIsNone(self.claim('我用工行转你了，记得查收。'))
        self.assertIsNone(self.claim('Your order shipped with USPS and arrives Tuesday.'))

    def test_chinese_organisations_by_chinese_names_only(self):
        # ABC is the Agricultural Bank of China's abbreviation, and the start of many English texts.
        self.assertIsNone(self.claim('ABC Dental: your appointment is on Monday at 9.'))
        self.assertEqual(self.claim('【农业银行】您的信用卡账单已出。'), '中国农业银行')

    def test_zero_width_characters_do_not_hide_a_name(self):
        self.assertEqual(self.claim('【工​商银行】您的账户存在异常。'), '中国工商银行')


class LinkTests(unittest.TestCase):
    def test_links_with_and_without_a_scheme(self):
        links = sms.text_links('Pay now at ezpass-pay.com/x, or https://www.usps.com/track. 点击t.cn/abc查看')
        self.assertEqual([url for _label, url in links],
                         ['http://ezpass-pay.com/x', 'https://www.usps.com/track', 'http://t.cn/abc'])

    def test_an_ip_address_after_a_scheme(self):
        self.assertEqual(sms.text_links('Click:http://23.254.215.52 to fill out the form'),
                         [('http://23.254.215.52', 'http://23.254.215.52')])
        self.assertIn('link.ip_host', [item.get('rule_id') for item in app.analyze_sms(
            '', 'Click:http://23.254.215.52 to fill out the form')['extra_indicators']])

    def test_what_is_no_link(self):
        for text in ('See file.txt for details.', 'e.g. tomorrow', 'Version 3.14 is out.', 'Write to name@example.com',
                     'Update to version 1.2.3.4 tonight.'):
            with self.subTest(text=text):
                self.assertEqual(sms.text_links(text), [])


class RuleTests(unittest.TestCase):
    def test_sender_mismatch(self):
        for sender, text, expected in (
                ('13812345678', '【工商银行】您的账户存在异常，请尽快处理。', ['sms.sender_mismatch']),
                ('+1 212 555 0100', '【工商银行】您的账户存在异常，请尽快处理。', ['sms.sender_mismatch']),
                ('95588', '【工商银行】您的账户存在异常，请尽快处理。', []),
                ('1069000012345', '【工商银行】您的账户存在异常，请尽快处理。', []),
                ('', '【工商银行】您的账户存在异常，请尽快处理。', []),
                ('toll@example.com', 'USPS: Your package is waiting.', ['sms.sender_mismatch']),
                ('+63 917 123 4567', 'USPS: Your package is waiting.', ['sms.sender_mismatch']),
                ('+1 212 555 0100', 'USPS: Your package is waiting.', ['sms.sender_mismatch_weak']),
                ('28777', 'USPS: Your package is waiting.', []),
                ('(833) 555-0100', 'USPS: Your package is waiting.', []),
                ('USPS', 'USPS: Your package is waiting.', []),
                ('13812345678', '我用工行转你了，记得查收。', [])):
            with self.subTest(sender=sender, text=text):
                found = sms.sms_findings(sender, text)['indicators']
                self.assertEqual([item['code'] for item in found if item['code'].startswith('sms.sender')], expected)

    def test_link_off_brand(self):
        def off(text):
            return [item['params'].get('host') for item in sms.sms_findings('', text)['indicators']
                    if item['code'] == 'sms.link_off_brand']
        self.assertEqual(off('USPS: Track it at https://tools.usps.com/go/x'), [])
        self.assertEqual(off('USPS: Update your address at usps-redelivery.top/a'), ['usps-redelivery.top'])
        self.assertEqual(off('Your parcel: usps-redelivery.top/a'), [])  # no claim

    def test_reopen_to_activate(self):
        for text in ('Please reply Y, then exit the text message and reopen it to activate the link.',
                     'Reply 1 and open this message again to click the link.',
                     'Or copy the link to your Safari browser and open it.',
                     '请回复Y，然后退出短信重新打开以激活链接。',
                     '如链接无法打开，请复制链接到浏览器打开。'):
            with self.subTest(text=text):
                self.assertIn('sms.reopen_to_activate', [i['code'] for i in sms.sms_findings('', text)['indicators']])
        for text in ('Reply Y to confirm your appointment. Reply STOP to opt out.', 'Copy this code: 123456.',
                     '回复TD退订。'):
            with self.subTest(text=text):
                self.assertNotIn('sms.reopen_to_activate', [i['code'] for i in sms.sms_findings('', text)['indicators']])


class PrizeCallbackTests(unittest.TestCase):
    def fires(self, text):
        return 'sms.prize_callback' in [item['code'] for item in sms.sms_findings('', text)['indicators']]

    def test_a_prize_to_claim_through_a_number(self):
        for text in ('URGENT! You have won a £1000 prize GUARANTEED. Call 09061234567 from a landline to claim.',
                     'Congratulations! You have been selected to receive a $500 gift card. Text WIN to 55123.',
                     'Your complimentary holiday or £1000 cash awaits collection. Dial 0871 234 5678 now.'):
            with self.subTest(text=text):
                self.assertTrue(self.fires(text))

    def test_no_prize_or_no_number(self):
        for text in ("I won't be home tonight, call me on 555 0100 when you land.",
                     'Reply Y to confirm your appointment on Monday at 9.',
                     'You won! Visit the store to pick up your prize.',
                     'Your order 123456 has shipped.'):
            with self.subTest(text=text):
                self.assertFalse(self.fires(text))


class PremiumCallbackTests(unittest.TestCase):
    def found(self, text):
        return [item['params'] for item in sms.sms_findings('', text)['indicators'] if item['code'] == 'sms.premium_callback']

    def test_a_premium_rate_number_to_call_or_text(self):
        self.assertEqual(self.found('Please CALL 09061213237 immediately as there is an urgent message waiting.'),
                         [{'number': '09061213237'}])
        self.assertEqual(self.found('Your account is on hold. Call +1 900 555 0100 to restore it.'),
                         [{'number': '+1 900 555 0100'}])

    def test_other_numbers(self):
        for text in ('Your table is ready. Call 212-555-0100 if you are running late.',
                     'Questions? Call us toll-free at 1-833-555-0100.',
                     'Reference 09061213237 was paid.'):  # no request to call
            with self.subTest(text=text):
                self.assertEqual(self.found(text), [])


class VerdictTests(unittest.TestCase):
    def test_no_finding_is_unknown_never_safe(self):
        result = app.analyze_sms('', 'See you at lunch tomorrow.')
        self.assertEqual((result['risk_level'], result['total_score'], codes(result)), ('unknown', 0, []))
        self.assertEqual(app.analyze_sms('95588', '【工商银行】您尾号0000的账户于今日入账100元。')['risk_level'], 'unknown')

    def test_a_matching_official_number_never_lowers_the_score(self):
        text = '【工商银行】您的账户已冻结，请立即点击 icbc-verify.top/a 输入密码和验证码解冻。'
        official, unknown = app.analyze_sms('95588', text), app.analyze_sms('', text)
        self.assertEqual(official['total_score'], unknown['total_score'])
        self.assertEqual(official['risk_level'], unknown['risk_level'])
        # The same text from a personal number adds the mismatch.
        personal = app.analyze_sms('13812345678', text)
        self.assertEqual(personal['total_score'], official['total_score'] + 4)
        self.assertIn('sms.sender_mismatch', codes(personal))

    def test_a_forged_official_number_is_left_to_the_content_and_link_rules(self):
        # The level such a text reaches depends on the Chinese SMS wording, whose phrases are
        # added from data in calibration (plan, Task 9); the link rules catch it already.
        result = app.analyze_sms('95588', '【工商银行】您的账户已冻结，请立即点击 icbc-verify.top/a 输入密码和验证码解冻。')
        self.assertNotIn('sms.sender_mismatch', codes(result))
        self.assertIn('sms.link_off_brand', codes(result))
        self.assertIn('link.sensitive_host', codes(result))
        self.assertNotEqual(result['risk_level'], 'unknown')
        self.assertEqual(result['official_channels'][0]['organization'], '中国工商银行')

    def test_toll_and_parcel_lures(self):
        toll = app.analyze_sms('+63 917 123 4567', 'Unpaid toll balance of $4.15 is past due. Pay at ezpass-pay.com/x to avoid fees.')
        self.assertIn('sms.fine_lure', codes(toll))
        self.assertIn(toll['risk_level'], {'high', 'critical'})
        parcel = app.analyze_sms('toll@example.com', 'USPS: Your package could not be delivered due to an incomplete '
                                                     'address. Update your address at usps-redelivery.top/a')
        self.assertIn('sms.delivery_lure', codes(parcel))
        self.assertIn('sms.sender_mismatch', codes(parcel))
        genuine = app.analyze_sms('28777', 'USPS: Your package was delivered. Track it at https://tools.usps.com/go/x')
        self.assertEqual((codes(genuine), genuine['category_results'], genuine['risk_level']), ([], [], 'unknown'))

    def test_only_the_claimed_organisations_own_name_is_discounted(self):
        other = app.analyze_sms('28777', 'USPS: Your PayPal refund is waiting. Track it at https://tools.usps.com/go/x')
        self.assertEqual([(cat['key'], cat['matched']) for cat in other['category_results']], [('impersonation', ['paypal'])])
        unsigned = app.analyze_sms('', 'Your package from USPS was delivered today.')
        self.assertEqual([cat['key'] for cat in unsigned['category_results']], ['impersonation'])

    def test_shared_text_rules_read_chinese_requests(self):
        result = app.analyze_sms('13812345678', '我是快递员，麻烦把收到的验证码发给我，帮你改地址。')
        self.assertTrue(any(code.startswith('content.') for code in codes(result)))
        self.assertIn(result['risk_level'], {'high', 'critical'})


if __name__ == '__main__':
    unittest.main()
