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


class OwnerCalibrationTests(unittest.TestCase):
    """Rules added on 2026-10-09 from the owner's first batch, on synthetic texts."""

    def codes(self, sender, text):
        return codes(app.analyze_sms(sender, text))

    def test_chinese_service_numbers_with_an_extension(self):
        for sender in ('1008611', '9555801', '1230601'):
            with self.subTest(sender=sender):
                self.assertEqual(sms.classify_sender(sender), 'short_code')
        self.assertNotIn('sms.sender_mismatch', self.codes('1008611', '【中国移动】您的套餐将于月底到期。'))

    def test_a_parcel_with_an_action_and_an_unknown_link(self):
        self.assertIn('sms.delivery_lure', self.codes('+1 202 555 0100',
                      'USPS: the scheduled delivery for your parcel changed. Please confirm here: w4fza.info/x'))
        for text in ('USPS: Your package was delivered. Track it at https://tools.usps.com/go/x',
                     'Update your delivery preferences at https://www.usps.com/manage',
                     'Your package will be delivered today. Track it at https://amzn.to/abc'):
            with self.subTest(text=text):
                self.assertNotIn('sms.delivery_lure', self.codes('28777', text))

    def test_easy_money_and_a_private_messenger(self):
        for text in ('亲，上次在我店买的宝贝降价多收了您钱，加薇信给您退红包。',
                     '稳赚不赔，诚招代理，详情加QQ咨询。',
                     'Remote part-time job, earn $300/day. Contact us on WhatsApp.'):
            with self.subTest(text=text):
                self.assertIn('sms.external_contact_lure', self.codes('', text))
        for text in ('添加企业微信领取返现券。', '您的理财产品已到期，如有疑问请致电95588。',
                     'Your order shipped. Questions? Chat with us on WhatsApp.'):
            with self.subTest(text=text):
                self.assertNotIn('sms.external_contact_lure', self.codes('', text))

    def test_split_words(self):
        found = app.analyze_sms('', '代~理会|员 月.赚百万佣.金，添加微|信即送彩.金')
        self.assertIn('sms.split_words', codes(found))
        self.assertIn('sms.external_contact_lure', codes(found))  # read joined again
        for text in ('您预订的北京-上海-广州航班已出票。', '欢迎欧阳·娜娜入住，房号1203。'):
            with self.subTest(text=text):
                self.assertNotIn('sms.split_words', self.codes('', text))

    def test_an_unsolicited_job(self):
        for text in ('Remote/Part-time jobs for 20hrs weekly. No experience needed. Apply: https://bit.ly/abc',
                     'We decided to offer you a remote position, salary paid daily. Please send a message to this number.'):
            with self.subTest(text=text):
                self.assertIn('sms.job_offer', self.codes('+1 202 555 0100', text))
        for text in ('New jobs for you: Remote Data Analyst, $80k salary. View: https://www.indeed.com/viewjob?jk=1',
                     'Hi, this is Ana from Acme recruiting. Are you still interested in the analyst role? Reply YES.'):
            with self.subTest(text=text):
                self.assertNotIn('sms.job_offer', self.codes('+1 202 555 0100', text))


class ChineseScamRuleTests(unittest.TestCase):
    """Rules calibrated on the FBS development half; synthetic texts in the same patterns."""

    def codes(self, text, sender=''):
        return codes(app.analyze_sms(sender, text))

    def assert_rule(self, code, fires, quiet):
        for text in fires:
            with self.subTest(text=text):
                result = app.analyze_sms('', text)
                self.assertIn(code, codes(result))
                self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})
        for text in quiet:
            with self.subTest(text=text):
                self.assertNotIn(code, self.codes(text))

    def test_account_lure(self):
        self.assert_rule('sms.account_lure', (
            '【建设银行】尊敬的建行用户，您的账户已满8000积分可兑换现金，请登录手机网 ccb-jf.top 兑换，逾期失效。',
            '尊敬的工行用户：您的电子密码器将于今日失效，请登入我行网站 icbc-mm.cc 重新激活。',
            '尊敬的客户，您的信用卡因逾期已被冻结，请致电13812345678办理解冻。招商银行',
            '尊 敬 的 工行 用户 您 的 密码 器 证书 将 于 今日 失效 请 登入 http://icbc-e.net 激活',
        ), (
            '【建设银行】您的信用卡积分可兑换礼品，详情请登录建行手机银行APP。',
            '【工商银行】您的电子密码器即将到期，请携带身份证到网点更换，详询95588。',
            '【工商银行】积分兑换活动请访问 https://www.icbc.com.cn 查看。',
            '您尾号1234的储蓄卡账户于10日取款500元，存款余额3000元。【工商银行】',
        ))

    def test_gambling_promo(self):
        self.assert_rule('sms.gambling_promo', (
            '新会员注册即送88元，首存100送100，百家乐、真人视讯、体育投注，网址 xpj88.vip',
            '彩票网五周年庆，充100元即送，1倍流水即可取款，联系在线客服申请。',
            '註冊即送彩金，天天返氺，加微信 wx12345 领取',
        ), (
            '【中国移动】充100送20元话费，登录 http://www.10086.cn 办理。',
            '新游上线！首充双倍，注册即送豪礼，点击下载。',
            '【中国体育彩票】您购买的彩票已开奖，请到购彩网点查询。',
            '【工商银行】您尾号1234的账户于10日取款500元，存款余额3000元。',
        ))

    def test_prize_link(self):
        self.assert_rule('sms.prize_link', (
            '您已被选为好声音幸运观众，将获得8万元及笔记本电脑一部，请登录 hsy-cj.cc 领取，验证码1234。',
            '恭喜您被抽中，获得苹果手机一部，详进 http://lucky-win.top 查看。',
        ), (
            '【淘宝】恭喜获得10元无门槛券，点击 https://www.taobao.com 领取。',
            '恭喜您中奖了！奖品已寄出，详情请在官方App查看。',
        ))

    def test_flight_compensation(self):
        self.assert_rule('sms.flight_compensation', (
            '尊敬的旅客您好，您预订的CA1234航班因机械故障已取消，请联系客服13812345678办理退改签，每位旅客补偿300元。',
        ), (
            '【中国国航】您预订的CA1234航班已取消，可在国航App免费改签或退票，详询95583。',
            '您的航班CA1234延误约1小时，请留意登机口广播。',
        ))

    def test_stock_group(self):
        self.assert_rule('sms.stock_group', (
            '前私募操盘手建群了，长线牛股今晚公布，不收费，人满即封，进QQ群验证。',
            '十年老股民开群讲股，加微信免费领取每日涨停股。',
        ), (
            '【中银基金】中银战略新兴产业股票基金今日起募集，详情见官网。投资有风险。',
            '您的股票账户本月交易已结算，请登录券商App查看对账单。',
        ))

    def test_album_link(self):
        self.assert_rule('sms.album_link', (
            '你认真看完这相册吧 bit.ly/a1b2',
            '小明，看看我们之前的精彩影集 http://xc-photo.top/x',
            '你都上新闻了，你自己看吧 http://news-x.cc/a',
        ), (
            '婚礼照片已上传，密码是生日。',
            '看看我们之前的照片，在家庭群里。',
        ))


class WordingRuleTests(unittest.TestCase):
    """Rules from the IMC 2025 development half and known Chinese parcel and authority scripts."""

    def assert_rule(self, code, fires, quiet):
        for text in fires:
            with self.subTest(text=text):
                result = app.analyze_sms('', text)
                self.assertIn(code, codes(result))
                self.assertIn(result['risk_level'], {'medium', 'high', 'critical'})
        for text in quiet:
            with self.subTest(text=text):
                self.assertNotIn(code, codes(app.analyze_sms('', text)))

    def test_account_threat(self):
        self.assert_rule('sms.account_threat', (
            'Dear SBI user, your A/C will be blocked today. Update your PAN card, click here http://sbi-kyc.co/x',
            'Dear customer your account has been suspended, please update your KYC. Call +91 98765 43210 now.',
            'WELLS FARGO: Unauthorized sign-in from a new device. If this was not you, visit wf-secure.info/v to verify.',
            'Your Kotak credit card points worth Rs.4878 will expire today. Redeem in cash: kotak-points.in/r',
            'Dear User your SBI account will be suspended today please update your PAN card, click here link',
        ), (
            'Chase: Your card ending 1234 is locked. To unlock it, call 1-800-935-9935 or visit chase.com.',
            'Your Apple ID was used to sign in on a new device. If this was not you, visit https://appleid.apple.com.',
            'Your subscription renews today. Manage it in the app.',
        ))

    def test_utility_cutoff(self):
        self.assert_rule('sms.utility_cutoff', (
            'Dear consumer, your electricity power will be disconnected tonight. Please contact 9876543210 immediately.',
        ), (
            'PG&E: service in your area will be shut off for maintenance tomorrow 9-11am.',
            'Your water service is scheduled for disconnection on 10/15. Pay at https://www.pge.com or call 1-800-743-5000.',
        ))

    def test_refund_lure(self):
        self.assert_rule('sms.refund_lure', (
            'HMRC: You have a pending tax refund of 265.84GBP. Follow our secure link below to claim.',
            'GOV.UK: You are eligible for the Energy Bills Support Scheme. Apply here: http://energy-support.uk-claim.com',
        ), (
            'GOV.UK: Your vehicle tax is due. Renew at https://www.gov.uk/vehicle-tax',
            'IRS: your refund has been issued. Check its status at https://www.irs.gov/refunds',
        ))

    def test_family_new_number(self):
        self.assert_rule('sms.family_new_number', (
            "Hi Mum, I dropped my phone in the toilet. This is my new number, text me when you can.",
            "It's dad, my phone is broken so I'm on a friend's phone. Can you send me 250 for a bill?",
        ), (
            'Mum, dinner at 7? Love you.',
            'Your new phone number is active. Welcome to Mint Mobile!',
        ))

    def test_parcel_problem(self):
        self.assert_rule('sms.parcel_problem', (
            'RoyalMail: Your item has a £2 unpaid shipping fee. Pay now at royal-redeliver.com/x or it will be returned to sender.',
            'Your package address is incomplete and cannot be delivered. Update it here: usps-addr.top/a',
            '您的包裹因地址不详无法派送，请点击 sf-redeliver.top/a 补充地址。',
        ), (
            'USPS: Your package was delivered. Track it at https://tools.usps.com/go/x',
            '【顺丰速运】您的快件因地址不详无法派送，请联系快递员13812345678。',
            'Your order is out for delivery today.',
        ))

    def test_authority_threat(self):
        self.assert_rule('sms.authority_threat', (
            '中国驻纽约领事馆提醒您，您有一份重要文件未领取，请按1了解详情。',
            '海关通知：您的包裹涉嫌违法被扣留，相关账户将被冻结，请致电 02012345678 处理。',
        ), (
            '【公安部】提醒您：凡是自称公检法说你涉嫌洗钱、要求转账到安全账户的，都是诈骗。',
            '【中国驻纽约总领馆】领事证件办理时间调整，详见官网。',
        ))

    def test_split_words_needs_a_split_lure_word(self):
        self.assertNotIn('sms.split_words', codes(app.analyze_sms(
            '', '想苗条的过冬天嘛~想穿再多的衣服也显瘦吗~那就赶紧试试吧~试了就有机会哟~赶紧快人一步')))
        self.assertNotIn('sms.split_words', codes(app.analyze_sms('', '主演：霍史尼玛·热蒂玛·伊比、吊·热德伊比、珍妮·玛碧热')))
