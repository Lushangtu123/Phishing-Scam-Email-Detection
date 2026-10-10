"""Official-brand registry additions, one test class per batch (synthetic inputs).

2026-10-02: USAA, Fifth Third Bank, PNC Bank, Charles Schwab, MetaMask, Tinder, 三井住友銀行 and
Alibaba.com.

2026-10-05: WeTransfer, Navy Federal Credit Union, Standard Bank and Absa by name, and Epic Games
and Twitch as services that verify their own mail.

2026-10-06, from the owner's list of common sites. First batch: RBC, TD, Scotiabank, CIBC, BMO,
DPD UK, Evri, Air Canada, Delta, Blizzard and Roblox by name, and American Airlines, OpenAI,
Nintendo and Riot Games as services that verify their own mail. Second batch: Fidelity
Investments, Discover, 1Password, Bitwarden, Hilton Honors and Emirates by name, and State Farm,
Chime, Uber, Lyft, Qatar Airways, British Airways and Target.

2026-10-07, Chinese services from the owner's list of common sites. First batch: 携程, 去哪儿网,
同程旅行, 美团, 抖音, 哔哩哔哩, 爱奇艺 and 小米账号 by name, and 滴滴出行 and 唯品会 as services that
verify their own mail. Second batch: 快手, 小红书, 菜鸟, 百度, 货拉拉, 德邦快递, 芒果TV, 酷狗音乐,
蜜雪冰城, 叮咚买菜 and 瑞幸咖啡 by name, and 微博 and 知乎 as services.
"""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import email_structure as es  # noqa: E402


GMAIL_PASS = ('Authentication-Results: mx.google.com;\r\n'
              '       dkim=pass header.i=@{domain} header.s=s1;\r\n'
              '       spf=pass (google.com: domain of bounce@{domain} designates 192.0.2.1 as permitted sender)'
              ' smtp.mailfrom=bounce@{domain};\r\n'
              '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={domain}\r\n')


def received(sender, name, subject, body='Your verification code is 482913. It expires in 15 minutes.'):
    domain = sender.rpartition('@')[2]
    raw = (GMAIL_PASS.format(domain=domain) + f'From: {name} <{sender}>\r\nTo: user@example.com\r\n'
           f'Subject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n')
    return es.analyze_raw_email(raw.encode(), mailbox_provider='gmail')


# The Chinese batches' default message.
ZH_CODE = '您的验证码是 482913，15 分钟内有效。'


class Additions20261002Tests(unittest.TestCase):
    def test_brands_shown_from_other_domains(self):
        for display, domain, brand in (
                ('USAA', 'virginia.edu', 'USAA'),
                ('Fifth Third Bank', 'arab-egypt.com', 'Fifth Third Bank'),
                ('PNC Alerts', 'windstream.net', 'PNC Alerts'),
                ('C​h​a​r​l​es S‍chwa​b & Co.', 'example.net', 'Charles Schwab'),
                ('MetaMask', 'nucleuspos.com', 'MetaMask'),
                ('Tinder', 'allufa.ru', 'Tinder'),
                ('三井住友銀行', 'wvbflyh.cn', '三井住友銀行')):
            with self.subTest(display=display):
                self.assertEqual(es._registry_brand_claim(display, domain), brand)

    def test_their_own_domains(self):
        for display, domain in (
                ('USAA', 'mailcenter.usaa.com'), ('Fifth Third Bank', '53.com'), ('PNC Alerts', 'pnc.com'),
                ('Charles Schwab', 'email.schwab.com'), ('MetaMask', 'metamask.io'), ('MetaMask', 'cl-cards.com'),
                ('MetaMask', 'metamask.discoursemail.com'), ('Tinder', 'gotinder.com'), ('Tinder', 'mail.gotinder.com'),
                ('三井住友銀行', 'smbc.co.jp')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_names_left_out(self):
        # Shared names are not claims: Schwab Charitable, SMBC group companies, another
        # community's Discourse mail.
        for display, domain in (('Schwab Charitable', 'schwabcharitable.org'), ('SMBC日興証券', 'smbcnikko.co.jp'),
                                ('SMBC Card', 'smbc-card.com')):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, domain))
        self.assertEqual(es._registry_brand_claim('MetaMask', 'other.discoursemail.com'), 'MetaMask')

    def test_alibaba(self):
        for display, domain in (('Alibaba Trade Center', 'noreply.com'), ('Alibaba trade Centre', 'kbss.sk'),
                                ('Alibaba.com Team', 'notice-alibaba.top')):
            with self.subTest(display=display):
                self.assertIsNotNone(es._registry_brand_claim(display, domain))
        for display, domain in (('Alibaba.com', 'service.alibaba.com'), ('Alibaba Cloud', 'alibabacloud.com'),
                                ('AliExpress', 'aliexpress.com')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))


class Additions20261005Tests(unittest.TestCase):
    def test_names_shown_from_other_domains(self):
        for display, domain, brand in (
                ('WeTransfer', 'wetransfer-secure.com', 'WeTransfer'),
                ('Navy Federal Credit Union', 'nfcu-alerts.com', 'Navy Federal Credit Union'),
                ('Navy Federal', 'mail.example.net', 'Navy Federal'),
                ('Standard Bank', 'sbsa-online.co', 'Standard Bank'),
                ('Absa', 'absa.co.za.example.com', 'Absa'),
                ('ABSA Alerts', 'secure-alerts.example', 'Absa')):
            with self.subTest(display=display, domain=domain):
                self.assertEqual(es._registry_brand_claim(display, domain), brand)

    def test_their_own_domains(self):
        for display, domain in (
                ('WeTransfer', 'wetransfer.com'), ('WeTransfer', 'mail.wetransfer.com'),
                ('Navy Federal', 'navyfederal.org'), ('Navy Federal Credit Union', 'email.navyfederal.org'),
                ('Standard Bank', 'standardbank.co.za'), ('Standard Bank', 'email.standardbank.com'),
                ('Absa', 'absa.co.za'), ('Absa', 'absa.africa')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_other_names(self):
        for display in ('Absalom Smith', 'Standard Chartered', 'Navy SEAL Foundation', 'Federal Navy Supplies',
                        'Transfer Wise'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.net'))

    def test_services_verify_their_own_mail(self):
        for sender, name, organization in (('help@acct-auth.epicgames.com', 'Epic Games', 'Epic Games'),
                                           ('no-reply@twitch.tv', 'Twitch', 'Twitch')):
            with self.subTest(sender=sender):
                structure = received(sender, name, 'Your sign-in code')
                self.assertEqual(structure['verified_official_sender']['organization'], organization)
        # amazon.com, which Twitch also uses, stays Amazon's.
        self.assertEqual(es._official_sender('amazon.com'), 'Amazon')

    def test_transfer_notices_are_relays(self):
        structure = received('noreply@wetransfer.com', 'WeTransfer', 'alex@example.org sent you some files',
                             body='alex@example.org sent you 2 files. Download them before they expire.')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertIn('structure.platform_relay', {item['code'] for item in structure['indicators']})
        account = received('noreply@wetransfer.com', 'WeTransfer', 'Your WeTransfer verification code')
        self.assertEqual(account['verified_official_sender']['organization'], 'WeTransfer')


class Additions20261006Tests(unittest.TestCase):
    def test_names_shown_from_other_domains(self):
        for display, domain, claimed in (
                ('RBC Royal Bank', 'rbc-secure-alerts.com', 'RBC Royal Bank'),
                ('Royal Bank of Canada', 'mail.example.net', 'Royal Bank of Canada'),
                ('TD Canada Trust', 'td-canada-verify.com', 'TD Canada Trust'),
                ('Scotiabank Alerts', 'scotia-online.co', 'Scotiabank'),
                ('CIBC Online Banking', 'cibc-secure.net', 'CIBC'),
                ('BMO Financial Group', 'bmo-verify.com', 'BMO Financial Group'),
                ('Bank of Montreal', 'example.org', 'Bank of Montreal'),
                ('DPD UK', 'dpd-redelivery.com', 'DPD UK'),
                ('Evri Parcel Team', 'evri-redelivery.info', 'Evri'),
                ('Air Canada', 'aircanada-refunds.com', 'Air Canada'),
                ('Aeroplan Rewards', 'aeroplan-points.net', 'Aeroplan'),
                ('Delta Air Lines', 'delta-airlines-refund.com', 'Delta Air Lines'),
                ('Delta Airlines Support', 'example.net', 'Delta Air Lines'),
                ('Battle.net Support', 'battlenet-security.com', 'Battle.net'),
                ('Blizzard Entertainment', 'blizzard-support.co', 'Blizzard Entertainment'),
                ('Roblox', 'noreply-roblox.com', 'Roblox')):
            with self.subTest(display=display, domain=domain):
                self.assertEqual(es._registry_brand_claim(display, domain), claimed)

    def test_their_own_domains(self):
        for display, domain in (
                ('RBC Royal Bank', 'rbc.com'), ('RBC Royal Bank', 'email.rbc.com'), ('TD Canada Trust', 'td.com'),
                ('Scotiabank', 'scotiabank.com'), ('CIBC', 'cibc.com'), ('BMO Financial Group', 'bmo.com'),
                ('DPD UK', 'dpdlocal.co.uk'), ('DPD Local', 'dpd.uk'), ('Evri', 'myhermes.co.uk'),
                ('Air Canada', 'mail.aircanada.com'), ('Aeroplan', 'communications.aeroplan.com'),
                ('Air Canada Vacations', 'vacv.com'), ('Delta Air Lines', 't.delta.com'),
                ('Battle.net', 'te.battle.net'), ('Blizzard Entertainment', 'em.overwatchleague.com'),
                ('Roblox', 'roblox.com')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_names_left_out(self):
        # Organizations sharing a registered acronym or name, and the names left out on purpose.
        for display in ('RBC Bearings', 'TD Ameritrade', 'TD Bank', 'BMO Stadium', 'BMO Field', 'DPD',
                        'Hermes Paris', 'Blizzard Weather Alert', 'Delta Faucet', 'Delta Dental', 'Scotia iTRADE',
                        'American Airlines Federal Credit Union', 'American Airlines Center', 'OpenAI',
                        'ChatGPT', 'Nintendo', 'Riot Games'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.net'))

    def test_their_own_mail_is_verified(self):
        for sender, name, organization in (
                ('noreply@rbc.com', 'RBC Royal Bank', 'RBC Royal Bank'),
                ('alerts@td.com', 'TD Canada Trust', 'TD Bank Group'),
                ('no-reply@roblox.com', 'Roblox', 'Roblox'),
                ('no-reply@info.email.aa.com', 'American Airlines', 'American Airlines'),
                ('otp@tm1.openai.com', 'OpenAI', 'OpenAI'),
                ('no-reply@accounts.nintendo.com', 'Nintendo', 'Nintendo'),
                ('noreply@mail.accounts.riotgames.com', 'Riot Games', 'Riot Games')):
            with self.subTest(sender=sender):
                structure = received(sender, name, 'Your sign-in code')
                self.assertEqual(structure['verified_official_sender']['organization'], organization)

    def test_workspace_invites_are_relays(self):
        # OpenAI sends workspace and GPT invites, which carry another user's names, from this address.
        structure = received('noreply@tm.openai.com', 'ChatGPT', 'You have been asked to join a workspace')
        self.assertIsNone(structure['verified_official_sender'])
        self.assertIn('structure.platform_relay', {item['code'] for item in structure['indicators']})

    def test_shared_services_stay_unofficial(self):
        for domain in ('qualtrics-research.com', 'qemailserver.com', 'payments.interac.ca', 'buyatab.com',
                       'custhelp.com', 'evri.custhelp.com', 'riotgames.zendesk.com', 'stellaconnect.net',
                       'globaleco.app', 'tdbank.com', 'rbcroyalbank.com', 'usbank.com', 'walmart.com'):
            with self.subTest(domain=domain):
                self.assertIsNone(es._official_sender(domain))

    def test_official_channels_name_the_bank(self):
        channels = es.official_channels(['Scotiabank', 'Your account has been locked'])
        self.assertEqual([(c['organization'], c['website']) for c in channels], [('Scotiabank', 'scotiabank.com')])
        self.assertIn('never', channels[0]['statement'])


class Additions20261006SecondBatchTests(unittest.TestCase):
    def test_names_shown_from_other_domains(self):
        for display, domain, claimed in (
                ('Fidelity Investments', 'fidelity-alerts.com', 'Fidelity Investments'),
                ('Discover Card Services', 'discover-secure.net', 'Discover Card'),
                ('Discover Bank', 'example.net', 'Discover Bank'),
                ('1Password', '1password-security.com', '1Password'),
                ('Bitwarden Vault', 'bitwarden-login.net', 'Bitwarden'),
                ('Hilton Honors', 'hilton-honors-rewards.com', 'Hilton Honors'),
                ('Emirates Skywards', 'skywards-miles.net', 'Emirates Skywards'),
                ('Fly Emirates', 'example.org', 'Fly Emirates')):
            with self.subTest(display=display, domain=domain):
                self.assertEqual(es._registry_brand_claim(display, domain), claimed)

    def test_their_own_domains(self):
        for display, domain in (
                ('Fidelity Investments', 'mail.fidelity.com'), ('Discover Card', 'service.discover.com'),
                ('1Password', '1password.eu'), ('1Password Community', '1password.community'),
                ('1Password', 'agilebits.com'), ('Bitwarden', 'bitwarden.eu'), ('Hilton Honors', 'h6.hilton.com'),
                ('Emirates Skywards', 'emirates.email'), ('Fly Emirates', 'e.emirates.com')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_names_left_out(self):
        for display in ('Fidelity Bank', 'Discover', 'Discover Weekly', 'Hilton', 'Paris Hilton', 'Emirates',
                        'Emirates NBD', 'Emirates Post', 'State Farm Agent Sam Lee', 'Chime', 'Uber', 'Lyft',
                        'Qatar Airways', 'British Airways', 'Target'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.net'))

    def test_their_own_mail_is_verified(self):
        for sender, name, organization in (
                ('alerts@fidelity.com', 'Fidelity Investments', 'Fidelity Investments'),
                ('discover@service.discover.com', 'Discover Card', 'Discover'),
                ('hello@1password.com', '1Password', '1Password'),
                ('failed-payments@bitwarden.com', 'Bitwarden', 'Bitwarden'),
                ('noreply@h6.hilton.com', 'Hilton Honors', 'Hilton'),
                ('do-not-reply@emirates.email', 'Emirates Skywards', 'Emirates'),
                ('donotreply@e.sfdividend.com', 'State Farm', 'State Farm'),
                ('no-reply@chime.com', 'Chime', 'Chime'),
                ('noreply@uber.com', 'Uber Eats', 'Uber'),
                ('no-reply@lyftmail.com', 'Lyft', 'Lyft'),
                ('privilegeclub@qr.qatarairways.com', 'Qatar Airways Privilege Club', 'Qatar Airways'),
                ('BritishAirways@email.ba.com', 'British Airways', 'British Airways'),
                ('orders@oe.target.com', 'Target', 'Target')):
            with self.subTest(sender=sender):
                structure = received(sender, name, 'Your sign-in code')
                self.assertEqual(structure['verified_official_sender']['organization'], organization)

    def test_community_and_invitation_mail_are_relays(self):
        # 1Password's community notifications and custom invitations, and Bitwarden's no-reply address,
        # which also sends invitations to an organization the inviter names.
        for sender, name in (('notifications@1password.community', '1Password Community'),
                             ('invite@custommail.1password.com', '1Password'),
                             ('no-reply@bitwarden.com', 'Bitwarden')):
            with self.subTest(sender=sender):
                structure = received(sender, name, 'Join Acme on the team vault')
                self.assertIsNone(structure['verified_official_sender'])
                self.assertIn('structure.platform_relay', {item['code'] for item in structure['indicators']})

    def test_shared_and_unlisted_domains_stay_unofficial(self):
        for domain in ('lyft.zendesk.com', '1password.email.ada.support', 'reachdesk.com', 'reachdesk-mail.com',
                       'qatarairways.com', 'ba.com', 'britishairways.com', 'temu.com', 'wise.com', 'doordash.com'):
            with self.subTest(domain=domain):
                self.assertIsNone(es._official_sender(domain))


class Additions20261007ChineseTests(unittest.TestCase):
    def test_names_shown_from_other_domains(self):
        for display, domain, claimed in (
                ('携程旅行网', 'ctrip-refund.com', '携程'), ('Trip.com', 'trip-booking.net', 'Trip.com'),
                ('去哪儿网客服', 'qunar-tuipiao.com', '去哪儿网'), ('同程旅行', 'ly-refund.cn', '同程旅行'),
                ('美团月付', 'meituan-pay.cn', '美团'), ('抖音电商', 'douyin-shop.cn', '抖音'),
                ('哔哩哔哩大会员', 'bili-vip.com', '哔哩哔哩'), ('爱奇艺VIP会员', 'iqiyi-vip.cn', '爱奇艺'),
                ('小米账号安全中心', 'mi-account.cn', '小米账号')):
            with self.subTest(display=display, domain=domain):
                self.assertEqual(es._registry_brand_claim(display, domain), claimed)

    def test_their_own_domains(self):
        for display, domain in (
                ('携程旅行网', 'mail.ctrip.com'), ('Trip.com', 'trip.com'), ('去哪儿网', 'qunar.com'),
                ('同程旅行', 'ly.com'), ('美团', 'meituan.com'), ('抖音', 'bytedance.com'),
                ('哔哩哔哩', 'bilibili.com'), ('爱奇艺', 'qiyi.com'), ('小米账号', 'xiaomi.com')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_names_left_out(self):
        # Common phrases, nicknames and names whose senders' domains no page names.
        for display in ('周末去哪儿', '小米', '小米粥铺', '小米商城', '同程艺龙', '滴滴出行', '唯品会', '饿了么'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.com'))

    def test_their_own_mail_is_verified(self):
        for sender, name, organization in (
                ('account-service@xiaomi.com', '小米账号', '小米'),
                ('service@ctrip.com', '携程旅行网', '携程旅行'),
                ('invoice@didichuxing.com', '滴滴出行', '滴滴出行'),
                ('service@vipshop.com', '唯品会', '唯品会')):
            with self.subTest(sender=sender):
                structure = received(sender, name, '您的验证码', body=ZH_CODE)
                self.assertEqual(structure['verified_official_sender']['organization'], organization)

    def test_official_channels_and_numbers(self):
        channels = es.official_channels(['携程旅行网', '您的航班已取消'])
        self.assertEqual([(c['organization'], c['website'], c['service_numbers']) for c in channels],
                         [('携程旅行', 'ctrip.com', ['95010'])])
        # A message asking to call an organization's own published number is not a callback lure.
        self.assertLessEqual({'95010', '95117', '95711', '4001005678', '4009237171', '4006789888', '4001782233'},
                             es.OFFICIAL_SERVICE_NUMBERS)


class Additions20261007ChineseSecondBatchTests(unittest.TestCase):
    def test_names_shown_from_other_domains(self):
        for display, domain, claimed in (
                ('快手官方', 'kuaishou-kefu.cn', '快手官方'), ('小红书商家服务', 'xhs-shop.cn', '小红书'),
                ('菜鸟驿站', 'cainiao-post.cn', '菜鸟驿站'), ('百度网盘', 'baidu-pan.net', '百度'),
                ('货拉拉客服', 'hll-kefu.cn', '货拉拉'), ('德邦快递', 'deppon-ex.cn', '德邦快递'),
                ('芒果TV会员', 'mgtv-vip.cn', '芒果TV'), ('酷狗音乐', 'kugou-vip.cn', '酷狗音乐'),
                ('蜜雪冰城加盟', 'mxbc-jiameng.com', '蜜雪冰城'), ('叮咚买菜', 'ddmc.cn', '叮咚买菜'),
                ('瑞幸咖啡', 'luckin-coupon.cn', '瑞幸咖啡'), ('luckin coffee', 'example.net', 'luckin coffee')):
            with self.subTest(display=display, domain=domain):
                self.assertEqual(es._registry_brand_claim(display, domain), claimed)

    def test_their_own_domains(self):
        for display, domain in (
                ('快手官方', 'kuaishou.com'), ('小红书', 'xiaohongshu.com'), ('菜鸟裹裹', 'service.cainiao.com'),
                ('百度', 'baidu.com'), ('货拉拉', 'huolala.cn'), ('德邦快递', 'deppon.com'), ('芒果TV', 'mgtv.com'),
                ('酷狗音乐', 'kugou.com'), ('蜜雪冰城', 'mxbc.com'), ('叮咚买菜', '100.me'),
                ('瑞幸咖啡', 'lkcoffee.com'), ('luckin coffee', 'luckincoffee.com')):
            with self.subTest(display=display, domain=domain):
                self.assertIsNone(es._registry_brand_claim(display, domain))

    def test_names_left_out(self):
        # Common words, other companies, social platforms that only verify their own mail, and the
        # services not added.
        for display in ('快手', '装修快手', '菜鸟', '菜鸟教程', '德邦证券', '酷狗宠物', '微博', '某某官方微博', '知乎',
                        '哈啰出行', '得物', '喜马拉雅', '豆瓣', '高德地图', '大众点评', '优酷', '盒马', '网易云音乐',
                        '钉钉', '飞书', '闲鱼', 'BOSS直聘'):
            with self.subTest(display=display):
                self.assertIsNone(es._registry_brand_claim(display, 'example.com'))

    def test_their_own_mail_is_verified(self):
        for sender, name, organization in (
                ('notice@service.weibo.com', '微博', '微博'), ('noreply@zhihu.com', '知乎', '知乎'),
                ('service@kugou.com', '酷狗音乐', '酷狗音乐'), ('privacy@lkcoffee.com', '瑞幸咖啡', '瑞幸咖啡')):
            with self.subTest(sender=sender):
                structure = received(sender, name, '您的验证码', body=ZH_CODE)
                self.assertEqual(structure['verified_official_sender']['organization'], organization)

    def test_official_numbers(self):
        self.assertLessEqual({'4000066666', '4001260088', '4008008888', '95036', '95353', '4009770707', '4000608888',
                              '4007006146', '10103365', '4000100100', '4000960960'}, es.OFFICIAL_SERVICE_NUMBERS)


if __name__ == '__main__':
    unittest.main()
