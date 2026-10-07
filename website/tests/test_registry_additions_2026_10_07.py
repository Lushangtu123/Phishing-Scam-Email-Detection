"""Chinese services added on 2026-10-07 from the owner's list of common sites (synthetic inputs):
携程, 去哪儿网, 同程旅行, 美团, 抖音, 哔哩哔哩, 爱奇艺 and 小米账号 by name, and 滴滴出行 and 唯品会 as
services that verify their own mail."""
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


def received(sender, name, subject, body='您的验证码是 482913，15 分钟内有效。'):
    domain = sender.rpartition('@')[2]
    raw = (GMAIL_PASS.format(domain=domain) + f'From: {name} <{sender}>\r\nTo: user@example.com\r\n'
           f'Subject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n')
    return es.analyze_raw_email(raw.encode(), mailbox_provider='gmail')


class ChineseServiceTests(unittest.TestCase):
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
                structure = received(sender, name, '您的验证码')
                self.assertEqual(structure['verified_official_sender']['organization'], organization)

    def test_official_channels_and_numbers(self):
        channels = es.official_channels(['携程旅行网', '您的航班已取消'])
        self.assertEqual([(c['organization'], c['website'], c['service_numbers']) for c in channels],
                         [('携程旅行', 'ctrip.com', ['95010'])])
        # A message asking to call an organization's own published number is not a callback lure.
        self.assertLessEqual({'95010', '95117', '95711', '4001005678', '4009237171', '4006789888', '4001782233'},
                             es.OFFICIAL_SERVICE_NUMBERS)



if __name__ == '__main__':
    unittest.main()
