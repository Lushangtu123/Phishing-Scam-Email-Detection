"""Chinese services added on 2026-10-07 from the owner's list of common sites (synthetic inputs).

First batch: 携程, 去哪儿网, 同程旅行, 美团, 抖音, 哔哩哔哩, 爱奇艺 and 小米账号 by name, and 滴滴出行
and 唯品会 as services that verify their own mail. Second batch: 快手, 小红书, 菜鸟, 百度, 货拉拉,
德邦快递, 芒果TV, 酷狗音乐, 蜜雪冰城, 叮咚买菜 and 瑞幸咖啡 by name, and 微博 and 知乎 as services.
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




class SecondChineseBatchTests(unittest.TestCase):
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
                structure = received(sender, name, '您的验证码')
                self.assertEqual(structure['verified_official_sender']['organization'], organization)

    def test_official_numbers(self):
        self.assertLessEqual({'4000066666', '4001260088', '4008008888', '95036', '95353', '4009770707', '4000608888',
                              '4007006146', '10103365', '4000100100', '4000960960'}, es.OFFICIAL_SERVICE_NUMBERS)


if __name__ == '__main__':
    unittest.main()
