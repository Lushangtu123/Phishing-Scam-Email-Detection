"""Text messages (SMS, iMessage): what kind of sender a number is, which organisation a text
says it comes from, its links, and the rules only texts need.

app.analyze_sms runs these beside the plain-text rules texts share with email
(docs/superpowers/specs/2026-10-08-sms-scam-detection-design.md). This module needs nothing
from app.py, so app.py can import it.
"""
from __future__ import annotations

import json
import re
import unicodedata
from urllib.parse import urlsplit

import phonenumbers
from phonenumbers import PhoneNumberType

from email_structure import _OFFICIAL_BRANDS_PATHS, _ORGANIZATIONAL_DOMAINS, normalize_domain
from server_messages import indicator

SENDER_KINDS = ('short_code', 'cn_port_106', 'cn_mobile', 'nanp_toll_free', 'nanp_long_code', 'premium_rate',
                'international', 'other_number', 'email', 'alphanumeric', 'none')
_ZERO_WIDTH = re.compile('[​-‏⁠﻿]')
_EMAIL = re.compile(r'[^@\s]+@[^@\s]+\.[A-Za-z]{2,}')
_CN_MOBILE = re.compile(r'1[3-9]\d{9}')
# Carriers (10086, 10010, 10000), banks and services (95xxx, 96xxx) and public services
# (12306, 12345) also text from extensions of their numbers, such as 1008611.
_CN_SERVICE_EXTENSION = re.compile(r'(?:100\d\d|9[56]\d{3}|12\d{3})\d{1,4}')


def clean_text(text: str) -> str:
    """The text without zero-width characters, which scams put inside names and links."""
    return _ZERO_WIDTH.sub('', text or '')


def _chinese_kind(national: str) -> str | None:
    if _CN_MOBILE.fullmatch(national):
        return 'cn_mobile'
    if national.startswith('106') and len(national) >= 8:
        return 'cn_port_106'
    if 3 <= len(national) <= 6 or _CN_SERVICE_EXTENSION.fullmatch(national):
        return 'short_code'
    return None


def _number_type(number: str, region: str | None = None) -> int | None:
    """libphonenumber's type for a valid number (offline metadata only), else None."""
    try:
        parsed = phonenumbers.parse(number, region)
    except phonenumbers.NumberParseException:
        return None
    return phonenumbers.number_type(parsed) if phonenumbers.is_valid_number(parsed) else None


def _north_american_kind(ten: str) -> str | None:
    if len(ten) != 10 or ten[0] not in '23456789':
        return None
    kind = _number_type('+1' + ten)
    return ('premium_rate' if kind == PhoneNumberType.PREMIUM_RATE else
            'nanp_toll_free' if kind == PhoneNumberType.TOLL_FREE else 'nanp_long_code')


def classify_sender(sender: str) -> str:
    """The kind of sender, one of SENDER_KINDS. The number itself is never kept.

    A bare 11-digit number starting with 13–19 is read as a Chinese mobile: phones show
    North American numbers with +1 or as 10 digits.
    """
    value = clean_text(unicodedata.normalize('NFKC', sender or '')).strip()
    if not value:
        return 'none'
    if _EMAIL.fullmatch(value):
        return 'email'
    compact = re.sub(r'[\s\-.() ]', '', value)
    if not re.fullmatch(r'\+?\d+', compact):
        return 'alphanumeric' if re.search(r'[^\W\d_]', value) else 'other_number'
    plus, digits = compact.startswith('+'), compact.lstrip('+')
    if not plus and digits.startswith('00'):
        plus, digits = True, digits[2:]
    if plus:
        if digits.startswith('86'):
            return _chinese_kind(digits[2:]) or 'other_number'
        if digits.startswith('1') and len(digits) == 11:
            return _north_american_kind(digits[1:]) or 'other_number'
        kind = _number_type('+' + digits)
        return 'other_number' if kind is None else 'premium_rate' if kind == PhoneNumberType.PREMIUM_RATE else 'international'
    return (_chinese_kind(digits) or _north_american_kind(digits)
            or (len(digits) == 11 and digits.startswith('1') and _north_american_kind(digits[1:]))
            or (digits.startswith('86') and _chinese_kind(digits[2:])) or 'other_number')


def _load_brands(paths=_OFFICIAL_BRANDS_PATHS) -> tuple[dict, ...]:
    """Organisations a text can claim to be, with their region and official domains.

    Services named only by a verified sender (display_check "sender_only") are left out, as
    in email. Chinese organisations are claimed by their Chinese names only: their ASCII
    abbreviations (ABC, CCB, BOC) open many English texts.
    """
    brands = []
    for path in paths:
        region = 'cn' if path.name == 'official_brands_cn.json' else 'intl'
        for brand in json.loads(path.read_text(encoding='utf-8'))['brands']:
            if brand.get('display_check') == 'sender_only':
                continue
            names = ([name for name in brand.get('claim_names') or brand['display_names'] if not name.isascii()]
                     if region == 'cn' else brand['display_names'])
            if names:
                brands.append({
                    'name': brand['name'], 'region': region,
                    'names': tuple(sorted(names, key=len, reverse=True)),
                    'domains': frozenset(normalize_domain(domain) for domain in (
                        *brand['official_domains'], *brand.get('gov_suffixes', ()), *brand.get('brand_tlds', ()))),
                })
    return tuple(brands)


BRANDS = _load_brands()
_SIGNATURE = re.compile(r'^\s*[【\[]([^】\]\n]{1,24})[】\]]|[【\[]([^】\]\n]{1,24})[】\]]\s*$')


def _names(text: str, name: str, *, opening: bool) -> bool:
    """Whether text shows name: anywhere in a signature, or at its very start."""
    folded = unicodedata.normalize('NFKC', text).casefold()
    if name.isascii():
        pattern = r'\s*'.join(map(re.escape, name.casefold().split()))
        found = (re.match if opening else re.search)(rf'(?<![a-z0-9])(?:{pattern})(?![a-z0-9])', folded.lstrip())
        return found is not None
    joined = ''.join(folded.split())
    return joined.startswith(name.casefold()) if opening else name.casefold() in joined


def claimed_brand(text: str) -> dict | None:
    """The organisation a text says it comes from: its signature (【…】 or […] at the start or
    end) or the name it opens with. A later mention ("我用工行转你了") is no claim."""
    text = clean_text(text)
    signatures = [group for match in _SIGNATURE.finditer(text) for group in match.groups() if group]
    for brand in BRANDS:
        for name in brand['names']:
            if any(_names(signature, name, opening=False) for signature in signatures) or _names(text, name, opening=True):
                return brand
    return None


# Hosts with or without a scheme: texts often write ezpass-pay.com/x, and Chinese texts put no
# space around a link (点击t.cn/abc查看). A bare host counts only when the Public Suffix List
# knows its suffix, so file.txt or e.g. is no link.
_LINK = re.compile(
    r'(?<![@A-Za-z0-9.\-])((?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{2,5})?'
    r'(?:/[^\s<>"　-〿一-鿿＀-￯]*)?'
    # An IPv4 host only after an explicit scheme: "version 1.2.3.4" is no link.
    r'|https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?:/[^\s<>"　-〿一-鿿＀-￯]*)?)', re.IGNORECASE)


def text_links(text: str) -> list[tuple[str, str]]:
    """(label, url) for each link, as the email link rules take them; a bare host gets http://."""
    links = []
    for match in _LINK.finditer(clean_text(text)):
        label = match.group(1).rstrip('.,;:!?)\'"')
        url = label if re.match(r'https?://', label, re.IGNORECASE) else 'http://' + label
        host = (urlsplit(url).hostname or '').lower()
        parts = _ORGANIZATIONAL_DOMAINS(host)
        if (parts.suffix and parts.domain) or re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host):
            links.append((label, url))
    return links


def link_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


# "Reply Y, then exit and reopen this text to activate the link", or copy it into a
# browser: phones disable links in texts from unknown senders until the reader replies.
# A request only to reply (to confirm an appointment, or STOP) is not this.
_REOPEN_TO_ACTIVATE = re.compile(
    r"\breply\b.{0,80}?\b(?:re-?open|open\s+(?:(?:this|the|it)\s+)?(?:(?:text\s+)?message\s+|text\s+|sms\s+|link\s+)?again"
    r"|return\s+to\s+(?:this|the)\s+(?:message|text))"
    r"|\bcopy\b.{0,30}?\b(?:link|url|web\s*address|website)\b.{0,40}?\b(?:browser|safari|chrome)\b"
    r"|回复.{0,20}?(?:重新打开|再次打开|重新进入|退出.{0,10}?(?:打开|进入))"
    r"|复制.{0,15}?(?:链接|网址).{0,20}?浏览器|(?:链接|网址).{0,15}?复制.{0,20}?浏览器",
    re.IGNORECASE | re.DOTALL)
# A prize, award or free offer to claim by calling, texting or dialling a number: the prize
# scams of the Mishra and Soni development half. "won't" is no win. A premium-rate number alone
# (09…, 087…) is left out: it marks old British texts, not today's US or Chinese ones.
_PRIZE = re.compile(
    r"\b(?:won(?!['’]t)|winners?|prizes?|claim|award(?:ed)?|rewards?|congratulations|congrats|guaranteed"
    r"|selected\s+to\s+receive|free\s+(?:entry|gift|flights?|holiday|cruise|phone|mobile)|for\s+free"
    r"|gift\s*cards?|vouchers?|cash\s+prize|awaits?\s+collection|unclaimed|complimentary|entitled\s+to)\b",
    re.IGNORECASE)
_CALL_A_NUMBER = re.compile(
    r"\b(?:call|dial|ring|phone|text|txt|send|reply|contact|claim)\b[^.!?\n]{0,40}?(?<![\d£$€])(\+?\d[\d\s-]{3,}\d)",
    re.IGNORECASE)
# Numbering plans tried for a number written without a country code: the US and China, which
# the SMS mode covers, and the UK of the public data. Premium rate is a fact of each plan, not
# a pattern of one dataset.
_NATIONAL_PLANS = ('US', 'GB', 'CN')


def _premium_rate(number: str) -> bool:
    if number.startswith(('+', '00')):
        return _number_type('+' + number.lstrip('+')[2:] if number.startswith('00') else number) == \
            PhoneNumberType.PREMIUM_RATE
    return any(_number_type(number, region) == PhoneNumberType.PREMIUM_RATE for region in _NATIONAL_PLANS)
# Money for little effort (rebates, commissions, part-time or remote pay, sure-win returns,
# gambling) and a request to move to a private messenger, where no platform sees the rest.
# A business's own WeCom ("企业微信") is left out: retailers hand out coupons through it.
_EASY_MONEY = re.compile(
    r"返利|返现|返款|返佣|佣金|提成|兼职|刷单|点赞|做任务|日赚|日结|日入|稳赚|保本|高回报|高收益|代理|博彩|彩票|投注|赌"
    r"|退款|退.{0,2}红包|多收|理赔|赔付|补偿"
    r"|\b(?:part[- ]?time|remote (?:job|work|position)|work from home|daily pay|commission|salary|investment|crypto"
    r"|(?:earn|make)\s+(?:up to\s+)?\$?\d|guaranteed (?:profit|income|returns?))\b"
    r"|\$\d[\d,]*\s*(?:-\s*\$?\d[\d,]*\s*)?(?:/|per|a)\s*(?:day|hour|hr|week)\b",
    re.IGNORECASE)
_PRIVATE_MESSENGER = re.compile(
    r"(?:加|添加|联系|私信)[^，。,.!！?？\n]{0,6}(?<!企业)(?:微信|vx|v信|薇信|威信|qq|扣扣|企鹅|好友|老师|助理)"
    r"|(?<!企业)微信号|qq号|vx[:：]|飞机号|电报|纸飞机"
    r"|\b(?:whats\s?app|telegram|wechat|line id|kakao(?:talk)?)\b",
    re.IGNORECASE)
# Chinese words broken up with symbols ("佣.金", "微|信", "代~理") to slip past filters. The
# rules read the text joined again; four or more breaks are a finding of their own.
_SPLIT_HAN = re.compile(r'(?<=[\u4e00-\u9fff])[.|~*\-_·•]+(?=[\u4e00-\u9fff])')
# An unsolicited job: work, pay or hours, and a way off the platform (a short link, a
# messenger, or "send a message to this number"). Job alerts link to the site itself.
_JOB = re.compile(r"\b(?:remote|part[- ]?time|full[- ]?time|work from home|jobs?|position|hiring|recruit(?:er|ment|ing)?)\b"
                  r"|兼职|招聘|岗位|在家工作|远程工作", re.IGNORECASE)
_JOB_PAY = re.compile(r"\$\s?\d|\b(?:salary|income|daily pay|bonus|commission)\b|\bper (?:day|hour|week)\b"
                      r"|\b\d+\s*(?:hrs?|hours)\s*(?:a |per )?week(?:ly)?\b|\bno experience\b"
                      r"|日结|日薪|月薪|时薪|底薪|工资|佣金|无需经验", re.IGNORECASE)
_JOB_CONTACT = re.compile(r"\b(?:send|text|message|reply|contact|call)\b[^.!?\n]{0,30}\b(?:this|my|our) number\b", re.IGNORECASE)
_SHORTENERS = frozenset({'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 't.ly', 'shorturl.at',
                         'ow.ly', 'buff.ly', 'rebrand.ly', 's.id', 't.cn', 'url.cn', 'dwz.cn', 'tiny.cc'})
# Chinese scam texts, calibrated on the development half of the FBS spam texts (CCS 2020,
# fake base stations in China; docs/evaluation.md). They read a view of the text with
# traditional and look-alike characters made plain (註冊 注册, 婇票 彩票, 氺 水) and spaces
# between Chinese characters removed.
_VARIANTS = str.maketrans({
    '註': '注', '冊': '册', '贈': '赠', '專': '专', '員': '员', '網': '网', '樂': '乐', '楽': '乐', '婇': '彩', '倸': '彩',
    '唫': '金', '氺': '水', '氷': '水', '囍': '喜', '僖': '喜', '萬': '万', '領': '领', '獎': '奖', '驗': '验', '證': '证',
    '碼': '码', '號': '号', '戶': '户', '開': '开', '凱': '开', '體': '体', '錢': '钱', '為': '为', '選': '选', '寳': '宝',
    '記': '记', '査': '查', '內': '内', '現': '现', '賭': '赌', '歀': '款', '餸': '送', '囎': '赠', '賽': '赛', '緹': '提',
    '優': '优', '會': '会', '國': '国', '際': '际', '時': '时', '盤': '盘', '賠': '赔', '視': '视', '訊': '讯', '腦': '脑',
    '請': '请', '進': '进', '詳': '详', '節': '节', '凍': '冻',
})
_CJK_GAP = re.compile(r'(?<=[㐀-鿿0-9])\s+(?=[㐀-鿿])|(?<=[㐀-鿿])\s+(?=[0-9])')
# A notice about a bank account, points or security token that sends the reader to a link or
# a mobile number: "积分可兑换现金，请登录…", "电子密码器将于今日失效，请登入我行网站…",
# "信用卡已冻结，请致电138…". Banks point to their own app, site or 95 number.
_ACCOUNT_SUBJECT = re.compile(r'银行|我行|网银|手机银行|银联|信用卡|储蓄卡|[工建农中交招]行|邮储|工银')
_ACCOUNT_LURE = re.compile(
    r'积分.{0,30}?(?:兑换|兑现|清零|失效|过期|现金|礼包|礼品)'
    r'|(?:密码器|电子密码|u盾|证书|动态口令|口令卡|e令).{0,12}?(?:失效|过期|冻结|停用|升级|激活|效验|校验|更新|维护|到期)'
    r'|(?:账户|帐户|银行卡|信用卡|网银|网上银行|手机银行).{0,12}?(?:冻结|异常|失效|过期|升级|停用|注销|激活|提额|锁定)'
    r'|额度.{0,6}?(?:提升|上调|调整|提高)|(?:提升|上调|调整|提高).{0,10}?额度|实名.{0,8}?补录|资料不全')
# An online gambling site: two of its terms, or one and a sign-up, deposit, payout or bonus
# offer. A top-up offer (充100送20), a game's first-purchase bonus or a bank's deposit and
# withdrawal notice has no gambling term, rebate or deposit bonus.
_GAMBLING_GROUPS = {
    'games': re.compile(r'彩金|菜金|彩票|采票|菜票|娱乐城|娱乐场|娱乐成|乐城|棋牌|百家乐|佰家|百稼|真人(?:视讯|娱乐|荷官|发牌|真钱|游戏|游艺)'
                        r'|荷官|视讯|电子游艺|老虎机|捕鱼|投注|网投|下注|博彩|赌|六合|时时彩|时时采|快三|一肖|特码|赔率|滚球|盘口'
                        r'|bbin|xpj|葡京|威尼斯人|太阳城|vip\s*厅|机麻|爆分|收米'),
    'turnover': re.compile(r'流水|倍水|返水|反水|回水|打码|转码|洗码|水位'),
    'deposit': re.compile(r'首存|续存|存\d*送|存赠|首次入款|入款|多存多送'),
    'signup': re.compile(r'注册.{0,3}送|开户.{0,4}送|新会员|开户'),
    'payout': re.compile(r'提款|取款|出款|出账|秒到'),
    'bonus': re.compile(r'红包|最高送|送[一二三四五六七八九十百千万\d]|豪礼|首充|充\d*送|赠'),
}
_PHONE_NUMBER = re.compile(r'(?<!\d)(?:1[3-9]\d{9}|400\d{7}|0\d{9,11})(?!\d)')
_MOBILE_NUMBER = re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)')
_REACH_OUT = re.compile(r'(?<!\d)(?:1[3-9]\d{9}|400\d{7}|0\d{9,11})(?!\d)|客服|专员|qq|微信|wx|vx|网址|官网|登入|登录|注册')
# Being picked or winning something large, with a link to claim it ("您已被选为幸运观众，将获得
# 8万元及笔记本电脑，请登录…领取"). Shops' coupons ("恭喜获得10元券") are no selection.
_PRIZE_PICKED = re.compile(r'(?:中奖|获奖|抽中|抽选|选为|选定|选中|幸运(?:观众|用户|号码|号|者)|中了|您中|互动者|得主).{0,40}?'
                           r'(?:万|奖金|笔记本|笔极本|电脑|苹果|apple|iphone|汽车|现金|大礼|大奖)', re.DOTALL)
_PRIZE_CLAIM = re.compile(r'领取|兑奖|领奖|查收|查看|验证码|验码|详进|详情')
# A cancelled or delayed flight with compensation through a number: airlines announce changes
# in their app and from their service numbers, and do not pay out by phone.
_FLIGHT_CHANGE = re.compile(r'航班.{0,40}?(?:取消|延误|故障|停飞|无法.{0,4}起飞)', re.DOTALL)
_FLIGHT_PAYOUT = re.compile(r'补偿|赔偿|延误费|误机费')
# A stock-tip group on a messenger ("前私募操盘手建群了，长线牛股今晚公布，进QQ…").
_STOCK = re.compile(r'牛股|股票|炒股|股市|股友|讲股|荐股|操盘|私募|涨停|拉升|主力|黑马|个股')
_GROUP = re.compile(r'进群|建群|开群|入群|加群|群内|群里|(?:qq|微信|wx)群|人满')
# "Look at our old album", "you're in the news, see for yourself", with a link: a lure to
# install malware.
_ALBUM = re.compile(r'相册|影集|照片|留念照|艺术照|视频|录像|上新闻')
_ALBUM_HOOK = re.compile(r'自己看|认真看|看看我们|看完|打开看|瞧瞧|这是怎么回事|上新闻了')


def _chinese_view(text: str) -> str:
    return _CJK_GAP.sub('', unicodedata.normalize('NFKC', text).translate(_VARIANTS).casefold())


def _gambling(text: str) -> bool:
    groups = {name for name, pattern in _GAMBLING_GROUPS.items() if pattern.search(text)}
    games = {match.group() for match in _GAMBLING_GROUPS['games'].finditer(text)}
    return len(games) >= 2 or (bool(groups & {'games', 'turnover', 'deposit'}) and len(groups) >= 2)


def _official_host(host: str) -> bool:
    return any(host == domain or host.endswith('.' + domain) for brand in BRANDS for domain in brand['domains'])


# Senders each region's organisations text from; "none" and "alphanumeric" say nothing.
_EXPECTED_SENDERS = {'cn': frozenset({'short_code', 'cn_port_106'}),
                     'intl': frozenset({'short_code', 'nanp_toll_free'})}
_UNINFORMATIVE_SENDERS = frozenset({'none', 'alphanumeric'})


def sms_findings(sender: str, text: str) -> dict:
    """The SMS rules: points, the floor they set, and their indicators.

    A sender that matches the claimed organisation never lowers the risk: sender numbers
    can be forged (ICBC warns of texts that appear to come from 95588).
    """
    text = clean_text(text)
    kind = classify_sender(sender)
    brand = claimed_brand(text)
    links = text_links(text)
    score, floor, found = 0, 'safe', []
    if brand and kind not in _UNINFORMATIVE_SENDERS and kind not in _EXPECTED_SENDERS[brand['region']]:
        if brand['region'] == 'intl' and kind == 'nanp_long_code':
            # Many genuine US businesses text from registered 10-digit numbers.
            score += 2
            found.append(indicator('medium', 'sms.sender_mismatch_weak', brand=brand['name']))
        else:
            score += 4
            floor = 'medium'
            found.append(indicator('high', 'sms.sender_mismatch', brand=brand['name']))
    if brand:
        host = next((host for host in map(link_host, (url for _label, url in links)) if host and not any(
            host == domain or host.endswith('.' + domain) for domain in brand['domains'])), None)
        if host:
            score += 2
            found.append(indicator('medium', 'sms.link_off_brand', brand=brand['name'], host=host))
    if _REOPEN_TO_ACTIVATE.search(text):
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.reopen_to_activate'))
    if _PRIZE.search(text) and _CALL_A_NUMBER.search(text):
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.prize_callback'))
    breaks = len(_SPLIT_HAN.findall(text))
    joined = _SPLIT_HAN.sub('', text)
    if breaks >= 4:
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.split_words', count=breaks))
    messenger = _PRIVATE_MESSENGER.search(joined)
    if _EASY_MONEY.search(joined) and messenger:
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.external_contact_lure'))
    short_link = any(link_host(url) in _SHORTENERS for _label, url in links)
    if _JOB.search(joined) and _JOB_PAY.search(joined) and (short_link or messenger or _JOB_CONTACT.search(joined)):
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.job_offer'))
    premium = next((match.group(1).strip() for match in _CALL_A_NUMBER.finditer(text)
                    if _premium_rate(re.sub(r'[\s-]', '', match.group(1)))), None)
    if premium:
        score += 4
        floor = 'medium'
        found.append(indicator('high', 'sms.premium_callback', number=premium))
    zh = _chinese_view(joined)
    off_platform = any(not _official_host(link_host(url)) for _label, url in links)
    chinese_rules = (
        ('sms.account_lure', _ACCOUNT_SUBJECT.search(zh) and _ACCOUNT_LURE.search(zh)
         and (off_platform or _MOBILE_NUMBER.search(zh))),
        ('sms.gambling_promo', _gambling(zh) and (links or messenger or _REACH_OUT.search(zh))),
        ('sms.prize_link', _PRIZE_PICKED.search(zh) and _PRIZE_CLAIM.search(zh) and off_platform),
        ('sms.flight_compensation', _FLIGHT_CHANGE.search(zh) and _FLIGHT_PAYOUT.search(zh)
         and _PHONE_NUMBER.search(zh) and ('客服' in zh or '联系' in zh or '致电' in zh)),
        ('sms.stock_group', _STOCK.search(zh) and _GROUP.search(zh)),
        ('sms.album_link', _ALBUM.search(zh) and _ALBUM_HOOK.search(zh) and off_platform),
    )
    for code, fired in chinese_rules:
        if fired:
            score += 4
            floor = 'medium'
            found.append(indicator('high', code))
    return {'score': score, 'floor': floor, 'indicators': found, 'sender_kind': kind,
            'claimed_brand': brand['name'] if brand else None, 'claimed_names': brand['names'] if brand else (),
            'links': links}
