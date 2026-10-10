"""Chinese lures: words split by brackets and symbols, and mailbox upgrade notices whose
sign-in link leaves the sender's domain (synthetic inputs, text rules only)."""
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

LURE = '<p>亲爱的用户：为了提高邮件系统的安全性，用户需登录新邮件系统将原有数据备案进行升级，逾期将停止服务。</p>'


def analyze(body, subject='邮箱系统升级'):
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(subject=subject, body=body))).body)


def analyze_eml(sender, body, subject='邮件系统迁移通知'):
    raw = (f'From: {sender}\r\nTo: user@school.edu.cn\r\nSubject: {subject}\r\n'
           'Content-Type: text/html; charset=utf-8\r\n\r\n' + body).encode()
    with patch.object(app, '_content_pipeline', None):
        return json.loads(asyncio.run(app._analyze_content(app.ContentRequest(), es.analyze_raw_email(raw),
                                                           observe_sender_history=False)).body)


def codes(result):
    return {item.get('code') for item in result['extra_indicators']}


class SplitWordTests(unittest.TestCase):
    """Senders put brackets and symbols inside Chinese words to break keyword matches."""

    def test_keywords_match_through_inserted_symbols(self):
        for text in ('将被〈关闭', '将被（关）闭', '将 被 关 闭', '将被*关#闭'):
            with self.subTest(text=text):
                self.assertTrue(content_rules._keyword_matches(text, '将被关闭'))
        # Sentence punctuation still separates words.
        self.assertFalse(content_rules._keyword_matches('将被。关闭', '将被关闭'))

    def test_a_subsidy_lure_split_by_brackets_is_found(self):
        self.assertTrue(content_rules._subsidy_lure('2023年第一季度《财 政》补〉贴已发放，扫码领取'))
        self.assertTrue(content_rules._subsidy_lure('个人劳动（补贴））今日立即申请'))
        self.assertFalse(content_rules._subsidy_lure('财政补贴已发放，请查收'))

    def test_compaction_keeps_letters_digits_and_sentence_breaks(self):
        self.assertEqual(content_rules._han_compact('《财 政》补〉贴 2023 年。下 发'), '《财政补贴2023年。下发')


class MailboxLureTests(unittest.TestCase):
    def test_a_sign_in_link_off_the_senders_domain(self):
        result = analyze(LURE + '<a href="https://qiyeyouxiang-bazx.com/x">点此登录完成本次升级</a>')
        self.assertEqual(result['risk_level'], 'high')
        self.assertIn('content.mailbox_lure', codes(result))
        self.assertIn('credential', result['mail_type']['tactics'])
        # A label split by symbols is the same label.
        self.assertIn('content.mailbox_lure', codes(analyze(LURE + '<a href="https://x-mail.top/x">点〉此登〈录</a>')))

    def test_a_school_or_provider_notice_linking_to_its_own_sign_in(self):
        own = analyze_eml('网络中心 <it@school.edu.cn>', LURE + '<a href="https://mail.school.edu.cn/">点此登录新系统</a>')
        self.assertNotIn('content.mailbox_lure', codes(own))
        for link in ('https://mail.163.com/', 'https://exmail.qq.com/login', 'https://outlook.office.com/mail/'):
            with self.subTest(link=link):
                self.assertNotIn('content.mailbox_lure', codes(analyze(LURE + f'<a href="{link}">点击登录</a>')))

    def test_a_spoofed_school_sender_linking_elsewhere(self):
        spoofed = analyze_eml('网络中心 <it@school.edu.cn>', LURE + '<a href="https://www.loppu.top/school">点此登录新系统</a>')
        self.assertIn('content.mailbox_lure', codes(spoofed))

    def test_the_lure_needs_its_wording_and_an_action_link(self):
        self.assertNotIn('content.mailbox_lure', codes(analyze(LURE + '<a href="https://example.org/news">查看新闻</a>')))
        self.assertNotIn('content.mailbox_lure', codes(analyze(
            '<p>欢迎订阅我们的新闻。</p><a href="https://example.org/login">点此登录</a>', subject='新闻')))
        # Mailbox and upgrade in different sentences are no lure.
        self.assertFalse(content_rules._mailbox_lure('邮箱很好用。系统将在周末升级。', [('点此登录', 'https://example.org/')]))


class OtherLanguageMailboxLureTests(unittest.TestCase):
    """The same lures in English and other languages: only threats to the mailbox count."""

    def test_lures(self):
        off = 'https://recover-mail.web.app/x'
        for text, label in (
                ('Your 14 incoming emails are stuck on the mail server and will be deleted.', 'Retrieve 14 Emails'),
                ('Your mailbox storage is full. Messages are on hold.', 'Release messages'),
                ('jose@example.org username authentication will expire on 19 Apr; your email will be blocked.', 'Keep my password'),
                ('귀하의 우편함 할당량이 적습니다.', '업그레이드'),
                ('Ваш почтовый ящик истекает сегодня.', 'Обновить'),
                ('Vous avez 4 messages bloqués.', 'Lire les messages')):
            with self.subTest(text=text):
                self.assertTrue(content_rules._mailbox_lure(text, [(label, off)]))

    def test_genuine_notices(self):
        # Sign-up confirmations through a mailing service's tracking domain.
        self.assertFalse(content_rules._mailbox_lure('Please verify your email address to finish signing up.',
                                           [('Verify email', 'https://u123.ct.sendgrid.net/ls/click?x')]))
        # A provider's own storage notice, or a link to a known provider's sign-in.
        self.assertFalse(content_rules._mailbox_lure('Your mailbox is almost full.', [('Upgrade', 'https://one.google.com/storage')]))
        self.assertFalse(content_rules._mailbox_lure('Your mailbox is almost full.', [('Sign in', 'https://outlook.live.com/')]))
        self.assertFalse(content_rules._mailbox_lure('Your mailbox is almost full.', [('Upgrade', 'https://mail.example.org/plans')],
                                           'it@example.org'))
        # Newsletter boilerplate.
        self.assertFalse(content_rules._mailbox_lure('If this email is not displayed correctly, view it in your browser.',
                                           [('View in browser', 'https://news.example.org/view')]))


if __name__ == '__main__':
    unittest.main()
