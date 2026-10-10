"""Mailbox lures the rule missed: the reader's address inside the sentence, password-expiry
and can't-send wording, and button labels in more languages or in small capitals
(synthetic inputs, text rules only)."""
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))


import content_rules  # noqa: E402

OFF = 'https://mail-portal.workers.dev/x'


class MailboxLureGapTests(unittest.TestCase):
    def test_the_readers_address_inside_the_sentence(self):
        self.assertTrue(content_rules._mailbox_lure('Попередження: квота jose@example.org перевищена!',
                                          [('Оновіть електронну пошту зараз', OFF)]))
        self.assertTrue(content_rules._mailbox_lure('كلمة السر الخاصة بك لـ jose@example.org تنتهي اليوم',
                                          [('استخدام كلمة المرور الحالية', OFF)]))

    def test_new_wording(self):
        for text, label in (
                ('Your account jose@example.org password expires today.', 'Keep same password'),
                ('The current password for jose@example.org expired today.', 'Confirm account'),
                ('You are unable to send and receive messages from your account.', 'Activate My Account Now'),
                ("Your jose@example.org is out of date, you won't be able to send or receive new messages.",
                 'Confirm your Email'),
                ('There is a new version update of your webmail box.', 'Login to Update Now')):
            with self.subTest(text=text):
                self.assertTrue(content_rules._mailbox_lure(text, [(label, OFF)]))

    def test_new_labels(self):
        for text, label in (
                ('귀하의 우편함 할당량이 적습니다.', '더 많은 공간을 추가'),
                ('由于您的电子邮件帐户受到限制，您的某些电子邮件功能已被暂停。', '移除限制'),
                ('Due to a server error on your e-mail, incoming messages were delayed.', 'Read Delayed Messages'),
                ('The current password for jose@example.org expired today.', 'Cᴏɴғɪʀᴍ ᴀᴄᴄᴏᴜɴᴛ Hᴇʀᴇ')):
            with self.subTest(label=label):
                self.assertTrue(content_rules._mailbox_lure(text, [(label, OFF)]))

    def test_genuine_notices_still_pass(self):
        # A company's own password reminder links to its own domain.
        self.assertFalse(content_rules._mailbox_lure('Your email password expires in 5 days.',
                                           [('Change password', 'https://password.example.org/')], 'it@example.org'))
        # An address near an expiry that is not the mailbox's.
        self.assertFalse(content_rules._mailbox_lure('The invitation sent to jose@example.org expires in 7 days.',
                                           [('View invitation', OFF)]))
        # "Read more" is not "read messages".
        self.assertFalse(content_rules._mailbox_lure('Your mailbox is almost full.', [('Read more', OFF)]))


if __name__ == '__main__':
    unittest.main()
