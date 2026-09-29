import asyncio
import json
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

# (text, should flag). Negatives cover genuine one-time-code emails, reminders not to
# share codes, retail gift cards, and warnings that quote what scammers ask for.
CASES = [
 ("Reply to this email with the 6-digit verification code we just sent to your phone.", True),
 ("Please send your backup recovery codes and buy two gift cards, then reply with the card numbers.", True),
 ("Your verification code is 482913. Enter this code on the sign-in page. Don't share this code with anyone.", False),
 ("Amazon will never ask you to share your one-time password.", False),
 ("If anyone asks you to read out your security code, hang up.", False),
 ("We will never ask you to send us your PIN.", False),
 ("To keep your account open, text us your PIN now.", True),
 ("Move your funds to a new secure wallet to protect them.", True),
 ("Download AnyDesk so our technician can fix your account.", True),
 ("Give the agent the gift card numbers on the back.", True),
 ("Buy a gift card for Mother's Day and save 10%.", False),
 ("Send a gift card to a friend in seconds.", False),
 ("Scammers may ask you to buy gift cards. Don't.", False),
 ("Pay the outstanding balance with Apple gift cards and send photos of the cards.", True),
 ("请将短信验证码回复给客服以完成退款。", True),
 ("验证码为482913，请勿告知他人。任何人索要验证码都是诈骗。", False),
 ("请立即把资金转账到安全账户。", True),
 ("请下载会议软件并共享屏幕。", True),
 ("Confirm your password change by clicking the button.", False),
 ("Reset your password using the link we sent.", False),
 ("We noticed a new sign-in. If this was you, no action is needed.", False),
 ("Please provide your online banking password to verify your identity.", True),
 ("Use code SAVE20 at checkout.", False),
 ("Your email password was changed on June 3.", False),
 ("Email Password Expiration Notification", False),
 ("Text us your PIN to continue.", True),
 ("Email us the verification code from your phone.", True),
 ("Buy gift cards and email them to your friends.", False),
 ("Buy two gift cards and email us the codes.", True),
 ("Pay with your Amazon gift card balance at checkout.", False),
 ("Buy a $50 gift card and we will email it to your friend.", False),
 ("Share this code with friends to get $10 off: SAVE20", False),
 ("Your Apple Account code is: 123456. Don't share it with anyone.", False),
]


class SensitiveRequestTests(unittest.TestCase):
    def test_requests_to_hand_over_codes_secrets_or_payment_are_flagged_and_reminders_are_not(self):
        for text, expected in CASES:
            with self.subTest(text=text):
                self.assertEqual(bool(app._sensitive_requests(text)), expected)

    def test_each_kind_has_its_own_explainable_code(self):
        expected = {
            'Reply with the 6-digit verification code.': 'one_time_code',
            'Text us your PIN now.': 'password_pin',
            'Send us your seed phrase to restore the wallet.': 'recovery_secret',
            'Give the agent the gift card numbers.': 'gift_card',
            'Move your funds to a new secure wallet.': 'crypto_transfer',
            'Download AnyDesk so we can help.': 'remote_access',
        }
        for text, kind in expected.items():
            with self.subTest(text=text):
                self.assertEqual(app._sensitive_requests(text), [f'content.sensitive_request.{kind}'])
        self.assertEqual(set(app._SENSITIVE_REQUEST_CODES.values()),
                         {f'content.sensitive_request.{kind}' for kind in expected.values()})

    def test_rule_adds_one_high_signal_with_every_kind_listed(self):
        body = 'Please reply with the verification code and buy two gift cards, then send the card numbers.'
        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(subject='Account notice', body=body))).body)
        codes = [item['code'] for item in result['extra_indicators']
                 if item.get('code', '').startswith('content.sensitive_request.')]
        self.assertEqual(codes, ['content.sensitive_request.one_time_code', 'content.sensitive_request.gift_card'])
        self.assertIn(result['risk_level'], {'high', 'critical'})
        clean = json.loads(asyncio.run(app.analyze_content_endpoint(app.ContentRequest(
            subject='Your code', body='Your verification code is 482913. Enter it on the sign-in page. '
                                      'Never share this code with anyone.'))).body)
        self.assertFalse([item for item in clean['extra_indicators']
                          if item.get('code', '').startswith('content.sensitive_request.')])


if __name__ == '__main__':
    unittest.main()
