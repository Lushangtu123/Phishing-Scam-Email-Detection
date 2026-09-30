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



CALLBACK_CASES = [
    ('If you do not authorized this charge, you have 24 hours. To cancel and receive an immediate refund of your '
     'transaction, please contact our Customer Care on : +1 (818) 284-4559.', True),
    ('Your Norton subscription has been auto-renewed for $399.99. If this wasn\'t you, call 1-888-555-0147 to cancel.', True),
    ('You have been charged $499 for Geek Squad protection. To dispute this charge call (844) 555 0199 today.', True),
    ('您的账户已自动续费 699 元，如非本人操作，请立即拨打 400-123-4567 办理退款。', True),
    # Genuine receipts and itineraries list numbers for questions or changes.
    ('To change your reservation, please call 1-800-433-7300 and refer to your record locator. '
     'If you have questions regarding our refund policy, please visit www.aa.com/refunds.', False),
    ('From your itinerary, click the How to cancel this hotel reservation link. To make changes after booking, '
     'please call +1 (800) 997-6494.', False),
    ('Questions? Order by Phone? Call 800.538.7424. Why not you? Limited quantities.', False),
    ('Your order has shipped. For questions about your order, call 1-866-220-3355.', False),
    ('If you did not authorize this sign-in, change your password in the app. No phone number is ever needed.', False),
    # "Don't recognize" framing, and letters written for digits to slip past number filters.
    ("YOUR NOTE TO Hayley: Don't recognize this seller, Please contact PayPal at I(888) 673-593I", True),
    ('If you did not make this purchase call +1 (8O8) 555-l234 now.', True),
    # Vanity numbers and words next to numbers are not rewritten.
    ('Questions about your order? Call 1-800-FLOWERS or 1-800-555-0199. Order 12345678 Or visit us.', False),
]


class CallbackRequestTests(unittest.TestCase):
    def test_phone_numbers_with_unexpected_charge_framing_are_flagged_and_receipts_are_not(self):
        for text, expected in CALLBACK_CASES:
            with self.subTest(text=text[:60]):
                self.assertEqual(bool(app._callback_request(text)), expected)

    def test_official_service_numbers_never_count(self):
        text = '您的账户已自动续费，如非本人操作，请拨打 95588 或 400-123-4567。'
        self.assertEqual(app._callback_request(text, frozenset({'4001234567'})), None)
        self.assertIn('95588', app._OFFICIAL_SERVICE_NUMBERS)

    def test_the_finding_quotes_the_number_as_written(self):
        text = "Don't recognize this seller? Please contact PayPal at I(888) 673-593I."
        self.assertEqual(app._callback_request(text), 'I(888) 673-593I')
        self.assertIsNone(app._callback_request(text, frozenset({'8886735931'})))

    def test_callback_request_is_a_high_signal_with_the_number(self):
        body = ('Your McAfee plan has been renewed and you have been charged $349.99. '
                'If this wasn\'t you, call our billing team at 1 (877) 555-0123 to cancel the renewal.')
        result = json.loads(asyncio.run(app.analyze_content_endpoint(
            app.ContentRequest(subject='Payment receipt', body=body))).body)
        item = next(item for item in result['extra_indicators'] if item.get('code') == 'content.callback_request')
        self.assertIn('877', item['params']['number'])
        self.assertIn(result['risk_level'], {'high', 'critical'})


if __name__ == '__main__':
    unittest.main()
