import asyncio
import json
import sys
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app  # noqa: E402

import content_rules  # noqa: E402

import email_structure  # noqa: E402

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
                self.assertEqual(bool(content_rules._sensitive_requests(text)), expected)

    def test_spelled_out_code_lengths_count_like_numerals(self):
        # "six digit" once missed the rule that "6 digit" matched (docs/evaluation.md).
        code = 'content.sensitive_request.one_time_code'
        for text in ('Please send us the six digit verification code that just arrived on your phone '
                     'so we can restore access to your account.',
                     'share your six-digit code with our agent', 'reply with the eight digit security code'):
            with self.subTest(text=text):
                self.assertIn(code, content_rules._sensitive_requests(text))
        for text in ('Your six-digit verification code is 482913. It expires in 10 minutes.',
                     'Never share this six digit code with anyone.',
                     'We will never ask you to send your six-digit code.',
                     'Enter the six digit code on the sign-in page.'):
            with self.subTest(text=text):
                self.assertNotIn(code, content_rules._sensitive_requests(text))

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
                self.assertEqual(content_rules._sensitive_requests(text), [f'content.sensitive_request.{kind}'])
        self.assertEqual(set(content_rules._SENSITIVE_REQUEST_CODES.values()),
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



# (text, kind it must flag or None). A negation or attribution exempts a request only when it
# ends the words before the request in the same clause; each case is paired with a control.
NEGATION_SCOPE_CASES = [
    # A negation elsewhere in the clause does not exempt the request.
    ('Do not worry, please reply with your one-time verification code so I can finish the setup.', 'one_time_code'),
    ('This is not a scam, send us your password to confirm the account.', 'password_pin'),
    ('We will not delay the order, please share the six digit security code with our agent now.', 'one_time_code'),
    ('不要担心，请把验证码发给我，我来帮你完成设置。', 'one_time_code'),
    ('这不是诈骗，请回复短信里的验证码确认身份。', 'one_time_code'),
    # A negation of the request itself does.
    ('Never reply with your one-time verification code.', None),
    ('Reply with your one-time verification code.', 'one_time_code'),
    ('Do not share your verification code with anyone.', None),
    ('Share your verification code with anyone.', 'one_time_code'),
    ('Please never send your password by email.', None),
    ('Please send your password by email.', 'password_pin'),
    ('请勿将验证码告知他人。', None),
    ('请将验证码告知客服。', 'one_time_code'),
    ('千万不要把密码发给任何人。', None),
    ('请把密码发给我们核对。', 'password_pin'),
    # Only the set phrases may stand between the negation and the request.
    ('Do not, under any circumstances, send your password to anyone.', None),
    ('Please, under any circumstances, send your password to our agent.', 'password_pin'),
    ('Please do not — even if asked — share your verification code.', None),
    ('Please — even if asked — share your verification code.', 'one_time_code'),
    ('Never, for your safety, reply with your one-time passcode.', None),
    ('Now, for your safety, reply with your one-time passcode.', 'one_time_code'),
    ('请勿向任何人提供验证码。', None),
    ('向任何人提供验证码。', 'one_time_code'),
    ('千万别轻易告诉别人你的支付密码。', None),
    ('轻易告诉别人你的支付密码。', 'password_pin'),
    # Attribution to someone else, including a negated subject, exempts the request it governs.
    ('If anyone asks you to send your verification code, report it to us.', None),
    ('We ask you to send your verification code to us.', 'one_time_code'),
    ('Scammers may ask you to share your PIN over the phone.', None),
    ('Our agent may ask you to share your PIN over the phone.', 'password_pin'),
    ('Our bank will never ask you to provide your password by email.', None),
    ('Our bank will ask you to provide your password by email.', 'password_pin'),
    ('No one will ask you to share your verification code.', None),
    ('Our agent will ask you to share your verification code.', 'one_time_code'),
    ('Nobody will ask you to send your password.', None),
    ('Our team will ask you to send your password.', 'password_pin'),
    ('如果有人要求你提供验证码，请立即拒绝。', None),
    ('客服要求你提供验证码，请立即回复。', 'one_time_code'),
    ('我们不会要求您发送登录密码。', None),
    ('我们会要求您发送登录密码。', 'password_pin'),
    ('没有人会要求你提供验证码。', None),
    ('客服会要求你提供验证码。', 'one_time_code'),
    # Attribution that does not govern the request does not exempt it.
    ('Scammers are everywhere, so please reply with your verification code to confirm it is you.', 'one_time_code'),
    ('Scammers may ask you to reply with your verification code to confirm it is you.', None),
    ('If anyone asks, tell them you are busy. Now send us your password to finish the setup.', 'password_pin'),
    ('If anyone asks, tell them you are busy, then send us your password to finish the setup.', 'password_pin'),
    ('If anyone asks you to send us your password, tell them you are busy.', None),
    ('Fraudsters target accounts like yours, share the six digit security code with our agent today.', 'one_time_code'),
    ('Fraudsters may ask you to share the six digit security code with an agent.', None),
    ('骗子很多，请把验证码发给我核实身份。', 'one_time_code'),
    ('骗子要求你把验证码发给他们。', None),
    ('谨防诈骗，请回复短信中的验证码完成认证。', 'one_time_code'),
    ('如果有人让你回复短信中的验证码，请拒绝。', None),
]


class NegationScopeTests(unittest.TestCase):
    def test_only_a_negation_or_attribution_that_governs_the_request_exempts_it(self):
        for text, kind in NEGATION_SCOPE_CASES:
            with self.subTest(text=text):
                found = content_rules._sensitive_requests(text)
                if kind is None:
                    self.assertEqual(found, [])
                else:
                    self.assertIn(f'content.sensitive_request.{kind}', found)

    def test_an_unrelated_negation_no_longer_lowers_a_code_request(self):
        rest = 'Please reply with the one-time verification code from the sign-in message so I can finish the setup.'
        for opening in ('Do not worry, ', 'We will not delay the setup, ', 'This is not a scam, '):
            with self.subTest(opening=opening):
                result = json.loads(asyncio.run(app.analyze_content_endpoint(
                    app.ContentRequest(subject='Project update', body=opening + rest))).body)
                self.assertIn('content.sensitive_request.one_time_code',
                              [item.get('code') for item in result['extra_indicators']])
                self.assertIn(result['risk_level'], {'high', 'critical'})


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
                self.assertEqual(bool(content_rules._callback_request(text)), expected)

    def test_official_service_numbers_never_count(self):
        text = '您的账户已自动续费，如非本人操作，请拨打 95588 或 400-123-4567。'
        self.assertEqual(content_rules._callback_request(text, frozenset({'4001234567'})), None)
        self.assertIn('95588', email_structure.OFFICIAL_SERVICE_NUMBERS)

    def test_the_finding_quotes_the_number_as_written(self):
        text = "Don't recognize this seller? Please contact PayPal at I(888) 673-593I."
        self.assertEqual(content_rules._callback_request(text), 'I(888) 673-593I')
        self.assertIsNone(content_rules._callback_request(text, frozenset({'8886735931'})))

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
