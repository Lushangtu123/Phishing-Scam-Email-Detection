"""Counterfactual families of version 2 (docs/evaluation.md, 2026-10-19): each removes its evidence
where it is found, with the points and floor it adds; replays run through the evaluation's own
analyzer; a replay without intervention reproduces the baseline. Synthetic inputs only, reused
from the rule tests."""
from collections import Counter
from functools import partial
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app  # noqa: E402
import content_rules  # noqa: E402
import link_analysis  # noqa: E402
from test_hidden_text_rules import CALLBACK, MAILBOX  # noqa: E402
from test_mixed_script_words import REQUEST, cyrillic  # noqa: E402
from test_review_2026_10_01 import deployment_pipeline  # noqa: E402
from test_salting_and_attachment_lures import FILLER, html_mail, pdf, with_attachment  # noqa: E402
from tools.counterfactual_evidence import (  # noqa: E402
    FAMILIES, V1_FAMILIES, CounterfactualEvidence, reanalyze_without,
)
from tools.evaluate_serving_pipeline import analyze_record  # noqa: E402

RANK = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
MAILBOX_PDF = ['Dear User, your email account mailbox requires immediate update.',
               'Click here for reactivation of your web-mail account.']
OFF_DOMAIN = ['http://mailfix.example-host.net/']
PREFILLED = ('From: Joyt Master <billing@vps-mailer.example.com>\r\nTo: jose@example.org\r\nSubject: Document\r\n'
             'Content-Type: text/html; charset=utf-8\r\n\r\n<p>A document was shared with you.</p>'
             '<a href="https://royalgarden.example.shop/cn/?email=jose@example.org">View document</a>').encode()
LUNCH = 'The team lunch is on Friday at noon in the main hall.'
SINGLE_LINK_RULES = ('link_display_mismatch', 'link_brand_lookalike')


def replayed(collector):
    """The families replayed for an input whose baseline has neither single link rule."""
    return [family for family in collector.families if family not in SINGLE_LINK_RULES]


def pasted(body, subject='Project update'):
    return {'subject': subject, 'body': body}


def eml(raw: bytes) -> dict:
    return {'eml_path': 'synthetic.eml', '_eml_bytes': raw}


def hidden(text):
    return f'<p>Team lunch on Friday at noon.</p><div style="display:none">{text}</div>'


def attached(inner: bytes, body='See the attached message.') -> bytes:
    """A message that attaches another, as a forwarded .eml."""
    return ('From: Colleague <pat@example.org>\r\nTo: user@example.org\r\nSubject: Forward\r\nMIME-Version: 1.0\r\n'
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            f'{body}\r\n--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename="fwd.eml"\r\n\r\n'
            ).encode() + inner + b'\r\n--b--\r\n'


def findings(result):
    """Each finding as (code, prefixes), with repeats."""
    return Counter((item.get('code'), tuple(prefix['code'] for prefix in item.get('prefixes', ())))
                   for item in result['extra_indicators']
                   if str(item.get('code', '')).startswith(('content.', 'link.', 'structure.', 'sender.')))


def without_code(counter, codes):
    return Counter({key: count for key, count in counter.items() if key[0] not in codes})


class RuleFamilyTests(unittest.TestCase):
    """The text model is off, so scores and floors are the rules' own."""

    def setUp(self):
        patcher = patch.object(app, '_content_pipeline', None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_removed(self, row, family, codes, points, floor):
        """An isolated finding: its codes go, the score falls by its points, the floor returns to
        what the other evidence sets, and every other finding stays."""
        codes = {codes} if isinstance(codes, str) else set(codes)
        base, after = analyze_record(row), reanalyze_without(row, family)
        self.assertTrue(codes & {code for code, _prefixes in findings(base)}, 'the input must show the finding')
        self.assertEqual(findings(after), without_code(findings(base), codes))
        self.assertEqual(base['total_score'] - after['total_score'], points)
        self.assertEqual(after['risk_floor'], floor)
        return base, after

    def test_text_requests_in_the_body_hidden_text_and_attachment_text(self):
        self.assert_removed(pasted(CALLBACK), 'text_requests', 'content.callback_request', 4, 'safe')
        self.assert_removed(pasted(REQUEST, 'Account'), 'text_requests', 'content.sensitive_request.password_pin', 4, 'safe')
        # Found only in text that styles may hide: +3 and a Medium floor (app._fuse_content_result).
        self.assert_removed(pasted(hidden(CALLBACK)), 'text_requests', 'content.callback_request', 3, 'safe')
        # Attachment text: +4 and a High floor; the sender's Medium floor remains.
        self.assert_removed(eml(with_attachment(pdf([CALLBACK]), 'invoice.pdf', 'application/pdf')),
                            'text_requests', 'content.callback_request', 4, 'medium')

    def test_lures_shown_hidden_and_in_attachments(self):
        self.assert_removed(pasted(MAILBOX.format(attributes='class="button"'), 'Mailbox'), 'lures',
                            'content.mailbox_lure', 4, 'safe')
        self.assert_removed(pasted(MAILBOX.format(attributes='style="display:none"'), 'Mailbox'), 'lures',
                            'content.mailbox_lure', 3, 'safe')
        self.assert_removed(eml(with_attachment(pdf(MAILBOX_PDF, OFF_DOMAIN), 'notice.pdf', 'application/pdf')),
                            'lures', 'content.attachment_mailbox_lure', 4, 'medium')

    def test_html_tricks(self):
        self.assert_removed(pasted('<form><input type="password"></form><p>Team lunch on Friday.</p>', 'Form'),
                            'html_tricks', 'content.password_form', 4, 'safe')
        padding = ('<a href="https://parcel-notice.example.com/r"><b>Sorry we missed you! Schedule your next '
                   f'delivery date.</b></a><p style="color:#FFFFFF;font-size:8px;">{FILLER}</p>')
        self.assert_removed(eml(html_mail(padding)), 'html_tricks', 'content.hidden_padding', 3, 'medium')
        self.assert_removed(eml(PREFILLED), 'html_tricks', 'link.recipient_prefilled', 3, 'high')
        # A request only text styles may hide shows is the hidden finding itself.
        self.assert_removed(pasted(hidden(CALLBACK)), 'html_tricks', 'content.callback_request', 3, 'safe')

    def test_weak_cues_one_at_a_time(self):
        for row, code, points, floor in (
                (pasted('Great news!!! ' + LUNCH, 'Lunch'), 'content.exclamation_marks', 1, 'safe'),
                (pasted(LUNCH.upper() + ' PLEASE BRING YOUR BADGE.', 'Lunch'), 'content.capitalization', 1, 'safe'),
                (pasted('Dear Customer, ' + LUNCH, 'Lunch'), 'content.generic_greeting', 2, 'safe'),
                (pasted('The approved budget for the new building is $9,500,000 this year.', 'Budget'),
                 'content.large_amounts', 2, 'safe'),
                (pasted('Click here to see the menu. Click here to see the map. ' + LUNCH, 'Lunch'),
                 'content.generic_cta', 1, 'safe'),
                (pasted('Your P@yP@l receipt for the team lunch is attached.', 'Notice'), 'content.obfuscation', 3, 'safe'),
                # Its Medium floor goes with it; the look-alike letters are still read as Latin.
                (pasted('Hello ' + cyrillic('team') + ', lunch is at noon.', 'Lunch'), 'content.mixed_script_words', 3, 'safe'),
                (pasted('The slides from the team meeting: https://bit.ly/demo', 'Slides'), 'content.shortened_urls', 2, 'safe'),
                (pasted(LUNCH, 'Lunch on Friday??'), 'content.subject_question_marks', 1, 'safe'),
                (pasted(' '.join(f'https://example.org/page{index}' for index in range(7)), 'Links'),
                 'content.url_count', 1, 'safe'),
                (eml(b'From: PayPaI Service <service@billing-desk.example.com>\r\nTo: user@example.org\r\n'
                     b'Subject: Notice\r\n\r\nThe team lunch is on Friday.\r\n'), 'content.obfuscation', 3, 'high')):
            with self.subTest(code=code, row=str(row)[:60]):
                self.assert_removed(row, 'weak_cues', code, points, floor)

    def test_cues_scored_inline_match_the_input_without_them(self):
        # Exclamation marks, mixed-script words, subject question marks and the link count have no check
        # of their own; the replay subtracts their points. It must equal the input without the cue.
        for row, control in (
                (pasted('Great news!!! ' + LUNCH, 'Lunch'), pasted('Great news... ' + LUNCH, 'Lunch')),
                (pasted('Hello ' + cyrillic('team') + ', lunch is at noon.' + ' Your password resets today.', 'Lunch'),
                 pasted('Hello team, lunch is at noon.' + ' Your password resets today.', 'Lunch')),
                (pasted(LUNCH, 'Lunch on Friday??'), pasted(LUNCH, 'Lunch on Friday.')),
                (pasted(' '.join(f'https://example.org/page{index}' for index in range(7)), 'Links'),
                 pasted(' '.join(f'https://example.org/page{index}' for index in range(6)), 'Links'))):
            with self.subTest(row=str(row)[:60]):
                after, plain = reanalyze_without(row, 'weak_cues'), analyze_record(control)
                for key in ('risk_level', 'total_score', 'risk_floor', 'category_results'):
                    self.assertEqual(after[key], plain[key], key)
                self.assertEqual(findings(after), findings(plain))

    def test_combined_attachment_findings_share_one_increment(self):
        # Attachment requests and lures add one +4 and a High floor between them.
        row = eml(with_attachment(pdf([*MAILBOX_PDF, CALLBACK], OFF_DOMAIN), 'notice.pdf', 'application/pdf'))
        base, after = analyze_record(row), reanalyze_without(row, 'text_requests')
        self.assertEqual(findings(after), without_code(findings(base), {'content.callback_request'}))
        self.assertIn(('content.attachment_mailbox_lure', ('prefix.pdf_text',)), findings(after))
        self.assertEqual((after['total_score'], after['risk_floor']), (base['total_score'], 'high'))
        both = reanalyze_without(row, 'lures')
        self.assertIn(('content.callback_request', ('prefix.pdf_text',)), findings(both))
        self.assertEqual(both['total_score'], base['total_score'])

    def test_an_attached_message_merges_by_maximum(self):
        inner = html_mail(f'<p>{CALLBACK}</p>', sender='Billing <billing@renewals-desk.example.com>')
        row = eml(attached(inner))
        # The same outer message without its attachment.
        outer = eml(b'From: Colleague <pat@example.org>\r\nTo: user@example.org\r\nSubject: Forward\r\n\r\n'
                    b'See the attached message.\r\n')
        base, after = analyze_record(row), reanalyze_without(row, 'text_requests')
        self.assertIn(('content.callback_request', ('prefix.attached_message',)), findings(base))
        self.assertEqual(findings(after), without_code(findings(base), {'content.callback_request'}))
        # The outer result keeps the maximum of its own evidence and the attached message's.
        own, attachment = reanalyze_without(outer, 'text_requests'), reanalyze_without(eml(inner), 'text_requests')
        self.assertEqual(after['total_score'], max(own['total_score'], attachment['total_score']))
        self.assertEqual(after['risk_floor'], max(own['risk_floor'], attachment['risk_level'], key=RANK.get))
        self.assertEqual(after['message_structure']['nested_messages'][0]['risk_level'], attachment['risk_level'])

    def test_message_structure_clears_attached_messages_too(self):
        inner = b'From: Apple <alice@unrelated.net>\r\nTo: b@example.org\r\nSubject: Hi\r\n\r\nHello there.\r\n'
        row = eml(attached(inner))
        base = analyze_record(row)
        self.assertTrue(any(code.startswith('structure.') and 'prefix.attached_message' in prefixes
                            for code, prefixes in findings(base)))
        after = reanalyze_without(row, 'message_structure')
        self.assertFalse(any(code.startswith('structure.') for code, _prefixes in findings(after)))
        self.assertEqual(findings(after), Counter({key: count for key, count in findings(base).items()
                                                   if not key[0].startswith('structure.')}))

    def test_intent_rules_are_a_family_of_their_own(self):
        rules = ('credential', 'payment')
        analyze = partial(analyze_record, intent_rules=rules)
        fixture = WEBSITE_DIR / 'tests/fixtures/intent_rules/development.jsonl'
        codes = {'content.intent.credential_handover', 'content.intent.payment_redirection'}
        matched = 0
        for line in fixture.read_text(encoding='utf-8').splitlines():
            record = json.loads(line)
            row = pasted(record['body'], record['subject'])
            base = analyze(row)
            found = codes & {code for code, _prefixes in findings(base)}
            if not found:
                continue
            matched += 1
            after = reanalyze_without(row, 'intent_rules', analyze)
            self.assertEqual(findings(after), without_code(findings(base), codes))
            self.assertEqual(base['total_score'] - after['total_score'], 3 * len(found))
            # The other families leave the intent findings in place.
            self.assertTrue(found <= {code for code, _prefixes in findings(reanalyze_without(row, 'weak_cues', analyze))})
            if matched == 3:
                break
        self.assertEqual(matched, 3)
        self.assertNotIn('intent_rules', CounterfactualEvidence().families)
        self.assertIn('intent_rules', CounterfactualEvidence(intent_rules_enabled=True).families)


class ReplaySettingsTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(app, '_content_pipeline', None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_replays_use_the_baseline_mailbox_setting(self):
        seen = []
        original = app.analyze_raw_email

        def parse(raw, **kwargs):
            seen.append(kwargs.get('mailbox_provider'))
            return original(raw, **kwargs)

        row = {**eml(b'From: Alice <notice@paypa1.example>\nSubject: Notes\n\nMeeting notes.'), 'provider': 'gmail'}
        analyze = partial(analyze_record, mailbox_setting='recorded')
        collector = CounterfactualEvidence(analyze=analyze)
        with patch.object(app, 'analyze_raw_email', parse):
            result = analyze(row)
            collector.add(row, 'legitimate', 'alerted', result)
        self.assertEqual(seen, ['gmail'] * (2 + len(replayed(collector))))  # baseline, identity, families

    def test_replays_use_the_baseline_intent_rules(self):
        enabled = []

        def analyze(row):  # the evaluation's analyzer, with its rules
            enabled.append(row)
            return analyze_record(row, intent_rules=('credential',))

        row = pasted(CALLBACK)
        collector = CounterfactualEvidence(analyze=analyze, intent_rules_enabled=True)
        collector.add(row, 'legitimate', 'alerted', analyze(row))
        self.assertEqual(len(enabled), 2 + len(replayed(collector)))
        self.assertIn('intent_rules', collector.families)

    def test_identity_replay_must_reproduce_the_baseline(self):
        row = pasted(CALLBACK)
        result = analyze_record(row)
        collector = CounterfactualEvidence()
        collector.add(row, 'legitimate', 'alerted', result)
        self.assertEqual(collector._identity_verified, 1)
        # A replay under other settings than the baseline's is refused before any removal.
        changed = {**result, 'total_score': result['total_score'] + 1}
        with self.assertRaisesRegex(ValueError, 'does not reproduce'):
            CounterfactualEvidence().add(row, 'legitimate', 'alerted', changed)

    def test_an_exception_inside_a_replay_restores_every_patch(self):
        names = {app: ('_select_message_sender', 'analyze_raw_email', '_analyze_link_destinations', '_content_pipeline',
                       '_mailbox_lure', '_has_password_form', '_read_parts', '_recipient_prefilled_link',
                       '_hidden_text_findings', '_detect_obfuscation', '_has_shortener_url', '_text_rule_findings',
                       'analyze_email_content', 'intent_findings', '_analyze_content_within_budget',
                       '_fuse_content_result'),
                 content_rules: ('_callback_request', '_sensitive_requests', '_excessive_caps_ratio',
                                 '_detect_obfuscation'),
                 link_analysis: ('_visible_link_host', '_label_uses_brand_lookalike')}
        before = {(module, name): getattr(module, name) for module, attributes in names.items() for name in attributes}
        rules = json.dumps(content_rules.CONTENT_RULES, sort_keys=True)
        option, intent = app.MODEL_ONLY_OPTION.get(), app.INTENT_RULES.get()

        def failing(row):
            raise RuntimeError('private text')

        for family in FAMILIES:
            with self.subTest(family=family), self.assertRaises(RuntimeError):
                reanalyze_without(pasted(CALLBACK), family, failing)
        self.assertEqual({key: getattr(*key) for key in before}, before)
        self.assertEqual(json.dumps(content_rules.CONTENT_RULES, sort_keys=True), rules)
        self.assertEqual((app.MODEL_ONLY_OPTION.get(), app.INTENT_RULES.get()), (option, intent))
        # A replay that fails mid-way is counted, and the next input's identity still holds.
        calls = []

        def flaky(row):
            calls.append(row['id'])
            if row['id'] == 'first' and len(calls) > 2:
                raise RuntimeError('private text')
            return analyze_record(row)

        collector = CounterfactualEvidence(analyze=flaky)
        for name in ('first', 'second'):
            row = {**pasted(CALLBACK), 'id': name}
            collector.add(row, 'legitimate', 'alerted', analyze_record(row))
        self.assertEqual(collector._identity_verified, 2)
        self.assertEqual(collector.failure_count, len(replayed(collector)) - 1)  # the first family ran
        self.assertEqual({key: getattr(*key) for key in before}, before)

    def test_a_failing_identity_replay_stops_without_echoing_the_error(self):
        private = 'private-client@example.com'

        def replay(row, family):
            raise RuntimeError(private)

        with self.assertRaises(RuntimeError) as raised:
            CounterfactualEvidence(replay).add({}, 'legitimate', 'alerted', {'risk_level': 'high'})
        self.assertNotIn(private, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        # Every replayed alert must have had its identity verified before a snapshot is written.
        collector = CounterfactualEvidence(lambda row, family: {'risk_level': 'high'})
        collector.add({}, 'legitimate', 'alerted', {'risk_level': 'high'})
        collector._identity_verified -= 1
        with self.assertRaisesRegex(ValueError, 'identity'):
            collector.snapshot({'evaluation_scope': 'local_serving_pipeline', 'model_artifact_sha256': 'a' * 64,
                                'input_integrity': {'evaluated_rows': 1, 'evaluated_cohort_sha256': 'b' * 64}})
        from contextlib import ExitStack
        from tools.counterfactual_evidence import _interventions
        with ExitStack() as stack, self.assertRaises(ValueError):
            _interventions(stack, 'unrecognized')

    def test_attachment_link_rules_are_matched_by_code(self):
        called = []

        def replay(row, family):
            called.append(family)
            return baseline if family is None else {'risk_level': 'low'}

        baseline = {'risk_level': 'high', 'extra_indicators': [{'code': 'link.brand_lookalike'}]}
        CounterfactualEvidence(replay).add({}, 'legitimate', 'alerted', baseline)
        self.assertIn('link_brand_lookalike', called)
        self.assertNotIn('link_display_mismatch', called)

    def test_v1_family_names_are_kept(self):
        self.assertEqual(FAMILIES[:len(V1_FAMILIES)], V1_FAMILIES)
        self.assertEqual(len(set(FAMILIES)), len(FAMILIES))


class OuterFusionTests(unittest.TestCase):
    """Only the outermost final fusion goes without the model probability."""
    ALLOWED = {'risk_level', 'risk_label', 'combined_phishing_score', 'fusion_basis', 'fusion_method',
               'mail_type', 'model_only_review'}

    def setUp(self):
        patcher = patch.object(app, '_content_pipeline', deployment_pipeline(self))
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_only_fusion_differs(self, row):
        base, after = analyze_record(row), reanalyze_without(row, 'outer_fusion_without_model_probability')
        self.assertEqual(set(base), set(after))
        differing = {key for key in base if base[key] != after[key]}
        self.assertLessEqual(differing, self.ALLOWED)
        for key in ('ml_status', 'ml_phishing_probability', 'analysis_warnings', 'extra_indicators',
                    'total_score', 'risk_floor'):
            self.assertEqual(after.get(key), base.get(key), key)
        return base, after

    def test_the_model_reading_stays_and_only_the_fusion_changes(self):
        changed = 0
        for body in (CALLBACK, LUNCH, 'Please review the attached invoice and confirm the payment date.',
                     MAILBOX.format(attributes='class="button"')):
            with self.subTest(body=body[:40]):
                base, after = self.assert_only_fusion_differs(pasted(body))
                self.assertIsNotNone(base.get('ml_phishing_probability'))
                changed += base['risk_level'] != after['risk_level'] or base['fusion_basis'] != after['fusion_basis']
        self.assertGreater(changed, 0)

    def test_attached_messages_are_analysed_as_before(self):
        inner = html_mail('<p>Please review the attached invoice and confirm the payment date.</p>',
                          sender='Billing <billing@renewals-desk.example.com>')
        base, after = self.assert_only_fusion_differs(eml(attached(inner)))
        self.assertEqual(after['message_structure']['nested_messages'], base['message_structure']['nested_messages'])


class CommandLineTests(unittest.TestCase):
    """The serving evaluator hands its own analyzer to the replays."""

    def test_sidecars_replay_with_the_evaluation_settings(self):
        import subprocess
        import tempfile
        from test_review_2026_09_30 import SCAM, message
        deployment_pipeline(self)  # skips where the committed artifact cannot load
        scam = message('billing@renewals-desk.example.com', 'Billing', 'Renewal', SCAM)
        lunch = message('pat@renewals-desk.example.com', 'Pat', 'Lunch', LUNCH)
        row = {**eml(scam), 'provider': 'gmail'}
        with patch.object(app, '_content_pipeline', None):
            # Chosen as Gmail's download, the message reads differently: a replay without it would differ.
            self.assertNotEqual(analyze_record(row, mailbox_setting='recorded'), analyze_record(row))
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            lines = []
            for name, raw, label in (('scam', scam, 'phishing'), ('lunch', lunch, 'legitimate')):
                (folder / f'{name}.eml').write_bytes(raw)
                lines.append(json.dumps({'id': name, 'label': label, 'provider': 'gmail', 'received_at': '2026-09-01',
                                         'eml_path': str(folder / f'{name}.eml')}))
            (folder / 'input.jsonl').write_text('\n'.join(lines) + '\n')
            completed = subprocess.run(
                [sys.executable, str(WEBSITE_DIR / 'tools/evaluate_serving_pipeline.py'), '--input',
                 str(folder / 'input.jsonl'), '--mailbox-setting', 'recorded', '--intent-rules', 'credential',
                 '--counterfactual-output', str(folder / 'counterfactual.json'),
                 '--attribution-output', str(folder / 'attribution.json')],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
            counterfactual = json.loads((folder / 'counterfactual.json').read_text())
            attribution = json.loads((folder / 'attribution.json').read_text())
        self.assertEqual(counterfactual['schema_version'], 'counterfactual-evidence/v2')
        self.assertIn('intent_rules', counterfactual['families'])
        alerts = counterfactual['baseline_outcomes']['phishing_alerted'] + counterfactual['baseline_outcomes']['legitimate_alerted']
        self.assertGreater(alerts, 0)
        self.assertEqual(counterfactual['identity_verified_alerts'], alerts)
        self.assertEqual(attribution['schema_version'], 'evidence-attribution/v2')
        self.assertRegex(counterfactual['tool']['file_sha256'], r'^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
