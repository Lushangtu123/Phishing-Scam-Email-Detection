"""Registry entries added on 2026-10-06 from the owner's list of common sites (synthetic inputs).

First batch: RBC, TD, Scotiabank, CIBC, BMO, DPD UK, Evri, Air Canada, Delta, Blizzard and Roblox
by name, and American Airlines, OpenAI, Nintendo and Riot Games as services that verify their own
mail. Second batch: Fidelity Investments, Discover, 1Password, Bitwarden, Hilton Honors and
Emirates by name, and State Farm, Chime, Uber, Lyft, Qatar Airways, British Airways and Target.
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


class RegistryAdditionTests(unittest.TestCase):
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



class SecondBatchTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
