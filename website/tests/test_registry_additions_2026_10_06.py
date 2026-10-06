"""Registry entries added on 2026-10-06 from the owner's list of common sites: RBC, TD, Scotiabank,
CIBC, BMO, DPD UK, Evri, Air Canada, Delta, Blizzard and Roblox by name, and American Airlines,
OpenAI, Nintendo and Riot Games as services that verify their own mail (synthetic inputs)."""
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


if __name__ == '__main__':
    unittest.main()
