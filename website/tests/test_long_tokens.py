"""One long run of address characters (docs/superpowers/specs/2026-10-20-long-token-timing-criteria.md).
The mail-address replacement of the mailbox-lure rules was retried from each character of the
run, so a 55,000-character token took the analysis 10 s. It must stay linear, and replace
exactly what the plain pattern replaced."""
import random
import re
import sys
import time
import unittest
from pathlib import Path

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import content_rules  # noqa: E402

# The pattern as it was until 2026-10-20: the reference for what is replaced.
PLAIN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Word characters of several scripts, a combining mark (not a word character), and the
# characters the pattern treats specially.
ALPHABET = 'aZ0_.+-@ é中²!́\n'
# Runs that hold no address, each of which the plain pattern took 8 to 10 s to read: one
# beside an address, so the text holds an "@"; one ending in "@"; a domain with no dot; host-like
# labels; and Han characters, which are word characters too.
LONG = ('a' * 55_000 + ' pat@example.org', 'a' * 55_000 + '@', 'a@' + 'b' * 55_000,
        'x1.' * 18_000 + ' pat@example.org', '中' * 50_000 + ' pat@example.org')


def plain(text):
    return PLAIN.sub(' address ', text)


class LongTokenTests(unittest.TestCase):
    def assertQuick(self, function, *args):
        start = time.perf_counter()
        function(*args)
        # 8 to 10 s with the plain pattern, at most 26 ms now (2026-10-20, one laptop).
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_a_long_run_is_read_once(self):
        for text in LONG:
            with self.subTest(text=text[:12]):
                self.assertQuick(content_rules._without_mail_addresses, text)
                self.assertQuick(content_rules._mailbox_lure, text, [('Verify', 'https://example.net/')])
                self.assertQuick(content_rules._attachment_mailbox_lure,
                                 {'extracted_text': text, 'extracted_links': ['https://example.net/']}, '')

    def test_the_same_addresses_are_replaced(self):
        cases = ['', 'Write to pat@example.org today.', 'a@b', 'a@b.', 'a@b.c', 'a@b.c.+x@y.z', 'a@b.c..x@y.z',
                 'a@b.c+x@y.z', 'x.y@a.b.@c.d', '@@a@b.c', '.@a.b', '-@-.-', 'é@ü.中', 'a@b.c@d.e', 'a@b-c.d-e.f!g@h.i',
                 'pat@example.org.', 'pat@example.org+tag@example.net', 'a@b.c' * 3]
        rng = random.Random(20261020)
        cases += [''.join(rng.choices(ALPHABET, k=rng.randint(0, 40))) for _ in range(3_000)]
        for text in cases:
            self.assertEqual(content_rules._without_mail_addresses(text), plain(text), repr(text))

    def test_the_rules_read_the_text_without_addresses(self):
        # Unchanged behaviour of both callers: an address in the lure does not end its sentence.
        # Each lure matches only through the address.
        lure = 'Your mailbox pat@example.org will be deactivated today.'
        self.assertTrue(content_rules._mailbox_lure(lure, [('Verify now', 'https://example.net/')]))
        self.assertEqual(content_rules._attachment_mailbox_lure(
            {'extracted_text': 'The mailbox pat@example.org will be deactivated today.',
             'extracted_links': ['https://example.net/login']}, 'example.org'), 'example.net')


if __name__ == '__main__':
    unittest.main()
