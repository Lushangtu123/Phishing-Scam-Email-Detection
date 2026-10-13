"""Work and memory budgets for crafted input: CSS selectors and var(), PDF font tables,
and ARC key lookups. Each stops with "analysis incomplete" (or no trust) instead of
holding an analysis thread or its memory."""
import base64
import sys
import threading
import time
import tracemalloc
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import email_structure as es  # noqa: E402
import html_visibility as hv  # noqa: E402
from link_analysis import _extract_links  # noqa: E402

CSS_BUDGET = hv._CASCADE_BUDGET_WARNING
STYLESHEET = hv._STYLESHEET_VISIBILITY_WARNING


def render(html):
    warnings, readings = [], {}
    start = time.perf_counter()
    visible = hv._visible_content_text(html, warnings, readings=readings)
    return visible, warnings, readings, time.perf_counter() - start


def descendant_trap(depth, nesting=40):
    # The first compound exists in the document but is never an ancestor: every way to
    # place the others is tried. 6 combinators took 16.9 s before matching was memoized.
    selector = 'q ' + ' '.join(['div'] * depth) + ' span'
    return (f'<style>{selector}{{font-size:0}}</style>' + '<div>' * nesting
            + '<span>hi</span>' + '</div>' * nesting + '<q>z</q>')


def sibling_trap(depth, siblings=40):
    selector = 'q ~ ' + ' ~ '.join(['p'] * depth) + ' ~ i'
    return f'<style>{selector}{{font-size:0}}</style><div>' + '<p></p>' * siblings + '<i>x</i></div><q>z</q>'


class CascadeBudgetTests(unittest.TestCase):
    def test_backtracking_selectors_finish_and_still_resolve(self):
        for html in (descendant_trap(6), sibling_trap(6)):
            with self.subTest(html=html[:40]):
                _visible, warnings, readings, seconds = render(html)
                self.assertLess(seconds, 1.0)
                self.assertTrue(readings['resolved'])
                self.assertNotIn(CSS_BUDGET, warnings)

    def test_matching_finds_the_same_elements_as_before(self):
        # Memoized matching changes how often, not what, a selector matches.
        html = ('<style>.a .b ~ .c > span{display:none}</style>'
                '<div class="a"><p class="b">x</p><p>y</p><div class="c"><span>HIDDEN</span></div></div>'
                '<div class="c"><span>SHOWN</span></div>')
        _visible, _warnings, readings, _seconds = render(html)
        self.assertNotIn('HIDDEN', readings['certain'])
        self.assertIn('SHOWN', readings['certain'])

    def test_polynomial_work_past_the_budget_is_reported_incomplete(self):
        selector = 'q ' + ' '.join(['b'] * 6) + ' i'
        html = f'<style>{selector}{{font-size:0}}</style>' + '<b>' * 2000 + '<i></i>' * 2000 + '<q>z</q>'
        _visible, warnings, readings, seconds = render(html)
        self.assertLess(seconds, 5.0)  # 429 s before; about 1.3 s here
        self.assertIn(CSS_BUDGET, warnings)
        self.assertIn(STYLESHEET, warnings)
        self.assertFalse(readings.get('resolved'))
        self.assertNotIn('certain', readings)

    def test_var_expansion_past_its_limit_is_reported_incomplete(self):
        variables = ''.join(f'--v{i}:var(--v{i + 1}) var(--v{i + 1}) var(--v{i + 1}) var(--v{i + 1});'
                            for i in range(8)) + '--v8:x;'
        _visible, warnings, readings, _seconds = render(
            f'<style>p{{{variables}color:var(--v0);font-size:0}}</style><p>hello</p>')
        self.assertIn(CSS_BUDGET, warnings)
        self.assertFalse(readings.get('resolved'))

    def test_short_var_chains_still_resolve(self):
        _visible, warnings, readings, _seconds = render(
            '<style>p{--a:0;--b:var(--a);font-size:var(--b)}</style><p>tiny</p><div>shown</div>')
        self.assertNotIn(CSS_BUDGET, warnings)
        self.assertTrue(readings['resolved'])
        self.assertNotIn('tiny', readings['certain'])

    def test_link_labels_share_one_budget(self):
        selector = 'q ' + ' '.join(['b'] * 5) + ' i'
        label = f'<style>{selector}{{font-size:0}}</style>' + '<b>' * 60 + '<i></i>' * 60 + '<q>z</q>'
        anchor = f'<a href="https://e.example/">{label}</a>'
        start = time.perf_counter()
        links = _extract_links(anchor * (60000 // len(anchor)), hidden_labels=True)
        self.assertLess(time.perf_counter() - start, 6.0)  # 30 s with a budget per label
        self.assertEqual(len(links), 60000 // len(anchor))

    def test_budget_is_per_thread(self):
        seen = {}

        def run(name):
            with hv.shared_cascade_budget():
                seen[name] = hv._SHARED_CASCADE_BUDGET.get()
        threads = [threading.Thread(target=run, args=(name,)) for name in 'ab']
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIsNot(seen['a'], seen['b'])
        self.assertIsNone(hv._SHARED_CASCADE_BUDGET.get())


def font_pdf(fonts, *, shared=True, link=False):
    """fonts Type0 fonts whose ToUnicode CMaps each map 65,536 codes: one CMap they share,
    or one each."""
    cmap = zlib.compress(b'begincmap 1 beginbfrange <0000> <FFFF> <0041> endbfrange endcmap', 9)
    objects, names = [], b''
    for index in range(1 if shared else fonts):
        objects.append(b'%d 0 obj <</Length %d /Filter /FlateDecode>> stream\n' % (100 + index, len(cmap))
                       + cmap + b'\nendstream endobj')
    objects.append(b'2 0 obj <</W [0 65535 500] /DW 1000>> endobj')
    for index in range(fonts):
        objects.append(b'%d 0 obj <</Type /Font /Subtype /Type0 /ToUnicode %d 0 R /DescendantFonts [2 0 R]>> endobj'
                       % (10 + index, 100 if shared else 100 + index))
        names += b'/F%d %d 0 R ' % (index, 10 + index)
    content = b'BT /F0 12 Tf (AB) Tj ET'
    objects.append(b'3 0 obj <</Type /Page /Contents 4 0 R /Resources <</Font <<' + names + b'>> >> >> endobj')
    objects.append(b'4 0 obj <</Length %d>> stream\n' % len(content) + content + b'\nendstream endobj')
    if link:
        objects.append(b'5 0 obj <</Type /Annot /A <</S /URI /URI (https://evil.example/x)>> >> endobj')
    return b'%PDF-1.4\n' + b'\n'.join(objects) + b'\n%%EOF'


def peak_mib(function, *args):
    tracemalloc.start()
    try:
        result = function(*args)
        return result, tracemalloc.get_traced_memory()[1] / 2 ** 20
    finally:
        tracemalloc.stop()


class PdfFontBudgetTests(unittest.TestCase):
    def test_fonts_sharing_a_cmap_expand_it_once(self):
        one, one_peak = peak_mib(es.pdf_text, font_pdf(1))
        many, many_peak = peak_mib(es.pdf_text, font_pdf(30))
        self.assertEqual(one, many)
        # 388 MiB for 30 fonts before; the shared table is built once.
        self.assertLess(many_peak, one_peak * 1.5)

    def test_distinct_cmaps_past_the_document_budget_stop(self):
        with self.assertRaises(es._PdfResourceLimit):
            es.pdf_text(font_pdf(30, shared=False))
        self.assertTrue(es.pdf_text(font_pdf(2, shared=False)))  # 131,072 entries fit

    def test_attachments_share_one_budget_and_keep_their_links(self):
        attachment = base64.b64encode(font_pdf(1, link=True))
        parts = b''.join(b'--b\r\nContent-Type: application/pdf; name=a%d.pdf\r\n'
                         b'Content-Transfer-Encoding: base64\r\n\r\n%s\r\n' % (index, attachment)
                         for index in range(10))
        raw = (b'From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n'
               b'Content-Type: multipart/mixed; boundary=b\r\n\r\n' + parts + b'--b--\r\n')
        structure = es.analyze_raw_email(raw)
        attachments = structure['attachments']
        self.assertTrue(all(item.get('extracted_links') == ['https://evil.example/x'] for item in attachments))
        # Three 65,536-code tables (plus widths) fill the message's budget.
        self.assertLess(sum('extracted_text' in item for item in attachments), len(attachments))
        warning = es.message_text('warning.attachment_resource_limit')
        self.assertIn(warning, structure['parse_warnings'])



def stream_pdf(content: bytes, *, link: bool = False) -> bytes:
    """A one-page PDF whose compressed content stream is content."""
    stream = zlib.compress(content, 9)
    annotation = b'3 0 obj << /Type /Annot /A << /S /URI /URI (https://evil.example/x) >> >> endobj\n' if link else b''
    return (b'%PDF-1.4\n1 0 obj << /Type /Page /Contents 2 0 R >> endobj\n2 0 obj << /Length '
            + str(len(stream)).encode() + b' /Filter /FlateDecode >> stream\n' + stream
            + b'\nendstream endobj\n' + annotation + b'%%EOF')


def pdf_message(*documents) -> bytes:
    parts = b''.join(b'--b\r\nContent-Type: application/pdf; name=a%d.pdf\r\n'
                     b'Content-Transfer-Encoding: base64\r\n\r\n%s\r\n' % (index, base64.b64encode(document))
                     for index, document in enumerate(documents))
    return (b'From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n'
            b'Content-Type: multipart/mixed; boundary=b\r\n\r\n' + parts + b'--b--\r\n')


class PdfMessageBudgetTests(unittest.TestCase):
    warning = es.message_text('warning.attachment_resource_limit')

    def test_one_document_at_its_own_limits_is_not_cut(self):
        # 300,000 tokens and 4 MB inflated are each a document's own limit, unchanged.
        for content in (b'BT ' + b'x ' * 160_000 + b'ET', b'BT (Hello) Tj ET ' + b' ' * 4_200_000):
            structure = es.analyze_raw_email(pdf_message(stream_pdf(content, link=True)))
            self.assertNotIn(self.warning, structure['parse_warnings'])
            self.assertEqual(structure['attachments'][0].get('extracted_links'), ['https://evil.example/x'])

    def test_many_token_heavy_documents_share_one_budget(self):
        # 76 such PDFs fit in a 55 KB message: 7.5 s with a budget each.
        document = stream_pdf(b'BT (Pay now) Tj ' + b'x ' * 160_000 + b'ET', link=True)
        start = time.perf_counter()
        structure = es.analyze_raw_email(pdf_message(*[document] * 40))
        self.assertLess(time.perf_counter() - start, 2.0)
        self.assertIn(self.warning, structure['parse_warnings'])
        attachments = structure['attachments']
        self.assertIn('Pay now', attachments[0].get('extracted_text', ''))
        self.assertTrue(all(item.get('extracted_links') == ['https://evil.example/x'] for item in attachments))

    def test_inflated_bytes_are_shared_across_documents(self):
        document = stream_pdf(b'BT (Hello) Tj ET ' + b' ' * 4_200_000)
        structure = es.analyze_raw_email(pdf_message(*[document] * 5))
        self.assertIn(self.warning, structure['parse_warnings'])
        self.assertIn('Hello', structure['attachments'][0].get('extracted_text', ''))
        self.assertNotIn('extracted_text', structure['attachments'][-1])

    def test_a_document_read_alone_has_its_own_budget(self):
        document = stream_pdf(b'BT (Hello) Tj ' + b'x ' * 160_000 + b'ET')
        self.assertIn('Hello', es.pdf_text(document))
        self.assertIn('Hello', es.pdf_text(document))

def arc_set(instance, selector=b'arc-1', domain=b'google.com', extra=b''):
    return (b'ARC-Seal: i=%d; a=rsa-sha256; t=1; cv=%s; %sd=%s; s=%s; b=AAAA\r\n'
            % (instance, b'none' if instance == 1 else b'pass', extra, domain, selector)
            + b'ARC-Message-Signature: i=%d; a=rsa-sha256; c=relaxed/relaxed; %sd=%s; s=%s; h=from; bh=AAAA; b=AAAA\r\n'
            % (instance, extra, domain, selector)
            + b'ARC-Authentication-Results: i=%d; mx.google.com; dkim=pass\r\n' % instance)


def arc_message(*sets):
    return b''.join(sets) + b'From: a@dropbox.com\r\nTo: b@example.com\r\nSubject: s\r\n\r\nbody\r\n'


class ArcLookupTests(unittest.TestCase):
    def setUp(self):
        self.lookups = []
        es._ARC_KEY_CACHE.clear()

    def dns(self, name, timeout=5):
        self.lookups.append(name)
        return None

    def test_a_decoy_tag_cannot_pass_the_sealer_check(self):
        # x-d=google.com once made the pre-check read google.com while the verifier
        # looked up the key at the real d=evil.example.
        raw = arc_message(arc_set(1, domain=b'evil.example', extra=b'x-d=google.com; '))
        self.assertIsNone(es.arc_sealed_results(raw, dnsfunc=self.dns))
        self.assertEqual(self.lookups, [])

    def test_lookups_are_checked_where_they_are_made(self):
        guarded = es._guarded_arc_dns(self.dns, time.monotonic() + 5)
        for name in (b'sel._domainkey.evil.example.', b'sel._domainkey.google.com.evil.example.',
                     b'evil.example.', b'sel._domainkey.google.com\n.evil.example', 'sel._domainkey.evil.example'):
            self.assertIsNone(guarded(name))
        self.assertEqual(self.lookups, [])
        guarded(b'arc-20160816._domainkey.google.com.')
        self.assertEqual(self.lookups, [b'arc-20160816._domainkey.google.com.'])

    def test_a_long_chain_makes_a_bounded_number_of_lookups(self):
        raw = arc_message(*(arc_set(instance, selector=b'sel%d' % instance) for instance in range(20, 0, -1)))
        self.assertIsNone(es.arc_sealed_results(raw, dnsfunc=self.dns))
        self.assertLessEqual(len(self.lookups), es._ARC_MAX_LOOKUPS)
        self.assertGreater(len(self.lookups), 0)

    def test_slow_dns_stops_at_the_deadline(self):
        def slow(name, timeout=5):
            self.lookups.append((name, timeout))
            time.sleep(min(timeout, 0.3))
            return None
        raw = arc_message(*(arc_set(instance, selector=b'sel%d' % instance) for instance in range(20, 0, -1)))
        start = time.perf_counter()
        with patch.object(es, '_ARC_VERIFY_SECONDS', 0.8):
            self.assertIsNone(es.arc_sealed_results(raw, dnsfunc=slow))
        self.assertLess(time.perf_counter() - start, 2.5)
        self.assertLessEqual(len(self.lookups), 4)
        self.assertTrue(all(timeout <= 0.8 for _name, timeout in self.lookups))

    def test_busy_verification_threads_mean_no_trust_without_waiting(self):
        raw = arc_message(arc_set(1))
        with patch.object(es._arc_pool, 'submit', return_value=None):
            start = time.perf_counter()
            self.assertIsNone(es.arc_sealed_results(raw, dnsfunc=self.dns))
        self.assertLess(time.perf_counter() - start, 0.5)
        self.assertEqual(self.lookups, [])

    def test_verification_runs_off_the_calling_thread(self):
        threads = []

        def dns(name, timeout=5):
            threads.append(threading.current_thread().name)
            return None
        es.arc_sealed_results(arc_message(arc_set(1)), dnsfunc=dns)
        self.assertTrue(threads)
        self.assertTrue(all(name.startswith('arc') for name in threads))


if __name__ == '__main__':
    unittest.main()
