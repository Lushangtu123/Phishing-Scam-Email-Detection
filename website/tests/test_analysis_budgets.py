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

    def test_vars_that_expand_to_nothing_still_cost_a_step_each(self):
        # Charged only by the length they produced, empty expansions once cost nothing:
        # 8 references per level, 7 levels, 615 bytes took 5.85 s; 12 per level, over 60 s.
        with self.assertRaises(hv._CascadeBudgetExceeded):
            hv._substitute_variables('var(--a)', {'--a': ''}, budget=hv._CascadeBudget(0))
        def page(fan):
            props = ''.join(f'--v{i}:' + f'var(--v{i + 1})' * fan + ';' for i in range(7)) + '--v7:var(--none,);'
            return f'<style>p{{{props}font-size:var(--v0) 0}}</style><p>x</p><i>y</i>'
        _visible, warnings, readings, seconds = render(page(12))
        self.assertLess(seconds, 1.0)
        self.assertNotIn(CSS_BUDGET, warnings)
        # Both expand to the same empty text: the same reading, wide or narrow.
        self.assertEqual(readings, render(page(2))[2])

    def test_repeated_references_expand_the_same_way(self):
        custom = {'--a': 'var(--b) var(--b)', '--b': 'var(--c,red)', '--c': 'var(--missing)'}
        self.assertIsNone(hv._substitute_variables('var(--a)', custom))
        custom['--c'] = 'blue'
        self.assertEqual(hv._substitute_variables('var(--a) var(--a)', custom), 'blue blue blue blue')
        # The same value, 'var(--d7)', expands to x one level down but passes depth 8 seven
        # levels down: what is remembered must be per depth.
        deep = {f'--d{i}': f'var(--d{i + 1})' for i in range(1, 8)} | {'--d8': 'var(--z)', '--z': 'x',
                                                                       '--a': 'var(--d7)'}
        self.assertEqual(hv._substitute_variables('var(--a)', deep), 'x')
        self.assertIsNone(hv._substitute_variables('var(--d1)', deep))
        self.assertIsNone(hv._substitute_variables('var(--a) var(--d1)', deep))

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


def mapped_text_pdf(target_bytes: int, codes: int) -> bytes:
    """A PDF whose font maps code 01 to target_bytes bytes of UTF-16 text, showing it codes times."""
    cmap = b'begincmap 1 beginbfchar <01> <' + b'0041' * (target_bytes // 2) + b'> endbfchar endcmap'
    content = b'BT /F1 12 Tf (' + b'\x01' * codes + b') Tj ET'
    return b''.join([
        b'%PDF-1.4\n',
        b'1 0 obj << /Type /Page /Resources << /Font << /F1 3 0 R >> >> /Contents 2 0 R >> endobj\n',
        b'2 0 obj << /Length %d /Filter /FlateDecode >> stream\n' % len(zlib.compress(content)), zlib.compress(content),
        b'\nendstream endobj\n',
        b'3 0 obj << /Type /Font /Subtype /Type1 /ToUnicode 4 0 R >> endobj\n',
        b'4 0 obj << /Length %d >> stream\n' % len(cmap), cmap, b'\nendstream endobj\n%%EOF'])


class PdfTextMemoryTests(unittest.TestCase):
    def test_one_code_maps_to_at_most_512_bytes_of_text(self):
        mapping, _length = es._pdf_cmap(b'beginbfchar <01> <' + b'0041' * 1000 + b'> endbfchar', [10, 10 ** 6])
        self.assertEqual(len(mapping[b'\x01']), 256)

    def test_mapped_text_is_charged_to_the_font_budget(self):
        # 4,096 codes of 256 characters each: past the 1,000,000 characters a message may map.
        stream = b'beginbfrange <0000> <0FFF> <' + b'00' * 512 + b'> endbfrange'
        with self.assertRaises(es._PdfResourceLimit):
            es._pdf_cmap(stream, [es._MAX_PDF_FONT_ENTRIES, es._MAX_PDF_FONT_TEXT_CHARS])

    def test_text_is_decoded_only_as_far_as_the_limit(self):
        # 50,000 codes of 200 characters were 10,000,000 characters before the text limit cut them.
        document = mapped_text_pdf(400, 50_000)
        text, peak = peak_mib(es.pdf_text, document)
        self.assertEqual(text, 'A' * es._MAX_PDF_TEXT_CHARS)
        self.assertLess(peak, 5)

    def test_long_strings_spend_the_token_budget_as_they_are_read(self):
        budget = [1000]
        tokens = list(es._pdf_tokens(b'(' + b'a' * 5000 + b') Tj', budget))
        self.assertEqual(len(tokens), 1)
        self.assertLess(len(tokens[0][1]), 1000)
        self.assertLessEqual(budget[0], 0)

    def test_short_mapped_text_reads_as_before(self):
        self.assertEqual(es.pdf_text(mapped_text_pdf(4, 3)), 'AAAAAA')

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


def nested_html_message(count: int) -> bytes:
    """A message attaching count messages, each an HTML part with a stylesheet that may hide text."""
    inner = (b'From: inner@example.com\r\nSubject: inner\r\nContent-Type: text/html\r\n\r\n'
             b'<style>.a{font-size:0}</style><p class="a">hidden</p><p>shown</p>\r\n')
    parts = b''.join(b'--b\r\nContent-Type: message/rfc822\r\n\r\n' + inner for _index in range(count))
    return (b'From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n'
            b'Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n'
            b'<style>.a{font-size:0}</style><p class="a">x</p>\r\n' + parts + b'--b--\r\n')


class RequestBudgetTests(unittest.TestCase):
    def test_attached_messages_share_the_request_budget(self):
        import asyncio
        import app
        created = []

        class Counted(hv._CascadeBudget):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)
        structure = es.analyze_raw_email(nested_html_message(3))
        self.assertEqual(len(structure['nested_messages']), 3)
        with patch.object(hv, '_CascadeBudget', Counted), patch.object(app, '_content_pipeline', None):
            asyncio.run(app._analyze_content(app.ContentRequest(), structure, observe_sender_history=False))
        # Once one per attached message (and per pass), each with a full budget.
        self.assertEqual(len(created), 1)
        self.assertLess(created[0].left, hv._MAX_CASCADE_OPERATIONS)

    def test_analysis_threads_see_the_callers_context(self):
        import asyncio
        import contextvars
        import app
        marker = contextvars.ContextVar('marker', default=None)

        async def run():
            marker.set('request')
            return await app._run_analysis(marker.get)
        self.assertEqual(asyncio.run(run()), 'request')


if __name__ == '__main__':
    unittest.main()
