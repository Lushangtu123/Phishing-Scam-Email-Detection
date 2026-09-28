import assert from 'node:assert/strict';
import test from 'node:test';
import {collectEmail} from './vision-email.mjs';
import PostalMime from './vendor/vision/postal-mime/postal-mime.js';

const image = bytes => `<img src="data:image/png;base64,${Buffer.from(bytes).toString('base64')}">`;
const html = (body, headers = []) => ['Content-Type: text/html; charset=utf-8', ...headers, '', body];
function message(parts, kind = 'mixed', boundary = 'PART') {
  return ['MIME-Version: 1.0', `Content-Type: multipart/${kind}; boundary="${boundary}"`, '',
    ...parts.flatMap(part => [`--${boundary}`, ...part]), `--${boundary}--`, ''].join('\r\n');
}
const nested = raw => ['Content-Type: message/rfc822', 'Content-Transfer-Encoding: base64', '', Buffer.from(raw).toString('base64')];
const attached = bytes => ['Content-Type: image/png', 'Content-Transfer-Encoding: base64', '', Buffer.from(bytes).toString('base64')];
async function collect(raw) {
  const images = [], warnings = [];
  await collectEmail(raw, images, warnings);
  return {images: images.map(item => Buffer.from(item.buffer).toString()), warnings};
}

for (const kind of ['mixed', 'alternative', 'related']) {
  for (const prefix of ['<script>unclosed', '<template>unclosed', '<!-- unclosed', '<style>p { color: red; }', '<textarea>unclosed']) {
    test(`${kind} HTML parts cannot inherit an earlier ${prefix.split('>')[0]} parser context`, async () => {
      const result = await collect(message([html(prefix), html(image('visible'))], kind));
      assert.deepEqual(result.images, ['visible']);
      assert.deepEqual(result.warnings, []);
    });
  }
}

test('complete HTML documents each retain their own image candidates', async () => {
  const result = await collect(message([
    html(`<!doctype html><html><head><title>First</title></head><body>${image('first')}</body></html>`),
    html(`<!doctype html><html><head><title>Second</title></head><body>${image('second')}</body></html>`),
  ], 'alternative'));
  assert.deepEqual(result.images, ['first', 'second']);
  assert.deepEqual(result.warnings, []);
});

test('inert markup stays inert inside each individual HTML part', async () => {
  const result = await collect(message([
    html(`<script>${image('script')}</script><template>${image('template')}</template><!-- ${image('comment')} -->`),
    html(image('visible')),
  ]));
  assert.deepEqual(result.images, ['visible']);
  assert.deepEqual(result.warnings, []);
});

test('separate MIME parts cannot concatenate an image attribute', async () => {
  const result = await collect(message([
    html('<img src="data:image/png;base64,aGVs'), html('bG8=">'), html(image('visible')),
  ]));
  assert.deepEqual(result.images, ['visible']);
  assert.deepEqual(result.warnings, []);
});

test('separate HTML parts preserve MIME transfer and charset decoding', async () => {
  const base64 = Buffer.from(image('utf16'), 'utf16le').toString('base64');
  const result = await collect(message([
    html('<script>unclosed'),
    ['Content-Type: text/html; charset=utf-16le', 'Content-Transfer-Encoding: base64', '', base64],
    html(image('quoted-printable').replaceAll('=', '=3D'), ['Content-Transfer-Encoding: quoted-printable']),
  ]));
  assert.deepEqual(result.images, ['utf16', 'quoted-printable']);
  assert.deepEqual(result.warnings, []);
});

test('nested mail preserves independent HTML parts and the shared image budget', async () => {
  const inner = message([html('<script>unclosed'), html(image('first') + image('second'))], 'alternative', 'INNER');
  const result = await collect(message([
    html(image('first')), nested(inner), attached('third'), attached('fourth'), attached('fifth'),
  ]));
  assert.deepEqual(result.images, ['first', 'second', 'third', 'fourth']);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0], /four-image limit/);
});

test('the HTML part budget preserves prior images and still checks attachments', async () => {
  const result = await collect(message([
    html(image('first')), ...Array.from({length: 63}, () => html('<p>ordinary text</p>')),
    html(image('over-limit')), attached('attachment'),
  ]));
  assert.deepEqual(result.images, ['first', 'attachment']);
  assert.match(result.warnings.join(' '), /HTML part limit.*incomplete/);
});

test('nested messages share the HTML part budget', async () => {
  const inner = message([html(image('last-allowed')), html(image('over-limit'))], 'mixed', 'INNER');
  const result = await collect(message([
    ...Array.from({length: 63}, () => html('<p>ordinary text</p>')), nested(inner), attached('attachment'),
  ]));
  assert.deepEqual(result.images, ['last-allowed', 'attachment']);
  assert.match(result.warnings.join(' '), /HTML part limit.*incomplete/);
});

test('the cumulative HTML text budget reports skipped parts while preserving earlier evidence', async () => {
  const result = await collect(message([
    html(image('first')), html('x'.repeat(1024 * 1024)),
    html('x'.repeat(1024 * 1024) + image('over-limit')), attached('attachment'),
  ]));
  assert.deepEqual(result.images, ['first', 'attachment']);
  assert.match(result.warnings.join(' '), /HTML text limit.*incomplete/);
});

test('unavailable parser part metadata reports incomplete coverage without joined HTML fallback', async t => {
  const original = PostalMime.prototype.parse;
  t.mock.method(PostalMime.prototype, 'parse', async function(...args) {
    const mail = await original.apply(this, args);
    this.textMap = undefined;
    return mail;
  });
  const result = await collect(message([html(image('joined-html')), attached('attachment')]));
  assert.deepEqual(result.images, ['attachment']);
  assert.match(result.warnings.join(' '), /Independent HTML parts.*incomplete/);
});

test('malformed parser HTML entries are skipped with a warning while valid entries survive', async t => {
  const original = PostalMime.prototype.parse;
  t.mock.method(PostalMime.prototype, 'parse', async function(...args) {
    const mail = await original.apply(this, args);
    this.textMap = new Map([
      ['missing', null], ['invalid-list', {html: 'not a list'}],
      ['invalid-entries', {html: [null, {type: 'subMessage', value: image('unsafe')}, {type: 'text', value: 1}]}],
      ...this.textMap,
    ]);
    return mail;
  });
  const result = await collect(message([html(image('visible'))]));
  assert.deepEqual(result.images, ['visible']);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0], /Independent HTML parts.*incomplete/);
});
