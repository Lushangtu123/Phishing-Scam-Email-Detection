import assert from 'node:assert/strict';
import test from 'node:test';
import {collectEmail} from './vision-email.mjs';
import {dataImages} from './vision-core.mjs';
import PostalMime from './vendor/vision/postal-mime/postal-mime.js';

const html = body => ['Content-Type: text/html; charset=utf-8', '', body];
const cidHTML = id => html(`<img src="${id}">`);
function attachment(id, bytes = 'image', type = 'image/png', extra = []) {
  return [`Content-Type: ${type}`, ...(id === null ? [] : [`Content-ID: <${id}>`]),
    ...extra, 'Content-Transfer-Encoding: base64', '', Buffer.from(bytes).toString('base64')];
}
function multipart(parts, kind = 'related', boundary = 'ROOT') {
  return [`Content-Type: multipart/${kind}; boundary="${boundary}"`, '',
    ...parts.flatMap(part => [`--${boundary}`, ...part]), `--${boundary}--`];
}
const nested = parts => ['Content-Type: message/rfc822', 'Content-Transfer-Encoding: base64', '',
  Buffer.from(parts.join('\r\n')).toString('base64')];
async function collect(parts) {
  const images = [], warnings = [];
  await collectEmail(parts.join('\r\n'), images, warnings);
  return {images: images.map(item => Buffer.from(item.buffer).toString()), warnings};
}
const cidWarnings = result => result.warnings.filter(warning => /CID|Content-ID/i.test(warning));

test('an unrelated image cannot hide a missing CID resource', async () => {
  const result = await collect(multipart([cidHTML('cid:private-missing@example.test'), attachment('other@example.test')]));
  assert.deepEqual(result.images, ['image']);
  assert(cidWarnings(result).length);
  assert(result.warnings.every(warning => !warning.includes('private-missing')), 'Coverage warnings do not expose identifiers');
});

for (const kind of ['related', 'mixed']) {
  test(`a matching image CID in multipart/${kind} preserves normal collection`, async () => {
    const result = await collect(multipart([cidHTML('CID:logo@example.test'), attachment('logo@example.test')], kind));
    assert.deepEqual(result.images, ['image']);
    assert.deepEqual(result.warnings, []);
  });
}

for (const [reference, id, matches] of [
  ['cid:logo%25tag@example.test', 'logo%tag@example.test', true],
  ['cid:logo%2525tag@example.test', 'logo%25tag@example.test', true],
  ['cid:logo%2525tag@example.test', 'logo%tag@example.test', false],
  ['cid:Logo@example.test', 'logo@example.test', false],
  ['cid:logo@EXAMPLE.test', 'logo@example.test', false],
  ['cid:logo&commat;example.test', 'logo@example.test', true],
  ['cid:', '', false], ['cid:bad%ZZ@example.test', 'bad%ZZ@example.test', false],
  ['cid:bad%00@example.test', 'bad@example.test', false],
]) {
  test(`CID comparison keeps decoding and case boundaries: ${reference} / ${id}`, async () => {
    const result = await collect(multipart([cidHTML(reference), attachment(id)]));
    assert.equal(cidWarnings(result).length === 0, matches);
    assert.deepEqual(result.images, ['image']);
  });
}

test('a matching filename or Content-Location cannot substitute for Content-ID', async () => {
  const result = await collect(multipart([cidHTML('cid:logo@example.test'), attachment(null, 'image', 'image/png', [
    'Content-Disposition: inline; filename="logo@example.test"', 'Content-Location: cid:logo@example.test',
  ])]));
  assert(cidWarnings(result).length);
});

for (const direction of ['inner', 'outer']) {
  test(`CID images cannot cross a nested message boundary (${direction})`, async () => {
    const inner = direction === 'inner' ? [attachment('logo@example.test')] : [cidHTML('cid:logo@example.test')];
    const outer = direction === 'inner' ? [cidHTML('cid:logo@example.test')] : [attachment('logo@example.test')];
    const result = await collect(multipart([...outer, nested(multipart(inner, 'related', 'INNER'))]));
    assert.deepEqual(result.images, ['image']);
    assert(cidWarnings(result).length);
  });
}

test('parallel related branches cannot satisfy each other\'s missing CID', async () => {
  const result = await collect(multipart([
    multipart([cidHTML('cid:logo@example.test')], 'related', 'LEFT'),
    multipart([attachment('logo@example.test')], 'related', 'RIGHT'),
  ], 'mixed'));
  assert(cidWarnings(result).length);
});

test('inner related HTML can reference an image in its enclosing related scope', async () => {
  const result = await collect(multipart([
    multipart([cidHTML('cid:logo@example.test')], 'related', 'INNER'), attachment('logo@example.test'),
  ]));
  assert.deepEqual(result.warnings, []);
});

test('outer related HTML cannot use a resource belonging to an inner related scope', async () => {
  const result = await collect(multipart([
    cidHTML('cid:logo@example.test'), multipart([attachment('logo@example.test')], 'related', 'INNER'),
  ]));
  assert(cidWarnings(result).length);
});

test('alternative related bodies keep their own legitimate duplicate CIDs', async () => {
  const result = await collect(multipart([
    multipart([cidHTML('cid:logo@example.test'), attachment('logo@example.test', 'left')], 'related', 'LEFT'),
    multipart([cidHTML('cid:logo@example.test'), attachment('logo@example.test', 'right')], 'related', 'RIGHT'),
  ], 'alternative'));
  assert.deepEqual(result.images, ['left', 'right']);
  assert.deepEqual(result.warnings, []);
});

test('simultaneously available duplicate CIDs report ambiguous coverage', async () => {
  const result = await collect(multipart([
    cidHTML('cid:logo@example.test'), attachment('logo@example.test', 'one'), attachment('logo@example.test', 'two'),
  ]));
  assert.deepEqual(result.images, ['one', 'two']);
  assert(cidWarnings(result).some(warning => /ambiguous|multiple/i.test(warning)));
});

test('mutually exclusive image alternatives do not create duplicate CID warnings', async () => {
  const result = await collect(multipart([
    cidHTML('cid:logo@example.test'), multipart([
      attachment('logo@example.test', 'one'), attachment('logo@example.test', 'two'),
    ], 'alternative', 'VERSIONS'),
  ]));
  assert.deepEqual(result.images, ['one', 'two']);
  assert.deepEqual(result.warnings, []);
});

for (const [type, bytes] of [['text/plain', 'ordinary text'], ['image/svg+xml', '<svg/>'], ['image/png', '']]) {
  test(`matching ${type} (${bytes.length} bytes) cannot imply available image coverage`, async () => {
    const result = await collect(multipart([cidHTML('cid:logo@example.test'), attachment('logo@example.test', bytes, type)]));
    assert(cidWarnings(result).length);
  });
}

test('inert CID examples produce no missing image warnings', async () => {
  const result = await collect(html('<script>"<img src=cid:missing>"</script><template><img src=cid:missing></template>'));
  assert.deepEqual(result, {images: [], warnings: []});
});

test('CID resource extraction without MIME context explicitly reports incomplete coverage', () => {
  const result = dataImages('<img src="cid:logo@example.test">');
  assert(cidWarnings(result).length);
});

test('missing MIME tree context cannot silently certify a CID but data images survive', async t => {
  const original = PostalMime.prototype.parse;
  t.mock.method(PostalMime.prototype, 'parse', async function(...args) {
    const mail = await original.apply(this, args);
    this.root = undefined;
    return mail;
  });
  const result = await collect(multipart([
    html('<img src="cid:logo@example.test"><img src="data:image/png;base64,ZGF0YQ==">'), attachment('logo@example.test'),
  ]));
  assert.deepEqual(result.images, ['data', 'image']);
  assert(cidWarnings(result).length);
});

test('mapping CID contexts preserves the parser\'s grouped HTML order and image budget', async () => {
  const imageHTML = text => html(`<img src="data:image/png;base64,${Buffer.from(text).toString('base64')}">`);
  const result = await collect(multipart([
    imageHTML('first'), multipart([imageHTML('inner')], 'alternative', 'INNER'),
    imageHTML('second'), imageHTML('third'), imageHTML('fourth'),
  ], 'alternative'));
  assert.deepEqual(result.images, ['first', 'second', 'third', 'fourth']);
  assert(result.warnings.some(warning => /four-image limit/.test(warning)));
});

test('identical HTML text in separate related scopes cannot borrow a CID', async () => {
  const result = await collect(multipart([
    multipart([cidHTML('cid:logo@example.test'), attachment('logo@example.test')], 'related', 'LEFT'),
    multipart([cidHTML('cid:logo@example.test')], 'related', 'RIGHT'),
  ], 'alternative'));
  assert.deepEqual(result.images, ['image']);
  assert(cidWarnings(result).length);
});

test('attached HTML is excluded while a multipart attachment retains the parser\'s existing child semantics', async () => {
  const attachedHTML = ['Content-Type: text/html', 'Content-Disposition: attachment', '', '<img src="cid:missing">'];
  assert.deepEqual(await collect(attachedHTML), {images: [], warnings: []});
  const parts = multipart([cidHTML('cid:missing')]);
  parts.splice(1, 0, 'Content-Disposition: attachment');
  assert(cidWarnings(await collect(parts)).length);
});

for (const corrupt of ['children', 'cycle', 'text']) {
  test(`invalid MIME context (${corrupt}) cannot silence a CID warning`, async t => {
    const original = PostalMime.prototype.parse;
    t.mock.method(PostalMime.prototype, 'parse', async function(...args) {
      const mail = await original.apply(this, args);
      if (corrupt === 'children') this.root.childNodes = null;
      if (corrupt === 'cycle') this.root.childNodes.push(this.root);
      if (corrupt === 'text') this.root.childNodes[0].getTextContent = () => 'changed';
      return mail;
    });
    const result = await collect(multipart([cidHTML('cid:logo@example.test'), attachment('logo@example.test')]));
    assert.deepEqual(result.images, ['image']);
    assert(cidWarnings(result).length);
  });
}

test('malformed HTML metadata does not shift the following entry into another CID scope', async t => {
  const original = PostalMime.prototype.parse;
  t.mock.method(PostalMime.prototype, 'parse', async function(...args) {
    const mail = await original.apply(this, args);
    this.textMap.values().next().value.html[0] = null;
    return mail;
  });
  const result = await collect(multipart([
    multipart([cidHTML('cid:logo@example.test'), attachment('logo@example.test')], 'related', 'LEFT'),
    multipart([cidHTML('cid:logo@example.test')], 'related', 'RIGHT'),
  ], 'alternative'));
  assert(result.warnings.some(warning => /Independent HTML parts/.test(warning)));
  assert(cidWarnings(result).length);
});

test('CID resolver failure leaves later data-image extraction available', () => {
  const result = dataImages('<img src="cid:missing"><img src="data:image/png;base64,ZGF0YQ==">', [], [], () => {throw new Error();});
  assert.deepEqual(result.images.map(item => Buffer.from(item.buffer).toString()), ['data']);
  assert(cidWarnings(result).length);
});

test('only an explicit successful CID resolution can suppress a coverage warning', () => {
  for (const value of [undefined, false, '', {}, 0, 1]) {
    const result = dataImages('<img src="cid:missing">', [], [], () => value);
    assert(cidWarnings(result).length);
  }
  assert.deepEqual(dataImages('<img src="cid:found">', [], [], () => null).warnings, []);
});
