import assert from 'node:assert/strict';
import test from 'node:test';
import PostalMime from './vendor/vision/postal-mime/postal-mime.js';
import {createCIDResolver} from './vision-cid.mjs';

const part = (type, body = 'content', headers = []) => [`Content-Type: ${type}`, ...headers, '', body].join('\r\n');
let sequence = 0;
function multi(kind, parts) {
  const boundary = `CID-control-${++sequence}`;
  return part(`multipart/${kind}; boundary="${boundary}"`,
    [...parts.map(item => `--${boundary}\r\n${item}`), `--${boundary}--`, ''].join('\r\n'));
}
const html = () => part('text/html', '<p>HTML context</p>');
const image = (id = 'logo@example.test', type = 'image/png', body = 'pixels') =>
  part(type, body, [`Content-ID: <${id}>`]);
async function fixture(raw) {
  const parser = new PostalMime({forceRfc822Attachments: true});
  await parser.parse(raw);
  const htmlNodes = [], pending = [parser.root];
  while (pending.length) {
    const node = pending.pop();
    if (node.contentType.parsed.value === 'text/html') htmlNodes.push(node);
    pending.push(...node.childNodes.slice().reverse());
  }
  return {root: parser.root, htmlNodes, resolve: createCIDResolver(parser.root)};
}

test('CID metadata resolves supported image candidates without claiming pixel decoding', async () => {
  for (const type of ['image/png', 'image/jpeg', 'image/webp']) {
    const {resolve, htmlNodes} = await fixture(multi('related', [html(), image('logo@example.test', type)]));
    // Deliberately not encoded image pixels: decoding is a separate stage.
    assert.equal(resolve('cid:logo@example.test', htmlNodes[0]), null);
  }
});
test('missing CID is not supplied by unrelated filename or Content-Location metadata', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), part('image/png', 'pixels', [
    'Content-Disposition: inline; filename="missing@example.test"', 'Content-Location: cid:missing@example.test',
  ])]));
  assert.match(resolve('cid:missing@example.test', htmlNodes[0]), /no matching resource.*incomplete/);
});
test('URL escaping is decoded exactly once and header escaping remains literal', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), image('logo%40example.test'), image('logo%tag@example.test')]));
  assert.equal(resolve('CID:logo%2540example.test', htmlNodes[0]), null);
  assert.equal(resolve('cid:logo%25tag@example.test', htmlNodes[0]), null);
  assert.match(resolve('cid:logo%40example.test', htmlNodes[0]), /no matching resource/);
});
test('CID and Content-ID identifiers retain exact case', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), image('Logo@EXAMPLE.test')]));
  assert.equal(resolve('cId:Logo@EXAMPLE.test', htmlNodes[0]), null);
  assert.match(resolve('cid:logo@example.test', htmlNodes[0]), /no matching resource/);
});
test('URL fragment delimiters must be escaped before matching a literal Content-ID', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), image('logo#fragment')]));
  assert.match(resolve('cid:logo#fragment', htmlNodes[0]), /malformed.*incomplete/);
  assert.equal(resolve('cid:logo%23fragment', htmlNodes[0]), null);
});
test('opaque local IDs are supported without requiring a domain', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), image('logo')]));
  assert.equal(resolve('cid:logo', htmlNodes[0]), null);
});
test('malformed or overlong references cannot silently match a resource', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), image()]));
  for (const reference of ['', null, 'cid:', 'cid:%', 'cid:%GG', 'cid:%00', 'cid:%ff', 'cid:%3Cid%3E',
    'cid:logo @example.test', 'cid:logo\n@example.test', 'https://example.test', 'cid:' + 'a'.repeat(7000)])
    assert.match(resolve(reference, htmlNodes[0]), /malformed.*incomplete/);
});
test('malformed Content-ID headers cannot resolve as ordinary IDs', async () => {
  for (const value of ['logo', '<<logo>>', '<logo> trailing', '<>', '\u00a0<logo>', '<logo>\ufeff']) {
    const {resolve, htmlNodes} = await fixture(multi('related', [html(), part('image/png', 'pixels', [`Content-ID: ${value}`])]));
    assert.match(resolve('cid:logo', htmlNodes[0]), /no matching resource/);
  }
});
test('non-image, unsupported, and empty resources produce explicit coverage warnings', async () => {
  for (const [type, body, expected] of [['application/pdf', 'pdf', /non-image/],
    ['image/gif', 'gif', /unsupported image/], ['image/svg+xml', '<svg/>', /unsupported image/],
    ['image/png', '', /empty image/]]) {
    const resource = body ? image('logo', type, body) : part(type, '', ['Content-ID: <logo>', 'Content-Transfer-Encoding: base64']);
    const {resolve, htmlNodes} = await fixture(multi('related', [html(), resource]));
    assert.match(resolve('cid:logo', htmlNodes[0]), expected);
  }
});
test('ordinary multipart/mixed mail can resolve a top-level local image candidate', async () => {
  const {resolve, htmlNodes} = await fixture(multi('mixed', [html(), image()]));
  assert.equal(resolve('cid:logo@example.test', htmlNodes[0]), null);
});
test('nested related HTML can use outer related resources', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), image(), multi('related', [html(), image('inner')])]));
  assert.equal(resolve('cid:logo@example.test', htmlNodes[1]), null);
  assert.equal(resolve('cid:inner', htmlNodes[1]), null);
  assert.match(resolve('cid:inner', htmlNodes[0]), /no matching resource/);
});
test('parallel related scopes cannot satisfy each other or top-level HTML', async () => {
  const {resolve, htmlNodes} = await fixture(multi('mixed', [html(),
    multi('related', [html(), image('first')]), multi('related', [html(), image('second')])]));
  assert.match(resolve('cid:first', htmlNodes[0]), /no matching resource/);
  assert.match(resolve('cid:second', htmlNodes[1]), /no matching resource/);
  assert.equal(resolve('cid:second', htmlNodes[2]), null);
});
test('parallel alternative related branches may legitimately reuse a CID', async () => {
  const {resolve, htmlNodes} = await fixture(multi('alternative', [
    multi('related', [html(), image()]), multi('related', [html(), image()])]));
  assert.equal(resolve('cid:logo@example.test', htmlNodes[0]), null);
  assert.equal(resolve('cid:logo@example.test', htmlNodes[1]), null);
});
test('HTML cannot borrow a resource from a mutually exclusive alternative branch', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [multi('alternative', [
    multi('mixed', [html(), image('first')]), multi('mixed', [html(), image('second')])])]));
  assert.equal(resolve('cid:first', htmlNodes[0]), null);
  assert.match(resolve('cid:second', htmlNodes[0]), /no matching resource/);
});
test('alternative image versions do not count as simultaneous duplicate IDs', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), multi('alternative', [
    image(), image('logo@example.test', 'image/jpeg')])]));
  assert.equal(resolve('cid:logo@example.test', htmlNodes[0]), null);
});
test('same-branch duplicates and independent alternatives remain ambiguous', async () => {
  for (const resources of [[image(), image()], [image(), multi('alternative', [image(), image()])],
    [multi('alternative', [image(), image()]), multi('alternative', [image(), image()])],
    [multi('alternative', [multi('mixed', [image(), image()]), image()])]]) {
    const {resolve, htmlNodes} = await fixture(multi('related', [html(), ...resources]));
    assert.match(resolve('cid:logo@example.test', htmlNodes[0]), /multiple simultaneously/);
  }
});
test('nested mutually exclusive alternatives remain one possible match', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), multi('alternative', [
    multi('alternative', [image(), image()]), multi('alternative', [image(), image()])])]));
  assert.equal(resolve('cid:logo@example.test', htmlNodes[0]), null);
});
test('unknown alternative format or empty version remains incomplete', async () => {
  const {resolve, htmlNodes} = await fixture(multi('related', [html(), multi('alternative', [
    image(), image('logo@example.test', 'image/gif')])]));
  assert.match(resolve('cid:logo@example.test', htmlNodes[0]), /unsupported image/);
});
test('encapsulated messages never supply CID resources to their parent', async () => {
  const {resolve, htmlNodes} = await fixture(multi('mixed', [html(), part('message/rfc822',
    multi('related', [html(), image()]))]));
  assert.match(resolve('cid:logo@example.test', htmlNodes[0]), /no matching resource/);
  const child = await fixture(multi('related', [html(), image()]));
  assert.equal(child.resolve('cid:logo@example.test', child.htmlNodes[0]), null);
  assert.match(resolve('cid:logo@example.test', child.htmlNodes[0]), /metadata limits/);
});

function node(type = 'multipart/mixed', children = []) {
  return {childNodes: children, contentType: {parsed: {value: type}}};
}
test('cyclic, excessive, and unavailable MIME metadata fails closed without recursion errors', () => {
  const cycle = node(); cycle.childNodes.push(cycle);
  let deep = node('text/html'); const deepest = deep;
  for (let i = 0; i < 40; i++) deep = node('multipart/related', [deep]);
  for (const root of [null, {}, cycle, node('multipart/mixed', Array.from({length: 5000}, () => node('text/html'))), deep]) {
    const resolve = createCIDResolver(root);
    assert.match(resolve('cid:logo', deepest), /metadata limits.*incomplete/);
  }
});
test('query budget bounds unique references while cached answers remain available', () => {
  const htmlNode = node('text/html'), resource = node('image/png');
  resource.contentId = '<logo>'; resource.content = new Uint8Array([1]);
  const resolve = createCIDResolver(node('multipart/related', [htmlNode, resource]));
  assert.equal(resolve('cid:logo', htmlNode), null);
  let last;
  for (let i = 0; i < 4200; i++) last = resolve(`cid:missing-${i}`, htmlNode);
  assert.match(last, /metadata limits/);
  assert.equal(resolve('cid:logo', htmlNode), null);
});
