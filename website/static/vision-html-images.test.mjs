import test from 'node:test';
import assert from 'node:assert/strict';
import {dataImages} from './vision-core.mjs';
import {imageReferences} from './vision-html.mjs';

// Extraction tests deliberately use short, distinct byte strings. Image-format
// validation is a later step, independently covered by vision-image-format.
const uri = label => `data:image/png;base64,${Buffer.from(label).toString('base64')}`;
const extracted = result => result.images.map(image => new TextDecoder().decode(image.buffer));
const decoy = uri('decoy');
const real = uri('real');

for (const [name, html] of [
  ['ordinary comment', `<!-- <img src="${decoy}"> -->`],
  ['script literal', `<script>const example = '<img src="${decoy}">';</script>`],
  ['nested inert template', `<template><div><template><img src="${decoy}"></template></div></template>`],
  ['textarea literal', `<textarea><img src="${decoy}"></textarea>`],
  ['title literal', `<title><img src="${decoy}"></title>`],
  ['ordinary prose', `<p>Example encoded image: ${decoy}</p>`],
  ['escaped HTML example', `<p>&lt;img src="${decoy}"&gt;</p>`],
  ['CSS comment', `<style>/* .example { background: url(${decoy}) } */</style>`],
  ['CSS content string', `<style>.example::before { content: "url(${decoy})" }</style>`],
]) {
  test(`${name} cannot supply image evidence`, () => {
    const result = dataImages(`${html}<img src="${real}">`);
    assert.deepEqual(extracted(result), ['real']);
  });
}

test('alternative text, tooltips and data attributes are not image resources', () => {
  const result = dataImages(`<img src="${real}" alt="${decoy}" title="${decoy}" data-src="${decoy}">
    <div data-image="${decoy}" title="${decoy}">Example</div>`);
  assert.deepEqual(extracted(result), ['real']);
});

test('non-image navigation attributes do not supply image evidence', () => {
  const result = dataImages(`<a href="${decoy}">Download sample</a><iframe src="${decoy}"></iframe>
    <img src="${real}">`);
  assert.deepEqual(extracted(result), ['real']);
});

test('commented-out examples cannot consume the budget before a real image', () => {
  const comments = Array.from({length: 6}, (_, n) => `<!-- <img src="${uri(`example-${n}`)}"> -->`).join('');
  const result = dataImages(`${comments}<img src="${real}">`);
  assert.deepEqual(extracted(result), ['real']);
  assert.doesNotMatch(result.warnings.join(' '), /four-image limit/i);
});

test('real image sources survive quoted angle brackets and case variations', () => {
  const result = dataImages(`<IMG title="A > B < C" SRC='${real}'>`);
  assert.deepEqual(extracted(result), ['real']);
});

test('the first duplicate source attribute determines the image candidate', () => {
  const result = dataImages(`<img src="${real}" SRC="${decoy}">`);
  assert.deepEqual(extracted(result), ['real']);
});

test('img srcset preserves each candidate without splitting the data URI comma', () => {
  const result = dataImages(`<img src="${real}" srcset="${uri('small')} 1x, ${uri('large')} 2x">`);
  assert.deepEqual(new Set(extracted(result)), new Set(['real', 'small', 'large']));
});

test('picture sources and their fallback remain inspectable candidates', () => {
  const result = dataImages(`<picture><source media="(min-width: 800px)" srcset="${uri('wide')} 1x">
    <img src="${real}"></picture>`);
  assert.deepEqual(new Set(extracted(result)), new Set(['wide', 'real']));
});

test('simple CSS and legacy HTML backgrounds remain inspectable candidates', () => {
  const result = dataImages(`<style>.banner { background-image: url('${uri('stylesheet')}'); }</style>
    <div class="banner" style="background: url(${uri('inline-style')})"></div>
    <table><tr><td background="${uri('legacy')}">Notice</td></tr></table>`);
  assert.deepEqual(new Set(extracted(result)), new Set(['stylesheet', 'inline-style', 'legacy']));
  // This collector identifies resource candidates; it cannot verify CSS
  // selector matching, cascade, media conditions or actual email-client layout.
  assert.match(result.warnings.join(' '), /render|CSS|visibility/i);
});

test('Outlook conditional image candidates are retained with a rendering limitation', () => {
  const result = dataImages(`<!--[if mso]><v:imagedata src="${uri('outlook')}"><![endif]-->
    <img src="${real}">`);
  assert.deepEqual(new Set(extracted(result)), new Set(['outlook', 'real']));
  assert.match(result.warnings.join(' '), /conditional|client-dependent|render/i);
});

test('image-like prose and inert markup do not create missing-image warnings', () => {
  const result = dataImages(`<p>Example: src="https://images.example.test/tracker.png"</p>
    <!-- <img src="https://images.example.test/tracker.png"> -->
    <script>const sample = '<img src="data:image/svg+xml;base64,PHN2Zz4=">';</script>
    <img src="${real}" alt="data:image/gif;base64,R0lGODlh" data-src="https://images.example.test/pixel.png">`);
  assert.deepEqual(extracted(result), ['real']);
  assert.doesNotMatch(result.warnings.join(' '), /Remote images|Unsupported inline image/i);
});

test('real remote and unsupported image sources still disclose uninspected content', () => {
  const result = dataImages('<img src="https://images.example.test/tracker.png"><img src="data:image/gif;base64,R0lGODlh">');
  assert.deepEqual(result.images, []);
  assert.match(result.warnings.join(' '), /Remote images/i);
  assert.match(result.warnings.join(' '), /Unsupported inline image/i);
});

test('HTML attribute character references are decoded exactly once', () => {
  const once = real.replace('data:', 'data&#58;');
  const twice = decoy.replace('data:', 'data&amp;#58;');
  const html = `<img src="${once}"><img src="${twice}">`;
  assert.deepEqual(imageReferences(html).urls, [real, decoy.replace('data:', 'data&#58;')]);
  assert.deepEqual(extracted(dataImages(html)), ['real']);
});

test('CSS URL escapes are decoded exactly once', () => {
  const escaped = real.replace('data', String.raw`\64 ata`);
  const literalEscape = decoy.replace('data', String.raw`\\64 ata`);
  const html = `<style>.a {background-image: url("${escaped}")}
    .b {background-image: url("${literalEscape}")}</style>`;
  assert.deepEqual(imageReferences(html).urls, [real, decoy.replace('data', String.raw`\64 ata`)]);
  assert.deepEqual(extracted(dataImages(html)), ['real']);
});

test('CSS image-set string candidates are preserved without treating unrelated strings as URLs', () => {
  const result = dataImages(`<style>.a {background-image: image-set("${real}" 1x, "${uri('retina')}" 2x)}
    .b::before {content: "${decoy}"}</style>`);
  assert.deepEqual(new Set(extracted(result)), new Set(['real', 'retina']));
  assert.match(result.warnings.join(' '), /CSS|render/i);
});

test('an empty first src does not enable a later duplicate source attribute', () => {
  const result = dataImages(`<img src="" src="${decoy}"><img src="${real}">`);
  assert.deepEqual(extracted(result), ['real']);
});

test('MSO comment syntax inside script or template cannot activate image candidates', () => {
  const conditional = `<!--[if mso]><img src="${decoy}"><![endif]-->`;
  const result = dataImages(`<script>const sample = '${conditional}';</script>
    <template>${conditional}</template><img src="${real}">`);
  assert.deepEqual(extracted(result), ['real']);
  assert.doesNotMatch(result.warnings.join(' '), /conditional|client-dependent/i);
});

test('a hidden non-MSO branch is ignored while its revealed form remains visible', () => {
  const result = dataImages(`<!--[if !mso]><img src="${decoy}"><![endif]-->
    <!--[if !mso]><!--><img src="${real}"><!--<![endif]-->`);
  assert.deepEqual(extracted(result), ['real']);
  assert.doesNotMatch(result.warnings.join(' '), /conditional|client-dependent/i);
});

test('Outlook ghost tables spanning separate comments preserve background candidates', () => {
  const result = dataImages(`<!--[if mso]><table><tr><td background="${uri('ghost-background')}"><![endif]-->
    <p>Shared message content</p><img src="${real}">
    <!--[if mso]></td></tr></table><![endif]-->`);
  assert.deepEqual(new Set(extracted(result)), new Set(['real', 'ghost-background']));
  assert.match(result.warnings.join(' '), /conditional|client-dependent|render/i);
});

test('unclosed script and textarea retain image-shaped text as inert content', () => {
  for (const tag of ['script', 'textarea']) {
    const result = dataImages(`<${tag}><img src="${decoy}">`);
    assert.deepEqual(result.images, [], tag);
  }
});

test('a self-closing slash does not close nonvoid inert HTML elements', () => {
  for (const tag of ['script', 'textarea', 'template']) {
    const result = dataImages(`<${tag}/><img src="${decoy}"></${tag}><img src="${real}">`);
    assert.deepEqual(extracted(result), ['real'], tag);
  }
});

test('exceeding the HTML node budget explicitly reports incomplete image coverage', () => {
  const result = dataImages(`${'<span></span>'.repeat(21000)}<img src="${real}">`);
  assert.deepEqual(result.images, []);
  assert.match(result.warnings.join(' '), /node limit.*incomplete/i);
});

test('the parser stops at its nesting budget and preserves only earlier candidates', () => {
  // Near the file-size ceiling: construction must stop before parsing the
  // entire deep chain, not merely skip its nodes during a later traversal.
  const result = dataImages(`<img src="${real}">${'<div>'.repeat(90000)}<img src="${decoy}">${'</div>'.repeat(90000)}<img src="${uri('unread')}">`);
  assert.deepEqual(extracted(result), ['real']);
  assert.match(result.warnings.join(' '), /nesting limit.*incomplete/i);
});

test('a CSS URL value outside the supported parser grammar remains explicitly incomplete', () => {
  const result = dataImages(String.raw`<div style="background:u\72 l(${real})"></div>`);
  assert.deepEqual(result.images, []);
  assert.match(result.warnings.join(' '), /CSS.*incomplete/i);
});

test('non-CSS style contents cannot supply image candidates', () => {
  const result = dataImages(`<style type="text/plain">.x { background:url(${decoy}) }</style><img src="${real}">`);
  assert.deepEqual(extracted(result), ['real']);
});

test('nested template fragments cannot bypass the parser nesting limit', () => {
  const result = dataImages(`<img src="${real}">${'<template>'.repeat(20000)}${'</template>'.repeat(20000)}`);
  assert.deepEqual(extracted(result), ['real']);
  assert.match(result.warnings.join(' '), /nesting limit.*incomplete/i);
});

test('huge attribute lists stop before tag deduplication can grow without bound', () => {
  for (const unique of [false, true]) {
    const attributes = Array.from({length: 20000}, (_, n) => `data-a${unique ? n : ''}="x"`).join(' ');
    const result = dataImages(`<img src="${real}"><div ${attributes}></div><img src="${decoy}">`);
    assert.deepEqual(extracted(result), ['real']);
    assert.match(result.warnings.join(' '), /attribute limit.*incomplete/i);
  }
});

for (const [name, css] of [
  ['escaped property name', String.raw`backg\72 ound: url('${real}')`],
  ['escaped image-set function name', String.raw`background: image\2d set('${real}' 1x)`],
  ['escaped URL function name', String.raw`background: u\72 l('${real}')`],
]) {
  test(`a CSS ${name} preserves its actual image candidate`, () => {
    const result = dataImages(`<div style="${css}"></div>`);
    assert.deepEqual(extracted(result), ['real']);
    assert.match(result.warnings.join(' '), /CSS|render/i);
  });
}

test('a CSS custom property preserves its image candidate and reports unverified rendering', () => {
  const result = dataImages(`<div style="--notice-image: url('${real}'); background-image: var(--notice-image)"></div>`);
  assert.deepEqual(extracted(result), ['real']);
  assert.match(result.warnings.join(' '), /CSS|render/i);
});
