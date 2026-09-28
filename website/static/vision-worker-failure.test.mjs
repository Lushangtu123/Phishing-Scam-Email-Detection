import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {collectEmail} from './vision-email.mjs';
import {LIMITS, checkImage, decodeQRs, urlLineConfidence} from './vision-core.mjs';

const require = createRequire(import.meta.url);
const jsQR = require('./vendor/vision/jsQR.js');
const matrix = JSON.parse(readFileSync(new URL('../tests/fixtures/vision/qr-matrices.json', import.meta.url)))[1];
const fixtures = ['synthetic-qr.png', 'synthetic-benign.png', 'synthetic-phishing.png', 'synthetic-chinese.png']
  .map(name => ({name, bytes: readFileSync(new URL(`../tests/fixtures/vision/${name}`, import.meta.url))}));
const email = new TextEncoder().encode([
  'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="worker-control"', '',
  ...fixtures.flatMap(({name, bytes}) => ['--worker-control', 'Content-Type: image/png',
    `Content-Disposition: attachment; filename="${name}"`, 'Content-Transfer-Encoding: base64', '', bytes.toString('base64')]),
  '--worker-control--', '',
].join('\r\n')).buffer;

// Run the production message handler with real MIME/image/QR helpers. Node has
// no worker canvas or Tesseract browser runtime, so replace only those external
// boundaries and the clock. Real-browser integration covers their normal path.
const source = readFileSync(new URL('./vision-worker.mjs', import.meta.url), 'utf8')
  .replace(/^import .*;$/gm, '')
  .replace('import.meta.url', JSON.stringify(new URL('./vision-worker.mjs', import.meta.url).href));
const pending = () => new Promise(() => {});
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(resolve => setImmediate(resolve)); };
const imageSide = matrix.matrix.length * 3 + 24;
function pixels(withQR = true) {
  const data = new Uint8ClampedArray(imageSide * imageSide * 4).fill(255);
  if (withQR) matrix.matrix.forEach((row, y) => row.forEach((on, x) => {
    if (on) for (let dy = 0; dy < 3; dy++) for (let dx = 0; dx < 3; dx++) {
      const offset = ((12 + y * 3 + dy) * imageSide + 12 + x * 3 + dx) * 4;
      data[offset] = data[offset + 1] = data[offset + 2] = 0;
    }
  }));
  return {width: imageSide, height: imageSide, data};
}

async function runWorker({create, parameters, recognize, terminate, failBitmapAt = 0,
  createDelayMs = 0, bitmapDelay = {}, withQR = true} = {}) {
  let now = 0, timerId = 0, closed = false, settled = false, jobError;
  const timers = new Map(), messages = [];
  const calls = {create: 0, parameters: 0, recognize: 0, terminate: 0, bitmap: 0};
  const delay = ms => new Promise(resolve => { timers.set(++timerId, {at: now + ms, callback: resolve}); });
  class FakeDate extends Date { static now() { return now; } }
  class Canvas {
    constructor(width, height) { this.width = width; this.height = height; this.image = pixels(withQR); }
    getContext() {
      return {fillRect() {}, drawImage() {}, getImageData: () => this.image,
        putImageData: image => { this.image = image; }};
    }
    async convertToBlob() { return new Blob(['synthetic browser image']); }
  }
  const worker = {
    async setParameters(...args) { calls.parameters++; return parameters?.(...args); },
    async recognize(...args) {
      calls.recognize++;
      if (recognize) return recognize(...args);
      return {data: {text: 'Project meeting notes.', confidence: 95, blocks: []}};
    },
    async terminate() { calls.terminate++; return terminate?.(); },
  };
  const self = {jsQR, close() { closed = true; }};
  vm.runInNewContext(source, {
    self, postMessage: message => messages.push({at: now, ...message}),
    collectEmail, LIMITS, checkImage, decodeQRs, urlLineConfidence,
    Tesseract: {async createWorker(...args) {
      calls.create++;
      if (createDelayMs) await delay(createDelayMs);
      return create ? create(worker, ...args) : worker;
    }},
    Date: FakeDate, performance: {now: () => now}, URL, Blob, Uint8Array, Uint8ClampedArray,
    crypto: {subtle: {async digest(_algorithm, buffer) { return Uint8Array.from(createHash('sha256').update(new Uint8Array(buffer)).digest()).buffer; }}},
    async createImageBitmap() {
      calls.bitmap++;
      if (bitmapDelay[calls.bitmap]) await delay(bitmapDelay[calls.bitmap]);
      if (failBitmapAt === calls.bitmap) throw new Error('Synthetic image decode failure');
      return {width: imageSide, height: imageSide, close() {}};
    },
    OffscreenCanvas: Canvas,
    ImageData: class { constructor(data, width, height) { Object.assign(this, {data, width, height}); } },
    setTimeout(callback, ms, ...args) { const id = ++timerId; timers.set(id, {at: now + ms, callback: () => callback(...args)}); return id; },
    clearTimeout(id) { timers.delete(id); },
  }, {filename: 'vision-worker.mjs'});
  self.onmessage({data: {buffer: email, name: 'synthetic-four-images.eml', kind: 'eml', language: 'eng'}})
    .then(() => { settled = true; }, error => { settled = true; jobError = error; });
  // Never wait in wall-clock time for a hung worker. Stop at the existing UI's
  // 150-second deadline, where the real page would terminate it and lose data.
  for (let turn = 0; turn < 30; turn++) {
    await flush();
    if (settled) break;
    const next = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
    if (!next || next[1].at >= 150000) break;
    now = next[1].at;
    timers.delete(next[0]);
    next[1].callback();
  }
  await flush();
  return {messages, calls, closed, settled, jobError};
}

function retainedQRResult(run) {
  assert.equal(run.jobError, undefined, 'Worker must handle a failed external service');
  assert.equal(run.messages.some(message => message.error), false, 'Partial recognition must still return observations');
  const response = run.messages.find(message => message.result);
  assert(response, 'Result must arrive before the page terminates recognition at 150 seconds');
  assert(response.at < 150000);
  assert.equal(response.result.observations.length, 4);
  for (const observation of response.result.observations) {
    assert.deepEqual(Array.from(observation.qr_payloads), [matrix.text]);
    assert.equal(observation.status, 'partial');
    assert.equal(observation.ocr_text, '');
    assert(observation.warnings.some(warning => /OCR|recognition|text/i.test(warning)), 'Skipped text requires a coverage warning');
  }
  return response.result;
}

test('stalled OCR startup is attempted once while all four QR observations survive', async () => {
  const run = await runWorker({create: pending});
  retainedQRResult(run);
  assert.equal(run.calls.create, 1, 'Do not repeatedly start a stalled OCR service within one task');
  assert.equal(run.calls.recognize, 0);
});

test('OCR startup arriving after its deadline is cleaned up without activating recognition', async () => {
  // The next bitmap remains in progress when startup eventually resolves, so
  // this exercises late cleanup before the containing worker has closed.
  const run = await runWorker({createDelayMs: 46000, bitmapDelay: {2: 2000}});
  retainedQRResult(run);
  assert.equal(run.calls.create, 1);
  assert.equal(run.calls.parameters, 0);
  assert.equal(run.calls.recognize, 0);
  assert.equal(run.calls.terminate, 1);
  assert.equal(run.closed, true);
});

test('stalled OCR parameter setup cannot consume the whole recognition deadline', async () => {
  const run = await runWorker({parameters: pending});
  retainedQRResult(run);
  assert.equal(run.calls.create, 1);
  assert.equal(run.calls.recognize, 0);
});

test('stalled OCR recognition degrades to QR without repeatedly invoking the failed service', async () => {
  const run = await runWorker({recognize: pending});
  retainedQRResult(run);
  assert.equal(run.calls.create, 1);
  assert.equal(run.calls.recognize, 1);
});

for (const mode of ['reject', 'stall']) {
  test(`OCR cleanup that ${mode}s cannot discard decoded QR observations`, async () => {
    const run = await runWorker({recognize: async () => { throw new Error('Synthetic OCR failure'); },
      terminate: mode === 'reject' ? async () => { throw new Error('Synthetic cleanup failure'); } : pending});
    retainedQRResult(run);
    assert.equal(run.calls.create, 1);
    assert.equal(run.closed, true, 'The containing recognition worker must still close');
  });
  test(`successful OCR results survive final cleanup that ${mode}s`, async () => {
    const run = await runWorker({terminate: mode === 'reject'
      ? async () => { throw new Error('Synthetic cleanup failure'); } : pending});
    assert.equal(run.jobError, undefined);
    const result = run.messages.find(message => message.result)?.result;
    assert(result);
    assert.equal(result.observations.length, 4);
    assert.equal(run.calls.create, 1);
    assert.equal(run.calls.recognize, 4);
    assert.equal(run.closed, true, 'Final cleanup must not hold the containing worker open');
    for (const observation of result.observations) {
      assert.equal(observation.status, 'processed');
      assert.equal(observation.ocr_text, 'Project meeting notes.');
    }
  });
}

test('four successful images reuse one OCR worker and preserve literal output', async () => {
  const run = await runWorker();
  assert.equal(run.jobError, undefined);
  const result = run.messages.find(message => message.result)?.result;
  assert(result);
  assert.equal(result.observations.length, 4);
  assert.equal(run.calls.create, 1);
  assert.equal(run.calls.parameters, 1);
  assert.equal(run.calls.recognize, 4);
  assert.equal(run.closed, true);
  for (const observation of result.observations) {
    assert.equal(observation.status, 'processed');
    assert.equal(observation.ocr_text, 'Project meeting notes.');
    assert.deepEqual(Array.from(observation.qr_payloads), [matrix.text]);
  }
});

for (const failBitmapAt of [1, 2]) {
  test(`damaged image ${failBitmapAt} preserves OCR availability and reuse for other images`, async () => {
    const run = await runWorker({failBitmapAt});
    assert.equal(run.jobError, undefined);
    const result = run.messages.find(message => message.result)?.result;
    assert(result);
    assert.equal(result.observations.length, 4);
    assert.equal(result.observations[failBitmapAt - 1].status, 'failed');
    assert.equal(run.calls.create, 1);
    assert.equal(run.calls.recognize, 3);
    for (const [index, observation] of result.observations.entries()) {
      if (index === failBitmapAt - 1) continue;
      assert.equal(observation.status, 'processed');
      assert.equal(observation.ocr_text, 'Project meeting notes.');
      assert.deepEqual(Array.from(observation.qr_payloads), [matrix.text]);
    }
  });
}

test('OCR failure without a decoded QR marks every uninspected image failed', async () => {
  const run = await runWorker({create: pending, withQR: false});
  assert.equal(run.jobError, undefined);
  const response = run.messages.find(message => message.result);
  assert(response);
  assert(response.at < 150000);
  assert.equal(response.result.observations.length, 4);
  assert.equal(run.calls.create, 1);
  for (const observation of response.result.observations) {
    assert.equal(observation.status, 'failed');
    assert.equal(observation.ocr_text, '');
    assert.equal(observation.qr_payloads.length, 0);
    assert(observation.warnings.length > 0);
  }
});

test('a later OCR failure preserves text already recognized in an earlier image', async () => {
  let attempted = 0;
  const run = await runWorker({recognize: async () => {
    if (++attempted === 2) throw new Error('Synthetic later-image OCR failure');
    return {data: {text: 'Earlier image text.', confidence: 96, blocks: []}};
  }});
  assert.equal(run.jobError, undefined);
  const result = run.messages.find(message => message.result)?.result;
  assert(result);
  assert.equal(result.observations.length, 4);
  assert.equal(run.calls.create, 1);
  assert.equal(run.calls.recognize, 2);
  assert.equal(result.observations[0].status, 'processed');
  assert.equal(result.observations[0].ocr_text, 'Earlier image text.');
  for (const [index, observation] of result.observations.entries()) {
    assert.deepEqual(Array.from(observation.qr_payloads), [matrix.text]);
    if (!index) continue;
    assert.equal(observation.status, 'partial');
    assert.equal(observation.ocr_text, '');
    assert(observation.warnings.length > 0);
  }
});
