import test from 'node:test';
import assert from 'node:assert/strict';
import {copyFile, mkdtemp, rm, symlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {prepareHoldout, finalizeHoldout} from '../tools/vision-benchmark/holdout.mjs';

const fixture = new URL('../tests/fixtures/vision/synthetic-phishing.png', import.meta.url);
async function imageDirectory(t) {
  const root = await mkdtemp(join(tmpdir(), 'vision-holdout-'));
  t.after(() => rm(root, {recursive:true, force:true}));
  await copyFile(fixture, join(root, 'email.png'));
  return root;
}
const prepared = root => prepareHoldout({imageRoot:root, datasetId:'email-screenshot-holdout',
  source:'Locally collected email screenshots', rights:'Use permission checked per image'});
function annotate(draft) {
  const row = draft.records[0];
  Object.assign(row, {language:'eng', expected_text:'Visit https://paypa1.example/login\n',
    expected_urls:['https://paypa1.example/login'], expected_qr_payloads:[], label:'unknown',
    source_type:'email_screenshot', source_reference:'local-case-1', rights_reference:'permission-note-1',
    annotation:{transcribed_by:'annotator-a', verified_by:'reviewer-b',
      method:'manual_pixels', url_reviewed:true, qr_reviewed:true}});
  return draft;
}

test('a manually reviewed holdout produces the existing hashed manifest without image bytes', async t => {
  const root = await imageDirectory(t);
  const draft = annotate(await prepared(root));
  const manifest = await finalizeHoldout(draft, root, {minimumImages:1, minimumUrlPositive:1, minimumUrlNegative:0});
  assert.equal(manifest.schema_version, 'phishguard-vision-benchmark/v1');
  assert.equal(manifest.records.length, 1);
  assert.equal(manifest.records[0].expected_urls[0], 'https://paypa1.example/login');
  assert.equal(manifest.holdout_audit.review_declarations_validated, 1);
  assert.doesNotMatch(JSON.stringify(manifest), /image_base64|data:image/);
});

test('finalization rejects OCR-derived, incomplete and self-reviewed ground truth', async t => {
  const root = await imageDirectory(t);
  for (const change of [row => {row.annotation.method='ocr_output';},
      row => {row.annotation.verified_by=row.annotation.transcribed_by;},
      row => {row.annotation.url_reviewed=false;},
      row => {row.expected_urls=['https://paypal.example/login'];},
      row => {row.source_type='webpage_screenshot';},
      row => {row.source_reference='';},
      row => {row.rights_reference='';}]) {
    const draft = annotate(await prepared(root));
    change(draft.records[0]);
    await assert.rejects(finalizeHoldout(draft, root, {minimumImages:1, minimumUrlPositive:1, minimumUrlNegative:0}));
  }
});

test('finalization rejects a changed image and an undersized set', async t => {
  const root = await imageDirectory(t);
  const draft = annotate(await prepared(root));
  await assert.rejects(finalizeHoldout(draft, root), /30/);
  await writeFile(join(root, 'email.png'), Buffer.from('changed'));
  await assert.rejects(finalizeHoldout(draft, root, {minimumImages:1, minimumUrlPositive:1, minimumUrlNegative:0}));
});

test('preparation rejects image symlinks and duplicate image bytes', async t => {
  const root = await imageDirectory(t);
  await symlink(fixture.pathname, join(root, 'link.png'));
  await assert.rejects(prepared(root), /symbolic link/i);
  await rm(join(root, 'link.png'));
  await copyFile(fixture, join(root, 'copy.png'));
  await assert.rejects(prepared(root), /duplicate/i);
});

test('preparation refuses nested or unsupported images instead of silently omitting them', async t => {
  const root = await imageDirectory(t);
  await writeFile(join(root, 'not-supported.gif'), Buffer.from('GIF89a'));
  await assert.rejects(prepared(root), /unsupported/i);
});
