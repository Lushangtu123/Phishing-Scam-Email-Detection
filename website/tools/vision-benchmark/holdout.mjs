#!/usr/bin/env node
// Prepare and audit manually labeled email screenshots. No OCR or network access.
import {createHash} from 'node:crypto';
import {lstat, readdir, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkImage} from '../../static/vision-core.mjs';
import {SCHEMA, extractURLs, validateManifest} from './metrics.mjs';
import {readBoundedFile} from './evaluate-service.mjs';

const DRAFT_SCHEMA = 'phishguard-vision-holdout-draft/v1';
const IMAGE_LIMIT = 2 * 1024 * 1024;
const IMAGE_NAMES = /\.(png|jpe?g|webp)$/i;
const OTHER_IMAGE_NAMES = /\.(gif|bmp|tiff?|heic|avif)$/i;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function insist(condition, message) { if (!condition) throw new Error(message); }
function shortText(value, name, max = 500) {
  insist(typeof value === 'string' && value.trim() === value && value.length > 0 && value.length <= max &&
    !/[\x00-\x1f\x7f]/.test(value), `${name} must be nonempty, bounded single-line text.`);
}
function filename(name) {
  insist(typeof name === 'string' && name.length > 0 && name.length <= 300 && IMAGE_NAMES.test(name) &&
    name !== '.' && name !== '..' && !/[\\/:\x00-\x1f\x7f]/.test(name), 'Use flat PNG, JPEG or WebP filenames.');
  return name;
}
async function originalImage(root, name) {
  const path = resolve(root, filename(name));
  const metadata = await lstat(path);
  insist(metadata.isFile() && !metadata.isSymbolicLink(), 'Image symbolic links and non-regular files are unsupported.');
  const bytes = await readBoundedFile(path, IMAGE_LIMIT);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const info = checkImage(buffer);
  const suffix = name.toLowerCase().split('.').pop();
  insist((suffix === 'png' && info.mime === 'image/png') ||
    ((suffix === 'jpg' || suffix === 'jpeg') && info.mime === 'image/jpeg') ||
    (suffix === 'webp' && info.mime === 'image/webp'), `Image extension and content disagree: ${name}`);
  return {sha256:hash(bytes), width:info.width, height:info.height};
}

export async function prepareHoldout({imageRoot, datasetId, source, rights}) {
  insist(typeof datasetId === 'string' && /^[a-z0-9][a-z0-9_-]{2,79}$/.test(datasetId), 'Use a short lowercase dataset id.');
  shortText(source, 'Dataset source');
  shortText(rights, 'Dataset rights');
  const entries = await readdir(imageRoot, {withFileTypes:true});
  insist(!entries.some(entry => entry.isDirectory() || OTHER_IMAGE_NAMES.test(entry.name)),
    'Use a flat folder of supported images; nested and unsupported images must not be silently omitted.');
  const selected = entries.filter(entry => IMAGE_NAMES.test(entry.name))
    .sort((a,b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  insist(selected.length > 0 && selected.length <= 1000, 'Expected 1–1000 flat image files.');
  const seen = new Set(), records = [];
  for (const entry of selected) {
    filename(entry.name);
    insist(entry.isFile() && !entry.isSymbolicLink(), 'Image symbolic links and non-regular files are unsupported.');
    const image = await originalImage(imageRoot, entry.name);
    insist(!seen.has(image.sha256), 'Duplicate image bytes are not independent samples.');
    seen.add(image.sha256);
    records.push({id:`sample-${String(records.length + 1).padStart(4, '0')}`,
      filename:entry.name, ...image, source_type:null, source_reference:'', rights_reference:'',
      language:null, expected_text:null, expected_urls:null, expected_qr_payloads:null,
      label:null, annotation:{method:null, transcribed_by:'', verified_by:'',
        url_reviewed:false, qr_reviewed:false}});
  }
  return {schema_version:DRAFT_SCHEMA, dataset_id:datasetId, source, license:rights,
    instructions:'Transcribe pixels manually; do not paste OCR output. A different reviewer checks text, visible URLs and QR presence. Do not put private mail or images in Git.',
    records};
}

export async function finalizeHoldout(draft, imageRoot, {
  minimumImages = 30, minimumUrlPositive = 10, minimumUrlNegative = 5,
} = {}) {
  insist(draft?.schema_version === DRAFT_SCHEMA, 'Expected a holdout annotation draft.');
  shortText(draft.dataset_id, 'Dataset id', 80);
  shortText(draft.source, 'Dataset source');
  shortText(draft.license, 'Dataset rights');
  insist(Array.isArray(draft.records) && draft.records.length >= minimumImages && draft.records.length <= 1000,
    `At least ${minimumImages} reviewed screenshots are required.`);
  const seenFiles = new Set(), seenHashes = new Set(), seenIds = new Set(), records = [];
  for (const row of draft.records) {
    insist(row && typeof row === 'object', 'Invalid screenshot record.');
    shortText(row.id, 'Record id', 120);
    filename(row.filename);
    insist(!seenFiles.has(row.filename) && !seenIds.has(row.id), 'Duplicate record id or filename.');
    seenFiles.add(row.filename); seenIds.add(row.id);
    insist(row.source_type === 'email_screenshot', `${row.id}: this holdout accepts email screenshots only.`);
    shortText(row.source_reference, `${row.id} source reference`);
    shortText(row.rights_reference, `${row.id} rights reference`);
    insist(row.annotation?.method === 'manual_pixels' && row.annotation.url_reviewed === true &&
      row.annotation.qr_reviewed === true, `${row.id}: manually review pixels, visible URLs and QR presence.`);
    shortText(row.annotation.transcribed_by, `${row.id} transcriber`, 120);
    shortText(row.annotation.verified_by, `${row.id} verifier`, 120);
    insist(row.annotation.transcribed_by !== row.annotation.verified_by,
      `${row.id}: use a different verifier for the independent review declaration.`);
    const image = await originalImage(imageRoot, row.filename);
    insist(row.sha256 === image.sha256 && row.width === image.width && row.height === image.height,
      `${row.id}: original image changed after annotation.`);
    insist(!seenHashes.has(image.sha256), 'Duplicate image bytes are not independent samples.');
    seenHashes.add(image.sha256);
    insist(Array.isArray(row.expected_urls) && JSON.stringify([...row.expected_urls].sort()) ===
      JSON.stringify(extractURLs(row.expected_text)),
      `${row.id}: visible URL labels must exactly match literal HTTP(S) tokens in the manual transcription.`);
    const record = {id:row.id, filename:row.filename, sha256:image.sha256,
      language:row.language, expected_text:row.expected_text,
      expected_urls:row.expected_urls, expected_qr_payloads:row.expected_qr_payloads,
      label:row.label, source_type:row.source_type, source_reference:row.source_reference,
      rights_reference:row.rights_reference,
      annotation:row.annotation};
    validateManifest({schema_version:SCHEMA, dataset_id:draft.dataset_id, records:[record]});
    records.push(record);
  }
  const urlPositive = records.filter(row => row.expected_urls.length > 0).length;
  const urlNegative = records.length - urlPositive;
  insist(urlPositive >= minimumUrlPositive && urlNegative >= minimumUrlNegative,
    `The holdout needs at least ${minimumUrlPositive} visible-URL and ${minimumUrlNegative} URL-negative screenshots.`);
  const manifest = {schema_version:SCHEMA, dataset_id:draft.dataset_id, source:draft.source,
    license:draft.license, limitations:[
      'Human review is declared in metadata; this tool cannot prove transcription, provenance, rights, or representativeness.',
      'URLs are visible characters only; hidden email hyperlink targets are outside OCR scope.',
      'No engine output was used to create ground truth by this tool.'
    ], holdout_audit:{review_declarations_validated:records.length, url_positive_count:urlPositive,
      url_negative_count:urlNegative, independent_accuracy:'not_established'}, records};
  validateManifest(manifest);
  return manifest;
}

function parseArgs(args) {
  const command = args.shift();
  insist(command === 'prepare' || command === 'finalize',
    'Use prepare --image-root DIR --dataset-id ID --source TEXT --rights TEXT --output FILE, or finalize --draft FILE --image-root DIR --output FILE.');
  const values = {};
  const allowed = command === 'prepare'
    ? ['--image-root','--dataset-id','--source','--rights','--output']
    : ['--draft','--image-root','--output'];
  insist(args.length % 2 === 0, 'Arguments must be name/value pairs.');
  for (let i = 0; i < args.length; i += 2) {
    insist(allowed.includes(args[i]) && args[i + 1] && !(args[i] in values), 'Unknown or duplicate argument.');
    values[args[i]] = args[i + 1];
  }
  insist(allowed.every(key => key in values), 'Missing required argument.');
  return {command, values};
}

async function main() {
  const {command, values} = parseArgs(process.argv.slice(2));
  const manifest = command === 'prepare'
    ? await prepareHoldout({imageRoot:values['--image-root'], datasetId:values['--dataset-id'],
        source:values['--source'], rights:values['--rights']})
    : await finalizeHoldout(JSON.parse((await readBoundedFile(resolve(values['--draft']),4*1024*1024)).toString('utf8')),
        values['--image-root']);
  await writeFile(resolve(values['--output']), JSON.stringify(manifest,null,2)+'\n', {mode:0o600, flag:'wx'});
  process.stdout.write(JSON.stringify({schema_version:manifest.schema_version,
    dataset_id:manifest.dataset_id, count:manifest.records.length,
    ...(manifest.holdout_audit || {})})+'\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
