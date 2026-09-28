#!/usr/bin/env node
// OCR-only evaluation of the optional loopback service. Never follows URLs.
import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {open, realpath, stat, writeFile} from 'node:fs/promises';
import http from 'node:http';
import {dirname, isAbsolute, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {score, validateManifest} from './metrics.mjs';

export const IMAGE_LIMIT = 2 * 1024 * 1024;
export const REQUEST_LIMIT = 3 * 1024 * 1024;
export const RESPONSE_LIMIT = 64 * 1024;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const inside = (root, path) => { const rel = relative(root, path); return rel !== '..' && !rel.startsWith('../') && !isAbsolute(rel); };
function error(status, message) { return Object.assign(new Error(message), {status}); }

export async function readBoundedFile(path, limit) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    if (!(await file.stat()).isFile()) throw error('failed', 'Expected a regular file.');
    const buffer = Buffer.alloc(limit + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const {bytesRead} = await file.read(buffer, offset, buffer.length - offset, null);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset > limit) throw error('failed', 'File size limit exceeded.');
    return buffer.subarray(0, offset);
  } finally { await file.close(); }
}

export async function readVerifiedImage(imageRoot, record) {
  if (typeof record.filename !== 'string' || /[\\:\x00-\x1f]/.test(record.filename) || isAbsolute(record.filename) || record.filename.split('/').some(p => !p || p === '.' || p === '..')) throw error('failed', 'Unsafe image filename.');
  const root = await realpath(imageRoot);
  if (!(await stat(root)).isDirectory()) throw error('failed', 'Image root must be a directory.');
  let path;
  try { path = await realpath(resolve(root, record.filename)); }
  catch (e) { if (e.code === 'ENOENT' || e.code === 'ENOTDIR') throw error('missing', 'Image is missing.'); throw e; }
  if (!inside(root, path)) throw error('failed', 'Image symlink escapes the image root.');
  const bytes = await readBoundedFile(path, IMAGE_LIMIT);
  if (!bytes.length) throw error('failed', 'Image is empty.');
  if (sha256(bytes) !== record.sha256) throw error('hash_mismatch', 'Image SHA-256 does not match the manifest.');
  return bytes;
}

export function requestRecognition(port, image, language, timeoutMs = 55000) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Service port must be 1–65535.');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) throw new Error('Timeout must be 1–120000 ms.');
  if (!Buffer.isBuffer(image) || !image.length || image.length > IMAGE_LIMIT) throw error('failed', 'Image size limit exceeded.');
  if (!['eng', 'chi_sim', 'eng+chi_sim'].includes(language)) throw error('failed', 'Unsupported language.');
  const body = Buffer.from(JSON.stringify({image_base64:image.toString('base64'), language, include_semantics:false}));
  if (body.length > REQUEST_LIMIT) throw error('failed', 'Request size limit exceeded.');
  return new Promise((resolveRequest, reject) => {
    let settled = false;
    const finish = (err, result) => { if (settled) return; settled = true; clearTimeout(timer); err ? reject(err) : resolveRequest(result); };
    // node:http uses this literal host directly: no proxy environment, DNS or redirects.
    const request = http.request({hostname:'127.0.0.1', port, path:'/recognize', method:'POST', agent:false,
      headers:{'Content-Type':'application/json', 'Content-Length':body.length}}, response => {
      if (response.statusCode !== 200) { response.resume(); finish(error('failed', 'Recognition returned a non-200 response.')); request.destroy(); return; }
      let size = 0; const chunks = [];
      response.on('data', chunk => {
        size += chunk.length;
        if (size > RESPONSE_LIMIT) { finish(error('failed', 'Recognition response size limit exceeded.')); response.destroy(); return; }
        chunks.push(chunk);
      });
      response.on('error', e => finish(error('failed', e.code || 'Response failed.')));
      response.on('end', () => {
        if (settled) return;
        try { finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { finish(error('failed', 'Recognition returned invalid JSON.')); }
      });
    });
    const timer = setTimeout(() => { finish(error('timeout', 'Recognition timed out.')); request.destroy(); }, timeoutMs);
    request.on('error', e => finish(error('failed', e.code || 'Request failed.')));
    request.end(body);
  });
}

// Accept only engine/version/hash metadata. Raw OCR and semantic outputs never enter exports.
export function extractionMetadata(response, expectedHash) {
  const ocr = response?.ocr;
  if (response?.schema !== 'phishguard-enhanced-vision/v1' || response.image_sha256 !== expectedHash || !hash(expectedHash)) throw error('failed', 'Recognition schema or input hash mismatch.');
  if (!ocr || typeof ocr.text !== 'string' || ocr.text.length > 24000 || !['engine', 'version'].every(k => typeof ocr[k] === 'string' && ocr[k].length > 0 && ocr[k].length <= 160)) throw error('failed', 'Invalid OCR result or engine identity.');
  if (ocr.confidence !== undefined && ocr.confidence !== null && (!Number.isFinite(ocr.confidence) || ocr.confidence < 0 || ocr.confidence > 100)) throw error('failed', 'Invalid OCR confidence.');
  if (!Array.isArray(response.warnings) || response.warnings.some(w => typeof w !== 'string')) throw error('failed', 'Invalid service warning list.');
  const metadata = {engine:ocr.engine, version:ocr.version, image_sha256:expectedHash, warning_count:response.warnings.length, provenance:'service_declared'};
  const declared = response.provenance || {};
  for (const key of ['runtime_version']) {
    if (typeof declared[key] === 'string' && /^[A-Za-z0-9_.+/@ -]{1,160}$/.test(declared[key])) metadata[key] = declared[key];
  }
  if (hash(declared.engine_source_sha256)) metadata.engine_source_sha256 = declared.engine_source_sha256;
  for (const key of ['model_sha256']) {
    const values = declared[key];
    if (!values || typeof values !== 'object' || Array.isArray(values)) continue;
    const entries = Object.entries(values).filter(([name, value]) => /^[A-Za-z0-9_.-]{1,80}$/.test(name) && hash(value));
    if (entries.length) metadata[key] = Object.fromEntries(entries);
  }
  return metadata;
}

function omitQR(report) {
  report.qr_evaluation = 'not_requested';
  report.semantics.provenance = 'Loopback OCR service metadata is service-declared. Input SHA-256 is verified against original manifest bytes; this does not authenticate model provenance.';
  report.semantics.qr = 'Not evaluated: this runner calls OCR only and never guesses QR payloads.';
  for (const group of [report.summary, ...Object.values(report.by_language)]) {
    group.qr_evaluation = 'not_requested';
    for (const key of Object.keys(group).filter(k => k.startsWith('qr_') && k !== 'qr_evaluation')) group[key] = null;
  }
  for (const row of report.records) {
    row.qr_evaluation = 'not_requested';
    row.qr_exact = row.qr_matched_count = row.qr_extra_count = null;
  }
  return report;
}

export async function evaluateService({manifestBytes, imageRoot, port, timeoutMs = 55000, identity = {}}) {
  const manifest = validateManifest(JSON.parse(manifestBytes.toString('utf8')));
  const outcomes = [], metadata = new Map();
  for (const record of manifest.records) {
    const started = performance.now();
    const outcome = {id:record.id, status:'failed', text:'', qr_payloads:[], elapsed_ms:null};
    try {
      const image = await readVerifiedImage(imageRoot, record);
      const response = await requestRecognition(port, image, record.language, timeoutMs);
      metadata.set(record.id, extractionMetadata(response, record.sha256));
      outcome.status = response.warnings.length ? 'partial' : 'processed';
      outcome.text = response.ocr.text;
    } catch (e) { outcome.status = ['missing','hash_mismatch','timeout'].includes(e.status) ? e.status : 'failed'; }
    if (outcome.status !== 'missing') outcome.elapsed_ms = Math.round(performance.now() - started);
    outcomes.push(outcome);
  }
  const report = omitQR(score(manifest, outcomes, {...identity, manifest_sha256:sha256(manifestBytes), service_origin:`http://127.0.0.1:${port}`, extraction_mode:'service_ocr_only', generated_at:new Date().toISOString(), runtime_node:process.version, risk_requested:false, independent_accuracy:'not_established'}));
  for (const row of report.records) {
    const record = manifest.records.find(r => r.id === row.id);
    row.ground_truth_sha256 = sha256(Buffer.from(JSON.stringify(record)));
    row.extraction = metadata.get(row.id) || null;
  }
  report.identity.actual_engines = [...new Set([...metadata.values()].map(m => `${m.engine}@${m.version}`))].sort();
  return report;
}

function parseArgs(args) {
  const values = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--manifest','--image-root','--service-port','--timeout-ms','--output'].includes(args[i]) || !args[i+1] || values[args[i]]) throw new Error('Use --manifest FILE --image-root DIR --service-port PORT --output FILE [--timeout-ms N].');
    values[args[i]] = args[i+1];
  }
  if (!['--manifest','--image-root','--service-port','--output'].every(k => values[k])) throw new Error('Manifest, image root, service port and output are required.');
  return values;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const ownPath = fileURLToPath(import.meta.url), scorerPath = fileURLToPath(new URL('./metrics.mjs', import.meta.url));
  const identity = {source_hashes:{evaluate_service:sha256(await readBoundedFile(ownPath, 1024*1024)), metrics:sha256(await readBoundedFile(scorerPath,1024*1024))}};
  try {
    const cwd = resolve(dirname(ownPath), '../../..');
    identity.code_commit = execFileSync('git',['rev-parse','HEAD'],{cwd,encoding:'utf8'}).trim();
    identity.code_dirty = Boolean(execFileSync('git',['status','--porcelain'],{cwd,encoding:'utf8'}).trim());
  } catch { identity.code_commit = 'unavailable'; identity.code_dirty = null; }
  const port = Number(args['--service-port']), timeoutMs = Number(args['--timeout-ms'] || 55000);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) throw new Error('Invalid port or timeout.');
  const report = await evaluateService({manifestBytes:await readBoundedFile(resolve(args['--manifest']),4*1024*1024), imageRoot:resolve(args['--image-root']), port, timeoutMs, identity});
  await writeFile(resolve(args['--output']), JSON.stringify(report,null,2)+'\n', {mode:0o600});
  process.stdout.write(JSON.stringify({dataset_id:report.dataset_id, count:report.summary.count, statuses:report.summary.statuses, actual_engines:report.identity.actual_engines, url_exact_set_rate:report.summary.url_exact_set_rate, character_error_rate:report.summary.character_error_rate, qr_evaluation:report.qr_evaluation, risk_evaluation:report.risk_evaluation})+'\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(e => { process.stderr.write(`${e.message}\n`); process.exitCode = 1; });
