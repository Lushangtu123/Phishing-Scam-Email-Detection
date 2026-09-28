#!/usr/bin/env node
// Compare sanitized metrics, requiring the same exact manifest and every row.
import {writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {SCHEMA, validateManifest} from './metrics.mjs';
import {readBoundedFile, sha256} from './evaluate-service.mjs';

const statuses = ['processed','partial','failed','timeout','missing','hash_mismatch','cancelled'];
const usable = row => ['processed','partial'].includes(row.status);
const ratio = (n,d) => d ? n/d : null;
const near = (a,b) => a === b || (Number.isFinite(a) && Number.isFinite(b) && Math.abs(a-b) < 1e-12);
const insist = (ok,message) => { if (!ok) throw new Error(message); };
const integer = n => Number.isInteger(n) && n >= 0;

function measurements(rows) {
  const urls = rows.filter(r => r.urls_scored), chars = rows.reduce((n,r) => n+r.reference_characters,0);
  const edits = rows.reduce((n,r) => n+r.edit_distance,0);
  return {count:rows.length, statuses:Object.fromEntries(statuses.map(s => [s,rows.filter(r => r.status === s).length])),
    failed_count:rows.filter(r => !usable(r)).length, partial_count:rows.filter(r => r.status === 'partial').length,
    reference_characters:chars, edit_distance:edits, character_error_rate:ratio(edits,chars),
    text_exact_rate:ratio(rows.filter(r => r.text_exact).length,rows.length),
    url_scored_count:urls.length, url_exact_set_rate:ratio(urls.filter(r => r.urls_exact).length,urls.length),
    empty_reference_false_text_count:rows.filter(r => r.reference_characters === 0 && r.actual_characters > 0).length};
}

function validateSummary(summary, rows, name) {
  insist(summary && typeof summary === 'object', `${name}: summary is missing.`);
  const expected = measurements(rows);
  for (const key of ['count','reference_characters','edit_distance','character_error_rate','text_exact_rate','url_scored_count','url_exact_set_rate','empty_reference_false_text_count']) insist(near(summary[key],expected[key]), `${name}: inconsistent ${key} denominator or aggregate.`);
  for (const status of statuses) insist(summary.statuses?.[status] === expected.statuses[status], `${name}: inconsistent status count.`);
}

export function validateReport(report, manifest, manifestHash, name = 'report') {
  insist(report?.schema_version === SCHEMA, `${name}: unsupported report schema.`);
  insist(report.dataset_id === manifest.dataset_id, `${name}: dataset mismatch.`);
  insist(report.identity?.manifest_sha256 === manifestHash, `${name}: manifest hash mismatch.`);
  insist(Array.isArray(report.records) && report.records.length === manifest.records.length, `${name}: every manifest record is required.`);
  const byId = new Map();
  for (const row of report.records) { insist(row && !byId.has(row.id), `${name}: duplicate record.`); byId.set(row.id,row); }
  for (const record of manifest.records) {
    const row = byId.get(record.id);
    insist(row, `${name}: missing manifest record.`);
    insist(row.language === record.language && row.label === record.label && row.reference_characters === Array.from(record.expected_text).length && row.expected_qr_count === record.expected_qr_payloads.length && row.urls_scored === (record.expected_urls !== undefined), `${name}: record ground truth mismatch.`);
    if (row.ground_truth_sha256 !== undefined) insist(row.ground_truth_sha256 === sha256(Buffer.from(JSON.stringify(record))), `${name}: ground truth hash mismatch.`);
    insist(statuses.includes(row.status) && integer(row.edit_distance) && integer(row.actual_characters) && row.actual_characters <= 24000 && typeof row.text_exact === 'boolean' && typeof row.urls_exact === 'boolean', `${name}: invalid metric row.`);
    insist(row.elapsed_ms === null || Number.isFinite(row.elapsed_ms) && row.elapsed_ms >= 0, `${name}: invalid timing.`);
    insist(!row.text_exact || usable(row) && row.edit_distance === 0 && row.actual_characters === row.reference_characters, `${name}: impossible exact-text metric.`);
    insist(!row.urls_exact || usable(row) && row.urls_scored, `${name}: impossible exact-URL metric.`);
    if (!usable(row)) insist(row.actual_characters === 0 && row.edit_distance === row.reference_characters && !row.text_exact && !row.urls_exact, `${name}: failed records cannot count as successful.`);
  }
  insist(byId.size === manifest.records.length, `${name}: unknown record.`);
  validateSummary(report.summary,report.records,name);
  for (const language of ['eng','chi_sim','eng+chi_sim']) validateSummary(report.by_language?.[language],report.records.filter(r => r.language === language),`${name}/${language}`);
  return byId;
}

function delta(baseline,candidate) {
  const first = measurements(baseline), second = measurements(candidate);
  return {baseline:first, candidate:second,
    url_exact_gain_percentage_points:first.url_exact_set_rate === null || second.url_exact_set_rate === null ? null : 100*(second.url_exact_set_rate-first.url_exact_set_rate),
    character_error_rate_delta:first.character_error_rate === null || second.character_error_rate === null ? null : second.character_error_rate-first.character_error_rate,
    failed_count_delta:second.failed_count-first.failed_count};
}

function safeIdentity(identity = {}) {
  const out = {};
  for (const key of ['code_commit','manifest_sha256','generated_at','runtime_node','started_with_browser','service_origin','extraction_mode','independent_accuracy']) if (typeof identity[key] === 'string' && identity[key].length <= 512) out[key] = identity[key];
  for (const key of ['code_dirty','working_tree_dirty','asset_manifest_verified']) if (typeof identity[key] === 'boolean' || identity[key] === null) out[key] = identity[key];
  for (const key of ['source_hashes','evaluation_sha256','extraction_sha256']) {
    if (!identity[key] || typeof identity[key] !== 'object' || Array.isArray(identity[key])) continue;
    out[key] = Object.fromEntries(Object.entries(identity[key]).filter(([name,value]) => /^[A-Za-z0-9_./-]{1,160}$/.test(name) && typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)));
  }
  if (Array.isArray(identity.actual_engines)) out.actual_engines = identity.actual_engines.filter(value => typeof value === 'string' && /^[A-Za-z0-9_.+/@ -]{1,321}$/.test(value));
  return out;
}

function engineProvenance(report) {
  const values = report.records.map(row => row.extraction).filter(Boolean).map(metadata => {
    const result = {};
    for (const key of ['engine','version','provenance','runtime_version']) if (typeof metadata[key] === 'string' && /^[A-Za-z0-9_.+/@ -]{1,160}$/.test(metadata[key])) result[key] = metadata[key];
    if (typeof metadata.engine_source_sha256 === 'string' && /^[a-f0-9]{64}$/.test(metadata.engine_source_sha256)) result.engine_source_sha256 = metadata.engine_source_sha256;
    for (const key of ['model_sha256']) {
      if (!metadata[key] || typeof metadata[key] !== 'object' || Array.isArray(metadata[key])) continue;
      result[key] = Object.fromEntries(Object.entries(metadata[key]).filter(([name,value]) => /^[A-Za-z0-9_.-]{1,80}$/.test(name) && typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)));
    }
    return result;
  });
  return [...new Map(values.map(value => [JSON.stringify(value),value])).values()];
}

export function compareReports(baseline,candidate,manifestBytes,{mandatoryIds} = {}) {
  const manifest = validateManifest(JSON.parse(manifestBytes.toString('utf8'))), manifestHash = sha256(manifestBytes);
  const before = validateReport(baseline,manifest,manifestHash,'baseline'), after = validateReport(candidate,manifest,manifestHash,'candidate');
  const extras = mandatoryIds === undefined ? [] : mandatoryIds;
  insist(Array.isArray(extras) && extras.length === new Set(extras).size && extras.every(id => before.has(id)), 'Mandatory controls must be unique manifest record ids.');
  const mandatory = [...new Set([...manifest.records.filter(r => r.expected_urls !== undefined).map(r => r.id), ...extras])];
  const regressions = [];
  for (const id of mandatory) {
    const a = before.get(id), b = after.get(id), losses = [];
    if (a.urls_scored && a.urls_exact && !b.urls_exact) losses.push('literal_url_set');
    if (a.text_exact && !b.text_exact) losses.push('exact_text');
    if (usable(a) && !usable(b)) losses.push('extraction_failure');
    if (losses.length) regressions.push({id,losses});
  }
  const summary = delta(baseline.records,candidate.records);
  const urlPass = summary.url_exact_gain_percentage_points !== null && summary.url_exact_gain_percentage_points >= 10-1e-10;
  const coveragePass = summary.candidate.failed_count <= summary.baseline.failed_count;
  const emptyPass = summary.candidate.empty_reference_false_text_count <= summary.baseline.empty_reference_false_text_count;
  const mandatoryPass = mandatory.length > 0 && regressions.length === 0;
  const gatePass = urlPass && coveragePass && emptyPass && mandatoryPass;
  return {schema_version:'phishguard-vision-engine-comparison/v1',dataset_id:manifest.dataset_id,manifest_sha256:manifestHash,
    identities:{baseline:safeIdentity(baseline.identity), candidate:safeIdentity(candidate.identity)},
    engine_provenance:{baseline:engineProvenance(baseline),candidate:engineProvenance(candidate)},summary,
    by_language:Object.fromEntries(['eng','chi_sim','eng+chi_sim'].map(language => [language,delta(baseline.records.filter(r => r.language === language),candidate.records.filter(r => r.language === language))])),
    proposed_gate:{minimum_url_gain_percentage_points:10, url_gain_passed:urlPass, mandatory_control_ids:mandatory, mandatory_no_losses:mandatoryPass, regressions,
      failed_count_no_increase:coveragePass, empty_reference_false_text_no_increase:emptyPass, metric_gate:gatePass ? 'passed' : 'failed', adoption_ready:false},
    qr_evaluation:'not_requested',risk_evaluation:'not_requested',independent_accuracy:'not_established',
    limitations:['This comparison measures OCR only; QR and phishing-risk quality are not evaluated.',
      'A metric gate pass is not deployment approval. Independent representative, manually annotated screenshots are still required.',
      'Project synthetic controls and scanned-receipt diagnostics do not estimate production phishing accuracy.',
      'Model/runtime metadata is service-declared. Exact manifest hashes and complete denominators establish comparable ground truth, not model authenticity.']};
}

function parseArgs(args) {
  const values = {}, mandatoryIds = [];
  for (let i = 0; i < args.length; i += 2) {
    if (!['--baseline','--candidate','--manifest','--output','--mandatory-id'].includes(args[i]) || !args[i+1]) throw new Error('Use --baseline FILE --candidate FILE --manifest FILE --output FILE [--mandatory-id ID].');
    if (args[i] === '--mandatory-id') mandatoryIds.push(args[i+1]);
    else { if (values[args[i]]) throw new Error('Duplicate argument.'); values[args[i]] = args[i+1]; }
  }
  insist(['--baseline','--candidate','--manifest','--output'].every(k => values[k]), 'Baseline, candidate, manifest and output are required.');
  return {...values,mandatoryIds:mandatoryIds.length ? mandatoryIds : undefined};
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [baseline,candidate,manifestBytes] = await Promise.all([
    readBoundedFile(resolve(args['--baseline']),8*1024*1024).then(b => JSON.parse(b.toString('utf8'))),
    readBoundedFile(resolve(args['--candidate']),8*1024*1024).then(b => JSON.parse(b.toString('utf8'))),
    readBoundedFile(resolve(args['--manifest']),4*1024*1024)]);
  const comparison = compareReports(baseline,candidate,manifestBytes,{mandatoryIds:args.mandatoryIds});
  await writeFile(resolve(args['--output']),JSON.stringify(comparison,null,2)+'\n',{mode:0o600});
  process.stdout.write(JSON.stringify({dataset_id:comparison.dataset_id,...comparison.summary, proposed_gate:comparison.proposed_gate})+'\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(e => { process.stderr.write(`${e.message}\n`); process.exitCode = 1; });
