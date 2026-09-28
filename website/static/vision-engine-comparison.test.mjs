import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, symlink, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import http from 'node:http';
import {score, SCHEMA} from '../tools/vision-benchmark/metrics.mjs';
import {IMAGE_LIMIT, RESPONSE_LIMIT, sha256, readVerifiedImage, requestRecognition, extractionMetadata, evaluateService} from '../tools/vision-benchmark/evaluate-service.mjs';
import {compareReports} from '../tools/vision-benchmark/compare-engines.mjs';

const image = Buffer.from('project-owned image bytes for service contract tests');
const record = (id,extra={}) => ({id,filename:`${id}.png`,sha256:sha256(image),language:'eng',expected_text:'https://paypa1.example/login.\n',expected_qr_payloads:[],expected_urls:['https://paypa1.example/login.'],label:'phishing',...extra});
const manifest = records => ({schema_version:SCHEMA,dataset_id:'synthetic-engine-controls',records});
const bytes = data => Buffer.from(JSON.stringify(data));
const outcome = (record,extra={}) => ({id:record.id,status:'processed',text:record.expected_text,qr_payloads:[],elapsed_ms:10,...extra});
function report(data,outcomes) { return score(data,outcomes,{manifest_sha256:sha256(bytes(data)),risk_requested:false}); }
const response = (extra={}) => ({schema:'phishguard-enhanced-vision/v1',image_sha256:sha256(image),ocr:{engine:'RapidOCR',version:'1.4.4',text:'https://paypa1.example/login.\n',confidence:.95},semantic:{status:'disabled'},warnings:[],...extra});

async function temporary(t) {
  const root = await mkdtemp(join(tmpdir(),'phishguard-engine-tests-'));
  t.after(() => rm(root,{recursive:true,force:true}));
  return root;
}
async function service(t, handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return server.address().port;
}

test('comparison requires identical dataset, exact manifest bytes and every ground-truth record',() => {
  const data = manifest([record('a'),record('b')]), baseline = report(data,data.records.map(r => outcome(r)));
  for (const patch of [r => {r.dataset_id='other';},r => {r.identity.manifest_sha256='a'.repeat(64);},r => {r.records.pop();},r => {r.records[0].language='chi_sim';},r => {r.records[0].reference_characters++;},r => {r.records[0].expected_qr_count++;}]) {
    const candidate = structuredClone(baseline); patch(candidate);
    assert.throws(() => compareReports(baseline,candidate,bytes(data)), /mismatch|required/);
  }
  assert.throws(() => compareReports(baseline,baseline,Buffer.from(JSON.stringify(data,null,2))),/manifest hash/);
});

test('dropped failures cannot improve URL or CER denominators',() => {
  const data = manifest([record('a'),record('b'),record('c',{language:'chi_sim'})]);
  const baseline = report(data,[outcome(data.records[0]),outcome(data.records[1],{status:'timeout'} )]);
  const candidate = report(data,[outcome(data.records[0]),outcome(data.records[1]),outcome(data.records[2])]);
  const comparison = compareReports(baseline,candidate,bytes(data));
  assert.equal(comparison.summary.baseline.count,3);
  assert.equal(comparison.summary.baseline.url_exact_set_rate,1/3);
  assert.equal(comparison.summary.baseline.failed_count,2);
  assert.equal(comparison.by_language.chi_sim.baseline.failed_count,1);
  assert.equal(comparison.summary.candidate.url_exact_set_rate,1);
  assert.equal(comparison.proposed_gate.metric_gate,'passed');
  assert.equal(comparison.proposed_gate.adoption_ready,false);
  const dropped = structuredClone(baseline); dropped.summary.count=1;
  assert.throws(() => compareReports(dropped,candidate,bytes(data)),/denominator/);
  const changed = structuredClone(baseline); changed.summary.url_exact_set_rate=1;
  assert.throws(() => compareReports(changed,candidate,bytes(data)),/denominator/);
});

test('changed URL spelling and punctuation remain mandatory-control regressions',() => {
  const data = manifest([record('a'),record('b'),record('c')]);
  const baseline = report(data,[outcome(data.records[0]),outcome(data.records[1],{status:'failed'}),outcome(data.records[2],{status:'failed'})]);
  for (const changed of ['https://paypal.example/login.\n','https://paypa1.example/login\n']) {
    const candidate = report(data,[outcome(data.records[0],{text:changed}),outcome(data.records[1]),outcome(data.records[2])]);
    const comparison = compareReports(baseline,candidate,bytes(data));
    assert.ok(comparison.summary.url_exact_gain_percentage_points > 10);
    assert.equal(comparison.proposed_gate.url_gain_passed,true);
    assert.equal(comparison.proposed_gate.mandatory_no_losses,false);
    assert.equal(comparison.proposed_gate.metric_gate,'failed');
    assert.deepEqual(comparison.proposed_gate.regressions[0].losses,['literal_url_set','exact_text']);
  }
});

test('extra mandatory ids cannot hide a regression on URL-labeled controls',() => {
  const data=manifest([record('a'),record('b'),record('c',{expected_urls:undefined})]);
  const baseline=report(data,[outcome(data.records[0]),outcome(data.records[1],{status:'failed'}),outcome(data.records[2])]);
  const candidate=report(data,[outcome(data.records[0],{text:'https://paypal.example/login.\n'}),outcome(data.records[1]),outcome(data.records[2])]);
  const comparison=compareReports(baseline,candidate,bytes(data),{mandatoryIds:['c']});
  assert.deepEqual(comparison.proposed_gate.mandatory_control_ids,['a','b','c']);
  assert.equal(comparison.proposed_gate.metric_gate,'failed');
  assert.equal(comparison.proposed_gate.regressions[0].id,'a');
});

test('no URL ground truth and empty mandatory controls cannot pass adoption gate',() => {
  const data = manifest([record('a',{expected_urls:undefined})]), result = report(data,[outcome(data.records[0])]);
  const comparison = compareReports(result,result,bytes(data));
  assert.equal(comparison.summary.url_exact_gain_percentage_points,null);
  assert.equal(comparison.proposed_gate.metric_gate,'failed');
  assert.throws(() => compareReports(result,result,bytes(data),{mandatoryIds:['unknown']}));
});

test('comparison excludes raw content and explicit risk/QR claims',() => {
  const data = manifest([record('a')]), a = report(data,[outcome(data.records[0])]);
  a.identity.private_ocr_text='PRIVATE_OCR_SENTINEL';
  a.records[0].text='PRIVATE_OCR_SENTINEL';
  const comparison = compareReports(a,a,bytes(data));
  assert.ok(!JSON.stringify(comparison).includes('PRIVATE_OCR_SENTINEL'));
  assert.equal(comparison.qr_evaluation,'not_requested');
  assert.equal(comparison.risk_evaluation,'not_requested');
  assert.equal(comparison.independent_accuracy,'not_established');
});

test('image reads enforce original-byte hash and reject traversal and escaped symlinks',async t => {
  const root = await temporary(t), images = join(root,'images');
  await mkdir(images); await writeFile(join(images,'a.png'),image); await writeFile(join(root,'outside.png'),image);
  assert.deepEqual(await readVerifiedImage(images,record('a')),image);
  await assert.rejects(readVerifiedImage(images,record('a',{sha256:'a'.repeat(64)})),e => e.status === 'hash_mismatch');
  await assert.rejects(readVerifiedImage(images,record('missing')),e => e.status === 'missing');
  for (const filename of ['../outside.png','/outside.png','https://example.com/a.png','a\\b.png']) await assert.rejects(readVerifiedImage(images,record('a',{filename})),/Unsafe/);
  await symlink(join(root,'outside.png'),join(images,'escape.png'));
  await assert.rejects(readVerifiedImage(images,record('escape')),/symlink escapes/);
  await symlink(join(root),join(images,'outside-dir'));
  await assert.rejects(readVerifiedImage(images,record('a',{filename:'outside-dir/outside.png'})),/symlink escapes/);
  await writeFile(join(images,'large.png'),Buffer.alloc(IMAGE_LIMIT+1));
  await assert.rejects(readVerifiedImage(images,record('large')),/size limit/);
});

test('service requests target only fixed loopback and send bounded OCR-only JSON',async t => {
  let received;
  const port = await service(t,(req,res) => {
    assert.equal(req.url,'/recognize'); assert.equal(req.method,'POST');
    assert.equal(req.socket.localAddress,'127.0.0.1');
    const chunks=[]; req.on('data',c => chunks.push(c)); req.on('end',() => { received=JSON.parse(Buffer.concat(chunks)); res.end(JSON.stringify(response())); });
  });
  const result = await requestRecognition(port,image,'eng');
  assert.equal(result.ocr.engine,'RapidOCR');
  assert.deepEqual(received,{image_base64:image.toString('base64'),language:'eng',include_semantics:false});
  assert.throws(() => requestRecognition(port,Buffer.alloc(IMAGE_LIMIT+1),'eng'),/size limit/);
  assert.throws(() => requestRecognition(0,image,'eng'),/port/);
});

test('redirects are not followed and oversized responses are rejected',async t => {
  let followed=0;
  const port = await service(t,(req,res) => {
    if(req.url === '/other') {followed++;res.end(JSON.stringify(response()));return;}
    res.writeHead(302,{Location:'/other'});res.end();
  });
  await assert.rejects(requestRecognition(port,image,'eng'),/non-200/);
  assert.equal(followed,0);
  const bigPort = await service(t,(_req,res) => res.end('x'.repeat(RESPONSE_LIMIT+1)));
  await assert.rejects(requestRecognition(bigPort,image,'eng'),/size limit/);
});

test('service timeouts and invalid hashes are explicit rather than plausible OCR',async t => {
  const port = await service(t,() => {});
  await assert.rejects(requestRecognition(port,image,'eng',20),e => e.status === 'timeout');
  assert.throws(() => extractionMetadata(response({image_sha256:'a'.repeat(64)}),sha256(image)),/hash mismatch/);
  assert.throws(() => extractionMetadata(response({ocr:{text:'words'}}),sha256(image)),/engine identity/);
});

test('actual service engine provenance is retained without raw OCR, semantic or QR data',() => {
  const result = response({provenance:{model_sha256:{det:'a'.repeat(64)},runtime_version:'1.20.1',engine_source_sha256:'b'.repeat(64),private_ocr_text:'PRIVATE_OCR_SENTINEL'}});
  result.ocr.text='PRIVATE_OCR_SENTINEL'; result.semantic={status:'processed',observations:['PRIVATE_SEMANTIC_SENTINEL'],visible_urls:['https://private.example']};
  const metadata = extractionMetadata(result,sha256(image));
  assert.equal(metadata.engine,'RapidOCR'); assert.equal(metadata.version,'1.4.4');
  assert.deepEqual(metadata.model_sha256,{det:'a'.repeat(64)});
  assert.equal(metadata.runtime_version,'1.20.1');
  assert.ok(!JSON.stringify(metadata).includes('PRIVATE'));
  assert.ok(!JSON.stringify(metadata).includes('https://private.example'));
});

test('evaluation preserves missing and wrong-hash records, languages, and QR not evaluated',async t => {
  const root = await temporary(t);
  await writeFile(join(root,'a.png'),image); await writeFile(join(root,'wrong.png'),image);
  const data = manifest([record('a'),record('missing',{language:'chi_sim'}),record('wrong',{sha256:'a'.repeat(64),expected_qr_payloads:['PRIVATE_QR_SENTINEL']})]);
  const port = await service(t,(_req,res) => res.end(JSON.stringify(response())));
  const result = await evaluateService({manifestBytes:bytes(data),imageRoot:root,port});
  assert.equal(result.summary.count,3); assert.equal(result.summary.statuses.processed,1);
  assert.equal(result.summary.statuses.missing,1); assert.equal(result.summary.statuses.hash_mismatch,1);
  assert.equal(result.summary.url_exact_set_rate,1/3);
  assert.equal(result.by_language.chi_sim.count,1);
  assert.equal(result.summary.qr_exact_set_rate,null); assert.equal(result.summary.qr_positive_count,null);
  assert.equal(result.records[2].qr_exact,null); assert.equal(result.records[2].expected_qr_count,1);
  assert.equal(result.risk_evaluation,'not_requested'); assert.equal(result.qr_evaluation,'not_requested');
  assert.ok(!JSON.stringify(result).includes('PRIVATE_QR_SENTINEL'));
  assert.ok(!JSON.stringify(result).includes('https://paypa1.example'));
  assert.deepEqual(result.identity.actual_engines,['RapidOCR@1.4.4']);
  const comparison = compareReports(report(data,[outcome(data.records[0])]),result,bytes(data));
  assert.equal(comparison.engine_provenance.candidate[0].engine,'RapidOCR');
});

test('timeout and partial OCR remain scored with no raw warnings exported',async t => {
  const root = await temporary(t); await writeFile(join(root,'a.png'),image);
  const data = manifest([record('a')]);
  const silentPort = await service(t,() => {});
  const timeout = await evaluateService({manifestBytes:bytes(data),imageRoot:root,port:silentPort,timeoutMs:20});
  assert.equal(timeout.summary.statuses.timeout,1); assert.equal(timeout.summary.url_exact_set_rate,0);
  const port = await service(t,(_req,res) => res.end(JSON.stringify(response({warnings:['PRIVATE_WARNING_SENTINEL']}))));
  const partial = await evaluateService({manifestBytes:bytes(data),imageRoot:root,port});
  assert.equal(partial.summary.statuses.partial,1); assert.equal(partial.summary.url_exact_set_rate,1);
  assert.equal(partial.records[0].extraction.warning_count,1);
  assert.ok(!JSON.stringify(partial).includes('PRIVATE_WARNING_SENTINEL'));
});
