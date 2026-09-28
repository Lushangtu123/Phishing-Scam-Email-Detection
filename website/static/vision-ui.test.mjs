import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
class Element {
  constructor(tag) { this.tag=tag;this.children=[];this.textContent=''; }
  set innerHTML(_) {throw new Error('HTML rendering is forbidden');}
  append(...nodes) {this.children.push(...nodes);}
  replaceChildren(...nodes) {this.children=nodes;}
}
function setup() {
  const workers=[], created=[], revoked=[];
  class Worker {
    constructor() {workers.push(this);}
    postMessage(message) {this.input=message;}
    terminate() {this.terminated=true;}
  }
  const window={};
  vm.runInNewContext(readFileSync(new URL('./vision.js',import.meta.url),'utf8'),{
    window,document:{createElement:tag=>new Element(tag)},Worker,setTimeout,clearTimeout,Uint8Array,
    URL:{createObjectURL(file) { created.push(file); return `blob:preview-${created.length}`; },
      revokeObjectURL(url) { revoked.push(url); }},
    btoa:s=>Buffer.from(s,'binary').toString('base64'),
  });
  return {api:window.PhishGuardVision,workers,created,revoked};
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
test('image bytes are included only after explicit enhanced-recognition consent', async()=>{
  for (const enhance of [false,true]) {
    const {api,workers}=setup(), bytes=new Uint8Array([1,2,3]);
    const promise=api.recognize({name:'test.png',size:3,arrayBuffer:async()=>bytes.buffer},()=>{},'eng',{enhance});
    await tick();workers[0].onmessage({data:{result:{observations:[],warnings:[]}}});
    const result=await promise;
    assert.equal('enhancement' in result,enhance);
    if (enhance) {
      assert.equal(result.enhancement.consent,true);
      assert.deepEqual(Buffer.from(result.enhancement.image_base64,'base64'),Buffer.from(bytes));
      assert.equal(result.enhancement.include_semantics,false);
    }
  }
});
test('enhancement refuses EML before reading or transmitting original bytes',async()=>{
  const {api}=setup();let read=false;
  await assert.rejects(api.recognize({name:'test.eml',size:1,arrayBuffer:async()=>{read=true;}},()=>{},'eng',{enhance:true}),/standalone image/);
  assert.equal(read,false);
});
test('additional model observations render as text without replacing browser OCR',()=>{
  const {api}=setup(),root=new Element('section');
  api.render(root,{observations:[{name:'image.png',status:'processed',ocr_confidence:90,ocr_text:'https://paypa1.example',qr_payloads:[],warnings:[]}],
    enhancement:{status:'available',ocr:{engine:'RapidOCR',version:'test',text:'https://paypal.example'},url_disagreement:true,
      semantic:{status:'available',model:'test',observations:['<script>bad()</script>'],visible_urls:['javascript:alert(1)']},warnings:[]}});
  const walk=node=>[node,...node.children.flatMap(walk)],nodes=walk(root),text=nodes.map(n=>n.textContent).join(' ');
  assert.match(text,/paypa1\.example/);assert.match(text,/paypal\.example/);assert.match(text,/disagree/);
  assert.match(text,/not a safety verdict/);assert(nodes.some(n=>n.textContent==='<script>bad()</script>'));
  assert(!nodes.some(n=>['a','script'].includes(n.tag)));
});
test('cancel while reading a file prevents the worker and result from appearing',async()=>{
  const {api,workers}=setup();let release;
  const promise=api.recognize({name:'test.png',size:1,arrayBuffer:()=>new Promise(resolve=>{release=resolve;})});
  const rejected=assert.rejects(promise,/cancelled/);
  api.cancel(); release(new Uint8Array([1]).buffer);await rejected;
  assert.equal(workers.length,0);
});
test('cancel terminates active recognition; late messages cannot restore a result',async()=>{
  const {api,workers}=setup();
  const promise=api.recognize({name:'test.png',size:1,arrayBuffer:async()=>new Uint8Array([1]).buffer});
  const rejected=assert.rejects(promise,/cancelled/);
  await tick();api.cancel();workers[0].onmessage({data:{result:{observations:[],warnings:[]}}});await rejected;
  assert.equal(workers[0].terminated,true);
});
test('EML envelope preserves non-UTF8 bytes and recognition evidence',async()=>{
  const {api,workers}=setup(),bytes=new Uint8Array([72,233,98,101]);
  const promise=api.recognize({name:'original.eml',size:4,arrayBuffer:async()=>bytes.buffer});
  await tick();workers[0].onmessage({data:{result:{observations:[],warnings:['Some images skipped']}}});
  const payload=await promise;
  assert.deepEqual(Buffer.from(payload.eml_base64,'base64'),Buffer.from(bytes));
  assert.equal(payload.warnings[0],'Some images skipped');assert.equal(workers[0].terminated,true);
});
test('recognition evidence renders malicious payloads only as text, never links or HTML',()=>{
  const {api}=setup(),root=new Element('section');
  const payload='<img src=x onerror=alert(1)>',url='javascript:alert(1)';
  api.render(root,{observations:[{name:payload,status:'processed',risk_level:'high',ocr_confidence:80,qr_payloads:[url],ocr_text:payload,warnings:[]}],warnings:[]});
  function walk(node) {return [node,...node.children.flatMap(walk)];}
  const nodes=walk(root);
  assert(nodes.some(n=>n.tag==='pre'&&n.textContent===url));
  assert(nodes.some(n=>n.tag==='pre'&&n.textContent===payload));
  assert(!nodes.some(n=>['img','a','script'].includes(n.tag)));
  api.render(root,null);assert.equal(root.children.length,0);assert.equal(root.hidden,true);
});

test('successful OCR with unknown risk distinguishes recognition from risk and model confidence',()=>{
  const {api}=setup(),root=new Element('section');
  const item={name:'newsletter.png',status:'processed',risk_level:'unknown',ocr_confidence:92,
    qr_payloads:[],ocr_text:'Readable newsletter text.',warnings:[],ml_status:'available',ml_phishing_probability:12};
  function textOf(node) {return [node.textContent,...node.children.map(textOf)].join(' ');}
  api.render(root,{observations:[item],warnings:[]});
  let text=textOf(root);
  assert.match(text,/Recognition completed/);
  assert.match(text,/Risk undetermined/);
  assert.match(text,/OCR confidence 92%/);
  assert.match(text,/Extracted-text model score: 12%/);
  assert.match(text,/not a phishing probability/);
  api.render(root,{observations:[{...item,status:'failed',ocr_text:'',ml_status:'insufficient_context',ml_phishing_probability:null}],warnings:[]});
  text=textOf(root);
  assert.match(text,/Recognition failed/);
  assert.doesNotMatch(text,/Recognition completed|model score: 12%/);
  assert.match(text,/Too little readable text/);
});
test('URL line confidence is displayed separately from high whole-image confidence',()=>{
  const {api}=setup(),root=new Element('section');
  api.render(root,{observations:[{name:'url.png',status:'processed',risk_level:'unknown',ocr_confidence:92,
    ocr_url_line_confidence:48,qr_payloads:[],ocr_text:'https://paypal.example/login',warnings:[]}]});
  const text=JSON.stringify(root);
  assert.match(text,/OCR confidence 92%/);
  assert.match(text,/URL-like line OCR confidence: 48%/);
  assert.match(text,/character by character/);
  assert.match(text,/https:\/\/paypal.example\/login/);
});

test('multiple independent sources label their maximum model score honestly',()=>{
  const {api}=setup(),root=new Element('section');
  api.render(root,{observations:[{name:'mixed.png',status:'processed',risk_level:'high',ocr_confidence:90,
    qr_payloads:['Enter your password'],ocr_text:'Do not',warnings:[],ml_status:'available',
    ml_phishing_probability:88,assessment_method:'independent-source-max',assessed_source_count:2}]});
  const text=JSON.stringify(root);
  assert.match(text,/Highest extracted-source model score: 88%/);
  assert.doesNotMatch(text,/Extracted-text model score:/);
  assert.match(text,/Do not/);
  assert.match(text,/Enter your password/);
});

test('original image preview stays local and its object URL is revoked on clear or replacement',()=>{
  const {api,created,revoked}=setup(), root=new Element('section');
  const file={name:'suspect.png',type:'image/png',size:1024};
  const item={name:'suspect.png',source:'upload',mime_type:'image/png',status:'processed',
    risk_level:'unknown',ocr_confidence:92,qr_payloads:[],ocr_text:'https://paypal.example/login',warnings:[]};
  const analysis={observations:[item],warnings:[]};
  function walk(node) {return [node,...node.children.flatMap(walk)];}
  api.render(root,analysis,file);
  const image=walk(root).find(node=>node.tag==='img');
  assert.equal(image?.src,'blob:preview-1');
  assert.match(JSON.stringify(root),/Original uploaded image/);
  assert.deepEqual(created,[file]);
  assert.deepEqual(revoked,[]);
  api.render(root,analysis,file);
  assert.deepEqual(revoked,['blob:preview-1']);
  api.render(root,null);
  assert.deepEqual(revoked,['blob:preview-1','blob:preview-2']);
  assert.equal(root.children.length,0);
  api.render(root,analysis,{...file,type:'image/svg+xml'});
  api.render(root,{observations:[{...item,source:'mime'}]},file);
  assert.equal(created.length,2,'unsupported and embedded files are not previewed');
});

test('OCR language defaults to English and forwards each explicit supported choice',async()=>{
  for (const language of [undefined,'eng','chi_sim','eng+chi_sim']) {
    const {api,workers}=setup();
    const promise=api.recognize({name:'test.png',size:1,arrayBuffer:async()=>new Uint8Array([1]).buffer},()=>{},language);
    await tick();
    const sent=workers[0].input.language;
    workers[0].onmessage({data:{result:{observations:[],warnings:[]}}});
    await promise;
    assert.equal(sent,language ?? 'eng');
  }
});
test('unsupported OCR language is rejected before reading the file or starting a worker',async()=>{
  const {api,workers}=setup();let read=false;
  const rejected=assert.rejects(api.recognize({name:'test.png',size:1,arrayBuffer:async()=>{read=true;return new ArrayBuffer(1);}},()=>{},'../../unknown'),/language/i);
  await tick();workers[0]?.onmessage({data:{result:{observations:[],warnings:[]}}});await rejected;
  assert.equal(read,false);assert.equal(workers.length,0);
});
