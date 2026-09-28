import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import {CASE_SCRIPTS, capture, caseRecord, loadCases, router, runCaseScenarios, tick as settle} from '../tests/fixtures/i18n/cases-scenarios.mjs';
import {memoryStorage} from '../tests/fixtures/i18n/scenarios.mjs';

class Element {
  constructor() { this.value = ''; this.textContent = ''; this.className = ''; this.hidden = false; this.disabled = false; this.open = false; this.dataset = {}; this.listeners = {}; this.children = []; this.files = []; this.attrs = {}; this.classList = {add(){},remove(){}}; }
  set innerHTML(_) { throw new Error('Untrusted content must never use HTML'); }
  setAttribute(key, value) { this.attrs[key] = value; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  reset() {}
  showModal() { this.open = true; }
  close() { this.open = false; this.dispatchEvent({type: 'close'}); }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  dispatchEvent(event) { this.listeners[event.type]?.(event); }
  contains(target) { return target === this; }
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const caseValue = () => ({id: 'case-1', title: '<img src=x onerror=alert(1)>', risk: 'high', status: 'pending', verdict: null, version: 1,
  created_by: 'alice', created_at: '2026-09-20T00:00:00Z', source: {subject: 'Synthetic', body: '<script>bad()</script>'},
  analysis: {extra_indicators: ['<iframe src=x>']}, provenance: {}, events: [{actor: 'alice', action: 'created', happened_at: '2026-09-20T00:00:00Z', changes: {}, note: '<svg onload=bad()>'}]});
function setup(handler, vision = {cancel() {}, render() {}}, {languages = ['en-US'], storage = new Map()} = {}) {
  const elements = new Map(), calls = [], windowEvents = {};
  const el = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  const source = readFileSync(new URL('./cases.js', import.meta.url), 'utf8');
  class DataTransfer { constructor(){this.files=[];this.items={add:file=>this.files.push(file)};} }
  const window = {addEventListener(name, callback) { windowEvents[name] = callback; }, confirm: () => true, PhishGuardVision: vision};
  let uuid = 0;
  const context=vm.createContext({document: {getElementById: el, createElement: () => new Element(), addEventListener() {}}, window,
    navigator: {languages, language: languages[0]}, localStorage: {getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value)},
    DataTransfer, Event, URLSearchParams, crypto: {randomUUID: () => 'synthetic-uuid-' + (++uuid)}, fetch: async (url, options) => { calls.push({url, options}); const result = await handler(url, options); return {ok: result.status < 400, status: result.status, json: async () => result.data}; }});
  // cases.html loads i18n.js before the other scripts.
  vm.runInContext(readFileSync(new URL('./i18n.js',import.meta.url),'utf8'),context);
  vm.runInContext(readFileSync(new URL('./file-intake.js',import.meta.url),'utf8'),context);
  vm.runInContext(source,context);
  const fire = async (id, name = 'click') => { el(id).listeners[name]({preventDefault() {}, submitter: el(id === 'create-form' ? 'create-case' : id + '-submit'), currentTarget: el(id)}); await tick(); };
  const login = async () => { el('token').value = 'synthetic-access-token-at-least-32-characters'; await fire('login-form', 'submit'); };
  return {el, fire, login, calls, window, windowEvents};
}
const standard = async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.startsWith('/api/cases?') ? {items: [caseValue()], total: 1} : caseValue()});

test('EML feedback displays decoded text and warnings without falling back to transport encoding', async () => {
  let record = {...caseValue(),kind:'feedback',provenance:{input_mode:'eml',source_consent:true},
    source:{subject:'',body:'Content-Transfer-Encoding: base64\n\nencoded'},
    source_preview:{status:'available',subject:'合成通知',body:'Meeting <img onerror=bad()>',warnings:['Charset fallback'],truncated:false}};
  const ui = setup(async url => url.split('?')[0].endsWith('/case-1') ? {status:200,data:record} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('source').textContent,'合成通知\n\nMeeting <img onerror=bad()>');
  assert.match(ui.el('source-note').textContent,/decoded/i);
  assert.match(ui.el('source-note').textContent,/Charset fallback/);
  record = {...record,source_preview:{status:'unavailable',warnings:['Original evidence unchanged']}};
  await ui.fire('reload-case');
  assert.equal(ui.el('source').textContent,'');
  assert.match(ui.el('source-note').textContent,/unavailable/i);
});

test('closing the only row on a filtered last page returns to the last valid page', async () => {
  let total = 26; const offsets = [];
  const ui = setup(async (url, options) => {
    if (options.method === 'PATCH') { total = 25; return {status:200,data:{...caseValue(),status:'closed',version:3}}; }
    if (url.startsWith('/api/cases?')) {
      const offset = Number(new URL(url,'https://synthetic.test').searchParams.get('offset'));
      offsets.push(offset);
      return {status:200,data:{items:offset >= total ? [] : [{...caseValue(),status:'in_progress',version:2}],total}};
    }
    return url.split('?')[0].endsWith('/case-1')
      ? {status:200,data:{...caseValue(),status:'in_progress',version:2}} : standard(url);
  });
  await ui.login(); ui.el('filter-status').value = 'in_progress'; await ui.fire('filters','submit');
  await ui.fire('next'); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'closed'; ui.el('note').value = 'Closing';
  await ui.fire('review-form','submit');
  assert.equal(ui.el('page').textContent, 'Page 1');
  assert.deepEqual(offsets.slice(-2), [25,0]);
  assert.equal(ui.el('count').textContent, '25 matching records');
  assert.equal(ui.el('case-list').children[0].className, 'case-row');
});

test('programmatic submits without a submitter still run and the filter summary counts active filters', async () => {
  const ui = setup(standard);
  ui.el('token').value = 'synthetic-access-token-at-least-32-characters';
  ui.el('login-form').listeners.submit({preventDefault() {}, submitter: null}); await tick();
  assert.equal(ui.el('workspace').hidden, false);
  assert.equal(ui.el('actor').textContent, 'alice');

  ui.el('filter-kind').value = 'all';
  ui.el('filters').listeners.submit({preventDefault() {}, submitter: null}); await tick();
  assert.equal(ui.el('filter-summary').textContent, 'All records');

  ui.el('filter-kind').value = 'case'; ui.el('filter-risk').value = 'high'; ui.el('filter-from').value = '2026-09-01';
  ui.el('filters').listeners.submit({preventDefault() {}, submitter: null}); await tick();
  assert.equal(ui.el('filter-summary').textContent, '3 active');
  assert(ui.calls.some(call => call.url.startsWith('/api/cases?') && call.url.includes('risk=high')));
});

test('sign-out with unsaved input waits for the themed confirmation', async () => {
  const ui = setup(standard);
  await ui.login();
  ui.el('subject').value = 'Unsaved subject';
  const prompts = [];
  ui.window.PhishGuardConfirm = async message => { prompts.push(message); return false; };
  await ui.fire('logout');
  assert.equal(ui.el('workspace').hidden, false);
  ui.window.PhishGuardConfirm = async () => true;
  await ui.fire('logout');
  assert.equal(ui.el('workspace').hidden, true);
  assert.match(prompts[0], /discard unsaved drafts/);
});

test('a corrected page request cannot overwrite a newer filter or its review draft', async () => {
  let shrink = false, release; let loads = 0;
  const ui = setup(async url => {
    if (!url.startsWith('/api/cases?')) return standard(url);
    const params = new URL(url,'https://synthetic.test').searchParams;
    if (params.get('risk') === 'low') return {status:200,data:{items:[caseValue()],total:1}};
    if (!shrink) return {status:200,data:{items:[caseValue()],total:26}};
    loads++;
    if (params.get('offset') === '25') return {status:200,data:{items:[],total:25}};
    return await new Promise(resolve => { release = resolve; });
  });
  await ui.login(); await ui.fire('next');
  ui.el('case-list').children[0].listeners.click(); await tick(); ui.el('note').value = 'Keep draft';
  shrink = true; await ui.fire('refresh'); assert.equal(loads, 2);
  ui.el('filter-risk').value = 'low'; await ui.fire('filters','submit');
  release({status:200,data:{items:[],total:0}}); await tick();
  assert.equal(ui.el('count').textContent, '1 matching records');
  assert.equal(ui.el('note').value, 'Keep draft');
});

test('page recovery is bounded while a partial queue keeps shrinking', async () => {
  let shrinking = false; const offsets = [];
  const ui = setup(async url => {
    if (!url.startsWith('/api/cases?')) return standard(url);
    const offset = Number(new URL(url,'https://synthetic.test').searchParams.get('offset'));
    if (!shrinking) return {status:200,data:{items:[caseValue()],total:75}};
    offsets.push(offset);
    return {status:200,data:{items:[],total:offset ? offset : 0,partial:true,sources:{case:'unavailable',feedback:'available'}}};
  });
  await ui.login(); await ui.fire('next'); await ui.fire('next');
  shrinking = true; await ui.fire('refresh');
  assert.deepEqual(offsets, [50,25]);
  assert.match(ui.el('notice').textContent, /changed.*refresh/i);
  assert.match(ui.el('queue-warning').textContent, /Cases unavailable/);
  assert.doesNotMatch(ui.el('case-list').children[0].textContent, /No cases match/);
});

test('failed corrective read preserves the page and retries safely; zero results reset to page one', async () => {
  let phase = 'initial'; const offsets = [];
  const ui = setup(async url => {
    if (!url.startsWith('/api/cases?')) return standard(url);
    const offset = Number(new URL(url,'https://synthetic.test').searchParams.get('offset')); offsets.push(offset);
    if (phase === 'initial') return {status:200,data:{items:[caseValue()],total:26}};
    if (phase === 'empty') return {status:200,data:{items:[],total:0}};
    if (offset === 25) return {status:200,data:{items:[],total:25}};
    if (phase === 'failure') return {status:503,data:{detail:'Corrective read failed'}};
    return {status:200,data:{items:[caseValue()],total:25}};
  });
  await ui.login(); await ui.fire('next');
  phase = 'failure'; await ui.fire('refresh');
  assert.equal(ui.el('page').textContent, 'Page 2');
  assert.equal(ui.el('case-list').children[0].className, 'case-row');
  phase = 'recovered'; await ui.fire('refresh');
  assert.deepEqual(offsets.slice(-2), [25,0]);
  assert.equal(ui.el('page').textContent, 'Page 1');
  phase = 'initial'; await ui.fire('next');
  phase = 'empty'; await ui.fire('refresh');
  assert.equal(ui.el('page').textContent, 'Page 1');
  assert.equal(ui.el('previous').disabled, true);
  assert.equal(ui.el('next').disabled, true);
});

test('failed pagination retries the same page and keeps committed rows and controls', async () => {
  const offsets=[]; let fail=true;
  const ui=setup(async url => {
    if (!url.startsWith('/api/cases?')) return standard(url);
    const offset=Number(new URL(url,'https://synthetic.test').searchParams.get('offset'));
    offsets.push(offset);
    if (offset===25 && fail) { fail=false; return {status:503,data:{detail:'Temporarily unavailable'}}; }
    return {status:200,data:{items:[{...caseValue(),title:'Row '+offset}],total:75}};
  });
  await ui.login(); await ui.fire('next');
  assert.equal(ui.el('page').textContent,'Page 1');
  assert.equal(ui.el('case-list').children[0].children[1].children[0].textContent,'Row 0');
  assert.equal(ui.el('previous').disabled,true);
  await ui.fire('next');
  assert.deepEqual(offsets,[0,25,25]);
  assert.equal(ui.el('page').textContent,'Page 2');
  assert.equal(ui.el('notice').textContent,'');
});

test('only the newest page request can commit its offset', async () => {
  let release;
  const ui=setup(async url=>url.startsWith('/api/cases?') && url.includes('offset=25')
    ? await new Promise(resolve=>{release=resolve;}) : standard(url));
  await ui.login(); await ui.fire('next');
  await ui.fire('filters','submit');
  release({status:200,data:{items:[{...caseValue(),title:'Old page'}],total:75}}); await tick();
  assert.equal(ui.el('page').textContent,'Page 1');
  assert.equal(ui.el('previous').disabled,true);
});

test('a detail read started before a save cannot replace the saved revision', async () => {
  let releaseSave, releaseRead, delayRead = false;
  const ui = setup(async (url, options) => options.method === 'PATCH'
    ? await new Promise(resolve => { releaseSave = resolve; })
    : url.split('?')[0].endsWith('/case-1') && delayRead
      ? await new Promise(resolve => { releaseRead = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'in_progress'; ui.el('note').value = 'Saved note';
  await ui.fire('review-form', 'submit');
  delayRead = true; await ui.fire('reload-case');
  releaseSave({status:200, data:{...caseValue(),version:2,status:'in_progress'}}); await tick();
  ui.el('note').value = 'New draft after save';
  releaseRead({status:200, data:caseValue()}); await tick();
  assert.equal(ui.el('review-status').value, 'in_progress');
  assert.equal(ui.el('note').value, 'New draft after save');
  assert.match(ui.el('case-meta').textContent, /2/);
});

test('partial queues identify unavailable sources and carry record kind to detail and review', async () => {
  const feedback = {...caseValue(),kind:'feedback'};
  let partial = true;
  const ui = setup(async (url, options) => url.startsWith('/api/cases?')
    ? {status:200,data:{items:[feedback],total:1,partial,sources:{case:partial?'unavailable':'available',feedback:'available'}}}
    : options.method === 'PATCH' || url.split('?')[0].endsWith('/case-1')
      ? {status:200,data:feedback} : standard(url));
  await ui.login();
  assert.match(ui.el('queue-warning').textContent, /case.*unavailable/i);
  assert.match(ui.el('count').textContent, /available sources/i);
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert(ui.calls.some(c=>c.url==='/api/cases/case-1?kind=feedback'));
  await ui.fire('review-form','submit');
  assert(ui.calls.some(c=>c.options.method==='PATCH' && c.url==='/api/cases/case-1?kind=feedback'));
  partial=false; await ui.fire('refresh');
  assert.equal(ui.el('queue-warning').textContent,'');
});

test('cached Jev lookup uses GET while disabled; explicit save retains history and current review draft', async () => {
  const receipt = 'a'.repeat(64);
  const opinion = {receipt_id:receipt,model:'jev-1.13.0',requested_at:'2026-09-22T00:00:00Z',
    probabilities:{phishing_intent:0.75},affects_risk:false};
  const saved = {...caseValue(),version:2,auxiliary_save:{outcome:'saved',base_version:1,receipt_id:receipt},events:[...caseValue().events,{actor:'alice',action:'auxiliary_saved',
    happened_at:'2026-09-22T00:00:01Z',changes:{auxiliary_opinion:{from:null,to:opinion}},note:''}]};
  const ui = setup(async (url, options) => url.endsWith('/auxiliary/save') ? {status:200,data:saved}
    : url.endsWith('/auxiliary') ? {status:200,data:{...opinion,status:'available',case_id:'case-1',case_version:1,reused:true}}
    : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('jev-read').disabled,false);
  assert.equal(ui.el('jev-run').disabled,true);
  ui.el('note').value='Unsaved human review'; await ui.fire('jev-read');
  assert.equal(ui.calls.find(c=>c.url.endsWith('/auxiliary')).options.method, 'GET');
  assert.equal(ui.el('jev-save').hidden,false);
  ui.window.confirm=()=>false; await ui.fire('jev-save');
  assert(!ui.calls.some(c=>c.url.endsWith('/auxiliary/save')));
  ui.window.confirm=()=>true; await ui.fire('jev-save');
  const sent=JSON.parse(ui.calls.find(c=>c.url.endsWith('/auxiliary/save')).options.body);
  assert.deepEqual(sent,{expected_version:1,receipt_id:receipt,confirm_save:true});
  assert.equal(ui.el('note').value,'Unsaved human review');
  assert.equal(ui.el('draft-rebase').hidden,true);
  assert.match(ui.el('case-meta').textContent,/Revision 2/);
  const text = element => element.textContent + element.children.map(text).join(' ');
  assert.match(text(ui.el('history')), /75\.0%/);
  assert.match(text(ui.el('history')), /jev-1\.13\.0/);
  assert.doesNotMatch(text(ui.el('history')), /\[object Object\]/);
});

test('repeated opinion save keeps a conflict when another review advanced the case', async () => {
const opinion={receipt_id:'a'.repeat(64),model:'jev-1.13.0',requested_at:'2026-09-22T00:00:00Z',probabilities:{phishing_intent:.75},affects_risk:false};
const original={...caseValue(),version:2,status:'in_progress',events:[...caseValue().events,{actor:'alice',action:'auxiliary_saved',happened_at:'2026-09-22T00:00:01Z',changes:{auxiliary_opinion:{from:null,to:opinion}},note:''}]};
const changed={...original,version:3,auxiliary_save:{outcome:'already_saved',base_version:2,receipt_id:opinion.receipt_id},verdict:'phishing',events:[...original.events,{actor:'alice',action:'reviewed',happened_at:'2026-09-22T00:00:02Z',changes:{verdict:{from:null,to:'phishing'}},note:'Updated in another tab'}]};
const ui=setup(async url=>url.endsWith('/me') ? {status:200,data:{actor:'alice'}}
 :url.startsWith('/api/cases?') ? {status:200,data:{items:[original],total:1}}
 :url.endsWith('/auxiliary/save') ? {status:200,data:changed}
 :url.endsWith('/auxiliary') ? {status:200,data:{...opinion,status:'available',case_id:'case-1',case_version:2,reused:true}}
 : {status:200,data:original});
await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
ui.el('verdict').value='legitimate'; ui.el('note').value='Unsaved competing verdict'; await ui.fire('review-form','input');
await ui.fire('jev-read'); await ui.fire('jev-save');
assert.equal(ui.el('draft-rebase').hidden,false);
assert.equal(ui.el('save-review').disabled,true);
assert.equal(ui.el('verdict').value,'legitimate');
assert.match(ui.el('notice').textContent,/already saved/i);
});

test('late cached lookup is cleared at signout and never posts to the model route', async () => {
  let release;
  const ui=setup(async url=>url.endsWith('/auxiliary') ? await new Promise(resolve=>{release=resolve;}) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  await ui.fire('jev-read'); await ui.fire('logout');
  release({status:200,data:{status:'available',receipt_id:'b'.repeat(64),case_id:'case-1',case_version:1}}); await tick();
  assert.equal(ui.el('jev-save').hidden,true);
  assert.equal(ui.el('jev-results').children.length,0);
  assert(!ui.calls.some(c=>c.url.endsWith('/auxiliary')&&c.options.method==='POST'));
});

test('saving one opinion cannot release a different case lookup in flight', async () => {
  let releaseSave, releaseRead;
  const second={...caseValue(),id:'case-2'};
  const ui=setup(async (url, options) => {
    if(url.endsWith('/auxiliary/save')) return await new Promise(resolve=>{releaseSave=resolve;});
    if(url.endsWith('/case-1/auxiliary')) return {status:200,data:{status:'available',receipt_id:'a'.repeat(64),case_id:'case-1',case_version:1}};
    if(url.endsWith('/case-2/auxiliary')) return await new Promise(resolve=>{releaseRead=resolve;});
    if(url.startsWith('/api/cases?')) return {status:200,data:{items:[caseValue(),second],total:2}};
    if(url.startsWith('/api/cases/case-2?')) return {status:200,data:second};
    return standard(url);
  });
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  await ui.fire('jev-read'); await ui.fire('jev-save');
  ui.el('case-list').children[1].listeners.click(); await tick();
  await ui.fire('jev-read');
  releaseSave({status:200,data:{...caseValue(),version:2}}); await tick();
  assert.equal(ui.el('jev-read').disabled,true);
  await ui.fire('jev-read');
  assert.equal(ui.calls.filter(c=>c.url.endsWith('/case-2/auxiliary')).length,1);
  releaseRead({status:200,data:{status:'skipped',reason:'no_cached_opinion',case_id:'case-2',case_version:1}}); await tick();
  assert.equal(ui.el('jev-read').disabled,false);
});

test('capacity shows both unfiltered queues, warns near full and recovers after an unavailable refresh', async () => {
  let capacity = {cases:{status:'available',used:80,limit:100},feedback:{status:'available',used:100,limit:100}};
  const ui = setup(async url => url.endsWith('/capacity') ? {status:200,data:capacity} : standard(url));
  await ui.login();
  assert.match(ui.el('case-capacity').textContent, /80 \/ 100/);
  assert.match(ui.el('feedback-capacity').textContent, /100 \/ 100/);
  assert.match(ui.el('capacity-warning').textContent, /full/i);
  ui.el('filter-status').value = 'closed'; await ui.fire('filters','submit');
  assert.match(ui.el('case-capacity').textContent, /80 \/ 100/);
  capacity = {cases:{status:'unavailable'},feedback:{status:'available',used:5,limit:null}};
  await ui.fire('refresh');
  assert.match(ui.el('case-capacity').textContent, /unavailable/i);
  assert.doesNotMatch(ui.el('case-capacity').textContent, /80|0 \/ 100/);
  assert.match(ui.el('feedback-capacity').textContent, /5/);
  assert.doesNotMatch(ui.el('feedback-capacity').textContent, /100|unlimited/i);
  assert.equal(ui.el('case-list').children.length, 1);
  capacity = {cases:{status:'available',used:20,limit:100},feedback:{status:'available',used:5,limit:100}};
  await ui.fire('refresh');
  assert.match(ui.el('case-capacity').textContent, /20 \/ 100/);
  assert.equal(ui.el('capacity-warning').textContent, '');
});

test('late capacity responses cannot restore information after signout', async () => {
  let release;
  const ui = setup(async url => url.endsWith('/capacity') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); await ui.fire('logout');
  release?.({status:200,data:{cases:{status:'available',used:80,limit:100}}}); await tick();
  assert.equal(ui.el('case-capacity').textContent, '');
  assert.equal(ui.el('workspace').hidden, true);
});

test('review drafts survive switching and reload without being silently rebased', async () => {
  let revision = 1;
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? {status: 200, data: {...caseValue(), version: revision + 1, status: 'in_progress'}}
    : url.split('?')[0].endsWith('/case-1') ? {status: 200, data: {...caseValue(), version: revision}}
    : url.split('?')[0].endsWith('/case-2') ? {status: 200, data: {...caseValue(), id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200, data:{items:[caseValue(), {...caseValue(), id:'case-2'}],total:2}}
    : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Keep this review'; ui.el('verdict').value = 'uncertain';
  ui.el('case-list').children[1].listeners.click(); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value, 'Keep this review');
  assert.equal(ui.el('verdict').value, 'uncertain');
  revision = 2; await ui.fire('reload-case');
  assert.equal(ui.el('note').value, 'Keep this review');
  await ui.fire('review-form', 'submit');
  assert.equal(ui.calls.filter(c => c.options.method === 'PATCH').length, 0);
  assert.equal(ui.el('draft-rebase').hidden, false);
  await ui.fire('draft-rebase'); await ui.fire('review-form', 'submit');
  const sent = JSON.parse(ui.calls.find(c => c.options.method === 'PATCH').options.body);
  assert.equal(sent.expected_version, 2); assert.equal(sent.note, 'Keep this review');
  assert.equal(ui.el('note').value, '');
});

test('drafts warn before leaving, support discard, and are cleared at signout', async () => {
  const ui = setup(standard); await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Private draft';
  let prevented = false;
  ui.windowEvents.beforeunload?.({preventDefault(){prevented=true;}});
  assert.equal(prevented, true);
  ui.window.confirm = () => false; await ui.fire('logout');
  assert.equal(ui.el('workspace').hidden, false); assert.equal(ui.el('note').value, 'Private draft');
  await ui.fire('draft-discard'); assert.equal(ui.el('note').value, '');
  prevented = false; ui.windowEvents.beforeunload({preventDefault(){prevented=true;}});
  assert.equal(prevented, false);
  ui.el('note').value = 'Another private draft'; ui.window.confirm = () => true;
  await ui.fire('logout'); await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value, '');
});

test('a review saved after switching cases does not reappear as an unsaved note', async () => {
  let release, saved = caseValue();
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; })
    : url.split('?')[0].endsWith('/case-1') ? {status:200,data:saved}
    : url.split('?')[0].endsWith('/case-2') ? {status:200,data:{...caseValue(),id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[saved,{...caseValue(),id:'case-2'}],total:2}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Submitted note'; await ui.fire('review-form','submit');
  ui.el('note').value = 'Later unsaved note';
  ui.el('case-list').children[1].listeners.click(); await tick();
  saved = {...caseValue(),version:2}; release({status:200,data:saved}); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value, 'Later unsaved note');
  assert.equal(ui.el('draft-rebase').hidden, true);
});

test('saving a review preserves later edits and the next save uses the new revision', async () => {
  let release;
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'in_progress'; ui.el('note').value = 'First note';
  await ui.fire('review-form', 'submit');
  ui.el('note').value = 'New note typed while saving';
  ui.el('verdict').value = 'uncertain';
  release({status: 200, data: {...caseValue(), version: 2, status: 'in_progress'}}); await tick();
  assert.equal(ui.el('note').value, 'New note typed while saving');
  assert.equal(ui.el('verdict').value, 'uncertain');
  assert.match(ui.el('notice').textContent, /unsaved/i);
  await ui.fire('review-form', 'submit');
  const sent = ui.calls.filter(c => c.options.method === 'PATCH').map(c => JSON.parse(c.options.body));
  assert.equal(sent[1].expected_version, 2);
  assert.equal(sent[1].note, 'New note typed while saving');
  release({status: 200, data: {...caseValue(), version: 3, status: 'in_progress', verdict: 'uncertain'}}); await tick();
  assert.equal(ui.el('note').value, '');
  assert.equal(ui.el('notice').textContent, 'Review saved.');
});

test('reverting to the previous status during a pending save remains a newer edit after switching away', async () => {
  let release, saved = caseValue();
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; })
    : url.split('?')[0].endsWith('/case-1') ? {status:200,data:saved}
    : url.split('?')[0].endsWith('/case-2') ? {status:200,data:{...caseValue(),id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[saved,{...caseValue(),id:'case-2'}],total:2}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'in_progress'; await ui.fire('review-form','submit');
  ui.el('review-status').value = 'pending';
  ui.el('case-list').children[1].listeners.click(); await tick();
  saved = {...caseValue(),version:2,status:'in_progress'};
  release({status:200,data:saved}); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('review-status').value, 'pending');
  await ui.fire('review-form','submit');
  assert.equal(ui.calls.filter(c=>c.options.method==='PATCH').length,1);
});

test('a completed save stays clean when switching during a slow capacity refresh', async () => {
  let holdCapacity = false, release, saved = caseValue();
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? {status:200,data:(saved={...caseValue(),version:2})}
    : url.endsWith('/capacity') && holdCapacity ? await new Promise(resolve=>{release=resolve;})
    : url.split('?')[0].endsWith('/case-1') ? {status:200,data:saved}
    : url.split('?')[0].endsWith('/case-2') ? {status:200,data:{...caseValue(),id:'case-2'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[saved,{...caseValue(),id:'case-2'}],total:2}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value='Saved note'; holdCapacity=true;
  await ui.fire('review-form','submit');
  ui.el('case-list').children[1].listeners.click(); await tick();
  holdCapacity=false; release({status:200,data:{}}); await tick();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('note').value,''); assert.equal(ui.el('draft-status').textContent,'');
});

test('authenticated analysts can open and close the create-case drawer without losing the draft', async () => {
  const ui = setup(standard); await ui.login();
  assert.equal(typeof ui.el('open-compose').listeners.click, 'function');
  assert.equal(typeof ui.el('close-compose').listeners.click, 'function');
  ui.el('subject').value = 'Keep this draft';
  await ui.fire('open-compose');
  assert.equal(ui.el('compose-dialog').open, true);
  await ui.fire('close-compose');
  assert.equal(ui.el('compose-dialog').open, false);
  assert.equal(ui.el('subject').value, 'Keep this draft');
});

test('queue rows expose the dashboard columns while keeping untrusted titles as text', async () => {
  const ui = setup(standard); await ui.login();
  const row = ui.el('case-list').children[0];
  assert.deepEqual(row.children.map(child => child.className),
    ['case-cell risk-cell', 'case-cell title-cell', 'case-cell status-cell',
      'case-cell verdict-cell', 'case-cell date-cell']);
  assert.equal(row.children[1].children[0].textContent, '<img src=x onerror=alert(1)>');
});

test('signout closes and clears the create-case drawer', async () => {
  const ui = setup(standard); await ui.login();
  ui.el('subject').value = 'Private draft';
  await ui.fire('open-compose');
  await ui.fire('logout');
  assert.equal(ui.el('compose-dialog').open, false);
  assert.equal(ui.el('subject').value, '');
});

test('successful creation closes the drawer and keeps the saved case selected', async () => {
  const ui = setup(standard); await ui.login();
  await ui.fire('open-compose');
  ui.el('subject').value = 'Synthetic case';
  await ui.fire('create-form', 'submit');
  assert.equal(ui.el('compose-dialog').open, false);
  assert.equal(ui.el('subject').value, '');
  assert.equal(ui.el('case-title').textContent, '<img src=x onerror=alert(1)>');
  assert.equal(ui.el('case-list').children[0].attrs['aria-pressed'], 'true');
});

test('Jev failure shows actionable safe guidance without retrying or changing risk', async () => {
  for (const [reason, message] of [['provider_authentication', /API key/], ['provider_timeout', /timed out/],
                                  ['provider_request_invalid', /request format/], ['private-secret', /unavailable or skipped/]]) {
    const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
      url.endsWith('/auxiliary') ? {status: 200, data: {case_id: 'case-1', case_version: 1, status: 'unavailable', reason}} : standard(url));
    await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
    const original = ui.el('analysis-summary').textContent;
    ui.el('jev-consent').checked = true; await ui.fire('jev-run');
    assert.match(ui.el('jev-status').textContent, message);
    assert(!ui.el('jev-status').textContent.includes('private-secret'));
    assert.equal(ui.el('analysis-summary').textContent, original);
    assert.equal(ui.calls.filter(call => call.url.endsWith('/auxiliary')).length, 1);
  }
});

test('protected Preview login preserves the gateway session and still requires the analyst token', async () => {
  for (const accepted of [true, false]) {
    const ui = setup(async (url, options) => {
      // The deployment gateway redirects cookieless requests to external SSO,
      // which the application's same-origin CSP correctly blocks.
      if (!['same-origin', 'include'].includes(options.credentials)) throw new TypeError('Failed to fetch');
      if (!accepted || options.headers.Authorization !== 'Bearer synthetic-access-token-at-least-32-characters') {
        return {status: 401, data: {detail: 'A valid analyst access token is required'}};
      }
      return standard(url);
    });
    await ui.login();
    if (accepted) {
      assert.equal(ui.el('notice').textContent, '');
      assert.equal(ui.el('login-panel').hidden, true);
      assert.equal(ui.el('case-list').children.length, 1);
    } else {
      assert.equal(ui.el('workspace').hidden, true);
      assert.equal(ui.el('token').value, '');
      assert.match(ui.el('notice').textContent, /valid analyst access token/);
    }
  }
});

test('Jev is opt-in, independent of case risk, and rendered as text', async () => {
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
    url.endsWith('/auxiliary') ? {status: 200, data: {case_id: 'case-1', case_version: caseValue().version,
      status: 'available', model: '<img src=x onerror=bad()>', evidence_incomplete: true,
      probabilities: {phishing_intent: .95, insufficient_evidence: .7}}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('jev-panel').hidden, false);
  await ui.fire('jev-run');
  assert(!ui.calls.some(call => call.url.endsWith('/auxiliary')));
  assert.match(ui.el('jev-status').textContent, /permission/);
  const original = ui.el('analysis-summary').textContent;
  ui.el('jev-consent').checked = true; await ui.fire('jev-run');
  const request = ui.calls.find(call => call.url.endsWith('/auxiliary'));
  assert.deepEqual(JSON.parse(request.options.body), {allow_external_processing: true});
  assert.match(ui.el('jev-status').textContent, /<img src=x onerror=bad\(\)>/);
  assert.match(ui.el('jev-status').textContent, /evidence is incomplete/);
  assert.equal(ui.el('jev-results').children[0].children.length, 2);
  assert.equal(ui.el('analysis-summary').textContent, original);
  assert.equal(ui.el('jev-consent').checked, false);
  await ui.fire('logout');
  assert.equal(ui.el('jev-panel').hidden, true);
  assert.equal(ui.el('jev-results').children.length, 0);
});

test('late Jev results cannot reappear after switching case or signing out', async () => {
  let release;
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
    url.endsWith('/auxiliary') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('jev-consent').checked = true; await ui.fire('jev-run');
  await ui.fire('logout');
  release({status: 200, data: {status: 'available', model: 'jev', probabilities: {phishing_intent: 1}}}); await tick();
  assert.equal(ui.el('jev-results').children.length, 0);
  assert.equal(ui.el('jev-status').textContent, '');
});

test('Jev panel explains unavailable configuration and refreshes without losing notes', async () => {
  let enabled = false;
  const handler = async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice',
    jev_available: enabled, jev: {status: enabled ? 'available' : 'configuration_error', daily_limit: 20, used: 0}}} : standard(url);
  const ui = setup(handler); await ui.login();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('jev-panel').hidden, false);
  assert.equal(ui.el('jev-run').disabled, true);
  assert.match(ui.el('jev-availability').textContent, /configuration/i);
  ui.el('note').value = 'Unsaved review';
  enabled = true; await ui.fire('refresh');
  assert.equal(ui.el('jev-run').disabled, false);
  assert.equal(ui.el('note').value, 'Unsaved review');
  assert(!ui.calls.some(call => call.url.endsWith('/auxiliary')));
});

test('dropped and pasted case files use existing recognition and require explicit submission',async()=>{
  for(const kind of ['drop','paste']){
    let recognized;
    const ui=setup(standard,{cancel(){},render(){},async recognize(file){recognized=file;return {observations:[],warnings:[]};}});
    await ui.login();
    const file={name:'clipboard.png',type:'image/png',size:100};
    ui.el('case-file-dropzone').listeners[kind]({preventDefault(){},stopPropagation(){},
      [kind==='drop'?'dataTransfer':'clipboardData']:{files:[file],types:['Files']}});
    assert.equal(ui.el('body').disabled,true);assert.match(ui.el('case-file-status').textContent,/clipboard.png loaded/);
    assert(!ui.calls.some(call=>call.options.method==='POST'));
    await ui.fire('create-form','submit');
    assert.equal(recognized,file);assert(ui.calls.some(call=>call.url==='/api/cases/visual'));
    assert.equal(ui.el('case-file-status').textContent,'');
  }
});

test('token is sent only in auth header and untrusted evidence is rendered as text', async () => {
  const ui = setup(standard); await ui.login();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('source').textContent, 'Synthetic\n\n<script>bad()</script>');
  assert.equal(ui.el('case-title').textContent, '<img src=x onerror=alert(1)>');
  assert.equal(ui.el('history').children[0].children.at(-1).textContent, '<svg onload=bad()>');
  assert.equal(ui.el('token').value, '');
  assert(ui.calls.every(call => !call.url.includes('token') && call.options.headers.Authorization.startsWith('Bearer ') && call.options.cache === 'no-store'));
  assert.equal(ui.el('next').disabled, true);
});

test('signout clears saved content and late responses cannot restore it', async () => {
  let release;
  const ui = setup(async url => url.split('?')[0].endsWith('/case-1') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  await ui.fire('logout'); release({status: 200, data: caseValue()}); await tick();
  assert.equal(ui.el('source').textContent, ''); assert.equal(ui.el('workspace').hidden, true);
  assert.equal(ui.el('case-list').children.length, 0);
});

test('failed creation retries with same idempotency key and input', async () => {
  const ui = setup(async (url, opts) => opts.method === 'POST' ? {status: 503, data: {detail: 'Storage unavailable'}} : standard(url));
  await ui.login(); ui.el('subject').value = 'Synthetic';
  await ui.fire('create-form', 'submit'); await ui.fire('create-form', 'submit');
  const posts = ui.calls.filter(call => call.options.method === 'POST');
  assert.equal(posts.length, 2); assert.equal(posts[0].options.headers['Idempotency-Key'], posts[1].options.headers['Idempotency-Key']);
  assert.equal(posts[0].options.body, posts[1].options.body);
  assert.equal(ui.el('subject').value, 'Synthetic');
});

test('editing an uncertain case submission keeps the original retry and acknowledges its receipt', async () => {
  const records = new Map(); let attempt = 0;
  const ui = setup(async (url, opts) => {
    if (opts.method !== 'POST') return standard(url);
    const key = opts.headers['Idempotency-Key'];
    if (!records.has(key)) records.set(key, {...caseValue(),id:'created-' + records.size});
    return ++attempt === 1 ? {status:503,data:{detail:'Unconfirmed storage'}} : {status:201,data:records.get(key)};
  });
  await ui.login(); await ui.fire('open-compose'); ui.el('subject').value = 'Original';
  await ui.fire('create-form','submit');
  ui.el('subject').value = 'Later edit'; await ui.fire('create-form','input');
  ui.window.confirm = () => false; await ui.fire('create-form','submit');
  assert.equal(attempt,1);
  ui.window.confirm = () => true; await ui.fire('create-form','submit');
  const posts = ui.calls.filter(c => c.options.method === 'POST');
  assert.equal(records.size,1); assert.equal(posts[0].options.body,posts[1].options.body);
  assert.equal(posts[0].options.headers['Idempotency-Key'],posts[1].options.headers['Idempotency-Key']);
  assert.equal(ui.el('subject').value,'Later edit'); assert.equal(ui.el('compose-dialog').open,true);
  assert.match(ui.el('creation-status').textContent,/saved.*later edits.*not sent/i);
  await ui.fire('create-form','submit'); assert.equal(attempt,2);
  await ui.fire('new-case-draft'); await ui.fire('create-form','submit');
  assert.equal(records.size,2);
  assert.equal(JSON.parse(ui.calls.filter(c => c.options.method === 'POST')[2].options.body).subject,'Later edit');
});

test('image retry survives cancel and language changes without rescanning or forgetting an earlier timeout', async () => {
  let scans = 0, attempts = 0;
  const ui = setup(async (url, opts) => opts.method === 'POST'
    ? {status:++attempts === 1 ? 503 : attempts === 2 ? 429 : 201,data:attempts < 3 ? {detail:'Retry later'} : caseValue()}
    : standard(url), {cancel(){},render(){},async recognize(){scans++;return {observations:[],warnings:[]};}});
  await ui.login(); ui.el('eml').files = [{name:'original.png',size:100}];
  await ui.fire('create-form','submit'); await ui.fire('cancel-vision');
  ui.el('eml').files = [{name:'later.png',size:200}]; await ui.fire('eml','change');
  ui.el('case-ocr-language').value = 'chi_sim'; await ui.fire('case-ocr-language','change');
  await ui.fire('create-form','submit'); await ui.fire('create-form','submit');
  const posts = ui.calls.filter(c => c.options.method === 'POST');
  assert.equal(scans,1); assert.equal(new Set(posts.map(c => c.options.headers['Idempotency-Key'])).size,1);
  assert.equal(new Set(posts.map(c => c.options.body)).size,1);
  assert.equal(ui.el('eml').files[0].name,'later.png');
  assert.match(ui.el('creation-status').textContent,/saved/i);
});

test('a definitive initial rejection allows correction while a late success preserves edited drafts', async () => {
  let attempts = 0, release;
  const ui = setup(async (url, opts) => {
    if (opts.method !== 'POST') return standard(url);
    if (++attempts === 1) return {status:422,data:{detail:'Invalid message'}};
    return await new Promise(resolve => {release = resolve;});
  });
  await ui.login(); await ui.fire('open-compose'); ui.el('body').value = 'Original';
  await ui.fire('create-form','submit'); ui.el('body').value = 'Corrected'; await ui.fire('create-form','input');
  await ui.fire('create-form','submit'); await ui.fire('create-form','submit'); assert.equal(attempts,2);
  ui.el('body').value = 'Later draft'; await ui.fire('create-form','input');
  release({status:201,data:caseValue()}); await tick(); await tick();
  const posts = ui.calls.filter(c => c.options.method === 'POST');
  assert.notEqual(posts[0].options.headers['Idempotency-Key'],posts[1].options.headers['Idempotency-Key']);
  assert.equal(ui.el('body').value,'Later draft'); assert.equal(ui.el('create-case').disabled,true);
  assert.match(ui.el('creation-status').textContent,/later edits.*not sent/i);
});

test('late creation replies cannot release a new session submission or restore a receipt', async () => {
  const releases = [];
  const ui = setup(async (url, opts) => opts.method === 'POST'
    ? await new Promise(resolve => releases.push(resolve)) : standard(url));
  await ui.login(); ui.el('subject').value = 'Old session'; await ui.fire('create-form','submit');
  await ui.fire('logout'); await ui.login(); ui.el('subject').value = 'New session'; await ui.fire('create-form','submit');
  releases[0]({status:201,data:caseValue()}); await tick();
  await ui.fire('create-form','submit'); assert.equal(releases.length,2);
  assert.equal(ui.el('create-case').disabled,true);
  assert.doesNotMatch(ui.el('creation-status').textContent,/case-1 saved/);
  releases[1]({status:201,data:caseValue()}); await tick();
});

test('a stale review preserves the analyst note and requests reload', async () => {
  const ui = setup(async (url, opts) => opts.method === 'PATCH' ? {status: 409, data: {detail: 'Conflict'}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Do not lose this note'; ui.el('review-status').value = 'in_progress';
  await ui.fire('review-form', 'submit');
  assert.equal(ui.el('note').value, 'Do not lose this note');
  assert.match(ui.el('notice').textContent, /Another analyst/);
  const patch = JSON.parse(ui.calls.find(call => call.options.method === 'PATCH').options.body);
  assert.equal(patch.expected_version, 1); assert.equal(patch.actor, undefined);
});

test('feedback review sends structured reason and evidence basis without changing case reviews', async () => {
  const feedback = {...caseValue(), id: 'feedback-1', kind: 'feedback', provenance: {record_kind: 'user_feedback', source_consent: true},
    events: [...caseValue().events, {actor: 'alice', action: 'reviewed', happened_at: '2026-09-21T00:00:00Z',
      changes: {feedback_reason: {from: null, to: 'false_alert'}, evidence_basis: {from: null, to: 'retained_message'}}, note: ''}]};
  const ui = setup(async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} :
    url.startsWith('/api/cases?') ? {items: [feedback], total: 1} : feedback}));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('feedback-review-fields').hidden, false);
  assert.equal(ui.el('feedback-reason').value, 'false_alert');
  assert.equal(ui.el('evidence-basis').value, 'retained_message');
  await ui.fire('review-form', 'submit');
  const patch = JSON.parse(ui.calls.find(call => call.options.method === 'PATCH').options.body);
  assert.equal(patch.feedback_reason, 'false_alert');
  assert.equal(patch.evidence_basis, 'retained_message');
});

test('selected case stays visibly selected after switching cases and refreshing the queue', async () => {
  const first = caseValue(), second = {...caseValue(), id: 'case-2', title: 'Second message', risk: 'safe'};
  const ui = setup(async url => ({status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.startsWith('/api/cases?') ? {items: [first, second], total: 2} : url.split('?')[0].endsWith('/case-2') ? second : first}));
  await ui.login();
  ui.el('case-list').children[0].listeners.click(); await tick();
  assert.equal(ui.el('case-list').children[0].attrs['aria-pressed'], 'true');
  ui.el('case-list').children[1].listeners.click(); await tick();
  assert.equal(ui.el('case-title').textContent, 'Second message');
  assert.equal(ui.el('case-list').children[0].attrs['aria-pressed'], 'false');
  assert.equal(ui.el('case-list').children[1].attrs['aria-pressed'], 'true');
  await ui.fire('refresh');
  assert.equal(ui.el('case-list').children[1].attrs['aria-pressed'], 'true');
});


test('image case retry reuses extracted evidence and its idempotency key', async () => {
  let scans=0;
  const vision={cancel(){},render(){},async recognize(){scans++;return {observations:[{ocr_text:'Synthetic OCR'}],warnings:[]};}};
  const ui=setup(async(url,opts)=>opts.method==='POST'?{status:503,data:{detail:'Unavailable'}}:standard(url),vision);
  await ui.login(); ui.el('eml').files=[{name:'synthetic.png',size:100}];
  await ui.fire('create-form','submit'); await ui.fire('create-form','submit');
  const posts=ui.calls.filter(c=>c.options.method==='POST');
  assert.equal(scans,1);assert.equal(posts.length,2);assert.equal(posts[0].url,'/api/cases/visual');
  assert.equal(posts[0].options.body,posts[1].options.body);
  assert.equal(posts[0].options.headers['Idempotency-Key'],posts[1].options.headers['Idempotency-Key']);
});
test('signout during OCR prevents late extraction from posting a case', async()=>{
  let release,cancelled=false;
  const ui=setup(standard,{render(){},cancel(){cancelled=true;},recognize:()=>new Promise(resolve=>{release=resolve;})});
  await ui.login();ui.el('eml').files=[{name:'synthetic.png',size:100}];
  await ui.fire('create-form','submit');await ui.fire('logout');
  release({observations:[],warnings:[]});await tick();
  assert.equal(cancelled,true);assert.equal(ui.el('workspace').hidden,true);
  assert.equal(ui.calls.filter(c=>c.options.method==='POST').length,0);
});

test('case OCR forwards language and invalidates in-flight output when it changes',async()=>{
  let release, selectedLanguage;
  const ui=setup(standard,{cancel(){},render(){},async recognize(_file,_progress,language){
    selectedLanguage=language;return new Promise(resolve=>{release=resolve;});
  }});
  await ui.login();ui.el('eml').files=[{name:'test.png',size:1}];
  ui.el('case-ocr-language').value='eng+chi_sim';
  await ui.fire('create-form','submit');assert.equal(selectedLanguage,'eng+chi_sim');
  ui.el('case-ocr-language').value='eng';await ui.fire('case-ocr-language','change');
  release({observations:[],warnings:[]});await tick();
  assert(!ui.calls.some(call=>call.options.method==='POST'));
});

test('quota exhausted still retrieves a prior receipt and never changes risk', async () => {
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true,
    jev: {status: 'quota_exhausted', daily_limit: 20, used: 20, reset_at: 1790121600}}} :
    url.endsWith('/auxiliary') ? {status: 200, data: {case_id: 'case-1', case_version: 1,
      status: 'available', model: 'jev', reused: true, probabilities: {phishing_intent: .2}}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.match(ui.el('jev-availability').textContent, /daily allowance is exhausted/);
  assert.equal(ui.el('jev-run').disabled, false);
  const risk = ui.el('analysis-summary').textContent;
  ui.el('jev-consent').checked = true; await ui.fire('jev-run');
  assert.match(ui.el('jev-status').textContent, /no new provider call/);
  assert.equal(ui.el('analysis-summary').textContent, risk);
});

test('refresh during Jev request keeps it busy and cannot send duplicate calls', async () => {
  let release;
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true}} :
    url.endsWith('/auxiliary') ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('jev-consent').checked = true; await ui.fire('jev-run'); await ui.fire('refresh');
  assert.equal(ui.el('jev-run').disabled, true);
  await ui.fire('jev-run');
  assert.equal(ui.calls.filter(c => c.url.endsWith('/auxiliary')).length, 1);
  release({status: 200, data: {case_id: 'case-1', case_version: 1, status: 'skipped', reason: 'request_pending', receipt_expires_at: 1790121600}});
  await tick();
  assert.match(ui.el('jev-status').textContent, /outcome is unknown/);
  assert.match(ui.el('jev-status').textContent, /will not start another provider call/);
  assert.equal(ui.el('jev-run').disabled, false);
});

test('failed status refresh disables Jev without clearing unsaved notes', async () => {
  let failed = false;
  const ui = setup(async url => url.endsWith('/me') ? {status: failed ? 503 : 200,
    data: {actor: 'alice', jev_available: true, detail: 'Storage unavailable'}} : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Keep this note'; failed = true; await ui.fire('refresh');
  assert.equal(ui.el('note').value, 'Keep this note');
  assert.equal(ui.el('jev-run').disabled, true);
  assert.match(ui.el('jev-availability').textContent, /controls are unavailable/);
});

test('review edits made during a failed save survive without a success notice', async () => {
  let release;
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; }) : standard(url));
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('note').value = 'Submitted';
  await ui.fire('review-form', 'submit'); ui.el('note').value = 'Unsaved after request';
  release({status: 503, data: {detail: 'Storage unavailable'}}); await tick();
  assert.equal(ui.el('note').value, 'Unsaved after request');
  assert.equal(ui.el('notice').textContent, 'Storage unavailable');
});

test('new feedback choices survive saving and unavailable status requires a new choice', async () => {
  let release;
  const feedback = {...caseValue(), kind: 'feedback', status: 'in_progress'};
  const ui = setup(async (url, options) => options?.method === 'PATCH'
    ? await new Promise(resolve => { release = resolve; })
    : {status: 200, data: url.endsWith('/me') ? {actor: 'alice'} : url.startsWith('/api/cases?') ? {items: [feedback], total: 1} : feedback});
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  ui.el('review-status').value = 'closed'; ui.el('note').value = 'Closing';
  await ui.fire('review-form', 'submit');
  ui.el('feedback-reason').value = 'missed_threat';
  ui.el('evidence-basis').value = 'external_verification';
  ui.el('review-status').value = 'pending'; // A no-longer-valid draft cannot silently change the saved state.
  release({status: 200, data: {...feedback, status: 'closed', version: 2}}); await tick();
  assert.equal(ui.el('note').value, ''); // The submitted note was saved, not a new draft.
  assert.equal(ui.el('feedback-reason').value, 'missed_threat');
  assert.equal(ui.el('evidence-basis').value, 'external_verification');
  assert.equal(ui.el('review-status').value, 'pending');
  await ui.fire('review-form', 'submit');
  assert.match(ui.el('notice').textContent, /Choose an available status/);
  assert.equal(ui.calls.filter(c => c.options.method === 'PATCH').length, 1);
});

test('history capacity protects reserved slots while allowing a final close', async () => {
  const full = {...caseValue(), status:'in_progress', version:199,
    history_capacity:{used:199,limit:200,recovery_limit:202,remaining:0,review_statuses:['closed'],can_save_opinion:false}};
  const ui=setup(async url=>url.endsWith('/auxiliary')
    ? {status:200,data:{status:'available',case_id:full.id,case_version:199,receipt_id:'a'.repeat(64)}}
    : url.endsWith('/me') ? {status:200,data:{actor:'alice'}}
    : url.startsWith('/api/cases?') ? {status:200,data:{items:[full],total:1}}
    : {status:200,data:full});
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.match(ui.el('history-capacity').textContent,/199/);
  assert.match(ui.el('history-capacity').textContent,/reserved/i);
  assert.equal(ui.el('save-review').disabled,true);
  await ui.fire('jev-read'); assert.equal(ui.el('jev-save').disabled,true);
  ui.el('review-status').value='closed'; await ui.fire('review-form','change');
  assert.equal(ui.el('save-review').disabled,false);
});

test('feedback overview uses all retained reports and clears counts when storage fails', async () => {
  let overview={status:'available',total:7,pending:2,in_progress:1,closed:4,false_alerts:1,missed_threats:2};
  const ui=setup(async url=>url.endsWith('/feedback-overview') ? {status:200,data:overview} : standard(url));
  await ui.login();
  assert.equal(ui.el('feedback-open-count').textContent,'3');
  assert.equal(ui.el('feedback-closed-count').textContent,'4');
  assert.equal(ui.el('feedback-false-alerts-count').textContent,'1');
  assert.equal(ui.el('feedback-missed-threats-count').textContent,'2');
  ui.el('filter-kind').value='feedback'; ui.el('filter-verdict').value='legitimate';
  ui.el('filter-feedback-reason').value='false_alert'; await ui.fire('filters','submit');
  const url=ui.calls.filter(c=>c.url.startsWith('/api/cases?')).at(-1).url;
  assert.match(url,/verdict=legitimate/); assert.match(url,/feedback_reason=false_alert/);
  assert.match(ui.el('feedback-overview-status').textContent,/not.*model/i);
  assert.equal(ui.el('feedback-open-count').textContent,'3');
  overview={status:'unavailable'}; await ui.fire('refresh');
  assert.equal(ui.el('feedback-open-count').textContent,'—');
  assert.match(ui.el('feedback-overview-status').textContent,/unavailable/i);
  ui.el('filter-kind').value='case'; await ui.fire('filter-kind','change');
  assert.equal(ui.el('filter-feedback-reason').value,'');
  assert.equal(ui.el('filter-feedback-reason').disabled,true);
  await ui.fire('logout'); assert.equal(ui.el('feedback-overview-status').textContent,'');
});

test('byte-full legacy cases explain storage limits and offer only forward review', async () => {
  const full={...caseValue(),status:'in_progress',version:34,
    history_capacity:{used:34,limit:200,remaining:165,bytes_used:750000,byte_limit:750000,
      bytes_remaining:0,byte_recovery_limit:850000,review_statuses:['closed'],can_save_opinion:false}};
  const ui=setup(async url=>url.endsWith('/me') ? {status:200,data:{actor:'alice'}}
    :url.startsWith('/api/cases?') ? {status:200,data:{items:[full],total:1}} : {status:200,data:full});
  await ui.login(); ui.el('case-list').children[0].listeners.click(); await tick();
  assert.match(ui.el('history-capacity').textContent,/165 ordinary history slots/);
  assert.match(ui.el('history-capacity').textContent,/750\.0 \/ 750 KB/);
  assert.match(ui.el('history-capacity').textContent,/0\.0 KB available/);
  assert.match(ui.el('history-capacity').textContent,/850 KB/);
  assert.equal(ui.el('save-review').disabled,true);
  ui.el('review-status').value='closed'; await ui.fire('review-form','change');
  assert.equal(ui.el('save-review').disabled,false);
});

test('an old feedback overview cannot overwrite a newer refresh or a signed-out screen', async () => {
  let release;
  const ui=setup(async url=>url.endsWith('/feedback-overview') ? await new Promise(resolve=>{release=resolve;}) : standard(url));
  await ui.login(); const old=release; await ui.fire('refresh');
  release({status:200,data:{status:'available',total:1,pending:0,in_progress:0,closed:1,false_alerts:1,missed_threats:0}}); await tick();
  old({status:200,data:{status:'available',total:2,pending:2,in_progress:0,closed:0,false_alerts:0,missed_threats:0}}); await tick();
  assert.equal(ui.el('feedback-open-count').textContent,'0');
  await ui.fire('refresh'); await ui.fire('logout');
  release({status:200,data:{status:'available',total:9,pending:9,in_progress:0,closed:0,false_alerts:0,missed_threats:0}}); await tick();
  assert.equal(ui.el('feedback-overview-status').textContent,'');
  assert.equal(ui.el('feedback-open-count').textContent,'—');
});

test('the signed-out view has its own h1 and headings do not skip a level', () => {
  const html = readFileSync(new URL('./cases.html', import.meta.url), 'utf8');
  const login = html.slice(html.indexOf('<section id="login-panel"'), html.indexOf('</section>', html.indexOf('<section id="login-panel"')));
  const levels = [...login.matchAll(/<h([1-6])\b/g)].map(match => Number(match[1]));
  assert.equal(levels[0], 1, 'first heading in the login view is h1');
  assert.equal(levels.filter(level => level === 1).length, 1);
  // The intro column is display:none at <=680px, so the h1 must live in the always-visible form panel.
  const intro = login.slice(login.indexOf('class="login-intro"'), login.indexOf('class="login-form-panel"'));
  assert.doesNotMatch(intro, /<h[1-6]\b/);
  assert.match(login.slice(login.indexOf('class="login-form-panel"')), /<h1 data-i18n="cases\.login\.title">Analyst sign in<\/h1>/);
  levels.reduce((previous, level) => { assert.ok(level <= previous + 1, `h${previous} -> h${level}`); return level; }, 0);
});

test('timestamps name their time zone and time elements carry ISO UTC values', async () => {
  const zoneOf = ms => new Intl.DateTimeFormat(undefined, {timeZoneName: 'short'})
    .formatToParts(new Date(ms)).find(part => part.type === 'timeZoneName').value;
  const ui = setup(async url => url.endsWith('/me') ? {status: 200, data: {actor: 'alice', jev_available: true,
    jev: {status: 'quota_exhausted', daily_limit: 20, used: 20, reset_at: 1790121600}}} :
    url.endsWith('/auxiliary') ? {status: 200, data: {case_id: 'case-1', case_version: 1, status: 'skipped',
      reason: 'request_pending', receipt_expires_at: 1790121600}} : standard(url));
  await ui.login();
  const created = ui.el('case-list').children[0].children[4];
  assert.ok(created.textContent.endsWith(zoneOf(Date.parse('2026-09-20T00:00:00Z'))), created.textContent);
  assert.equal(created.attrs.datetime, '2026-09-20T00:00:00.000Z');
  assert.match(created.title, /2026.*UTC$/);
  ui.el('case-list').children[0].listeners.click(); await tick();
  const happened = ui.el('history').children[0].children[1].children[0];
  assert.equal(happened.attrs.datetime, '2026-09-20T00:00:00.000Z');
  assert.ok(happened.textContent.endsWith(zoneOf(Date.parse('2026-09-20T00:00:00Z'))), happened.textContent);
  const zone = zoneOf(1790121600 * 1000);
  assert.ok(ui.el('jev-availability').textContent.includes(`${zone}.`), ui.el('jev-availability').textContent);
  ui.el('jev-consent').checked = true; await ui.fire('jev-run');
  assert.ok(ui.el('jev-status').textContent.includes(`${zone};`), ui.el('jev-status').textContent);
  const html = readFileSync(new URL('./cases.html', import.meta.url), 'utf8');
  assert.match(html, /<span data-i18n="cases\.filters\.from">From \(UTC\)<\/span><input id="filter-from" type="date"/);
  assert.match(html, /<span data-i18n="cases\.filters\.through">Through \(UTC\)<\/span><input id="filter-to" type="date"/);
});

test('case workspace faint text meets WCAG AA and fields avoid iOS focus zoom', () => {
  const css = readFileSync(new URL('./cases.css', import.meta.url), 'utf8');
  const luminance = hex => [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map(v => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
    .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
  const contrast = (a, b) => { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
  for (const block of [css.match(/^:root \{([^}]*)\}/m)[1], css.match(/:root\[data-theme="light"\] \{([^}]*)\}/)[1]]) {
    const token = name => block.match(new RegExp(`${name}:\\s*(#[0-9a-f]{6});`, 'i'))[1];
    for (const bg of ['--canvas', '--sidebar', '--surface', '--raised', '--soft']) {
      assert.ok(contrast(token('--faint'), token(bg)) >= 4.5, `--faint ${token('--faint')} on ${bg} ${token(bg)}`);
      assert.ok(contrast(token('--muted'), token(bg)) > contrast(token('--faint'), token(bg)));
    }
  }
  const touch = css.match(/@media \(hover: none\) and \(pointer: coarse\) \{\n([\s\S]*?)\n\}/)[1];
  assert.match(touch, /\.filter-grid input, \.filter-grid select[^{]*\{ font-size: 16px; \}/);
  assert.match(touch, /input:not\(\[type="checkbox"\], \[type="file"\]\), select, textarea/);
});

// ── Language ─────────────────────────────────────────────────────────────────
const PAGE = ['i18n.js', ...CASE_SCRIPTS];
const zhDictionary = (() => {
  const window = {};
  vm.runInNewContext(readFileSync(new URL('./i18n.js', import.meta.url), 'utf8'),
    {window, navigator: {languages: ['en-US']}, localStorage: memoryStorage(), console});
  return window.PhishGuardI18n.DICTIONARY.zh;
})();
const texts = nodes => nodes.flatMap(node => [node.textContent, ...texts(node.children || [])]).filter(Boolean);

test('English rendering is byte-for-byte the output of the pre-i18n cases.js', async () => {
  const snapshot = JSON.parse(readFileSync(new URL('../tests/fixtures/i18n/cases-en-snapshot.json', import.meta.url), 'utf8'));
  const results = JSON.parse(JSON.stringify(await runCaseScenarios(PAGE)));
  assert.deepEqual(Object.keys(results), Object.keys(snapshot));
  for (const name of Object.keys(snapshot)) assert.deepEqual(results[name], snapshot[name], name);
  // An English browser with a stored English choice renders the same.
  const stored = JSON.parse(JSON.stringify(await runCaseScenarios(PAGE, {languages: ['zh-CN'], storage: memoryStorage({'phishguard-lang': 'en'})})));
  assert.deepEqual(stored, snapshot);
});

test('Chinese queue, detail, review form and history render from codes; free text stays as sent', async () => {
  const ui = loadCases(PAGE, {handler: router(), languages: ['zh-CN']});
  assert.equal(ui.document.documentElement.lang, 'zh-CN');
  await ui.login();
  assert.equal(ui.el('count').textContent, '60 条匹配记录');
  assert.equal(ui.el('page').textContent, '第 1 页');
  assert.equal(ui.el('case-capacity').textContent, '案例：已存储 85 / 100 条 · 剩余 15 条。');
  assert.equal(ui.el('capacity-warning').textContent, '案例存储即将用尽。' + zhDictionary['cases.capacity.advice']);
  const rows = ui.el('case-list').children.map(row => texts([row]));
  assert.deepEqual(rows[0].slice(0, 5), ['严重', 'Subject 0', '案例', '待处理', '未复核']);
  assert.deepEqual(rows[2].slice(0, 5), ['中', '用户反馈 · 漏报', '用户反馈', '已关闭', '正常']);
  assert.deepEqual(rows[6].slice(0, 1), ['未确定'], 'an unknown risk is undetermined');
  assert.match(rows[0][5], /^2026年9月10日 UTC 00:05$/);
  assert.equal(ui.el('case-list').children[0].children[4].title, '2026年9月10日 UTC 00:05');
  assert.equal(ui.el('case-list').children[0].children[4].attrs.datetime, '2026-09-10T00:05:00.000Z');

  await ui.open(0);
  assert.equal(ui.el('case-title').textContent, 'Your account will be suspended', 'subjects are shown as sent');
  assert.equal(ui.el('case-meta').textContent, 'case-1 · 修订版本 4 · 创建者 alice');
  assert.deepEqual(texts(ui.el('badges').children), ['高', '处理中', '未复核']);
  assert.equal(ui.el('analysis-summary').textContent, '高风险 — 可能是钓鱼邮件。请先审阅证据再做决定。');
  const evidence = texts(ui.el('evidence').children);
  assert.deepEqual(evidence.slice(0, 6), [
    zhDictionary['server.warning.attachments_uninspected'], 'A browser warning without a code',
    '包含短链接 URL（bit.ly、tinyurl 等）— 隐藏了真实的目标域名',
    '发件人：域名包含连字符（paypa1-verify.xyz）— 主流服务商的域名通常不使用连字符',
    'A reworded server message', '潜在危险附件：<img src=x>。']);
  assert.equal(evidence.at(-2), '紧迫感与施压：钓鱼邮件会制造人为的时间压力，让人来不及仔细思考。 匹配：urgent、suspended');
  assert.match(evidence.at(-1), /^凭据窃取：A reworded description from an older release\. 匹配：verify$/, 'reworded server text is shown as sent');
  assert.match(ui.el('analysis-json').textContent, /"risk_label": "High Risk — Likely Phishing"/, 'the audit JSON is untouched');
  assert.deepEqual(ui.el('review-status').children.map(option => [option.value, option.textContent]), [['in_progress', '处理中'], ['closed', '已关闭']]);
  const history = texts(ui.el('history').children);
  for (const line of ['alice · 已创建', '状态：— → 待处理', 'bob · 已复核', '状态：待处理 → 处理中', '人工判定：— → 钓鱼', 'Looks like a lure.',
    'carol · 已重新打开', 'bob · 已保存 Jev 意见', '欺骗意图：估计概率 75.0%。这不是严重程度评分。', '原始证据不完整。', '意见来源信息',
    'dave · custom_action', 'unknown_field：x → —']) assert.ok(history.includes(line), line);
  assert.ok(history.includes('jev-1.13.0 · 请求时间 2026年9月22日 UTC 09:15。已保存的模型意见；风险和人工判定均未改变。'));
  assert.match(ui.el('jev-availability').textContent, /^Jev 已配置。[\s\S]*工作区今日尝试次数：3\/20。重置时间：2026年9月23日 UTC 00:00。$/);

  await ui.open(2);
  assert.equal(ui.el('feedback-context').textContent,
    '用户报告：误报 · 原始输入未包含。报告者备注：“This is my bank.”此诊断快照由浏览器提供；依赖它之前请先核实。');
  assert.deepEqual(texts(ui.el('evidence').children), ['报告的信号：紧迫感与施压', '报告的信号：品牌域名仿冒', '报告的信号：mystery code']);
  assert.ok(texts(ui.el('history').children).includes('复核原因：— → 误报'));
  assert.ok(texts(ui.el('history').children).includes('证据依据：— → 已保留的邮件'));
  assert.equal(ui.el('case-title').textContent, '用户反馈 · 误报');
});

test('a Chinese review save, conflict and server error keep server detail text as sent', async () => {
  let patch = () => ({status: 409, data: {detail: 'Case changed'}});
  const ui = loadCases(PAGE, {languages: ['zh-CN'], handler: router({record: (url, options) => options?.method === 'PATCH' ? patch()
    : {status: 200, data: caseRecord({status: 'pending'})}})});
  await ui.login(); await ui.open(0);
  ui.el('review-status').value = 'in_progress'; ui.el('note').value = '草稿'; await ui.fire('review-form', 'input');
  assert.equal(ui.el('draft-status').textContent, '未保存的草稿保留在此标签页中。离开前请保存。');
  await ui.fire('review-form', 'submit');
  assert.equal(ui.el('notice').textContent, zhDictionary['cases.error.conflict']);
  patch = () => ({status: 422, data: {detail: 'A human verdict is required to close a case'}});
  await ui.fire('review-form', 'submit');
  assert.equal(ui.el('notice').textContent, 'A human verdict is required to close a case');
  patch = () => ({status: 200, data: caseRecord({status: 'in_progress', version: 5})});
  await ui.fire('review-form', 'submit');
  assert.equal(ui.el('notice').textContent, '复核已保存。');
  ui.window.answer = false; ui.el('subject').value = 'x'; await ui.fire('logout');
  assert.deepEqual(ui.prompts, ['退出登录并放弃此标签页中未保存的草稿？']);
});

test('switching language re-renders loaded data without refetching or losing drafts and form input', async () => {
  const storage = memoryStorage();
  const ui = loadCases(PAGE, {handler: router({any: url => url.endsWith('/auxiliary')
    ? {status: 200, data: {...caseRecord().events[3].changes.auxiliary_opinion.to, status: 'available', case_id: 'case-1', case_version: 4}} : null}),
    storage});
  await ui.login(); await ui.open(0);
  await ui.fire('jev-read');
  ui.el('filter-risk').value = 'high'; await ui.fire('filters', 'submit');
  ui.el('verdict').value = 'phishing'; ui.el('note').value = 'Unsaved analyst note'; await ui.fire('review-form', 'input');
  ui.el('subject').value = 'Composer subject'; ui.el('body').value = 'Composer body';
  ui.el('feedback-reason').value = '';
  ui.el('jev-consent').checked = true;
  const english = capture(ui), calls = ui.calls.length;

  ui.context.window.PhishGuardI18n.setLang('zh');
  await settle();
  assert.equal(ui.calls.length, calls, 'nothing is refetched');
  assert.equal(storage.getItem('phishguard-lang'), 'zh');
  assert.equal(ui.document.documentElement.lang, 'zh-CN');
  assert.equal(ui.el('note').value, 'Unsaved analyst note');
  assert.equal(ui.el('verdict').value, 'phishing');
  assert.equal(ui.el('review-status').value, 'in_progress');
  assert.equal(ui.el('subject').value, 'Composer subject');
  assert.equal(ui.el('body').value, 'Composer body');
  assert.equal(ui.el('jev-consent').checked, true, 'consent is not reset');
  assert.equal(ui.el('draft-status').textContent, '未保存的草稿保留在此标签页中。离开前请保存。');
  assert.equal(ui.el('filter-summary').textContent, '1 项生效');
  assert.equal(ui.el('count').textContent, '60 条匹配记录');
  assert.equal(ui.el('case-list').children[0].attrs['aria-pressed'], 'false');
  assert.equal(ui.el('case-list').children.find(row => row.dataset.caseId === 'row-0') !== undefined, true);
  assert.deepEqual(ui.el('review-status').children.map(option => option.textContent), ['处理中', '已关闭']);
  assert.match(ui.el('jev-status').textContent, /^jev-1\.13\.0 · 模型意见，并非已核实的结论。/);
  assert.equal(ui.el('jev-results').children[0].children.length, 5);
  assert.equal(ui.el('jev-save').hidden, false, 'the retrieved opinion can still be saved');
  assert.match(ui.el('feedback-overview-status').textContent, /^所有日期共保留 7 份报告/);

  // The switch persists: the saved review and a reload stay in Chinese.
  ui.el('case-list').children[0].listeners.click(); await settle(); await settle();
  assert.equal(ui.el('case-meta').textContent, 'case-1 · 修订版本 4 · 创建者 alice');

  ui.context.window.PhishGuardI18n.setLang('en');
  await settle();
  assert.equal(ui.calls.length, calls + 1, 'only the explicit case open fetched');
  const back = capture(ui);
  for (const key of Object.keys(english)) {
    if (!['jev-status', 'jev-results', 'jev-save.flags', 'case-list'].includes(key)) assert.deepEqual(back[key], english[key], key);
  }
  assert.equal(ui.el('note').value, 'Unsaved analyst note');
});

test('language switches keep a pending draft save and an open notice, and work with throwing storage', async () => {
  const blocked = {getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceeded'); }};
  let release;
  const ui = loadCases(PAGE, {storage: blocked, handler: router({record: (url, options) => options?.method === 'PATCH'
    ? new Promise(resolve => { release = resolve; }) : {status: 200, data: caseRecord({status: 'pending'})}})});
  await ui.login(); await ui.open(0);
  ui.el('review-status').value = 'in_progress'; ui.el('note').value = 'Starting'; await ui.fire('review-form', 'input');
  const saving = ui.fire('review-form', 'submit');
  ui.el('note').value = 'Typed while saving'; await ui.fire('review-form', 'input');
  assert.doesNotThrow(() => ui.context.window.PhishGuardI18n.setLang('zh'));
  assert.equal(ui.document.documentElement.lang, 'zh-CN');
  assert.equal(ui.el('save-review').disabled, true, 'the save stays in flight');
  assert.equal(ui.el('note').value, 'Typed while saving');
  release({status: 200, data: caseRecord({status: 'in_progress', version: 5})});
  await saving; await settle();
  assert.equal(ui.el('notice').textContent, '复核已保存。您之后的修改仍未保存。');
  assert.equal(ui.el('note').value, 'Typed while saving');
  ui.context.window.PhishGuardI18n.setLang('en');
  assert.equal(ui.el('notice').textContent, 'Review saved. Your newer edits are still unsaved.', 'the notice follows the language');
  assert.equal(ui.document.documentElement.lang, 'en');
});

test('the workspace loads lang-init.js in <head> and i18n.js before every other script, with a language switch', () => {
  const html = readFileSync(new URL('./cases.html', import.meta.url), 'utf8');
  const head = html.slice(0, html.indexOf('</head>'));
  assert.match(head, /<script src="\/static\/cases-theme\.js\?v=\d+"><\/script>\s*<script src="\/static\/lang-init\.js\?v=\d+"><\/script>/);
  const deferred = [...head.matchAll(/<script src="\/static\/([a-z0-9-]+\.js)\?v=\d+" defer><\/script>/g)].map(match => match[1]);
  assert.deepEqual(deferred, ['i18n.js', 'vision.js', 'file-intake.js', 'confirm-dialog.js', 'cases.js']);
  assert.equal((html.match(/<script\b/g) || []).length, 7, 'no other (inline) scripts: CSP is script-src \'self\'');
  const topbar = html.slice(html.indexOf('<header class="topbar">'), html.indexOf('</header>', html.indexOf('<header class="topbar">')));
  const toggle = topbar.match(/<button class="lang-toggle" id="lang-toggle" type="button"([^>]*)>([\s\S]*?)<\/button>/);
  assert.ok(toggle, 'a real <button> in the topbar');
  assert.match(toggle[1], /aria-label="Language: English\. Switch to Simplified Chinese \(中文\)"/);
  assert.match(toggle[1], /data-i18n-attr="aria-label:nav\.lang\.label;title:nav\.lang\.label"/);
  assert.match(toggle[2], /data-lang-option="en" lang="en"[^>]*>EN</);
  assert.match(toggle[2], /data-lang-option="zh" lang="zh-CN"[^>]*>中文</);
  assert.ok(topbar.indexOf('id="case-theme"') < topbar.indexOf('id="lang-toggle"'), 'next to the theme control');
  const css = readFileSync(new URL('./cases.css', import.meta.url), 'utf8');
  assert.match(css, /:root\[data-i18n-pending\] body \{[^}]*visibility: hidden;[^}]*animation: i18n-reveal[^}]*!important/);
  assert.match(css, /\.lang-toggle \{[^}]*min-height: 32px/);
});

test('a Chinese workspace is translated before first paint, including <title>, and revealed', () => {
  const html = readFileSync(new URL('./cases.html', import.meta.url), 'utf8');
  const make = (key, attrs = {}) => ({attributes: {'data-i18n': key, ...attrs}, textContent: '', classList: {toggle() {}},
    getAttribute(name) { return this.attributes[name] ?? null; }, setAttribute(name, value) { this.attributes[name] = value; }});
  const text = [...html.matchAll(/\sdata-i18n="([^"]+)"/g)].map(match => make(match[1]));
  const attr = [...html.matchAll(/\sdata-i18n-attr="([^"]+)"/g)].map(match => make(null, {'data-i18n-attr': match[1]}));
  const title = text.find(node => node.attributes['data-i18n'] === 'cases.meta.title');
  const pending = new Set(['data-i18n-pending']);
  const document = {title: 'Cases · PhishGuard', documentElement: {lang: 'en', removeAttribute: name => pending.delete(name)},
    querySelectorAll: selector => ({'[data-i18n]': text, '[data-i18n-attr]': attr})[selector] || [],
    querySelector: selector => (selector === 'title[data-i18n]' ? title : null), getElementById: () => null};
  vm.runInNewContext(readFileSync(new URL('./i18n.js', import.meta.url), 'utf8'),
    {window: {}, document, navigator: {languages: ['en-US']}, localStorage: memoryStorage({'phishguard-lang': 'zh'}), console});
  assert.equal(document.documentElement.lang, 'zh-CN');
  assert.equal(pending.size, 0);
  assert.equal(title.textContent, '案例 · PhishGuard');
  assert.equal(document.title, 'Cases · PhishGuard', 'the homepage title is not applied');
  for (const node of text) assert.equal(node.textContent, zhDictionary[node.attributes['data-i18n']]);
  assert.ok(attr.every(node => node.attributes['data-i18n-attr'].split(';').every(pair => {
    const [name, key] = pair.split(':'); return node.attributes[name] === zhDictionary[key];
  })));
});

test('lang-init.js reveals a pending page at DOMContentLoaded even if i18n.js never runs', () => {
  const attrs = new Set(), listeners = {};
  const documentElement = {lang: '', setAttribute: name => attrs.add(name), removeAttribute: name => attrs.delete(name)};
  vm.runInNewContext(readFileSync(new URL('./lang-init.js', import.meta.url), 'utf8'), {navigator: {languages: ['zh-CN']},
    localStorage: {getItem: () => null}, document: {documentElement, addEventListener: (type, fn) => { listeners[type] = fn; }}});
  assert.equal(documentElement.lang, 'zh-CN');
  assert.ok(attrs.has('data-i18n-pending'));
  listeners.DOMContentLoaded();
  assert.equal(attrs.has('data-i18n-pending'), false);
});
