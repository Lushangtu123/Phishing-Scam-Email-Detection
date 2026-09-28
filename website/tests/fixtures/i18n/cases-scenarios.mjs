// Rendering scenarios for the case workspace (cases.js) in a fake DOM. The
// English snapshot (cases-en-snapshot.json) was captured from the pre-i18n
// cases.js, so i18n.test.mjs / cases.test.mjs can prove that English output is
// unchanged byte for byte. Regenerate only for an intentional English change:
//   node website/tests/fixtures/i18n/capture-cases.mjs
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {memoryStorage} from './scenarios.mjs';

const STATIC_DIR = new URL('../../../static/', import.meta.url);
const source = (name, dir = STATIC_DIR) => readFileSync(new URL(name, dir), 'utf8');
export const CASE_SCRIPTS = ['vision.js', 'file-intake.js', 'confirm-dialog.js', 'cases.js'];

export class CaseElement {
  constructor(tag = '') {
    this.tag = tag; this.value = ''; this.textContent = ''; this.className = ''; this.hidden = false; this.disabled = false;
    this.open = false; this.checked = false; this.dataset = {}; this.listeners = {}; this.children = []; this.files = [];
    this.attrs = {}; this.classList = {add() {}, remove() {}, toggle() {}, contains: () => false};
  }
  set innerHTML(_) { throw new Error('Untrusted content must never use HTML'); }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  getAttribute(key) { return Object.hasOwn(this.attrs, key) ? this.attrs[key] : null; }
  removeAttribute(key) { delete this.attrs[key]; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  reset() {}
  showModal() { this.open = true; }
  close() { this.open = false; this.dispatchEvent({type: 'close'}); }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  dispatchEvent(event) { this.listeners[event.type]?.(event); }
  contains(target) { return target === this; }
  querySelectorAll() { return []; }
}

// Deterministic time: the default locale is en-US and the viewer's zone is UTC.
class FixedDate extends Date {
  toLocaleString(locale, options = {}) { return super.toLocaleString(locale ?? 'en-US', {timeZone: 'UTC', ...options}); }
}

export const tick = () => new Promise(resolve => setImmediate(resolve));

// Loads the page scripts in order into one context; `handler(url, options)`
// answers fetch with {status, data}.
export function loadCases(scripts, {handler, languages = ['en-US'], storage = memoryStorage(), vision, staticDir = STATIC_DIR} = {}) {
  const elements = new Map(), calls = [], prompts = [], windowEvents = {}, documentEvents = {};
  const el = id => { if (!elements.has(id)) elements.set(id, new CaseElement()); return elements.get(id); };
  const window = {addEventListener(name, callback) { windowEvents[name] = callback; },
    confirm: message => { prompts.push(message); return window.answer ?? true; }, answer: true};
  const documentElement = {lang: 'en', dataset: {}, attrs: {}, setAttribute(key, value) { this.attrs[key] = value; },
    getAttribute(key) { return this.attrs[key] ?? null; }, removeAttribute(key) { delete this.attrs[key]; }};
  const document = {
    documentElement, title: 'Cases · PhishGuard', getElementById: el, createElement: tag => new CaseElement(tag),
    querySelectorAll: () => [], querySelector: () => null,
    addEventListener(type, fn) { (documentEvents[type] ??= []).push(fn); },
    dispatchEvent(event) { (documentEvents[event.type] || []).forEach(fn => fn(event)); return true; },
  };
  class DataTransfer { constructor() { this.files = []; this.items = {add: file => this.files.push(file)}; } }
  let uuid = 0;
  const context = vm.createContext({
    window, document, navigator: {languages, language: languages[0]}, localStorage: storage, console,
    DataTransfer, Event, CustomEvent, URLSearchParams, Date: FixedDate, setTimeout, clearTimeout,
    URL: {createObjectURL: () => 'blob:x', revokeObjectURL() {}},
    crypto: {randomUUID: () => 'synthetic-uuid-' + (++uuid)},
    fetch: async (url, options) => {
      calls.push({url, options});
      const result = await handler(url, options);
      if (result instanceof Error) throw result;
      return {ok: result.status < 400, status: result.status, json: async () => result.data};
    },
  });
  for (const name of scripts) vm.runInContext(source(name, staticDir), context, {filename: name});
  // A stub replaces the real vision.js where a scenario needs recognition.
  if (vision !== undefined) window.PhishGuardVision = vision;
  const fire = async (id, name = 'click', submitter) => {
    el(id).listeners[name]({preventDefault() {}, submitter: submitter === undefined ? el(id === 'create-form' ? 'create-case' : id + '-submit') : submitter,
      currentTarget: el(id)});
    await tick(); await tick();
  };
  const login = async () => { el('token').value = 'synthetic-access-token-at-least-32-characters'; await fire('login-form', 'submit'); };
  const open = async (index = 0) => { el('case-list').children[index].listeners.click(); await tick(); await tick(); };
  return {el, fire, login, open, calls, prompts, window, context, document, storage, windowEvents};
}

// ── Serialization ────────────────────────────────────────────────────────────
function tree(node) {
  if (!node || typeof node !== 'object') return node;
  const out = {};
  if (node.tag) out.tag = node.tag;
  if (node.className) out.class = node.className;
  if (node.textContent) out.text = node.textContent;
  if (node.value) out.value = node.value;
  if (node.title) out.title = node.title;
  if (node.disabled) out.disabled = true;
  if (node.hidden) out.hidden = true;
  for (const key of ['datetime', 'aria-pressed']) if (node.attrs?.[key] !== undefined) out[key] = node.attrs[key];
  if (node.children?.length) out.children = node.children.map(tree);
  return out;
}
const TEXT_IDS = ['notice', 'actor', 'count', 'page', 'queue-warning', 'filter-summary', 'case-capacity', 'feedback-capacity',
  'capacity-warning', 'feedback-open-count', 'feedback-closed-count', 'feedback-false-alerts-count', 'feedback-missed-threats-count',
  'feedback-overview-status', 'case-title', 'case-meta', 'history-capacity', 'feedback-context', 'analysis-summary', 'source',
  'source-note', 'analysis-json', 'draft-status', 'jev-availability', 'jev-status', 'create-case', 'creation-status',
  'case-file-status', 'vision-progress'];
const TREE_IDS = ['case-list', 'badges', 'evidence', 'visual-evidence', 'review-status', 'jev-results', 'history'];
const FLAG_IDS = ['draft-rebase', 'draft-discard', 'save-review', 'jev-save', 'jev-run', 'jev-read', 'new-case-draft', 'feedback-context',
  'feedback-review-fields', 'previous', 'next', 'detail', 'workspace'];

export function capture(ui) {
  const out = {};
  for (const id of TEXT_IDS) out[id] = ui.el(id).textContent;
  out['notice.error'] = ui.el('notice').dataset.error;
  for (const id of ['case-capacity', 'feedback-capacity']) out[id + '.level'] = ui.el(id).dataset.level;
  out['history-capacity.warning'] = ui.el('history-capacity').dataset.warning;
  for (const id of TREE_IDS) out[id] = tree(ui.el(id)).children || [];
  for (const id of FLAG_IDS) out[id + '.flags'] = `hidden=${ui.el(id).hidden} disabled=${ui.el(id).disabled}`;
  for (const id of ['review-status', 'verdict', 'note', 'feedback-reason', 'evidence-basis']) out[id + '.value'] = ui.el(id).value;
  out.prompts = [...ui.prompts];
  return out;
}

// ── Synthetic records ────────────────────────────────────────────────────────
const T0 = '2026-09-20T08:30:00Z';
export const jevOpinion = {receipt_id: 'a'.repeat(64), requested_at: '2026-09-22T09:15:00Z', provider: 'typesafe', model: 'jev-1.13.0',
  questions_sha256: 'b'.repeat(64), input_sha256: 'c'.repeat(64), evidence_incomplete: true, affects_risk: false,
  probabilities: {credential_request: 0.61, payment_redirection: 0.05, authority_pressure: 0.25, phishing_intent: 0.75, insufficient_evidence: 0.1}};

export function caseRecord(overrides = {}) {
  return {
    id: 'case-1', kind: 'case', title: 'Your account will be suspended', risk: 'high', status: 'in_progress', verdict: null, version: 4,
    created_by: 'alice', created_at: T0, input_sha256: 'd'.repeat(64),
    source: {subject: 'Your account will be suspended', body: 'Verify now at http://bit.ly/x', input_mode: 'subject-body', text_truncated: false},
    analysis: {
      risk_level: 'high', risk_label: 'High Risk — Likely Phishing', analysis_complete: true,
      analysis_warnings: ['Attachment content was not inspected; only filenames and MIME types were checked. Analysis is incomplete.',
        'A browser warning without a code'],
      extra_indicators: [
        {level: 'medium', msg: 'Contains shortened URLs (bit.ly, tinyurl, etc.) — hides the true destination domain', code: 'content.shortened_urls', params: {}},
        {level: 'medium', msg: 'Sender: Domain contains a hyphen (paypa1-verify.xyz) — major providers typically do not use hyphens in their domains',
          code: 'sender.domain_hyphen', params: {domain: 'paypa1-verify.xyz'}, prefixes: [{code: 'prefix.sender', params: {}}]},
        {level: 'low', msg: 'A reworded server message', code: 'content.shortened_urls', params: {}},
        {level: 'high', msg: 'Potentially dangerous attachment: <img src=x>.', code: 'structure.dangerous_attachment', params: {filename: '<img src=x>'}},
        'A plain string indicator', {level: 'info', message: 'Legacy message field'}, {level: 'info', detail: 'no text'},
      ],
      category_results: [
        {key: 'urgency', label: 'Urgency & Pressure', level: 'high', count: 2,
          description: 'Phishing emails create artificial time pressure to prevent careful thinking.', matched: ['urgent', 'suspended']},
        {key: 'credential', label: 'Credential Harvesting', level: 'medium', count: 1,
          description: 'A reworded description from an older release.', matched: ['verify']},
        {key: 'threats', label: 'Threats', level: 'low', count: 0, description: 'Not shown', matched: []},
      ],
      visual_analysis: {observations: [{name: 'shot.png', status: 'processed', risk_level: 'medium', ocr_confidence: 88.4,
        ocr_language: 'eng', ml_status: 'insufficient_context', qr_payloads: ['https://qr.example'], ocr_text: 'Verify now',
        warnings: ['Server warning']}], warnings: []},
    },
    analysis_warning_details: [
      {code: 'warning.attachments_uninspected', params: {}, msg: 'Attachment content was not inspected; only filenames and MIME types were checked. Analysis is incomplete.'},
      {code: null, params: {}, msg: 'A browser warning without a code'}],
    provenance: {input_mode: 'subject-body'},
    history_capacity: {used: 3, limit: 200, remaining: 194, bytes_used: 12345, byte_limit: 750000, bytes_remaining: 700000,
      byte_recovery_limit: 850000, review_statuses: ['in_progress', 'closed'], can_save_opinion: true},
    events: [
      {actor: 'alice', action: 'created', happened_at: T0, changes: {status: {from: null, to: 'pending'}}, note: ''},
      {actor: 'bob', action: 'reviewed', happened_at: '2026-09-21T10:00:00Z',
        changes: {status: {from: 'pending', to: 'in_progress'}, verdict: {from: null, to: 'phishing'}}, note: 'Looks like a lure.'},
      {actor: 'carol', action: 'reopened', happened_at: '2026-09-21T11:00:00Z', changes: {status: {from: 'closed', to: 'in_progress'}}, note: ''},
      {actor: 'bob', action: 'auxiliary_saved', happened_at: '2026-09-22T09:16:00Z', changes: {auxiliary_opinion: {from: null, to: jevOpinion}}, note: ''},
      {actor: 'dave', action: 'custom_action', happened_at: '2026-09-22T12:00:00Z', changes: {unknown_field: {from: 'x', to: null}}, note: ''},
    ],
    ...overrides,
  };
}

export function feedbackRecord(overrides = {}) {
  return caseRecord({
    id: 'fb-1', kind: 'feedback', title: 'User feedback · false_positive', risk: 'medium', status: 'pending', verdict: null, version: 2,
    created_by: 'user_feedback', source: {subject: '', body: ''},
    analysis: {risk_level: 'medium', risk_label: 'Medium Risk — Suspicious Content', risk_score: 41, analysis_complete: null,
      evidence_codes: ['urgency', 'links_in_tags', 'mystery_code']},
    provenance: {record_kind: 'user_feedback', report_type: 'false_positive', note: 'This is my bank.', source_consent: false,
      input_mode: 'content', client_reported: true},
    history_capacity: {used: 2, limit: 200, remaining: 195, review_statuses: ['pending', 'in_progress'], can_save_opinion: false},
    events: [
      {actor: 'user_feedback', action: 'created', happened_at: T0, changes: {status: {from: null, to: 'pending'}}, note: ''},
      {actor: 'erin', action: 'reviewed', happened_at: '2026-09-21T10:00:00Z',
        changes: {feedback_reason: {from: null, to: 'false_alert'}, evidence_basis: {from: null, to: 'retained_message'}}, note: 'Checked with the bank.'},
    ],
    ...overrides,
  });
}

const RISKS = ['critical', 'high', 'medium', 'low', 'safe', 'unknown', 'bogus'];
const STATUSES = ['pending', 'in_progress', 'closed'];
const VERDICTS = [null, 'phishing', 'legitimate', 'uncertain'];
export const listItems = () => RISKS.map((risk, index) => ({
  id: 'row-' + index, kind: index % 3 === 2 ? 'feedback' : 'case',
  title: index % 3 === 2 ? 'User feedback · false_negative' : 'Subject ' + index, risk,
  status: STATUSES[index % 3], verdict: VERDICTS[index % 4], version: 1, created_at: `2026-09-${10 + index}T0${index}:05:00Z`,
}));

const me = (jev = {status: 'available', used: 3, daily_limit: 20, reset_at: 1790121600}) =>
  ({actor: 'alice', jev_available: ['available', 'quota_exhausted'].includes(jev.status), jev});

// A small router: `routes` entries override the defaults below.
export function router(routes = {}) {
  const defaults = {
    me: () => ({status: 200, data: me()}),
    list: () => ({status: 200, data: {items: listItems(), total: 60, partial: false, sources: {case: 'available', feedback: 'available'}}}),
    capacity: () => ({status: 200, data: {cases: {status: 'available', used: 85, limit: 100}, feedback: {status: 'available', used: 12, limit: null}}}),
    overview: () => ({status: 200, data: {status: 'available', total: 7, pending: 2, in_progress: 1, closed: 4, false_alerts: 1, missed_threats: 2}}),
    record: url => ({status: 200, data: url.includes('kind=feedback') ? feedbackRecord() : caseRecord()}),
  };
  const pick = name => routes[name] || defaults[name];
  return async (url, options) => {
    const path = url.split('?')[0];
    if (routes.any) { const answer = await routes.any(url, options); if (answer) return answer; }
    if (path.endsWith('/me')) return pick('me')(url, options);
    if (url.startsWith('/api/cases?')) return pick('list')(url, options);
    if (path.endsWith('/capacity')) return pick('capacity')(url, options);
    if (path.endsWith('/feedback-overview')) return pick('overview')(url, options);
    return pick('record')(url, options);
  };
}

// Visual evidence is rendered by the real vision.js, like on the page.
export const SCENARIOS = {
  async 'list and capacity'(load, shots) {
    const ui = load({handler: router()});
    shots.signedOut = capture(ui);
    await ui.login(); shots.list = capture(ui);
    ui.el('filter-kind').value = 'case'; ui.el('filter-risk').value = 'high'; ui.el('filter-from').value = '2026-09-01';
    await ui.fire('filters', 'submit'); shots.filtered = capture(ui);
    await ui.fire('next'); shots.page2 = capture(ui);
  },
  async 'queue edge states'(load, shots) {
    let list = {items: listItems().slice(0, 2), total: 2, partial: true, sources: {case: 'unavailable', feedback: 'available'}};
    const ui = load({handler: router({list: () => ({status: 200, data: list}),
      capacity: () => ({status: 200, data: {cases: {status: 'disabled'}, feedback: {status: 'available', used: 100, limit: 100}}}),
      overview: () => ({status: 200, data: {status: 'disabled'}})})});
    await ui.login(); shots.partial = capture(ui);
    list = {items: [], total: 0, partial: true, sources: {case: 'available', feedback: 'unavailable'}};
    await ui.fire('refresh'); shots.partialEmpty = capture(ui);
    list = {items: [], total: 0, partial: false, sources: {case: 'available'}};
    await ui.fire('refresh'); shots.empty = capture(ui);
  },
  async 'unstable queue and unavailable counts'(load, shots) {
    let shrinking = false;
    const ui = load({handler: router({
      list: url => {
        const offset = Number(new URL(url, 'https://synthetic.test').searchParams.get('offset'));
        if (!shrinking) return {status: 200, data: {items: listItems(), total: 75}};
        return {status: 200, data: {items: [], total: offset ? offset : 0, partial: true, sources: {case: 'unavailable', feedback: 'available'}}};
      },
      capacity: () => ({status: 503, data: {detail: 'Case storage is unavailable.'}}),
      overview: () => ({status: 200, data: {status: 'unavailable'}})})});
    await ui.login(); await ui.fire('next'); await ui.fire('next');
    shrinking = true; await ui.fire('refresh'); shots.unstable = capture(ui);
  },
  async 'case detail'(load, shots) {
    const ui = load({handler: router()});
    await ui.login(); await ui.open(0); shots.detail = capture(ui);
    ui.el('note').value = 'Draft note'; await ui.fire('review-form', 'input'); shots.draft = capture(ui);
  },
  async 'history capacity limits'(load, shots) {
    let record = caseRecord({history_capacity: {used: 199, limit: 200, remaining: 0, review_statuses: ['closed'], can_save_opinion: false}});
    const ui = load({handler: router({record: () => ({status: 200, data: record})})});
    await ui.login(); await ui.open(0); shots.reserved = capture(ui);
    record = caseRecord({version: 5, history_capacity: {used: 34, limit: 200, remaining: 165, bytes_used: 750000, byte_limit: 750000,
      bytes_remaining: 0, byte_recovery_limit: 850000, review_statuses: ['closed'], can_save_opinion: false}});
    await ui.fire('reload-case'); shots.bytesFull = capture(ui);
    record = caseRecord({version: 6, status: 'closed', verdict: 'legitimate',
      history_capacity: {used: 200, limit: 200, remaining: 0, review_statuses: [], can_save_opinion: false}});
    await ui.fire('reload-case'); shots.full = capture(ui);
  },
  async 'feedback records'(load, shots) {
    let record = feedbackRecord();
    const ui = load({handler: router({record: () => ({status: 200, data: record})})});
    await ui.login(); await ui.open(2); shots.noConsent = capture(ui);
    record = feedbackRecord({version: 3, provenance: {record_kind: 'user_feedback', report_type: 'incorrect_evidence', note: '',
      source_consent: true, input_mode: 'eml'}, source: {subject: '', body: 'raw'},
      source_preview: {status: 'available', subject: 'Invoice', body: 'Pay today', truncated: false,
        warnings: ['Charset fallback', 'Attached message could not be parsed; analysis is incomplete.'],
        warning_details: [{code: null, params: {}, msg: 'Charset fallback'}, {code: 'warning.attached_message_unparsed', params: {},
          msg: 'Attached message could not be parsed; analysis is incomplete.'}]}});
    await ui.fire('reload-case'); shots.emlPreview = capture(ui);
    record = feedbackRecord({version: 4, provenance: {record_kind: 'user_feedback', report_type: 'other', source_consent: true, input_mode: 'eml'},
      source: {subject: '', body: 'raw'}, source_preview: {status: 'unavailable', warnings: []}});
    await ui.fire('reload-case'); shots.emlUnavailable = capture(ui);
    record = feedbackRecord({version: 5, provenance: {record_kind: 'user_feedback', source_consent: true, input_mode: 'content'},
      source: {subject: 'Hello', body: 'Body', text_truncated: true}});
    await ui.fire('reload-case'); shots.truncated = capture(ui);
  },
  async 'review flow'(load, shots) {
    let record = caseRecord({status: 'pending', version: 4}), patch = null;
    const ui = load({handler: router({record: (url, options) => options?.method === 'PATCH' ? patch() : {status: 200, data: record}})});
    await ui.login(); await ui.open(0);
    ui.el('review-status').value = 'in_progress'; ui.el('note').value = 'Started'; await ui.fire('review-form', 'input');
    patch = () => ({status: 200, data: caseRecord({status: 'in_progress', version: 5})});
    await ui.fire('review-form', 'submit'); shots.saved = capture(ui);
    ui.el('note').value = 'Newer note'; await ui.fire('review-form', 'input');
    record = caseRecord({status: 'closed', verdict: 'phishing', version: 7});
    await ui.fire('reload-case'); shots.conflict = capture(ui);
    await ui.fire('review-form', 'submit'); shots.conflictSubmit = capture(ui);
    await ui.fire('draft-rebase'); shots.rebased = capture(ui);
    patch = () => ({status: 409, data: {detail: 'Case changed'}});
    ui.el('review-status').value = 'in_progress'; await ui.fire('review-form', 'change');
    await ui.fire('review-form', 'submit'); shots.stale = capture(ui);
    patch = () => ({status: 422, data: {detail: [{loc: ['body'], msg: 'bad'}]}});
    await ui.fire('review-form', 'submit'); shots.invalid = capture(ui);
    patch = () => ({status: 422, data: {detail: 'A human verdict is required to close a case'}});
    await ui.fire('review-form', 'submit'); shots.serverDetail = capture(ui);
    patch = () => new TypeError('Failed to fetch');
    await ui.fire('review-form', 'submit'); shots.network = capture(ui);
    await ui.fire('draft-discard'); shots.discarded = capture(ui);
  },
  async 'review status no longer available'(load, shots) {
    let record = caseRecord({status: 'pending', version: 1});
    const ui = load({handler: router({record: () => ({status: 200, data: record})})});
    await ui.login(); await ui.open(0);
    ui.el('review-status').value = 'pending'; ui.el('note').value = 'Pending note'; await ui.fire('review-form', 'input');
    record = caseRecord({status: 'closed', verdict: 'uncertain', version: 2});
    await ui.fire('reload-case'); shots.unavailableOption = capture(ui);
    await ui.fire('draft-rebase'); await ui.fire('review-form', 'submit'); shots.submit = capture(ui);
    record = caseRecord({status: 'in_progress', version: 3, history_capacity: {used: 199, limit: 200, remaining: 0, review_statuses: ['closed'], can_save_opinion: false}});
    await ui.fire('reload-case'); await ui.fire('draft-rebase');
    ui.el('review-status').value = 'in_progress'; await ui.fire('review-form', 'submit'); shots.capacitySubmit = capture(ui);
  },
  async 'feedback review saved'(load, shots) {
    const ui = load({handler: router({record: (url, options) => options?.method === 'PATCH'
      ? {status: 200, data: feedbackRecord({status: 'in_progress', version: 3})} : {status: 200, data: feedbackRecord()}})});
    await ui.login(); await ui.open(2);
    ui.el('review-status').value = 'in_progress'; ui.el('feedback-reason').value = 'false_alert'; ui.el('evidence-basis').value = 'report_only';
    await ui.fire('review-form', 'input');
    const pending = ui.fire('review-form', 'submit');
    ui.el('note').value = 'Typed during save'; await ui.fire('review-form', 'input');
    await pending; shots.savedWithLaterEdit = capture(ui);
  },
  async 'jev availability'(load, shots) {
    let jev = {status: 'disabled'};
    const ui = load({handler: router({me: () => ({status: 200, data: me(jev)})})});
    await ui.login(); await ui.open(0);
    for (const status of ['disabled', 'configuration_error', 'control_unavailable', 'quota_exhausted', 'available', 'mystery']) {
      jev = status === 'quota_exhausted' ? {status, used: 20, daily_limit: 20, reset_at: 1790121600}
        : status === 'available' ? {status, used: 2, daily_limit: 20} : {status};
      await ui.fire('refresh'); shots[status] = ui.el('jev-availability').textContent;
    }
  },
  async 'jev requests'(load, shots) {
    let answer = null;
    const ui = load({handler: router({any: (url, options) => url.endsWith('/auxiliary') ? answer(options) : null})});
    await ui.login(); await ui.open(0);
    await ui.fire('jev-run'); shots.noConsent = ui.el('jev-status').textContent;
    const reasons = ['no_cached_opinion', 'provider_authentication', 'provider_access_denied', 'provider_request_invalid',
      'provider_rate_limited', 'provider_overloaded', 'provider_timeout', 'provider_tls_error', 'provider_network_error',
      'provider_http_error', 'provider_invalid_response', 'local_capacity_exhausted', 'call_budget_exhausted',
      'daily_quota_exhausted', 'request_pending', 'empty_or_oversized_text', 'legacy_source_format', 'private-secret'];
    for (const reason of reasons) {
      answer = () => ({status: 200, data: {case_id: 'case-1', case_version: 4, status: 'skipped', reason,
        receipt_expires_at: reason === 'request_pending' ? 1790121600 : null}});
      ui.el('jev-consent').checked = true; await ui.fire('jev-run'); shots['reason:' + reason] = ui.el('jev-status').textContent;
    }
    answer = () => ({status: 200, data: {case_id: 'case-1', case_version: 3, status: 'available'}});
    await ui.fire('jev-read'); shots.changed = ui.el('jev-status').textContent;
    answer = () => ({status: 503, data: {}});
    await ui.fire('jev-read'); shots.failed = ui.el('jev-status').textContent;
    answer = () => ({status: 503, data: {detail: 'Auxiliary analysis is temporarily unavailable.'}});
    await ui.fire('jev-read'); shots.serverError = ui.el('jev-status').textContent;
    answer = () => ({status: 200, data: {...jevOpinion, status: 'available', case_id: 'case-1', case_version: 4, reused: true,
      quota: {used: 4, daily_limit: 20}, receipt_expires_at: 1790121600}});
    ui.el('jev-consent').checked = true; await ui.fire('jev-run'); shots.available = capture(ui);
    answer = () => ({status: 200, data: {...jevOpinion, evidence_incomplete: false, status: 'available', case_id: 'case-1', case_version: 4, reused: false}});
    await ui.fire('jev-read'); shots.availableComplete = capture(ui);
  },
  async 'jev save'(load, shots) {
    let saveAnswer, version = 4;
    const saved = (outcome, next) => caseRecord({version: next, auxiliary_save: {outcome, base_version: version, receipt_id: jevOpinion.receipt_id}});
    const ui = load({handler: router({any: (url, options) => url.endsWith('/auxiliary/save') ? saveAnswer()
      : url.endsWith('/auxiliary') ? {status: 200, data: {...jevOpinion, status: 'available', case_id: 'case-1', case_version: version}} : null})});
    await ui.login(); await ui.open(0);
    await ui.fire('jev-read');
    ui.window.answer = false; await ui.fire('jev-save'); shots.declined = capture(ui);
    ui.window.answer = true; saveAnswer = () => ({status: 200, data: saved('saved', 5)});
    await ui.fire('jev-save'); shots.saved = capture(ui);
    version = 5; await ui.fire('jev-read'); saveAnswer = () => ({status: 200, data: saved('already_saved', 6)});
    await ui.fire('jev-save'); shots.already = capture(ui);
    version = 6; await ui.fire('jev-read'); saveAnswer = () => new Error('');
    await ui.fire('jev-save'); shots.failed = capture(ui);
    const closed = load({handler: router({record: () => ({status: 200, data: caseRecord({status: 'closed', verdict: 'phishing'})}),
      any: url => url.endsWith('/auxiliary') ? {status: 200, data: {...jevOpinion, status: 'available', case_id: 'case-1', case_version: 4}} : null})});
    await closed.login(); await closed.open(0); await closed.fire('jev-read'); shots.closed = closed.el('jev-status').textContent;
  },
  async 'case creation'(load, shots) {
    let create = () => ({status: 500, data: {}});
    const ui = load({handler: router({any: (url, options) => options?.method === 'POST' && (url === '/api/cases' || url === '/api/cases/visual') ? create() : null}),
      vision: {cancel() {}, render() {}, recognize: async () => ({subject: 'From image', body: 'OCR'})}});
    await ui.login(); await ui.fire('open-compose');
    shots.opened = capture(ui);
    ui.el('subject').value = 'Hello'; ui.el('body').value = 'Body'; await ui.fire('create-form', 'input');
    await ui.fire('create-form', 'submit'); shots.uncertain = capture(ui);
    ui.el('body').value = 'Edited body'; await ui.fire('create-form', 'input');
    ui.window.answer = false; await ui.fire('create-form', 'submit'); shots.retryDeclined = capture(ui);
    ui.window.answer = true; create = () => ({status: 200, data: caseRecord({id: 'case-9', version: 1, status: 'pending'})});
    await ui.fire('create-form', 'submit'); shots.saved = capture(ui);
    await ui.fire('new-case-draft'); shots.newDraft = capture(ui);
    ui.el('compose-dialog').listeners.cancel?.({preventDefault() {}});
    ui.el('eml').files = [{name: 'huge.png', size: 3 * 1024 * 1024}]; await ui.fire('eml', 'change'); shots.fileLoaded = capture(ui);
    await ui.fire('open-compose'); await ui.fire('create-form', 'submit'); shots.fileTooLarge = capture(ui);
    let release;
    create = () => new Promise(resolve => { release = resolve; });
    ui.el('eml').files = []; await ui.fire('eml', 'change');
    ui.el('subject').value = 'Pending'; await ui.fire('create-form', 'input');
    const pending = ui.fire('create-form', 'submit');
    ui.el('compose-dialog').listeners.cancel({preventDefault() {}}); await tick(); shots.pendingCancel = capture(ui);
    release({status: 422, data: {detail: 'Provide a subject or body'}}); await pending; await tick(); shots.rejected = capture(ui);
  },
  async 'image input errors'(load, shots) {
    const ui = load({handler: router(), vision: null});
    await ui.login(); await ui.fire('open-compose');
    ui.el('eml').files = [{name: 'shot.png', size: 100}]; await ui.fire('eml', 'change');
    ui.context.window.PhishGuardVision = undefined;
    await ui.fire('create-form', 'submit'); shots.noVision = capture(ui);
    let progress, finish;
    ui.context.window.PhishGuardVision = {cancel() {}, render() {}, recognize: (file, onProgress) => new Promise(resolve => {
      progress = onProgress; finish = () => resolve({observations: []});
    })};
    const pending = ui.fire('create-form', 'submit');
    progress('Reading image 1 of 1…'); shots.progress = capture(ui);
    ui.el('case-ocr-language').value = 'chi_sim'; ui.el('case-ocr-language').listeners.change();
    finish(); await pending; await tick(); await tick(); shots.inputChanged = capture(ui);
  },
  async 'sign out prompts'(load, shots) {
    const ui = load({handler: router()});
    await ui.login(); ui.el('subject').value = 'Unsaved';
    ui.window.answer = false; await ui.fire('logout'); shots.kept = capture(ui);
    ui.window.answer = true; await ui.fire('logout'); shots.signedOut = capture(ui);
    const denied = load({handler: router({me: () => ({status: 401, data: {detail: 'A valid analyst access token is required'}})})});
    await denied.login(); shots.denied = capture(denied);
    const failing = load({handler: router({me: () => new Error('')})});
    await failing.login(); shots.emptyError = capture(failing);
  },
};

export async function runCaseScenarios(scripts, options = {}) {
  const results = {};
  for (const [name, scenario] of Object.entries(SCENARIOS)) {
    const shots = {};
    await scenario(settings => loadCases(scripts, {vision: undefined, ...options, ...settings}), shots);
    // Each capture lists only what changed since the previous one in the
    // scenario (the first is complete), which keeps the fixture reviewable.
    let previous = {};
    results[name] = {};
    for (const [shot, value] of Object.entries(JSON.parse(JSON.stringify(shots)))) {
      if (!value || typeof value !== 'object') { results[name][shot] = value; continue; }
      results[name][shot] = Object.fromEntries(Object.entries(value)
        .filter(([key, item]) => JSON.stringify(item) !== JSON.stringify(previous[key])));
      previous = value;
    }
  }
  return results;
}
