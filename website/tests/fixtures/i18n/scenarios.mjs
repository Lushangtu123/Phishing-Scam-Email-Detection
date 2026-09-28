// Rendering scenarios for the homepage scripts in a fake DOM. The English
// snapshot (en-snapshot.json) was captured from the pre-i18n scripts, so
// i18n.test.mjs can prove that English output is unchanged byte for byte.
// Regenerate only for an intentional English copy change:
//   node website/tests/fixtures/i18n/capture.mjs
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

export const STATIC_DIR = new URL('../../../static/', import.meta.url);

export class FakeElement {
  constructor(tag = 'div') {
    const classes = new Set();
    this.tagName = tag.toUpperCase();
    this.className = '';
    this.innerHTML = '';
    this.style = {};
    this.textContent = '';
    this.value = '';
    this.listeners = {};
    this.children = [];
    this.dataset = {};
    this.attributes = {};
    this.selected = new Map();
    this.classList = {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle: (name, force) => {
        if (force === true) return classes.add(name);
        if (force === false) return classes.delete(name);
        return classes.has(name) ? classes.delete(name) : classes.add(name);
      },
      contains: name => classes.has(name),
    };
  }
  scrollIntoView() {}
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return name in this.attributes ? this.attributes[name] : null; }
  hasAttribute(name) { return name in this.attributes; }
  removeAttribute(name) { delete this.attributes[name]; }
  // Each selector resolves to one stable child, so code that appends to
  // `el.querySelector('.vb-left')` can be inspected afterwards.
  querySelector(selector) {
    if (!this.selected.has(selector)) this.selected.set(selector, new FakeElement());
    return this.selected.get(selector);
  }
  querySelectorAll() { return []; }
  appendChild(child) { this.children.push(child); return child; }
  append(...nodes) { this.children.push(...nodes); }
  remove() { this.removed = true; }
  focus() {}
  click() {}
  addEventListener(event, callback) { this.listeners[event] = callback; }
}

export function memoryStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: key => (data.has(key) ? data.get(key) : null),
    setItem: (key, value) => { data.set(key, String(value)); },
    removeItem: key => { data.delete(key); },
  };
}

export const source = name => readFileSync(new URL(name, STATIC_DIR), 'utf8');

// Loads `scripts` (in page order) into one context, like the classic scripts
// on the page.
export function loadPage(scripts, overrides = {}) {
  const elements = new Map();
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  const document = {
    documentElement: {lang: 'en', dataset: {}, setAttribute() {}, getAttribute() { return null; }},
    addEventListener() {},
    createElement: tag => new FakeElement(tag),
    getElementById,
    querySelector: () => new FakeElement(),
    querySelectorAll: () => [],
    ...overrides.document,
  };
  const window = {addEventListener() {}, scrollY: 0,
    PhishGuardVision: {cancel() {}, render() {}}, ...overrides.window};
  const {document: _d, window: _w, ...rest} = overrides;
  const context = vm.createContext({document, window, console, setTimeout: fn => fn(), clearTimeout() {},
    navigator: {languages: ['en-US'], language: 'en-US'}, ...rest});
  for (const name of scripts) vm.runInContext(source(name), context, {filename: name});
  return {context, elements, document, window};
}

const text = (elements, ...ids) => Object.fromEntries(ids.map(id => [id, elements.get(id)?.textContent ?? null]));
const html = (elements, ...ids) => Object.fromEntries(ids.map(id => [id, elements.get(id)?.innerHTML ?? null]));

// ── Sender results ───────────────────────────────────────────────────────────
const baseSender = {
  email: 'security-alert@paypa1-verify.xyz', verdict: 'critical', label: 'Critical Sender Risk', risk_score: 100,
  risk_indicators: [
    {level: 'high', msg: 'Domain imitates paypal.com (digit substitution)'},
    {level: 'high', msg: 'Suspicious TLD .xyz'},
    {level: 'medium', msg: 'Unrecognized provider'},
    {level: 'low', msg: 'Hyphen in domain'},
    {level: 'info', msg: 'Plus alias'},
  ],
  high_risk_count: 2, med_risk_count: 1, phish_feature_count: 4,
  feature_breakdown: [
    {name: 'links_in_tags', label: 'Brand Domain Spoofing', email_desc: 'Domain appears to impersonate a well-known brand (e.g. paypal, apple)', value: -1},
    {name: 'statistical_report', label: 'Suspicious TLD', email_desc: 'TLD is a known high-risk or free domain extension heavily used in phishing', value: -1},
    {name: 'age_of_domain', label: 'Domain Label Length', email_desc: 'Domain label is abnormally long — may be disguising a legitimate domain name', value: 0},
    {name: 'having_ip_address', label: 'IP Address Domain', email_desc: 'Domain uses a proper hostname, not a raw IP address', value: 1},
    {name: 'unknown_feature', label: 'Some <Server> Feature', email_desc: 'Server-provided text', value: 1},
  ],
  disposable_status: 'no_known_match', address_alias_type: null,
  account_observability: 'provider_account_unverifiable', sender_history_status: 'raw_message_required',
};

const SENDER_VARIANTS = {
  critical: {},
  medium: {verdict: 'medium', label: 'Suspicious Sender', risk_score: 41, disposable_status: 'suspicious_mailbox_pattern',
    email: 'xq7m9v2k4p8z@gmail.com', address_alias_type: 'subaddress', sender_history_status: 'first_seen'},
  lowDisposable: {verdict: 'low', label: 'Low Sender Risk', risk_score: 0, risk_indicators: [{level: 'info', msg: 'Known disposable-email provider'}],
    high_risk_count: 0, med_risk_count: 0, disposable_status: 'known_disposable_provider', matched_provider_domain: 'mailinator.com',
    email: 'user@mailinator.com', sender_history_status: 'previously_seen', account_observability: null},
  relay: {verdict: 'low', label: 'Low Sender Risk', risk_score: 3, disposable_status: 'privacy_relay', matched_provider_domain: 'relay.firefox.com',
    email: 'a1b2@relay.firefox.com', sender_history_status: 'not_seen', risk_indicators: [{level: 'low', msg: 'x'}]},
  domainPattern: {verdict: 'high', label: 'High Sender Risk', risk_score: 66, disposable_status: 'suspicious_domain_pattern',
    email: 'user@tempinbox-mail.net', sender_history_status: 'unavailable', address_alias_type: 'subaddress'},
  legacyDisposable: {verdict: 'low', label: 'Low Sender Risk', risk_score: 10, disposable_status: undefined, is_disposable: true,
    is_suspected_disposable: false, disposable_service: 'guerrillamail.com', email: 'hello@guerrillamail.com', sender_history_status: undefined},
  unknownVerdict: {verdict: 'weird', label: 'Server Label', risk_score: 55, email: 'x@outlook.com', account_observability: 'provider_account_unverifiable',
    sender_history_status: 'first_seen'},
};

function senderScenario(variant) {
  return page => {
    const {context, elements} = page;
    const data = {...baseSender, ...SENDER_VARIANTS[variant]};
    context.renderResult(data);
    const banner = elements.get('verdict-banner');
    const note = banner.querySelector('.vb-left').children.at(-1);
    const badge = elements.get('disposable-check-card').children.at(-1);
    return {
      ...text(elements, 'vb-title', 'vb-email', 'vb-scope', 'vb-prob-label', 'vb-prob', 'phish-pct', 'risk-count',
        'disp-check-label', 'disp-check-detail', 'sender-history-label', 'sender-history-detail', 'score-breakdown-formula'),
      ...html(elements, 'risk-summary', 'risk-indicators-list', 'feature-breakdown-list', 'score-breakdown-list', 'vb-icon', 'disp-check-icon'),
      bannerClass: banner.className,
      suspectNote: note ? note.textContent : null,
      disposableBadge: badge ? badge.textContent : null,
      summary: context.senderSummaryText(data),
      markdown: context.senderReportMarkdown(data, new Date(Date.UTC(2026, 8, 28, 20, 5, 9))),
    };
  };
}

// ── Content results ──────────────────────────────────────────────────────────
const baseContent = {
  risk_level: 'high', risk_label: 'High Risk — Likely Phishing', total_score: 9, combined_phishing_score: 72.4,
  analysis_complete: true, input_mode: 'subject-body',
  category_results: [
    {key: 'urgency', label: 'Urgency & Pressure', level: 'high', count: 2, description: 'Phishing emails create artificial time pressure to prevent careful thinking.', matched: ['urgent', 'within 24 hours']},
    {key: 'credential', label: 'Credential Harvesting', level: 'high', count: 1, description: 'Requests for passwords, card numbers, SSN, or account details are major red flags.', matched: ['password']},
    {key: 'mystery', label: 'Server <Category>', level: 'medium', count: 3, description: 'Unmapped server text', matched: ['a', 'b', 'c']},
  ],
  extra_indicators: [{level: 'high', msg: 'IP address link http://192.168.1.1/'}, {level: 'medium', msg: 'Shortened URL'}, {level: 'info', msg: 'Provider context'}],
  safety_signals: ['Unsubscribe link present', 'Physical address present'],
  ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 72.4, ml_legitimate_probability: 27.6,
  ml_prediction: 1, ml_top_contributors: [{term: 'verify', contribution: 0.42}, {term: 'suspended', contribution: 0.31}],
  ml_metrics: {model: 'LogisticRegression', Accuracy: 0.97, Phishing_Recall: 0.981, False_Negative_Rate: 0.019, PR_AUC: 0.9912, decision_threshold: 0.3125},
  analysis_warnings: ['Attachment content was not inspected; only metadata was checked.'],
  sender_analysis: {email: 'billing@outlook.com', sender_history_status: 'previously_seen', account_observability: 'provider_account_unverifiable'},
};

const CONTENT_VARIANTS = {
  high: {},
  singular: {category_results: [baseContent.category_results[1]], extra_indicators: [{level: 'low', msg: 'x'}], ml_prediction: 0,
    ml_label: 'Likely Legitimate', ml_top_contributors: [], ml_metrics: {}, sender_analysis: undefined, input_mode: 'raw-email'},
  modelOnly: {category_results: [], extra_indicators: [], fusion_basis: 'model_only', risk_label: 'High Risk — Model Signal Needs Review'},
  modelLed: {category_results: [], extra_indicators: [], fusion_basis: 'model_led', risk_label: 'High Risk — Model Signal Needs Review', ml_metrics: {model: 'CalibratedLinearSVC'}},
  safe: {risk_level: 'safe', risk_label: 'No Phishing Indicators Found', combined_phishing_score: 3, category_results: [], extra_indicators: [],
    safety_signals: [], ml_label: null, ml_status: 'disabled', sender_analysis: undefined},
  riskNoEvidence: {risk_level: 'medium', risk_label: 'Medium Risk — Suspicious Content', category_results: [], extra_indicators: [],
    ml_label: null, ml_status: 'disabled', combined_phishing_score: null, total_score: 12},
  incomplete: {risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined', combined_phishing_score: null, analysis_complete: false,
    ml_status: 'insufficient_context', ml_label: null, category_results: [], extra_indicators: [],
    message_structure: {attachments: [{inspection_status: 'metadata_only'}], parse_warnings: ['bad MIME']},
    inline_image_coverage: {inspection_status: 'metadata_only'}, remote_image_coverage: {inspection_status: 'metadata_only'},
    unresolved_image_coverage: {inspection_status: 'metadata_only'}},
  coverage: {ml_status: 'insufficient_feature_coverage', ml_label: null, analysis_complete: false, risk_label: 'No Indicators in Inspected Text — Remote Image Unchecked', risk_level: 'low'},
  unverified: {ml_status: 'unverified_rendering', ml_label: null, analysis_complete: false, ml_metrics: {model: 'ComplementNB'}},
  image: {input_mode: 'image-evidence', risk_level: 'unknown', risk_label: 'Image Analysis Incomplete — Risk Undetermined', analysis_complete: false,
    combined_phishing_score: null, ml_label: null, ml_status: 'insufficient_context', category_results: []},
  unknownLabel: {risk_level: 'critical', risk_label: 'Some Future Server Label', ml_metrics: {model: 'GradientBoosting', Accuracy: 0.9, Phishing_Recall: 0.5, False_Negative_Rate: 0.5, PR_AUC: 0.5, decision_threshold: 0.5}},
};

function contentScenario(variant) {
  return page => {
    const {context, elements} = page;
    const data = {...baseContent, ...CONTENT_VARIANTS[variant]};
    context.renderContentResult(data);
    return {
      ...text(elements, 'crb-title', 'crb-sub', 'crb-score', 'content-ml-title', 'content-ml-sub', 'content-phish-pct', 'content-legit-pct',
        'content-sender-history-label', 'content-sender-history-detail'),
      ...html(elements, 'content-ml-metrics', 'content-ml-contribs', 'content-category-grid', 'content-extra-list', 'content-safety-list', 'crb-icon'),
      bannerClass: elements.get('content-risk-banner').className,
      summary: context.contentSummaryText(data),
      markdown: context.contentReportMarkdown(data, new Date(Date.UTC(2026, 8, 28, 20, 5, 9))),
    };
  };
}

// ── Verification ─────────────────────────────────────────────────────────────
const STEPS = ['format', 'mx', 'smtp', 'ptr', 'spf', 'dmarc', 'age'];
const VERIFY_VARIANTS = {
  invalidFormat: {email: 'bad', format_valid: false},
  nullMx: {email: 'a@example.com', format_valid: true, null_mx: true, overall: 'no_mail_service', smtp_message: 'Domain publishes Null MX.'},
  noMx: {email: 'a@example.com', format_valid: true, mx_found: false, overall: 'likely_invalid'},
  dnsTimeout: {email: 'a@example.com', format_valid: true, mx_found: false, overall: 'unverifiable', smtp_message: 'DNS lookup timed out.'},
  full: {email: 'a@example.com', format_valid: true, mx_found: true, mx_records: [[10, 'mx1.example.com'], [20, 'mx2.example.com']],
    smtp_result: 'exists', smtp_message: '250 OK', mx_ptr: {found: true, ptr: 'mx1.example.com'},
    spf: {found: true, policy: 'strict'}, dmarc: {found: true, policy: 'reject'},
    domain_age: {found: true, age_days: 4000, message: 'Domain is 10 years old.', registrar: 'Example Registrar'},
    overall: 'verified', verification_complete: false},
  lite: {email: 'a@example.com', format_valid: true, mx_found: true, mx_records: [], smtp_status: 'skipped', smtp_result: 'unavailable',
    mx_ptr: {found: false}, spf: {found: true, policy: 'softfail'}, dmarc: {found: true, policy: 'none'},
    domain_age: {found: false}, overall: 'domain_valid', verification_complete: false, domain_verification: {complete: true}},
  blocked: {email: 'a@example.com', format_valid: true, mx_found: true, smtp_result: '', smtp_connectable: false,
    mx_ptr: {found: false, message: 'PTR lookup timed out'}, spf: {found: true, policy: 'open'}, dmarc: {found: true, policy: 'quarantine'},
    domain_age: {found: true, age_days: 12, message: 'Registered 12 days ago.'}, overall: 'suspicious', verification_complete: true},
  noResponse: {email: 'a@example.com', format_valid: true, mx_found: true, smtp_result: '', smtp_connectable: true,
    spf: {found: false}, dmarc: {found: false}, overall: 'mystery'},
  transient: {email: 'a@example.com', format_valid: true, mx_found: true, smtp_result: 'temporarily_unavailable', smtp_message: '451 try later',
    spf: {found: true, policy: 'weird'}, dmarc: {found: true, policy: 'odd'}, overall: 'temporarily_unavailable', verification_complete: false},
  missing: {email: 'a@example.com', format_valid: true, mx_found: true, smtp_result: 'does_not_exist', smtp_message: '550 no such user',
    overall: 'likely_invalid'},
  invalidOverall: {email: 'a@example.com', format_valid: true, mx_found: true, smtp_result: 'exists', overall: 'invalid_format'},
};

function verifyScenario(variant) {
  return ({context, elements}) => {
    context.renderVerifyResult(VERIFY_VARIANTS[variant]);
    const out = {verdict: elements.get('verify-verdict').innerHTML, verdictClass: elements.get('verify-verdict').className};
    for (const step of STEPS) out[step] = elements.get(`vstep-${step}-detail`)?.textContent ?? null;
    return out;
  };
}

// ── Other visible strings ────────────────────────────────────────────────────
const CONFIG_VARIANTS = [
  {email_verification_enabled: true, smtp_verification_enabled: false},
  {email_verification_enabled: false, deployment_profile: 'development'},
  {email_verification_enabled: false, deployment_profile: 'production'},
  {},
];

async function requestErrors({context}) {
  const cases = {
    network: async () => { throw new Error('offline'); },
    retrySeconds: async () => ({ok: false, status: 429, headers: {get: () => '37'}}),
    retryUnknown: async () => ({ok: false, status: 429, headers: {get: () => null}}),
    unavailable: async () => ({ok: false, status: 503}),
    missing: async () => ({ok: false, status: 404}),
    unreadable: async () => ({ok: true, status: 200, json: async () => { throw new Error('bad'); }}),
    invalid: async () => ({ok: false, status: 422, json: async () => ({detail: [{msg: 'x'}]})}),
    serverDetail: async () => ({ok: false, status: 400, json: async () => ({detail: 'Server-provided detail.'})}),
  };
  const out = {};
  for (const [name, fetch] of Object.entries(cases)) {
    context.fetch = fetch;
    try { await context.postJSON('/api/x', {}); out[name] = null; } catch (error) { out[name] = error.message; }
  }
  return out;
}

async function inputErrors({context, elements}) {
  context.fetch = async () => { throw new Error('unexpected'); };
  context.document.getElementById('email-input').value = 'hello';
  await context.runEmailAnalysis();
  const out = {email: elements.get('email-error').textContent};
  context.document.getElementById('content-subject').value = '';
  context.document.getElementById('content-body').value = '';
  await context.runContentAnalysis();
  out.content = elements.get('content-error').textContent;
  context.setupInputEvents();
  const change = files => elements.get('raw-email-file').listeners.change({target: {files}});
  let finish;
  const pending = change([{name: 'mail.eml', size: 10, arrayBuffer: () => new Promise(resolve => { finish = resolve; })}]);
  out.reading = elements.get('raw-email-status').textContent;
  await context.runContentAnalysis();
  out.pending = elements.get('content-error').textContent;
  finish(new TextEncoder().encode('From: a@b.test\n\nHi').buffer);
  await pending;
  out.loaded = elements.get('raw-email-status').textContent;
  await change([{name: 'big.eml', size: 3 * 1024 * 1024, arrayBuffer: async () => new ArrayBuffer(1)}]);
  out.tooLarge = elements.get('content-error').textContent;
  await change([{name: 'empty.eml', size: 3, arrayBuffer: async () => new TextEncoder().encode('   ').buffer}]);
  out.empty = elements.get('content-error').textContent;
  await change([{name: 'broken.eml', size: 3, arrayBuffer: async () => { throw new Error('read'); }}]);
  out.unreadable = elements.get('content-error').textContent;
  return out;
}

async function buttons({context, elements}) {
  const out = {};
  let release;
  context.fetch = () => new Promise(resolve => { release = resolve; });
  context.document.getElementById('email-input').value = 'a@example.com';
  const sender = context.runEmailAnalysis();
  out.senderBusy = elements.get('analyze-btn-text').textContent;
  release({ok: true, json: async () => ({...baseSender, disposable_status: 'no_known_match'})});
  await sender;
  out.senderIdle = elements.get('analyze-btn-text').textContent;
  context.document.getElementById('content-subject').value = 'Hi';
  const content = context.runContentAnalysis();
  out.contentBusy = elements.get('content-btn-text').textContent;
  release({ok: true, json: async () => ({...baseContent})});
  await content;
  out.contentIdle = elements.get('content-btn-text').textContent;
  return out;
}

async function copyAndDownload({context, elements}) {
  const out = {};
  const label = {textContent: 'Copy summary'};
  const button = {querySelector: () => label};
  const queue = [];
  const flush = () => queue.splice(0).forEach(fn => fn());
  context.renderResult({...baseSender});
  context.setTimeout = fn => { queue.push(fn); return 0; };
  context.navigator = {clipboard: {writeText: async () => {}}};
  await context.copySummary('sender', button);
  out.copiedLabel = label.textContent;
  flush();
  out.copiedStatus = elements.get('copy-status').textContent;
  out.restoredLabel = label.textContent;
  context.navigator = {clipboard: {writeText: async () => { throw new Error('denied'); }}};
  await context.copySummary('sender', button);
  out.failedLabel = label.textContent;
  flush();
  out.failedStatus = elements.get('copy-status').textContent;
  context.URL = {createObjectURL: () => 'blob:x', revokeObjectURL() {}};
  context.Blob = class { constructor(parts, options) { this.parts = parts; this.type = options.type; } };
  context.document.body = {appendChild() {}};
  context.downloadReport('sender', 'md');
  flush();
  out.downloaded = elements.get('copy-status').textContent;
  context.URL = {createObjectURL: () => { throw new Error('no'); }, revokeObjectURL() {}};
  context.downloadReport('sender', 'md');
  flush();
  out.downloadFailed = elements.get('copy-status').textContent;
  return out;
}

function recentChecks(storage) {
  return ({context, elements}) => {
    const now = Date.now();
    for (const [offset, entry] of [
      [3 * 3_600_000, {mode: 'image', label: 'Medium Risk — Suspicious Content', level: 'medium', score: 40}],
      [5 * 60_000, {mode: 'eml', label: 'Analysis Incomplete — Risk Undetermined', level: 'unknown', score: null}],
      [10_000, {mode: 'content', label: 'High Risk — Likely Phishing', level: 'high', score: 72}],
      [1_000, {mode: 'sender', label: 'Critical Sender Risk', level: 'critical', score: 100, domain: 'paypa1-verify.xyz'}],
      [500, {mode: 'content', label: '', level: 'safe', score: 2}],
    ]) context.recordRecentCheck({...entry, at: now - offset});
    const list = elements.get('recent-checks-list').innerHTML
      .replace(/datetime="[^"]*"/g, 'datetime="…"').replace(/title="[^"]*"/g, 'title="…"');
    const out = {list, count: elements.get('recent-checks-count').textContent, empty: elements.get('recent-checks-empty').textContent,
      stored: storage ? JSON.parse(storage.getItem('phishguard-recent-checks')).map(({at, ...rest}) => rest) : null};
    context.clearRecentChecks();
    out.cleared = elements.get('copy-status').textContent;
    out.emptyAfter = elements.get('recent-checks-empty').textContent;
    return out;
  };
}

function blockedRecent({context, elements}) {
  context.renderRecentChecks();
  return {empty: elements.get('recent-checks-empty').textContent};
}

export const SCENARIOS = {
  ...Object.fromEntries(Object.keys(SENDER_VARIANTS).map(v => [`sender.${v}`, senderScenario(v)])),
  ...Object.fromEntries(Object.keys(CONTENT_VARIANTS).map(v => [`content.${v}`, contentScenario(v)])),
  ...Object.fromEntries(Object.keys(VERIFY_VARIANTS).map(v => [`verify.${v}`, verifyScenario(v)])),
  config: ({context, elements}) => CONFIG_VARIANTS.map(config => {
    context.applyPublicConfig(config);
    return elements.get('verification-local-notice').textContent;
  }),
  metrics: ({context, elements}) => {
    context.renderMetricsTable({
      'Random Forest': {Accuracy: 0.97, Precision: 0.96, Recall: 0.95, F1: 0.94, ROC_AUC: 0.99},
      'Logistic <Regression>': {Accuracy: 0.92, Precision: 0.93, Recall: 0.9, F1: 0.91, ROC_AUC: 0.97},
    });
    return elements.get('metrics-tbody').innerHTML;
  },
  metricsUnavailable: async ({context, elements}) => {
    context.fetch = async () => ({ok: false, status: 500});
    context.console = {error() {}, warn() {}, log() {}};
    await context.loadMetrics();
    return elements.get('metrics-tbody').innerHTML;
  },
  relativeTimes: ({context}) => {
    const now = Date.UTC(2026, 8, 28, 12);
    return [10_000, 5 * 60_000, 59 * 60_000, 3 * 3_600_000, 23 * 3_600_000].map(offset => context.formatRecentTime(now - offset, now));
  },
  requestErrors,
  inputErrors,
  buttons,
  copyAndDownload,
  recent: page => recentChecks(page.storage)(page),
  recentBlocked: blockedRecent,
  mobileMenu: ({context, elements}) => {
    const toggle = new FakeElement();
    const navbar = new FakeElement();
    context.document.getElementById = id => (id === 'nav-menu-toggle' ? toggle : elements.get(id) ?? new FakeElement());
    context.document.querySelector = selector => (selector === '.navbar' ? navbar : new FakeElement());
    context.window.innerWidth = 1200;
    context.setupMobileNav();
    toggle.listeners.click();
    const open = toggle.attributes['aria-label'];
    toggle.listeners.click();
    return {open, closed: toggle.attributes['aria-label']};
  },
  themeTitle: ({context, elements}) => {
    context.document.documentElement = {dataset: {}};
    context.applyTheme('auto');
    const auto = elements.get('theme-toggle').title;
    context.applyTheme('dark');
    return {auto, dark: elements.get('theme-toggle').title};
  },
};

// Some scenarios need special page options.
export const SCENARIO_OVERRIDES = {
  recent: () => { const storage = memoryStorage(); return {options: {localStorage: storage}, storage}; },
  recentBlocked: () => ({options: {localStorage: {getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('x'); }, removeItem() {}}}}),
};

export async function runScenarios(scripts, extraOverrides = {}) {
  const results = {};
  for (const [name, run] of Object.entries(SCENARIOS)) {
    const special = SCENARIO_OVERRIDES[name]?.() ?? {options: {}};
    const page = loadPage(scripts, {...special.options, ...extraOverrides});
    page.storage = special.storage;
    results[name] = await run(page);
  }
  return results;
}

// ── Visual evidence (vision.js) ──────────────────────────────────────────────
class VisionNode {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; this.className = ''; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
}
const describe = node => [node.tag + (node.className ? '.' + node.className : '') + (node.alt ? `[alt=${node.alt}]` : '') +
  (node.textContent ? ': ' + node.textContent : ''), ...node.children.flatMap(child => describe(child).map(line => '  ' + line))];

export const VISION_ANALYSIS = {
  observations: [
    {name: 'invoice.png', source: 'upload', mime_type: 'image/png', status: 'processed', risk_level: 'high', ocr_confidence: 91.6,
      ocr_language: 'eng+chi_sim', ocr_url_line_confidence: 77.2, ml_status: 'available', ml_phishing_probability: 81,
      assessment_method: 'independent-source-max', assessed_source_count: 2, qr_payloads: ['https://paypa1.example/login'],
      ocr_text: 'Verify your account', warnings: ['Server warning A'], assessment_warnings: ['Server warning A', 'Server warning B']},
    {name: 'second.jpg', source: 'email', mime_type: 'image/jpeg', status: 'partial', risk_level: 'unknown', ocr_confidence: 12,
      ocr_language: 'eng', ml_status: 'insufficient_context', qr_payloads: [], ocr_text: ''},
    {name: 'third.webp', status: 'failed', ocr_confidence: 0, ml_status: 'insufficient_feature_coverage', ocr_language: 'chi_sim'},
    {name: 'fourth.png', status: 'skipped', ocr_confidence: 0, ml_status: 'unverified_rendering', ocr_language: 'x'},
    {name: 'fifth.png', status: 'weird', ocr_confidence: 50, ml_status: 'other', ml_phishing_probability: null},
    {name: 'sixth.png', status: 'processed', ocr_confidence: 50, ml_status: 'available', ml_phishing_probability: 10, assessment_method: 'x'},
  ],
  enhancement: {status: 'available', ocr: {engine: 'RapidOCR', version: '1.0', text: 'https://paypal.example'}, url_disagreement: true,
    semantic: {status: 'available', model: 'test-model', observations: ['A login form'], visible_urls: ['https://paypal.example']},
    warnings: ['Enhancement warning']},
  warnings: ['Top-level warning'],
};

export function runVisionScenario(scripts, windowExtras = {}) {
  const window = {...windowExtras};
  const context = vm.createContext({window, document: {createElement: tag => new VisionNode(tag)}, setTimeout, clearTimeout,
    URL: {createObjectURL: () => 'blob:preview', revokeObjectURL() {}}, navigator: {languages: ['en-US']}, console});
  for (const name of scripts) vm.runInContext(source(name), context, {filename: name});
  const render = (analysis, file) => {
    const root = new VisionNode('section');
    window.PhishGuardVision.render(root, analysis, file);
    return describe(root);
  };
  const file = {name: 'invoice.png', size: 10, type: 'image/png'};
  return {
    full: render(VISION_ANALYSIS, file),
    noEnhancement: render({...VISION_ANALYSIS, enhancement: undefined, observations: VISION_ANALYSIS.observations.slice(0, 1)}, file),
    empty: render({observations: [], warnings: []}),
  };
}
