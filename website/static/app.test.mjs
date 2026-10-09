import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

class FakeElement {
  constructor() {
    const classes = new Set();
    this.className = '';
    this.innerHTML = '';
    this.style = {};
    this.textContent = '';
    this.value = '';
    this.listeners = {};
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
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); }
  removeAttribute(name) { if (this.attributes) delete this.attributes[name]; }
  querySelector() { return null; }
  appendChild() {}
  focus() {}
  addEventListener(event, callback) { this.listeners[event] = callback; }
}

// The homepage scripts, in the order index.html loads them. They are classic
// scripts sharing one global scope, so they run in one context like the page.
// i18n.js loads before them (see the script-order test) and provides t().
const APP_SCRIPTS = [
  'app-core.js', 'app-theme.js', 'app-layout.js', 'app-config.js', 'app-sender.js',
  'app-verify.js', 'app-content.js', 'app-content-render.js', 'app-sms.js', 'app-reports.js',
  'app-metrics.js', 'app.js',
];
const appSource = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');

function loadFrontend(overrides = {}) {
  const elements = new Map();
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  const document = {
    addEventListener() {},
    createElement: () => new FakeElement(),
    getElementById,
    querySelector: () => new FakeElement(),
    querySelectorAll: () => [],
  };
  const window = { addEventListener() {}, scrollY: 0,
    PhishGuardVision: { cancel() {}, render() {}, async recognize(file) {
      return {eml_base64: Buffer.from(await file.arrayBuffer()).toString('base64'), observations: [], warnings: []};
    }},
  };
  const context = vm.createContext({ document, window, console, setTimeout: fn => fn(), ...overrides });
  for (const name of ['i18n.js', ...APP_SCRIPTS]) vm.runInContext(appSource(name), context, { filename: name });
  return { context, elements };
}

test('the page loads the homepage scripts in the order the tests run them', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const scripts = [...html.matchAll(/<script src="\/static\/([^"?]+)\?v=[^"]+"><\/script>/g)].map(match => match[1]);
  const start = scripts.indexOf('feedback.js') + 1;
  assert.ok(start > 0);
  assert.deepEqual(scripts.slice(start, start + APP_SCRIPTS.length + 1), [...APP_SCRIPTS, 'analytics-init.js']);
  assert.equal(scripts.filter(name => /^app[-.]/.test(name)).length, APP_SCRIPTS.length);
  // i18n.js is the first script in <body>, so the markup is translated before
  // anything renders, and every later script can call it.
  const body = html.slice(html.indexOf('<body>'));
  const bodyScripts = [...body.matchAll(/<script src="\/static\/([^"?]+)\?v=[^"]+"><\/script>/g)].map(match => match[1]);
  assert.equal(bodyScripts[0], 'i18n.js');
  assert.equal(bodyScripts[1], 'vision.js');
  // lang-init.js sets <html lang> in <head>, right after the theme bootstrap.
  const head = html.slice(0, html.indexOf('</head>'));
  assert.match(head, /<script src="\/static\/theme-init\.js\?v=\d+"><\/script>\s*<script src="\/static\/lang-init\.js\?v=\d+"><\/script>/);
});

test('feedback diagnostics retain signal identifiers without source-bearing messages', () => {
  const {context} = loadFrontend();
  const sender = context.feedbackAnalysis({verdict:'high', risk_score:70, label:'High Sender Risk',
    risk_indicators:[{level:'high', msg:'Address alice@example.test is suspicious'}],
    feature_breakdown:[{name:'known_provider', value:-1}, {name:'address_length', value:1}]}, true);
  assert.deepEqual(Array.from(sender.evidence_codes), ['known_provider']);
  assert.doesNotMatch(JSON.stringify(sender), /alice@example\.test/);
  const content = context.feedbackAnalysis({risk_level:'medium', risk_label:'Medium Risk',
    category_results:[{key:'credential_request', matched:['private phrase']}],
    extra_indicators:[{level:'high', msg:'Private destination https://example.test'}]});
  assert.deepEqual(Array.from(content.evidence_codes), ['credential_request']);
  assert.doesNotMatch(JSON.stringify(content), /private phrase|https:\/\/example\.test/);
});

test('public reporting actions follow the server availability flag', () => {
  const {context} = loadFrontend();
  const rows = [{hidden:true}, {hidden:true}];
  context.document.querySelectorAll = selector => selector === '.result-report' ? rows : [];
  context.applyPublicConfig({feedback_enabled:true});
  assert.deepEqual(rows.map(row => row.hidden), [false, false]);
  context.applyPublicConfig({feedback_enabled:false});
  assert.deepEqual(rows.map(row => row.hidden), [true, true]);
});

test('image understanding requires an enabled enhanced image upload', async () => {
  const {context, elements} = loadFrontend();
  context.setupInputEvents();
  context.applyPublicConfig({enhanced_vision_enabled:true, enhanced_vision_semantics_enabled:true});
  const enhanced = elements.get('content-enhanced-vision');
  const semantics = elements.get('content-image-understanding');
  assert.equal(enhanced.disabled, true);
  assert.equal(semantics.disabled, true);
  await elements.get('raw-email-file').listeners.change({target:{files:[{
    name:'message.png', type:'image/png', size:1,
    arrayBuffer:async()=>new Uint8Array([1]).buffer,
  }]}});
  assert.equal(enhanced.disabled, false);
  assert.equal(semantics.disabled, true);
  enhanced.checked = true;
  enhanced.listeners.change();
  assert.equal(semantics.disabled, false);
  semantics.checked = true;
  enhanced.checked = false;
  enhanced.listeners.change();
  assert.equal(semantics.checked, false);
  assert.equal(semantics.disabled, true);
});

test('a pending score animation cannot overwrite a newer zero score', () => {
  let frames = [];
  const { context } = loadFrontend({
    performance: { now: () => 0 },
    requestAnimationFrame: fn => frames.push(fn),
  });
  const number = new FakeElement();
  context.animateNumber(number, 100, value => `${Math.round(value)}/100`);
  context.animateNumber(number, 0, value => `${Math.round(value)}/100`);
  frames.splice(0).forEach(fn => fn(2000));
  assert.equal(number.textContent, '0/100');
});

test('content summary handles zero, singular, and plural categories', () => {
  const { context, elements } = loadFrontend();
  const makeCategory = () => ({
    level: 'high',
    icon: '!',
    label: 'Urgency',
    count: 1,
    description: 'Urgent language',
    matched: ['urgent'],
  });
  const render = categoryResults => context.renderContentResult({
    risk_level: 'high',
    risk_label: 'High risk',
    total_score: 10,
    category_results: categoryResults,
    extra_indicators: [],
    safety_signals: [],
  });

  render([]);
  assert.match(elements.get('crb-sub').textContent, /risk detected/i);

  render([makeCategory()]);
  assert.equal(elements.get('crb-sub').textContent, '1 suspicious category detected.');

  render([makeCategory(), makeCategory()]);
  assert.equal(elements.get('crb-sub').textContent, '2 suspicious categories detected.');
});

test('image-only results do not present empty email-body analysis as OCR failure', () => {
  const {context, elements} = loadFrontend();
  const result = {risk_level:'unknown', risk_label:'Analysis Incomplete — Risk Undetermined',
    total_score:0, category_results:[], extra_indicators:[], safety_signals:[],
    analysis_complete:false, ml_status:'insufficient_context', ml_label:null,
    input_mode:'image-evidence', visual_analysis:{observations:[{
      status:'processed', ocr_text:'A community newsletter with a long readable message.',
      ocr_confidence:92, ml_status:'available', ml_phishing_probability:12,
    }]}};
  context.renderContentResult(result);
  assert.equal(elements.get('content-ml-card').style.display, 'none');
  assert.equal(elements.get('content-category-grid').style.display, 'none');
  assert.doesNotMatch(elements.get('crb-sub').textContent, /text model could not score this message/);
  assert.match(elements.get('crb-sub').textContent, /Image & QR evidence/);
  assert.match(elements.get('crb-title').textContent, /[Uu]ndetermined/);
  context.renderContentResult({...result, input_mode:'manual', visual_analysis:undefined});
  assert.equal(elements.get('content-ml-card').style.display, '');
  assert.equal(elements.get('content-category-grid').style.display, '');
  assert.match(elements.get('content-ml-sub').textContent, /too little text/);
});

test('Null MX explains no mail service without claiming phishing or a missing mailbox', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({email: 'user@example.com', format_valid: true, mx_found: false,
    null_mx: true, overall: 'no_mail_service', verification_complete: false,
    smtp_message: 'Domain publishes Null MX: it does not accept email.'});
  assert.match(elements.get('verify-verdict').innerHTML, /No Mail Service/);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /Likely Invalid|probably does not exist/);
  assert.match(elements.get('vstep-mx').className, /vstep-info/);
});

test('partial verification preserves SMTP result while showing incomplete checks', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({email: 'user@example.com', format_valid: true, mx_found: true,
    overall: 'verified', smtp_result: 'exists', verification_complete: false,
    domain_age: {found: false, status: 'timeout', message: 'WHOIS lookup failed.'}});
  assert.match(elements.get('verify-verdict').innerHTML, /Verification Incomplete/);
  assert.match(elements.get('verify-verdict').innerHTML, /server accepted/i);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /mailbox exists and can receive/);
  assert.match(elements.get('verify-verdict').className, /vv-warn/);
});

test('DNS timeout remains unverifiable rather than an invalid mailbox', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({email: 'user@example.com', format_valid: true, mx_found: false,
    overall: 'unverifiable', verification_complete: false, smtp_message: 'DNS lookup timed out.'});
  assert.match(elements.get('vstep-mx').className, /vstep-warn/);
  assert.match(elements.get('verify-verdict').innerHTML, /Unverifiable/);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /Likely Invalid|records are real/i);
});

test('lite result presents domain evidence without claiming mailbox verification', () => {
  const { context, elements } = loadFrontend();
  context.renderVerifyResult({
    email: 'user@example.com',
    format_valid: true,
    mx_found: true,
    mx_records: [[10, 'mx.example.com']],
    smtp_result: 'unavailable',
    smtp_status: 'skipped',
    smtp_message: 'SMTP mailbox probing is unavailable on this deployment.',
    overall: 'domain_valid',
    verification_complete: false,
    domain_verification: { status: 'valid', complete: true },
    mailbox_verification: { status: 'unavailable' },
    spf: { found: true, policy: 'strict', message: 'Strict SPF.' },
    dmarc: { found: true, policy: 'reject', message: 'Reject DMARC.' },
    mx_ptr: { found: true, message: 'PTR found.' },
    domain_age: { found: true, age_days: 365, message: 'Established domain.' },
  });

  assert.match(elements.get('vstep-smtp').className, /vstep-info/);
  assert.match(elements.get('verify-verdict').innerHTML, /Domain Valid/);
  assert.match(elements.get('verify-verdict').innerHTML, /mailbox.*not verified/i);
  assert.doesNotMatch(elements.get('verify-verdict').innerHTML, /SMTP Accepted/);
});

test('incomplete analysis is not displayed as zero risk and cancels old animation', () => {
  const frames = [];
  const { context, elements } = loadFrontend({
    performance: { now: () => 0 }, requestAnimationFrame: fn => frames.push(fn),
  });
  const data = { total_score: 0, category_results: [], extra_indicators: [], safety_signals: [] };
  context.renderContentResult({ ...data, risk_level: 'high', risk_label: 'High', combined_phishing_score: 55 });
  context.renderContentResult({ ...data, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null });
  frames.splice(0).forEach(fn => fn(2000));
  assert.equal(elements.get('crb-score').textContent, '—');
  assert.match(elements.get('crb-sub').textContent, /incomplete/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /risk detected|no indicators detected/i);
  context.renderContentResult({ ...data, risk_level: 'high', risk_label: 'High',
    analysis_complete: false, combined_phishing_score: 55 });
  assert.equal(elements.get('crb-title').textContent, 'High');
  assert.match(elements.get('crb-sub').textContent, /incomplete/i);
});

test('attachment coverage is distinguished from parser and model limitations', () => {
  const { context, elements } = loadFrontend();
  const data = { total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null };
  context.renderContentResult({ ...data, message_structure: { attachments: [
    { filename: 'chart.png', content_type: 'image/png', inspection_status: 'metadata_only' }
  ], parse_warnings: [] } });
  assert.match(elements.get('crb-sub').textContent, /attachment contents were not inspected/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /could not be reliably parsed/i);
  assert.equal(elements.get('crb-score').textContent, '—');

  context.renderContentResult({ ...data, message_structure: {
    attachments: [], parse_warnings: ['MIME structure is malformed.']
  } });
  assert.match(elements.get('crb-sub').textContent, /could not be reliably parsed/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /attachment contents/i);

  context.renderContentResult({ ...data, ml_status: 'insufficient_context', message_structure: {
    attachments: [], parse_warnings: []
  } });
  assert.match(elements.get('crb-sub').textContent, /text model/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /could not be reliably parsed/i);

  context.renderContentResult({ ...data,
    analysis_warnings: ['Attached message: Attachment content was not inspected; only filenames and MIME types were checked.'],
    message_structure: { attachments: [
      { filename: 'forwarded.eml', content_type: 'message/rfc822', inspection_status: 'message_analyzed' }
    ], parse_warnings: [] } });
  assert.match(elements.get('crb-sub').textContent, /attachment contents were not inspected/i);
});

test('embedded image coverage has distinct incomplete-analysis wording', () => {
  const { context, elements } = loadFrontend();
  const data = { total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null, inline_image_coverage: { count: 1, inspection_status: 'metadata_only' } };
  context.renderContentResult(data);
  assert.match(elements.get('crb-sub').textContent, /embedded image content was not inspected/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /attachment contents|reliably parsed|text model/i);
  assert.equal(elements.get('crb-score').textContent, '—');
});

test('remote image coverage explains that image content was not inspected', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null, remote_image_coverage: { count: 1, inspection_status: 'metadata_only' } });
  assert.match(elements.get('crb-sub').textContent, /remote image content was not inspected/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /embedded image content was not inspected/i);
});

test('unresolved image coverage explains that referenced image content was not inspected', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: false, risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    combined_phishing_score: null, unresolved_image_coverage: { count: 1, inspection_status: 'metadata_only' } });
  assert.match(elements.get('crb-sub').textContent, /unresolved image references were not inspected/i);
});

test('model-only high result explains that independent evidence is absent', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: true, risk_level: 'high', risk_label: 'High Risk — Model Signal Needs Review',
    combined_phishing_score: 84.2, fusion_basis: 'model_only',
    ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 84.2,
    ml_legitimate_probability: 15.8, ml_prediction: 1, ml_top_contributors: [], ml_metrics: {} });
  assert.match(elements.get('crb-sub').textContent, /model-only.*no independent/i);
});

test('an original email whose text model alone flags it shows a note, not an alert', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 0, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: true, risk_level: 'low', risk_label: 'Low Risk — Text Model Signal Only',
    combined_phishing_score: 29, fusion_basis: 'model_only', input_mode: 'raw-email',
    ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 84.2,
    ml_legitimate_probability: 15.8, ml_prediction: 1, ml_top_contributors: [], ml_metrics: {} });
  // The model's own reading stays visible beside the note.
  assert.match(elements.get('crb-sub').textContent,
    /84\.2%.*Text-model signal only: with no rule, sender, or link evidence in the original email it is a note, not an alert/);
  assert.equal(elements.get('crb-score').textContent, '29%');
});

test('model-led high result distinguishes weak rules from strong corroboration', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ total_score: 1, category_results: [], extra_indicators: [], safety_signals: [],
    analysis_complete: true, risk_level: 'high', risk_label: 'High Risk — Model Signal Needs Review',
    combined_phishing_score: 95.8, fusion_basis: 'model_led',
    ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 95.8,
    ml_legitimate_probability: 4.2, ml_prediction: 1, ml_top_contributors: [], ml_metrics: {} });
  assert.match(elements.get('crb-sub').textContent, /model-led.*no strong independent/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /combined analysis/i);
});

test('content model abstention is shown without probability bars', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'insufficient_feature_coverage', ml_label: null,
    ml_phishing_probability: null, ml_legitimate_probability: null,
    ml_prediction: null, ml_top_contributors: [],
  });

  assert.equal(elements.get('content-ml-card').style.display, '');
  assert.equal(elements.get('content-ml-prob-bars').style.display, 'none');
  assert.match(elements.get('content-ml-sub').textContent, /coverage.*not applied/i);
  assert.equal(elements.get('content-phish-bar').style.width, '0%');
  assert.equal(elements.get('content-legit-bar').style.width, '0%');
  assert.equal(elements.get('content-phish-pct').textContent, '—');
  assert.equal(elements.get('content-legit-pct').textContent, '—');
});

test('short-message abstention explains that the text is insufficient', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'insufficient_context', ml_label: null,
    ml_phishing_probability: null, ml_legitimate_probability: null,
    ml_prediction: null, ml_top_contributors: [],
  });

  assert.equal(elements.get('content-ml-card').style.display, '');
  assert.equal(elements.get('content-ml-prob-bars').style.display, 'none');
  assert.match(elements.get('content-ml-sub').textContent, /too little text.*not applied/i);
  assert.equal(elements.get('content-phish-pct').textContent, '—');
  assert.equal(elements.get('content-legit-pct').textContent, '—');
});

test('unverified rendering abstention is explicit and has no stale score bars', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'unknown', risk_label: 'Analysis Incomplete — Risk Undetermined',
    analysis_complete: false, combined_phishing_score: null, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    analysis_warnings: ['A stylesheet may hide or reveal text.'],
    ml_status: 'unverified_rendering', ml_label: null,
    ml_phishing_probability: null, ml_legitimate_probability: null,
    ml_prediction: null, ml_top_contributors: [],
  });

  assert.equal(elements.get('content-ml-prob-bars').style.display, 'none');
  assert.match(elements.get('content-ml-sub').textContent, /CSS visibility or image fallback.*not applied/i);
  assert.match(elements.get('crb-sub').textContent, /text model could not score/i);
  assert.match(elements.get('content-ml-contribs').innerHTML, /Uncertain HTML text was withheld/i);
  assert.equal(elements.get('content-phish-pct').textContent, '—');
  assert.equal(elements.get('content-legit-pct').textContent, '—');
});

test('available content model output is labelled a risk score not confidence', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({
    risk_level: 'high', risk_label: 'High', analysis_complete: true,
    combined_phishing_score: 72, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'available', ml_label: 'Likely Phishing',
    ml_phishing_probability: 72, ml_legitimate_probability: 28,
    ml_prediction: 1, ml_top_contributors: [], ml_metrics: {},
  });

  assert.match(elements.get('content-ml-sub').textContent, /model risk score 72\.0%/i);
  assert.equal(elements.get('content-ml-prob-bars').style.display, '');
  assert.doesNotMatch(elements.get('content-ml-sub').textContent, /confidence/i);
  assert.match(elements.get('crb-sub').textContent, /ML risk score: 72%/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /% phishing/i);
});

test('content analysis copy does not describe model output as probability', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');

  assert.doesNotMatch(html, /group-isolated probability/i);
  assert.match(html, /group-isolated model score/i);
});

test('benchmark cells carry column labels for the stacked phone layout', () => {
  const { context, elements } = loadFrontend();
  context.renderMetricsTable({
    'Random Forest': { Accuracy: 0.97, Precision: 0.96, Recall: 0.95, F1: 0.94, ROC_AUC: 0.99 },
  });
  const html = elements.get('metrics-tbody').innerHTML;
  for (const label of ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC AUC']) {
    assert.match(html, new RegExp(`data-label="${label}"`));
  }
  assert.doesNotMatch(html, /data-label="ROC_AUC"/);
});

test('benchmark chart colours follow the active theme', () => {
  const { context } = loadFrontend();
  const config = () => ({
    data: { datasets: [{}, {}] },
    options: {
      plugins: { legend: { labels: {} }, tooltip: {} },
      scales: { y: { ticks: {}, grid: {} }, x: { ticks: {} } },
    },
  });
  const dark = config();
  context.applyChartTheme(dark);
  assert.equal(dark.data.datasets[0].backgroundColor, 'rgba(79,209,255,0.80)');

  const tokens = { '--text-muted': '#56627a', '--text': '#0f172a' };
  context.document.documentElement = { dataset: { theme: 'light' } };
  context.getComputedStyle = () => ({ getPropertyValue: name => tokens[name] || '' });
  const light = config();
  context.applyChartTheme(light);
  assert.equal(light.data.datasets[0].backgroundColor, 'rgba(10,127,214,0.80)');
  assert.equal(light.options.scales.x.ticks.color, '#56627a');
  assert.equal(light.options.plugins.tooltip.titleColor, '#0f172a');
});

test('case login stays on the stable deployment except on a local server', () => {
  const { context } = loadFrontend();
  const deployed = 'https://phishguard-email-analyzer.vercel.app/cases';
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    assert.equal(context.caseLoginHref(host, deployed), '/cases');
  }
  for (const host of ['phishguard-email-analyzer.vercel.app', 'preview-abc.vercel.app', 'localhost.example']) {
    assert.equal(context.caseLoginHref(host, deployed), deployed);
  }
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /class="case-login" href="https:\/\/phishguard-email-analyzer\.vercel\.app\/cases"/);
});

test('view transitions wrap updates when supported and fall back to a direct update', async () => {
  const { context } = loadFrontend();
  const calls = [];
  context.withViewTransition(() => calls.push('update'), () => calls.push('done'));
  assert.deepEqual(calls, ['update', 'done']);

  calls.length = 0;
  context.document.startViewTransition = update => {
    calls.push('start'); update();
    return { finished: Promise.resolve() };
  };
  context.withViewTransition(() => calls.push('update'), () => calls.push('done'));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ['start', 'update', 'done']);

  calls.length = 0;
  context.matchMedia = () => ({ matches: true });
  context.withViewTransition(() => calls.push('update'), () => calls.push('done'));
  assert.deepEqual(calls, ['update', 'done']);
});

test('loading states render a result-shaped skeleton', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.equal((html.match(/<div class="skeleton" aria-hidden="true">/g) || []).length, 2);
  assert.doesNotMatch(html, /class="loading-spinner"/);
  assert.ok(html.indexOf('id="loading-area"') < html.indexOf('id="result-area"'));
});

test('homepage uses SVG icons instead of glyphs and links the renamed repository', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const js = APP_SCRIPTS.map(appSource).join('\n');
  assert.doesNotMatch(html, /[✓✕]/);
  assert.doesNotMatch(js, /safety-dot">✓/);
  assert.doesNotMatch(html, /CS-166-Final-Project/);
  assert.match(html, /github\.com\/Lushangtu123\/Phishing-Scam-Email-Detection"/);
  assert.match(html, /class="case-login-link" href="https:\/\/phishguard-email-analyzer\.vercel\.app\/cases"/);
});

test('score breakdown reproduces the sender score and hides on drift', () => {
  const { context, elements } = loadFrontend();
  const indicators = [
    { level: 'medium', msg: 'Unrecognized provider' },
    { level: 'high', msg: 'Homoglyph <b>paypa1</b>' },
    { level: 'low', msg: 'Hyphen in domain' },
    { level: 'info', msg: 'Plus alias' },
  ];
  const breakdown = context.senderScoreBreakdown({ risk_indicators: indicators, risk_score: 41 });
  assert.equal(breakdown.raw, 41);
  assert.equal(breakdown.consistent, true);
  assert.deepEqual(Array.from(breakdown.rows, row => row.points), [28, 10, 3]);

  context.renderScoreBreakdown({ risk_indicators: indicators, risk_score: 41 });
  assert.equal(elements.get('score-breakdown').hidden, false);
  assert.match(elements.get('score-breakdown-list').innerHTML, /Homoglyph &lt;b&gt;paypa1&lt;\/b&gt;/);
  assert.match(elements.get('score-breakdown-formula').textContent, /1 high × 28 \+ 1 medium × 10 \+ 1 low × 3 = 41\./);

  const capped = Array.from({ length: 4 }, () => ({ level: 'high', msg: 'x' }));
  context.renderScoreBreakdown({ risk_indicators: capped, risk_score: 100 });
  assert.match(elements.get('score-breakdown-formula').textContent, /= 112, capped at 100\./);

  context.renderScoreBreakdown({ risk_indicators: indicators, risk_score: 55 });
  assert.equal(elements.get('score-breakdown').hidden, true);
});

test('copy summaries describe the result without HTML and carry the disclaimer', async () => {
  let copied = '';
  const { context } = loadFrontend({
    navigator: { clipboard: { writeText: async text => { copied = text; } } },
    setTimeout: () => 0, clearTimeout: () => {},
  });
  context.renderResult({
    email: 'a@paypa1-verify.xyz', verdict: 'critical', label: 'Critical Sender Risk', risk_score: 100,
    risk_indicators: [{ level: 'high', msg: 'Homoglyph attack' }, { level: 'info', msg: 'note' }],
    feature_breakdown: [], high_risk_count: 1, med_risk_count: 0, phish_feature_count: 1,
    disposable_status: 'no_known_match',
  });
  const label = { textContent: 'Copy summary' };
  await context.copySummary('sender', { querySelector: () => label });
  assert.match(copied, /^PhishGuard sender check: a@paypa1-verify\.xyz\nVerdict: Critical Sender Risk \(100\/100\)/);
  assert.match(copied, /- \[high\] Homoglyph attack/);
  assert.doesNotMatch(copied, /note/);
  assert.match(copied, /does not prove a message is safe or malicious/);
  assert.equal(label.textContent, 'Copied');

  assert.match(context.contentSummaryText({
    risk_label: 'High Risk', combined_phishing_score: 72.4, total_score: 9,
    category_results: [{ label: 'Urgency', level: 'high', count: 2 }], extra_indicators: [],
  }), /Verdict: High Risk \(72% risk\)\nCategories:\n- Urgency \(high, 2 signals\)/);
});

test('scripts are same-origin and the vendored chart library matches its integrity pin', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const sources = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map(match => match[1]);
  assert.ok(sources.length > 0);
  for (const src of sources) assert.match(src, /^\/(static|_vercel)\//, src);
  // Chart.js is not in the initial HTML; app-metrics.js inserts it on demand
  // with the same same-origin URL and SRI pin.
  assert.doesNotMatch(html, /chart\.umd/);
  const metrics = appSource('app-metrics.js');
  const src = metrics.match(/const CHART_SRC = '\/static\/(vendor\/chart\/chart\.umd\.min\.js)\?v=[^']+';/);
  const integrity = metrics.match(/const CHART_INTEGRITY = '(sha384-[A-Za-z0-9+/]{64})';/);
  assert.ok(src && integrity, 'vendored Chart.js keeps its SRI pin');
  const bytes = readFileSync(new URL(`./${src[1]}`, import.meta.url));
  assert.equal(`sha384-${createHash('sha384').update(bytes).digest('base64')}`, integrity[1]);
});

test('the hidden clear control leaves the tab order and is a usable touch target when shown', () => {
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  const hidden = css.match(/\n\.btn-clear \{([^}]*)\}/)[1];
  const shown = css.match(/\n\.btn-clear\.visible \{([^}]*)\}/)[1];
  assert.match(hidden, /visibility:\s*hidden/);
  assert.match(shown, /visibility:\s*visible/);
  assert.match(hidden, /min-height:\s*(4[4-9]|[5-9]\d)px/);
});

test('light-theme section eyebrows meet WCAG AA text contrast on the page background', () => {
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  const light = css.match(/:root\[data-theme="light"\] \{([^}]*)\}/)[1];
  const background = light.match(/--bg:\s*(#[0-9a-f]{6})/i)[1];
  const eyebrow = css.match(/:root\[data-theme="light"\] \.section-eyebrow \{ color: (#[0-9a-f]{6}); \}/i)[1];
  const luminance = hex => {
    const [r, g, b] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
      .map(v => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const [hi, lo] = [luminance(background), luminance(eyebrow)].sort((a, b) => b - a);
  assert.ok((hi + 0.05) / (lo + 0.05) >= 4.5, `${eyebrow} on ${background}`);
});

test('homepage has no inline scripts or inline event handlers', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
});

test('every declared page action calls the handler its inline attribute used to call', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const declared = [...html.matchAll(/data-action="([^"]+)"(?:[^>]*?data-arg="([^"]*)")?/g)]
    .map(([, action, arg]) => ({ action, arg }));
  assert.equal(declared.length, 40);
  const controls = declared.map(({ action, arg }) =>
    Object.assign(new FakeElement(), { dataset: arg === undefined ? { action } : { action, arg } }));
  const elements = new Map();
  const document = {
    addEventListener() {},
    createElement: () => new FakeElement(),
    getElementById: id => elements.get(id) ?? elements.set(id, new FakeElement()).get(id),
    querySelector: () => new FakeElement(),
    querySelectorAll: selector => selector === '[data-action]' ? controls : [],
  };
  const { context } = loadFrontend({ document });
  const calls = [];
  for (const name of ['cycleTheme', 'switchDemoTab', 'clearEmail', 'runEmailAnalysis', 'cancelEmailAnalysis', 'setExample', 'copySummary',
    'openFeedback', 'runVerification', 'clearContent', 'runContentAnalysis', 'setContentExample',
    'clearSms', 'runSmsAnalysis', 'setSmsExample', 'downloadReport', 'clearRecentChecks']) {
    context[name] = (...args) => calls.push([name, ...args]);
  }
  context.setupPageActions();

  const expected = {
    'cycle-theme': (_arg, event) => ['cycleTheme', event],
    'switch-tab': arg => ['switchDemoTab', arg],
    'clear-email': () => ['clearEmail'],
    'analyze-email': () => ['runEmailAnalysis'],
    'cancel-email': () => ['cancelEmailAnalysis'],
    'set-example': arg => ['setExample', arg],
    'copy-summary': (arg, event) => ['copySummary', arg, event.currentTarget],
    'open-feedback': arg => ['openFeedback', arg],
    'verify-email': () => ['runVerification'],
    'clear-content': () => ['clearContent'],
    'analyze-content': () => ['runContentAnalysis'],
    'set-content-example': arg => ['setContentExample', arg],
    'clear-sms': () => ['clearSms'],
    'analyze-sms': () => ['runSmsAnalysis'],
    'set-sms-example': arg => ['setSmsExample', arg],
    'download-report': arg => ['downloadReport', ...arg.split(':')],
    'clear-recent': () => ['clearRecentChecks'],
  };
  controls.forEach((control, index) => {
    const event = { currentTarget: control };
    calls.length = 0;
    assert.equal(typeof control.listeners.click, 'function', control.dataset.action);
    control.listeners.click(event);
    assert.deepEqual(calls, [expected[control.dataset.action](declared[index].arg, event)], control.dataset.action);
  });
  assert.ok(declared.some(({ action, arg }) => action === 'set-example' && arg === 'security-alert@paypa1-verify.xyz'));
  for (const kind of ['sender', 'content']) {
    for (const format of ['md', 'json']) {
      assert.ok(declared.some(({ action, arg }) => action === 'download-report' && arg === `${kind}:${format}`), `${kind}:${format}`);
    }
  }

  calls.length = 0;
  elements.get('email-input').listeners.keydown({ key: 'a' });
  elements.get('email-input').listeners.keydown({ key: 'Enter' });
  assert.deepEqual(calls, [['runEmailAnalysis']]);
});

test('demo tabs expose tab semantics and keep aria-selected in sync', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /<div class="demo-tabs" role="tablist" aria-label="[^"]+"[^>]*>/);
  for (const name of ['email-address', 'email-content', 'sms']) {
    assert.match(html, new RegExp(`id="tab-${name}"[^>]*role="tab"[^>]*aria-controls="panel-${name}"`));
    assert.match(html, new RegExp(`id="panel-${name}" role="tabpanel" aria-labelledby="tab-${name}"`));
  }
  assert.equal((html.match(/aria-selected="true"/g) || []).length, 1);

  const tabs = { 'email-address': new FakeElement(), 'email-content': new FakeElement() };
  tabs['email-address'].classList.add('active');
  const document = {
    addEventListener() {},
    createElement: () => new FakeElement(),
    getElementById: id => tabs[id.replace(/^tab-/, '')] ?? new FakeElement(),
    querySelector: () => new FakeElement(),
    querySelectorAll: selector => selector === '.demo-tab' ? Object.values(tabs) : [],
  };
  const { context } = loadFrontend({ document });
  context.switchDemoTab('email-content');
  assert.equal(tabs['email-content'].attributes['aria-selected'], 'true');
  assert.equal('tabindex' in tabs['email-content'].attributes, false);
  assert.equal(tabs['email-address'].attributes['aria-selected'], 'false');
  assert.equal(tabs['email-address'].attributes.tabindex, '-1');
});

test('the SMS tab appears only when enabled, and renders the sender kind, claim and findings', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /id="tab-sms"[^>]*\bhidden>/);
  const { context, elements } = loadFrontend();
  context.applySmsConfig({ sms_analysis_enabled: false });
  assert.equal(elements.get('tab-sms').hidden, true);
  context.applySmsConfig({ sms_analysis_enabled: true });
  assert.equal(elements.get('tab-sms').hidden, false);

  context.renderSmsResult({ risk_level: 'high', risk_label: 'High Risk — Likely a Scam Text', sender_kind: 'email',
    claimed_brand: 'United States Postal Service', category_results: [], official_channels: [],
    extra_indicators: [{ level: 'high', code: 'sms.sender_mismatch', params: { brand: 'United States Postal Service' },
      msg: 'The text says it is from United States Postal Service, but it was sent from a personal or foreign number or an email address, not from the organisation\'s own service numbers. Check through its official app or website.' }] });
  assert.equal(elements.get('sms-sender-kind').textContent, 'Sender: an email address');
  assert.equal(elements.get('sms-claimed').textContent, 'Says it is from: United States Postal Service');
  assert.equal(elements.get('sms-sender-note').hidden, false);
  assert.match(elements.get('sms-sender-note').textContent, /email address or a number abroad/);
  assert.match(elements.get('sms-extra-list').innerHTML, /sent from a personal or foreign number/);
  assert.equal(elements.get('sms-result-area').classList.contains('hidden'), false);

  context.renderSmsResult({ risk_level: 'unknown', risk_label: 'No Known Scam Signs Found', sender_kind: 'short_code',
    claimed_brand: null, category_results: [], official_channels: [], extra_indicators: [] });
  assert.equal(elements.get('sms-banner-sub').textContent,
    'No rule found a known scam sign. This does not show that the text is safe.');
  assert.equal(elements.get('sms-claimed').hidden, true);
  assert.equal(elements.get('sms-sender-note').hidden, true, 'no note for a short code');
  assert.equal(elements.get('sms-extra-card').hidden, true);
  assert.deepEqual({ ...context.smsRecentEntry({ risk_level: 'unknown', risk_label: 'x' }), at: 0 },
    { mode: 'sms', label: 'x', level: 'unknown', score: null, at: 0 });
});

test('homepage has a skip link, a main landmark, a named sender input and ordered headings', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /<body>\s*<a class="skip-link" href="#main">/);
  assert.equal((html.match(/<main id="main" tabindex="-1">/g) || []).length, 1);
  assert.ok(html.indexOf('<main id="main"') < html.indexOf('id="demo"'));
  assert.ok(html.indexOf('</main>') < html.indexOf('<footer'));
  assert.match(html, /id="email-input"\s+aria-label="[^"]+"/);
  const levels = [...html.matchAll(/<h([1-6])\b/g)].map(match => Number(match[1]));
  levels.reduce((previous, level) => {
    assert.ok(level <= previous + 1, `heading jumps from h${previous} to h${level}`);
    return level;
  }, 0);
});

test('narrow-screen section menu is wired to the collapsible link list', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /<ul class="nav-links" id="nav-links">/);
  assert.match(html, /id="nav-menu-toggle"[^>]*aria-expanded="false"[^>]*aria-controls="nav-links"/);
});

test('HTML page loads enabled Vercel observability scripts from this site', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const queues = readFileSync(new URL('./analytics-init.js', import.meta.url), 'utf8');
  assert.match(queues, /window\.va\s*=\s*window\.va\s*\|\|/);
  assert.match(queues, /window\.si\s*=\s*window\.si\s*\|\|/);
  const queuesAt = html.indexOf('src="/static/analytics-init.js');
  assert.ok(queuesAt > 0, 'queue script is loaded');
  assert.match(html, /src="\/_vercel\/insights\/script\.js"/);
  assert.match(html, /src="\/_vercel\/speed-insights\/script\.js"/);
  assert.ok(queuesAt < html.indexOf('src="/_vercel/insights/script.js"'), 'queues exist before the collectors load');
  assert.ok(queuesAt < html.indexOf('src="/_vercel/speed-insights/script.js"'), 'queues exist before the collectors load');
  assert.doesNotMatch(html, /@vercel\/(analytics|speed-insights)\/next/);
});

test('content input explains server processing and pseudonymous sender retention', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');

  assert.match(html, /processed on this server/i);
  assert.match(html, /does not retain.*message body.*attachment content/is);
  assert.match(html, /pseudonymous sender observation/i);
  assert.match(html, /remove unrelated personal content/i);
});

const senderResult = email => ({
  email, verdict: 'low', label: 'Low Sender Risk', risk_score: 0,
  risk_indicators: [], feature_breakdown: [], high_risk_count: 0, med_risk_count: 0,
});
const contentResult = label => ({
  risk_level: 'safe', risk_label: label, total_score: 0,
  category_results: [], extra_indicators: [], safety_signals: [],
});
const response = data => ({ ok: true, json: async () => data });
const emlBytes = text => new TextEncoder().encode(text).buffer;
function deferredFetch() {
  const pending = [];
  return { pending, fetch: () => new Promise(resolve => pending.push(resolve)) };
}

test('late sender response cannot replace the latest result or undo clearing', async () => {
  const network = deferredFetch();
  const { context, elements } = loadFrontend({ fetch: network.fetch });
  const input = context.document.getElementById('email-input');
  input.value = 'first@gmail.com';
  const first = context.runEmailAnalysis();
  input.value = 'second@outlook.com';
  const second = context.runEmailAnalysis();
  network.pending[1](response(senderResult(input.value)));
  await second;
  network.pending[0](response(senderResult('first@gmail.com')));
  await first;
  assert.equal(elements.get('vb-email').textContent, 'second@outlook.com');
  const third = context.runEmailAnalysis();
  context.clearEmail();
  network.pending[2](response(senderResult('second@outlook.com')));
  await third;
  assert.equal(elements.get('result-area').classList.contains('hidden'), true);
});

test('late verification cannot render for another sender', async () => {
  const network = deferredFetch();
  const { context } = loadFrontend({ fetch: network.fetch });
  context.applyPublicConfig({ email_verification_enabled: true });
  context.renderResult(senderResult('first@gmail.com'));
  let rendered = false;
  context.renderVerifyResult = () => { rendered = true; };
  const pending = context.runVerification();
  context.renderResult(senderResult('second@outlook.com'));
  network.pending[0](response({ email: 'first@gmail.com', format_valid: true }));
  await pending;
  assert.equal(rendered, false);
});

test('verification HTTP failures show actionable errors, not a mailbox verdict', async () => {
  for (const [status, expected] of [[429, /37 seconds/i], [503, /unavailable/i], [404, /unavailable/i]]) {
    const { context, elements } = loadFrontend({ fetch: async () => ({
      ok: false, status, headers: { get: () => '37' },
      json: async () => ({ detail: 'Request rejected' }),
    }) });
    context.applyPublicConfig({ email_verification_enabled: true });
    context.renderResult(senderResult('user@gmail.com'));
    await context.runVerification();
    assert.match(elements.get('verify-error')?.textContent || '', expected);
    assert.equal(elements.get('verify-result').classList.contains('hidden'), true);
    assert.equal(elements.get('verify-idle').classList.contains('hidden'), false);
  }
});

test('non-address input is rejected before calling the sender API', async () => {
  let calls = 0;
  const { context, elements } = loadFrontend({ fetch: async () => { calls++; return response(senderResult('hello')); } });
  context.document.getElementById('email-input').value = 'hello';
  await context.runEmailAnalysis();
  assert.equal(calls, 0);
  assert.match(elements.get('email-error').textContent, /email address/i);
  assert.equal(elements.get('result-area').classList.contains('hidden'), true);
});

test('structural evidence is included when no keyword category matches', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ ...contentResult('High Risk'), risk_level: 'high',
    extra_indicators: [{ level: 'high', msg: 'IP address link' }, { level: 'info', msg: 'Provider context' }],
  });
  assert.match(elements.get('crb-sub').textContent, /1 technical risk indicator/i);
  assert.doesNotMatch(elements.get('crb-sub').textContent, /no suspicious patterns/i);
});

test('content requests ignore stale results and results arriving after clear', async () => {
  const network = deferredFetch();
  const { context, elements } = loadFrontend({ fetch: network.fetch });
  context.document.getElementById('content-subject').value = 'First';
  const first = context.runContentAnalysis();
  context.document.getElementById('content-subject').value = 'Second';
  const second = context.runContentAnalysis();
  network.pending[1](response(contentResult('Second result')));
  await second;
  network.pending[0](response(contentResult('First result')));
  await first;
  assert.equal(elements.get('crb-title').textContent, 'Second result');
  const third = context.runContentAnalysis();
  context.clearContent();
  network.pending[2](response(contentResult('Third result')));
  await third;
  assert.equal(elements.get('content-result-area').classList.contains('hidden'), true);
});

test('choosing a content example clears the file, status and pending file read', async () => {
  const { context, elements } = loadFrontend();
  context.setupInputEvents();
  const fileInput = elements.get('raw-email-file');
  fileInput.value = 'previous.eml';
  let finishRead;
  const read = fileInput.listeners.change({ target: { files: [{name: 'previous.eml', arrayBuffer: () => new Promise(resolve => { finishRead = resolve; })}] } });
  context.runContentAnalysis = () => {};
  context.setContentExample('legit-newsletter');
  finishRead(emlBytes('From: old@example.com\n\nOld message'));
  await read;
  assert.equal(fileInput.value, '');
  assert.equal(elements.get('raw-email-status').textContent, '');
  assert.equal(vm.runInContext('_rawEmailSource', context), '');
});

test('editing the sender input invalidates an in-flight verification', async () => {
  const network = deferredFetch();
  const { context, elements } = loadFrontend({ fetch: network.fetch });
  context.setupInputEvents();
  context.applyPublicConfig({ email_verification_enabled: true });
  context.renderResult(senderResult('first@gmail.com'));
  let rendered = false;
  context.renderVerifyResult = () => { rendered = true; };
  const pending = context.runVerification();
  elements.get('email-input').value = 'second@outlook.com';
  elements.get('email-input').listeners.input();
  network.pending[0](response({ format_valid: true }));
  await pending;
  assert.equal(rendered, false);
  assert.equal(elements.get('result-area').classList.contains('hidden'), true);
});

test('content analysis waits for file reading and clearing prevents a late read', async () => {
  let calls = 0;
  const { context, elements } = loadFrontend({ fetch: async () => { calls++; return response(contentResult('Result')); } });
  context.setupInputEvents();
  elements.get('content-subject').value = 'Note';
  let finishRead;
  const read = elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'email.eml', arrayBuffer: () => new Promise(resolve => { finishRead = resolve; }),
  }] } });
  await context.runContentAnalysis();
  assert.equal(calls, 0);
  assert.match(elements.get('content-error').textContent, /finish loading/i);
  context.clearContent();
  finishRead(emlBytes('From: test@example.com\n\nHello'));
  await read;
  assert.equal(vm.runInContext('_rawEmailSource', context), '');
  assert.equal(elements.get('raw-email-status').textContent, '');
});

test('upload mode excludes manual fields and restores editing when cleared', async () => {
  let submitted;
  const { context, elements } = loadFrontend({ fetch: async (_url, options) => {
    submitted = _url === '/api/analyze-eml' ? options.body : JSON.parse(options.body);
    return response(contentResult('File result'));
  } });
  context.setupInputEvents();
  elements.get('content-subject').value = 'Old subject';
  elements.get('content-body').value = 'Old body';
  const raw = emlBytes('From: alice@gmail.com\nSubject: File\n\nActual body');
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'message.eml', arrayBuffer: async () => raw,
  }] } });
  assert.equal(elements.get('content-body').disabled, true);
  assert.equal(elements.get('content-subject').disabled, true);
  assert.match(elements.get('raw-email-status').textContent, /manual.*ignored/i);
  await context.runContentAnalysis();
  assert.deepEqual(Buffer.from(submitted.eml_base64, 'base64'), Buffer.from(raw));
  assert.equal(submitted.body, undefined);
  assert.equal(submitted.subject, undefined);
  context.clearRawEmail();
  assert.equal(elements.get('content-body').disabled, false);
  assert.equal(elements.get('content-subject').disabled, false);
  await context.runContentAnalysis();
  assert.equal(submitted.body, 'Old body');
});

test('an empty upload restores manual editing and reports an input error', async () => {
  const { context, elements } = loadFrontend();
  context.setupInputEvents();
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'empty.eml', arrayBuffer: async () => emlBytes('   '),
  }] } });
  assert.equal(elements.get('content-body').disabled, false);
  assert.match(elements.get('content-error').textContent, /empty/i);
  assert.equal(elements.get('raw-email-status').textContent, '');
});

test('uploaded non-UTF8 bytes survive the visual endpoint base64 envelope', async () => {
  let submitted;
  const { context, elements } = loadFrontend({ fetch: async (url, options) => {
    submitted = { url, ...options };
    return response(contentResult('File result'));
  } });
  context.setupInputEvents();
  const bytes = new Uint8Array([72, 233, 98, 101]);
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'latin1.eml', size: bytes.length,
    arrayBuffer: async () => bytes.buffer,
    text: async () => { throw new Error('Must not decode original bytes'); },
  }] } });
  await context.runContentAnalysis();
  assert.equal(submitted?.url, '/api/analyze-visual');
  assert.equal(submitted.headers['Content-Type'], 'application/json');
  assert.deepEqual(Buffer.from(JSON.parse(submitted.body).eml_base64, 'base64'), Buffer.from(bytes));
});

test('oversized email is rejected before reading and restores manual input', async () => {
  let read = false;
  const { context, elements } = loadFrontend();
  context.setupInputEvents();
  await elements.get('raw-email-file').listeners.change({ target: { files: [{
    name: 'large.eml', size: 2 * 1024 * 1024 + 1, arrayBuffer: async () => { read = true; return new ArrayBuffer(2 * 1024 * 1024 + 1); },
  }] } });
  assert.equal(read, false);
  assert.equal(elements.get('content-body').disabled, false);
  assert.match(elements.get('content-error').textContent, /2 MiB limit/);
});

test('network and unreadable service responses remain request errors', async () => {
  for (const fetch of [async () => { throw new Error('offline'); },
    async () => ({ok:true,json:async()=>{throw new Error('invalid JSON');}})]) {
    const { context, elements } = loadFrontend({ fetch });
    context.applyPublicConfig({ email_verification_enabled: true });
    context.renderResult(senderResult('user@gmail.com'));
    await context.runVerification();
    assert.match(elements.get('verify-error').textContent, /service/i);
    assert.equal(elements.get('verify-result').classList.contains('hidden'), true);
  }
});

test('public configuration replaces verification controls with a local-only notice', () => {
  const { context, elements } = loadFrontend();

  assert.equal(typeof context.applyPublicConfig, 'function');
  context.applyPublicConfig({ email_verification_enabled: false, deployment_profile: 'production' });

  assert.equal(elements.get('verify-idle').classList.contains('hidden'), true);
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), false);
  assert.match(elements.get('verification-local-notice').textContent, /your own computer/i);
});

test('local disabled configuration stays accurate after rendering a result', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({ email_verification_enabled: false, deployment_profile: 'development' });
  context.resetVerifyCard();
  assert.match(elements.get('verification-local-notice').textContent, /disabled in this local/i);
  assert.doesNotMatch(elements.get('verification-local-notice').textContent, /public service/i);
});

test('missing configuration does not claim a public deployment', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({});
  assert.match(elements.get('verification-local-notice').textContent, /could not be confirmed/i);
  assert.equal(elements.get('verify-idle').classList.contains('hidden'), true);
});

test('enabling verification only exposes the idle controls', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({ email_verification_enabled: true, deployment_profile: 'development' });
  assert.equal(elements.get('verification-local-notice').textContent, '');
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), true);
  assert.equal(elements.get('verify-idle').classList.contains('hidden'), false);
  assert.equal(elements.get('verify-loading').classList.contains('hidden'), true);
  assert.equal(elements.get('verify-result').classList.contains('hidden'), true);
});

test('lite verification exposes domain checks and explains unavailable SMTP', () => {
  const { context, elements } = loadFrontend();
  context.applyPublicConfig({
    deployment_profile: 'production',
    verification_mode: 'lite',
    email_verification_enabled: true,
    domain_verification_enabled: true,
    smtp_verification_enabled: false,
  });

  assert.equal(elements.get('verify-idle').classList.contains('hidden'), false);
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), false);
  assert.match(elements.get('verification-local-notice').textContent, /domain checks are enabled/i);
  assert.match(elements.get('verification-local-notice').textContent, /SMTP mailbox probing is unavailable/i);
});

test('disposable status and low sender score have distinct neutral presentation', () => {
  const { context, elements } = loadFrontend();
  const result = {
    email: 'user@mailinator.com', verdict: 'low', label: 'Low Sender Risk',
    risk_score: 0, risk_indicators: [{ level: 'info', msg: 'Known disposable-email provider' }], high_risk_count: 0, med_risk_count: 0,
    phish_feature_count: 0, feature_breakdown: [],
    disposable_status: 'known_disposable_provider', matched_provider_domain: 'mailinator.com',
  };
  context.renderResult(result);
  assert.match(elements.get('verdict-banner').className, /banner-neutral/);
  assert.equal(elements.get('disp-check-label').textContent, 'Known disposable-email provider');
  assert.match(elements.get('vb-scope').textContent, /does not establish.*safe/i);
  assert.doesNotMatch(elements.get('risk-summary').innerHTML, /Disposable|Suspected Phishing/);
  assert.doesNotMatch(elements.get('risk-indicators-list').innerHTML, /disposable-email provider/i);
  context.renderResult({ ...result, verdict: 'critical', risk_score: 92, label: 'Critical Sender Risk' });
  assert.match(elements.get('verdict-banner').className, /banner-phish/);
  assert.equal(elements.get('vb-prob').textContent, '92/100');
});

test('resetting results does not reveal disabled verification controls', () => {
  const { context, elements } = loadFrontend();

  context.applyPublicConfig({ email_verification_enabled: false });
  context.resetVerifyCard();

  assert.equal(elements.get('verify-idle').classList.contains('hidden'), true);
  assert.equal(elements.get('verification-local-notice').classList.contains('hidden'), false);
});

test('sender analysis renders an honest heuristic risk score', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    email: 'security@paypa1-verify.example',
    verdict: 'critical',
    label: 'Critical Sender Risk',
    risk_score: 92,
    analysis_method: 'sender-domain-heuristics',
    risk_indicators: [],
    high_risk_count: 2,
    med_risk_count: 1,
    phish_feature_count: 5,
    feature_breakdown: [],
    is_disposable: false,
    is_suspected_disposable: false,
    disposable_status: 'no_known_match',
    disposable_confidence: 'unknown',
    matched_provider_domain: null,
    address_alias_type: null,
  });

  assert.equal(elements.get('vb-prob-label').textContent, 'Sender Risk Score');
  assert.equal(elements.get('vb-prob').textContent, '92/100');
  assert.equal(elements.get('disp-check-label').textContent, 'No known disposable-provider match');
  assert.doesNotMatch(elements.get('disp-check-label').textContent, /not a disposable/i);
});

test('privacy relay classification is informational', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    email: 'user@relay.firefox.com', verdict: 'low', label: 'Low Sender Risk',
    risk_score: 0, risk_indicators: [], high_risk_count: 0, med_risk_count: 0,
    phish_feature_count: 0, feature_breakdown: [], is_disposable: false,
    is_suspected_disposable: false, disposable_status: 'privacy_relay',
    disposable_confidence: 'confirmed', matched_provider_domain: 'relay.firefox.com',
    address_alias_type: null,
  });

  assert.equal(elements.get('disp-check-label').textContent, 'Privacy relay / masked address');
  assert.match(elements.get('disp-check-detail').textContent, /not phishing evidence/i);
});

test('suspicious mailbox classification communicates uncertainty', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    email: 'xq7m9v2k4p8z@gmail.com', verdict: 'low', label: 'Low Sender Risk',
    risk_score: 10, risk_indicators: [], high_risk_count: 0, med_risk_count: 1,
    phish_feature_count: 2, feature_breakdown: [], is_disposable: false,
    is_suspected_disposable: true, disposable_status: 'suspicious_mailbox_pattern',
    disposable_confidence: 'heuristic', matched_provider_domain: null,
    address_alias_type: null,
  });

  assert.equal(
    elements.get('disp-check-label').textContent,
    'Mailbox pattern is suspicious; lifetime unknown',
  );
  assert.match(elements.get('disp-check-detail').textContent, /cannot be confirmed/i);
});

test('sender history reports a first observation without claiming provider account age', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('new.account@gmail.com'),
    account_observability: 'provider_account_unverifiable',
    sender_history_status: 'first_seen',
    sender_history_scope: 'this_service_history',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'First observed by this service');
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /observed 1 time/i);
  assert.match(elements.get('sender-history-detail').textContent, /Gmail account age cannot be verified/i);
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /new account|account created/i);
});

test('sender history distinguishes a previous observation from sender safety', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('billing@outlook.com'),
    sender_history_status: 'previously_seen',
    sender_history_scope: 'this_service_history',
    account_observability: 'provider_account_unverifiable',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'Observed previously by this service');
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /observed 12 times/i);
  assert.match(elements.get('sender-history-detail').textContent, /does not establish.*safe/i);
});

test('address-only analysis explains that retained history requires a raw message', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('alice@gmail.com'),
    sender_history_status: 'raw_message_required',
    sender_history_scope: 'this_service_history',
    account_observability: 'provider_account_unverifiable',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'Available with full-message analysis');
  assert.match(elements.get('sender-history-detail').textContent, /does not query retained sender history/i);
});

test('unavailable sender history never renders a false zero-count claim', () => {
  const { context, elements } = loadFrontend();

  context.renderResult({
    ...senderResult('user@example.com'),
    sender_history_status: 'unavailable',
    sender_history_scope: 'this_service_history',
    account_observability: 'unknown',
  });

  assert.equal(elements.get('sender-history-label').textContent, 'Observation history unavailable');
  assert.doesNotMatch(elements.get('sender-history-detail').textContent, /0 times|never seen/i);
});

test('raw-message results surface the observed sender history', () => {
  const { context, elements } = loadFrontend();

  context.renderContentResult({
    risk_level: 'low', risk_label: 'Low', analysis_complete: true,
    combined_phishing_score: 8, total_score: 0,
    category_results: [], extra_indicators: [], safety_signals: [],
    ml_status: 'insufficient_feature_coverage', ml_label: null,
    sender_analysis: {
      email: 'new.account@outlook.com',
      account_observability: 'provider_account_unverifiable',
      sender_history_status: 'first_seen',
      sender_history_scope: 'this_service_history',
    },
  });

  assert.equal(
    elements.get('content-sender-history-label').textContent,
    'First observed by this service',
  );
  assert.match(elements.get('content-sender-history-detail').textContent, /Outlook account age cannot be verified/i);
});

test('disposable education copy does not claim mailbox lifetime from a domain match', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');

  assert.doesNotMatch(html, /500\+ detected/i);
  assert.doesNotMatch(html, /They require no registration and expire/i);
  assert.match(html, /does not prove that an individual mailbox expires/i);
});

test('content payload includes an uploaded raw email', () => {
  const { context } = loadFrontend();
  const payload = context.buildContentPayload('', '', 'From: sender@example.com\n\nHello');

  assert.equal(payload.raw_email, 'From: sender@example.com\n\nHello');
});

test('attacker-controlled indicator text is HTML escaped before rendering', () => {
  const { context } = loadFrontend();

  assert.equal(
    context.escapeHtml('<img src=x onerror=alert(1)>'),
    '&lt;img src=x onerror=alert(1)&gt;',
  );
});

test('server-supplied levels, counts and contributions cannot inject markup', () => {
  const payload = 'x"><img src=x onerror=alert(1)>';
  const { context, elements } = loadFrontend();
  context.renderResult({ ...senderResult('a@example.com'), high_risk_count: payload, med_risk_count: payload,
    risk_indicators: [{ level: payload, msg: 'indicator' }] });
  context.renderContentResult({ ...contentResult('Result'), analysis_complete: true, risk_level: 'high',
    category_results: [{ key: 'urgency', level: payload, label: 'L', count: payload, description: 'd', matched: [] }],
    extra_indicators: [{ level: payload, msg: 'extra' }],
    ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 80, ml_legitimate_probability: 20,
    ml_prediction: 1, ml_top_contributors: [{ term: 'verify', contribution: payload }], ml_metrics: {} });
  for (const id of ['risk-summary', 'risk-indicators-list', 'content-category-grid', 'content-extra-list', 'content-ml-contribs']) {
    const html = elements.get(id).innerHTML;
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/, id);
    assert.doesNotMatch(html, /<img|"><img/, id);
  }
});

test('decorative button icons are hidden and the benchmark chart has a text alternative', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  for (const [, inner] of html.matchAll(/<(?:button|a)\b[^>]*>([\s\S]*?)<\/(?:button|a)>/g)) {
    for (const [svg] of inner.matchAll(/<svg\b[^>]*>/g)) assert.match(svg, /aria-hidden="true"/, svg);
  }
  assert.match(html, /<canvas id="metricsChart" role="img" aria-label="[^"]*table above[^"]*"[^>]*>/);
});

test('public OCR forwards language and discards recognition after the selection changes',async()=>{
  let release, selectedLanguage, posts=0;
  const {context,elements}=loadFrontend({fetch:async()=>{posts++;return response(contentResult('File result'));}});
  context.window.PhishGuardVision.recognize=async(_file,_progress,language)=>{
    selectedLanguage=language;return new Promise(resolve=>{release=resolve;});
  };
  context.setupInputEvents();
  await elements.get('raw-email-file').listeners.change({target:{files:[{
    name:'test.png',size:1,arrayBuffer:async()=>new Uint8Array([1]).buffer,
  }]}});
  const select=elements.get('content-ocr-language');
  assert(select,'language selector is wired');select.value='chi_sim';
  const pending=context.runContentAnalysis();
  assert.equal(selectedLanguage,'chi_sim');
  select.value='eng';select.listeners.change();
  release({observations:[],warnings:[]});await pending;
  assert.equal(posts,0);assert.equal(elements.get('content-analyze-btn').disabled,false);
});

test('risk score colours use theme tokens so the light theme applies', () => {
  const { context, elements } = loadFrontend();
  const expected = { unknown: 'yellow', safe: 'accent2', low: 'info', medium: 'yellow', high: 'orange', critical: 'red' };
  for (const [level, token] of Object.entries(expected)) {
    context.renderContentResult({ ...contentResult('Result'), risk_level: level });
    assert.equal(elements.get('crb-score').style.color, `var(--${token})`, level);
    assert.equal(elements.get('crb-ring').style.stroke, `var(--${token})`, level);
  }
  // The medium verdict appends a note to the banner's left column.
  context.document.getElementById('verdict-banner').querySelector = selector =>
    (selector === '.vb-left' ? new FakeElement() : null);
  for (const [verdict, token] of [['high', 'red'], ['medium', 'yellow'], ['low', 'info']]) {
    context.renderResult({ ...senderResult('user@example.com'), verdict });
    assert.equal(elements.get('vb-prob').style.color, `var(--${token})`, verdict);
    assert.equal(elements.get('vb-ring').style.stroke, `var(--${token})`, verdict);
  }
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  const block = selector => css.slice(css.indexOf(selector + ' {'), css.indexOf('}', css.indexOf(selector + ' {')));
  for (const token of new Set(Object.values(expected))) {
    assert.match(block(':root'), new RegExp(`--${token}:`), `dark ${token}`);
    assert.match(block(':root[data-theme="light"]'), new RegExp(`--${token}:`), `light ${token}`);
  }
});

test('benchmark load failures replace the loading row, but a chart failure keeps the table', async () => {
  const errors = [];
  const quiet = { error: (...args) => errors.push(args) };
  const unavailable = /<td colspan="6" class="loading-cell">Benchmark results are unavailable right now\.<\/td>/;
  for (const fetch of [
    async () => ({ ok: false, status: 503, json: async () => ({ detail: 'down' }) }),
    async () => ({ ok: true, json: async () => { throw new SyntaxError('bad json'); } }),
    async () => ({ ok: true, json: async () => ({}) }),
    async () => { throw new TypeError('offline'); },
  ]) {
    const { context, elements } = loadFrontend({ fetch, console: quiet });
    await context.loadMetrics();
    assert.match(elements.get('metrics-tbody').innerHTML, unavailable);
  }
  assert.equal(errors.length, 4);

  // FakeElement has no canvas context, so the chart step throws after the table rendered.
  const metrics = { 'Random Forest': { Accuracy: 0.97, Precision: 0.96, Recall: 0.95, F1: 0.94, ROC_AUC: 0.99 } };
  const { context, elements } = loadFrontend({ fetch: async () => response({ metrics }), console: quiet, Chart: function Chart() {} });
  await context.loadMetrics();
  assert.match(elements.get('metrics-tbody').innerHTML, /Random Forest/);
  assert.doesNotMatch(elements.get('metrics-tbody').innerHTML, /unavailable/);
  assert.equal(errors.length, 5);
});

test('submitting empty content explains what to provide without calling the API', async () => {
  let calls = 0;
  const { context, elements } = loadFrontend({ fetch: async () => { calls++; return response(contentResult('Result')); } });
  await context.runContentAnalysis();
  assert.equal(calls, 0);
  assert.match(elements.get('content-error').textContent, /subject or body.*\.eml or image file/i);
  assert.equal(elements.get('content-error').classList.contains('hidden'), false);
});

test('rendered results move focus to the verdict title without scrolling twice', () => {
  const { context, elements } = loadFrontend();
  const focused = [];
  for (const id of ['vb-title', 'crb-title']) {
    context.document.getElementById(id).focus = options => focused.push([id, options.preventScroll]);
  }
  context.renderResult(senderResult('user@example.com'));
  context.renderContentResult(contentResult('Result'));
  assert.deepEqual(focused, [['vb-title', true], ['crb-title', true]]);
  assert.equal(elements.get('result-area').classList.contains('hidden'), false);
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /id="vb-title" tabindex="-1"/);
  assert.match(html, /id="crb-title" tabindex="-1"/);
});

test('result and in-page scrolling respect reduced motion; hash links update the URL and focus', () => {
  for (const reduce of [true, false]) {
    const pushed = [];
    const { context, elements } = loadFrontend({
      matchMedia: () => ({ matches: reduce }),
      history: { pushState: (_state, _title, url) => pushed.push(url) },
    });
    const behaviors = [];
    for (const id of ['result-area', 'content-result-area']) {
      context.document.getElementById(id).scrollIntoView = options => behaviors.push(options.behavior);
    }
    context.renderResult(senderResult('user@example.com'));
    context.renderContentResult(contentResult('Result'));

    const target = new FakeElement();
    target.tabIndex = -1;
    target.hasAttribute = name => Boolean(target.attributes && name in target.attributes);
    target.scrollIntoView = options => behaviors.push(options.behavior);
    let focusOptions;
    target.focus = options => { focusOptions = options; };
    const link = new FakeElement();
    link.getAttribute = () => '#about';
    context.document.querySelectorAll = () => [link];
    context.document.querySelector = selector => (selector === '#about' ? target : null);
    context.setupSmoothScroll();
    let prevented = false;
    link.listeners.click({ preventDefault: () => { prevented = true; } });

    const expected = reduce ? 'auto' : 'smooth';
    assert.deepEqual(behaviors, [expected, expected, expected]);
    assert.equal(prevented, true);
    assert.deepEqual(pushed, ['#about']);
    assert.equal(target.attributes.tabindex, '-1');
    assert.equal(focusOptions.preventScroll, true);
    assert.equal(elements.has('about'), false);
  }
});

test('benchmark names are escaped and the best row is computed from F1, then ROC AUC', () => {
  const { context, elements } = loadFrontend();
  const row = (F1, ROC_AUC) => ({ Accuracy: 0.9, Precision: 0.9, Recall: 0.9, F1, ROC_AUC });
  context.renderMetricsTable({
    'Random Forest': row(0.90, 0.999),
    '<img src=x onerror=alert(1)>': row(0.95, 0.96),
    'Tie & Winner': row(0.95, 0.97),
  });
  const html = elements.get('metrics-tbody').innerHTML;
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  const best = html.split('</tr>').filter(tr => /<tr class="row-best">/.test(tr));
  assert.equal(best.length, 1);
  assert.match(best[0], /Tie &amp; Winner <span class="best-badge">/);
  assert.equal(html.match(/best-badge/g).length, 1);
});

test('copy results are announced through a polite live region', async () => {
  const timers = [];
  const { context } = loadFrontend({
    navigator: { clipboard: { writeText: async () => {} } },
    setTimeout: (fn, ms) => timers.push({ fn, ms }), clearTimeout: () => {},
  });
  context.renderResult({
    email: 'a@example.test', verdict: 'low', label: 'Low Sender Risk', risk_score: 5,
    risk_indicators: [], feature_breakdown: [], high_risk_count: 0, med_risk_count: 0, phish_feature_count: 0,
    disposable_status: 'no_known_match',
  });
  const status = context.document.getElementById('copy-status');
  const label = { textContent: 'Copy summary' };
  const flush = () => timers.splice(0).filter(t => t.ms < 1000).forEach(t => t.fn());
  timers.length = 0;
  status.textContent = 'Summary copied to clipboard';
  await context.copySummary('sender', { querySelector: () => label });
  assert.equal(status.textContent, '', 'cleared first so a repeated message is announced again');
  flush();
  assert.equal(status.textContent, 'Summary copied to clipboard');
  assert.equal(label.textContent, 'Copied');

  context.navigator.clipboard.writeText = async () => { throw new Error('denied'); };
  await context.copySummary('sender', { querySelector: () => label });
  flush();
  assert.equal(status.textContent, 'Copy failed');
  assert.equal(label.textContent, 'Copy failed');

  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const region = html.match(/<p id="copy-status"[^>]*>/);
  assert.ok(region, 'index.html has the copy live region');
  for (const attr of ['class="sr-only"', 'role="status"', 'aria-live="polite"']) assert.ok(region[0].includes(attr), attr);
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(css, /\n\.sr-only \{[^}]*position: absolute;[^}]*clip: rect\(0, 0, 0, 0\);/);
});

test('--text-dim meets WCAG AA on page and card backgrounds in both themes, below --text-muted', () => {
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  const luminance = hex => {
    const [r, g, b] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
      .map(v => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const contrast = (a, b) => {
    const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (hi + 0.05) / (lo + 0.05);
  };
  const blocks = {
    dark: css.match(/\n:root \{([^}]*)\}/)[1],
    light: css.match(/\n:root\[data-theme="light"\] \{([^}]*)\}/)[1],
  };
  for (const [theme, block] of Object.entries(blocks)) {
    const token = name => block.match(new RegExp(`${name}:\\s*(#[0-9a-f]{6});`, 'i'))[1];
    const dim = token('--text-dim'), muted = token('--text-muted');
    for (const bg of ['--bg', '--bg-card', '--bg-card2']) {
      const ratio = contrast(dim, token(bg));
      assert.ok(ratio >= 4.5, `${theme} --text-dim ${dim} on ${bg} ${token(bg)} is ${ratio.toFixed(2)}:1`);
      assert.ok(contrast(muted, token(bg)) > ratio, `${theme} --text-dim stays dimmer than --text-muted on ${bg}`);
    }
  }
});

test('text fields use 16px on touch devices so iOS Safari does not zoom on focus', () => {
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  const touch = [...css.matchAll(/@media \(hover: none\) and \(pointer: coarse\) \{\n([\s\S]*?)\n\}/g)]
    .map(match => match[1]).find(body => /font-size:\s*16px/.test(body));
  assert.ok(touch, 'a coarse-pointer 16px rule exists');
  for (const selector of ['.email-input', '.content-subject-input', '.content-body-textarea',
    '.ocr-language-select', '.feedback-dialog select', '.feedback-dialog textarea']) {
    assert.ok(touch.includes(selector), selector);
  }
  // Desktop sizes are unchanged.
  assert.match(css, /\n\.email-input \{[^}]*font-size: 15px;/);
  assert.match(css, /\n\.content-subject-input \{[^}]*font-size: 14px;/);
});

// ── Tab deep links ───────────────────────────────────────────────────────────
function tabPage({ search = '', href = `https://phishguard.test/${search}`, deferTransitions = false } = {}) {
  const tabs = { 'email-address': new FakeElement(), 'email-content': new FakeElement() };
  const panels = { 'email-address': new FakeElement(), 'email-content': new FakeElement() };
  tabs['email-address'].classList.add('active');
  panels['email-content'].classList.add('hidden');
  Object.entries(tabs).forEach(([name, tab]) => { tab.id = `tab-${name}`; });
  const transitions = [], pendingUpdates = [];
  const document = {
    addEventListener() {},
    createElement: () => new FakeElement(),
    getElementById: id => id.startsWith('tab-') ? tabs[id.slice(4)] ?? null
      : id.startsWith('panel-') ? panels[id.slice(6)] ?? null : new FakeElement(),
    querySelector: selector => selector === '.demo-tab.active'
      ? Object.values(tabs).find(tab => tab.classList.contains('active')) ?? null : null,
    querySelectorAll: selector => selector === '.demo-tab' ? Object.values(tabs)
      : selector === '.tab-panel' ? Object.values(panels) : [],
    // Browsers run the update callback a frame later; deferTransitions models that.
    startViewTransition: update => {
      transitions.push('start');
      if (deferTransitions) pendingUpdates.push(update); else update();
      return { finished: Promise.resolve() };
    },
  };
  const replaced = [], pushed = [];
  const location = { search, href };
  const history = {
    state: null,
    replaceState: (_state, _title, url) => { replaced.push(url); location.href = new URL(url, location.href).href; },
    pushState: (_state, _title, url) => pushed.push(url),
  };
  const { context } = loadFrontend({ document, location, history, URL, URLSearchParams });
  return { context, tabs, panels, transitions, pendingUpdates, replaced, pushed, location };
}

test('?tab=content opens the content tab on load without animation or a history entry', () => {
  const page = tabPage({ search: '?tab=content', href: 'https://phishguard.test/?tab=content#demo' });
  page.context.setupDemoTabs();
  assert.equal(page.tabs['email-content'].classList.contains('active'), true);
  assert.equal(page.tabs['email-content'].attributes['aria-selected'], 'true');
  assert.equal(page.tabs['email-address'].attributes['aria-selected'], 'false');
  assert.equal(page.panels['email-content'].classList.contains('hidden'), false);
  assert.equal(page.panels['email-address'].classList.contains('hidden'), true);
  assert.deepEqual(page.transitions, [], 'no view transition on load');
  assert.deepEqual(page.replaced, [], 'the URL already says content');
  assert.deepEqual(page.pushed, []);

  const address = tabPage({ search: '?tab=address' });
  address.context.setupDemoTabs();
  assert.equal(address.tabs['email-address'].classList.contains('active'), true);
  assert.equal(address.tabs['email-content'].classList.contains('active'), false);
});

test('switching tabs replaces the tab query, keeps other params and the #hash', () => {
  const page = tabPage({ search: '?lang=en', href: 'https://phishguard.test/?lang=en#about' });
  page.context.setupDemoTabs();
  page.context.switchDemoTab('email-content');
  assert.deepEqual(page.transitions, ['start'], 'user switches still animate');
  page.context.switchDemoTab('email-content');
  page.context.switchDemoTab('email-address');
  assert.deepEqual(page.replaced, ['/?lang=en&tab=content#about', '/?lang=en&tab=address#about']);
  assert.deepEqual(page.pushed, [], 'tab switches never add history entries');

  // Keyboard switching goes through the same path.
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /href="#tab=|href="\?tab=/, 'no hash-based tab links');
});

test('a second tab switch during a pending view transition is not dropped', () => {
  const page = tabPage({ deferTransitions: true });
  page.context.switchDemoTab('email-content');
  page.context.switchDemoTab('email-address');
  page.context.switchDemoTab('email-content');
  assert.equal(page.transitions.length, 3);
  page.pendingUpdates.splice(0).forEach(update => update());
  assert.equal(page.tabs['email-content'].classList.contains('active'), true);
  assert.equal(page.tabs['email-address'].classList.contains('active'), false);
  assert.equal(page.panels['email-content'].classList.contains('hidden'), false);
  assert.deepEqual(page.replaced, ['/?tab=content', '/?tab=address', '/?tab=content']);
});

test('unknown or malformed ?tab values are ignored', () => {
  for (const search of ['?tab=admin', '?tab=', '?tab=email-content', '?tab=constructor', '?tab=__proto__', '?TAB=content', '']) {
    const page = tabPage({ search });
    page.context.setupDemoTabs();
    assert.equal(page.tabs['email-address'].classList.contains('active'), true, search);
    assert.equal(page.tabs['email-content'].classList.contains('active'), false, search);
    assert.deepEqual(page.replaced, [], search);
  }
  const page = tabPage();
  page.context.switchDemoTab('nonexistent');
  assert.deepEqual(page.replaced, []);
  // Without URL support the tab still switches.
  const { context } = loadFrontend({ location: { search: '?tab=content', href: 'x' },
    history: { replaceState() { throw new Error('blocked'); } } });
  assert.equal(context.tabFromSearch('?tab=content'), null, 'URLSearchParams missing is tolerated');
  assert.doesNotThrow(() => context.syncTabQuery('email-content'));
});

// ── ML card title ────────────────────────────────────────────────────────────
test('the ML card title names the model the API reports, with a generic fallback', () => {
  const { context, elements } = loadFrontend();
  const result = model => ({
    ...contentResult('Result'), ml_label: 'Phishing', ml_prediction: 1,
    ml_phishing_probability: 81.2, ml_legitimate_probability: 18.8,
    ml_metrics: model === undefined ? undefined : { model },
  });
  const title = () => elements.get('content-ml-title').textContent;
  context.renderContentResult(result('LogisticRegression'));
  assert.equal(title(), 'TF-IDF + Logistic Regression');
  context.renderContentResult(result('CalibratedLinearSVC'));
  assert.equal(title(), 'TF-IDF + Linear SVM (calibrated)');
  context.renderContentResult(result('ComplementNB'));
  assert.equal(title(), 'TF-IDF + Complement Naive Bayes');
  for (const model of [undefined, null, '', 'GradientBoosting', 'constructor', '__proto__', '<img src=x onerror=alert(1)>']) {
    context.renderContentResult(result(model));
    assert.equal(title(), 'Text model', String(model));
  }
  assert.equal(elements.get('content-ml-title').innerHTML, '', 'set through textContent only');

  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /<span class="ml-badge">ML<\/span>\s*<span id="content-ml-title">Text model<\/span>/);
  assert.doesNotMatch(html, /TF-IDF \+ Logistic Regression/);
});

// ── Recent checks ────────────────────────────────────────────────────────────
function memoryStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: key => (data.has(key) ? data.get(key) : null),
    setItem: (key, value) => { data.set(key, String(value)); },
    removeItem: key => { data.delete(key); },
  };
}
const RECENT = 'phishguard-recent-checks';
const stored = storage => JSON.parse(storage.getItem(RECENT) || '[]');

test('a sender check is recorded with the domain only, never the local part', async () => {
  const storage = memoryStorage();
  const { context, elements } = loadFrontend({ localStorage: storage,
    fetch: async () => response({ ...senderResult('alice.secret+tag@Mail.Example.COM'), verdict: 'high',
      label: 'High Sender Risk', risk_score: 38 }) });
  context.document.getElementById('email-input').value = 'alice.secret+tag@Mail.Example.COM';
  await context.runEmailAnalysis();
  const entries = stored(storage);
  assert.equal(entries.length, 1);
  assert.deepEqual(Object.keys(entries[0]).sort(), ['at', 'domain', 'label', 'level', 'mode', 'score']);
  assert.equal(entries[0].mode, 'sender');
  assert.equal(entries[0].domain, 'mail.example.com');
  assert.equal(entries[0].level, 'high');
  assert.equal(entries[0].score, 38);
  assert.doesNotMatch(storage.getItem(RECENT), /alice|secret|tag@/i);
  const list = elements.get('recent-checks-list');
  assert.match(list.innerHTML, /Sender<\/span>/);
  assert.match(list.innerHTML, /mail\.example\.com/);
  assert.match(list.innerHTML, /38\/100/);
  assert.match(list.innerHTML, /Just now/);
  assert.doesNotMatch(list.innerHTML, /alice/);
  assert.equal(list.hidden, false);
  assert.equal(elements.get('recent-checks-count').textContent, '(1)');
  assert.equal(elements.get('recent-checks-clear').hidden, false);
});

test('content, email-file and image checks store no subject, body, file name or text', async () => {
  const storage = memoryStorage();
  const { context, elements } = loadFrontend({ localStorage: storage,
    fetch: async () => response({ ...contentResult('High Risk — Likely Phishing'), risk_level: 'high',
      combined_phishing_score: 72.6, input_mode: 'subject-body', subject: 'Private subject', body: 'Private body' }) });
  context.document.getElementById('content-subject').value = 'Private subject';
  context.document.getElementById('content-body').value = 'Private body';
  await context.runContentAnalysis();
  let entries = stored(storage);
  assert.equal(entries.length, 1);
  assert.deepEqual(Object.keys(entries[0]).sort(), ['at', 'label', 'level', 'mode', 'score']);
  assert.equal(entries[0].mode, 'content');
  assert.equal(entries[0].score, 73);
  assert.doesNotMatch(storage.getItem(RECENT), /Private/);

  for (const [inputMode, mode] of [['raw-email', 'eml'], ['image-evidence', 'image']]) {
    const entry = context.contentRecentEntry({ ...contentResult('Unknown'), risk_level: 'unknown',
      combined_phishing_score: 12, input_mode: inputMode });
    assert.equal(entry.mode, mode);
    assert.equal(entry.score, null, 'undetermined risk keeps no score');
  }
  // Even if a caller passes extra fields, only allowed ones are written.
  context.recordRecentCheck({ mode: 'image', label: 'Medium Risk', level: 'medium', score: 40, at: Date.now(),
    filename: 'invoice-secret.png', ocr_text: 'Private OCR', subject: 'Private', domain: 'x.test' });
  entries = stored(storage);
  assert.deepEqual(Object.keys(entries[0]).sort(), ['at', 'label', 'level', 'mode', 'score']);
  assert.doesNotMatch(storage.getItem(RECENT), /invoice|Private|x\.test/);
  assert.match(elements.get('recent-checks-list').innerHTML, /Image<\/span>[\s\S]*40%[\s\S]*Content<\/span>[\s\S]*73%/);
});

test('recent checks keep the newest ten and nothing is recorded on errors', async () => {
  const storage = memoryStorage();
  let fail = true;
  const { context } = loadFrontend({ localStorage: storage,
    fetch: async () => { if (fail) throw new Error('offline'); return response(senderResult('a@example.com')); } });
  context.document.getElementById('email-input').value = 'a@example.com';
  await context.runEmailAnalysis();
  assert.equal(storage.getItem(RECENT), null, 'a failed request records nothing');
  fail = false;
  for (let i = 0; i < 12; i++) {
    context.recordRecentCheck({ mode: 'sender', label: `Check ${i}`, level: 'low', score: i, domain: `d${i}.test`, at: 1_700_000_000_000 + i });
  }
  const entries = stored(storage);
  assert.equal(entries.length, 10);
  assert.equal(entries[0].label, 'Check 11');
  assert.equal(entries[9].label, 'Check 2');
});

test('recent checks survive throwing, empty and tampered storage', async () => {
  const throwing = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceeded'); },
    removeItem() { throw new Error('SecurityError'); } };
  const { context, elements } = loadFrontend({ localStorage: throwing, clearTimeout() {},
    fetch: async () => response(senderResult('a@example.com')) });
  context.document.getElementById('email-input').value = 'a@example.com';
  await context.runEmailAnalysis();
  assert.equal(elements.get('result-area').classList.contains('hidden'), false, 'the result still renders');
  assert.equal(elements.get('email-error').textContent, '');
  assert.equal(elements.get('recent-checks-list').hidden, true);
  assert.match(elements.get('recent-checks-empty').textContent, /blocking local storage/);
  assert.doesNotThrow(() => context.clearRecentChecks());

  // A getter that throws (storage disabled entirely) is tolerated too.
  const blocked = loadFrontend({ clearTimeout() {} }).context;
  Object.defineProperty(blocked, 'localStorage', { get() { throw new Error('SecurityError'); } });
  assert.doesNotThrow(() => { blocked.setupRecentChecks(); blocked.recordRecentCheck(blocked.senderRecentEntry(senderResult('a@b.test'))); });

  // Empty storage shows the empty state; corrupt JSON is ignored.
  const empty = loadFrontend({ localStorage: memoryStorage({ [RECENT]: '{not json' }) });
  empty.context.setupRecentChecks();
  assert.equal(empty.elements.get('recent-checks-list').innerHTML, '');
  assert.equal(empty.elements.get('recent-checks-clear').hidden, true);
  assert.match(empty.elements.get('recent-checks-empty').textContent, /No checks yet/);

  // Hand-edited entries are rebuilt from allowed fields and escaped.
  const tampered = memoryStorage({ [RECENT]: JSON.stringify([
    { mode: 'sender', label: '<img src=x onerror=alert(1)>', level: 'high" onclick="x', score: 999,
      domain: 'bob@evil.test', at: 1_700_000_000_000, subject: 'Private' },
    { mode: 'evil', label: 'dropped', at: 1 },
    { mode: 'content', label: 'bad time', at: 'soon' },
    { mode: 'content', label: 'no score', score: '', at: 1_700_000_000_000 },
  ]) });
  const edited = loadFrontend({ localStorage: tampered });
  edited.context.setupRecentChecks();
  const html = edited.elements.get('recent-checks-list').innerHTML;
  assert.doesNotMatch(html, /<img|onclick|bob|dropped|bad time|Private/);
  assert.match(html, /&lt;img src=x/);
  assert.match(html, /recent-item recent-unknown/);
  assert.match(html, /evil\.test/);
  assert.match(html, /100\/100/);
  assert.match(html, /no score[\s\S]*—/);
  assert.equal(edited.elements.get('recent-checks-count').textContent, '(2)');
});

test('clearing recent checks wipes storage, announces, and returns focus to the disclosure', () => {
  const storage = memoryStorage();
  const { context, elements } = loadFrontend({ localStorage: storage, clearTimeout() {} });
  let focused = false;
  const summary = new FakeElement();
  summary.focus = () => { focused = true; };
  context.document.querySelector = selector => (selector === '#recent-checks > summary' ? summary : null);
  context.recordRecentCheck(context.senderRecentEntry(senderResult('a@example.com')));
  assert.equal(stored(storage).length, 1);
  context.clearRecentChecks();
  assert.equal(storage.getItem(RECENT), null);
  assert.equal(elements.get('recent-checks-list').innerHTML, '');
  assert.equal(elements.get('recent-checks-clear').hidden, true);
  assert.equal(elements.get('recent-checks-count').textContent, '');
  assert.equal(elements.get('copy-status').textContent, 'Recent checks cleared');
  assert.equal(focused, true);
});

test('relative times fall back to a date after a day', () => {
  const { context } = loadFrontend();
  const now = Date.UTC(2026, 8, 28, 12);
  assert.equal(context.formatRecentTime(now - 10_000, now), 'Just now');
  assert.equal(context.formatRecentTime(now - 5 * 60_000, now), '5 min ago');
  assert.equal(context.formatRecentTime(now - 3 * 3_600_000, now), '3 h ago');
  assert.match(context.formatRecentTime(now - 3 * 86_400_000, now), /2026/);
});

test('the recent list and privacy copy say the list stays in this browser', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const recent = html.match(/<details class="recent-checks" id="recent-checks">[\s\S]*?<\/details>/);
  assert.ok(recent, 'recent checks disclosure exists');
  assert.match(recent[0], /<summary>(?:<span[^>]*>)?Recent checks/);
  assert.match(recent[0], /only in this browser/i);
  assert.match(recent[0], /id="recent-checks-clear" data-action="clear-recent"/);
  assert.ok(html.indexOf('end panel-email-content') < html.indexOf('id="recent-checks"'));
  const notice = html.match(/<p class="raw-email-status content-privacy-notice">([\s\S]*?)<\/p>/)[1];
  assert.match(notice, /Recent checks list keeps only verdicts and scores in this browser/);
});

// ── Download report ──────────────────────────────────────────────────────────
function downloadHarness(overrides = {}) {
  const blobs = [], revoked = [], clicks = [];
  const { context, elements } = loadFrontend({
    Blob, clearTimeout() {},
    URL: { createObjectURL: blob => { blobs.push(blob); return `blob:report-${blobs.length}`; },
      revokeObjectURL: url => revoked.push(url) },
    ...overrides,
  });
  const appended = [];
  context.document.body = { appendChild: el => appended.push(el) };
  context.document.createElement = () => {
    const link = new FakeElement();
    link.click = () => clicks.push({ href: link.href, download: link.download, attached: appended.includes(link) });
    link.remove = () => { link.removed = true; };
    return link;
  };
  return { context, elements, blobs, revoked, clicks, appended };
}

test('sender reports download as Markdown with a timestamp, escaped text and the disclaimer', async () => {
  const h = downloadHarness();
  h.context.renderResult({ ...senderResult('a@paypa1-verify.xyz'), verdict: 'critical', label: 'Critical Sender Risk',
    risk_score: 100, disposable_status: 'no_known_match',
    risk_indicators: [{ level: 'high', msg: 'Homoglyph [login](http://evil.test) <b>*x*</b>' }, { level: 'info', msg: 'note' }] });
  h.context.downloadReport('sender', 'md');
  assert.equal(h.clicks.length, 1);
  assert.match(h.clicks[0].download, /^phishguard-sender-\d{8}-\d{6}\.md$/);
  assert.equal(h.clicks[0].href, 'blob:report-1');
  assert.equal(h.clicks[0].attached, true);
  assert.equal(h.appended[0].removed, true);
  assert.deepEqual(h.revoked, ['blob:report-1'], 'the object URL is revoked');
  assert.equal(h.blobs[0].type, 'text/markdown;charset=utf-8');
  const text = await h.blobs[0].text();
  assert.match(text, /^# PhishGuard sender check\n\n- \*\*Sender:\*\* a@paypa1-verify\.xyz\n- \*\*Verdict:\*\* Critical Sender Risk \(100\/100\)\n/);
  assert.match(text, /- \*\*Mailbox type:\*\* No known disposable-provider match/);
  assert.match(text, /- \*\*Generated:\*\* \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/);
  assert.match(text, /- \*\*high\*\* — Homoglyph \\\[login\\\]\(http:\/\/evil\.test\) \\<b\\>\\\*x\\\*\\<\/b\\>/);
  assert.doesNotMatch(text, /note/);
  assert.match(text, /_Heuristic result from PhishGuard; it does not prove a message is safe or malicious\._\n$/);
  assert.equal(h.elements.get('copy-status').textContent, 'Report downloaded');
});

test('content reports download as JSON with the API response and no *_base64 fields', async () => {
  const h = downloadHarness();
  const data = { ...contentResult('Medium Risk — Suspicious Content'), risk_level: 'medium', input_mode: 'image-evidence',
    eml_base64: 'AAAA', visual_analysis: { observations: [{ ocr_text: 'Pay now', image_base64: 'BBBB', nested: [{ Thumb_BASE64: 'CCCC', keep: 1 }] }] } };
  h.context.renderContentResult(data);
  h.context.downloadReport('content', 'json');
  assert.match(h.clicks[0].download, /^phishguard-image-\d{8}-\d{6}\.json$/);
  assert.equal(h.blobs[0].type, 'application/json');
  const text = await h.blobs[0].text();
  assert.doesNotMatch(text, /_base64|AAAA|BBBB|CCCC/i);
  const report = JSON.parse(text);
  assert.deepEqual(Object.keys(report), ['generated_at', 'tool', 'language', 'mode', 'result']);
  assert.equal(report.tool, 'PhishGuard');
  assert.equal(report.language, 'en');
  assert.equal(report.mode, 'image');
  assert.match(report.generated_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.equal(report.result.risk_label, 'Medium Risk — Suspicious Content');
  assert.equal(report.result.visual_analysis.observations[0].ocr_text, 'Pay now');
  assert.equal(report.result.visual_analysis.observations[0].nested[0].keep, 1);
  assert.equal(data.eml_base64, 'AAAA', 'the rendered result is not mutated');
  assert.deepEqual(h.revoked, ['blob:report-1']);
  assert.equal(h.elements.get('copy-status').textContent, 'Report downloaded');

  h.context.renderResult(senderResult('a@example.com'));
  h.context.downloadReport('sender', 'json');
  const sender = JSON.parse(await h.blobs[1].text());
  assert.equal(sender.mode, 'sender');
  assert.equal(sender.result.email, 'a@example.com');
  assert.match(h.clicks[1].download, /^phishguard-sender-\d{8}-\d{6}\.json$/);
});

test('content Markdown names the input, model and warnings; filenames use local time', () => {
  const { context } = loadFrontend();
  const text = context.contentReportMarkdown({
    ...contentResult('High Risk — Likely Phishing'), input_mode: 'raw-email', combined_phishing_score: 72.4,
    ml_label: 'Phishing', ml_phishing_probability: 63.2, ml_metrics: { model: 'LogisticRegression' },
    category_results: [{ label: 'Urgency', level: 'high', count: 1 }],
    extra_indicators: [{ level: 'medium', msg: 'Link text differs from destination' }],
    analysis_warnings: ['Attachment content was not inspected; only metadata was checked.'],
  }, new Date(Date.UTC(2026, 8, 28, 20, 5, 9)));
  assert.match(text, /^# PhishGuard content check\n\n- \*\*Input:\*\* Email file\n- \*\*Verdict:\*\* High Risk — Likely Phishing \(72% risk\)\n- \*\*Text model:\*\* TF-IDF \+ Logistic Regression — 63\.2% model risk score\n- \*\*Generated:\*\* 2026-09-28T20:05:09\.000Z\n/);
  assert.match(text, /## Categories\n\n- Urgency \(high, 1 signal\)/);
  assert.match(text, /## Technical indicators\n\n- \*\*medium\*\* — Link text differs from destination/);
  assert.match(text, /## Analysis warnings\n\n- Attachment content was not inspected; only metadata was checked\./);
  assert.match(text, /does not prove a message is safe or malicious/);
  assert.doesNotMatch(context.contentReportMarkdown({ ...contentResult('X'), input_mode: 'image-evidence', ml_label: 'Phishing' },
    new Date()), /Text model/, 'image results have no top-level model score');
  assert.equal(context.reportFilename('sender', 'md', new Date(2026, 8, 28, 13, 5, 9)), 'phishguard-sender-20260928-130509.md');
});

test('downloads ignore missing results and unknown formats, and report failures', () => {
  const h = downloadHarness();
  h.context.downloadReport('sender', 'md');
  h.context.renderResult(senderResult('a@example.com'));
  for (const [kind, format] of [['sender', 'pdf'], ['sender', undefined], ['sender', '__proto__'], ['sender', 'toString'], ['__proto__', 'md'], ['constructor', 'json']]) {
    h.context.downloadReport(kind, format);
  }
  assert.equal(h.clicks.length, 0);
  assert.equal(h.elements.has('copy-status'), false, 'nothing was announced');

  const failing = downloadHarness({ URL: { createObjectURL() { throw new Error('no blobs'); }, revokeObjectURL() { throw new Error('unexpected'); } } });
  failing.context.renderResult(senderResult('a@example.com'));
  failing.context.downloadReport('sender', 'md');
  assert.equal(failing.elements.get('copy-status').textContent, 'Download failed');
});

test('download controls sit beside each copy button as a labelled, keyboard-reachable group', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  for (const kind of ['sender', 'content']) {
    const group = html.match(new RegExp(`data-action="copy-summary" data-arg="${kind}">[\\s\\S]*?<div class="download-group" role="group" aria-labelledby="${kind}-download-label">([\\s\\S]*?)</div>`));
    assert.ok(group, kind);
    assert.match(group[1], new RegExp(`<span class="download-label" id="${kind}-download-label">[\\s\\S]*Download report</span>`));
    assert.match(group[1], new RegExp(`<button type="button" class="download-option" data-action="download-report" data-arg="${kind}:md">Markdown</button>`));
    assert.match(group[1], new RegExp(`<button type="button" class="download-option" data-action="download-report" data-arg="${kind}:json">JSON</button>`));
  }
});

// ── Without JavaScript, and on phones ────────────────────────────────────────
test('a visible <noscript> notice explains that the analyzer needs JavaScript', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const notices = [...html.matchAll(/<noscript>([\s\S]*?)<\/noscript>/g)].map(match => match[1]);
  assert.equal(notices.length, 2, 'one at the top of the page, one in place of the demo form');
  for (const notice of notices) {
    assert.match(notice, /^<p class="noscript-notice" role="note">[\s\S]*JavaScript[\s\S]*<\/p>$/);
    // Plain text only: no script, style or translation hooks (nothing runs to translate it).
    assert.doesNotMatch(notice, /<(script|style|link)\b|data-i18n|\sstyle=/);
  }
  assert.ok(html.indexOf('<noscript>') < html.indexOf('class="hero-badge"'), 'the first notice opens the hero');
  const demo = html.slice(html.indexOf('id="demo"'));
  assert.ok(demo.indexOf('<noscript>') < demo.indexOf('class="demo-tabs"'), 'the second replaces the demo form');
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(css, /\.noscript-notice \{[^}]*border:[^}]*\}/);
  // Controls that do nothing without scripts are hidden where `scripting` is supported;
  // other browsers show the page exactly as before.
  const noScript = css.match(/@media \(scripting: none\) \{([^}]*)\}/)[1];
  for (const selector of ['.theme-toggle', '.lang-toggle', '.nav-menu-toggle', '.demo-tabs', '.tab-panel']) {
    assert.ok(noScript.includes(selector), selector);
  }
  // The pre-paint hiding is set only by lang-init.js, so without JavaScript the page is never hidden.
  assert.doesNotMatch(html, /data-i18n-pending/);
});

test('the sender address field asks phones for an address keyboard without native email validation', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const input = html.match(/<input\s[^>]*id="email-input"[^>]*>/)[0];
  for (const attr of ['type="text"', 'inputmode="email"', 'autocapitalize="off"', 'autocorrect="off"',
    'enterkeyhint="go"', 'autocomplete="off"', 'spellcheck="false"']) {
    assert.ok(input.includes(attr), attr);
  }
  assert.doesNotMatch(input, /type="email"|\srequired|\spattern=/, 'the app keeps its own address rules (IDN, syntax)');
});

// ── Severity in words (WCAG 1.4.1) and a style-src 'self' page ───────────────
const levelRows = html => [...html.matchAll(/<div class="risk-item risk-([^"]*)">([\s\S]*?)<\/div>/g)]
  .map(([, level, row]) => ({level, row}));

test('indicator rows state their level in words next to a decorative dot', () => {
  const { context, elements } = loadFrontend();
  context.renderResult({ ...senderResult('a@example.com'), verdict: 'high', risk_score: 41,
    risk_indicators: ['critical', 'high', 'medium', 'low', 'info', 'bogus'].map(level => ({ level, msg: `${level} <msg>` })) });
  const sender = levelRows(elements.get('risk-indicators-list').innerHTML);
  // Info notes stay out of the sender list, as before.
  assert.deepEqual(sender.map(row => row.level), ['critical', 'high', 'medium', 'low', 'bogus']);
  context.renderContentResult({ ...contentResult('Result'), risk_level: 'high',
    extra_indicators: ['critical', 'high', 'medium', 'low', 'info', 'bogus'].map(level => ({ level, msg: `${level} <msg>` })) });
  const content = levelRows(elements.get('content-extra-list').innerHTML);
  assert.deepEqual(content.map(row => row.level), ['critical', 'high', 'medium', 'low', 'info', 'bogus']);
  for (const { level, row } of [...sender, ...content]) {
    assert.match(row, /^\s*<span class="risk-dot" aria-hidden="true"><\/span>/, level);
    assert.match(row, new RegExp(`${level} &lt;msg&gt;</span>\\s*$`), level);
    if (level === 'bogus') {
      assert.doesNotMatch(row, /level-label/, 'an unknown level gets no label');
    } else {
      assert.match(row, new RegExp(`<span class="level-label level-${level}">${level}</span>\\s*<span class="risk-msg">`), level);
    }
  }
});

test('the level pill looks like the category badge and keeps AA contrast in the light theme', () => {
  const css = appSource('style.css');
  assert.match(css, /\.cat-level-badge, \.level-label \{[^}]*text-transform: uppercase;/);
  for (const level of ['critical', 'high', 'medium', 'low', 'info']) assert.match(css, new RegExp(`\\.level-${level} +\\{`), level);
  const light = Object.fromEntries([...css.matchAll(/:root\[data-theme="light"\] \.level-(\w+) +\{ color: (#[0-9a-f]{6}); \}/g)]
    .map(([, level, color]) => [level, color]));
  assert.deepEqual(Object.keys(light), ['critical', 'high', 'medium', 'low']);
  // Measured on the pill tint over a tinted row on the light card (the darkest case).
  const channel = value => { const c = value / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
  const luminance = rgb => 0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2]);
  const hex = value => [1, 3, 5].map(index => parseInt(value.slice(index, index + 2), 16));
  const over = (top, alpha, bottom) => top.map((c, index) => c * alpha + bottom[index] * (1 - alpha));
  const card = over([255, 255, 255], 0.62, hex('#f4f6fb'));
  const tint = { critical: '#ff5c6c', high: '#ff8a4c', medium: '#f0c05a', low: '#6fb6ff' };
  for (const [level, color] of Object.entries(light)) {
    const background = over(hex(tint[level]), 0.16, over(hex('#ff5c6c'), 0.10, card));
    const [a, b] = [luminance(hex(color)), luminance(background)].sort((x, y) => y - x);
    assert.ok((a + 0.05) / (b + 0.05) >= 4.5, `${level}: ${((a + 0.05) / (b + 0.05)).toFixed(2)}`);
  }
});

test('technical indicator and safety cards toggle with the hidden attribute, not an inline style', () => {
  const { context, elements } = loadFrontend();
  context.renderContentResult({ ...contentResult('Result'), extra_indicators: [{ level: 'high', msg: 'x' }], safety_signals: ['ok'] });
  assert.equal(elements.get('content-extra-card').hidden, false);
  assert.equal(elements.get('content-safety-card').hidden, false);
  context.renderContentResult(contentResult('Result'));
  assert.equal(elements.get('content-extra-card').hidden, true);
  assert.equal(elements.get('content-safety-card').hidden, true);
  for (const id of ['content-extra-card', 'content-safety-card']) assert.equal(elements.get(id).style.display, undefined, id);
  const html = appSource('index.html');
  assert.match(html, /<div class="col-card" id="content-extra-card" hidden>/);
  assert.match(html, /<div class="col-card" id="content-safety-card" hidden>/);
  assert.match(appSource('style.css'), /\.col-card\[hidden\] \{ display: none; \}/);
});

test('the homepage and 404 page need no inline styles, so the CSP can be style-src \'self\'', () => {
  for (const page of ['index.html', '404.html']) {
    const html = appSource(page);
    assert.doesNotMatch(html, /\sstyle\s*=/i, `${page}: style attribute`);
    assert.doesNotMatch(html, /<style\b/i, `${page}: <style> element`);
  }
  // Scripts may set element.style (CSSOM, allowed by the CSP) but never a style
  // attribute, a style="" in HTML they insert, or a <style> element.
  const scripts = [...APP_SCRIPTS, 'i18n.js', 'i18n-zh.js', 'vision.js', 'vision-core.mjs', 'vision-email.mjs', 'vision-html.mjs',
    'vision-cid.mjs', 'vision-worker.mjs', 'feedback.js', 'confirm-dialog.js', 'file-intake.js', 'request.js', 'analytics-init.js',
    'theme-init.js', 'lang-init.js'];
  for (const name of scripts) {
    const code = appSource(name);
    assert.doesNotMatch(code, /setAttribute\(\s*['"`]style['"`]/, `${name}: setAttribute('style')`);
    assert.doesNotMatch(code, /\sstyle=/, `${name}: style= in markup`);
    assert.doesNotMatch(code, /createElement(NS)?\([^)]*['"`]style['"`]\)|<style\b|\.cssText\b|insertRule\(|adoptedStyleSheets/, `${name}: stylesheet injection`);
  }
});

test('forced-colours mode keeps dots, rings, badges and level labels distinguishable', () => {
  const block = (css, name) => {
    const start = css.indexOf('@media (forced-colors: active) {');
    assert.ok(start >= 0, name);
    return css.slice(start, css.indexOf('\n}\n', start));
  };
  const home = block(appSource('style.css'), 'style.css');
  assert.match(home, /\.bg-fluid, \.orb, \.orb-ring \{ display: none; \}/);
  assert.match(home, /\.risk-item \.risk-dot[^{]*\{ forced-color-adjust: none; background: CanvasText;/);
  assert.match(home, /\.ring-track \{ stroke: CanvasText; \}/);
  assert.match(home, /\.ring-fg \{ stroke: Highlight !important; \}/);
  assert.match(home, /\.level-label, \.cat-level-badge, \.pill,[^{]*\{ border: 1px solid CanvasText; \}/);
  assert.match(home, /outline: 2px solid Highlight/);
  const cases = block(appSource('cases.css'), 'cases.css');
  assert.match(cases, /\.status-dot, #evidence li::before[^{]*\{ forced-color-adjust: none; background: CanvasText;/);
  assert.match(cases, /\.badge, \.feedback-badge \{ border: 1px solid CanvasText; \}/);
});

test('an .eml topped by Gmail\'s own check suggests the mailbox choice without making it', async () => {
  const { context, elements } = loadFrontend({ fetch: async () => response(contentResult('File result')) });
  context.setupInputEvents();
  const raw = emlBytes('Authentication-Results: mx.google.com;\r\n  dmarc=pass header.from=example.com\r\n'
    + 'From: a@example.com\r\nSubject: Hi\r\n\r\nBody');
  await elements.get('raw-email-file').listeners.change({ target: { files: [{ name: 'mail.eml', arrayBuffer: async () => raw }] } });
  assert.equal(elements.get('content-mailbox').value, '');
  assert.equal(elements.get('content-mailbox-hint').hidden, false);
  assert.match(elements.get('content-mailbox-hint-text').textContent, /Gmail’s own sender check/);
  elements.get('content-mailbox-use').listeners.click();
  assert.equal(elements.get('content-mailbox').value, 'gmail');
  assert.equal(elements.get('content-mailbox-hint').hidden, true);
  const other = emlBytes('Authentication-Results: mx.example.net; dmarc=pass\r\nFrom: a@example.com\r\n\r\nBody');
  await elements.get('raw-email-file').listeners.change({ target: { files: [{ name: 'other.eml', arrayBuffer: async () => other }] } });
  assert.equal(elements.get('content-mailbox-hint').hidden, true);
});

test('an alerting result suggests the original .eml, or rerunning with the detected mailbox', async () => {
  const requests = [];
  const alerting = { ...contentResult('Alert'), risk_level: 'high' };
  const { context, elements } = loadFrontend({ fetch: async (url, options) => {
    requests.push({ url, body: JSON.parse(options.body) });
    return response(alerting);
  } });
  context.setupInputEvents();
  elements.get('content-body').value = 'Your account is locked.';
  await context.runContentAnalysis();
  assert.equal(elements.get('content-accuracy-tip').hidden, false);
  assert.match(elements.get('content-accuracy-tip-text').textContent, /original email \(\.eml\)/);
  assert.equal(elements.get('content-accuracy-guide').hidden, false);
  assert.equal(elements.get('content-accuracy-rerun').hidden, true);

  const raw = emlBytes('Authentication-Results: mx.microsoft.com 1; dmarc=pass header.from=example.com\r\n'
    + 'From: a@example.com\r\nSubject: Hi\r\n\r\nBody');
  await elements.get('raw-email-file').listeners.change({ target: { files: [{ name: 'mail.eml', arrayBuffer: async () => raw }] } });
  // The reader is asked first; nothing is sent until they answer.
  const sent = requests.length;
  await context.runContentAnalysis();
  assert.equal(requests.length, sent);
  assert.equal(elements.get('content-mailbox-hint').hidden, false);
  assert.match(elements.get('content-mailbox-hint-text').textContent, /Did you download it from Outlook\.com yourself\? Answer this first/);
  await elements.get('content-mailbox-decline').listeners.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(requests.at(-1).url, '/api/analyze-visual');
  assert.equal(requests.at(-1).body.mailbox, undefined);
  assert.equal(elements.get('content-mailbox-hint').hidden, true);
  assert.equal(elements.get('content-accuracy-rerun').hidden, false);
  assert.match(elements.get('content-accuracy-rerun').textContent, /Outlook\.com/);
  await elements.get('content-accuracy-rerun').listeners.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(requests.at(-1).body.mailbox, 'outlook');
  assert.equal(elements.get('content-accuracy-tip').hidden, true);
});

test('a model-driven alert says the text model raised it, without changing the verdict', async () => {
  let result = { ...contentResult('Medium Risk — Model Signal Needs Review'), risk_level: 'medium',
    combined_phishing_score: 72, fusion_basis: 'model_only' };
  const { context, elements } = loadFrontend({ fetch: async () => response(result) });
  context.setupInputEvents();
  elements.get('content-body').value = 'Your security code is 123456.';
  await context.runContentAnalysis();
  assert.equal(elements.get('content-accuracy-tip').hidden, false);
  const pasted = elements.get('content-accuracy-tip-text').textContent;
  assert.match(pasted, /^This alert comes mainly from the text model/);
  assert.match(pasted, /original email \(\.eml\)/);
  assert.equal(elements.get('content-accuracy-guide').hidden, false);
  assert.equal(elements.get('crb-title').textContent, 'Medium Risk — Model Signal Needs Review');

  // An .eml topped by Outlook.com's check: the rerun offer, with the model reason.
  result = { ...result, risk_level: 'high', risk_label: 'High Risk — Model Signal Needs Review', fusion_basis: 'model_led' };
  const raw = emlBytes('Authentication-Results: mx.microsoft.com 1; dmarc=pass header.from=example.com\r\n'
    + 'From: a@example.com\r\nSubject: Hi\r\n\r\nBody');
  await elements.get('raw-email-file').listeners.change({ target: { files: [{ name: 'mail.eml', arrayBuffer: async () => raw }] } });
  await context.runContentAnalysis();
  await elements.get('content-mailbox-decline').listeners.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(elements.get('content-accuracy-tip-text').textContent, /^This alert comes mainly from the text model.*Outlook\.com/);
  assert.equal(elements.get('content-accuracy-rerun').hidden, false);

  // With the mailbox chosen there is nothing more to choose; the reason stays.
  await elements.get('content-accuracy-rerun').listeners.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(elements.get('content-accuracy-tip').hidden, false);
  assert.match(elements.get('content-accuracy-tip-text').textContent,
    /^This alert comes mainly from the text model.*Check the sender address and links yourself/);
  assert.equal(elements.get('content-accuracy-rerun').hidden, true);
  assert.equal(elements.get('content-accuracy-guide').hidden, true);

  // Corroborated alerts on a chosen mailbox keep no tip, as before.
  result = { ...result, risk_label: 'High Risk — Likely Phishing', fusion_basis: 'corroborated' };
  await context.runContentAnalysis();
  assert.equal(elements.get('content-accuracy-tip').hidden, true);
});

test('an original email with only a text-model note has nothing to settle', async () => {
  const result = { ...contentResult('Low Risk — Text Model Signal Only'), risk_level: 'low', input_mode: 'raw-email',
    combined_phishing_score: 29, fusion_basis: 'model_only', ml_phishing_probability: 91, ml_label: 'Likely Phishing' };
  const { context, elements } = loadFrontend({ fetch: async () => response(result) });
  context.setupInputEvents();
  elements.get('content-body').value = 'Your security code is 123456.';
  await context.runContentAnalysis();
  assert.equal(elements.get('crb-title').textContent, 'Low Risk — Text Model Signal Only');
  assert.match(elements.get('crb-sub').textContent, /a note, not an alert/);
  // No accuracy tip and no "did you do this yourself?" question.
  assert.equal(elements.get('content-accuracy-tip').hidden, true);
  assert.equal(elements.get('content-requested').hidden, true);
});

test('a clean result shows no accuracy tip', async () => {
  const { context, elements } = loadFrontend({ fetch: async () => response(contentResult('Clean')) });
  context.setupInputEvents();
  elements.get('content-body').value = 'Lunch at noon?';
  await context.runContentAnalysis();
  assert.equal(elements.get('content-accuracy-tip').hidden, true);
});

test('the mail-type note names scam tactics or advertising beside the verdict', async () => {
  let result = { ...contentResult('High Risk — Likely Phishing'), risk_level: 'high',
    mail_type: { type: 'phishing', tactics: ['callback', 'impersonation', 'unknown_tactic'] } };
  const { context, elements } = loadFrontend({ fetch: async () => response(result) });
  context.setupInputEvents();
  elements.get('content-body').value = 'Call us to cancel the charge.';
  await context.runContentAnalysis();
  const note = elements.get('crb-type');
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, 'Looks like phishing or a scam: asks you to call a number, impersonates a known brand.');
  assert.equal(elements.get('crb-title').textContent, 'High Risk — Likely Phishing');

  result = { ...contentResult('Low Risk — Minor Concerns'), risk_level: 'low', mail_type: { type: 'advertising' } };
  await context.runContentAnalysis();
  assert.match(note.textContent, /^Looks like advertising or marketing mail, not phishing/);

  result = { ...result, risk_level: 'medium', risk_label: 'Medium Risk — Suspicious Content' };
  await context.runContentAnalysis();
  assert.match(note.textContent, /^Looks like advertising, but scam signs remain/);

  result = { ...contentResult('No Phishing Indicators Found'), risk_level: 'safe', mail_type: null };
  await context.runContentAnalysis();
  assert.equal(note.hidden, true);
});

test('an .eml topped by a service check is asked about before it is analyzed', async () => {
  const requests = [];
  const { context, elements } = loadFrontend({ fetch: async (url, options) => {
    requests.push({ url, body: JSON.parse(options.body) });
    return response({ ...contentResult('Low Risk — Minor Concerns'), risk_level: 'low' });
  } });
  context.setupInputEvents();
  const raw = emlBytes('Authentication-Results: mx.microsoft.com 1; dmarc=pass header.from=example.com\r\n'
    + 'From: a@example.com\r\nSubject: Hi\r\n\r\nBody');
  const load = name => elements.get('raw-email-file').listeners.change(
    { target: { files: [{ name, arrayBuffer: async () => raw }] } });
  await load('mail.eml');
  await context.runContentAnalysis();
  assert.equal(requests.length, 0);
  assert.match(elements.get('content-mailbox-hint-text').textContent, /Answer this first/);
  assert.equal(elements.get('content-mailbox-decline').textContent, 'No, or not sure');
  await elements.get('content-mailbox-use').listeners.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(requests.at(-1).body.mailbox, 'outlook');
  assert.equal(elements.get('content-mailbox-hint').hidden, true);

  // A new file is asked about again.
  await load('other.eml');
  elements.get('content-mailbox').value = '';
  await context.runContentAnalysis();
  assert.equal(requests.length, 1);
  // Choosing in the menu answers the question too.
  elements.get('content-mailbox').listeners.change();
  await context.runContentAnalysis();
  assert.equal(requests.length, 2);
  assert.equal(requests.at(-1).body.mailbox, undefined);
});

test('a model-driven account notice asks whether it was requested and sends the answer', async () => {
  const requests = [];
  const { context, elements } = loadFrontend({ fetch: async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ url, body });
    return response(body.requested
      ? { ...contentResult('Low Risk — Confirmed as Your Own Action'), risk_level: 'low', requested_question: false }
      : { ...contentResult('High Risk — Model Signal Needs Review'), risk_level: 'high', fusion_basis: 'model_led',
          requested_question: true });
  } });
  context.setupInputEvents();
  elements.get('content-subject').value = 'Reset your password';
  elements.get('content-body').value = 'We received a request to reset the password for your account.';
  await context.runContentAnalysis();
  const question = elements.get('content-requested');
  assert.equal(question.hidden, false);
  assert.match(elements.get('content-requested-text').textContent, /Are you sure you did this yourself just now\?/);
  assert.equal(requests.at(-1).body.requested, undefined);

  await elements.get('content-requested-yes').listeners.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(requests.at(-1).url, '/api/analyze-content');
  assert.equal(requests.at(-1).body.requested, 'yes');
  assert.equal(question.hidden, true);
  assert.equal(elements.get('crb-title').textContent, 'Low Risk — Confirmed as Your Own Action');

  // Editing the text drops the earlier answer.
  elements.get('content-body').listeners.input();
  await context.runContentAnalysis();
  assert.equal(requests.at(-1).body.requested, undefined);
  assert.equal(question.hidden, false);
});

test('scroll reveal replays on every entry, from the side the element arrives on', () => {
  const step = new FakeElement();
  const props = {};
  step.style = { setProperty: (key, value) => { props[key] = value; }, removeProperty: key => { delete props[key]; } };
  step.parentElement = {};
  step.compareDocumentPosition = () => 0;
  let callback, options;
  const observed = [], unobserved = [];
  class FakeObserver {
    constructor(cb, opts) { callback = cb; options = opts; }
    observe(el) { observed.push(el); }
    unobserve(el) { unobserved.push(el); }
  }
  const document = {
    addEventListener() {},
    createElement: () => new FakeElement(),
    getElementById: () => new FakeElement(),
    querySelector: () => new FakeElement(),
    // The joined REVEAL_SELECTORS start with .section-header; the groups find nothing.
    querySelectorAll: selector => (selector.startsWith('.section-header') ? [step] : []),
  };
  const { context } = loadFrontend({ document, IntersectionObserver: FakeObserver, matchMedia: () => ({ matches: false }) });
  context.setupScrollReveal();
  assert.equal(options.threshold, 0);
  assert.deepEqual(observed, [step]);
  const has = name => step.classList.contains(name);
  const enter = top => callback([{ target: step, isIntersecting: true, boundingClientRect: { top }, rootBounds: { top: 0 } }]);

  enter(400);  // scrolling down: rises from below
  assert.ok(has('reveal') && has('in-view') && !has('from-above'));
  assert.equal(props['--reveal-delay'], '0ms');
  step.listeners.animationend({ target: step });
  assert.ok(has('settled'));

  callback([{ target: step, isIntersecting: false }]);  // fully out of view: reset
  assert.ok(has('reveal') && !has('in-view') && !has('settled'));
  assert.equal('--reveal-delay' in props, false);

  enter(-120);  // scrolling up: drifts down from above, and plays again
  assert.ok(has('in-view') && has('from-above') && !has('settled'));
  assert.deepEqual(unobserved, []);
});

test('compat.js gives older phone browsers the APIs the page setup calls', () => {
  // An older WebView: no Object.hasOwn, MediaQueryList with addListener only, crypto without randomUUID.
  const added = [];
  class MediaQueryList { addListener(listener) { added.push(listener); } removeListener() {} }
  const crypto = { getRandomValues: bytes => bytes.fill(7) };
  const context = vm.createContext({ MediaQueryList, crypto });
  vm.runInContext('delete Object.hasOwn;', context);
  assert.equal(vm.runInContext('typeof Object.hasOwn', context), 'undefined');
  vm.runInContext(appSource('compat.js'), context, { filename: 'compat.js' });
  assert.equal(vm.runInContext("Object.hasOwn({ a: 1 }, 'a') && !Object.hasOwn({}, 'toString')", context), true);
  const listener = () => {};
  new MediaQueryList().addEventListener('change', listener);
  assert.deepEqual(added, [listener]);
  assert.match(crypto.randomUUID(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('compat.js is the first script of every page and parses as ES5', () => {
  for (const page of ['index.html', 'cases.html', '404.html']) {
    const html = readFileSync(new URL(`./${page}`, import.meta.url), 'utf8');
    const first = html.match(/<script src="\/static\/([^"?]+)/)[1];
    assert.equal(first, 'compat.js', page);
  }
  const source = appSource('compat.js');
  assert.doesNotMatch(source, /=>|\b(?:let|const|class)\b|`|\?\.|\?\?/);
});

test('one failing setup step does not stop the others', () => {
  const errors = [];
  const { context } = loadFrontend({ console: { ...console, error: (...args) => errors.push(args) } });
  const ran = [];
  context.runSetupSteps([
    function setupTheme() { throw new TypeError('matchMedia(...).addEventListener is not a function'); },
    function setupSmsInput() { ran.push('sms'); },
  ]);
  assert.deepEqual(ran, ['sms']);
  assert.match(errors[0][0], /setupTheme failed/);
});
