import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import {FakeElement, loadPage, memoryStorage, runScenarios, runVisionScenario} from '../tests/fixtures/i18n/scenarios.mjs';

const source = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
const APP_SCRIPTS = ['app-core.js', 'app-theme.js', 'app-layout.js', 'app-config.js', 'app-sender.js', 'app-verify.js',
  'app-content.js', 'app-content-render.js', 'app-sms.js', 'app-reports.js', 'app-metrics.js', 'app.js'];
// A Chinese page runs i18n-zh.js (requested by lang-init.js) before i18n.js;
// the English snapshot runs without it, as an English visitor does.
const PAGE = ['i18n-zh.js', 'i18n.js', ...APP_SCRIPTS];
const EN_PAGE = ['i18n.js', ...APP_SCRIPTS];
// Homepage scripts whose strings come from the dictionary.
const T_FILES = [...APP_SCRIPTS, 'feedback.js'];
// Shared with cases.html: tr('key', 'English', params), whose inline English is
// the fallback if i18n.js failed to load.
const TR_FILES = ['vision.js', 'file-intake.js', 'confirm-dialog.js'];

function loadI18n({languages = ['en-US'], storage = memoryStorage(), document, console: con = console, zh = true} = {}) {
  const window = {};
  const context = vm.createContext({window, navigator: {languages, language: languages[0]}, localStorage: storage,
    console: con, CustomEvent, ...(document ? {document} : {})});
  if (zh) vm.runInContext(source('i18n-zh.js'), context, {filename: 'i18n-zh.js'});
  vm.runInContext(source('i18n.js'), context, {filename: 'i18n.js'});
  return {i18n: window.PhishGuardI18n, context, storage};
}
const {DICTIONARY} = loadI18n().i18n;
const {en, zh} = DICTIONARY;
const placeholders = text => [...text.matchAll(/\{(\w+)\}/g)].map(match => match[1]).sort();

// ── Dictionary shape ─────────────────────────────────────────────────────────
test('en and zh dictionaries have identical keys, no empty values and matching placeholders', () => {
  assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
  assert.ok(Object.keys(en).length > 400, `${Object.keys(en).length} keys`);
  for (const [lang, dict] of Object.entries(DICTIONARY)) {
    for (const [key, value] of Object.entries(dict)) {
      assert.equal(typeof value, 'string', `${lang} ${key}`);
      assert.ok(value.trim().length > 0, `${lang} ${key} is empty`);
      assert.match(key, /^[a-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/, `key shape: ${key}`);
    }
  }
  for (const key of Object.keys(en)) assert.deepEqual(placeholders(zh[key]), placeholders(en[key]), key);
});

test('only <kbd> markup appears in dictionary strings, and only in the data-i18n-html keys', () => {
  const html = source('index.html');
  const htmlKeys = new Set([...html.matchAll(/data-i18n-html="([^"]+)"/g)].map(match => match[1]));
  assert.deepEqual([...htmlKeys].sort(), ['content.hint.submit', 'sender.hint.slash']);
  for (const [lang, dict] of Object.entries(DICTIONARY)) {
    for (const [key, value] of Object.entries(dict)) {
      const tags = value.match(/<\/?[a-z][^>]*>/gi) || [];
      if (htmlKeys.has(key)) {
        assert.ok(tags.length > 0 && tags.every(tag => /^<\/?kbd>$/.test(tag)), `${lang} ${key}`);
      } else {
        assert.deepEqual(tags, [], `${lang} ${key} must be plain text`);
      }
    }
  }
});

test('Chinese strings keep the product name, protocol names and the key safety caveats', () => {
  for (const key of Object.keys(en)) {
    for (const term of ['PhishGuard', 'SPF', 'DKIM', 'DMARC', 'SMTP', 'WHOIS', 'OCR', 'MX', 'PTR', 'TF-IDF', 'RFC 5321', 'RFC 5322', 'Null MX',
      'Jev', 'TypeSafe', 'UTC', 'Vercel']) {
      if (en[key].includes(term)) assert.ok(zh[key].includes(term), `${key} keeps "${term}"`);
    }
    for (const number of en[key].match(/\b\d+(?:[.,]\d+)?\b/g) || []) {
      assert.ok(zh[key].includes(number), `${key} keeps the number ${number}`);
    }
  }
  // Caveats that must not be softened: heuristic ≠ probability, low risk ≠ safe.
  assert.match(zh['sender.suspectNote'], /不是训练模型给出的概率/);
  assert.match(zh['sender.scope'], /不能证明邮件是安全的/);
  assert.match(zh['content.sub.safe'], /并不能证明邮件是安全的/);
  assert.match(zh['footer.tagline'], /低风险结果并不代表一定安全/);
  assert.match(zh['summary.disclaimer'], /不能证明邮件是安全的[\s\S]*恶意/);
  assert.match(zh['vision.confidenceNote'], /不是钓鱼概率/);
  assert.match(zh['recent.note'], /绝不保存邮箱地址或邮件内容/);
  assert.match(zh['content.privacy'], /假名化/);
  assert.match(zh['feedback.privacy2'], /不会自动重新训练模型/);
  // Case workspace: the same caveats, retention and privacy notices.
  assert.match(zh['cases.footer.caveat'], /低风险结果并不代表一定安全/);
  assert.match(zh['cases.compose.privacy'], /原始附件数据不会保存[\s\S]*仅提交您有权保留的邮件/);
  assert.match(zh['cases.jev.disclosureText'], /其他个人信息可能仍然保留[\s\S]*不会改变案例的风险或判定[\s\S]*缓存 24 小时[\s\S]*案例保留政策/);
  assert.match(zh['cases.jev.probability'], /这不是严重程度评分/);
  assert.match(zh['cases.jev.result'], /并非已核实的结论/);
  assert.match(zh['cases.overview.status'], /不是模型的总体错误率/);
  assert.match(zh['cases.capacity.advice'], /关闭记录不会释放空间/);
  assert.match(zh['cases.login.tokenHelp'], /不会吊销/);
  // The homepage no longer calls the workspace English-only.
  assert.doesNotMatch(zh['nav.caseLogin.aria'], /英文/);
});

test('Chinese UI terminology is consistent (案例, 分析员, 判定, statuses)', () => {
  for (const [key, value] of Object.entries(zh)) {
    assert.doesNotMatch(value, /案件|分析人员|分析师/, key);
  }
  assert.deepEqual(['pending', 'in_progress', 'closed'].map(status => zh[`cases.status.${status}`]), ['待处理', '处理中', '已关闭']);
  assert.equal(zh['cases.reason.false_alert'], '误报');
  assert.equal(zh['cases.reason.missed_threat'], '漏报');
  assert.equal(zh['cases.review.verdictLabel'], '人工判定');
});

// ── Static markup ────────────────────────────────────────────────────────────
const decode = text => text.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
const normalize = text => decode(text).replace(/\s+/g, ' ').trim();

test('every data-i18n key in index.html exists and its English is the markup text itself', () => {
  const html = source('index.html');
  const elements = [...html.matchAll(/<([a-z0-9]+)\b([^>]*?)\sdata-i18n="([^"]+)"([^>]*)>([\s\S]*?)<\/\1>/g)];
  assert.ok(elements.length > 180, `${elements.length} data-i18n elements`);
  for (const [, tag, , key, , inner] of elements) {
    assert.ok(Object.hasOwn(en, key), `missing key ${key}`);
    assert.doesNotMatch(inner, /<[a-z]/i, `<${tag} data-i18n="${key}"> must contain text only`);
    assert.equal(normalize(inner), en[key], key);
  }
  for (const [, key, inner] of html.matchAll(/data-i18n-html="([^"]+)">([\s\S]*?)<\/p>/g)) {
    assert.equal(inner.replace(/\s+/g, ' ').trim(), en[key], key);
  }
});

test('every data-i18n-attr key exists and its English equals the attribute in the markup', () => {
  const html = source('index.html');
  const tags = [...html.matchAll(/<[a-z]+\b[^>]*data-i18n-attr="([^"]+)"[^>]*>/g)];
  assert.ok(tags.length >= 15, `${tags.length} tags`);
  for (const [tag, spec] of tags) {
    for (const pair of spec.split(';')) {
      const [attr, key] = pair.split(':');
      assert.ok(Object.hasOwn(en, key), `missing key ${key}`);
      const value = tag.match(new RegExp(`\\s${attr}="([^"]*)"`));
      assert.ok(value, `${attr} present on ${tag.slice(0, 60)}`);
      assert.equal(decode(value[1]), en[key], key);
    }
  }
});

test('all visible homepage text is translatable except language-neutral names', () => {
  // Text nodes outside any data-i18n element: brand/product names, example
  // addresses, numbers, file formats and header names stay as they are.
  // <noscript> text shows only without JavaScript, when nothing can translate
  // it, so it is English only (checked in app.test.mjs).
  const html = source('index.html').replace(/<!--[\s\S]*?-->|<!DOCTYPE[^>]*>/g, '')
    .replace(/<(script|style|svg|code|kbd|title|noscript)\b[\s\S]*?<\/\1>/g, '');
  const stack = [];
  const leftovers = [];
  for (const [, close, tag, attrs, textNode] of html.matchAll(/<(\/?)([a-z0-9]+)\b([^>]*)>|([^<]+)/g)) {
    if (textNode !== undefined) {
      const text = normalize(textNode);
      if (text && !stack.some(entry => entry.covered)) leftovers.push(text);
    } else if (close) {
      while (stack.length && stack.pop().tag !== tag);
    } else if (!/^(meta|link|input|br|img|source|hr)$/.test(tag) && !attrs.endsWith('/')) {
      stack.push({tag, covered: /\sdata-i18n(-html)?="/.test(attrs) || /aria-hidden="true"/.test(attrs) && tag !== 'button'});
    }
  }
  const allowed = /^(PhishGuard|\d+|0\d|[\w.+-]+@[\w.-]+|[\w-]+\.(com|cc)|Markdown|JSON|ML|Text model|From|Reply-To|Python 3\.13|scikit-learn|FastAPI|pandas|NumPy|Chart\.js|UCI ML Repo|GitHub|×)$/;
  assert.deepEqual(leftovers.filter(text => !allowed.test(text)), []);
});

// ── Case workspace markup (cases.html) ──────────────────────────────────────
test('every data-i18n key in cases.html exists and its English is the markup text itself', () => {
  const html = source('cases.html');
  const elements = [...html.matchAll(/<([a-z0-9]+)\b([^>]*?)\sdata-i18n="([^"]+)"([^>]*)>([\s\S]*?)<\/\1>/g)];
  assert.ok(elements.length > 110, `${elements.length} data-i18n elements`);
  for (const [, tag, , key, , inner] of elements) {
    assert.ok(Object.hasOwn(en, key), `missing key ${key}`);
    assert.doesNotMatch(inner, /<[a-z]/i, `<${tag} data-i18n="${key}"> must contain text only`);
    assert.equal(normalize(inner), en[key], key);
  }
  assert.doesNotMatch(html, /data-i18n-html=/, 'the workspace writes no dictionary HTML');
  assert.match(html, /<title data-i18n="cases\.meta\.title">Cases · PhishGuard<\/title>/);
  // Option labels are translated, so every option carries an explicit value.
  for (const [option] of html.matchAll(/<option\b[^>]*>/g)) assert.match(option, /\svalue="/, option);
  for (const label of ['From (UTC)', 'Through (UTC)']) assert.match(html, new RegExp(`data-i18n="[^"]+">${label.replace(/[()]/g, '\\$&')}<`));
});

test('every data-i18n-attr key in cases.html exists and its English equals the attribute', () => {
  const html = source('cases.html');
  const tags = [...html.matchAll(/<[a-z]+\b[^>]*data-i18n-attr="([^"]+)"[^>]*>/g)];
  assert.ok(tags.length >= 15, `${tags.length} tags`);
  for (const [tag, spec] of tags) {
    for (const pair of spec.split(';')) {
      const [attr, key] = pair.split(':');
      assert.ok(Object.hasOwn(en, key), `missing key ${key}`);
      const value = tag.match(new RegExp(`\\s${attr}="([^"]*)"`));
      assert.ok(value, `${attr} present on ${tag.slice(0, 60)}`);
      assert.equal(decode(value[1]), en[key], key);
    }
  }
  // Every accessible name and placeholder in the workspace is translatable.
  for (const [tag] of html.matchAll(/<[a-z]+\b[^>]*\s(?:aria-label|placeholder|title)="[^"]*"[^>]*>/g)) {
    if (/aria-hidden="true"/.test(tag)) continue;
    for (const [, attr] of tag.matchAll(/\s(aria-label|placeholder|title)="/g)) {
      assert.match(tag, new RegExp(`data-i18n-attr="[^"]*${attr}:`), `${attr} on ${tag.slice(0, 70)}`);
    }
  }
});

test('all visible workspace text is translatable except language-neutral names', () => {
  const html = source('cases.html').replace(/<!--[\s\S]*?-->|<!doctype[^>]*>/gi, '')
    .replace(/<(script|style|svg|title|noscript)\b[\s\S]*?<\/\1>/g, '');
  const stack = [];
  const leftovers = [];
  for (const [, close, tag, attrs, textNode] of html.matchAll(/<(\/?)([a-z0-9]+)\b([^>]*)>|([^<]+)/g)) {
    if (textNode !== undefined) {
      const text = normalize(textNode);
      if (text && !stack.some(entry => entry.covered)) leftovers.push(text);
    } else if (close) {
      while (stack.length && stack.pop().tag !== tag);
    } else if (!/^(meta|link|input|br|img|source|hr)$/.test(tag) && !attrs.endsWith('/')) {
      stack.push({tag, covered: /\sdata-i18n="/.test(attrs) || /aria-hidden="true"/.test(attrs) && tag !== 'button'});
    }
  }
  // The brand, section numbers, the "AI" section mark, count placeholders and
  // the dismiss glyph stay as they are.
  assert.deepEqual(leftovers.filter(text => !/^(PhishGuard|PHISHGUARD|0\d|AI|—|×)$/.test(text)), []);
});

// ── Script keys ──────────────────────────────────────────────────────────────
const exists = key => Object.hasOwn(en, key) || (Object.hasOwn(en, `${key}.one`) && Object.hasOwn(en, `${key}.other`));
const namespaces = new Set(Object.keys(en).map(key => key.split('.')[0]));

test('every dictionary-shaped string literal in the homepage scripts is a real key', () => {
  let checked = 0;
  for (const name of [...T_FILES, ...TR_FILES]) {
    for (const [, literal] of source(name).matchAll(/'([a-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'/g)) {
      if (!namespaces.has(literal.split('.')[0])) continue;
      assert.ok(exists(literal), `${name}: '${literal}' is not in the dictionary`);
      checked++;
    }
  }
  assert.ok(checked > 200, `${checked} literals checked`);
});

test('every key cases.js can ask for exists, including the families built from codes', () => {
  const text = source('cases.js');
  let checked = 0;
  for (const [, literal] of text.matchAll(/'([a-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'/g)) {
    if (!namespaces.has(literal.split('.')[0])) continue;
    assert.ok(exists(literal), `cases.js: '${literal}' is not in the dictionary`);
    checked++;
  }
  assert.ok(checked > 120, `${checked} literals checked`);
  // Computed keys, with every code the script can pass.
  const families = {
    'cases.status.${status}': ['pending', 'in_progress', 'closed'],
    'cases.risk.${level}': ['critical', 'high', 'medium', 'low', 'safe', 'unknown'],
    'cases.reportType.${type}': ['false_positive', 'false_negative', 'incorrect_risk', 'incorrect_evidence', 'other'],
    'cases.history.action.${event.action}': ['created', 'reviewed', 'reopened', 'auxiliary_saved'],
    'cases.capacity.warning.${key}.${level}': ['cases.near', 'cases.full', 'feedback.near', 'feedback.full'],
    'cases.jev.status.${jevConfig.status}': ['disabled', 'configuration_error', 'control_unavailable', 'quota_exhausted', 'available'],
    'cases.jev.signal.${key}': ['credential_request', 'payment_redirection', 'authority_pressure', 'phishing_intent', 'insufficient_evidence'],
    'cases.jev.reason.${result.reason}': ['no_cached_opinion', 'provider_authentication', 'provider_access_denied',
      'provider_request_invalid', 'provider_rate_limited', 'provider_overloaded', 'provider_timeout', 'provider_tls_error',
      'provider_network_error', 'provider_http_error', 'provider_invalid_response', 'local_capacity_exhausted',
      'call_budget_exhausted', 'daily_quota_exhausted', 'request_pending', 'empty_or_oversized_text', 'legacy_source_format'],
    // Looked up only after i18n.has() confirms them, or through known(), which
    // requires the server's English to match.
    'category.${code}.label': [], 'feature.${code}.label': [],
    'category.${category.key}.label': [], 'category.${category.key}.description': [],
  };
  const computed = [...new Set([...text.matchAll(/`((?:cases|category|feature)\.[^`]*\$\{[^`]+)`/g)].map(match => match[1]))];
  assert.deepEqual(computed.sort(), Object.keys(families).sort());
  for (const [pattern, codes] of Object.entries(families)) {
    for (const code of codes) {
      const key = pattern.replace(/\$\{[^}]+\}(\.\$\{[^}]+\})?/, code);
      assert.ok(exists(key), key);
    }
  }
  // The code lists in cases.js are exactly the families above.
  for (const name of ['JEV_REASONS', 'JEV_SIGNALS', 'JEV_STATUSES', 'REPORT_TYPES', 'STATUSES']) {
    const list = text.match(new RegExp(`const ${name} = \\[([^\\]]+)\\]`))[1].match(/'([^']+)'/g).map(item => item.slice(1, -1));
    const family = Object.entries(families).find(([pattern]) => pattern.startsWith({JEV_REASONS: 'cases.jev.reason', JEV_SIGNALS: 'cases.jev.signal',
      JEV_STATUSES: 'cases.jev.status', REPORT_TYPES: 'cases.reportType', STATUSES: 'cases.status'}[name]))[1];
    assert.deepEqual(list, family, name);
  }
});

test('keys built from codes cover every code the scripts can pass', () => {
  const families = {
    'sender.history.%.label': ['first', 'seen', 'notSeen', 'raw', 'unavailable', 'disabled'],
    'sender.history.%.detail': ['first', 'seen', 'notSeen', 'raw', 'unavailable', 'disabled'],
    'sender.verdict.%': ['critical', 'high', 'medium', 'low'],
    'verify.verdict.%': ['verified', 'no_mail_service', 'likely_invalid', 'unverifiable', 'suspicious', 'domain_valid',
      'invalid_format', 'temporarily_unavailable'],
    'content.ml.model.%': ['LogisticRegression', 'CalibratedLinearSVC', 'ComplementNB'],
    'content.ml.metric.%': ['recall', 'fnr', 'prauc', 'threshold'],
    'content.level.%': ['critical', 'high', 'medium', 'low', 'safe', 'unknown'],
    'level.%': ['critical', 'high', 'medium', 'low', 'info', 'safe', 'unknown'],
    'mailbox.%': ['known_disposable_provider', 'privacy_relay', 'suspicious_mailbox_pattern', 'suspicious_domain_pattern', 'no_known_match'],
    'theme.mode.%': ['auto', 'light', 'dark'],
    'sms.kind.%': ['short_code', 'cn_port_106', 'cn_mobile', 'nanp_toll_free', 'nanp_long_code', 'international',
      'other_number', 'email', 'alphanumeric', 'none'],
    'metric.%': ['Accuracy', 'Precision', 'Recall', 'F1', 'ROC_AUC'],
    'category.%.label': ['urgency', 'threats', 'financial', 'credential', 'impersonation', 'deception', 'attachments',
      'tech_scam', 'job_scam', 'social_engineering'],
  };
  for (const [pattern, codes] of Object.entries(families)) {
    for (const code of codes) assert.ok(exists(pattern.replace('%', code)), pattern.replace('%', code));
  }
  // The templates above are the only computed keys in the scripts.
  const computed = T_FILES.flatMap(name => [...source(name).matchAll(/\bt\(\s*`([^`]+)`/g)].map(match => match[1]));
  const allowed = ['sender.history.${state.key}.label', 'sender.history.${state.key}.detail', 'sender.verdict.${data.verdict}',
    'verify.verdict.${overall}', 'content.ml.model.${id}', 'content.level.${level}', 'mailbox.${status}',
    'content.ml.metric.${key}', 'metric.${key}', 'sender.verdict.${entry.level}',
    'sms.kind.${data.sender_kind}'];
  assert.deepEqual([...new Set(computed)].filter(key => !allowed.includes(key)), []);
});

test('shared components carry the dictionary English inline as their fallback', () => {
  let pairs = 0;
  for (const name of TR_FILES) {
    const text = source(name);
    const calls = (text.match(/\btr\(/g) || []).length;
    const matches = [...text.matchAll(/\btr\('([^']+)',\s*'((?:[^'\\]|\\.)*)'/g)];
    assert.equal(matches.length, calls, `${name}: every tr() call has a literal key and English text`);
    for (const [, key, english] of matches) {
      assert.equal(english.replace(/\\'/g, "'"), en[key], `${name} ${key}`);
      pairs++;
    }
  }
  assert.ok(pairs >= 40, `${pairs} inline strings`);
});

test('localized server wording matches what the backend sends', () => {
  const app = readFileSync(new URL('../app.py', import.meta.url), 'utf8');
  const featureBlock = app.slice(app.indexOf('FEATURE_INFO = ['), app.indexOf(']\n', app.indexOf('FEATURE_INFO = [')));
  const features = [...featureBlock.matchAll(/\{"name": "([a-z_]+)",\s*"label": "([^"]*)",[\s\S]*?"email_desc":\s*"([^"]*)",\s*"email_desc_pos": "([^"]*)"\}/g)];
  assert.equal(features.length, 30);
  for (const [, name, label, flag, ok] of features) {
    assert.equal(en[`feature.${name}.label`], label, name);
    assert.equal(en[`feature.${name}.flag`], flag, name);
    assert.equal(en[`feature.${name}.ok`], ok, name);
  }
  const rules = app.slice(app.indexOf('CONTENT_RULES: dict = {'));
  for (const key of ['urgency', 'threats', 'financial', 'credential', 'impersonation', 'deception', 'attachments',
    'tech_scam', 'job_scam', 'social_engineering']) {
    const block = rules.slice(rules.indexOf(`    "${key}": {`));
    assert.equal(en[`category.${key}.label`], block.match(/"label":\s*"([^"]*)"/)[1], key);
    assert.equal(en[`category.${key}.description`], block.match(/"description":\s*"([^"]*)"/)[1], key);
  }
  for (const [verdict, label] of Object.entries({critical: 'Critical Sender Risk', high: 'High Sender Risk',
    medium: 'Suspicious Sender', low: 'Low Sender Risk'})) {
    assert.match(app, new RegExp(`return "${verdict}", "${label}"`));
    assert.equal(en[`sender.verdict.${verdict}`], label);
  }
  const serverLabels = new Set([...readFileSync(new URL('../visual_evidence.py', import.meta.url), 'utf8').matchAll(/risk_label'\] = '([^']+)'/g),
    ...app.matchAll(/risk_label'\] = '([^']+)'/g), ...app.matchAll(/"(?:critical|high|medium|low|safe)",\s*"([^"]+ — [^"]+|No Phishing Indicators Found)"/g),
    ...app.matchAll(/"(High Risk — Model Signal Needs Review)"/g)].map(match => match[1]));
  const known = new Set(Object.keys(en).filter(key => key.startsWith('content.riskLabel.')).map(key => en[key]));
  assert.deepEqual([...serverLabels].sort(), [...known].sort());
  const inference = readFileSync(new URL('../content_inference.py', import.meta.url), 'utf8');
  assert.match(inference, new RegExp(`"ml_label": "${en['content.mlLabel.phishing']}" if prediction == 1 else "${en['content.mlLabel.legit']}"`));
});

// ── English is unchanged ─────────────────────────────────────────────────────
const snapshot = JSON.parse(readFileSync(new URL('../tests/fixtures/i18n/en-snapshot.json', import.meta.url), 'utf8'));

test('English rendering is byte-for-byte the pre-translation output (sender, content, verification, reports…)', async () => {
  const results = JSON.parse(JSON.stringify(await runScenarios(EN_PAGE)));
  assert.deepEqual(Object.keys(results), Object.keys(snapshot.app));
  for (const name of Object.keys(snapshot.app)) assert.deepEqual(results[name], snapshot.app[name], name);
});

test('English image evidence matches the pre-translation output, with and without i18n.js', () => {
  assert.deepEqual(runVisionScenario(['i18n.js', 'vision.js']), snapshot.vision);
  // Without i18n.js (failed to load) the inline English must match too.
  assert.deepEqual(runVisionScenario(['vision.js']), snapshot.vision);
});

// ── Language choice ──────────────────────────────────────────────────────────
function runLangInit({languages, stored, throwing = false}) {
  const attributes = {};
  const documentElement = {lang: '', setAttribute: (name, value) => { attributes[name] = value; }};
  const localStorage = throwing ? {getItem() { throw new Error('SecurityError'); }}
    : {getItem: key => (key === 'phishguard-lang' ? stored ?? null : null)};
  vm.runInNewContext(source('lang-init.js'), {document: {documentElement}, localStorage,
    navigator: {languages, language: languages[0]}});
  return {lang: documentElement.lang, pending: 'data-i18n-pending' in attributes};
}

test('language detection: stored choice wins, else the first browser language; lang-init.js agrees', () => {
  const cases = [
    [{languages: ['zh-CN', 'en-US']}, 'zh'], [{languages: ['zh']}, 'zh'], [{languages: ['zh-TW']}, 'zh'],
    [{languages: ['ZH-cn']}, 'zh'], [{languages: ['en-US', 'zh-CN']}, 'en'], [{languages: ['fr-FR']}, 'en'],
    [{languages: ['zhx']}, 'en'], [{languages: []}, 'en'],
    [{languages: ['zh-CN'], stored: 'en'}, 'en'], [{languages: ['en-US'], stored: 'zh'}, 'zh'],
    [{languages: ['zh-CN'], stored: 'fr'}, 'zh'], [{languages: ['zh-CN'], throwing: true}, 'zh'],
    [{languages: ['en-GB'], throwing: true}, 'en'],
  ];
  for (const [input, expected] of cases) {
    const storage = input.throwing ? {getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('x'); }}
      : memoryStorage(input.stored ? {'phishguard-lang': input.stored} : {});
    const {i18n} = loadI18n({languages: input.languages, storage});
    assert.equal(i18n.lang(), expected, JSON.stringify(input));
    const init = runLangInit(input);
    assert.equal(init.lang, expected === 'zh' ? 'zh-CN' : 'en', JSON.stringify(input));
    assert.equal(init.pending, expected === 'zh', 'only a translated page waits for i18n.js');
  }
});

function fakeDocument() {
  const listeners = {};
  const nodes = {text: [], html: [], attr: [], options: []};
  const attrs = new Map();
  const documentElement = {lang: 'en', dataset: {}, setAttribute: (name, value) => attrs.set(name, value),
    getAttribute: name => attrs.get(name) ?? null, removeAttribute: name => attrs.delete(name)};
  const node = (attributes = {}) => Object.assign(new FakeElement(), {
    getAttribute: name => attributes[name] ?? null,
    setAttribute(name, value) { attributes[name] = String(value); }, attributesMap: attributes,
  });
  const toggle = node();
  const document = {
    documentElement, title: 'PhishGuard – Phishing Email Detector',
    addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
    dispatchEvent(event) { (listeners[event.type] || []).forEach(fn => fn(event)); return true; },
    getElementById: id => (id === 'lang-toggle' ? toggle : null),
    querySelectorAll: selector => ({'[data-i18n]': nodes.text, '[data-i18n-html]': nodes.html,
      '[data-i18n-attr]': nodes.attr, '[data-lang-option]': nodes.options})[selector] || [],
  };
  nodes.text.push(Object.assign(node({'data-i18n': 'nav.demo'}), {textContent: 'Live Demo'}));
  nodes.html.push(node({'data-i18n-html': 'sender.hint.slash'}));
  nodes.attr.push(node({'data-i18n-attr': 'placeholder:sender.input.placeholder; aria-label:sender.input.aria'}));
  nodes.options.push(node({'data-lang-option': 'en'}), node({'data-lang-option': 'zh'}));
  attrs.set('data-i18n-pending', '');
  return {document, nodes, toggle, attrs, listeners};
}

test('a Chinese page is translated on load, before any script renders', () => {
  const page = fakeDocument();
  loadI18n({languages: ['zh-CN'], document: page.document});
  assert.equal(page.document.documentElement.lang, 'zh-CN');
  assert.equal(page.document.title, zh['meta.title']);
  assert.equal(page.nodes.text[0].textContent, '在线演示');
  assert.equal(page.nodes.html[0].innerHTML, zh['sender.hint.slash']);
  assert.equal(page.nodes.attr[0].attributesMap.placeholder, zh['sender.input.placeholder']);
  assert.equal(page.nodes.attr[0].attributesMap['aria-label'], zh['sender.input.aria']);
  assert.deepEqual(page.nodes.options.map(option => option.classList.contains('is-active')), [false, true]);
  assert.equal(page.attrs.has('data-i18n-pending'), false, 'the page is revealed');

  // English leaves the markup alone (it already is the English text).
  const english = fakeDocument();
  loadI18n({languages: ['en-US'], document: english.document});
  assert.equal(english.nodes.text[0].textContent, 'Live Demo');
  assert.equal(english.nodes.html[0].innerHTML, '');
  assert.equal(english.document.documentElement.lang, 'en');
  assert.equal(english.attrs.has('data-i18n-pending'), false);
});

// ── Chinese strings load separately (i18n-zh.js) ────────────────────────────
// A page in the fake DOM with a <head>, script elements whose load/error the
// test fires, and document.readyState, so lang-init.js, i18n.js and
// i18n-zh.js can run in one context in any order, as in a browser.
const ZH_URL = source('i18n.js').match(/const SOURCES = \{zh: '([^']+)'\}/)[1];

function browserPage({languages = ['en-US'], stored, readyState = 'loading'} = {}) {
  const page = fakeDocument();
  page.attrs.delete('data-i18n-pending');
  const {document} = page;
  const head = {children: [], appendChild(child) { this.children.push(child); return child; }};
  const created = [];
  document.head = head;
  document.readyState = readyState;
  document.createElement = tag => {
    const attributes = {}, listeners = {};
    const element = {tagName: tag.toUpperCase(), attributes,
      setAttribute(name, value) { attributes[name] = String(value); },
      getAttribute: name => (Object.hasOwn(attributes, name) ? attributes[name] : null),
      addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
      fire(type) { (listeners[type] || []).forEach(fn => fn({type})); },
      remove() { element.removed = true; head.children = head.children.filter(child => child !== element); }};
    created.push(element);
    return element;
  };
  document.querySelector = selector => {
    const match = selector.match(/^script\[data-i18n-dictionary="(\w+)"\]$/);
    return match ? head.children.find(child => child.getAttribute('data-i18n-dictionary') === match[1]) ?? null : null;
  };
  page.toggle.removeAttribute = name => { delete page.toggle.attributesMap[name]; };
  const storage = memoryStorage(stored ? {'phishguard-lang': stored} : {});
  const errors = [], events = [];
  const window = {};
  const context = vm.createContext({window, document, navigator: {languages, language: languages[0]}, localStorage: storage,
    console: {...console, error: (...args) => errors.push(args.join(' '))}, CustomEvent});
  const run = name => vm.runInContext(source(name), context, {filename: name});
  document.addEventListener('phishguard:languagechange', event => events.push(['change', event.detail.lang]));
  document.addEventListener('phishguard:languageerror', event => events.push(['error', event.detail.lang]));
  const contentLoaded = () => { document.readyState = 'interactive'; (page.listeners.DOMContentLoaded || []).forEach(fn => fn()); };
  // The dictionary file runs, then its load event fires, as in a browser.
  const deliver = script => { run('i18n-zh.js'); script.fire('load'); };
  return {...page, head, created, run, storage, errors, events, window, contentLoaded, deliver,
    i18n: () => window.PhishGuardI18n, pending: () => page.attrs.has('data-i18n-pending'),
    text: () => page.nodes.text[0].textContent, busy: () => page.toggle.attributesMap['aria-busy'] ?? null};
}

test('an English visitor never requests i18n-zh.js', () => {
  for (const html of ['index.html', 'cases.html']) assert.doesNotMatch(source(html), /i18n-zh/, `${html} has no static reference`);
  for (const options of [{languages: ['en-US']}, {languages: ['zh-CN'], stored: 'en'}, {languages: ['fr-FR']}]) {
    const page = browserPage(options);
    page.run('lang-init.js');
    page.run('i18n.js');
    page.contentLoaded();
    assert.equal(page.created.length, 0, JSON.stringify(options));
    assert.equal(page.i18n().lang(), 'en');
    assert.equal(page.pending(), false);
    assert.equal(page.i18n().DICTIONARY.zh, undefined);
  }
});

test('a Chinese visitor: lang-init.js requests i18n-zh.js in <head>, and the page stays hidden until it is applied', () => {
  for (const arrives of ['before DOMContentLoaded', 'after DOMContentLoaded']) {
    const page = browserPage({languages: ['zh-CN']});
    page.run('lang-init.js');
    assert.equal(page.document.documentElement.lang, 'zh-CN');
    assert.equal(page.pending(), true);
    assert.equal(page.created.length, 1);
    const [script] = page.head.children;
    assert.equal(script.src, ZH_URL);
    assert.equal(script.getAttribute('data-i18n-dictionary'), 'zh');
    assert.equal(script.fetchPriority, 'high');

    // i18n.js runs first (the dictionary is still downloading): no English
    // flash, since the page stays hidden, and no second request.
    page.run('i18n.js');
    assert.equal(page.pending(), true, arrives);
    assert.equal(page.text(), 'Live Demo');
    assert.equal(page.i18n().lang(), 'en', 'English strings until Chinese arrives');
    assert.equal(page.created.length, 1, 'the request lang-init.js started is reused');
    if (arrives === 'after DOMContentLoaded') {
      page.contentLoaded();
      assert.equal(page.pending(), true, 'DOMContentLoaded waits for the Chinese file');
    }

    page.deliver(script);
    assert.equal(page.i18n().lang(), 'zh');
    assert.equal(page.text(), '在线演示');
    assert.equal(page.document.documentElement.lang, 'zh-CN');
    assert.equal(page.document.title, zh['meta.title']);
    assert.equal(page.pending(), false, 'revealed once translated');
    // Before DOMContentLoaded no script has rendered yet; after it, they re-render.
    assert.deepEqual(page.events, arrives === 'after DOMContentLoaded' ? [['change', 'zh']] : []);
    if (arrives === 'before DOMContentLoaded') page.contentLoaded();
    assert.equal(page.pending(), false);
    assert.equal(page.storage.getItem('phishguard-lang'), null, 'loading does not store a choice');
    assert.deepEqual(page.errors, []);
  }
});

test('a Chinese dictionary that arrives before i18n.js is applied as i18n.js starts', () => {
  const page = browserPage({languages: ['en-US'], stored: 'zh'});
  page.run('lang-init.js');
  page.deliver(page.head.children[0]);
  assert.equal(page.pending(), true);
  page.run('i18n.js');
  assert.equal(page.i18n().lang(), 'zh');
  assert.equal(page.text(), '在线演示');
  assert.equal(page.pending(), false);
  assert.equal(page.created.length, 1);
  assert.equal(page.window.PhishGuardI18nDictionaries, undefined, 'the hand-over global is cleared');
});

test('if i18n-zh.js fails on load, the page is revealed in English and the failure is logged', () => {
  // Fails while i18n.js waits for it.
  const waiting = browserPage({languages: ['zh-CN']});
  waiting.run('lang-init.js');
  waiting.run('i18n.js');
  waiting.head.children[0].fire('error');
  assert.equal(waiting.pending(), false);
  assert.equal(waiting.document.documentElement.lang, 'en');
  assert.equal(waiting.i18n().lang(), 'en');
  assert.equal(waiting.text(), 'Live Demo');
  assert.equal(waiting.errors.length, 1);
  assert.match(waiting.errors[0], /zh strings could not be loaded/);
  assert.deepEqual(waiting.events, [['error', 'zh']]);

  // Failed before i18n.js ran: i18n.js sees lang-init.js's finished request.
  const early = browserPage({languages: ['zh-CN']});
  early.run('lang-init.js');
  const [script] = early.head.children;
  script.fire('error');
  assert.equal(script.getAttribute('data-state'), 'error');
  early.run('i18n.js');
  assert.equal(early.pending(), false);
  assert.equal(early.i18n().lang(), 'en');
  assert.equal(script.removed, true, 'a later switch requests the file again');
  assert.equal(early.created.length, 1);

  // i18n.js never ran: DOMContentLoaded still reveals the page once the file settles.
  const alone = browserPage({languages: ['zh-CN']});
  alone.run('lang-init.js');
  alone.contentLoaded();
  assert.equal(alone.pending(), true);
  alone.head.children[0].fire('error');
  assert.equal(alone.pending(), false);
  const settled = browserPage({languages: ['zh-CN']});
  settled.run('lang-init.js');
  settled.head.children[0].fire('load');
  settled.contentLoaded();
  assert.equal(settled.pending(), false, 'already settled: revealed at DOMContentLoaded');
});

test('switching to 中文 loads i18n-zh.js once, keeping English and a busy toggle until it arrives', () => {
  const page = browserPage();
  page.run('lang-init.js');
  page.run('i18n.js');
  page.contentLoaded();
  page.toggle.listeners.click();
  assert.equal(page.created.length, 1);
  const [script] = page.head.children;
  assert.equal(script.src, ZH_URL);
  assert.equal(page.busy(), 'true');
  assert.equal(page.i18n().lang(), 'en');
  assert.equal(page.text(), 'Live Demo');
  assert.equal(page.document.documentElement.lang, 'en');
  page.toggle.listeners.click();
  assert.equal(page.created.length, 1, 'clicks while loading are ignored');
  assert.deepEqual(page.events, []);

  page.deliver(script);
  assert.equal(page.i18n().lang(), 'zh');
  assert.equal(page.text(), '在线演示');
  assert.equal(page.document.documentElement.lang, 'zh-CN');
  assert.equal(page.busy(), null);
  assert.equal(page.storage.getItem('phishguard-lang'), 'zh');
  assert.deepEqual(page.events, [['change', 'zh']]);
  page.toggle.listeners.click();
  page.toggle.listeners.click();
  assert.equal(page.i18n().lang(), 'zh');
  assert.equal(page.created.length, 1, 'loaded once');
  assert.deepEqual(page.events, [['change', 'zh'], ['change', 'en'], ['change', 'zh']]);
  assert.deepEqual(page.errors, []);
});

test('a failed switch stays in English, announces the failure and can be retried', () => {
  const page = browserPage();
  page.run('lang-init.js');
  page.run('i18n.js');
  page.toggle.listeners.click();
  page.head.children[0].fire('error');
  assert.equal(page.i18n().lang(), 'en');
  assert.equal(page.text(), 'Live Demo');
  assert.equal(page.busy(), null);
  assert.equal(page.storage.getItem('phishguard-lang'), null);
  assert.deepEqual(page.events, [['error', 'zh']]);
  assert.equal(page.errors.length, 1);
  assert.equal(page.head.children.length, 0, 'the failed request is removed');
  page.toggle.listeners.click();
  assert.equal(page.created.length, 2);
  page.deliver(page.head.children[0]);
  assert.equal(page.i18n().lang(), 'zh');
  // A file that loads without registering (e.g. a stale copy) counts as a failure.
  const stale = browserPage();
  stale.run('i18n.js');
  stale.toggle.listeners.click();
  stale.head.children[0].fire('load');
  assert.equal(stale.i18n().lang(), 'en');
  assert.deepEqual(stale.events, [['error', 'zh']]);
});

test('a later choice wins over a Chinese file that is still loading', () => {
  const page = browserPage();
  page.run('i18n.js');
  page.i18n().setLang('zh');
  assert.equal(page.i18n().setLang('en'), 'en');
  page.deliver(page.head.children[0]);
  assert.equal(page.i18n().lang(), 'en');
  assert.equal(page.text(), 'Live Demo');
  assert.equal(page.busy(), null);
  assert.deepEqual(page.events, []);
  assert.ok(page.i18n().DICTIONARY.zh, 'kept for the next switch');
});

test('the i18n-zh.js URL is the same in lang-init.js and i18n.js and matches the asset manifest', () => {
  const urls = ['lang-init.js', 'i18n.js'].map(name => [...source(name).matchAll(/'(\/static\/i18n-zh\.js\?v=[^']+)'/g)].map(match => match[1]));
  assert.deepEqual(urls.map(list => list.length), [1, 1]);
  assert.equal(urls[0][0], urls[1][0]);
  assert.equal(urls[0][0], ZH_URL);
  const manifest = JSON.parse(readFileSync(new URL('../tools/asset-versions/manifest.json', import.meta.url), 'utf8'));
  assert.equal(ZH_URL, `/static/i18n-zh.js?v=${manifest['i18n-zh.js'].version}`);
});

test('the meta description follows the language on both pages', () => {
  for (const [html, key] of [['index.html', 'meta.description'], ['cases.html', 'cases.meta.description']]) {
    const markup = source(html).match(new RegExp(`<meta name="description" content="([^"]+)" data-i18n-attr="content:${key.replace(/\./g, '\\.')}"`));
    assert.ok(markup, html);
    assert.equal(decode(markup[1]), en[key]);
    const page = fakeDocument();
    const meta = Object.assign(new FakeElement('meta'), {attributesMap: {'data-i18n-attr': `content:${key}`, content: en[key]}});
    meta.getAttribute = name => meta.attributesMap[name] ?? null;
    meta.setAttribute = (name, value) => { meta.attributesMap[name] = String(value); };
    page.nodes.attr.push(meta);
    const {i18n} = loadI18n({document: page.document});
    i18n.setLang('zh');
    assert.equal(meta.attributesMap.content, zh[key]);
    i18n.setLang('en');
    assert.equal(meta.attributesMap.content, en[key]);
  }
});

test('the toggle switches language, persists the choice and announces the change', () => {
  const page = fakeDocument();
  const storage = memoryStorage();
  const {i18n} = loadI18n({languages: ['en-US'], storage, document: page.document});
  const events = [];
  page.document.addEventListener('phishguard:languagechange', event => events.push(event.detail.lang));
  page.toggle.listeners.click();
  assert.equal(i18n.lang(), 'zh');
  assert.equal(storage.getItem('phishguard-lang'), 'zh');
  assert.equal(page.document.documentElement.lang, 'zh-CN');
  assert.equal(page.document.title, zh['meta.title']);
  assert.equal(page.nodes.text[0].textContent, '在线演示');
  page.toggle.listeners.click();
  assert.equal(i18n.lang(), 'en');
  assert.equal(page.nodes.text[0].textContent, 'Live Demo');
  assert.equal(page.document.title, 'PhishGuard – Phishing Email Detector');
  assert.deepEqual(events, ['zh', 'en']);
  assert.equal(i18n.setLang('fr'), 'en', 'unknown languages are ignored');
  assert.equal(i18n.setLang('__proto__'), 'en');
  assert.deepEqual(events, ['zh', 'en']);
});

test('blocked storage still switches language for the page', () => {
  const page = fakeDocument();
  const storage = {getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceeded'); }};
  const {i18n} = loadI18n({languages: ['en-US'], storage, document: page.document});
  assert.doesNotThrow(() => i18n.setLang('zh'));
  assert.equal(i18n.lang(), 'zh');
  assert.equal(page.document.documentElement.lang, 'zh-CN');
});

test('interpolation, plural keys, English fallback and missing keys', () => {
  const warnings = [];
  const {i18n} = loadI18n({languages: ['zh-CN'], console: {warn: message => warnings.push(message)}});
  assert.equal(i18n.t('request.error.retryIn', {seconds: 37}), '请求过于频繁。请在 37 秒后重试。');
  assert.equal(i18n.t('request.error.retryIn'), '请求过于频繁。请在 {seconds} 秒后重试。', 'no params: template as is');
  assert.equal(i18n.t('verify.detail.mxPref', {host: '$&{pref}', pref: 10}), '$&{pref}（优先级 10）', 'values are not re-interpolated');
  assert.equal(i18n.plural('content.sub.categories', 1), '检测到 1 个可疑类别。');
  // A zh gap falls back to English rather than showing a key.
  delete i18n.DICTIONARY.zh['nav.demo'];
  assert.equal(i18n.t('nav.demo'), 'Live Demo');
  // An unknown key returns the key and warns once.
  assert.equal(i18n.t('no.such.key'), 'no.such.key');
  assert.equal(i18n.t('no.such.key'), 'no.such.key');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /no\.such\.key/);

  const english = loadI18n().i18n;
  assert.equal(english.plural('content.sub.categories', 1), '1 suspicious category detected.');
  assert.equal(english.plural('content.sub.categories', 2), '2 suspicious categories detected.');
  assert.equal(english.plural('content.sub.categories', 0), '0 suspicious categories detected.');
  assert.equal(english.known('category.urgency.label', 'Urgency & Pressure'), 'Urgency & Pressure');
});

test('server text is localized only while it matches the known English', () => {
  const {i18n} = loadI18n({languages: ['zh-CN']});
  assert.equal(i18n.known('category.urgency.label', 'Urgency & Pressure'), '紧迫感与施压');
  assert.equal(i18n.known('category.urgency.label', 'Urgency (reworded)'), 'Urgency (reworded)');
  assert.equal(i18n.known('category.__proto__.label', 'x'), 'x');
  assert.equal(i18n.known('level.high', 'high'), '高');
  assert.equal(i18n.known('level.<b>', '<b>'), '<b>');
  assert.equal(i18n.known('level.high', null), null);
});

// ── Chinese rendering ────────────────────────────────────────────────────────
const senderData = {
  email: 'security-alert@paypa1-verify.xyz', verdict: 'critical', label: 'Critical Sender Risk', risk_score: 100,
  risk_indicators: [{level: 'high', msg: 'Domain imitates paypal.com'}, {level: 'info', msg: 'note'}],
  high_risk_count: 1, med_risk_count: 0, disposable_status: 'suspicious_domain_pattern', address_alias_type: 'subaddress',
  feature_breakdown: [
    {name: 'links_in_tags', label: 'Brand Domain Spoofing', email_desc: 'Domain appears to impersonate a well-known brand (e.g. paypal, apple)', value: -1},
    {name: 'having_ip_address', label: 'IP Address Domain', email_desc: 'Domain uses a proper hostname, not a raw IP address', value: 1},
    {name: 'links_in_tags', label: 'Brand Domain Spoofing', email_desc: 'A reworded server description', value: -1},
  ],
  account_observability: 'provider_account_unverifiable', sender_history_status: 'first_seen',
};
const contentData = {
  risk_level: 'high', risk_label: 'High Risk — Likely Phishing', total_score: 9, combined_phishing_score: 72.4,
  analysis_complete: true, input_mode: 'subject-body',
  category_results: [{key: 'urgency', label: 'Urgency & Pressure', level: 'high', count: 2,
    description: 'Phishing emails create artificial time pressure to prevent careful thinking.', matched: ['urgent']}],
  extra_indicators: [{level: 'medium', msg: 'Shortened URL'}], safety_signals: [],
  ml_status: 'available', ml_label: 'Likely Phishing', ml_phishing_probability: 72.4, ml_legitimate_probability: 27.6,
  ml_prediction: 1, ml_top_contributors: [], ml_metrics: {model: 'LogisticRegression'},
  analysis_warnings: ['Attachment content was not inspected; only metadata was checked.'],
};
const fetchCounter = () => {
  const calls = [];
  return {calls, fetch: async url => {
    calls.push(url);
    return {ok: true, json: async () => (url === '/api/analyze-email' ? senderData
      : url === '/api/verify-email' ? {email: senderData.email, format_valid: true, mx_found: true, mx_records: [[10, 'mx.example']],
        smtp_result: 'exists', smtp_message: '250 OK', overall: 'verified', verification_complete: true,
        spf: {found: true, policy: 'strict'}, dmarc: {found: false}, mx_ptr: {found: true, ptr: 'mx.example'}, domain_age: {found: false}}
        : contentData)};
  }};
};

function eventDocument() {
  const listeners = {};
  return {
    addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
    dispatchEvent(event) { (listeners[event.type] || []).forEach(fn => fn(event)); return true; },
  };
}

test('switching language re-renders the visible results from the last responses, without new requests', async () => {
  const network = fetchCounter();
  const storage = memoryStorage();
  const page = loadPage(PAGE, {document: eventDocument(), CustomEvent, localStorage: storage, fetch: network.fetch});
  const {context, elements} = page;
  context.applyPublicConfig({email_verification_enabled: true, smtp_verification_enabled: false});
  context.document.getElementById('email-input').value = senderData.email;
  await context.runEmailAnalysis();
  await context.runVerification();
  context.document.getElementById('content-subject').value = 'Hi';
  await context.runContentAnalysis();
  assert.deepEqual(network.calls, ['/api/analyze-email', '/api/verify-email', '/api/analyze-content']);
  const storedBefore = storage.getItem('phishguard-recent-checks');
  const scoreBefore = elements.get('vb-prob').textContent;
  assert.equal(elements.get('vb-title').textContent, 'Critical Sender Risk');

  context.window.PhishGuardI18n.setLang('zh');
  assert.equal(network.calls.length, 3, 'no request is repeated');
  assert.equal(storage.getItem('phishguard-recent-checks'), storedBefore, 'stored entries are language-neutral');
  assert.equal(storage.getItem('phishguard-lang'), 'zh');
  // Sender result
  assert.equal(elements.get('vb-title').textContent, '发件人风险：严重');
  assert.equal(elements.get('vb-email').textContent, senderData.email);
  assert.equal(elements.get('vb-prob').textContent, scoreBefore, 'scores are not re-animated');
  assert.equal(elements.get('vb-scope').textContent, zh['sender.scope']);
  assert.equal(elements.get('disp-check-label').textContent, zh['sender.disp.domain.label']);
  assert.equal(elements.get('disp-check-detail').textContent,
    '域名“paypa1-verify.xyz”看起来像临时邮箱服务的名称，但不在已确认的服务商登记表中。' + zh['sender.disp.alias']);
  assert.equal(elements.get('sender-history-label').textContent, zh['sender.history.first.label']);
  assert.match(elements.get('sender-history-detail').textContent, /^无法通过该地址或本服务保留的历史记录核实 邮箱服务商 账户的注册时长。/);
  assert.match(elements.get('risk-summary').innerHTML, /疑似钓鱼[\s\S]*1 项高风险[\s\S]*0 项中风险/);
  const features = elements.get('feature-breakdown-list').innerHTML;
  assert.match(features, /品牌域名仿冒[\s\S]*域名疑似冒充知名品牌/);
  assert.match(features, /IP 地址作为域名[\s\S]*域名使用正规主机名/);
  assert.match(features, /A reworded server description/, 'unknown server wording is shown as sent');
  assert.match(features, /title="已标记的特征；并非最终结论"/);
  assert.match(elements.get('risk-indicators-list').innerHTML, /Domain imitates paypal\.com/, 'indicator messages stay as sent');
  // Verification card keeps its result, now in Chinese
  assert.equal(elements.get('verify-result').classList.contains('hidden'), false);
  assert.match(elements.get('verify-verdict').innerHTML, /SMTP 已接受 — 邮件服务器接受了该地址/);
  assert.equal(elements.get('vstep-format-detail').textContent, '地址符合 RFC 5321 格式。');
  assert.equal(elements.get('vstep-smtp-detail').textContent, '250 OK', 'SMTP server replies stay as sent');
  assert.equal(elements.get('vstep-mx-detail').textContent, 'MX 记录：mx.example（优先级 10）');
  assert.equal(elements.get('verification-local-notice').textContent, zh['config.notice.smtpOff']);
  // Content result
  assert.equal(elements.get('crb-title').textContent, '高风险 — 可能是钓鱼邮件');
  assert.equal(elements.get('crb-sub').textContent, '机器学习风险评分：72.4% — 可能是钓鱼邮件 • 检测到 1 个可疑类别。 • 检测到 1 项技术风险指标。');
  assert.equal(elements.get('content-ml-title').textContent, 'TF-IDF + 逻辑回归');
  assert.equal(elements.get('content-ml-sub').textContent, '可能是钓鱼邮件 — 模型风险评分 72.4%');
  const grid = elements.get('content-category-grid').innerHTML;
  assert.match(grid, /紧迫感与施压[\s\S]*匹配 2 个信号[\s\S]*level-high">高<[\s\S]*钓鱼邮件会制造人为的时间压力/);
  assert.match(grid, /kw-pill">urgent</, 'matched keywords stay as sent');
  // Buttons, recent checks
  assert.equal(elements.get('analyze-btn-text').textContent, '分析');
  assert.equal(elements.get('content-btn-text').textContent, '分析内容');
  const recent = elements.get('recent-checks-list').innerHTML;
  assert.match(recent, /recent-mode">内容<[\s\S]*高风险 — 可能是钓鱼邮件[\s\S]*刚刚/);
  assert.match(recent, /recent-mode">发件人<[\s\S]*发件人风险：严重[\s\S]*paypa1-verify\.xyz/);

  context.window.PhishGuardI18n.setLang('en');
  assert.equal(network.calls.length, 3);
  assert.equal(elements.get('vb-title').textContent, 'Critical Sender Risk');
  assert.equal(elements.get('crb-title').textContent, 'High Risk — Likely Phishing');
  assert.match(elements.get('verify-verdict').innerHTML, /SMTP Accepted/);
  assert.match(elements.get('recent-checks-list').innerHTML, /Critical Sender Risk/);
});

test('an in-flight analysis keeps its busy label across a language switch', async () => {
  let release;
  const page = loadPage(PAGE, {document: eventDocument(), CustomEvent, localStorage: memoryStorage(),
    fetch: () => new Promise(resolve => { release = resolve; })});
  page.context.document.getElementById('email-input').value = 'a@example.com';
  const pending = page.context.runEmailAnalysis();
  page.context.window.PhishGuardI18n.setLang('zh');
  assert.equal(page.elements.get('analyze-btn-text').textContent, '正在分析…');
  release({ok: true, json: async () => senderData});
  await pending;
  assert.equal(page.elements.get('analyze-btn-text').textContent, '分析');
  assert.equal(page.elements.get('vb-title').textContent, '发件人风险：严重');
});

test('recent checks render Chinese labels from stored codes; storage stays in English', () => {
  const storage = memoryStorage({'phishguard-lang': 'zh'});
  const page = loadPage(PAGE, {localStorage: storage});
  const now = Date.now();
  for (const entry of [
    {mode: 'sender', label: 'High Sender Risk', level: 'high', score: 66, domain: 'x.test'},
    {mode: 'image', label: 'Image Analysis Incomplete — Risk Undetermined', level: 'unknown', score: null},
    {mode: 'eml', label: 'Some future server label', level: 'medium', score: 40},
    {mode: 'content', label: '<img src=x onerror=alert(1)>', level: 'weird', score: 1},
    {mode: 'content', label: '', level: 'safe', score: 0},
  ]) page.context.recordRecentCheck({...entry, at: now - 5 * 60_000});
  const stored = JSON.parse(storage.getItem('phishguard-recent-checks'));
  assert.deepEqual(stored.map(entry => entry.label), ['', '<img src=x onerror=alert(1)>', 'Some future server label',
    'Image Analysis Incomplete — Risk Undetermined', 'High Sender Risk']);
  const list = page.elements.get('recent-checks-list').innerHTML;
  assert.match(list, /发件人<[\s\S]*发件人风险：高/);
  assert.match(list, /图片<[\s\S]*图片分析未完成 — 风险未确定/);
  assert.match(list, /邮件文件<[\s\S]*中等风险/, 'an unknown label is rendered from its level');
  assert.match(list, /风险未确定/, 'a tampered level is shown as undetermined');
  assert.doesNotMatch(list, /<img/);
  assert.match(list, /recent-label">结果</);
  assert.match(list, /5 分钟前/);
  assert.equal(page.context.formatRecentTime(now - 10_000, now), '刚刚');
  assert.equal(page.context.formatRecentTime(now - 3 * 3_600_000, now), '3 小时前');
  assert.match(page.context.formatRecentTime(Date.UTC(2026, 8, 25, 12), Date.UTC(2026, 8, 28, 12)), /2026年9月2[45]日/);
  page.context.clearRecentChecks();
  assert.equal(page.elements.get('copy-status').textContent, '已清除最近检查');
  assert.equal(page.elements.get('recent-checks-empty').textContent, zh['recent.empty']);
});

test('copy summaries and Markdown follow the language; JSON keeps raw API data and records the language', async () => {
  const blobs = [];
  const page = loadPage(PAGE, {localStorage: memoryStorage({'phishguard-lang': 'zh'}), Blob,
    URL: {createObjectURL: blob => { blobs.push(blob); return 'blob:x'; }, revokeObjectURL() {}}});
  const {context} = page;
  context.document.body = {appendChild() {}};
  assert.equal(context.senderSummaryText(senderData), [
    'PhishGuard 发件人检查：security-alert@paypa1-verify.xyz',
    '结论：发件人风险：严重（100/100）',
    '邮箱类型：类似一次性邮箱的域名（未确认）',
    '指标：',
    '- [高] Domain imitates paypal.com',
    '',
    zh['summary.disclaimer'],
  ].join('\n'));
  assert.equal(context.contentSummaryText(contentData), [
    'PhishGuard 内容检查',
    '结论：高风险 — 可能是钓鱼邮件（风险 72%）',
    '类别：',
    '- 紧迫感与施压（高，2 个信号）',
    '技术指标：',
    '- [中] Shortened URL',
    '',
    zh['summary.disclaimer'],
  ].join('\n'));
  const markdown = context.contentReportMarkdown({...contentData, input_mode: 'raw-email'}, new Date(Date.UTC(2026, 8, 28, 20, 5, 9)));
  assert.match(markdown, /^# PhishGuard 内容检查\n\n- \*\*输入：\*\* 邮件文件\n- \*\*结论：\*\* 高风险 — 可能是钓鱼邮件（风险 72%）\n- \*\*文本模型：\*\* TF-IDF \+ 逻辑回归 — 模型风险评分 72\.4%\n- \*\*生成时间：\*\* 2026-09-28T20:05:09\.000Z\n/);
  assert.match(markdown, /## 类别\n\n- 紧迫感与施压（高，2 个信号）/);
  assert.match(markdown, /## 技术指标\n\n- \*\*中\*\* — Shortened URL/);
  assert.match(markdown, /## 分析警告\n\n- Attachment content was not inspected; only metadata was checked\./);
  assert.match(context.senderReportMarkdown(senderData, new Date()), /- \*\*邮箱类型：\*\* 类似一次性邮箱的域名（未确认）/);

  context.renderContentResult(contentData);
  context.downloadReport('content', 'json');
  const report = JSON.parse(await blobs[0].text());
  assert.deepEqual(Object.keys(report), ['generated_at', 'tool', 'language', 'mode', 'result']);
  assert.equal(report.language, 'zh-CN');
  assert.equal(report.result.risk_label, 'High Risk — Likely Phishing', 'raw API data, English keys and values');
  assert.equal(report.result.category_results[0].label, 'Urgency & Pressure');
  assert.equal(page.elements.get('copy-status').textContent, '报告已下载');
});

test('request errors, input errors and the copy announcement are localized', async () => {
  const page = loadPage(PAGE, {localStorage: memoryStorage({'phishguard-lang': 'zh'}),
    fetch: async () => ({ok: false, status: 429, headers: {get: () => '37'}})});
  await assert.rejects(page.context.postJSON('/api/x', {}), {message: '请求过于频繁。请在 37 秒后重试。'});
  page.context.fetch = async () => ({ok: false, status: 400, json: async () => ({detail: 'Server-provided detail.'})});
  await assert.rejects(page.context.postJSON('/api/x', {}), {message: 'Server-provided detail.'});
  page.context.document.getElementById('email-input').value = 'hello';
  await page.context.runEmailAnalysis();
  assert.equal(page.elements.get('email-error').textContent, zh['sender.error.invalid']);
  const queue = [];
  page.context.setTimeout = fn => { queue.push(fn); return 0; };
  page.context.navigator = {clipboard: {writeText: async () => {}}};
  page.context.renderResult(senderData);
  const label = {textContent: '复制摘要'};
  await page.context.copySummary('sender', {querySelector: () => label});
  assert.equal(label.textContent, '已复制');
  queue.splice(0).forEach(fn => fn());
  assert.equal(page.elements.get('copy-status').textContent, '摘要已复制到剪贴板');
  assert.equal(label.textContent, '复制摘要');
});

test('Chinese server-derived text is escaped exactly like English', () => {
  const page = loadPage(PAGE, {localStorage: memoryStorage({'phishguard-lang': 'zh'})});
  page.context.renderContentResult({...contentData, category_results: [{key: '__proto__', label: '<img src=x>',
    level: '<b>', count: '<i>', description: '<script>', matched: ['<u>']}]});
  const grid = page.elements.get('content-category-grid').innerHTML;
  assert.doesNotMatch(grid, /<img|<b>|<i>|<script>|<u>/);
  assert.match(grid, /&lt;img src=x&gt;[\s\S]*匹配 &lt;i&gt; 个信号[\s\S]*&lt;b&gt;/);
});

test('Chinese image evidence and the unchanged English fallback for cases.html', () => {
  const zhRender = runVisionScenario(['i18n.js', 'vision.js'], {});
  // runVisionScenario loads with navigator en-US; switch before rendering via a stored choice.
  const window = {};
  const context = vm.createContext({window, navigator: {languages: ['zh-CN']}, localStorage: memoryStorage(), console,
    document: {createElement: tag => ({tag, children: [], textContent: '', append(...n) { this.children.push(...n); },
      replaceChildren(...n) { this.children = n; }})}, URL: {createObjectURL: () => 'blob:x', revokeObjectURL() {}},
    setTimeout, clearTimeout});
  vm.runInContext(source('i18n-zh.js'), context);
  vm.runInContext(source('i18n.js'), context);
  vm.runInContext(source('vision.js'), context);
  const root = {children: [], append(...n) { this.children.push(...n); }, replaceChildren(...n) { this.children = n; }};
  window.PhishGuardVision.render(root, {observations: [{name: 'a.png', status: 'processed', risk_level: 'high', ocr_confidence: 91.6,
    ocr_language: 'eng+chi_sim', ml_status: 'available', ml_phishing_probability: 81, qr_payloads: ['https://x.example'],
    ocr_text: 'Verify', warnings: ['Server warning']}], warnings: []});
  const texts = [];
  const walk = node => { if (node.textContent) texts.push(node.textContent); (node.children || []).forEach(walk); };
  walk(root);
  assert.deepEqual(texts.slice(0, 8), ['图片与二维码证据', zh['vision.intro'], zh['vision.confidenceNote'], 'a.png',
    '识别完成 · 风险：高 · OCR 置信度 92%', 'OCR 语言：中英混合', '提取文字的模型评分：钓鱼风险 81%。风险评估还会结合规则和链接证据。', '二维码内容']);
  assert.ok(texts.includes('Server warning'), 'server and worker warnings stay as sent');
  assert.deepEqual(zhRender, snapshot.vision, 'an English browser still gets English');
});

test('worker progress is shown in the page language', async () => {
  const run = languages => {
    const window = {};
    const workers = [];
    class Worker { constructor() { workers.push(this); } postMessage() {} terminate() {} }
    const context = vm.createContext({window, navigator: {languages}, localStorage: memoryStorage(), Worker,
      setTimeout, clearTimeout, Uint8Array, btoa: text => Buffer.from(text, 'binary').toString('base64')});
    vm.runInContext(source('i18n-zh.js'), context);
    vm.runInContext(source('i18n.js'), context);
    vm.runInContext(source('vision.js'), context);
    return {api: window.PhishGuardVision, workers};
  };
  for (const [languages, expected] of [[['zh-CN'], ['正在提取邮件中的图片…', '正在读取第 2 张图片（共 4 张）…', '正在识别英文和简体中文文字…', 'Some other message']],
    [['en-US'], ['Extracting email images…', 'Reading image 2 of 4…', 'Reading English and Simplified Chinese text…', 'Some other message']]]) {
    const {api, workers} = run(languages);
    const progress = [];
    const promise = api.recognize({name: 'a.eml', size: 3, arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer}, message => progress.push(message));
    await new Promise(resolve => setImmediate(resolve));
    for (const message of ['Extracting email images…', 'Reading image 2 of 4…', 'Reading English and Simplified Chinese text…', 'Some other message']) {
      workers[0].onmessage({data: {progress: message}});
    }
    workers[0].onmessage({data: {result: {observations: [], warnings: []}}});
    await promise;
    assert.deepEqual(progress, expected, languages[0]);
  }
});

test('shared components fall back to English without i18n.js and translate with it', async () => {
  const confirmSource = source('confirm-dialog.js');
  const labels = languages => {
    const created = [];
    const element = tag => ({tag, append() {}, addEventListener() {}, setAttribute() {}, showModal() {}, focus() {},
      set textContent(value) { created.push(value); }});
    const window = {};
    const context = vm.createContext({window, navigator: {languages}, localStorage: memoryStorage(), HTMLDialogElement: function () {},
      document: {createElement: element, body: {append() {}}}, console});
    if (languages) for (const name of ['i18n-zh.js', 'i18n.js']) vm.runInContext(source(name), context);
    vm.runInContext(confirmSource, context);
    window.PhishGuardConfirm('Message');
    return created.slice(1);
  };
  assert.deepEqual(labels(null), ['Cancel', 'Continue']);
  assert.deepEqual(labels(['en-US']), ['Cancel', 'Continue']);
  assert.deepEqual(labels(['zh-CN']), ['取消', '继续']);
});

test('the language toggle is a named, keyboard-operable button in the navbar', () => {
  const html = source('index.html');
  const nav = html.slice(html.indexOf('<nav class="navbar">'), html.indexOf('</nav>'));
  const toggle = nav.match(/<button class="lang-toggle" id="lang-toggle" type="button"([^>]*)>([\s\S]*?)<\/button>/);
  assert.ok(toggle, 'a real <button> in the navbar');
  assert.match(toggle[1], /aria-label="[^"]+"/);
  assert.match(toggle[1], /data-i18n-attr="aria-label:nav\.lang\.label;title:nav\.lang\.label"/);
  assert.match(toggle[2], /data-lang-option="en" lang="en"[^>]*>EN</);
  assert.match(toggle[2], /data-lang-option="zh" lang="zh-CN"[^>]*>中文</);
  assert.ok(nav.indexOf('id="lang-toggle"') < nav.indexOf('id="theme-toggle"'), 'next to the theme toggle');
  const css = source('style.css');
  assert.match(css, /\.lang-toggle:focus-visible \{[^}]*outline/);
  assert.match(css, /:root\[data-i18n-pending\] body \{[^}]*visibility: hidden;[^}]*animation: i18n-reveal/);
});

// ── Not-found page (404.html) ────────────────────────────────────────────────
test('404.html: every key exists in both languages, its English is the markup, and all text is covered', () => {
  const html = source('404.html');
  const elements = [...html.matchAll(/<([a-z0-9]+)\b([^>]*?)\sdata-i18n="([^"]+)"([^>]*)>([\s\S]*?)<\/\1>/g)];
  assert.deepEqual(elements.map(match => match[3]),
    ['notFound.meta.title', 'notFound.code', 'notFound.title', 'notFound.lead', 'notFound.home', 'notFound.cases']);
  for (const [, , , key, , inner] of elements) {
    assert.ok(Object.hasOwn(en, key) && Object.hasOwn(zh, key), key);
    assert.equal(normalize(inner), en[key], key);
  }
  for (const [tag, spec] of html.matchAll(/<[a-z]+\b[^>]*data-i18n-attr="([^"]+)"[^>]*>/g)) {
    for (const pair of spec.split(';')) {
      const [attr, key] = pair.split(':');
      assert.equal(decode(tag.match(new RegExp(`\\s${attr}="([^"]*)"`))[1]), en[key], key);
    }
  }
  const text = html.replace(/<!--[\s\S]*?-->|<!DOCTYPE[^>]*>/g, '').replace(/<(script|style|svg|title)\b[\s\S]*?<\/\1>/g, '');
  const stack = [], leftovers = [];
  for (const [, close, tag, attrs, textNode] of text.matchAll(/<(\/?)([a-z0-9]+)\b([^>]*)>|([^<]+)/g)) {
    if (textNode !== undefined) {
      const value = normalize(textNode);
      if (value && !stack.some(entry => entry.covered)) leftovers.push(value);
    } else if (close) {
      while (stack.length && stack.pop().tag !== tag);
    } else if (!/^(meta|link|input|br|img)$/.test(tag) && !attrs.endsWith('/')) {
      stack.push({tag, covered: /\sdata-i18n="/.test(attrs) || /aria-hidden="true"/.test(attrs) && tag !== 'button'});
    }
  }
  assert.deepEqual(leftovers, ['PhishGuard']);
});

test('404.html is translated to Chinese on load, <title> included', () => {
  const html = source('404.html');
  const make = key => ({attributes: {'data-i18n': key}, textContent: '',
    getAttribute(name) { return this.attributes[name] ?? null; }, setAttribute(name, value) { this.attributes[name] = value; }});
  const nodes = [...html.matchAll(/\sdata-i18n="([^"]+)"/g)].map(match => make(match[1]));
  const title = nodes.find(node => node.attributes['data-i18n'] === 'notFound.meta.title');
  const root = {lang: 'en', removeAttribute() {}};
  const document = {documentElement: root, readyState: 'loading', getElementById: () => null,
    querySelector: selector => (selector === 'title[data-i18n]' ? title : null),
    querySelectorAll: selector => (selector === '[data-i18n]' ? nodes : [])};
  loadI18n({languages: ['zh-CN'], document});
  assert.equal(root.lang, 'zh-CN');
  assert.deepEqual(nodes.map(node => node.textContent), nodes.map(node => zh[node.attributes['data-i18n']]));
  assert.equal(title.textContent, '页面未找到 · PhishGuard');
});

test('404.html: same start-up scripts as the homepage, no inline code, not indexed, links home and to the workspace', () => {
  const html = source('404.html');
  const head = html.slice(0, html.indexOf('</head>'));
  assert.match(head, /<script src="\/static\/theme-init\.js\?v=\d+"><\/script>\s*<script src="\/static\/lang-init\.js\?v=\d+"><\/script>/);
  assert.match(head, /<link rel="stylesheet" href="\/static\/style\.css\?v=\d+" \/>\s*<script src="\/static\/i18n\.js\?v=\d+" defer><\/script>/);
  assert.equal((html.match(/<script\b/g) || []).length, 3);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>|<style\b|\sstyle=|\son[a-z]+\s*=/i, 'nothing the CSP would block');
  assert.match(head, /<meta name="robots" content="noindex" \/>/);
  assert.match(html, /<a class="btn btn-primary" href="\/" data-i18n="notFound\.home">/);
  assert.match(html, /<a class="btn btn-outline" href="\/cases" data-i18n="notFound\.cases">/);
  assert.match(html, /<button class="lang-toggle" id="lang-toggle" type="button"/);
  assert.match(html, /<main id="main" class="nf-main">[\s\S]*<h1 data-i18n="notFound\.title">/);
});

test('indicator level labels use the shared level.* words in Chinese and English', () => {
  const levels = ['critical', 'high', 'medium', 'low', 'info'];
  assert.deepEqual(levels.map(level => zh[`level.${level}`]), ['严重', '高', '中', '低', '提示']);
  for (const [storage, words] of [[memoryStorage({'phishguard-lang': 'zh'}), levels.map(level => zh[`level.${level}`])],
    [memoryStorage({'phishguard-lang': 'en'}), levels]]) {
    const page = loadPage(PAGE, {localStorage: storage});
    const indicators = levels.map(level => ({level, msg: `${level} message`}));
    page.context.renderResult({email: 'a@example.com', verdict: 'high', label: 'High Sender Risk', risk_score: 41, risk_indicators: indicators,
      feature_breakdown: [], high_risk_count: 1, med_risk_count: 1});
    page.context.renderContentResult({risk_level: 'high', risk_label: 'High Risk — Likely Phishing', total_score: 9, category_results: [],
      extra_indicators: indicators, safety_signals: []});
    const labels = id => [...page.elements.get(id).innerHTML.matchAll(/<span class="level-label level-(\w+)">([^<]*)<\/span>/g)]
      .map(([, level, word]) => [level, word]);
    assert.deepEqual(labels('risk-indicators-list'), levels.slice(0, 4).map((level, index) => [level, words[index]]));
    assert.deepEqual(labels('content-extra-list'), levels.map((level, index) => [level, words[index]]));
  }
});
