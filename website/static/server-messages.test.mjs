// Server messages: the backend registry (data/server_messages.json, code →
// English template) must match the homepage dictionary, and coded messages
// must render in Chinese while English stays exactly the server's text.
import assert from 'node:assert/strict';
import {readdirSync, readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import {loadPage, memoryStorage} from '../tests/fixtures/i18n/scenarios.mjs';

const WEBSITE = new URL('../', import.meta.url);
const REGISTRY = JSON.parse(readFileSync(new URL('data/server_messages.json', WEBSITE), 'utf8'));
const source = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
const PAGE = ['i18n-zh.js', 'i18n.js', 'app-core.js', 'app-theme.js', 'app-layout.js', 'app-config.js', 'app-sender.js', 'app-verify.js',
  'app-content.js', 'app-content-render.js', 'app-sms.js', 'app-reports.js', 'app-metrics.js', 'app.js'];
const fields = text => [...text.matchAll(/\{(\w+)\}/g)].map(match => match[1]).sort();

function loadI18n(languages) {
  const window = {};
  const context = vm.createContext({window, navigator: {languages}, localStorage: memoryStorage(), console});
  for (const name of ['i18n-zh.js', 'i18n.js']) vm.runInContext(source(name), context);
  return window.PhishGuardI18n;
}
const {en, zh} = loadI18n(['en-US']).DICTIONARY;
const zhPage = () => loadPage(PAGE, {localStorage: memoryStorage({'phishguard-lang': 'zh'})});
const enPage = () => loadPage(PAGE, {localStorage: memoryStorage({'phishguard-lang': 'en'})});

// ── Registry ↔ dictionary guard ─────────────────────────────────────────────
test('every backend template is in the dictionary with identical English and matching Chinese placeholders', () => {
  const codes = Object.keys(REGISTRY);
  assert.ok(codes.length > 150, `${codes.length} codes`);
  const serverKeys = lang => Object.keys(lang).filter(key => key.startsWith('server.')).map(key => key.slice(7)).sort();
  assert.deepEqual(serverKeys(en), [...codes].sort(), 'en server.* keys are exactly the backend codes');
  assert.deepEqual(serverKeys(zh), [...codes].sort(), 'zh server.* keys are exactly the backend codes');
  for (const [code, template] of Object.entries(REGISTRY)) {
    assert.match(code, /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/, code);
    assert.equal(en[`server.${code}`], template, `server.${code}: update i18n.js when the backend wording changes`);
    assert.deepEqual(fields(zh[`server.${code}`]), fields(template), `server.${code} placeholders`);
    if (/[A-Za-z]/.test(template.replace(/\{\w+\}/g, ''))) assert.notEqual(zh[`server.${code}`], template, `server.${code} is translated`);
  }
});

test('every message code the backend can emit is registered and in the dictionary', () => {
  const families = ['sender', 'content', 'link', 'structure', 'warning', 'safety', 'prefix', 'verify'];
  const literal = new RegExp(`['"]((?:${families.join('|')})\\.[a-z0-9_.]*[a-z0-9_])['"]`, 'g');
  const used = new Set();
  for (const name of readdirSync(WEBSITE).filter(file => file.endsWith('.py'))) {
    for (const [, code] of readFileSync(new URL(name, WEBSITE), 'utf8').matchAll(literal)) used.add(code);
  }
  used.delete('verify.phishguard.local');  // the SMTP HELO name, not a message code
  assert.ok(used.size > 120, `${used.size} code literals`);
  for (const code of used) {
    assert.ok(Object.hasOwn(REGISTRY, code), `${code} is not in data/server_messages.json`);
    assert.ok(Object.hasOwn(en, `server.${code}`) && Object.hasOwn(zh, `server.${code}`), `${code} is not in i18n.js`);
  }
  // Codes composed at runtime (safety.<name>, sender.factor.<name>, verify.dmarc_<policy>) are registry
  // entries too, so the registry check above covers every emitted code.
});

// ── Rendering ────────────────────────────────────────────────────────────────
// Payload pieces below are verbatim backend output for the homepage examples.
const RANDOM = {code: 'sender.random_username', level: 'medium',
  msg: "Username 'security-alert' matches 2/6 randomness factors (entropy 3.38, unique-ratio 79%) — the mailbox pattern looks automatically generated, but account age and lifetime cannot be confirmed",
  params: {entropy: '3.38', factor_codes: 'entropy,unique', factors: 'entropy 3.38, unique-ratio 79%', score: 2, unique_percent: 79,
    username: 'security-alert', vowel_percent: 38}};
const HYPHEN = {code: 'sender.domain_hyphen', level: 'low', params: {domain: 'paypa1-verify.xyz'},
  msg: 'Domain contains a hyphen (paypa1-verify.xyz) — major providers typically do not use hyphens in their domains'};
const TLD = {code: 'sender.high_risk_tld', level: 'high', params: {tld: 'xyz'},
  msg: "TLD '.xyz' is a known high-risk or free domain extension heavily used in phishing campaigns"};
const KEYWORDS = {code: 'sender.username_keywords', level: 'high', params: {keywords: 'security, alert'},
  msg: 'Username contains phishing keywords: security, alert'};
const sender = {email: 'security-alert@paypa1-verify.xyz', verdict: 'critical', label: 'Critical Sender Risk', risk_score: 97,
  risk_indicators: [RANDOM, HYPHEN, TLD, KEYWORDS,
    {level: 'high', msg: 'A future indicator the dictionary does not know', code: 'sender.future_rule', params: {}}],
  high_risk_count: 3, med_risk_count: 1, feature_breakdown: [], disposable_status: 'no_known_match'};

test('Chinese sender results localize coded indicators, the score breakdown, the summary and the report', () => {
  const {context, elements} = zhPage();
  context.renderResult(sender);
  const list = elements.get('risk-indicators-list').innerHTML;
  assert.match(list, /用户名 &#39;security-alert&#39; 符合 2\/6 项随机性特征（熵值 3\.38、不重复字符占比 79%）— 该邮箱名看起来像是自动生成的/);
  assert.match(list, /域名包含连字符（paypa1-verify\.xyz）— 主流服务商的域名通常不使用连字符/);
  assert.match(list, /顶级域 &#39;\.xyz&#39; 属于已知的高风险或免费域名后缀/);
  assert.match(list, /用户名包含钓鱼关键词：security, alert/, 'matched keywords stay as sent');
  assert.match(list, /A future indicator the dictionary does not know/, 'an unknown code falls back to the English text');
  const breakdown = elements.get('score-breakdown-list').innerHTML;
  assert.match(breakdown, /\+28<\/span>\s*<span class="sb-msg">顶级域/);
  assert.match(breakdown, /\+3<\/span>\s*<span class="sb-msg">域名包含连字符/);
  const summary = context.senderSummaryText(sender);
  assert.match(summary, /- \[低\] 域名包含连字符（paypa1-verify\.xyz）/);
  const markdown = context.senderReportMarkdown(sender, new Date(Date.UTC(2026, 8, 28)));
  assert.match(markdown, /- \*\*高\*\* — 顶级域 '\.xyz' 属于已知的高风险/);
  assert.match(markdown, /- \*\*高\*\* — A future indicator/);
});

test('English rendering uses the server text exactly, with or without codes', () => {
  const coded = enPage();
  coded.context.renderResult(sender);
  const plain = enPage();
  plain.context.renderResult({...sender, risk_indicators: sender.risk_indicators.map(({level, msg}) => ({level, msg}))});
  for (const id of ['risk-indicators-list', 'score-breakdown-list']) {
    assert.equal(coded.elements.get(id).innerHTML, plain.elements.get(id).innerHTML, id);
  }
  assert.match(coded.elements.get('risk-indicators-list').innerHTML, /Domain contains a hyphen \(paypa1-verify\.xyz\)/);
  assert.equal(coded.context.senderSummaryText(sender), plain.context.senderSummaryText({...sender,
    risk_indicators: sender.risk_indicators.map(({level, msg}) => ({level, msg}))}));
});

test('server() localizes only when code and params reproduce the English text', () => {
  const i18n = loadI18n(['zh-CN']);
  assert.equal(i18n.server(HYPHEN), '域名包含连字符（paypa1-verify.xyz）— 主流服务商的域名通常不使用连字符');
  // Changed backend wording, a missing or truncated param, or no code: the server's text.
  assert.equal(i18n.server({...HYPHEN, msg: 'Domain has a hyphen (paypa1-verify.xyz)'}), 'Domain has a hyphen (paypa1-verify.xyz)');
  assert.equal(i18n.server({...HYPHEN, params: {}}), HYPHEN.msg);
  assert.equal(i18n.server({...HYPHEN, params: {domain: 'paypa1-veri…'}}), HYPHEN.msg);
  assert.equal(i18n.server({level: 'low', msg: HYPHEN.msg}), HYPHEN.msg);
  assert.equal(i18n.server({...HYPHEN, code: 'toString'}), HYPHEN.msg);
  assert.equal(i18n.server({...HYPHEN, code: '__proto__'}), HYPHEN.msg);
  assert.equal(i18n.server(null), null);
  // A factor list that cannot be rebuilt keeps the server's (English) factor text.
  assert.match(i18n.server({...RANDOM, params: {...RANDOM.params, factor_codes: 'entropy,mystery'}}), /（entropy 3\.38, unique-ratio 79%）/);
  // Prefixes wrap the inner message, outermost first; an unknown inner text stays as sent inside a known prefix.
  const nested = {code: 'warning.remote_images', params: {}, msg: 'Attached message: Image (a.png): Remote image content was not inspected; analysis is incomplete.',
    prefixes: [{code: 'prefix.attached_message', params: {}}, {code: 'prefix.image', params: {name: 'a.png'}}]};
  assert.equal(i18n.server(nested), '附件中的邮件：图片（a.png）：未检查远程图片内容；分析未完成。');
  assert.equal(i18n.server({code: 'prefix.image_recognition', params: {text: 'scan.png: decoder crashed'},
    msg: 'Image recognition: scan.png: decoder crashed'}), '图片识别：scan.png: decoder crashed');
  // Category labels inside messages use the category dictionary when the English matches.
  assert.equal(i18n.server({code: 'content.nested_category', params: {label: 'Urgency & Pressure', matched: 'urgent, act now', category: 'urgency'},
    msg: 'Urgency & Pressure — urgent, act now', prefixes: []}), `${zh['category.urgency.label']} — urgent, act now`);
  assert.equal(i18n.server({code: 'content.category', params: {label: 'Renamed', category: 'urgency'}, msg: 'Renamed'}), 'Renamed');
  // Placeholders in params are data, not templates.
  assert.equal(i18n.server({code: 'sender.domain_keywords', params: {keywords: '{text} <b>'}, msg: 'Domain contains phishing keywords: {text} <b>'}),
    '域名包含钓鱼关键词：{text} <b>');
  assert.deepEqual(i18n.serverList(['Mentions privacy policy — sign of compliance', 'Unknown signal'],
    [{code: 'safety.privacy_policy', params: {}, msg: 'Mentions privacy policy — sign of compliance'}]), ['提及隐私政策 — 合规的迹象', 'Unknown signal']);
  assert.equal(loadI18n(['en-US']).server(HYPHEN), HYPHEN.msg);
});

const content = {
  risk_level: 'high', risk_label: 'High Risk — Likely Phishing', total_score: 12, combined_phishing_score: 91, analysis_complete: false,
  input_mode: 'raw-email', category_results: [], ml_label: null, ml_status: 'disabled',
  extra_indicators: [
    {code: 'content.shortened_urls', level: 'high', params: {}, msg: 'Contains shortened URLs (bit.ly, tinyurl, etc.) — hides the true destination domain'},
    {code: 'content.exclamation_marks', level: 'medium', params: {count: 4}, msg: 'Excessive exclamation marks (4) — emotional manipulation tactic common in scam emails'},
    {code: 'link.unsafe_scheme', level: 'high', params: {scheme: 'javascript'}, msg: 'Link uses an unsafe destination scheme (javascript:).', rule_id: 'link.unsafe_scheme'},
    {...HYPHEN, msg: 'Sender: ' + HYPHEN.msg, prefixes: [{code: 'prefix.sender', params: {}}]},
    {code: 'warning.remote_images', level: 'info', params: {}, msg: 'Remote image content was not inspected; analysis is incomplete.'},
    {code: 'structure.dangerous_attachment', level: 'high', params: {filename: '<img src=x onerror=alert(1)>.exe'},
      msg: 'Potentially dangerous attachment: <img src=x onerror=alert(1)>.exe.'},
  ],
  safety_signals: ['Contains unsubscribe link — typical of legitimate bulk emails', 'Contains copyright notice'],
  safety_signal_details: [{code: 'safety.unsubscribe', params: {}, msg: 'Contains unsubscribe link — typical of legitimate bulk emails'},
    {code: 'safety.copyright', params: {}, msg: 'Contains copyright notice'}],
  analysis_warnings: ['Remote image content was not inspected; analysis is incomplete.', 'Image recognition: worker note'],
  analysis_warning_details: [{code: 'warning.remote_images', params: {}, msg: 'Remote image content was not inspected; analysis is incomplete.'},
    {code: null, params: {}, msg: 'Image recognition: worker note'}],
  remote_image_coverage: {inspection_status: 'metadata_only'},
};

test('Chinese content results localize technical indicators, safety signals and report warnings; params stay escaped', () => {
  const {context, elements} = zhPage();
  context.renderContentResult(content);
  const extras = elements.get('content-extra-list').innerHTML;
  assert.match(extras, /包含短链接 URL（bit\.ly、tinyurl 等）— 隐藏了真实的目标域名/);
  assert.match(extras, /感叹号过多（4 个）/);
  assert.match(extras, /链接使用了不安全的目标协议（javascript:）。/);
  assert.match(extras, /发件人：域名包含连字符（paypa1-verify\.xyz）/);
  assert.match(extras, /未检查远程图片内容；分析未完成。/);
  assert.match(extras, /潜在危险附件：&lt;img src=x onerror=alert\(1\)&gt;\.exe。/);
  assert.doesNotMatch(extras, /<img/);
  const safety = elements.get('content-safety-list').innerHTML;
  assert.match(safety, /包含退订链接 — 正规群发邮件的常见特征[\s\S]*包含版权声明/);
  const markdown = context.contentReportMarkdown(content, new Date(Date.UTC(2026, 8, 28)));
  assert.match(markdown, /## 分析警告\n\n- 未检查远程图片内容；分析未完成。\n- Image recognition: worker note/);
  assert.match(markdown, /- \*\*高\*\* — 潜在危险附件：\\<img src=x onerror=alert\(1\)\\>\.exe。/);
  assert.match(context.contentSummaryText(content), /- \[中\] 感叹号过多（4 个）/);
  // The sub-line still detects coverage from the English warnings.
  assert.match(elements.get('crb-sub').textContent, /未检查远程图片内容。/);
});

test('Chinese verification steps localize coded server messages and keep raw server replies', () => {
  const {context, elements} = zhPage();
  context.renderVerifyResult({email: 'a@example.com', format_valid: true, mx_found: true, mx_records: [[10, 'mx.example.com']],
    smtp_status: 'skipped', smtp_result: 'unavailable', smtp_message: 'SMTP mailbox probing is unavailable on this deployment.',
    smtp_message_code: 'verify.smtp_disabled', smtp_message_params: {},
    spf: {found: true, policy: 'strict', code: 'verify.spf_strict', params: {}, message: 'Strict policy (-all): unauthorized senders are rejected.'},
    dmarc: {found: true, policy: 'reject', code: 'verify.dmarc_reject_partial', params: {pct: 40},
      message: 'p=reject (requested for 40% of messages): domain requests rejection of DMARC-failing messages.'},
    domain_age: {found: true, age_days: 4000, registrar: 'Reg Inc', code: 'verify.age_established', params: {date: '2015-10-16', years: 10},
      message: 'Domain registered 2015-10-16 (10 years old) — well-established.'},
    mx_ptr: {found: false, code: 'verify.ptr_timeout', params: {}, message: 'PTR check timed out.'},
    overall: 'domain_valid', verification_complete: false, domain_verification: {complete: false}});
  assert.equal(elements.get('vstep-smtp-detail').textContent, '当前部署不支持 SMTP 邮箱探测。');
  assert.equal(elements.get('vstep-spf-detail').textContent, '严格策略（-all）：未授权的发件服务器会被拒收。');
  assert.equal(elements.get('vstep-dmarc-detail').textContent, 'p=reject（要求适用于 40% 的邮件）：域名要求拒收未通过 DMARC 的邮件。');
  assert.equal(elements.get('vstep-age-detail').textContent, '该域名注册于 2015-10-16（已有 10 年）— 历史较长。 · 注册商：Reg Inc');
  assert.equal(elements.get('vstep-ptr-detail').textContent, 'PTR 检查超时。');
  assert.equal(elements.get('vstep-ptr').className, 'verify-step vstep-skip', 'the timeout state still comes from the English text');

  context.renderVerifyResult({email: 'a@example.com', format_valid: true, mx_found: true, smtp_result: 'does_not_exist',
    smtp_message: 'Mail server reports no such mailbox (SMTP 550): 5.1.1 <a@example.com> unknown',
    smtp_message_code: 'verify.smtp_no_such_mailbox', smtp_message_params: {smtp_code: 550, response: '5.1.1 <a@example.com> unknown'},
    overall: 'likely_invalid'});
  assert.equal(elements.get('vstep-smtp-detail').textContent, '邮件服务器报告该邮箱不存在（SMTP 550）：5.1.1 <a@example.com> unknown');
  context.renderVerifyResult({email: 'bad', format_valid: false, smtp_message: 'Enter a single supported email address with an unquoted ASCII local part and a valid domain.',
    smtp_message_code: 'verify.format_invalid', smtp_message_params: {}});
  assert.equal(elements.get('vstep-format-detail').textContent, zh['server.verify.format_invalid']);
});

test('image evidence localizes coded assessment and enhancement warnings; cases.html keeps English', () => {
  const OCR = 'Verify website addresses against the original image character by character. OCR can confuse 1/l/I or 0/O and break URL punctuation, even with high confidence. The original OCR text is preserved; no address spelling has been verified.';
  const analysis = {observations: [{name: 'a.png', status: 'processed', risk_level: 'high', ocr_confidence: 90, ocr_language: 'eng',
    ml_status: 'available', ml_phishing_probability: 81, warnings: ['OCR confidence is low; verify the extracted text.'],
    assessment_warnings: [OCR], assessment_warning_details: [{code: 'warning.ocr_verify_urls', params: {}, msg: OCR}]}],
  enhancement: {status: 'unavailable', warnings: ['Enhanced recognition failed; browser OCR and QR results were retained.'],
    warning_details: [{code: 'warning.enhanced_failed', params: {}, msg: 'Enhanced recognition failed; browser OCR and QR results were retained.'}]},
  warnings: []};
  const render = (scripts, languages) => {
    const window = {};
    const node = tag => ({tag, children: [], textContent: '', append(...n) { this.children.push(...n); }, replaceChildren(...n) { this.children = n; }});
    const context = vm.createContext({window, navigator: {languages}, localStorage: memoryStorage(), console,
      document: {createElement: node}, URL: {createObjectURL: () => 'blob:x', revokeObjectURL() {}}, setTimeout, clearTimeout});
    for (const name of scripts) vm.runInContext(source(name), context);
    const root = node('section');
    window.PhishGuardVision.render(root, analysis);
    const texts = [];
    const walk = item => { if (item.textContent) texts.push(item.textContent); item.children.forEach(walk); };
    walk(root);
    return texts;
  };
  const chinese = render(['i18n-zh.js', 'i18n.js', 'vision.js'], ['zh-CN']);
  assert.ok(chinese.includes(zh['server.warning.ocr_verify_urls']));
  assert.ok(chinese.includes('增强识别失败；已保留浏览器端的 OCR 和二维码结果。'));
  assert.ok(chinese.includes('OCR confidence is low; verify the extracted text.'), 'browser worker warnings stay as sent');
  for (const [scripts, languages] of [[['vision.js'], ['zh-CN']], [['i18n.js', 'vision.js'], ['en-US']]]) {
    const english = render(scripts, languages);
    assert.ok(english.includes(OCR) && english.includes(analysis.enhancement.warnings[0]), scripts.join('+'));
  }
});
