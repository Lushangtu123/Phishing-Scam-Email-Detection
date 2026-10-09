/* ──────────────────────────────────────────────────────────────────────────
   app-sms.js – the text-message (SMS) tab
   Shown only when /api/config reports sms_analysis_enabled. Posts the sender
   and text to /api/analyze-sms and renders the result in the tab's own area,
   with the content tab's helpers (app-content-render.js, app-core.js).
   ────────────────────────────────────────────────────────────────────────── */

const SMS_MAX_CHARS = 2000;
// Synthetic examples; the numbers are reserved or fictional and the hosts are made up.
const SMS_EXAMPLES = {
  toll: { sender: '+63 917 555 0123',
    text: 'E-ZPass: Your unpaid toll balance of $4.15 is past due. Pay at ezpass-tollpay.top/x within 24 hours to avoid a $50 late fee.' },
  bank: { sender: '13800000000',
    text: '【工商银行】您的账户存在异常已被冻结，请回复Y后退出短信重新打开，点击 icbc-verify.top/a 解冻。' },
  delivered: { sender: '28777',
    text: 'USPS: Your package was delivered at 2:15 pm. Track it at https://tools.usps.com/go/TrackConfirmAction' },
};
const UNUSUAL_SMS_SENDERS = new Set(['email', 'international']);
let _smsRequestId = 0;
let _smsAbort = null;
let _smsResult = null;

// The tab starts hidden. A ?tab=sms link is read before the configuration arrives, so it is
// followed here once the tab is shown.
function applySmsConfig(config) {
  const tab = document.getElementById('tab-sms');
  tab.hidden = config.sms_analysis_enabled !== true;
  if (tab.hidden && tab.classList.contains('active')) switchDemoTab('email-address', { animate: false });
  const linked = typeof location !== 'undefined' ? tabFromSearch(location.search) : null;
  if (!tab.hidden && linked === 'sms') switchDemoTab('sms', { animate: false, updateUrl: false });
}

function updateSmsCount() {
  const length = document.getElementById('sms-text').value.length;
  document.getElementById('sms-count').textContent = t('sms.count', { count: length, max: SMS_MAX_CHARS });
}

function invalidateSms() {
  _smsRequestId++;
  _smsAbort?.abort();
  _smsAbort = null;
  setError('sms-error');
  document.getElementById('sms-result-area').classList.add('hidden');
}

function setSmsExample(key) {
  const example = SMS_EXAMPLES[key];
  if (!example) return;
  document.getElementById('sms-sender').value = example.sender;
  document.getElementById('sms-text').value = example.text;
  updateSmsCount();
  runSmsAnalysis();
}

function clearSms() {
  invalidateSms();
  document.getElementById('sms-sender').value = '';
  document.getElementById('sms-text').value = '';
  document.getElementById('sms-loading-area').classList.add('hidden');
  updateSmsCount();
}

async function runSmsAnalysis() {
  invalidateSms();
  const requestId = _smsRequestId;
  const sender = document.getElementById('sms-sender').value.trim();
  const text = document.getElementById('sms-text').value.trim();
  if (!text) {
    setError('sms-error', t('sms.error.empty'));
    return;
  }
  const btn = document.getElementById('sms-analyze-btn');
  btn.disabled = true;
  document.getElementById('sms-btn-text').textContent = t('sms.analyzing');
  document.getElementById('sms-loading-area').classList.remove('hidden');
  const controller = newAbortController();
  _smsAbort = controller;
  try {
    const data = await postJSON('/api/analyze-sms', { sender, text }, { signal: controller?.signal });
    if (requestId !== _smsRequestId) return;
    renderSmsResult(data);
    recordRecentCheck(smsRecentEntry(data));
  } catch (error) {
    if (requestId === _smsRequestId) setError('sms-error', error.message);
  } finally {
    if (requestId === _smsRequestId) {
      _smsAbort = null;
      btn.disabled = false;
      document.getElementById('sms-btn-text').textContent = t('sms.analyze');
      document.getElementById('sms-loading-area').classList.add('hidden');
    }
  }
}

function smsRecentEntry(data) {
  return { mode: 'sms', label: data.risk_label, level: data.risk_level, score: null, at: Date.now() };
}

// `languageOnly` re-renders the same result after a language switch without moving focus.
function renderSmsResult(data, { languageOnly = false } = {}) {
  _smsResult = data;
  const cfg = RISK_CONFIG[data.risk_level] || RISK_CONFIG.medium;
  document.getElementById('sms-risk-banner').className = 'content-risk-banner crb-' + data.risk_level;
  document.getElementById('sms-banner-icon').innerHTML = icon(cfg.icon);
  document.getElementById('sms-banner-title').textContent = contentRiskLabel(data.risk_label, data.risk_level);
  const indicators = (data.extra_indicators || []).filter(item => item.level !== 'info');
  const categories = data.category_results || [];
  const parts = [];
  if (categories.length) parts.push(tPlural('content.sub.categories', categories.length));
  if (indicators.length) parts.push(tPlural('content.sub.technical', indicators.length));
  document.getElementById('sms-banner-sub').textContent = parts.length ? parts.join(' • ') : t('sms.sub.none');

  document.getElementById('sms-sender-kind').textContent = t('sms.sender.kind', { kind: t(`sms.kind.${data.sender_kind}`) });
  const claimed = document.getElementById('sms-claimed');
  claimed.hidden = !data.claimed_brand;
  claimed.textContent = data.claimed_brand ? t('sms.sender.claimed', { organization: data.claimed_brand }) : '';
  // A note, not a score: friends' iMessages and some services abroad use these too, but in the
  // owner's texts 26 of 35 scams and none of 176 genuine texts came from them (docs/evaluation.md).
  const note = document.getElementById('sms-sender-note');
  note.hidden = !UNUSUAL_SMS_SENDERS.has(data.sender_kind);
  note.textContent = note.hidden ? '' : t('sms.sender.unusual');

  document.getElementById('sms-category-grid').innerHTML = categories.map(cat => `
    <div class="cat-card cat-${escapeHtml(cat.level)}">
      <div class="cat-header">
        <span class="cat-icon icon-tile tile-${escapeHtml(cat.level)}">${icon(CATEGORY_ICONS[cat.key] || 'alert')}</span>
        <div class="cat-title-wrap"><div class="cat-title">${escapeHtml(categoryText(cat, 'label'))}</div></div>
        <span class="cat-level-badge level-${escapeHtml(cat.level)}">${escapeHtml(levelName(cat.level))}</span>
      </div>
      <div class="cat-keywords">${cat.matched.map(kw => `<span class="kw-pill">${escapeHtml(kw)}</span>`).join('')}</div>
    </div>
  `).join('');

  const channels = data.official_channels || [];
  document.getElementById('sms-official-card').hidden = channels.length === 0;
  document.getElementById('sms-official-list').innerHTML = channels.map(channel => `
    <div class="official-item">
      <p class="official-advice">${escapeHtml(t('content.verify.channel', {
        organization: channel.organization, website: channel.website }))}</p>
      ${channel.service_numbers?.length ? `<p class="official-phone">${escapeHtml(t('content.verify.phone', {
        numbers: channel.service_numbers.join(' / ') }))}</p>` : ''}
      ${channel.statement ? `<blockquote class="official-statement">${escapeHtml(channel.statement)}
        <cite><a href="${escapeHtml(channel.statement_source)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
          t('content.verify.source', { organization: channel.organization }))}</a></cite></blockquote>` : ''}
    </div>
  `).join('');

  const all = data.extra_indicators || [];
  document.getElementById('sms-extra-card').hidden = all.length === 0;
  document.getElementById('sms-extra-list').innerHTML = all.map(item => `
    <div class="risk-item risk-${escapeHtml(item.level)}">
      <span class="risk-dot" aria-hidden="true"></span>
      ${levelLabelHtml(item.level)}
      <span class="risk-msg">${escapeHtml(serverText(item))}</span>
    </div>
  `).join('');

  document.getElementById('sms-result-area').classList.remove('hidden');
  if (!languageOnly) document.getElementById('sms-banner-title').focus?.();
}

function rerenderSmsForLanguage() {
  updateSmsCount();
  document.getElementById('sms-btn-text').textContent =
    t(document.getElementById('sms-analyze-btn').disabled ? 'sms.analyzing' : 'sms.analyze');
  if (_smsResult && !document.getElementById('sms-result-area').classList.contains('hidden')) {
    renderSmsResult(_smsResult, { languageOnly: true });
  }
}

function setupSmsInput() {
  const text = document.getElementById('sms-text');
  text.addEventListener('input', updateSmsCount);
  text.addEventListener('keydown', event => {
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) runSmsAnalysis();
  });
  updateSmsCount();
}
