/* ──────────────────────────────────────────────────────────────────────────
   app-sender.js – sender address analysis
   Examples, the request, result rendering, sender history and the
   score breakdown.
   ────────────────────────────────────────────────────────────────────────── */

let _senderRequestId = 0;
// Aborts the sender request in flight; null when none is.
let _senderAbort = null;

// Returns an AbortController for a new request, or null where there is none.
function newAbortController() {
  return typeof AbortController === 'function' ? new AbortController() : null;
}

function invalidateSender() {
  window.PhishGuardFeedback?.clear('sender');
  _senderRequestId++;
  _senderAbort?.abort();
  _senderAbort = null;
  abortVerification();
  _verificationRequestId++;
  _verifyEmail = null;
  const cancel = document.getElementById('cancel-sender-analysis');
  if (cancel) cancel.hidden = true;
  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('loading-area').classList.add('hidden');
  document.getElementById('analyze-btn').disabled = false;
  document.getElementById('analyze-btn-text').textContent = t('sender.analyze');
  setError('email-error');
  setError('verify-error');
}

// ── Quick examples ────────────────────────────────────────────────────────────
function setExample(email) {
  const input = document.getElementById('email-input');
  input.value = email;
  document.getElementById('btn-clear').classList.add('visible');
  input.focus();
  runEmailAnalysis();
}

function clearEmail() {
  invalidateSender();
  const input = document.getElementById('email-input');
  input.value = '';
  document.getElementById('btn-clear').classList.remove('visible');
  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('loading-area').classList.add('hidden');
  input.focus();
}

// ── Email Analysis ────────────────────────────────────────────────────────────
async function runEmailAnalysis() {
  const email = document.getElementById('email-input').value.trim();
  invalidateSender();
  const requestId = _senderRequestId;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    setError('email-error', t('sender.error.invalid'));
    shakeInput();
    return;
  }

  const btn = document.getElementById('analyze-btn');
  const btnText = document.getElementById('analyze-btn-text');
  btn.disabled = true;
  btnText.textContent = t('sender.analyzing');

  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('loading-area').classList.remove('hidden');
  const controller = newAbortController();
  _senderAbort = controller;
  const cancel = document.getElementById('cancel-sender-analysis');
  if (cancel && controller) cancel.hidden = false;

  try {
    const data = await postJSON('/api/analyze-email', { email }, { signal: controller?.signal });
    if (requestId !== _senderRequestId) return;
    renderResult(data);
    recordRecentCheck(senderRecentEntry(data));
    window.PhishGuardFeedback?.set('sender', {
      inputMode: 'sender', fingerprintInput: email,
      analysis: feedbackAnalysis(data, true), buildSource: () => ({email}),
    });
  } catch (e) {
    if (requestId === _senderRequestId) setError('email-error', e.message);
  } finally {
    if (requestId === _senderRequestId) {
      _senderAbort = null;
      if (cancel) cancel.hidden = true;
      btn.disabled = false;
      btnText.textContent = t('sender.analyze');
      document.getElementById('loading-area').classList.add('hidden');
    }
  }
}

// The Cancel button: stops the request, restores the idle form (no error) and
// says so through the live region. A response that still arrives is ignored.
function cancelEmailAnalysis() {
  if (!_senderAbort) return;
  invalidateSender();
  announce(t('request.cancelled'));
  document.getElementById('email-input').focus();
}

function shakeInput() {
  const wrap = document.querySelector('.email-input-wrap');
  wrap.classList.add('shake');
  setTimeout(() => wrap.classList.remove('shake'), 500);
}

function senderProviderName(email) {
  const domain = String(email || '').split('@')[1]?.toLowerCase() || '';
  if (domain === 'gmail.com' || domain === 'googlemail.com') return 'Gmail';
  if (['outlook.com', 'hotmail.com', 'live.com', 'msn.com'].includes(domain)) return 'Outlook';
  if (domain === 'yahoo.com') return 'Yahoo';
  if (domain === 'icloud.com' || domain === 'me.com' || domain === 'mac.com') return 'iCloud';
  if (domain === 'proton.me' || domain === 'protonmail.com') return 'Proton';
  return t('sender.history.provider');
}

// sender_history_status → dictionary key and row style.
const SENDER_HISTORY_STATES = {
  first_seen:           { key: 'first', cls: ' history-first', caveat: true },
  previously_seen:      { key: 'seen', cls: ' history-seen', caveat: true },
  not_seen:             { key: 'notSeen', cls: ' history-first', caveat: true },
  raw_message_required: { key: 'raw', cls: ' history-unavailable', caveat: true },
  unavailable:          { key: 'unavailable', cls: ' history-unavailable', caveat: false },
};
const SENDER_HISTORY_DISABLED = { key: 'disabled', cls: ' history-unavailable', caveat: false };

function renderSenderHistory(data, prefix = '') {
  const id = name => `${prefix}${name}`;
  const card = document.getElementById(id('sender-history-card'));
  const row = document.getElementById(id('sender-history-row'));
  const iconEl = document.getElementById(id('sender-history-icon'));
  const label = document.getElementById(id('sender-history-label'));
  const detail = document.getElementById(id('sender-history-detail'));
  const status = data.sender_history_status || 'disabled';
  const providerCaveat = data.account_observability === 'provider_account_unverifiable'
    ? t('sender.history.caveat', { provider: senderProviderName(data.email) })
    : '';
  const state = Object.hasOwn(SENDER_HISTORY_STATES, status) ? SENDER_HISTORY_STATES[status] : SENDER_HISTORY_DISABLED;

  card.classList.remove('hidden');
  row.className = 'sender-history-row';
  iconEl.innerHTML = icon('clock');

  row.className += state.cls;
  label.textContent = t(`sender.history.${state.key}.label`);
  detail.textContent = t(`sender.history.${state.key}.detail`, state.caveat ? { caveat: providerCaveat } : undefined);
}

// The verdict code maps one-to-one to the server's English label.
function senderVerdictLabel(data) {
  if (uiLang() === 'en' || !['critical', 'high', 'medium', 'low'].includes(data.verdict)) return data.label;
  return t(`sender.verdict.${data.verdict}`);
}

// Feature labels and descriptions are keyed by the stable feature name.
function featureText(feature, field) {
  const name = String(feature.name || '');
  if (field === 'label') return knownText(`feature.${name}.label`, feature.label);
  const flag = knownText(`feature.${name}.flag`, feature.email_desc);
  return flag !== feature.email_desc ? flag : knownText(`feature.${name}.ok`, feature.email_desc);
}

// ── Render Result ─────────────────────────────────────────────────────────────
// `languageOnly` re-renders the same result after a language switch: it keeps
// the verification card, skips the score animations, and does not scroll or
// move focus.
function renderResult(data, { languageOnly = false } = {}) {
  lastResults.sender = data;
  const isHighRisk = data.verdict === 'high' || data.verdict === 'critical';
  const isSuspect = data.verdict === 'medium';
  const area = document.getElementById('result-area');

  // Reset verify card so it shows "Run Verification" for the new email
  if (!languageOnly) {
    _verifyEmail = data.email;
    resetVerifyCard();
  }

  // Disposable classification is evidence-scoped: a registry match is
  // different from a privacy relay, a heuristic pattern, or no known match.
  const dispIcon  = document.getElementById('disp-check-icon');
  const dispLabel = document.getElementById('disp-check-label');
  const dispDet   = document.getElementById('disp-check-detail');
  const dispRow   = document.getElementById('disp-check-row');
  const dispCard  = document.getElementById('disposable-check-card');
  // Remove old badge if it exists
  const oldBadge = dispCard.querySelector('.disp-confidence-badge');
  if (oldBadge) oldBadge.remove();

  const domain = (data.email || '').split('@')[1] || '';
  const disposableStatus = data.disposable_status || (
    data.is_disposable
      ? (data.is_suspected_disposable ? 'suspicious_mailbox_pattern' : 'known_disposable_provider')
      : 'no_known_match'
  );
  const aliasNote = data.address_alias_type === 'subaddress' ? t('sender.disp.alias') : '';

  if (disposableStatus === 'known_disposable_provider') {
    dispRow.className  = 'disp-check-row disp-is-disposable';
    dispCard.className = 'col-card disposable-check-card is-disposable';
    dispIcon.innerHTML    = icon('trash');
    dispLabel.textContent = t('sender.disp.known.label');
    dispDet.textContent   = t('sender.disp.known.detail', {
      provider: data.matched_provider_domain || data.disposable_service || domain, alias: aliasNote });

  } else if (disposableStatus === 'privacy_relay') {
    dispRow.className  = 'disp-check-row disp-not-disposable';
    dispCard.className = 'col-card disposable-check-card not-disposable';
    dispIcon.innerHTML    = icon('shield');
    dispLabel.textContent = t('sender.disp.relay.label');
    dispDet.textContent   = t('sender.disp.relay.detail', { provider: data.matched_provider_domain || domain, alias: aliasNote });

  } else if (disposableStatus === 'suspicious_mailbox_pattern') {
    dispRow.className  = 'disp-check-row disp-suspected-disposable';
    dispCard.className = 'col-card disposable-check-card suspected-disposable';
    dispIcon.innerHTML    = icon('alert');
    dispLabel.textContent = t('sender.disp.mailbox.label');
    dispDet.textContent = t('sender.disp.mailbox.detail', { alias: aliasNote });
    const badge = document.createElement('div');
    badge.className = 'disp-confidence-badge';
    badge.textContent = t('sender.disp.mailbox.badge');
    dispCard.appendChild(badge);

  } else if (disposableStatus === 'suspicious_domain_pattern') {
    dispRow.className  = 'disp-check-row disp-suspected-disposable';
    dispCard.className = 'col-card disposable-check-card suspected-disposable';
    dispIcon.innerHTML    = icon('alert');
    dispLabel.textContent = t('sender.disp.domain.label');
    dispDet.textContent = t('sender.disp.domain.detail', { domain, alias: aliasNote });

  } else {
    dispRow.className  = 'disp-check-row disp-not-disposable';
    dispCard.className = 'col-card disposable-check-card not-disposable';
    dispIcon.innerHTML    = icon('mail');
    dispLabel.textContent = t('sender.disp.none.label');
    dispDet.textContent   = t('sender.disp.none.detail', { domain, alias: aliasNote });
  }

  renderSenderHistory(data);

  // Verdict banner
  const banner = document.getElementById('verdict-banner');
  let bannerCls, bannerIcon, probColor;
  if (isHighRisk) {
    bannerCls = 'banner-phish';   bannerIcon = 'alert';  probColor = 'var(--red)';
  } else if (isSuspect) {
    bannerCls = 'banner-suspect'; bannerIcon = 'search'; probColor = 'var(--yellow)';
  } else {
    bannerCls = 'banner-neutral'; bannerIcon = 'info'; probColor = 'var(--info)';
  }
  banner.className = 'verdict-banner ' + bannerCls;
  document.getElementById('vb-icon').innerHTML    = icon(bannerIcon);
  document.getElementById('vb-title').textContent = senderVerdictLabel(data);
  document.getElementById('vb-email').textContent = data.email;
  document.getElementById('vb-scope').textContent = t('sender.scope');
  document.getElementById('vb-prob-label').textContent = t('sender.riskScoreLabel');
  if (!languageOnly) {
    animateNumber(document.getElementById('vb-prob'), data.risk_score, v => `${Math.round(v)}/100`);
    document.getElementById('vb-prob').style.color  = probColor;
    setRing('vb-ring', data.risk_score, probColor);
  }

  // Remove previous suspect note if any
  const oldNote = banner.querySelector('.suspect-note');
  if (oldNote) oldNote.remove();
  if (isSuspect) {
    const note = document.createElement('div');
    note.className = 'suspect-note';
    note.textContent = t('sender.suspectNote');
    banner.querySelector('.vb-left').appendChild(note);
  }

  // Heuristic scale, not a probability or a complementary safety score.
  const riskScore = data.risk_score;
  if (!languageOnly) animateBar('phish-bar', riskScore);
  document.getElementById('phish-pct').textContent = riskScore + '/100';

  // Risk summary pills
  const riskSummary = document.getElementById('risk-summary');
  const h = data.high_risk_count;
  const m = data.med_risk_count;
  const suspectPill = isSuspect || isHighRisk
    ? `<span class="pill pill-suspect">${icon('search')} ${escapeHtml(t('sender.pill.suspected'))}</span>`
    : '';
  riskSummary.innerHTML = `
    <div class="risk-pills">
      ${suspectPill}
      <span class="pill pill-high">${escapeHtml(t('sender.pill.high', { count: h }))}</span>
      <span class="pill pill-med">${escapeHtml(t('sender.pill.medium', { count: m }))}</span>
    </div>
  `;

  // Risk indicators
  const riskList = document.getElementById('risk-indicators-list');
  const countEl = document.getElementById('risk-count');
  const riskIndicators = (data.risk_indicators || []).filter(r => r.level !== 'info');
  if (riskIndicators.length > 0) {
    countEl.textContent = `(${riskIndicators.length})`;
    riskList.innerHTML = riskIndicators.map(r => `
      <div class="risk-item risk-${escapeHtml(r.level)}">
        <span class="risk-dot" aria-hidden="true"></span>
        ${levelLabelHtml(r.level)}
        <span class="risk-msg">${escapeHtml(serverText(r))}</span>
      </div>
    `).join('');
  } else {
    countEl.textContent = '';
    riskList.innerHTML = `<div class="sender-no-risk">${escapeHtml(t('sender.noIndicators'))}</div>`;
  }
  renderScoreBreakdown(data, { keepOpen: languageOnly });

  // Feature breakdown
  const fbList = document.getElementById('feature-breakdown-list');
  fbList.innerHTML = data.feature_breakdown.map(f => {
    const valClass = f.value === -1 ? 'fv-phish' : f.value === 1 ? 'fv-legit' : 'fv-sus';
    const valLabel = f.value === -1 ? '−1' : f.value === 1 ? '+1' : '0';
    const valTitle = t(f.value === -1 ? 'sender.feature.flagged' : f.value === 1 ? 'sender.feature.clear' : 'sender.feature.mid');
    return `
      <div class="fb-row">
        <div class="fb-top">
          <span class="fb-label">${escapeHtml(featureText(f, 'label'))}</span>
          <span class="fb-val ${valClass}" title="${escapeHtml(valTitle)}">${valLabel}</span>
        </div>
        <div class="fb-desc">${escapeHtml(featureText(f, 'description'))}</div>
      </div>
    `;
  }).join('');

  area.classList.remove('hidden');
  if (languageOnly) return;
  area.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  // Move focus to the verdict so screen readers announce the result.
  document.getElementById('vb-title').focus({ preventScroll: true });
}

// ── Score breakdown ──────────────────────────────────────────────────────────
// Mirrors `_analyze_sender_address` in app.py. The breakdown is shown only when
// these weights reproduce the server's score, so drift hides it instead of lying.
const SENDER_WEIGHTS = { high: 28, medium: 10, low: 3 };

function senderScoreBreakdown(data) {
  const rows = (data.risk_indicators || [])
    .filter(r => SENDER_WEIGHTS[r.level])
    .map(r => ({ level: r.level, msg: serverText(r), points: SENDER_WEIGHTS[r.level] }))
    .sort((a, b) => b.points - a.points);
  const raw = rows.reduce((sum, row) => sum + row.points, 0);
  const total = Math.min(100, raw);
  return { rows, raw, total, consistent: total === data.risk_score };
}

function renderScoreBreakdown(data, { keepOpen = false } = {}) {
  const box = document.getElementById('score-breakdown');
  const { rows, raw, consistent } = senderScoreBreakdown(data);
  if (!keepOpen) box.open = false;
  box.hidden = !consistent || rows.length === 0;
  if (box.hidden) return;
  document.getElementById('score-breakdown-list').innerHTML = rows.map(row => `
    <li class="sb-row sb-${escapeHtml(row.level)}">
      <span class="sb-points">+${row.points}</span>
      <span class="sb-msg">${escapeHtml(row.msg)}</span>
    </li>
  `).join('');
  const count = level => rows.filter(row => row.level === level).length;
  document.getElementById('score-breakdown-formula').textContent =
    t('sender.breakdown.formula', { high: count('high'), medium: count('medium'), low: count('low'), raw }) +
    t(raw > 100 ? 'sender.breakdown.capped' : 'sender.breakdown.uncapped') + t('sender.breakdown.info');
}
