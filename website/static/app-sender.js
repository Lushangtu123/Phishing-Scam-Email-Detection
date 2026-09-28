/* ──────────────────────────────────────────────────────────────────────────
   app-sender.js – sender address analysis
   Examples, the request, result rendering, sender history and the
   score breakdown.
   ────────────────────────────────────────────────────────────────────────── */

let _senderRequestId = 0;

function invalidateSender() {
  window.PhishGuardFeedback?.clear('sender');
  _senderRequestId++;
  _verificationRequestId++;
  _verifyEmail = null;
  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('loading-area').classList.add('hidden');
  document.getElementById('analyze-btn').disabled = false;
  document.getElementById('analyze-btn-text').textContent = 'Analyze';
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
    setError('email-error', 'Enter a single email address, such as user@example.com. Use Email Content to analyze a message.');
    shakeInput();
    return;
  }

  const btn = document.getElementById('analyze-btn');
  const btnText = document.getElementById('analyze-btn-text');
  btn.disabled = true;
  btnText.textContent = 'Analyzing…';

  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('loading-area').classList.remove('hidden');

  try {
    const data = await postJSON('/api/analyze-email', { email });
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
      btn.disabled = false;
      btnText.textContent = 'Analyze';
      document.getElementById('loading-area').classList.add('hidden');
    }
  }
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
  return 'Provider';
}

function renderSenderHistory(data, prefix = '') {
  const id = name => `${prefix}${name}`;
  const card = document.getElementById(id('sender-history-card'));
  const row = document.getElementById(id('sender-history-row'));
  const iconEl = document.getElementById(id('sender-history-icon'));
  const label = document.getElementById(id('sender-history-label'));
  const detail = document.getElementById(id('sender-history-detail'));
  const status = data.sender_history_status || 'disabled';
  const providerCaveat = data.account_observability === 'provider_account_unverifiable'
    ? `${senderProviderName(data.email)} account age cannot be verified from the address or this service's retained history. `
    : '';

  card.classList.remove('hidden');
  row.className = 'sender-history-row';
  iconEl.innerHTML = icon('clock');

  if (status === 'first_seen') {
    row.className += ' history-first';
    label.textContent = 'First observed by this service';
    detail.textContent = `${providerCaveat}This is retained service history, not an account-creation date.`;
  } else if (status === 'previously_seen') {
    row.className += ' history-seen';
    label.textContent = 'Observed previously by this service';
    detail.textContent = `${providerCaveat}Prior observation does not establish that this sender or message is safe.`;
  } else if (status === 'not_seen') {
    row.className += ' history-first';
    label.textContent = 'No prior observation in this service history';
    detail.textContent = `${providerCaveat}Absence from retained history does not prove that the provider account is new or unsafe.`;
  } else if (status === 'raw_message_required') {
    row.className += ' history-unavailable';
    label.textContent = 'Available with full-message analysis';
    detail.textContent = `${providerCaveat}Address-only analysis does not query retained sender history. Upload a complete email to add and compare an observation.`;
  } else if (status === 'unavailable') {
    row.className += ' history-unavailable';
    label.textContent = 'Observation history unavailable';
    detail.textContent = 'The history service could not be checked. No sender-history conclusion was used in the risk score.';
  } else {
    row.className += ' history-unavailable';
    label.textContent = 'Observation history not enabled';
    detail.textContent = 'This service is not recording privacy-preserving sender observations. No account-age claim is available.';
  }
}

// ── Render Result ─────────────────────────────────────────────────────────────
function renderResult(data) {
  lastResults.sender = data;
  const isHighRisk = data.verdict === 'high' || data.verdict === 'critical';
  const isSuspect = data.verdict === 'medium';
  const area = document.getElementById('result-area');

  // Reset verify card so it shows "Run Verification" for the new email
  _verifyEmail = data.email;
  resetVerifyCard();

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
  const aliasNote = data.address_alias_type === 'subaddress'
    ? ' This address uses a plus tag, which is an alias and not a phishing signal.'
    : '';

  if (disposableStatus === 'known_disposable_provider') {
    dispRow.className  = 'disp-check-row disp-is-disposable';
    dispCard.className = 'col-card disposable-check-card is-disposable';
    dispIcon.innerHTML    = icon('trash');
    dispLabel.textContent = 'Known disposable-email provider';
    dispDet.textContent   = `Provider registry match: ${data.matched_provider_domain || data.disposable_service || domain}. The individual mailbox lifetime is not known.${aliasNote}`;

  } else if (disposableStatus === 'privacy_relay') {
    dispRow.className  = 'disp-check-row disp-not-disposable';
    dispCard.className = 'col-card disposable-check-card not-disposable';
    dispIcon.innerHTML    = icon('shield');
    dispLabel.textContent = 'Privacy relay / masked address';
    dispDet.textContent   = `Provider: ${data.matched_provider_domain || domain}. Privacy relays protect a user's primary address and are not phishing evidence by themselves.${aliasNote}`;

  } else if (disposableStatus === 'suspicious_mailbox_pattern') {
    dispRow.className  = 'disp-check-row disp-suspected-disposable';
    dispCard.className = 'col-card disposable-check-card suspected-disposable';
    dispIcon.innerHTML    = icon('alert');
    dispLabel.textContent = 'Mailbox pattern is suspicious; lifetime unknown';
    dispDet.textContent = `The username has several automatically generated characteristics. Account age and disposability cannot be confirmed from the address alone.${aliasNote}`;
    const badge = document.createElement('div');
    badge.className = 'disp-confidence-badge';
    badge.textContent = 'Heuristic Detection · Not Confirmed';
    dispCard.appendChild(badge);

  } else if (disposableStatus === 'suspicious_domain_pattern') {
    dispRow.className  = 'disp-check-row disp-suspected-disposable';
    dispCard.className = 'col-card disposable-check-card suspected-disposable';
    dispIcon.innerHTML    = icon('alert');
    dispLabel.textContent = 'Disposable-style domain name; not confirmed';
    dispDet.textContent = `Domain "${domain}" resembles a temporary-email service name but is not in the confirmed provider registry.${aliasNote}`;

  } else {
    dispRow.className  = 'disp-check-row disp-not-disposable';
    dispCard.className = 'col-card disposable-check-card not-disposable';
    dispIcon.innerHTML    = icon('mail');
    dispLabel.textContent = 'No known disposable-provider match';
    dispDet.textContent   = `Domain "${domain}" did not match the local provider registry. Account age and intent cannot be determined from the address alone.${aliasNote}`;
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
  document.getElementById('vb-title').textContent = data.label;
  document.getElementById('vb-email').textContent = data.email;
  document.getElementById('vb-scope').textContent =
    'This address-only score does not establish that a message is safe. Check the full email, links, and authentication headers. Mailbox service type is reported separately below.';
  document.getElementById('vb-prob-label').textContent = 'Sender Risk Score';
  animateNumber(document.getElementById('vb-prob'), data.risk_score, v => `${Math.round(v)}/100`);
  document.getElementById('vb-prob').style.color  = probColor;
  setRing('vb-ring', data.risk_score, probColor);

  // Remove previous suspect note if any
  const oldNote = banner.querySelector('.suspect-note');
  if (oldNote) oldNote.remove();
  if (isSuspect) {
    const note = document.createElement('div');
    note.className = 'suspect-note';
    note.textContent =
      'Sender and domain heuristics found suspicious structural patterns. ' +
      'This score is not a trained-model probability; verify the full message headers.';
    banner.querySelector('.vb-left').appendChild(note);
  }

  // Heuristic scale, not a probability or a complementary safety score.
  const riskScore = data.risk_score;
  animateBar('phish-bar', riskScore);
  document.getElementById('phish-pct').textContent = riskScore + '/100';

  // Risk summary pills
  const riskSummary = document.getElementById('risk-summary');
  const h = data.high_risk_count;
  const m = data.med_risk_count;
  const suspectPill = isSuspect || isHighRisk
    ? `<span class="pill pill-suspect">${icon('search')} Suspected Phishing</span>`
    : '';
  riskSummary.innerHTML = `
    <div class="risk-pills">
      ${suspectPill}
      <span class="pill pill-high">${escapeHtml(h)} high-risk</span>
      <span class="pill pill-med">${escapeHtml(m)} medium-risk</span>
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
        <span class="risk-dot"></span>
        <span class="risk-msg">${escapeHtml(r.msg)}</span>
      </div>
    `).join('');
  } else {
    countEl.textContent = '';
    riskList.innerHTML = '<div class="sender-no-risk">No sender risk indicators detected. Message safety is not established.</div>';
  }
  renderScoreBreakdown(data);

  // Feature breakdown
  const fbList = document.getElementById('feature-breakdown-list');
  fbList.innerHTML = data.feature_breakdown.map(f => {
    const valClass = f.value === -1 ? 'fv-phish' : f.value === 1 ? 'fv-legit' : 'fv-sus';
    const valLabel = f.value === -1 ? '−1' : f.value === 1 ? '+1' : '0';
    const valTitle = f.value === -1 ? 'Flagged feature; not a verdict' : f.value === 1 ? 'No flag for this feature' : 'Intermediate feature value';
    return `
      <div class="fb-row">
        <div class="fb-top">
          <span class="fb-label">${escapeHtml(f.label)}</span>
          <span class="fb-val ${valClass}" title="${valTitle}">${valLabel}</span>
        </div>
        <div class="fb-desc">${escapeHtml(f.email_desc)}</div>
      </div>
    `;
  }).join('');

  area.classList.remove('hidden');
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
    .map(r => ({ level: r.level, msg: r.msg, points: SENDER_WEIGHTS[r.level] }))
    .sort((a, b) => b.points - a.points);
  const raw = rows.reduce((sum, row) => sum + row.points, 0);
  const total = Math.min(100, raw);
  return { rows, raw, total, consistent: total === data.risk_score };
}

function renderScoreBreakdown(data) {
  const box = document.getElementById('score-breakdown');
  const { rows, raw, consistent } = senderScoreBreakdown(data);
  box.open = false;
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
    `${count('high')} high × 28 + ${count('medium')} medium × 10 + ${count('low')} low × 3 = ${raw}` +
    (raw > 100 ? ', capped at 100.' : '.') + ' Informational notes add nothing.';
}
