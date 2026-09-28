/* ──────────────────────────────────────────────────────────────────────────
   app-content-render.js – email content result rendering
   Risk banner, ML classifier card, category cards and indicators.
   ────────────────────────────────────────────────────────────────────────── */

const CATEGORY_ICONS = {
  urgency: 'clock', threats: 'bell', financial: 'dollar', credential: 'key',
  impersonation: 'mask', deception: 'eyeOff', attachments: 'paperclip',
  tech_scam: 'monitor', job_scam: 'briefcase', social_engineering: 'brain',
};

// Score colours are theme tokens so the light theme's darker shades apply.
const RISK_CONFIG = {
  unknown:  { icon: 'alert', color: 'medium', scoreColor: 'var(--yellow)' },
  safe:     { icon: 'check', color: 'safe',     scoreColor: 'var(--accent2)' },
  low:      { icon: 'info',  color: 'low',      scoreColor: 'var(--info)' },
  medium:   { icon: 'alert', color: 'medium',   scoreColor: 'var(--yellow)' },
  high:     { icon: 'bell',  color: 'high',     scoreColor: 'var(--orange)' },
  critical: { icon: 'skull', color: 'critical', scoreColor: 'var(--red)' },
};

// The API names the selected classifier in ml_metrics.model (see model selection
// in content_model.py); every candidate there shares the word + character TF-IDF
// vectorizer. Anything unrecognised falls back to a generic name.
const CONTENT_MODEL_NAMES = new Map([
  ['LogisticRegression', 'TF-IDF + Logistic Regression'],
  ['CalibratedLinearSVC', 'TF-IDF + Linear SVM (calibrated)'],
  ['ComplementNB', 'TF-IDF + Complement Naive Bayes'],
]);

function contentModelName(data) {
  return CONTENT_MODEL_NAMES.get(data && data.ml_metrics && data.ml_metrics.model) || 'Text model';
}

// Which input produced a content result, from the server's input_mode.
function contentMode(data) {
  const inputMode = data && data.input_mode;
  return inputMode === 'raw-email' ? 'eml' : inputMode === 'image-evidence' ? 'image' : 'content';
}

function renderContentResult(data) {
  lastResults.content = data;
  const cfg = RISK_CONFIG[data.risk_level] || RISK_CONFIG.medium;
  const imageOnly = data.input_mode === 'image-evidence';

  // Banner
  const banner = document.getElementById('content-risk-banner');
  banner.className = 'content-risk-banner crb-' + data.risk_level;
  document.getElementById('crb-icon').innerHTML    = icon(cfg.icon);
  document.getElementById('crb-title').textContent = data.risk_label;
  // Sub-line: now combines heuristic categories with ML verdict
  const subParts = [];
  if (data.analysis_complete === false) {
    const attachmentCoverage = (data.message_structure?.attachments || []).some(
      attachment => attachment.inspection_status === 'metadata_only') ||
      (data.analysis_warnings || []).some(warning => warning.includes('Attachment content was not inspected;'));
    const inlineImageCoverage = data.inline_image_coverage?.inspection_status === 'metadata_only' ||
      (data.analysis_warnings || []).some(warning => warning.includes('Embedded image content was not inspected;'));
    const remoteImageCoverage = data.remote_image_coverage?.inspection_status === 'metadata_only' ||
      (data.analysis_warnings || []).some(warning => warning.includes('Remote image content was not inspected;'));
    const unresolvedImageCoverage = data.unresolved_image_coverage?.inspection_status === 'metadata_only' ||
      (data.analysis_warnings || []).some(warning => warning.includes('Unresolved image references were not inspected;'));
    const parseIssues = (data.message_structure?.parse_warnings || []).length > 0;
    subParts.push(imageOnly
      ? 'Image risk coverage is limited. Review the recognition status and extracted-text assessment in Image & QR evidence.'
      : 'Analysis incomplete. Review the warnings below.');
    if (attachmentCoverage) {
      subParts.push('Attachment contents were not inspected; only filenames and MIME types were checked.');
    }
    if (inlineImageCoverage) subParts.push('Embedded image content was not inspected.');
    if (remoteImageCoverage) subParts.push('Remote image content was not inspected.');
    if (unresolvedImageCoverage) subParts.push('Unresolved image references were not inspected.');
    if (parseIssues) subParts.push('Some message content could not be reliably parsed.');
    if (!imageOnly && ['insufficient_context', 'insufficient_feature_coverage', 'unverified_rendering'].includes(data.ml_status)) {
      subParts.push('The text model could not score this message.');
    }
  }
  if (data.ml_label != null) {
    subParts.push(`ML risk score: ${data.ml_phishing_probability}% — ${data.ml_label}`);
  }
  if (data.fusion_basis === 'model_only') {
    subParts.push('Model-only risk signal; no independent rule, sender, or link evidence was found.');
  } else if (data.fusion_basis === 'model_led') {
    subParts.push('Model-led risk signal; no strong independent rule, sender, or link evidence was found.');
  }
  const categoryCount = data.category_results.length;
  const technicalCount = (data.extra_indicators || []).filter(ind =>
    ['low', 'medium', 'high', 'critical'].includes(ind.level)).length;
  if (categoryCount) subParts.push(`${categoryCount} suspicious ${categoryCount === 1 ? 'category' : 'categories'} detected.`);
  if (technicalCount) subParts.push(`${technicalCount} technical risk ${technicalCount === 1 ? 'indicator' : 'indicators'} detected.`);
  if (!categoryCount && !technicalCount && data.analysis_complete !== false &&
      !['model_only', 'model_led'].includes(data.fusion_basis)) {
    subParts.push(data.risk_level === 'safe'
      ? 'No indicators detected by the available checks. This does not prove the message is safe.'
      : 'Risk detected by the combined analysis. Review the evidence below.');
  }
  document.getElementById('crb-sub').textContent = subParts.join(' • ');
  const scoreEl = document.getElementById('crb-score');
  // Prefer the blended ML+heuristic score when available; fall back to raw heuristic total.
  if (data.risk_level === 'unknown') {
    animateNumber(scoreEl, 0, () => '—');
    setRing('crb-ring', 0, cfg.scoreColor);
  } else if (data.combined_phishing_score != null) {
    animateNumber(scoreEl, data.combined_phishing_score, v => `${Math.round(v)}%`);
    setRing('crb-ring', data.combined_phishing_score, cfg.scoreColor);
  } else {
    animateNumber(scoreEl, data.total_score, v => `${Math.round(v)}`);
    // Heuristic totals are open-ended; scale against the practical ceiling of 30.
    setRing('crb-ring', Math.min(100, (data.total_score / 30) * 100), cfg.scoreColor);
  }
  scoreEl.style.color = cfg.scoreColor;

  const contentHistoryCard = document.getElementById('content-sender-history-card');
  if (data.sender_analysis) {
    renderSenderHistory(data.sender_analysis, 'content-');
  } else {
    contentHistoryCard.classList.add('hidden');
  }

  // ── ML Classifier Card ───────────────────────────────────────────────────
  const mlCard = document.getElementById('content-ml-card');
  const mlProbabilityBars = document.getElementById('content-ml-prob-bars');
  document.getElementById('content-ml-title').textContent = contentModelName(data);
  if (imageOnly) {
    // The top-level model result describes the original email body, which is
    // empty for an image upload. Each image has its own extracted-text result.
    mlCard.style.display = 'none';
  } else if (['insufficient_context', 'insufficient_feature_coverage', 'unverified_rendering'].includes(data.ml_status)) {
    mlCard.style.display = '';
    mlProbabilityBars.style.display = 'none';
    document.getElementById('content-phish-bar').style.width = '0%';
    document.getElementById('content-phish-pct').textContent = '—';
    document.getElementById('content-legit-bar').style.width = '0%';
    document.getElementById('content-legit-pct').textContent = '—';
    document.getElementById('content-ml-sub').textContent = data.ml_status === 'insufficient_context'
      ? 'The message contains too little text, so ML classification was not applied.'
      : data.ml_status === 'unverified_rendering'
        ? 'CSS visibility or image fallback text could not be verified, so ML classification was not applied.'
        : 'Text-model coverage was insufficient, so ML classification was not applied.';
    document.getElementById('content-ml-metrics').innerHTML = '';
    document.getElementById('content-ml-contribs').innerHTML = data.ml_status === 'unverified_rendering'
      ? '<div class="ml-contribs-title">Uncertain HTML text was withheld; independent destinations, sender, and message-structure checks still ran.</div>'
      : '<div class="ml-contribs-title">Rule, sender, link, and message-structure checks still ran.</div>';
  } else if (data.ml_label != null) {
    mlCard.style.display = '';
    mlProbabilityBars.style.display = '';

    const phishPct = data.ml_phishing_probability;
    const legitPct = data.ml_legitimate_probability;

    document.getElementById('content-phish-bar').style.width = phishPct + '%';
    document.getElementById('content-phish-pct').textContent = phishPct + '%';
    document.getElementById('content-legit-bar').style.width = legitPct + '%';
    document.getElementById('content-legit-pct').textContent = legitPct + '%';

    const verdict = data.ml_prediction === 1 ? 'Likely phishing' : 'Likely legitimate';
    document.getElementById('content-ml-sub').textContent =
      `${verdict} — model risk score ${phishPct.toFixed(1)}%`;

    // Hold-out evaluation metrics for the content text classifier
    const m = data.ml_metrics || {};
    document.getElementById('content-ml-metrics').innerHTML = m.Accuracy != null ? `
      <div class="ml-metric"><span class="ml-metric-k">Phishing recall</span><span class="ml-metric-v">${(m.Phishing_Recall*100).toFixed(1)}%</span></div>
      <div class="ml-metric"><span class="ml-metric-k">False-negative rate</span><span class="ml-metric-v">${(m.False_Negative_Rate*100).toFixed(1)}%</span></div>
      <div class="ml-metric"><span class="ml-metric-k">PR AUC</span><span class="ml-metric-v">${m.PR_AUC.toFixed(4)}</span></div>
      <div class="ml-metric"><span class="ml-metric-k">Threshold</span><span class="ml-metric-v">${m.decision_threshold.toFixed(3)}</span></div>
    ` : '';

    // Per-email token contributions (what pushed the score toward "phishing")
    const contribs = data.ml_top_contributors || [];
    const contribBox = document.getElementById('content-ml-contribs');
    if (contribs.length > 0) {
      contribBox.innerHTML =
        `<div class="ml-contribs-title">Top tokens driving the ML score</div>` +
        `<div class="ml-contribs-list">` +
        contribs.map(c =>
          `<span class="ml-token" title="weighted contribution: ${escapeHtml(c.contribution)}">${escapeHtml(c.term)}</span>`
        ).join('') +
        `</div>`;
    } else {
      contribBox.innerHTML =
        `<div class="ml-contribs-title">No phishing-indicative tokens found in this email.</div>`;
    }
  } else {
    mlCard.style.display = 'none';
  }

  // Category cards
  const grid = document.getElementById('content-category-grid');
  grid.style.display = imageOnly ? 'none' : '';
  if (data.category_results.length === 0) {
    grid.innerHTML = `<div class="cat-empty">No suspicious keyword categories matched in this email.</div>`;
  } else {
    grid.innerHTML = data.category_results.map(cat => `
      <div class="cat-card cat-${escapeHtml(cat.level)}">
        <div class="cat-header">
          <span class="cat-icon icon-tile tile-${escapeHtml(cat.level)}">${icon(CATEGORY_ICONS[cat.key] || 'alert')}</span>
          <div class="cat-title-wrap">
            <div class="cat-title">${escapeHtml(cat.label)}</div>
            <div class="cat-count">${escapeHtml(cat.count)} signal${cat.count > 1 ? 's' : ''} matched</div>
          </div>
          <span class="cat-level-badge level-${escapeHtml(cat.level)}">${escapeHtml(cat.level)}</span>
        </div>
        <div class="cat-desc">${escapeHtml(cat.description)}</div>
        <div class="cat-keywords">
          ${cat.matched.map(kw => `<span class="kw-pill">${escapeHtml(kw)}</span>`).join('')}
        </div>
      </div>
    `).join('');
  }

  // Extra technical indicators
  const extraCard = document.getElementById('content-extra-card');
  const extraList = document.getElementById('content-extra-list');
  if (data.extra_indicators.length > 0) {
    extraCard.style.display = '';
    extraList.innerHTML = data.extra_indicators.map(ind => `
      <div class="risk-item risk-${escapeHtml(ind.level)}">
        <span class="risk-dot"></span>
        <span class="risk-msg">${escapeHtml(ind.msg)}</span>
      </div>
    `).join('');
  } else {
    extraCard.style.display = 'none';
  }

  // Safety signals
  const safetyCard = document.getElementById('content-safety-card');
  const safetyList = document.getElementById('content-safety-list');
  if (data.safety_signals.length > 0) {
    safetyCard.style.display = '';
    safetyList.innerHTML = data.safety_signals.map(s => `
      <div class="safety-item">
        <span class="safety-dot">${icon('check')}</span>
        <span class="safety-msg">${escapeHtml(s)}</span>
      </div>
    `).join('');
  } else {
    safetyCard.style.display = 'none';
  }

  const area = document.getElementById('content-result-area');
  area.classList.remove('hidden');
  area.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  document.getElementById('crb-title').focus({ preventScroll: true });
}
