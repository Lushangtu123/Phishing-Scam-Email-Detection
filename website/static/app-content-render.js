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
// vectorizer. Display names are `content.ml.model.<id>` in the dictionary;
// anything unrecognised falls back to a generic name.
const CONTENT_MODEL_IDS = new Set(['LogisticRegression', 'CalibratedLinearSVC', 'ComplementNB']);

function contentModelName(data) {
  const id = data && data.ml_metrics && data.ml_metrics.model;
  return t(CONTENT_MODEL_IDS.has(id) ? `content.ml.model.${id}` : 'content.ml.model.generic');
}

// The server's English risk_label is shown as-is in English. Other languages
// use the exact translation of a known label, else a label for the risk_level
// code, else the server's text (PhishGuardI18n.riskLabel, shared with cases.js).
function contentRiskLabel(label, level) {
  return i18n() ? i18n().riskLabel(label, level) : label;
}

function mlLabelText(label) {
  const phishing = knownText('content.mlLabel.phishing', label);
  return phishing !== label ? phishing : knownText('content.mlLabel.legit', label);
}

// Which input produced a content result, from the server's input_mode.
function contentMode(data) {
  const inputMode = data && data.input_mode;
  return inputMode === 'raw-email' ? 'eml' : inputMode === 'image-evidence' ? 'image' : 'content';
}

// `languageOnly` re-renders the same result after a language switch without
// replaying the score animation, scrolling or moving focus.
// How the last analysis was requested (not part of the API result or reports):
// mode 'content' | 'image' | 'eml', the mailbox chosen, and the service whose own
// check tops an uploaded .eml.
let contentInputContext = { mode: 'content', mailbox: '', detected: '' };
const MAILBOX_SERVICE_NAMES = { gmail: 'Gmail', outlook: 'Outlook.com' };

// A more reliable result is often one step away: the original .eml instead of text or
// a screenshot, or the mailbox choice for an .eml whose receiving service is known.
// Shown only for alerting or undetermined results, where it matters most.
// An alert raised mainly by the text model (fusion_basis model_only / model_led) says
// so: the model misjudges many genuine account and notification emails, and on an
// .eml with nothing more to choose the tip still explains that. Verdicts are unchanged.
function renderAccuracyTip(data) {
  const tip = document.getElementById('content-accuracy-tip');
  const { mode, mailbox, detected } = contentInputContext;
  const unsettled = ['medium', 'high', 'critical', 'unknown'].includes(data.risk_level);
  const modelDriven = ['medium', 'high', 'critical'].includes(data.risk_level) &&
    ['model_only', 'model_led'].includes(data.fusion_basis);
  const upload = unsettled && (mode === 'content' || mode === 'image');
  const choose = unsettled && mode === 'eml' && !mailbox && !!MAILBOX_SERVICE_NAMES[detected];
  tip.hidden = !(upload || choose || modelDriven);
  if (tip.hidden) return;
  const service = MAILBOX_SERVICE_NAMES[detected] || '';
  let text;
  if (upload) text = t(modelDriven ? 'content.tip.uploadModel' : 'content.tip.upload');
  else if (choose) text = t(modelDriven ? 'content.tip.chooseModel' : 'content.tip.choose', { service });
  else text = t('content.tip.modelEml');
  document.getElementById('content-accuracy-tip-text').textContent = text;
  const rerun = document.getElementById('content-accuracy-rerun');
  rerun.hidden = !choose;
  rerun.textContent = choose ? t('content.tip.rerun', { service }) : '';
  document.getElementById('content-accuracy-guide').hidden = !upload;
}

// What kind of mail this looks like, beside the verdict (never a change to it). Phishing
// lists the scam tactics found; advertising says plainly when scam signs remain, because
// scams dress up as deals too.
const MAIL_TACTICS = ['credential', 'callback', 'subsidy', 'payment', 'remote_access', 'impersonation',
  'deceptive_link', 'spoofed_sender', 'dangerous_attachment'];
function renderMailType(data) {
  const el = document.getElementById('crb-type');
  const type = data.mail_type?.type;
  el.hidden = !['phishing', 'advertising'].includes(type);
  if (el.hidden) { el.textContent = ''; return; }
  el.className = 'crb-type crb-type-' + type;
  if (type === 'phishing') {
    const tactics = (data.mail_type.tactics || []).filter(tactic => MAIL_TACTICS.includes(tactic))
      .map(tactic => t('content.tactic.' + tactic));
    el.textContent = t('content.type.phishing', { tactics: tactics.join(t('content.type.separator')) });
  } else {
    const alerting = ['medium', 'high', 'critical'].includes(data.risk_level);
    el.textContent = t(alerting ? 'content.type.adSuspicious' : 'content.type.ad');
  }
}

function renderContentResult(data, { languageOnly = false } = {}) {
  lastResults.content = data;
  const cfg = RISK_CONFIG[data.risk_level] || RISK_CONFIG.medium;
  const imageOnly = data.input_mode === 'image-evidence';

  // Banner
  const banner = document.getElementById('content-risk-banner');
  banner.className = 'content-risk-banner crb-' + data.risk_level;
  document.getElementById('crb-icon').innerHTML    = icon(cfg.icon);
  document.getElementById('crb-title').textContent = contentRiskLabel(data.risk_label, data.risk_level);
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
    subParts.push(t(imageOnly ? 'content.sub.imageLimited' : 'content.sub.incomplete'));
    if (attachmentCoverage) subParts.push(t('content.sub.attachments'));
    if (inlineImageCoverage) subParts.push(t('content.sub.inlineImages'));
    if (remoteImageCoverage) subParts.push(t('content.sub.remoteImages'));
    if (unresolvedImageCoverage) subParts.push(t('content.sub.unresolvedImages'));
    if (parseIssues) subParts.push(t('content.sub.parse'));
    if (!imageOnly && ['insufficient_context', 'insufficient_feature_coverage', 'unverified_rendering'].includes(data.ml_status)) {
      subParts.push(t('content.sub.modelUnscored'));
    }
  }
  if (data.ml_label != null) {
    subParts.push(t('content.sub.ml', { score: data.ml_phishing_probability, label: mlLabelText(data.ml_label) }));
  }
  if (data.fusion_basis === 'model_only') {
    subParts.push(t('content.sub.modelOnly'));
  } else if (data.fusion_basis === 'model_led') {
    subParts.push(t('content.sub.modelLed'));
  }
  const categoryCount = data.category_results.length;
  const technicalCount = (data.extra_indicators || []).filter(ind =>
    ['low', 'medium', 'high', 'critical'].includes(ind.level)).length;
  if (categoryCount) subParts.push(tPlural('content.sub.categories', categoryCount));
  if (technicalCount) subParts.push(tPlural('content.sub.technical', technicalCount));
  if (!categoryCount && !technicalCount && data.analysis_complete !== false &&
      !['model_only', 'model_led'].includes(data.fusion_basis)) {
    subParts.push(t(data.risk_level === 'safe' ? 'content.sub.safe' : 'content.sub.risk'));
  }
  document.getElementById('crb-sub').textContent = subParts.join(' • ');
  renderMailType(data);
  const scoreEl = document.getElementById('crb-score');
  // Prefer the blended ML+heuristic score when available; fall back to raw heuristic total.
  if (languageOnly) {
    // Scores are language-neutral; keep the rendered value and ring.
  } else if (data.risk_level === 'unknown') {
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
    document.getElementById('content-ml-sub').textContent = t(data.ml_status === 'insufficient_context'
      ? 'content.ml.abstain.context'
      : data.ml_status === 'unverified_rendering'
        ? 'content.ml.abstain.rendering'
        : 'content.ml.abstain.coverage');
    document.getElementById('content-ml-metrics').innerHTML = '';
    document.getElementById('content-ml-contribs').innerHTML = `<div class="ml-contribs-title">${escapeHtml(t(
      data.ml_status === 'unverified_rendering' ? 'content.ml.contribs.rendering' : 'content.ml.contribs.checks'))}</div>`;
  } else if (data.ml_label != null) {
    mlCard.style.display = '';
    mlProbabilityBars.style.display = '';

    const phishPct = data.ml_phishing_probability;
    const legitPct = data.ml_legitimate_probability;

    document.getElementById('content-phish-bar').style.width = phishPct + '%';
    document.getElementById('content-phish-pct').textContent = phishPct + '%';
    document.getElementById('content-legit-bar').style.width = legitPct + '%';
    document.getElementById('content-legit-pct').textContent = legitPct + '%';

    const verdict = t(data.ml_prediction === 1 ? 'content.ml.verdict.phishing' : 'content.ml.verdict.legit');
    document.getElementById('content-ml-sub').textContent =
      t('content.ml.sub', { verdict, score: phishPct.toFixed(1) });

    // Hold-out evaluation metrics for the content text classifier
    const m = data.ml_metrics || {};
    const metricLabel = key => escapeHtml(t(`content.ml.metric.${key}`));
    document.getElementById('content-ml-metrics').innerHTML = m.Accuracy != null ? `
      <div class="ml-metric"><span class="ml-metric-k">${metricLabel('recall')}</span><span class="ml-metric-v">${(m.Phishing_Recall*100).toFixed(1)}%</span></div>
      <div class="ml-metric"><span class="ml-metric-k">${metricLabel('fnr')}</span><span class="ml-metric-v">${(m.False_Negative_Rate*100).toFixed(1)}%</span></div>
      <div class="ml-metric"><span class="ml-metric-k">${metricLabel('prauc')}</span><span class="ml-metric-v">${m.PR_AUC.toFixed(4)}</span></div>
      <div class="ml-metric"><span class="ml-metric-k">${metricLabel('threshold')}</span><span class="ml-metric-v">${m.decision_threshold.toFixed(3)}</span></div>
    ` : '';

    // Per-email token contributions (what pushed the score toward "phishing")
    const contribs = data.ml_top_contributors || [];
    const contribBox = document.getElementById('content-ml-contribs');
    if (contribs.length > 0) {
      contribBox.innerHTML =
        `<div class="ml-contribs-title">${escapeHtml(t('content.ml.contribs.title'))}</div>` +
        `<div class="ml-contribs-list">` +
        contribs.map(c =>
          `<span class="ml-token" title="${escapeHtml(t('content.ml.contribs.tokenTitle', { value: c.contribution }))}">${escapeHtml(c.term)}</span>`
        ).join('') +
        `</div>`;
    } else {
      contribBox.innerHTML =
        `<div class="ml-contribs-title">${escapeHtml(t('content.ml.contribs.none'))}</div>`;
    }
  } else {
    mlCard.style.display = 'none';
  }

  // Category cards
  const grid = document.getElementById('content-category-grid');
  grid.style.display = imageOnly ? 'none' : '';
  if (data.category_results.length === 0) {
    grid.innerHTML = `<div class="cat-empty">${escapeHtml(t('content.cat.empty'))}</div>`;
  } else {
    grid.innerHTML = data.category_results.map(cat => `
      <div class="cat-card cat-${escapeHtml(cat.level)}">
        <div class="cat-header">
          <span class="cat-icon icon-tile tile-${escapeHtml(cat.level)}">${icon(CATEGORY_ICONS[cat.key] || 'alert')}</span>
          <div class="cat-title-wrap">
            <div class="cat-title">${escapeHtml(categoryText(cat, 'label'))}</div>
            <div class="cat-count">${escapeHtml(t(cat.count > 1 ? 'content.cat.count.other' : 'content.cat.count.one', { count: cat.count }))}</div>
          </div>
          <span class="cat-level-badge level-${escapeHtml(cat.level)}">${escapeHtml(levelName(cat.level))}</span>
        </div>
        <div class="cat-desc">${escapeHtml(categoryText(cat, 'description'))}</div>
        <div class="cat-keywords">
          ${cat.matched.map(kw => `<span class="kw-pill">${escapeHtml(kw)}</span>`).join('')}
        </div>
      </div>
    `).join('');
  }

  // Official channels to verify through, for organizations the message names.
  // Guidance only; it never changes the verdict.
  const officialCard = document.getElementById('content-official-card');
  const channels = data.official_channels || [];
  officialCard.hidden = channels.length === 0;
  document.getElementById('content-official-list').innerHTML = channels.map(channel => `
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

  // Extra technical indicators
  const extraCard = document.getElementById('content-extra-card');
  const extraList = document.getElementById('content-extra-list');
  if (data.extra_indicators.length > 0) {
    extraCard.hidden = false;
    extraList.innerHTML = data.extra_indicators.map(ind => `
      <div class="risk-item risk-${escapeHtml(ind.level)}">
        <span class="risk-dot" aria-hidden="true"></span>
        ${levelLabelHtml(ind.level)}
        <span class="risk-msg">${escapeHtml(serverText(ind))}</span>
      </div>
    `).join('');
  } else {
    extraCard.hidden = true;
  }

  // Safety signals
  const safetyCard = document.getElementById('content-safety-card');
  const safetyList = document.getElementById('content-safety-list');
  if (data.safety_signals.length > 0) {
    safetyCard.hidden = false;
    safetyList.innerHTML = serverStrings(data.safety_signals, data.safety_signal_details).map(s => `
      <div class="safety-item">
        <span class="safety-dot">${icon('check')}</span>
        <span class="safety-msg">${escapeHtml(s)}</span>
      </div>
    `).join('');
  } else {
    safetyCard.hidden = true;
  }

  // What to do if the reader already acted on an alerting message.
  document.getElementById('content-remediation').hidden = !['medium', 'high', 'critical'].includes(data.risk_level);
  renderAccuracyTip(data);

  const area = document.getElementById('content-result-area');
  area.classList.remove('hidden');
  if (languageOnly) return;
  area.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  document.getElementById('crb-title').focus({ preventScroll: true });
}

// Category label and description, keyed by the stable category key.
function categoryText(cat, field) {
  return knownText(`category.${String(cat.key)}.${field}`, cat[field]);
}
