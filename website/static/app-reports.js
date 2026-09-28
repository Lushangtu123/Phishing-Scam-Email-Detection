/* ──────────────────────────────────────────────────────────────────────────
   app-reports.js – what happens to a rendered result
   Feedback reporting, copy summary, report downloads and the recent
   checks list kept in this browser.
   ────────────────────────────────────────────────────────────────────────── */

// ── Feedback reporting ───────────────────────────────────────────────────────
function openFeedback(kind) { window.PhishGuardFeedback?.open(kind); }

function feedbackAnalysis(data, sender = false) {
  const codes = sender
    ? (data.feature_breakdown || []).filter(item => item.value === -1).map(item => item.name)
    : [...(data.category_results || []).map(item => item.key),
       ...(data.extra_indicators || []).map(item => item.code || item.key)];
  return {
    risk_level: sender ? data.verdict : data.risk_level,
    risk_score: sender ? data.risk_score : (data.combined_phishing_score ?? null),
    risk_label: sender ? data.label : data.risk_label,
    analysis_complete: sender ? null : data.analysis_complete ?? null,
    model_id: sender ? null : (data.content_model_id || null),
    evidence_codes: [...new Set(codes.filter(code => typeof code === 'string' && /^[a-z0-9_-]{1,48}$/.test(code)))].slice(0, 20),
  };
}
function encodeFeedbackEmail(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}

// ── Copy summary ─────────────────────────────────────────────────────────────
const lastResults = { sender: null, content: null };
const MAILBOX_LABELS = {
  known_disposable_provider: 'Known disposable-email provider',
  privacy_relay: 'Privacy relay / masked address',
  suspicious_mailbox_pattern: 'Suspicious mailbox pattern (not confirmed)',
  suspicious_domain_pattern: 'Disposable-style domain (not confirmed)',
  no_known_match: 'No known disposable-provider match',
};
const SUMMARY_DISCLAIMER = 'Heuristic result from PhishGuard; it does not prove a message is safe or malicious.';

function senderSummaryText(data) {
  const indicators = (data.risk_indicators || []).filter(r => r.level !== 'info');
  return [
    `PhishGuard sender check: ${data.email}`,
    `Verdict: ${data.label} (${data.risk_score}/100)`,
    `Mailbox type: ${MAILBOX_LABELS[data.disposable_status] || 'Unknown'}`,
    indicators.length ? 'Indicators:' : 'Indicators: none detected',
    ...indicators.map(r => `- [${r.level}] ${r.msg}`),
    '', SUMMARY_DISCLAIMER,
  ].join('\n');
}

function contentScoreText(data) {
  return data.combined_phishing_score != null
    ? `${Math.round(data.combined_phishing_score)}% risk`
    : `heuristic score ${data.total_score}`;
}

function contentSummaryText(data) {
  const score = contentScoreText(data);
  const categories = data.category_results || [];
  const extras = data.extra_indicators || [];
  return [
    'PhishGuard content check',
    `Verdict: ${data.risk_label} (${score})`,
    categories.length ? 'Categories:' : 'Categories: none matched',
    ...categories.map(c => `- ${c.label} (${c.level}, ${c.count} signal${c.count === 1 ? '' : 's'})`),
    ...(extras.length ? ['Technical indicators:', ...extras.map(r => `- [${r.level}] ${r.msg}`)] : []),
    '', SUMMARY_DISCLAIMER,
  ].join('\n');
}

function copyWithSelection(text) {
  if (!document.body || typeof document.execCommand !== 'function') return false;
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.className = 'copy-buffer';
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (error) { ok = false; }
  area.remove();
  return ok;
}

async function copySummary(kind, button) {
  const data = lastResults[kind];
  if (!data) return;
  const text = kind === 'sender' ? senderSummaryText(data) : contentSummaryText(data);
  const label = button && button.querySelector('.copy-label');
  let message = 'Copied', announcement = 'Summary copied to clipboard';
  try {
    await navigator.clipboard.writeText(text);
  } catch (error) {
    // navigator.clipboard is missing on non-secure origins (e.g. a LAN IP over http).
    if (!copyWithSelection(text)) message = announcement = 'Copy failed';
  }
  // The label swap is not reliably announced; the live region is.
  announce(announcement);
  if (!label) return;
  label.textContent = message;
  clearTimeout(button._copyTimer);
  button._copyTimer = setTimeout(() => { label.textContent = 'Copy summary'; }, 1800);
}

// ── Download report ──────────────────────────────────────────────────────────
// Reports are built in the browser from the last rendered result; nothing is
// sent anywhere. Markdown mirrors the copy summary; JSON carries the API response.
const REPORT_TYPES = { md: 'text/markdown;charset=utf-8', json: 'application/json' };

// Result text can come from the analysed message, so neutralise Markdown syntax
// (links, images, HTML, emphasis) and keep each value on one line.
function markdownText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim().replace(/[\\`*_[\]<>|~#]/g, '\\$&');
}

function senderReportMarkdown(data, generatedAt) {
  const indicators = (data.risk_indicators || []).filter(r => r.level !== 'info');
  return [
    '# PhishGuard sender check', '',
    `- **Sender:** ${markdownText(data.email)}`,
    `- **Verdict:** ${markdownText(data.label)} (${markdownText(data.risk_score)}/100)`,
    `- **Mailbox type:** ${MAILBOX_LABELS[data.disposable_status] || 'Unknown'}`,
    `- **Generated:** ${generatedAt.toISOString()}`, '',
    '## Indicators', '',
    ...(indicators.length
      ? indicators.map(r => `- **${markdownText(r.level)}** — ${markdownText(r.msg)}`)
      : ['None detected.']),
    '', '---', '', `_${SUMMARY_DISCLAIMER}_`, '',
  ].join('\n');
}

function contentReportMarkdown(data, generatedAt) {
  const mode = contentMode(data);
  const categories = data.category_results || [];
  const extras = data.extra_indicators || [];
  const warnings = data.analysis_warnings || [];
  const model = mode !== 'image' && data.ml_label != null
    ? [`- **Text model:** ${contentModelName(data)} — ${markdownText(data.ml_phishing_probability)}% model risk score`]
    : [];
  return [
    '# PhishGuard content check', '',
    `- **Input:** ${RECENT_MODES[mode]}`,
    `- **Verdict:** ${markdownText(data.risk_label)} (${markdownText(contentScoreText(data))})`,
    ...model,
    `- **Generated:** ${generatedAt.toISOString()}`, '',
    '## Categories', '',
    ...(categories.length
      ? categories.map(c => `- ${markdownText(c.label)} (${markdownText(c.level)}, ${markdownText(c.count)} signal${c.count === 1 ? '' : 's'})`)
      : ['None matched.']),
    ...(extras.length ? ['', '## Technical indicators', '',
      ...extras.map(r => `- **${markdownText(r.level)}** — ${markdownText(r.msg)}`)] : []),
    ...(warnings.length ? ['', '## Analysis warnings', '', ...warnings.map(w => `- ${markdownText(w)}`)] : []),
    '', '---', '', `_${SUMMARY_DISCLAIMER}_`, '',
  ].join('\n');
}

// Drops every *_base64 field at any depth so a report never embeds file bytes.
function withoutBase64(value) {
  if (Array.isArray(value)) return value.map(withoutBase64);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !/_base64$/i.test(key))
    .map(([key, item]) => [key, withoutBase64(item)]));
}

function reportFilename(mode, format, date) {
  const pad = n => String(n).padStart(2, '0');
  const stamp = `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}` +
    `-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
  return `phishguard-${mode}-${stamp}.${format}`;
}

function buildReport(kind, format, data, generatedAt) {
  const mode = kind === 'sender' ? 'sender' : contentMode(data);
  const text = format === 'json'
    ? JSON.stringify({
      generated_at: generatedAt.toISOString(), tool: 'PhishGuard', mode, result: withoutBase64(data),
    }, null, 2) + '\n'
    : (kind === 'sender' ? senderReportMarkdown : contentReportMarkdown)(data, generatedAt);
  return { text, filename: reportFilename(mode, format, generatedAt), type: REPORT_TYPES[format] };
}

function downloadReport(kind, format) {
  if ((kind !== 'sender' && kind !== 'content') || !Object.hasOwn(REPORT_TYPES, format) || !lastResults[kind]) return;
  const report = buildReport(kind, format, lastResults[kind], new Date());
  let url = null;
  try {
    url = URL.createObjectURL(new Blob([report.text], { type: report.type }));
    const link = document.createElement('a');
    link.href = url;
    link.download = report.filename;
    link.hidden = true;
    document.body.appendChild(link);
    link.click();
    link.remove();
  } catch (_error) {
    if (url) URL.revokeObjectURL(url);
    announce('Download failed');
    return;
  }
  // Revoke once the click has handed the URL to the browser's download manager.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  announce('Report downloaded');
}

// ── Recent checks (this browser only) ────────────────────────────────────────
// The last few verdicts are kept in localStorage so a user can compare checks.
// Each entry holds only the mode, verdict label and level, score and time, plus
// the sender's *domain*: never the local part, a subject, body, file name or
// extracted text. Entries are display-only and cannot be re-run.
const RECENT_KEY = 'phishguard-recent-checks';
const RECENT_LIMIT = 10;
const RECENT_MODES = { sender: 'Sender', content: 'Content', eml: 'Email file', image: 'Image' };
const RECENT_LEVELS = new Set(['safe', 'low', 'medium', 'high', 'critical', 'unknown']);
let _recentStorageOk = true;

function senderRecentEntry(data) {
  const email = String(data.email || '');
  return {
    mode: 'sender', label: data.label, level: data.verdict, score: data.risk_score,
    domain: email.includes('@') ? email.slice(email.lastIndexOf('@') + 1).toLowerCase() : '',
    at: Date.now(),
  };
}

function contentRecentEntry(data) {
  const scored = data.risk_level !== 'unknown' && data.combined_phishing_score != null;
  return {
    mode: contentMode(data), label: data.risk_label, level: data.risk_level,
    score: scored ? data.combined_phishing_score : null, at: Date.now(),
  };
}

// Rebuilds an entry from allowed fields only, so a stale or hand-edited list
// cannot carry anything else into storage or onto the page.
function cleanRecentEntry(entry) {
  if (!entry || typeof entry !== 'object' || !Object.hasOwn(RECENT_MODES, entry.mode)) return null;
  const at = Number(entry.at);
  if (!Number.isFinite(at) || Number.isNaN(new Date(at).getTime())) return null;
  const score = entry.score === null || entry.score === undefined || entry.score === ''
    || !Number.isFinite(Number(entry.score)) ? null : Math.max(0, Math.min(100, Math.round(Number(entry.score))));
  const clean = {
    mode: entry.mode,
    label: String(entry.label ?? '').slice(0, 80),
    level: RECENT_LEVELS.has(entry.level) ? entry.level : 'unknown',
    score, at,
  };
  if (entry.mode === 'sender' && typeof entry.domain === 'string' && entry.domain) {
    clean.domain = entry.domain.slice(entry.domain.lastIndexOf('@') + 1).slice(0, 253);
  }
  return clean;
}

function readRecentChecks() {
  try {
    const list = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
    _recentStorageOk = true;
    return Array.isArray(list) ? list.map(cleanRecentEntry).filter(Boolean).slice(0, RECENT_LIMIT) : [];
  } catch (error) {
    // Storage blocked (e.g. privacy mode) throws; corrupt JSON is simply ignored.
    _recentStorageOk = error instanceof SyntaxError;
    return [];
  }
}

function recordRecentCheck(entry) {
  const clean = cleanRecentEntry(entry);
  if (!clean) return;
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify([clean, ...readRecentChecks()].slice(0, RECENT_LIMIT)));
  } catch (_error) {
    _recentStorageOk = false;
  }
  renderRecentChecks();
}

function clearRecentChecks() {
  try { localStorage.removeItem(RECENT_KEY); } catch (_error) { _recentStorageOk = false; }
  renderRecentChecks();
  announce('Recent checks cleared');
  // The Clear button hides itself, so return focus to the disclosure.
  document.querySelector('#recent-checks > summary')?.focus();
}

function formatRecentTime(at, now) {
  const minutes = Math.floor((now - at) / 60000);
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes} min ago`;
  if (minutes < 24 * 60) return `${Math.floor(minutes / 60)} h ago`;
  return new Date(at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function renderRecentChecks() {
  const list = document.getElementById('recent-checks-list');
  if (!list) return;
  const entries = readRecentChecks();
  const now = Date.now();
  list.innerHTML = entries.map(entry => {
    const when = new Date(entry.at);
    const score = entry.score === null ? '—' : entry.mode === 'sender' ? `${entry.score}/100` : `${entry.score}%`;
    const domain = entry.domain ? `<span class="recent-domain">${escapeHtml(entry.domain)}</span>` : '';
    return `
      <li class="recent-item recent-${entry.level}">
        <span class="recent-mode">${escapeHtml(RECENT_MODES[entry.mode])}</span>
        <span class="recent-main"><span class="recent-label">${escapeHtml(entry.label || 'Result')}</span>${domain}</span>
        <span class="recent-score">${escapeHtml(score)}</span>
        <time class="recent-time" datetime="${when.toISOString()}" title="${escapeHtml(when.toLocaleString())}">${escapeHtml(formatRecentTime(entry.at, now))}</time>
      </li>`;
  }).join('');
  list.hidden = entries.length === 0;
  document.getElementById('recent-checks-count').textContent = entries.length ? `(${entries.length})` : '';
  document.getElementById('recent-checks-clear').hidden = entries.length === 0;
  const empty = document.getElementById('recent-checks-empty');
  empty.hidden = entries.length > 0;
  empty.textContent = _recentStorageOk
    ? 'No checks yet. Results you analyze here will be listed.'
    : 'This browser is blocking local storage, so recent checks are not kept.';
}

function setupRecentChecks() {
  renderRecentChecks();
  // Refresh relative times when reopened, and follow changes from other tabs.
  document.getElementById('recent-checks')?.addEventListener('toggle', renderRecentChecks);
  window.addEventListener('storage', event => {
    if (event.key === RECENT_KEY || event.key === null) renderRecentChecks();
  });
}
