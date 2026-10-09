/* ──────────────────────────────────────────────────────────────────────────
   app-config.js – public configuration from /api/config
   Toggles verification, reporting and enhanced image options.
   ────────────────────────────────────────────────────────────────────────── */

// ── Public configuration ─────────────────────────────────────────────────────
let _emailVerificationEnabled = false;
let _publicConfig = {};
// Dictionary key of the verification notice; null until the config is applied,
// '' when no notice is shown. Kept so a language switch can re-render it.
let _verificationNoticeKey = null;

function applyPublicConfig(config) {
  _publicConfig = config;
  applySmsConfig(config);
  document.getElementById('content-enhancement-options').hidden = config.enhanced_vision_enabled !== true;
  refreshEnhancedOptions();
  document.querySelectorAll('.result-report').forEach(row => { row.hidden = config.feedback_enabled !== true; });
  const enabled = typeof config.domain_verification_enabled === 'boolean'
    ? config.domain_verification_enabled
    : config.email_verification_enabled === true;
  const smtpEnabled = typeof config.smtp_verification_enabled === 'boolean'
    ? config.smtp_verification_enabled
    : enabled;
  _emailVerificationEnabled = enabled;
  const notice = document.getElementById('verification-local-notice');
  document.getElementById('verify-idle').classList.toggle('hidden', !enabled);
  ['verify-loading', 'verify-result'].forEach(id => {
    document.getElementById(id).classList.add('hidden');
  });
  notice.classList.toggle('hidden', enabled && smtpEnabled);
  if (enabled && !smtpEnabled) {
    _verificationNoticeKey = 'config.notice.smtpOff';
  } else if (enabled) {
    _verificationNoticeKey = '';
  } else if (config.deployment_profile === 'development' || config.deployment_profile === 'test') {
    _verificationNoticeKey = 'config.notice.local';
  } else if (config.deployment_profile === 'demo' || config.deployment_profile === 'production') {
    _verificationNoticeKey = 'config.notice.public';
  } else {
    _verificationNoticeKey = 'config.notice.unknown';
  }
  renderVerificationNotice();
}

function renderVerificationNotice() {
  if (_verificationNoticeKey === null) return;
  document.getElementById('verification-local-notice').textContent =
    _verificationNoticeKey ? t(_verificationNoticeKey) : '';
}

async function loadPublicConfig() {
  let config = { email_verification_enabled: false };
  try {
    const loaded = await getRequest('/api/config', { cache: 'no-store' },
      response => (response.ok ? response.json() : null));
    if (loaded) config = loaded;
  } catch (error) {
    console.warn('Public configuration unavailable; using safe defaults.', error);
  }
  applyPublicConfig(config);
}
