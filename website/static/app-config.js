/* ──────────────────────────────────────────────────────────────────────────
   app-config.js – public configuration from /api/config
   Toggles verification, reporting and enhanced image options.
   ────────────────────────────────────────────────────────────────────────── */

// ── Public configuration ─────────────────────────────────────────────────────
let _emailVerificationEnabled = false;
let _publicConfig = {};

function applyPublicConfig(config) {
  _publicConfig = config;
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
    notice.textContent = 'Domain checks are enabled. SMTP mailbox probing is unavailable on this deployment, so mailbox existence cannot be confirmed.';
  } else if (enabled) {
    notice.textContent = '';
  } else if (config.deployment_profile === 'development' || config.deployment_profile === 'test') {
    notice.textContent = 'Network-based mailbox verification is disabled in this local configuration. Enable it in the local server settings and restart the service, then reload this page.';
  } else if (config.deployment_profile === 'demo' || config.deployment_profile === 'production') {
    notice.textContent = 'Network-based mailbox verification is disabled on this public service. Deploy on your own computer to enable SMTP, DNS, and WHOIS checks.';
  } else {
    notice.textContent = 'Mailbox verification availability could not be confirmed. Reload this page to retry. Sender and message analysis remain available.';
  }
}

async function loadPublicConfig() {
  let config = { email_verification_enabled: false };
  try {
    const response = await fetch('/api/config', { cache: 'no-store' });
    if (response.ok) config = await response.json();
  } catch (error) {
    console.warn('Public configuration unavailable; using safe defaults.', error);
  }
  applyPublicConfig(config);
}
