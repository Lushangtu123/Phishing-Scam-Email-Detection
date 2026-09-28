/* ──────────────────────────────────────────────────────────────────────────
   app-verify.js – mailbox verification (DNS, SMTP, SPF, DMARC, WHOIS)
   ────────────────────────────────────────────────────────────────────────── */

// ── Email Authenticity Verification ──────────────────────────────────────────
let _verifyEmail = null;   // remember which email was last analyzed
let _verificationRequestId = 0;

function resetVerifyCard() {
  _verificationRequestId++;
  setError('verify-error');
  if (!_emailVerificationEnabled) {
    applyPublicConfig(_publicConfig);
    return;
  }
  document.getElementById('verify-idle').classList.remove('hidden');
  document.getElementById('verify-loading').classList.add('hidden');
  document.getElementById('verify-result').classList.add('hidden');
}

async function runVerification() {
  const email = _verifyEmail;
  if (!email || !_emailVerificationEnabled) return;
  const requestId = ++_verificationRequestId;
  setError('verify-error');

  document.getElementById('verify-idle').classList.add('hidden');
  document.getElementById('verify-loading').classList.remove('hidden');
  document.getElementById('verify-result').classList.add('hidden');

  try {
    const data = await postJSON('/api/verify-email', { email });
    if (requestId !== _verificationRequestId || email !== _verifyEmail) return;
    renderVerifyResult(data);
  } catch (err) {
    if (requestId !== _verificationRequestId) return;
    document.getElementById('verify-idle').classList.remove('hidden');
    setError('verify-error', err.message);
  } finally {
    if (requestId === _verificationRequestId) {
      document.getElementById('verify-loading').classList.add('hidden');
    }
  }
}

function renderVerifyResult(data) {
  const ICONS = {
    ok:   { icon: 'check', cls: 'vstep-ok'   },
    warn: { icon: 'alert', cls: 'vstep-warn' },
    fail: { icon: 'x',     cls: 'vstep-fail' },
    skip: { icon: 'minus', cls: 'vstep-skip' },
    info: { icon: 'info',  cls: 'vstep-info' },
  };

  function setStep(id, state, detail) {
    const iconEl   = document.getElementById(`vstep-${id}-icon`);
    const detailEl = document.getElementById(`vstep-${id}-detail`);
    const step     = document.getElementById(`vstep-${id}`);
    if (!iconEl) return;
    const cfg = ICONS[state] || ICONS.skip;
    iconEl.innerHTML     = icon(cfg.icon);
    step.className       = 'verify-step ' + cfg.cls;
    detailEl.textContent = detail;
  }

  // ── Section A: Mailbox Existence ────────────────────────────────────────
  // Step 1 – Format
  if (data.format_valid) {
    setStep('format', 'ok', 'Address conforms to RFC 5321 format.');
  } else {
    setStep('format', 'fail', data.smtp_message || 'Invalid email format.');
    ['mx', 'smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s =>
      setStep(s, 'skip', 'Skipped.'));
    showVerifyVerdict('invalid_format');
    return;
  }

  // Step 2 – DNS / MX
  if (data.null_mx && data.overall === 'no_mail_service') {
    setStep('mx', 'info', data.smtp_message);
    ['smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s => setStep(s, 'skip', 'Skipped: domain declares no mail service.'));
    showVerifyVerdict('no_mail_service');
    return;
  }
  if (data.mx_found) {
    const recs = (data.mx_records || [])
      .map(r => `${r[1]} (pref ${r[0]})`).join(' · ');
    setStep('mx', 'ok', `MX records: ${recs || data.email.split('@')[1]}`);
  } else {
    const inconclusive = data.overall === 'unverifiable';
    setStep('mx', inconclusive ? 'warn' : 'fail', data.smtp_message || 'No MX or A records found.');
    ['smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s => setStep(s, 'skip', 'Skipped.'));
    showVerifyVerdict(inconclusive ? 'unverifiable' : 'likely_invalid');
    return;
  }

  // Step 3 – SMTP probe
  const smtpResult = data.smtp_result || '';
  const smtpMsg    = data.smtp_message || '';
  if (smtpResult === 'exists') {
    setStep('smtp', 'ok', smtpMsg);
  } else if (smtpResult === 'does_not_exist') {
    setStep('smtp', 'fail', smtpMsg);
  } else if (smtpResult === 'temporarily_unavailable') {
    setStep('smtp', 'warn', smtpMsg);
  } else if (data.smtp_status === 'skipped' || data.mailbox_verification?.status === 'unavailable') {
    setStep('smtp', 'info', smtpMsg || 'SMTP mailbox probing is unavailable on this deployment.');
  } else {
    setStep('smtp', 'warn',
      smtpMsg || (!data.smtp_connectable
        ? 'Port 25 appears blocked — probe skipped. Domain MX exists, mailbox unconfirmed.'
        : 'Server gave no definitive response.'));
  }

  // Step 4 – MX PTR (reverse DNS)
  const ptr = data.mx_ptr || {};
  if (ptr.found) {
    setStep('ptr', 'ok', ptr.message || `PTR: ${ptr.ptr}`);
  } else if (ptr.message && ptr.message.includes('timed out')) {
    setStep('ptr', 'skip', ptr.message);
  } else {
    setStep('ptr', 'warn',
      ptr.message || 'No PTR record — legitimate mail servers should have reverse DNS.');
  }

  // ── Section B: Email Security Policy ───────────────────────────────────
  // Step 5 – SPF
  const spf = data.spf || {};
  if (spf.found) {
    const policy = spf.policy;
    const state  = policy === 'strict'   ? 'ok'   :
                   policy === 'softfail' ? 'warn'  :
                   policy === 'open'     ? 'fail'  : 'warn';
    setStep('spf', state, spf.message || `Policy: ${policy}`);
  } else {
    setStep('spf', 'warn', spf.message || 'No SPF record found.');
  }

  // Step 6 – DMARC
  const dmarc = data.dmarc || {};
  if (dmarc.found) {
    const policy = dmarc.policy;
    const state  = policy === 'reject'     ? 'ok'   :
                   policy === 'quarantine' ? 'warn'  :
                   policy === 'none'       ? 'warn'  : 'skip';
    setStep('dmarc', state, dmarc.message || `Policy: ${policy}`);
  } else {
    setStep('dmarc', 'warn', dmarc.message || 'No DMARC record found.');
  }

  // ── Section C: Domain Intelligence ─────────────────────────────────────
  // Step 7 – Domain Age
  const age = data.domain_age || {};
  if (age.found && age.age_days !== null) {
    const d = age.age_days;
    const state = d < 30 ? 'fail' : d < 180 ? 'warn' : 'ok';
    const detail = age.message + (age.registrar ? ` · Registrar: ${age.registrar}` : '');
    setStep('age', state, detail);
  } else {
    setStep('age', 'skip', age.message || 'WHOIS data unavailable.');
  }

  showVerifyVerdict(data.overall, data.verification_complete, data);
}

function showVerifyVerdict(overall, complete, data = {}) {
  const VERDICTS = {
    verified:    { cls: 'vv-ok',      icon: 'check',
      text: 'SMTP Accepted — The mail server accepted this address. This does not guarantee mailbox existence, delivery, or sender authenticity.' },
    no_mail_service: { cls: 'vv-warn', icon: 'info',
      text: 'No Mail Service — This domain explicitly does not accept email (Null MX). This alone is not evidence of phishing.' },
    likely_invalid: { cls: 'vv-fail', icon: 'x',
      text: 'Likely Invalid — This address probably does not exist.' },
    unverifiable: { cls: 'vv-warn',   icon: 'alert',
      text: 'Unverifiable — Available checks could not confirm mailbox existence. Review the DNS and SMTP details above; an unavailable or timed-out check does not prove the address is invalid.' },
    suspicious:  { cls: 'vv-suspicious', icon: 'bell',
      text: 'Suspicious — Domain was registered very recently (< 30 days). Newly registered domains are a hallmark of phishing campaigns.' },
    domain_valid: { cls: 'vv-ok', icon: 'check',
      text: 'Domain Valid — Mail-routing records exist and the available domain checks completed. The mailbox itself is not verified.' },
    invalid_format: { cls: 'vv-fail', icon: 'x',
      text: 'Invalid Format — This is not a valid email address.' },
    temporarily_unavailable: { cls: 'vv-warn', icon: 'alert',
      text: 'Temporarily Unavailable — The server returned a transient error. Try again later.' },
  };
  const cfg = VERDICTS[overall] || { cls: 'vv-warn', icon: 'minus', text: 'Result inconclusive.' };
  const el  = document.getElementById('verify-verdict');
  const incomplete = complete === false;
  el.className  = 'verify-verdict ' + (incomplete && overall === 'verified' ? 'vv-warn' : cfg.cls);
  const domainOnly = overall === 'domain_valid' && data.domain_verification?.complete === true;
  const warning = incomplete && !domainOnly
    ? ' Verification Incomplete — One or more checks failed, timed out, or could not run. See the individual results above.'
    : '';
  el.innerHTML  = `${icon(cfg.icon, 'ico-lead')} <span>${cfg.text}${warning}</span>`;

  document.getElementById('verify-result').classList.remove('hidden');
}
