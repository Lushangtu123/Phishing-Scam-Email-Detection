/* ──────────────────────────────────────────────────────────────────────────
   app-verify.js – mailbox verification (DNS, SMTP, SPF, DMARC, WHOIS)
   ────────────────────────────────────────────────────────────────────────── */

// ── Email Authenticity Verification ──────────────────────────────────────────
let _verifyEmail = null;   // remember which email was last analyzed
let _verificationRequestId = 0;
let _lastVerifyResult = null;   // re-rendered after a language switch
let _verificationAbort = null;  // aborts the verification request in flight

function abortVerification() {
  _verificationAbort?.abort();
  _verificationAbort = null;
}

function resetVerifyCard() {
  abortVerification();
  _verificationRequestId++;
  _lastVerifyResult = null;
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
  abortVerification();
  const requestId = ++_verificationRequestId;
  const controller = newAbortController();
  _verificationAbort = controller;
  setError('verify-error');

  document.getElementById('verify-idle').classList.add('hidden');
  document.getElementById('verify-loading').classList.remove('hidden');
  document.getElementById('verify-result').classList.add('hidden');

  try {
    // Times out after the action limit (45 s) like the analyses: the server
    // stops probing after 12 s, so only a request that never answers gets there.
    const data = await postJSON('/api/verify-email', { email }, { signal: controller?.signal });
    if (requestId !== _verificationRequestId || email !== _verifyEmail) return;
    renderVerifyResult(data);
  } catch (err) {
    if (requestId !== _verificationRequestId) return;
    document.getElementById('verify-idle').classList.remove('hidden');
    setError('verify-error', err.message);
  } finally {
    if (requestId === _verificationRequestId) {
      _verificationAbort = null;
      document.getElementById('verify-loading').classList.add('hidden');
    }
  }
}

function renderVerifyResult(data) {
  _lastVerifyResult = data;
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
    setStep('format', 'ok', t('verify.detail.formatOk'));
  } else {
    setStep('format', 'fail', verifyText(data, 'smtp_message') || t('verify.detail.formatInvalid'));
    ['mx', 'smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s =>
      setStep(s, 'skip', t('verify.detail.skipped')));
    showVerifyVerdict('invalid_format');
    return;
  }

  // Step 2 – DNS / MX
  if (data.null_mx && data.overall === 'no_mail_service') {
    setStep('mx', 'info', verifyText(data, 'smtp_message'));
    ['smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s => setStep(s, 'skip', t('verify.detail.skippedNoMail')));
    showVerifyVerdict('no_mail_service');
    return;
  }
  if (data.mx_found) {
    const recs = (data.mx_records || [])
      .map(r => t('verify.detail.mxPref', { host: r[1], pref: r[0] })).join(' · ');
    setStep('mx', 'ok', t('verify.detail.mxRecords', { records: recs || data.email.split('@')[1] }));
  } else {
    const inconclusive = data.overall === 'unverifiable';
    setStep('mx', inconclusive ? 'warn' : 'fail', verifyText(data, 'smtp_message') || t('verify.detail.noMx'));
    ['smtp', 'ptr', 'spf', 'dmarc', 'age'].forEach(s => setStep(s, 'skip', t('verify.detail.skipped')));
    showVerifyVerdict(inconclusive ? 'unverifiable' : 'likely_invalid');
    return;
  }

  // Step 3 – SMTP probe
  const smtpResult = data.smtp_result || '';
  const smtpMsg    = verifyText(data, 'smtp_message') || '';
  if (smtpResult === 'exists') {
    setStep('smtp', 'ok', smtpMsg);
  } else if (smtpResult === 'does_not_exist') {
    setStep('smtp', 'fail', smtpMsg);
  } else if (smtpResult === 'temporarily_unavailable') {
    setStep('smtp', 'warn', smtpMsg);
  } else if (data.smtp_status === 'skipped' || data.mailbox_verification?.status === 'unavailable') {
    setStep('smtp', 'info', smtpMsg || t('verify.detail.smtpUnavailable'));
  } else {
    setStep('smtp', 'warn',
      smtpMsg || t(!data.smtp_connectable ? 'verify.detail.port25' : 'verify.detail.noResponse'));
  }

  // Step 4 – MX PTR (reverse DNS)
  const ptr = data.mx_ptr || {};
  if (ptr.found) {
    setStep('ptr', 'ok', verifyText(ptr) || t('verify.detail.ptr', { ptr: ptr.ptr }));
  } else if (ptr.message && ptr.message.includes('timed out')) {
    setStep('ptr', 'skip', verifyText(ptr));
  } else {
    setStep('ptr', 'warn', verifyText(ptr) || t('verify.detail.noPtr'));
  }

  // ── Section B: Email Security Policy ───────────────────────────────────
  // Step 5 – SPF
  const spf = data.spf || {};
  if (spf.found) {
    const policy = spf.policy;
    const state  = policy === 'strict'   ? 'ok'   :
                   policy === 'softfail' ? 'warn'  :
                   policy === 'open'     ? 'fail'  : 'warn';
    setStep('spf', state, verifyText(spf) || t('verify.detail.policy', { policy }));
  } else {
    setStep('spf', 'warn', verifyText(spf) || t('verify.detail.noSpf'));
  }

  // Step 6 – DMARC
  const dmarc = data.dmarc || {};
  if (dmarc.found) {
    const policy = dmarc.policy;
    const state  = policy === 'reject'     ? 'ok'   :
                   policy === 'quarantine' ? 'warn'  :
                   policy === 'none'       ? 'warn'  : 'skip';
    setStep('dmarc', state, verifyText(dmarc) || t('verify.detail.policy', { policy }));
  } else {
    setStep('dmarc', 'warn', verifyText(dmarc) || t('verify.detail.noDmarc'));
  }

  // ── Section C: Domain Intelligence ─────────────────────────────────────
  // Step 7 – Domain Age
  const age = data.domain_age || {};
  if (age.found && age.age_days !== null) {
    const d = age.age_days;
    const state = d < 30 ? 'fail' : d < 180 ? 'warn' : 'ok';
    const detail = verifyText(age) + (age.registrar ? t('verify.detail.registrar', { registrar: age.registrar }) : '');
    setStep('age', state, detail);
  } else {
    setStep('age', 'skip', verifyText(age) || t('verify.detail.noWhois'));
  }

  showVerifyVerdict(data.overall, data.verification_complete, data);
}

function showVerifyVerdict(overall, complete, data = {}) {
  // Each overall code's text is `verify.verdict.<code>` in the dictionary.
  const VERDICTS = {
    verified:                { cls: 'vv-ok',         icon: 'check' },
    no_mail_service:         { cls: 'vv-warn',       icon: 'info'  },
    likely_invalid:          { cls: 'vv-fail',       icon: 'x'     },
    unverifiable:            { cls: 'vv-warn',       icon: 'alert' },
    suspicious:              { cls: 'vv-suspicious', icon: 'bell'  },
    domain_valid:            { cls: 'vv-ok',         icon: 'check' },
    invalid_format:          { cls: 'vv-fail',       icon: 'x'     },
    temporarily_unavailable: { cls: 'vv-warn',       icon: 'alert' },
  };
  const known = Object.hasOwn(VERDICTS, overall);
  const cfg = known ? VERDICTS[overall] : { cls: 'vv-warn', icon: 'minus' };
  const text = t(known ? `verify.verdict.${overall}` : 'verify.verdict.inconclusive');
  const el  = document.getElementById('verify-verdict');
  const incomplete = complete === false;
  el.className  = 'verify-verdict ' + (incomplete && overall === 'verified' ? 'vv-warn' : cfg.cls);
  const domainOnly = overall === 'domain_valid' && data.domain_verification?.complete === true;
  const warning = incomplete && !domainOnly ? t('verify.verdict.incomplete') : '';
  // Verdict text comes only from the trusted dictionary, as the literals did before.
  el.innerHTML  = `${icon(cfg.icon, 'ico-lead')} <span>${text}${warning}</span>`;

  document.getElementById('verify-result').classList.remove('hidden');
}
