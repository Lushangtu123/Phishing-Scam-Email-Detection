/* ──────────────────────────────────────────────────────────────────────────
   app-content.js – email content analysis input
   Manual fields, .eml / image file intake, examples and the request.
   Result rendering lives in app-content-render.js.
   ────────────────────────────────────────────────────────────────────────── */

let _rawEmailSource = '';
let _visualFile = null;
let _rawReadId = 0;
let _rawReadPending = false;
let _contentRequestId = 0;
// Aborts the content request in flight; null when none is.
let _contentAbort = null;
// The file status line: null shows the page's default hint (static markup),
// '' shows nothing, otherwise { key, params } for t(). Kept so a language
// switch can re-render it.
let _rawStatus = null;

function setRawStatus(status) {
  _rawStatus = status;
  renderRawStatus();
}

function renderRawStatus() {
  if (_rawStatus === null) return;
  document.getElementById('raw-email-status').textContent = _rawStatus ? t(_rawStatus.key, _rawStatus.params) : '';
}

function invalidateContent() {
  window.PhishGuardFeedback?.clear('content');
  window.PhishGuardVision?.cancel();
  window.PhishGuardVision?.render(document.getElementById('visual-evidence'), null);
  const progress = document.getElementById('visual-progress');
  if (progress) progress.textContent = '';
  const cancel = document.getElementById('cancel-content-scan');
  if (cancel) cancel.hidden = true;
  _contentRequestId++;
  _contentAbort?.abort();
  _contentAbort = null;
  document.getElementById('content-result-area').classList.add('hidden');
  document.getElementById('content-loading-area').classList.add('hidden');
  document.getElementById('content-analyze-btn').disabled = false;
  document.getElementById('content-btn-text').textContent = t('content.analyze');
  setError('content-error');
}

// The mailbox choice applies only to an .eml file; images and pasted text have no
// receiving-service authentication header to trust.
function setMailboxOptions(file) {
  const eml = !!file && (/\.eml$/i.test(file.name) || file.type === 'message/rfc822');
  document.getElementById('content-mailbox-options').hidden = !eml;
  if (!eml) document.getElementById('content-mailbox').value = '';
}

function mailboxChoice() {
  const options = document.getElementById('content-mailbox-options');
  return options.hidden ? '' : document.getElementById('content-mailbox').value;
}

function clearRawEmail() {
  _rawReadId++;
  _rawReadPending = false;
  _rawEmailSource = '';
  _visualFile = null;
  const enhanced = document.getElementById('content-enhanced-vision');
  const semantics = document.getElementById('content-image-understanding');
  if (enhanced) { enhanced.checked = false; enhanced.disabled = true; }
  if (semantics) { semantics.checked = false; semantics.disabled = true; }
  window.PhishGuardVision?.cancel();
  document.getElementById('raw-email-file').value = '';
  setMailboxOptions(null);
  setRawStatus('');
  ['content-subject', 'content-body'].forEach(id => {
    document.getElementById(id).disabled = false;
  });
}

// ── Input & file events ──────────────────────────────────────────────────────
function setupInputEvents() {
  const input = document.getElementById('email-input');
  const clearBtn = document.getElementById('btn-clear');
  input.addEventListener('input', () => {
    invalidateSender();
    clearBtn.classList.toggle('visible', input.value.length > 0);
  });
  ['content-subject', 'content-body'].forEach(id => {
    document.getElementById(id).addEventListener('input', invalidateContent);
  });
  document.getElementById('cancel-content-scan')?.addEventListener('click', cancelContentAnalysis);
  document.getElementById('content-ocr-language').addEventListener('change', invalidateContent);
  document.getElementById('content-enhanced-vision')?.addEventListener('change', () => {
    refreshEnhancedOptions();
    invalidateContent();
  });
  document.getElementById('content-image-understanding')?.addEventListener('change', invalidateContent);
  document.getElementById('content-mailbox').addEventListener('change', invalidateContent);
  const rawInput = document.getElementById('raw-email-file');
  if (rawInput) {
    rawInput.addEventListener('change', async event => {
      invalidateContent();
      const readId = ++_rawReadId;
      const file = event.target.files?.[0];
      _rawEmailSource = '';
      _visualFile = null;
      document.getElementById('content-enhanced-vision').checked = false;
      document.getElementById('content-image-understanding').checked = false;
      _rawReadPending = !!file;
      ['content-subject', 'content-body'].forEach(id => {
        document.getElementById(id).disabled = !!file;
      });
      setRawStatus(file ? { key: 'content.file.reading', params: { name: file.name } } : '');
      try {
        if (file?.size > 2 * 1024 * 1024) {
          clearRawEmail();
          setError('content-error', t('content.file.tooLarge'));
          return;
        }
        const source = file ? await file.arrayBuffer() : '';
        if (readId !== _rawReadId) return;
        if (file && source.byteLength > 2 * 1024 * 1024) {
          clearRawEmail();
          setError('content-error', t('content.file.tooLarge'));
          return;
        }
        if (file && new Uint8Array(source).every(byte => [9, 10, 13, 32].includes(byte))) {
          clearRawEmail();
          setError('content-error', t('content.file.empty'));
          return;
        }
        _rawEmailSource = source;
        _visualFile = file || null;
        setMailboxOptions(file);
        refreshEnhancedOptions();
        setRawStatus(file ? { key: 'content.file.loaded', params: { name: file.name } } : '');
      } catch (_error) {
        if (readId !== _rawReadId) return;
        clearRawEmail();
        setError('content-error', t('content.file.unreadable'));
      } finally {
        if (readId === _rawReadId) _rawReadPending = false;
      }
    });
    window.PhishGuardFiles?.bind({zone: document.getElementById('content-file-dropzone'), input: rawInput,
      enabled: () => !document.getElementById('panel-email-content').classList.contains('hidden'),
      onError: message => setError('content-error', message)});
  }
}

function refreshEnhancedOptions() {
  const enhanced = document.getElementById('content-enhanced-vision');
  const semantics = document.getElementById('content-image-understanding');
  const standaloneImage = !!_visualFile && !/\.eml$/i.test(_visualFile.name) && _visualFile.type !== 'message/rfc822';
  enhanced.disabled = _publicConfig.enhanced_vision_enabled !== true || !standaloneImage;
  if (enhanced.disabled) enhanced.checked = false;
  semantics.disabled = enhanced.disabled || !enhanced.checked || _publicConfig.enhanced_vision_semantics_enabled !== true;
  if (semantics.disabled) semantics.checked = false;
}

// ── Email Content Analysis ────────────────────────────────────────────────────

// Sample messages stay in English in every UI language: they exercise the
// English content rules and text model the analysis is built on.
const CONTENT_EXAMPLES = {
  'phishing-account': {
    subject: 'URGENT: Your P@yP@l account has been SUSPENDED!!!',
    body: `Dear valued customer,

We have detected UNAUTHORIZED ACCESS on your P@yP@l account. Your account has been SUSPENDED due to suspicious activity. Failure to act will result in PERMANENT TERMINATION and legal action.

URGENT ACTION REQUIRED: You must verify your identity within 24 hours!

Click here: http://192.168.1.1/paypal-verify-now
Click here to confirm: http://bit.ly/verify-account-now

Please enter your username, password, credit card number, date of birth, social security number, and bank account number to restore access.

DO NOT share this email. DELETE after reading. Keep this CONFIDENTIAL.

P@yP@l Security Department`,
  },
  'phishing-lottery': {
    subject: 'CONGRATULATIONS!!! You WON $5,000,000 – Claim NOW!!!',
    body: `Dear Lucky Winner,

I am Mr. James Williams, Senior Claims Agent. You have been SPECIALLY SELECTED as the winner of our international lottery draw!!! You have won FIVE MILLION DOLLARS ($5,000,000)!!!

To claim your prize you must act NOW! This offer expires in 24 hours! Kindly revert back to me immediately.

Please send your full name, date of birth, home address, bank account number, and routing number. A release fee of $200 is required via Bitcoin, gift card, or Western Union.

DO NOT tell anyone. Keep this strictly confidential. Do the needful and respond at the earliest.

God Bless You,
I am Barrister James, Esq.`,
  },
  'legit-newsletter': {
    subject: 'Your monthly digest from TechBlog – May 2026',
    body: `Hi Sarah,

Thanks for subscribing to the TechBlog monthly newsletter. Here's a roundup of what's new this month:

• The latest in AI and machine learning research
• Upcoming community events and webinars
• Product updates and release notes

We hope you find this content helpful. If you have feedback, feel free to contact us at hello@techblog.com.

You are receiving this email because you subscribed at techblog.com.
If you no longer wish to receive these emails, please click unsubscribe below or update your preferences.

Privacy Policy | Terms of Service
© 2026 TechBlog, All Rights Reserved.
Sent from TechBlog, 123 Main St, San Francisco, CA 94101`,
  },
};

function setContentExample(key) {
  const ex = CONTENT_EXAMPLES[key];
  if (!ex) return;
  document.getElementById('content-subject').value = ex.subject;
  document.getElementById('content-body').value = ex.body;
  clearRawEmail();
  runContentAnalysis();
}

function clearContent() {
  invalidateContent();
  document.getElementById('content-subject').value = '';
  document.getElementById('content-body').value = '';
  clearRawEmail();
  document.getElementById('content-result-area').classList.add('hidden');
  document.getElementById('content-loading-area').classList.add('hidden');
}

function buildContentPayload(subject, body, rawEmail) {
  return rawEmail ? { raw_email: rawEmail } : { subject, body, raw_email: '' };
}

async function runContentAnalysis() {
  invalidateContent();
  const requestId = _contentRequestId;
  if (_rawReadPending) {
    setError('content-error', t('content.error.pending'));
    return;
  }
  const subject = document.getElementById('content-subject').value.trim();
  const body    = document.getElementById('content-body').value.trim();
  if (!subject && !body && !_rawEmailSource) {
    setError('content-error', t('content.error.empty'));
    document.getElementById('content-body').classList.add('shake');
    setTimeout(() => document.getElementById('content-body').classList.remove('shake'), 500);
    return;
  }

  const btn = document.getElementById('content-analyze-btn');
  const btnText = document.getElementById('content-btn-text');
  btn.disabled = true;
  btnText.textContent = t('content.scanning');

  document.getElementById('content-result-area').classList.add('hidden');
  document.getElementById('content-loading-area').classList.remove('hidden');
  // One Cancel button covers the in-browser image scan and the server request.
  const controller = newAbortController();
  _contentAbort = controller;
  const request = { signal: controller?.signal };
  if (controller || _visualFile) document.getElementById('cancel-content-scan').hidden = false;

  try {
    let data;
    let recognitionPayload = null;
    if (_visualFile) {
      if (!window.PhishGuardVision) throw new Error(t('content.error.visionUnavailable'));
      const payload = await window.PhishGuardVision.recognize(_visualFile, message => {
        if (requestId === _contentRequestId) document.getElementById('visual-progress').textContent = message;
      }, document.getElementById('content-ocr-language').value || 'eng', {
        enhance: _publicConfig.enhanced_vision_enabled === true && document.getElementById('content-enhanced-vision').checked === true,
        includeSemantics: _publicConfig.enhanced_vision_semantics_enabled === true && document.getElementById('content-image-understanding').checked === true,
      });
      if (requestId !== _contentRequestId) return;
      recognitionPayload = payload;
      const mailbox = mailboxChoice();
      data = await postJSON('/api/analyze-visual', payload.eml_base64 && mailbox ? {...payload, mailbox} : payload, request);
    } else {
      data = _rawEmailSource
        ? await postRequest('/api/analyze-eml' + (mailboxChoice() ? `?mailbox=${encodeURIComponent(mailboxChoice())}` : ''),
          _rawEmailSource, 'message/rfc822', request)
        : await postJSON('/api/analyze-content', buildContentPayload(subject, body, ''), request);
    }
    if (requestId !== _contentRequestId) return;
    renderContentResult(data);
    recordRecentCheck(contentRecentEntry(data));
    window.PhishGuardVision?.render(document.getElementById('visual-evidence'), data.visual_analysis, _visualFile);
    const rawSnapshot = _rawEmailSource;
    const mode = _visualFile && /\.eml$/i.test(_visualFile.name) ? 'eml'
      : _visualFile ? 'image' : rawSnapshot ? 'eml' : 'content';
    window.PhishGuardFeedback?.set('content', {
      inputMode: mode, fingerprintInput: rawSnapshot || subject + '\0' + body,
      analysis: feedbackAnalysis(data),
      buildSource: () => mode === 'eml' ? {eml_base64: encodeFeedbackEmail(rawSnapshot)}
        : mode === 'image' ? {
          ocr_text: (recognitionPayload?.observations || []).map(item => item.ocr_text || '').join('\n').slice(0, 12000),
          qr_text: (recognitionPayload?.observations || []).flatMap(item => item.qr_payloads || []).join('\n').slice(0, 4000),
        } : {subject, body},
    });
  } catch (e) {
    if (requestId === _contentRequestId) setError('content-error', e.message);
  } finally {
    if (requestId === _contentRequestId) {
      _contentAbort = null;
      btn.disabled = false;
      btnText.textContent = t('content.analyze');
      document.getElementById('visual-progress').textContent = '';
      document.getElementById('content-loading-area').classList.add('hidden');
      document.getElementById('cancel-content-scan').hidden = true;
    }
  }
}

// The Cancel button: stops the image scan or the server request, restores the
// idle form (no error) and says so through the live region. A response that
// still arrives is ignored (the request id changed).
function cancelContentAnalysis() {
  const busy = document.getElementById('content-analyze-btn').disabled;
  invalidateContent();
  if (!busy) return;
  announce(t('request.cancelled'));
  document.getElementById('content-analyze-btn').focus();
}
