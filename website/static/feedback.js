/* Public reports are opt-in. Source builders run only after retention consent. */
'use strict';
window.PhishGuardFeedback = (() => {
  const contexts = {sender: null, content: null};
  // A report belongs to an analysis, so closing its dialog must not discard a
  // sent request, its idempotency key, or a receipt that arrives while closed.
  const sessions = {sender: null, content: null};
  let active = null;
  const $ = id => document.getElementById(id);
  // Homepage only: i18n.js loads first. Server `detail` messages stay as sent.
  const t = (key, params) => (window.PhishGuardI18n ? window.PhishGuardI18n.t(key, params) : key);
  const askConfirm = (message, options) => window.PhishGuardConfirm
    ? window.PhishGuardConfirm(message, options) : Promise.resolve(window.confirm(message));

  function clear(kind) {
    contexts[kind] = null;
    sessions[kind] = null;
    if (active?.kind === kind) {
      detach();
      $('feedback-dialog')?.close();
    }
  }
  function set(kind, context) { clear(kind); contexts[kind] = context; }
  function draft() {
    return {type: $('feedback-type').value, note: $('feedback-note').value,
      consent: $('feedback-consent').checked, evaluation: $('feedback-evaluation-consent').checked};
  }
  function detach() {
    if (!active) return;
    active.draft = draft();
    // A hash has no server-side effects. Cancel it without blocking a new
    // attempt; its eventual completion cannot unlock that newer attempt.
    if (!active.retry?.sent) { active.revision++; active.pending = null; }
    active = null;
  }
  function close() { detach(); $('feedback-dialog').close(); }
  function createSession(kind) {
    $('feedback-form').reset();
    return {kind, context: contexts[kind], pending: null, submitted: false,
      retry: null, receipt: null, revision: 0, draft: draft(), error: ''};
  }
  function render(session, restoreDraft = false) {
    if (active !== session) return;
    if (restoreDraft) {
      $('feedback-type').value = session.draft.type;
      $('feedback-note').value = session.draft.note;
      $('feedback-consent').checked = session.draft.consent;
      $('feedback-evaluation-consent').checked = session.draft.evaluation;
    }
    const supportsEvaluation = ['content', 'eml'].includes(session.context.inputMode);
    $('feedback-evaluation-consent-row').hidden = !supportsEvaluation;
    $('feedback-evaluation-consent').disabled = !supportsEvaluation || !$('feedback-consent').checked;
    $('feedback-error').textContent = session.error;
    $('feedback-error').classList[session.error ? 'remove' : 'add']('hidden');
    const edited = session.submitted && session.revision !== session.retry.revision;
    $('feedback-success').textContent = session.submitted
      ? t(edited ? 'feedback.successEdited' : 'feedback.success', {id: session.receipt}) : '';
    $('feedback-success').classList[session.submitted ? 'remove' : 'add']('hidden');
    $('feedback-fields').hidden = session.submitted && !edited;
    $('feedback-cancel').textContent = t(session.submitted ? 'feedback.close' : 'feedback.cancel');
    $('feedback-submit').hidden = session.submitted;
    $('feedback-submit').disabled = !!session.pending;
    $('feedback-submit').textContent = t(session.pending ? 'feedback.submitting'
      : session.retry?.sent ? 'feedback.retry' : 'feedback.submit');
    $('feedback-new-report').hidden = !session.submitted;
  }
  function open(kind) {
    if (!contexts[kind]) return;
    if (active) detach();
    if (!sessions[kind]) sessions[kind] = createSession(kind);
    active = sessions[kind];
    render(active, true);
    if (!$('feedback-dialog').open) $('feedback-dialog').showModal();
    $(active.submitted ? 'feedback-new-report' : 'feedback-type').focus();
  }
  function newReport() {
    if (!active?.submitted || active.pending) return;
    const previous = active, edited = previous.revision !== previous.retry.revision;
    previous.draft = draft();
    active = sessions[previous.kind] = createSession(previous.kind);
    if (edited) active.draft = {...previous.draft, consent: false, evaluation: false};
    render(active, true);
    $('feedback-type').focus();
  }
  async function fingerprint(value) {
    const bytes = value instanceof ArrayBuffer ? value : new TextEncoder().encode(String(value));
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return 'sha256:' + [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function consentedSource(context) {
    if (context.inputMode === 'eml' && context.fingerprintInput.byteLength > 60000) {
      throw new Error(t('feedback.error.emlTooLarge'));
    }
    const source = context.buildSource();
    if (context.inputMode === 'image' && !source.ocr_text && !source.qr_text) {
      throw new Error(t('feedback.error.noImageText'));
    }
    const limits = {email:320, subject:500, body:50000, ocr_text:12000, qr_text:4000};
    for (const [key, value] of Object.entries(source)) {
      if (key === 'eml_base64') continue;
      if (typeof value !== 'string' || new TextEncoder().encode(value).length > limits[key] || value.toLowerCase().includes('data:')) {
        throw new Error(t('feedback.error.limits'));
      }
    }
    return source;
  }
  async function submit(event) {
    event.preventDefault();
    if (!active || active.pending || active.submitted) return;
    const session = active, revision = session.revision, context = session.context, attempt = {};
    const current = () => active === session && $('feedback-dialog').open &&
      session.revision === revision && session.pending === attempt;
    session.draft = draft();
    session.pending = attempt;
    render(session);
    try {
      let submission = session.retry;
      if (submission?.sent && submission.revision !== revision) {
        const original = JSON.parse(submission.body);
        const retry = await askConfirm(t('feedback.retryConfirm', {
          source: t(original.include_source ? 'feedback.retryConfirm.withSource' : 'feedback.retryConfirm.withoutSource'),
          evaluation: original.evaluation_consent ? t('feedback.retryConfirm.evaluation') : '',
        }), {confirmLabel: t('feedback.retry')});
        if (!retry || !current()) return;
      }
      session.error = '';
      render(session);
      if (!submission) {
        const include = $('feedback-consent').checked;
        const payload = {
          report_type: $('feedback-type').value, note: $('feedback-note').value.trim(),
          include_source: include,
          evaluation_consent: include && ['content', 'eml'].includes(context.inputMode) && $('feedback-evaluation-consent').checked,
          input_mode: context.inputMode,
          analysis: context.analysis,
        };
        payload.input_fingerprint = await fingerprint(context.fingerprintInput);
        // Closing, replacing or editing this dialog invalidates unsent work.
        if (!current()) return;
        payload.source = include ? consentedSource(context) : null;
        submission = {key: crypto.randomUUID(), body: JSON.stringify(payload), revision};
        session.retry = submission;
      }
      submission.sent = true;
      // A request that times out may still have been saved: like a lost
      // response it leaves the outcome unconfirmed, and a retry resends the
      // same body and Idempotency-Key.
      const exchange = async signal => {
        const init = {method: 'POST', cache: 'no-store', credentials: 'same-origin',
          headers: {'Content-Type': 'application/json', 'Idempotency-Key': submission.key},
          body: submission.body};
        const response = await fetch('/api/feedback', signal ? {...init, signal} : init);
        try { return {response, result: await response.json()}; } catch (_error) { throw new Error(t('feedback.error.unreadable')); }
      };
      const request = window.PhishGuardRequest;
      let response, result;
      try {
        ({response, result} = await (request ? request.run(exchange, {timeout: request.TIMEOUTS.action}) : exchange()));
      } catch (error) {
        throw error?.timedOut ? new Error(t('request.error.timeout')) : error;
      }
      if (!response.ok) {
        // A definite rejection cannot settle an earlier ambiguous attempt.
        if ([400, 413, 422, 429].includes(response.status) && !submission.uncertain) session.retry = null;
        throw new Error(typeof result.detail === 'string' ? result.detail : t('feedback.error.notSaved'));
      }
      // Save the receipt even with no active modal. Rendering remains isolated
      // from sessions belonging to replaced or cleared analysis contexts.
      session.receipt = result.id;
      session.submitted = true;
    } catch (error) {
      if (session.pending !== attempt) return;
      if (session.retry?.sent) session.retry.uncertain = true;
      session.error = (error.message || t('feedback.error.notSaved')) +
        t(session.retry?.sent ? 'feedback.error.unconfirmed' : 'feedback.error.correct');
    } finally {
      if (session.pending === attempt) {
        session.pending = null;
        render(session);
      }
    }
  }
  function setup() {
    $('feedback-form').addEventListener('submit', submit);
    $('feedback-cancel').addEventListener('click', close);
    $('feedback-close').addEventListener('click', close);
    $('feedback-new-report').addEventListener('click', newReport);
    $('feedback-dialog').addEventListener('close', () => { if (!$('feedback-dialog').open) detach(); });
    for (const event of ['input', 'change']) $('feedback-form').addEventListener(event, () => {
      if (active) { if (!active.retry?.sent) active.retry = null; active.revision++; }
    });
    $('feedback-consent').addEventListener('change', () => {
      const allowed = $('feedback-consent').checked && !($('feedback-evaluation-consent-row').hidden);
      $('feedback-evaluation-consent').disabled = !allowed;
      if (!allowed) $('feedback-evaluation-consent').checked = false;
    });
  }
  document.addEventListener('DOMContentLoaded', setup);
  return {set, clear, open};
})();
