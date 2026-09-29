/* ──────────────────────────────────────────────────────────────────────────
   request.js – time limits and cancellation for API requests
   Shared by the homepage (app-core.js, app-config.js, app-metrics.js,
   feedback.js) and the case workspace (cases.js), and loaded before them on
   both pages. It only settles requests; each page words the error itself.
   ────────────────────────────────────────────────────────────────────────── */
'use strict';
window.PhishGuardRequest = (() => {
  // Milliseconds before a request is given up.
  const TIMEOUTS = Object.freeze({
    // Analysis, verification and saves (POST/PATCH). On Vercel a function is
    // stopped after maxDuration (30 s, vercel.json) and the platform answers
    // 504 itself, and verification has a 12 s server deadline, so a live
    // server answers well within this. The rest covers a cold start and a
    // slow upload of an image payload; only a request nothing will ever
    // answer reaches it.
    action: 45000,
    // Small reads (configuration, metrics, the case queue): a live server
    // answers in well under a second.
    read: 15000,
  });

  function stopped(kind) {
    const timedOut = kind === 'timeout';
    const error = new Error(timedOut ? 'The request timed out' : 'The request was cancelled');
    error.name = timedOut ? 'TimeoutError' : 'AbortError';
    error.timedOut = timedOut;
    error.aborted = !timedOut;
    return error;
  }

  // Runs work(signal), which fetches with `signal` and reads the response, and
  // rejects as soon as `timeout` ms pass (error.timedOut) or the caller's
  // `signal` aborts (error.aborted), aborting the fetch and its body. `work` is
  // called synchronously, so the request starts before run() returns.
  // Without AbortController (not a supported browser) there is no time limit.
  function start(work, signal) {
    try { return Promise.resolve(work(signal)); } catch (error) { return Promise.reject(error); }
  }

  function run(work, {timeout = TIMEOUTS.action, signal} = {}) {
    if (typeof AbortController !== 'function') return start(work, signal);
    const controller = new AbortController();
    let stop;
    const halted = new Promise((_resolve, reject) => {
      stop = kind => {
        if (controller.signal.aborted) return;
        reject(stopped(kind));
        controller.abort();
      };
    });
    const cancel = () => stop('abort');
    if (signal?.aborted) cancel();
    else signal?.addEventListener('abort', cancel);
    const timer = timeout > 0 && Number.isFinite(timeout) ? setTimeout(() => stop('timeout'), timeout) : null;
    // The first to settle wins; a fetch that rejects after an abort is ignored.
    return Promise.race([start(work, controller.signal), halted]).finally(() => {
      if (timer !== null) clearTimeout(timer);
      signal?.removeEventListener('abort', cancel);
    });
  }

  return {run, TIMEOUTS};
})();
