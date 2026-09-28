/* Browser extraction is supplementary evidence; all risk decisions happen on the server. */
'use strict';
window.PhishGuardVision = (() => {
  let active = null;
  let previewURL = null;
  const MAX_BYTES = 2 * 1024 * 1024;
  // cases.html loads this file without i18n.js, so every string keeps its
  // English text inline; i18n.test.mjs checks it matches the dictionary.
  // Worker errors, server warnings and extracted text are shown as received.
  const tr = (key, english, params) => window.PhishGuardI18n ? window.PhishGuardI18n.t(key, params)
    : english.replace(/\{(\w+)\}/g, (match, name) => (params && Object.hasOwn(params, name) ? String(params[name]) : match));
  const levelName = level => window.PhishGuardI18n ? window.PhishGuardI18n.known(`level.${level}`, level) : level;
  // vision-worker.mjs reports progress in English; show it in the page language.
  function progressText(message) {
    const text = String(message);
    if (text === 'Extracting email images…') return tr('vision.progress.extracting', 'Extracting email images…');
    const image = /^Reading image (\d+) of (\d+)…$/.exec(text);
    if (image) return tr('vision.progress.image', 'Reading image {index} of {total}…', {index: image[1], total: image[2]});
    const reading = /^Reading (English|Simplified Chinese|English and Simplified Chinese) text…$/.exec(text);
    if (!reading) return text;
    const language = {
      'English': () => tr('vision.progress.lang.eng', 'English'),
      'Simplified Chinese': () => tr('vision.progress.lang.chi_sim', 'Simplified Chinese'),
      'English and Simplified Chinese': () => tr('vision.progress.lang.mixed', 'English and Simplified Chinese'),
    }[reading[1]]();
    return tr('vision.progress.text', 'Reading {language} text…', {language});
  }
  function releasePreview() {
    if (previewURL) URL.revokeObjectURL(previewURL);
    previewURL = null;
  }
  function cancel() { if (active) { active.stop(); active = null; } }
  function base64(buffer) {
    const bytes = new Uint8Array(buffer); let text = '';
    for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(text);
  }
  async function recognize(file, onProgress = () => {}, language = 'eng', options = {}) {
    cancel();
    if (!['eng', 'chi_sim', 'eng+chi_sim'].includes(language)) throw new Error(tr('vision.error.language', 'Choose a supported OCR language.'));
    if (!file.size || file.size > MAX_BYTES) throw new Error(tr('vision.error.file', 'Choose a nonempty PNG, JPEG, WebP or EML file up to 2 MiB.'));
    const kind = /\.eml$/i.test(file.name) || file.type === 'message/rfc822' ? 'eml' : 'image';
    if (options.enhance === true && kind !== 'image') throw new Error(tr('vision.error.enhanceEml', 'Enhanced recognition supports one standalone image.'));
    // Register before the asynchronous file read, so clear/sign-out cancels reading too.
    let cancelled = false, worker, rejectWork, timer;
    const cancelledError = () => new Error(tr('vision.error.cancelled', 'Recognition cancelled.'));
    const task = {stop() { cancelled = true; clearTimeout(timer); worker?.terminate(); rejectWork?.(cancelledError()); }};
    active = task;
    try {
      const buffer = await file.arrayBuffer();
      if (cancelled) throw cancelledError();
      if (!buffer.byteLength || buffer.byteLength > MAX_BYTES) throw new Error(tr('vision.error.tooLarge', 'File exceeds the 2 MiB limit.'));
      const result = await new Promise((resolve, reject) => {
        rejectWork = reject;
        worker = new Worker('/static/vision-worker.mjs?v=10', {type: 'module'});
        timer = setTimeout(() => { worker.terminate(); reject(new Error(tr('vision.error.timeout', 'Recognition timed out. Try a smaller image.'))); }, 150000);
        worker.onerror = () => reject(new Error(tr('vision.error.start', 'Recognition could not start. Reload the page or try a supported browser.')));
        worker.onmessage = ({data}) => {
          if (cancelled) return;
          if (data.progress) onProgress(progressText(data.progress));
          if (data.error) reject(new Error(data.error));
          if (data.result) resolve(data.result);
        };
        worker.postMessage({buffer, name: file.name, kind, language});
      });
      if (cancelled) throw cancelledError();
      return {...result, ...(kind === 'eml' ? {eml_base64: base64(buffer)} : {}),
        ...(options.enhance === true ? {enhancement: {image_base64: base64(buffer),
          consent: true, include_semantics: options.includeSemantics === true}} : {})};
    } finally { clearTimeout(timer); worker?.terminate(); if (active === task) active = null; }
  }
  function render(target, analysis, originalFile = null) {
    releasePreview();
    if (!target) return;
    target.replaceChildren(); target.hidden = !analysis;
    if (!analysis) return;
    const node = (tag, text) => { const el = document.createElement(tag); el.textContent = text; return el; };
    target.append(node('h3', tr('vision.heading', 'Image & QR evidence')),
      node('p', tr('vision.intro', 'Extracted in your browser; not independently verified. Recognition may miss content and does not assess malware or all image meaning. Links are shown as text and are not opened.')),
      node('p', tr('vision.confidenceNote', 'OCR confidence measures text extraction, not a phishing probability. Successful recognition does not establish that an image is safe.')));
    const STATUS = {
      processed: () => tr('vision.status.processed', 'Recognition completed'),
      partial: () => tr('vision.status.partial', 'Recognition partially completed'),
      failed: () => tr('vision.status.failed', 'Recognition failed'),
      skipped: () => tr('vision.status.skipped', 'Recognition skipped'),
    };
    const OCR_LANGUAGES = {
      eng: () => tr('vision.lang.eng', 'English'),
      chi_sim: () => tr('vision.lang.chi_sim', 'Simplified Chinese'),
      'eng+chi_sim': () => tr('vision.lang.mixed', 'English + Chinese'),
    };
    for (const item of analysis.observations || []) {
      const section = node('section', '');
      const recognition = Object.hasOwn(STATUS, item.status) ? STATUS[item.status]()
        : tr('vision.status.unknown', 'Recognition status unavailable');
      const risk = !item.risk_level || item.risk_level === 'unknown' ? tr('vision.risk.undetermined', 'Risk undetermined')
        : tr('vision.risk.level', 'Risk: {level}', {level: levelName(item.risk_level)});
      section.append(node('h4', item.name), node('p', tr('vision.summary', '{recognition} · {risk} · OCR confidence {confidence}%',
        {recognition, risk, confidence: Math.round(item.ocr_confidence)})));
      const language = Object.hasOwn(OCR_LANGUAGES, item.ocr_language) ? OCR_LANGUAGES[item.ocr_language]()
        : tr('vision.lang.none', 'Not recorded');
      section.append(node('p', tr('vision.ocrLanguage', 'OCR language: {language}', {language})));
      if (!previewURL && originalFile && item.source === 'upload' &&
          item.name === originalFile.name.slice(0, 160) &&
          Number.isSafeInteger(originalFile.size) && originalFile.size > 0 && originalFile.size <= MAX_BYTES &&
          (!originalFile.type || originalFile.type === item.mime_type) &&
          ['image/png', 'image/jpeg', 'image/webp'].includes(item.mime_type) &&
          typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function') {
        previewURL = URL.createObjectURL(originalFile);
        const details = node('details', '');
        details.className = 'visual-original-preview';
        const scroller = node('div', '');
        scroller.className = 'visual-original-preview-scroll';
        const picture = node('img', '');
        picture.src = previewURL;
        picture.alt = tr('vision.preview.alt', 'Original uploaded image: {name}', {name: item.name});
        scroller.append(picture);
        details.append(node('summary', tr('vision.preview.summary', 'Original uploaded image — compare URL characters')),
          node('p', analysis.enhancement
            ? tr('vision.preview.enhanced', 'Enhanced recognition submitted this image for processing. This local preview and original image bytes are not saved with a case.')
            : tr('vision.preview.local', 'This local preview is not sent to the analysis API or saved with a case.')), scroller);
        section.append(details);
      }
      if (Number.isFinite(item.ocr_url_line_confidence))
        section.append(node('p', tr('vision.urlConfidence', 'URL-like line OCR confidence: {confidence}%. Compare the address character by character with the original image; this score does not verify its spelling.',
          {confidence: Math.round(item.ocr_url_line_confidence)})));
      if (item.ml_status === 'available' && Number.isFinite(item.ml_phishing_probability)) {
        const label = item.assessment_method === 'independent-source-max' && item.assessed_source_count > 1
          ? tr('vision.model.highest', 'Highest extracted-source model score') : tr('vision.model.extracted', 'Extracted-text model score');
        section.append(node('p', tr('vision.model.score', '{label}: {score}% phishing risk. Risk assessment also uses rule and link evidence.',
          {label, score: item.ml_phishing_probability})));
      } else {
        const REASONS = {
          insufficient_context: () => tr('vision.model.context', 'Too little readable text for the extracted-text model.'),
          insufficient_feature_coverage: () => tr('vision.model.coverage', 'The extracted text has insufficient model coverage.'),
          unverified_rendering: () => tr('vision.model.rendering', 'The extracted text could not be verified for model analysis.'),
        };
        section.append(node('p', Object.hasOwn(REASONS, item.ml_status) ? REASONS[item.ml_status]()
          : tr('vision.model.unavailable', 'Extracted-text model assessment is unavailable. Review the rule and link evidence.')));
      }
      for (const payload of item.qr_payloads || []) section.append(node('strong', tr('vision.qr', 'QR payload')), node('pre', payload));
      if (item.ocr_text) section.append(node('strong', tr('vision.text', 'Extracted text')), node('pre', item.ocr_text));
      for (const warning of [...new Set([...(item.warnings || []), ...(item.assessment_warnings || [])])]) section.append(node('p', warning));
      target.append(section);
    }
    if (analysis.enhancement) {
      const extra = analysis.enhancement, section = node('section', '');
      section.append(node('h4', tr('vision.enhancement.heading', 'Additional image recognition')));
      if (extra.status === 'available') {
        section.append(node('p', tr('vision.enhancement.ocr', '{engine} {version} · Additional text, not independently verified',
          {engine: extra.ocr.engine, version: extra.ocr.version})), node('pre', extra.ocr.text));
        if (extra.url_disagreement) section.append(node('strong', tr('vision.enhancement.disagree', 'The extractors disagree on visible URLs. Compare both readings against the original image character by character.')));
        if (extra.semantic.status === 'available') {
          section.append(node('p', tr('vision.enhancement.semantic', '{model} · Model-generated observations; not a safety verdict', {model: extra.semantic.model})));
          for (const observation of extra.semantic.observations) section.append(node('p', observation));
          for (const url of extra.semantic.visible_urls) section.append(node('pre', url));
        }
      }
      for (const warning of extra.warnings || []) section.append(node('p', warning));
      target.append(section);
    }
    for (const warning of analysis.warnings || []) target.append(node('p', warning));
    if (!analysis.observations?.length) target.append(node('p', tr('vision.none', 'No image observations were available. Review coverage warnings.')));
  }
  return {recognize, cancel, render, MAX_BYTES};
})();
