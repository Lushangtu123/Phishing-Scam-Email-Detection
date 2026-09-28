/* Browser extraction is supplementary evidence; all risk decisions happen on the server. */
'use strict';
window.PhishGuardVision = (() => {
  let active = null;
  let previewURL = null;
  const MAX_BYTES = 2 * 1024 * 1024;
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
    if (!['eng', 'chi_sim', 'eng+chi_sim'].includes(language)) throw new Error('Choose a supported OCR language.');
    if (!file.size || file.size > MAX_BYTES) throw new Error('Choose a nonempty PNG, JPEG, WebP or EML file up to 2 MiB.');
    const kind = /\.eml$/i.test(file.name) || file.type === 'message/rfc822' ? 'eml' : 'image';
    if (options.enhance === true && kind !== 'image') throw new Error('Enhanced recognition supports one standalone image.');
    // Register before the asynchronous file read, so clear/sign-out cancels reading too.
    let cancelled = false, worker, rejectWork, timer;
    const task = {stop() { cancelled = true; clearTimeout(timer); worker?.terminate(); rejectWork?.(new Error('Recognition cancelled.')); }};
    active = task;
    try {
      const buffer = await file.arrayBuffer();
      if (cancelled) throw new Error('Recognition cancelled.');
      if (!buffer.byteLength || buffer.byteLength > MAX_BYTES) throw new Error('File exceeds the 2 MiB limit.');
      const result = await new Promise((resolve, reject) => {
        rejectWork = reject;
        worker = new Worker('/static/vision-worker.mjs?v=7', {type: 'module'});
        timer = setTimeout(() => { worker.terminate(); reject(new Error('Recognition timed out. Try a smaller image.')); }, 150000);
        worker.onerror = () => reject(new Error('Recognition could not start. Reload the page or try a supported browser.'));
        worker.onmessage = ({data}) => {
          if (cancelled) return;
          if (data.progress) onProgress(data.progress);
          if (data.error) reject(new Error(data.error));
          if (data.result) resolve(data.result);
        };
        worker.postMessage({buffer, name: file.name, kind, language});
      });
      if (cancelled) throw new Error('Recognition cancelled.');
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
    target.append(node('h3', 'Image & QR evidence'), node('p', 'Extracted in your browser; not independently verified. Recognition may miss content and does not assess malware or all image meaning. Links are shown as text and are not opened.'),
      node('p', 'OCR confidence measures text extraction, not a phishing probability. Successful recognition does not establish that an image is safe.'));
    for (const item of analysis.observations || []) {
      const section = node('section', '');
      const recognition = {processed:'Recognition completed', partial:'Recognition partially completed',
        failed:'Recognition failed', skipped:'Recognition skipped'}[item.status] || 'Recognition status unavailable';
      const risk = !item.risk_level || item.risk_level === 'unknown' ? 'Risk undetermined' : `Risk: ${item.risk_level}`;
      section.append(node('h4', item.name), node('p', `${recognition} · ${risk} · OCR confidence ${Math.round(item.ocr_confidence)}%`));
      const language = {eng: 'English', chi_sim: 'Simplified Chinese', 'eng+chi_sim': 'English + Chinese'}[item.ocr_language];
      section.append(node('p', `OCR language: ${language || 'Not recorded'}`));
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
        picture.alt = `Original uploaded image: ${item.name}`;
        scroller.append(picture);
        details.append(node('summary', 'Original uploaded image — compare URL characters'),
          node('p', analysis.enhancement
            ? 'Enhanced recognition submitted this image for processing. This local preview and original image bytes are not saved with a case.'
            : 'This local preview is not sent to the analysis API or saved with a case.'), scroller);
        section.append(details);
      }
      if (Number.isFinite(item.ocr_url_line_confidence))
        section.append(node('p', `URL-like line OCR confidence: ${Math.round(item.ocr_url_line_confidence)}%. Compare the address character by character with the original image; this score does not verify its spelling.`));
      if (item.ml_status === 'available' && Number.isFinite(item.ml_phishing_probability)) {
        section.append(node('p', `Extracted-text model score: ${item.ml_phishing_probability}% phishing risk. Risk assessment also uses rule and link evidence.`));
      } else {
        const reason = {insufficient_context:'Too little readable text for the extracted-text model.',
          insufficient_feature_coverage:'The extracted text has insufficient model coverage.',
          unverified_rendering:'The extracted text could not be verified for model analysis.'}[item.ml_status];
        section.append(node('p', reason || 'Extracted-text model assessment is unavailable. Review the rule and link evidence.'));
      }
      for (const payload of item.qr_payloads || []) section.append(node('strong', 'QR payload'), node('pre', payload));
      if (item.ocr_text) section.append(node('strong', 'Extracted text'), node('pre', item.ocr_text));
      for (const warning of [...new Set([...(item.warnings || []), ...(item.assessment_warnings || [])])]) section.append(node('p', warning));
      target.append(section);
    }
    if (analysis.enhancement) {
      const extra = analysis.enhancement, section = node('section', '');
      section.append(node('h4', 'Additional image recognition'));
      if (extra.status === 'available') {
        section.append(node('p', `${extra.ocr.engine} ${extra.ocr.version} · Additional text, not independently verified`),
          node('pre', extra.ocr.text));
        if (extra.url_disagreement) section.append(node('strong', 'The extractors disagree on visible URLs. Compare both readings against the original image character by character.'));
        if (extra.semantic.status === 'available') {
          section.append(node('p', `${extra.semantic.model} · Model-generated observations; not a safety verdict`));
          for (const observation of extra.semantic.observations) section.append(node('p', observation));
          for (const url of extra.semantic.visible_urls) section.append(node('pre', url));
        }
      }
      for (const warning of extra.warnings || []) section.append(node('p', warning));
      target.append(section);
    }
    for (const warning of analysis.warnings || []) target.append(node('p', warning));
    if (!analysis.observations?.length) target.append(node('p', 'No image observations were available. Review coverage warnings.'));
  }
  return {recognize, cancel, render, MAX_BYTES};
})();
