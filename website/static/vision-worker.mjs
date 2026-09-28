import {collectEmail} from './vision-email.mjs';
import Tesseract from './vendor/vision/tesseract.esm.min.js';
import './vendor/vision/jsQR.js';
import {LIMITS, checkImage, decodeQRs, urlLineConfidence} from './vision-core.mjs';

const assets = new URL('./vendor/vision/', import.meta.url).href;
const progress = message => postMessage({progress: message});
function deadline(promise, ms, message) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); })]).finally(() => clearTimeout(timer));
}
self.onmessage = async ({data: {buffer, kind, name, language = 'eng'}}) => {
  let ocr, pendingOCR;
  const warnings = [], observations = [];
  try {
    if (!['eng', 'chi_sim', 'eng+chi_sim'].includes(language)) throw new Error('Choose a supported OCR language.');
    if (!buffer.byteLength || buffer.byteLength > LIMITS.bytes) throw new Error('Choose a nonempty file up to 2 MiB.');
    const images = [];
    if (kind === 'eml') {
      progress('Extracting email images…');
      try { await collectEmail(buffer, images, warnings); }
      catch { warnings.push('Email image extraction failed or exceeded parsing limits; original email analysis is still available.'); }
    } else images.push({buffer, name: name.slice(0, 160), source: 'upload'});
    if (images.length > LIMITS.images) warnings.push('Only the first four images were inspected.');
    const seen = new Set();
    for (const image of images.slice(0, LIMITS.images)) {
      const digest = await crypto.subtle.digest('SHA-256', image.buffer);
      const sha256 = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
      if (seen.has(sha256)) continue;
      seen.add(sha256);
      let info;
      try { info = checkImage(image.buffer); }
      catch (error) { warnings.push(`${image.name}: ${error.message}`.slice(0, 200)); continue; }
      const item = {name: image.name, source: image.source, mime_type: info.mime, sha256,
        status: 'processed', qr_payloads: [], ocr_language: language, ocr_text: '', ocr_confidence: 0,
        ocr_url_line_confidence: null, warnings: []};
      observations.push(item);
      let bitmap;
      try {
        progress(`Reading image ${observations.length} of ${Math.min(images.length, LIMITS.images)}…`);
        bitmap = await createImageBitmap(new Blob([image.buffer], {type: info.mime}));
        if (bitmap.width > LIMITS.side || bitmap.height > LIMITS.side || bitmap.width * bitmap.height > LIMITS.pixels)
          throw new Error('Decoded image exceeds recognition limits.');
        // QR modules can disappear when a large screenshot is reduced for OCR.
        // The original bitmap already passed the 8 MP / 4096-side bounds.
        const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
        const ctx = canvas.getContext('2d', {willReadFrequently: true});
        ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
        bitmap.close(); bitmap = null;
        {
          const qr = decodeQRs(ctx.getImageData(0, 0, canvas.width, canvas.height), self.jsQR);
          item.qr_payloads = qr.values; item.warnings.push(...qr.warnings);
          if (qr.values.length) {
            ctx.putImageData(new ImageData(qr.ocrImage.data, canvas.width, canvas.height), 0, 0);
          }
        }
        const scale = Math.min(1, 2000 / Math.max(canvas.width, canvas.height));
        let textCanvas = canvas;
        if (scale < 1) {
          textCanvas = new OffscreenCanvas(Math.max(1, Math.round(canvas.width * scale)), Math.max(1, Math.round(canvas.height * scale)));
          textCanvas.getContext('2d').drawImage(canvas, 0, 0, textCanvas.width, textCanvas.height);
          // Release the large drawing buffer before starting the OCR worker.
          canvas.width = canvas.height = 1;
          item.warnings.push('QR codes were scanned at original resolution. The image was resized for text recognition; small text may be missed.');
        }
        const languageLabel = {eng: 'English', chi_sim: 'Simplified Chinese', 'eng+chi_sim': 'English and Simplified Chinese'}[language];
        progress(`Reading ${languageLabel} text…`);
        if (!ocr) {
          pendingOCR = Tesseract.createWorker(language, 1, {
            workerPath: assets + 'worker.min.js', corePath: assets + 'core', langPath: assets + 'lang',
            workerBlobURL: false, cacheMethod: 'none', logger: () => {}, errorHandler: () => {},
          });
          ocr = await deadline(pendingOCR, 45000, 'OCR initialization timed out.');
          await ocr.setParameters({tessedit_pageseg_mode: '11'});
        }
        // Encode locally; no object URLs or remote image loads.
        const result = await deadline(ocr.recognize(new Uint8Array(await (await textCanvas.convertToBlob({type: 'image/png'})).arrayBuffer()), {}, {blocks: true}), 20000, 'OCR timed out.');
        item.ocr_text = result.data.text.slice(0, 6000);
        item.ocr_confidence = Math.max(0, Math.min(100, result.data.confidence || 0));
        item.ocr_url_line_confidence = result.data.text.length > 6000 ? null : urlLineConfidence(result.data.blocks);
        if (result.data.text.length > 6000) item.warnings.push('OCR text exceeded 6,000 characters and was truncated.');
        if (item.ocr_text.trim() && item.ocr_confidence < 60) item.warnings.push('OCR confidence is low; verify the extracted text.');
        if (!item.ocr_text.trim() && !item.qr_payloads.length) item.warnings.push('No readable text or QR code was found; image content remains unverified.');
      } catch {
        item.status = item.qr_payloads.length ? 'partial' : 'failed';
        item.warnings.push('Image/OCR recognition failed or timed out; any decoded QR payloads were retained.');
        if (ocr) { await ocr.terminate(); ocr = null; }
        // Terminate an initialization that resolves after its deadline.
        if (pendingOCR) pendingOCR.then(worker => worker.terminate()).catch(() => {});
      } finally { bitmap?.close(); }
      if (item.warnings.length && item.status === 'processed') item.status = 'partial';
      item.warnings = item.warnings.slice(0, 6);
    }
    if (kind !== 'eml' && !observations.length && !warnings.length) warnings.push('No supported image content could be inspected.');
    const uniqueWarnings = [...new Set(warnings)];
    if (uniqueWarnings.length > 8) uniqueWarnings.splice(7, Infinity, 'Additional recognition warnings were omitted; coverage is incomplete.');
    postMessage({result: {observations, warnings: uniqueWarnings}});
  } catch (error) { postMessage({error: error.message || 'Image recognition failed.'}); }
  finally { if (ocr) await ocr.terminate(); self.close(); }
};
