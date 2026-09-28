import PostalMime from './vendor/vision/postal-mime/postal-mime.js';
import {addImage, dataImages} from './vision-core.mjs';

const MAX_HTML_PARTS = 64;
const MAX_HTML_CHARS = 2 * 1024 * 1024;
const PARTS_WARNING = 'Independent HTML parts could not be read; visual coverage is incomplete.';

export async function collectEmail(buffer, images, warnings, depth = 0) {
  return collectEmailParts(buffer, images, warnings, depth, {parts: 0, chars: 0, exhausted: false});
}

function collectHTMLParts(parser, images, warnings, budget) {
  const warn = message => { if (!warnings.includes(message)) warnings.push(message); };
  // PostalMime 3.0.0 joins independent MIME documents in mail.html. Reading
  // its decoded text entries instead keeps unclosed markup from one document
  // from hiding (or manufacturing) an image in the next. Recheck this internal
  // structure when updating the pinned parser; never fall back to joined HTML.
  if (!(parser.textMap instanceof Map)) { warn(PARTS_WARNING); return; }
  for (const value of parser.textMap.values()) {
    if (budget.exhausted) return;
    if (!value || typeof value !== 'object') { warn(PARTS_WARNING); continue; }
    if (value.html === undefined) continue;
    if (!Array.isArray(value.html)) { warn(PARTS_WARNING); continue; }
    for (const entry of value.html) {
      if (budget.parts >= MAX_HTML_PARTS) {
        warn('Image extraction reached the HTML part limit; visual coverage is incomplete.');
        budget.exhausted = true;
        return;
      }
      budget.parts++;
      if (entry?.type !== 'text' || typeof entry.value !== 'string') { warn(PARTS_WARNING); continue; }
      if (entry.value.length > MAX_HTML_CHARS - budget.chars) {
        warn('Image extraction reached the HTML text limit; visual coverage is incomplete.');
        budget.exhausted = true;
        return;
      }
      budget.chars += entry.value.length;
      dataImages(entry.value, images, warnings);
    }
  }
}

async function collectEmailParts(buffer, images, warnings, depth, budget) {
  const parser = new PostalMime({maxNestingDepth: 20, maxHeadersSize: 32768, maxRfc822NestingDepth: 2, forceRfc822Attachments: true});
  const mail = await parser.parse(buffer);
  collectHTMLParts(parser, images, warnings, budget);
  for (const item of mail.attachments || []) {
    const content = item.content instanceof ArrayBuffer ? item.content : new Uint8Array(item.content).buffer;
    if (/^image\/(png|jpeg|webp)$/i.test(item.mimeType)) addImage(images, {buffer: content, name: (item.filename || 'inline-image').slice(0, 160), source: 'mime'}, warnings);
    else if (/^image\//i.test(item.mimeType)) warnings.push('Unsupported image attachments were not inspected.');
    else if (/^message\/(rfc822|global)$/i.test(item.mimeType)) {
      if (depth >= 2) warnings.push('Nested message images exceeded the visual nesting limit.');
      else await collectEmailParts(content, images, warnings, depth + 1, budget);
    }
  }
}
