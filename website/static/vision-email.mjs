import PostalMime from './vendor/vision/postal-mime/postal-mime.js';
import {addImage, dataImages} from './vision-core.mjs';
import {createCIDResolver} from './vision-cid.mjs';

const MAX_HTML_PARTS = 64;
const MAX_HTML_CHARS = 2 * 1024 * 1024;
const PARTS_WARNING = 'Independent HTML parts could not be read; visual coverage is incomplete.';
const CID_CONTEXT_WARNING = 'CID image references could not be matched to their MIME context; coverage is incomplete.';

export async function collectEmail(buffer, images, warnings, depth = 0) {
  return collectEmailParts(buffer, images, warnings, depth, {parts: 0, chars: 0, exhausted: false});
}

function htmlNodeGroups(parser) {
  const groups = new Map(), seen = new Set();
  function walk(node, alternative, depth) {
    if (!node || !Array.isArray(node.childNodes) || !node.contentType?.parsed ||
        seen.has(node) || seen.size >= 4096 || depth > 32) throw new Error('Unavailable MIME context');
    seen.add(node);
    if (!node.contentType.multipart && parser.isInlineTextNode(node) && node.contentType.parsed.value === 'text/html') {
      const selector = alternative || node;
      if (!groups.has(selector)) groups.set(selector, []);
      groups.get(selector).push(node);
    }
    if (node.contentType.multipart === 'alternative') alternative = node;
    for (const child of node.childNodes) walk(child, alternative, depth + 1);
  }
  try { walk(parser.root, null, 0); return groups; }
  catch { return new Map(); }
}

function collectHTMLParts(parser, images, warnings, budget) {
  const warn = message => { if (!warnings.includes(message)) warnings.push(message); };
  // PostalMime 3.0.0 joins independent MIME documents in mail.html. Reading
  // its decoded text entries instead keeps unclosed markup from one document
  // from hiding (or manufacturing) an image in the next. Recheck this internal
  // structure when updating the pinned parser; never fall back to joined HTML.
  if (!(parser.textMap instanceof Map)) { warn(PARTS_WARNING); return; }
  // textMap groups alternatives and does not retain each entry's source node.
  // Add context without changing its ordering or the shared image/HTML budgets.
  const groups = htmlNodeGroups(parser), resolveCID = createCIDResolver(parser.root);
  for (const [selector, value] of parser.textMap) {
    if (budget.exhausted) return;
    if (!value || typeof value !== 'object') { warn(PARTS_WARNING); continue; }
    if (value.html === undefined) continue;
    if (!Array.isArray(value.html)) { warn(PARTS_WARNING); continue; }
    for (const [index, entry] of value.html.entries()) {
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
      let source = groups.get(selector)?.[index];
      try { if (source?.getTextContent() !== entry.value) source = null; }
      catch { source = null; }
      dataImages(entry.value, images, warnings,
        reference => source ? resolveCID(reference, source) : CID_CONTEXT_WARNING);
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
