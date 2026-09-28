import PostalMime from './vendor/vision/postal-mime/postal-mime.js';
import {addImage, dataImages} from './vision-core.mjs';

export async function collectEmail(buffer, images, warnings, depth = 0) {
  const mail = await PostalMime.parse(buffer, {maxNestingDepth: 20, maxHeadersSize: 32768, maxRfc822NestingDepth: 2, forceRfc822Attachments: true});
  dataImages(mail.html || '', images, warnings);
  for (const item of mail.attachments || []) {
    const content = item.content instanceof ArrayBuffer ? item.content : new Uint8Array(item.content).buffer;
    if (/^image\/(png|jpeg|webp)$/i.test(item.mimeType)) addImage(images, {buffer: content, name: (item.filename || 'inline-image').slice(0, 160), source: 'mime'}, warnings);
    else if (/^image\//i.test(item.mimeType)) warnings.push('Unsupported image attachments were not inspected.');
    else if (/^message\/(rfc822|global)$/i.test(item.mimeType)) {
      if (depth >= 2) warnings.push('Nested message images exceeded the visual nesting limit.');
      else await collectEmail(content, images, warnings, depth + 1);
    }
  }
}
