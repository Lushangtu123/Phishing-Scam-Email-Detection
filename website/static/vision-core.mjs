// Pure helpers shared by the worker and tests. No DOM parsing or URL fetching.
export const LIMITS = Object.freeze({bytes: 2 * 1024 * 1024, images: 4, pixels: 8000000, side: 4096, qr: 8});
export function imageInfo(buffer) {
  const b = new Uint8Array(buffer), v = new DataView(buffer);
  const ascii = (i, n) => String.fromCharCode(...b.slice(i, i + n));
  if (b.length >= 33 && [137, 80, 78, 71, 13, 10, 26, 10].every((value, i) => b[i] === value) &&
      v.getUint32(8) === 13 && ascii(12, 4) === 'IHDR') {
    const info = {mime: 'image/png', width: v.getUint32(16), height: v.getUint32(20)};
    let animated = false, hasImageData = false;
    // APNG declares animation in acTL before IDAT. Inspect actual chunk
    // boundaries, including CRC bytes, rather than matching payload strings.
    // This validates framing, not CRC checksums or decoded pixels.
    for (let i = 33; i + 12 <= b.length;) {
      const size = v.getUint32(i), tag = ascii(i + 4, 4), end = i + 12 + size;
      if (size > 0x7fffffff || end > b.length || tag === 'IHDR') break;
      if (tag === 'acTL') {
        if (size !== 8 || !v.getUint32(i + 8) || hasImageData || animated) break;
        animated = true;
      }
      if (tag === 'IDAT') hasImageData = true;
      if (tag === 'IEND') {
        if (size !== 0 || !hasImageData) break;
        return animated ? {...info, animated: true} : info;
      }
      i = end;
    }
  }
  if (b.length >= 12 && ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') {
    for (let i = 12; i + 8 <= b.length;) {
      const tag = ascii(i, 4), size = v.getUint32(i + 4, true), p = i + 8;
      if (p + size > b.length) break;
      const u24 = n => b[n] | b[n + 1] << 8 | b[n + 2] << 16;
      if (tag === 'VP8X' && size >= 10) return {mime: 'image/webp', width: u24(p + 4) + 1, height: u24(p + 7) + 1, animated: Boolean(b[p] & 2)};
      if (tag === 'VP8 ' && size >= 10) return {mime: 'image/webp', width: v.getUint16(p + 6, true) & 0x3fff, height: v.getUint16(p + 8, true) & 0x3fff};
      if (tag === 'VP8L' && size >= 5 && b[p] === 47) return {mime: 'image/webp', width: 1 + (b[p + 1] | (b[p + 2] & 63) << 8), height: 1 + (b[p + 2] >> 6 | b[p + 3] << 2 | (b[p + 4] & 15) << 10)};
      i = p + size + (size & 1);
    }
  }
  if (b.length >= 4 && b[0] === 255 && b[1] === 216) {
    for (let i = 2; i + 3 < b.length;) {
      if (b[i++] !== 255) break;
      while (b[i] === 255) i++;
      const marker = b[i++];
      if (marker === 217 || marker === 218) break;
      if (marker === 1 || marker >= 208 && marker <= 215) continue;
      if (i + 2 > b.length) break;
      const size = v.getUint16(i);
      if (size < 2 || i + size > b.length) break;
      if ([192, 193, 194, 195, 197, 198, 199, 201, 202, 203, 205, 206, 207].includes(marker) && size >= 8)
        return {mime: 'image/jpeg', height: v.getUint16(i + 3), width: v.getUint16(i + 5)};
      i += size;
    }
  }
  throw new Error('Unsupported or damaged image. Use PNG, JPEG or WebP.');
}
export function checkImage(buffer) {
  if (!buffer.byteLength || buffer.byteLength > LIMITS.bytes) throw new Error('Image must be nonempty and at most 2 MiB.');
  const info = imageInfo(buffer);
  if (!info.width || !info.height || info.width > LIMITS.side || info.height > LIMITS.side || info.width * info.height > LIMITS.pixels)
    throw new Error('Image exceeds 4,096 pixels per side or 8 megapixels.');
  if (info.animated) throw new Error(`Animated ${info.mime === 'image/png' ? 'PNG' : 'WebP'} is not supported; export a still image.`);
  return info;
}
export function decodeQRs(image, decode) {
  const {width, height} = image, data = new Uint8ClampedArray(image.data), values = [], warnings = [];
  // jsQR may confuse finder patterns when several codes occupy one image.
  // Overlapping quadrants supply a bounded second pass without fetching targets.
  const regions = [{x: 0, y: 0, w: width, h: height}];
  const rw = Math.ceil(width * .6), rh = Math.ceil(height * .6);
  for (const y of [0, height - rh]) for (const x of [0, width - rw]) regions.push({x, y, w: rw, h: rh});
  let found = 0;
  for (const region of regions) {
    while (found < LIMITS.qr) {
      const pixels = new Uint8ClampedArray(region.w * region.h * 4);
      for (let y = 0; y < region.h; y++) pixels.set(data.subarray(((region.y + y) * width + region.x) * 4, ((region.y + y) * width + region.x + region.w) * 4), y * region.w * 4);
      const qr = decode(pixels, region.w, region.h, {inversionAttempts: 'attemptBoth'});
      if (!qr) break;
      found++;
      if (qr.data.length > 2048) warnings.push('QR payload exceeded 2,048 characters and was truncated.');
      if (!values.includes(qr.data.slice(0, 2048))) values.push(qr.data.slice(0, 2048));
      // Mask every decoded location, including duplicate payloads and quadrant
      // detections. An axis-aligned box would erase text beside rotated codes.
      const points = [qr.location.topLeftCorner, qr.location.topRightCorner, qr.location.bottomRightCorner, qr.location.bottomLeftCorner]
        .map(p => ({x: p.x + region.x, y: p.y + region.y}));
      const top = Math.max(0, Math.floor(Math.min(...points.map(p => p.y))));
      const bottom = Math.min(height, Math.ceil(Math.max(...points.map(p => p.y))));
      for (let y = top; y < bottom; y++) {
        const crossings = [];
        for (let i = 0; i < points.length; i++) {
          const a = points[i], b = points[(i + 1) % points.length], scan = y + .5;
          if ((a.y <= scan && b.y > scan) || (b.y <= scan && a.y > scan))
            crossings.push(a.x + (scan - a.y) * (b.x - a.x) / (b.y - a.y));
        }
        crossings.sort((a, b) => a - b);
        for (let i = 0; i + 1 < crossings.length; i += 2) {
          const left = Math.min(width, Math.max(0, Math.floor(crossings[i]))), right = Math.max(0, Math.min(width, Math.ceil(crossings[i + 1])));
          if (right > left) data.fill(255, (y * width + left) * 4, (y * width + right) * 4);
        }
      }
    }
    if (found === LIMITS.qr) { warnings.push('QR scan reached the eight-code limit; additional codes may be uninspected.'); break; }
  }
  // The caller may OCR this copy; original pixels and literal payloads survive.
  return {values, warnings: [...new Set(warnings)], ocrImage: {width, height, data}};
}
const URL_LIKE_LINE = /(?:\b(?:https?|httbs?)\s*[:：]\s*[/／]?|(?:[a-z0-9-]+\.)+(?:[a-z0-9-]+[a-z][a-z0-9-]*|[a-z][a-z0-9-]+)(?=\/|\b))/i;
export function urlLineConfidence(blocks) {
  // Tesseract's page confidence can hide a misread address on one otherwise
  // clear page. Retain only the lowest URL-like line score, never its spelling.
  let lowest = null;
  for (const block of blocks || []) for (const paragraph of block.paragraphs || [])
    for (const line of paragraph.lines || []) {
      if (typeof line.text !== 'string' || !URL_LIKE_LINE.test(line.text) ||
          !Number.isFinite(line.confidence) || line.confidence < 0 || line.confidence > 100) continue;
      lowest = lowest === null ? line.confidence : Math.min(lowest, line.confidence);
    }
  return lowest;
}
export function addImage(images, image, warnings) {
  // Compare original bytes before applying the shared budget. Retaining at
  // most four candidates bounds comparisons across inline and nested parts.
  const bytes = new Uint8Array(image.buffer);
  if (images.some(item => {
    if (item.buffer.byteLength !== bytes.length) return false;
    const other = new Uint8Array(item.buffer);
    for (let i = 0; i < bytes.length; i++) if (bytes[i] !== other[i]) return false;
    return true;
  })) return;
  if (images.length >= LIMITS.images) {
    const warning = 'Image extraction reached the four-image limit; additional distinct images were not inspected visually.';
    if (!warnings.includes(warning)) warnings.push(warning);
    return;
  }
  images.push(image);
}
export function dataImages(html, images = [], warnings = []) {
  // Scan strings only. Email HTML is never inserted into a document or fetched.
  for (const match of html.matchAll(/data:image\/(png|jpeg|webp);base64,([a-z0-9+/=]+)/gi)) {
    try {
      const text = atob(match[2]);
      if (text.length > LIMITS.bytes) throw new Error();
      addImage(images, {name: `inline-image-${images.length + 1}`, source: 'data-uri', buffer: Uint8Array.from(text, c => c.charCodeAt(0)).buffer}, warnings);
    } catch { warnings.push('An inline image could not be decoded within the size limit.'); }
  }
  if (/(?:src|srcset|background|url\s*\()[^<>]{0,40}(?:https?:)?\/\//i.test(html)) warnings.push('Remote images were not downloaded or inspected.');
  if (/data:image\/(?!png[;,]|jpeg[;,]|webp[;,])/i.test(html)) warnings.push('Unsupported inline image formats were not inspected.');
  return {images, warnings};
}
