// Pure syntax parsing in the worker: no DOM insertion, scripts or URL fetching.
import {Parser, defaultTreeAdapter} from './vendor/vision/html-parser.mjs';
import {parse as parseCSS, walk as walkCSS, ident} from './vendor/vision/css-parser.mjs';

const MAX_HTML = 2 * 1024 * 1024;
const MAX_NODES = 20000;
const INERT = new Set(['script', 'template', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'plaintext']);
const CSS_IMAGES = /^(?:(?:-webkit-)?(?:background(?:-image)?|border-image(?:-source)?|mask(?:-image)?|mask-box-image(?:-source)?)|mask-border(?:-source)?|list-style(?:-image)?|shape-outside|content|cursor|--.+)$/i;
const CSS_WARNING = 'CSS image candidates were inspected without verifying selectors, cascade or client rendering.';
const CONDITIONAL_WARNING = 'Conditional email images have client-dependent rendering; coverage is incomplete.';

class HTMLLimitError extends Error {}
function boundedHTML(text, locations, warnings) {
  let document, created = 0, openElements = 0;
  const count = () => {
    if (++created > MAX_NODES) throw new HTMLLimitError('HTML image extraction reached its node limit; coverage is incomplete.');
  };
  const checkParent = parent => {
    let depth = 0;
    for (let node = parent; node; node = node.parentNode)
      if (++depth > 128) throw new HTMLLimitError('HTML image extraction reached its nesting limit; coverage is incomplete.');
  };
  // Enforce limits during tree construction. A post-parse traversal alone
  // cannot bound parse5's work on deeply nested, attacker-controlled markup.
  const adapter = {...defaultTreeAdapter,
    createDocument() { document = defaultTreeAdapter.createDocument(); return document; },
    createDocumentFragment() { count(); return defaultTreeAdapter.createDocumentFragment(); },
    createElement(...args) { count(); return defaultTreeAdapter.createElement(...args); },
    createCommentNode(...args) { count(); return defaultTreeAdapter.createCommentNode(...args); },
    insertText(...args) { count(); defaultTreeAdapter.insertText(...args); },
    insertTextBefore(...args) { count(); defaultTreeAdapter.insertTextBefore(...args); },
    onItemPush() {
      // Template fragments reset parent chains but still occupy the parser stack.
      if (++openElements > 128)
        throw new HTMLLimitError('HTML image extraction reached its nesting limit; coverage is incomplete.');
    },
    onItemPop() { openElements--; },
    appendChild(parent, child) { checkParent(parent); defaultTreeAdapter.appendChild(parent, child); },
    insertBefore(parent, child, reference) { checkParent(parent); defaultTreeAdapter.insertBefore(parent, child, reference); },
  };
  try {
    const parser = new Parser({scriptingEnabled: false, sourceCodeLocationInfo: locations, treeAdapter: adapter});
    // These instance hooks are specific to pinned parse5 8.0.1. Attribute
    // deduplication occurs before treeAdapter callbacks and is otherwise
    // quadratic for a huge start tag. Recheck these hooks on parser upgrades.
    const leaveName = parser.tokenizer._leaveAttrName;
    if (typeof leaveName !== 'function') throw new Error('Parser budget hook unavailable');
    let attributeToken, attributes = 0;
    parser.tokenizer._leaveAttrName = function() {
      if (this.currentToken !== attributeToken) { attributeToken = this.currentToken; attributes = 0; }
      if (++attributes > 256) throw new HTMLLimitError('HTML image extraction reached its attribute limit; coverage is incomplete.');
      return leaveName.call(this);
    };
    parser.tokenizer.write(text, true);
    return parser.document;
  }
  catch (error) {
    if (!(error instanceof HTMLLimitError) || !document) throw error;
    warnings.add(error.message);
    return document; // Preserve earlier candidates; the unread remainder is incomplete.
  }
}

// URL tokens may contain commas (notably data URIs). Descriptors end at an
// unparenthesized comma, following the HTML srcset tokenization boundary.
function srcsetURLs(value) {
  const urls = [];
  let position = 0;
  while (position < value.length) {
    while (/[\t\n\f\r ,]/.test(value[position] || '') && position < value.length) position++;
    const start = position;
    while (position < value.length && !/[\t\n\f\r ]/.test(value[position])) position++;
    const token = value.slice(start, position);
    if (token.replace(/,+$/, '')) urls.push(token.replace(/,+$/, ''));
    if (!token.endsWith(',')) {
      let depth = 0;
      while (position < value.length) {
        const char = value[position++];
        if (char === '(') depth++;
        else if (char === ')') depth = Math.max(0, depth - 1);
        else if (char === ',' && depth === 0) break;
      }
    }
  }
  return urls;
}

export function imageReferences(html) {
  const urls = new Set(), warnings = new Set();
  const add = value => { if (value?.trim()) urls.add(value.trim()); };
  if (typeof html !== 'string' || html.length > MAX_HTML)
    return {urls: [], warnings: ['HTML image extraction exceeded the input limit; coverage is incomplete.']};

  function css(value, context) {
    try {
      const tree = parseCSS(value, {context, parseCustomProperty: true,
        onParseError: () => warnings.add('Some CSS could not be parsed; image coverage is incomplete.')});
      walkCSS(tree, {
        visit: 'Declaration',
        enter(declaration) {
          if (!CSS_IMAGES.test(ident.decode(declaration.property))) return;
          walkCSS(declaration.value, function(node) {
            // css-tree already decodes URL/string escapes exactly once.
            if (node.type === 'Url' || (node.type === 'String' &&
                /^(?:(?:-webkit-)?image-set|url)$/i.test(ident.decode(this.function?.name || '')))) {
              add(node.value); warnings.add(CSS_WARNING);
            }
            if (node.type === 'Raw') warnings.add('Some CSS image values could not be parsed; coverage is incomplete.');
          });
        },
      });
    } catch { warnings.add('CSS image parsing failed; image coverage is incomplete.'); }
  }

  function scan(text, expand) {
    const tree = boundedHTML(text, expand, warnings);
    const stack = [{node: tree, depth: 0}], replacements = [];
    let visited = 0;
    while (stack.length) {
      if (++visited > MAX_NODES) { warnings.add('HTML image extraction reached its node limit; coverage is incomplete.'); break; }
      const {node, depth} = stack.pop();
      if (depth > 128) { warnings.add('HTML image extraction reached its nesting limit; coverage is incomplete.'); continue; }
      const tag = node.tagName;
      if (INERT.has(tag)) continue;
      if (node.nodeName === '#comment') {
        const opening = /^\s*\[if\s+([^\]]+)\]>/i.exec(node.data);
        if (opening && /\bmso\b/i.test(opening[1])) {
          const condition = opening[1].replace(/\s/g, '').toLowerCase();
          const notMSO = (condition.match(/\(/g) || []).length === (condition.match(/\)/g) || []).length &&
            /^\(*(?:!|not)\(*mso\)*$/.test(condition);
          if (!notMSO) {
            warnings.add(CONDITIONAL_WARNING);
            const match = /^\s*\[if\s+[^\]]+\]>([\s\S]*?)<!\[endif\]\s*$/i.exec(node.data);
            if (expand && match && node.sourceCodeLocation) replacements.push({
              start: node.sourceCodeLocation.startOffset, end: node.sourceCodeLocation.endOffset, content: match[1],
            });
          }
        }
        continue;
      }
      // parse5 retains the first duplicate attribute, even when it is empty.
      const attrs = new Map((node.attrs || []).filter(attr => !attr.prefix).map(attr => [attr.name, attr.value]));
      if (tag === 'img' || tag === 'v:imagedata' || tag === 'v:fill') add(attrs.get('src'));
      if (tag === 'input' && attrs.get('type')?.toLowerCase() === 'image') add(attrs.get('src'));
      if (tag === 'video') add(attrs.get('poster'));
      if (tag === 'image') add(attrs.has('href') ? attrs.get('href') : node.attrs?.find(attr => attr.prefix === 'xlink' && attr.name === 'href')?.value);
      if (tag === 'img' || (tag === 'source' && node.parentNode?.tagName === 'picture')) {
        const srcset = attrs.get('srcset');
        if (srcset) {
          srcsetURLs(srcset).forEach(add);
          warnings.add('Responsive image candidates were inspected without verifying the client-selected image.');
        }
      }
      if (['body', 'table', 'td', 'th'].includes(tag)) add(attrs.get('background'));
      if (attrs.get('style')) css(attrs.get('style'), 'declarationList');
      if (tag === 'style' && (!attrs.get('type')?.trim() || attrs.get('type').trim().toLowerCase() === 'text/css'))
        css((node.childNodes || []).map(child => child.value || '').join(''), 'stylesheet');
      const children = node.childNodes || [];
      for (let i = children.length - 1; i >= 0; i--) stack.push({node: children[i], depth: depth + 1});
    }
    return replacements;
  }

  try {
    const replacements = scan(html, true).sort((a, b) => a.start - b.start);
    if (replacements.length) {
      // Union ordinary and one expanded MSO interpretation. Conditional ghost
      // tables may span several comments; replacing AST comment ranges retains
      // that context. Never expand strings or recurse indefinitely into comments.
      const parts = [];
      let offset = 0;
      for (const replacement of replacements) {
        parts.push(html.slice(offset, replacement.start), replacement.content);
        offset = replacement.end;
      }
      parts.push(html.slice(offset));
      scan(parts.join(''), false);
    }
  } catch { warnings.add('HTML image parsing failed; image coverage is incomplete.'); }
  return {urls: [...urls], warnings: [...warnings]};
}
