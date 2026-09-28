// Bounded MIME metadata matching only. A match does not establish that an
// image was decoded, displayed, or admitted by the separate image budget.
const MAX_NODES = 4096, MAX_DEPTH = 32, MAX_ID = 2048;
const MAX_QUERIES = 4096, MAX_LOOKUP_STEPS = 200000;
const INCOMPLETE = 'CID image references could not be checked within MIME metadata limits; coverage is incomplete.';
const INVALID = 'A CID image reference is malformed; visual coverage is incomplete.';
const MISSING = 'A CID image reference has no matching resource in its MIME scope; visual coverage is incomplete.';
const AMBIGUOUS = 'A CID image reference matches multiple simultaneously available resources; visual coverage is incomplete.';
const NOT_IMAGE = 'A CID image reference points to a non-image resource; visual coverage is incomplete.';
const UNSUPPORTED = 'A CID image reference points to an unsupported image format; visual coverage is incomplete.';
const EMPTY = 'A CID image reference points to an empty image resource; visual coverage is incomplete.';

function identifier(value) {
  // Accept common opaque IDs without requiring an @, but do not guess around
  // controls, whitespace, brackets, or non-ASCII identifiers.
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_ID &&
    /^[\x21-\x7e]+$/.test(value) && !/[<>]/.test(value) ? value : null;
}
function headerID(value) {
  if (typeof value !== 'string' || value.length > MAX_ID + 2) return null;
  const match = /^<([^<>]+)>$/.exec(value.replace(/^[ \t]+|[ \t]+$/g, ''));
  return match ? identifier(match[1]) : null;
}
function referenceID(reference) {
  if (typeof reference !== 'string' || reference.length > 3 * MAX_ID + 4 || !/^cid:/i.test(reference)) return null;
  const encoded = reference.slice(4);
  if (!encoded || /[^\x21-\x7e]|[<>#]|%(?![\da-f]{2})/i.test(encoded)) return null;
  // RFC 2392: decode the URL once; never decode the Content-ID header.
  return identifier(encoded.replace(/%([\da-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16))));
}
const branchGroup = () => ({count: 0, alternatives: new Map()});
function simultaneous(group) {
  let count = group.count;
  for (const branches of group.alternatives.values()) {
    let maximum = 0;
    for (const child of branches.values()) maximum = Math.max(maximum, simultaneous(child));
    count += maximum;
    if (count > 1) return 2;
  }
  return count;
}

export function createCIDResolver(root) {
  const contexts = new WeakMap(), byID = new Map(), cache = new WeakMap();
  let complete = true, nodes = 0, queries = 0, remaining = MAX_LOOKUP_STEPS;
  const stack = [{node: root, related: [], choices: [], depth: 0}];
  while (stack.length) {
    const {node, related, choices, depth} = stack.pop();
    if (!node || typeof node !== 'object' || contexts.has(node) || ++nodes > MAX_NODES || depth > MAX_DEPTH ||
        !Array.isArray(node.childNodes) || typeof node.contentType?.parsed?.value !== 'string') {
      complete = false;
      break;
    }
    const type = node.contentType.parsed.value.toLowerCase();
    const context = {related, choices, scope: related.at(-1) || root};
    contexts.set(node, context);
    const id = headerID(node.contentId);
    if (id) {
      if (!byID.has(id)) byID.set(id, []);
      byID.get(id).push({node, type, ...context});
    }
    // Encapsulated messages get their own resolver when parsed separately.
    // Do not consume subMessage metadata or allow it to satisfy this message.
    if (/^message\/(?:rfc822|global)$/.test(type)) continue;
    if (nodes + stack.length + node.childNodes.length > MAX_NODES) { complete = false; break; }
    const childRelated = type === 'multipart/related' ? [...related, node] : related;
    for (let i = node.childNodes.length - 1; i >= 0; i--) {
      const child = node.childNodes[i];
      stack.push({node: child, related: childRelated, depth: depth + 1,
        choices: type === 'multipart/alternative' ? [...choices, [node, child]] : choices});
    }
  }

  return function resolve(reference, htmlNode) {
    const id = referenceID(reference);
    if (!id) return INVALID;
    if (!complete || !contexts.has(htmlNode)) return INCOMPLETE;
    let saved = cache.get(htmlNode);
    if (!saved) { saved = new Map(); cache.set(htmlNode, saved); }
    if (saved.has(id)) return saved.get(id);
    if (++queries > MAX_QUERIES || remaining <= 0) return INCOMPLETE;
    const html = contexts.get(htmlNode), allowed = new Set(html.related.length ? html.related : [root]);
    const fixed = new Map(html.choices), groups = branchGroup(), candidates = [];
    for (const candidate of byID.get(id) || []) {
      remaining -= 1 + candidate.choices.length;
      if (remaining < 0) return INCOMPLETE;
      if (!allowed.has(candidate.scope) || candidate.choices.some(([alternative, branch]) =>
        fixed.has(alternative) && fixed.get(alternative) !== branch)) continue;
      candidates.push(candidate);
      // Count the maximum number of candidates that can coexist under MIME
      // alternative selections, rather than comparing every candidate pair.
      let group = groups;
      for (const [alternative, branch] of candidate.choices) {
        if (fixed.has(alternative)) continue;
        if (!group.alternatives.has(alternative)) group.alternatives.set(alternative, new Map());
        const branches = group.alternatives.get(alternative);
        if (!branches.has(branch)) branches.set(branch, branchGroup());
        group = branches.get(branch);
      }
      group.count++;
    }
    let warning = null;
    if (!candidates.length) warning = MISSING;
    else if (simultaneous(groups) > 1) warning = AMBIGUOUS;
    else if (candidates.some(item => !/^image\//.test(item.type))) warning = NOT_IMAGE;
    else if (candidates.some(item => !/^image\/(?:png|jpeg|webp)$/.test(item.type))) warning = UNSUPPORTED;
    else if (candidates.some(item => !Number.isSafeInteger(item.node.content?.byteLength) || item.node.content.byteLength <= 0)) warning = EMPTY;
    saved.set(id, warning);
    return warning;
  };
}
