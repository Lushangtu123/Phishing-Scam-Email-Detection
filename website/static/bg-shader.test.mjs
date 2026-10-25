import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {LIBRARY, PALETTES, PARAMS, READY_CLASS, colorsFor, startBackgroundShader, uniformsFor} from './bg-shader.mjs';

const source = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');

class FakeEventTarget {
  constructor() { this.listeners = {}; }
  addEventListener(type, listener) { (this.listeners[type] ??= new Set()).add(listener); }
  removeEventListener(type, listener) { this.listeners[type]?.delete(listener); }
  dispatch(type) { for (const listener of [...(this.listeners[type] ?? [])]) listener({type}); }
  count(type) { return this.listeners[type]?.size ?? 0; }
}

class FakeCanvas extends FakeEventTarget {
  constructor(container) { super(); this.container = container; this.width = 300; this.lost = 0; }
  getContext() { return {getExtension: () => ({loseContext: () => { this.lost++; }})}; }
  remove() { this.container.canvases = this.container.canvases.filter(canvas => canvas !== this); }
}

function fakePage({theme = 'dark', reducedMotion = false, saveData, withMatchMedia = true, forcedColors = false,
  readyState = 'complete', globals = {}} = {}) {
  const classes = new Set();
  const root = {dataset: {theme}, classList: {add: name => classes.add(name), remove: name => classes.delete(name)}};
  const container = {
    canvases: [], attributes: {},
    querySelectorAll: selector => (selector === 'canvas' ? container.canvases : []),
    setAttribute(name, value) { this.attributes[name] = value; },
    removeAttribute(name) { delete this.attributes[name]; },
  };
  const queries = {};
  const media = query => (queries[query] ??= Object.assign(new FakeEventTarget(), {
    matches: (query.includes('reduced-motion') && reducedMotion) || (query.includes('forced-colors') && forcedColors),
  }));
  const observers = [];
  class FakeMutationObserver {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe(target, options) { this.target = target; this.options = options; }
    disconnect() { this.disconnected = true; }
  }
  const connection = saveData === undefined ? undefined : Object.assign(new FakeEventTarget(), {saveData});
  const win = Object.assign(new FakeEventTarget(), {
    WebGL2RenderingContext: function WebGL2RenderingContext() {},
    ResizeObserver: function ResizeObserver() {},
    visualViewport: {},
    MutationObserver: FakeMutationObserver,
    requestAnimationFrame: callback => setImmediate(callback),
    setTimeout: (callback, ms) => setTimeout(callback, ms),
    navigator: {connection},
    ...(withMatchMedia ? {matchMedia: media} : {}),
    ...globals,
  });
  const doc = {readyState, documentElement: root, querySelector: selector => (selector === '.bg-shader' ? container : null)};
  const setTheme = next => {
    root.dataset.theme = next;
    for (const observer of observers) if (!observer.disconnected) observer.callback([{attributeName: 'data-theme'}]);
  };
  return {win, doc, root, classes, container, queries, media, observers, connection, setTheme};
}

// Stands in for ShaderMount: prepends a canvas like the real one, then "draws" after `drawAfter` frames.
function fakeLibrary({throwInConstructor = false, drawAfter = 1, failLoad = false} = {}) {
  const mounts = [];
  const canvases = [];
  class ShaderMount {
    constructor(parent, fragmentShader, uniforms, contextAttributes, speed, frame, minPixelRatio, maxPixelCount) {
      Object.assign(this, {parent, fragmentShader, uniforms, contextAttributes, speed, frame, minPixelRatio, maxPixelCount});
      this.calls = [];
      this.canvasElement = new FakeCanvas(parent);
      parent.canvases.unshift(this.canvasElement);
      canvases.push(this.canvasElement);
      if (throwInConstructor) throw new Error('Paper Shaders: WebGL is not supported in this browser');
      parent.setAttribute('data-paper-shader', '');
      parent.paperShaderMount = this;
      this.program = {};
      this.released = 0;
      this.gl = {isContextLost: () => this.released > 0, getExtension: () => ({loseContext: () => { this.released++; }})};
      this.resolutionChanged = true;
      let frames = 0;
      const tick = () => { if (++frames >= drawAfter) this.resolutionChanged = false; else setImmediate(tick); };
      if (drawAfter !== Infinity) setImmediate(tick);
      mounts.push(this);
    }
    setUniforms(uniforms) { this.calls.push(['setUniforms', uniforms]); }
    setSpeed(speed) { this.calls.push(['setSpeed', speed]); this.speed = speed; }
    dispose() {
      this.disposed = true;
      this.canvasElement.remove();
      this.parent.removeAttribute('data-paper-shader');
      delete this.parent.paperShaderMount;
    }
  }
  let loads = 0;
  const load = async () => {
    loads++;
    if (failLoad) throw new TypeError('Failed to fetch dynamically imported module');
    return [{ShaderMount}, {meshGradientFragmentShader: '#version 300 es\n// mesh gradient'}];
  };
  return {load, mounts, canvases, loads: () => loads};
}

const start = (page, library, options = {}) => startBackgroundShader({
  window: page.win, document: page.doc, load: library.load, whenReady: async () => {}, ...options,
});

test('without WebGL2, ResizeObserver or visualViewport, or in forced colours, nothing loads and the colour fields stay', async () => {
  for (const globals of [{WebGL2RenderingContext: undefined}, {ResizeObserver: undefined}, {visualViewport: undefined}]) {
    const page = fakePage({globals});
    const library = fakeLibrary();
    assert.equal(await start(page, library), null);
    assert.equal(library.loads(), 0, 'the library is not even fetched');
    assert.deepEqual([...page.classes], []);
  }
  const page = fakePage({forcedColors: true});
  const library = fakeLibrary();
  assert.equal(await start(page, library), null);
  assert.equal(library.loads(), 0);
});

test('a constructor error (no WebGL2 context) removes the canvas it left, releases it, and keeps the fields', async () => {
  const page = fakePage();
  const library = fakeLibrary({throwInConstructor: true});
  assert.equal(await start(page, library), null);
  assert.equal(library.canvases.length, 1);
  assert.deepEqual(page.container.canvases, []);
  assert.equal(library.canvases[0].lost, 1, 'its WebGL context (if any) is released');
  assert.deepEqual(page.container.attributes, {});
  assert.equal(page.container.paperShaderMount, undefined);
  assert.deepEqual([...page.classes], []);
});

test('a failed library fetch, or a shader that never draws, leaves the page as it was', async () => {
  const fetchFailure = fakePage();
  assert.equal(await start(fetchFailure, fakeLibrary({failLoad: true})), null);
  assert.deepEqual([...fetchFailure.classes], []);

  const page = fakePage();
  const library = fakeLibrary({drawAfter: Infinity});
  assert.equal(await start(page, library, {maxFrames: 5}), null);
  const [mount] = library.mounts;
  assert.ok(mount.disposed, 'disposed');
  assert.equal(mount.released, 1, 'and its WebGL context released');
  assert.deepEqual(page.container.canvases, []);
  assert.deepEqual([...page.classes], []);
  assert.equal(page.queries['(prefers-reduced-motion: reduce)'].count('change'), 0, 'listeners removed');
  assert.ok(page.observers.every(observer => observer.disconnected));
});

test('a mount that draws its first frame hides the colour fields; the shader gets the theme palette and limits', async () => {
  const page = fakePage();
  const library = fakeLibrary({drawAfter: 3});
  const result = await start(page, library);
  assert.ok(result);
  assert.deepEqual([...page.classes], [READY_CLASS]);
  const [mount] = library.mounts;
  assert.equal(mount.parent, page.container);
  assert.equal(mount.speed, PARAMS.speed);
  assert.equal(mount.minPixelRatio, 1);
  assert.ok(mount.maxPixelCount >= 1_000_000 && mount.maxPixelCount <= 1_500_000, String(mount.maxPixelCount));
  assert.deepEqual(mount.uniforms, uniformsFor('dark'));
  assert.equal(mount.uniforms.u_colorsCount, PALETTES.dark.length);
  assert.deepEqual(mount.contextAttributes, {alpha: false, antialias: false, depth: false, stencil: false,
    powerPreference: 'low-power', failIfMajorPerformanceCaveat: true});
  assert.equal(mount.uniforms.u_grainMixer, 0);
  assert.ok(mount.uniforms.u_grainOverlay > 0 && mount.uniforms.u_grainOverlay <= 0.02, 'a faint dithering grain only');
  assert.equal(mount.frame, PARAMS.frame);
});

test('a theme change updates the colours in place (no remount); an unchanged theme does nothing', async () => {
  const page = fakePage({theme: 'light'});
  const library = fakeLibrary();
  await start(page, library);
  const [mount] = library.mounts;
  assert.deepEqual(mount.uniforms.u_colors, colorsFor('light'));
  assert.deepEqual(page.observers[0].options, {attributes: true, attributeFilter: ['data-theme']});
  assert.equal(page.observers[0].target, page.root);
  page.setTheme('dark');
  page.setTheme('dark');
  page.setTheme('light');
  assert.deepEqual(mount.calls, [['setUniforms', {u_colors: colorsFor('dark')}], ['setUniforms', {u_colors: colorsFor('light')}]]);
  assert.equal(library.mounts.length, 1);
});

test('reduced motion gives a still frame (speed 0), followed live', async () => {
  const page = fakePage({reducedMotion: true});
  const library = fakeLibrary();
  await start(page, library);
  const [mount] = library.mounts;
  assert.equal(mount.speed, 0);
  const query = page.queries['(prefers-reduced-motion: reduce)'];
  query.matches = false;
  query.dispatch('change');
  assert.equal(mount.speed, PARAMS.speed);
  query.matches = true;
  query.dispatch('change');
  assert.equal(mount.speed, 0);
});

test('Save-Data gives a still frame too, followed live', async () => {
  const page = fakePage({saveData: true});
  const library = fakeLibrary();
  await start(page, library);
  const [mount] = library.mounts;
  assert.equal(mount.speed, 0);
  page.connection.saveData = false;
  page.connection.dispatch('change');
  assert.equal(mount.speed, PARAMS.speed);
});

test('nothing throws without matchMedia, IntersectionObserver, MutationObserver, requestIdleCallback or rAF', async () => {
  const page = fakePage({withMatchMedia: false, globals: {MutationObserver: undefined, requestAnimationFrame: undefined,
    IntersectionObserver: undefined, requestIdleCallback: undefined}});
  const library = fakeLibrary();
  const result = await startBackgroundShader({window: page.win, document: page.doc, load: library.load});
  assert.ok(result, 'still mounts');
  assert.equal(library.mounts[0].speed, PARAMS.speed);
  result.stop();
  // No window or document at all (Node): resolves to null.
  assert.equal(await startBackgroundShader({window: undefined, document: undefined}), null);
  assert.equal(await startBackgroundShader({window: {}, document: {querySelector() { throw new Error('boom'); }}}), null);
});

test('the library is fetched only after the load event, once the browser is idle', async () => {
  const idle = [];
  const page = fakePage({readyState: 'loading', globals: {requestIdleCallback: (callback, options) => idle.push([callback, options])}});
  const library = fakeLibrary();
  const started = startBackgroundShader({window: page.win, document: page.doc, load: library.load});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(library.loads(), 0, 'not before load');
  page.win.dispatch('load');
  assert.equal(library.loads(), 0, 'not before idle');
  assert.equal(idle.length, 1);
  assert.ok(idle[0][1].timeout > 0, 'with a timeout, so a busy page still gets it');
  idle[0][0]();
  assert.ok(await started);
  assert.equal(library.loads(), 1);
});

test('a lost WebGL context, or stop(), restores the colour fields and removes every listener', async () => {
  const page = fakePage({saveData: false});
  const library = fakeLibrary();
  const {stop} = await start(page, library);
  const [mount] = library.mounts;
  const query = page.queries['(prefers-reduced-motion: reduce)'];
  assert.equal(query.count('change'), 1);
  assert.equal(page.connection.count('change'), 1);
  mount.canvasElement.dispatch('webglcontextlost');
  assert.ok(mount.disposed);
  assert.equal(mount.released, 1, 'the WebGL context is released (ShaderMount 0.0.81 does not)');
  assert.deepEqual([...page.classes], []);
  assert.equal(query.count('change'), 0);
  assert.equal(page.connection.count('change'), 0);
  assert.equal(mount.canvasElement.count('webglcontextlost'), 0);
  assert.ok(page.observers.every(observer => observer.disconnected));
  page.setTheme('light');
  assert.deepEqual(mount.calls, []);
  assert.doesNotThrow(stop, 'stopping twice is harmless');
});

// WCAG relative luminance of #rrggbb.
const luminance = hex => {
  const [r, g, b] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map(v => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a, b) => { const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };

// Every mixture of the colours in steps of 1/steps of the total weight, then mixed with white
// (grain > 0) or black (grain < 0) in that proportion, as #rrggbb.
function mixtures(palette, steps, grain) {
  const channels = palette.map(hex => [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16)));
  const out = [];
  const visit = (index, left, weights) => {
    if (index === channels.length - 1) {
      const all = [...weights, left];
      const mix = [0, 1, 2].map(k => channels.reduce((sum, c, j) => sum + all[j] * c[k], 0) / steps)
        .map(value => (grain > 0 ? value + grain * (255 - value) : value * (1 + grain)));
      // Rounded towards less contrast with the text.
      out.push('#' + mix.map(value => (grain > 0 ? Math.ceil(value) : Math.floor(value)).toString(16).padStart(2, '0')).join(''));
      return;
    }
    for (let weight = 0; weight <= left; weight++) visit(index + 1, left - weight, [...weights, weight]);
  };
  visit(0, steps, []);
  return out;
}

test('the palettes are the page background and tints that keep every text colour AA on any mixture, with grain', () => {
  const css = source('style.css');
  const dark = css.match(/\n:root \{([^}]*)\}/)[1];
  const light = css.match(/:root\[data-theme="light"\] \{([^}]*)\}/)[1];
  for (const [theme, tokens] of [['dark', dark], ['light', light]]) {
    const token = name => tokens.match(new RegExp(`--${name}:\\s*(#[0-9a-f]{6})`, 'i'))[1];
    assert.deepEqual(PALETTES[theme].filter((_, i) => i % 2), Array(PALETTES[theme].length / 2).fill(token('bg')),
      `${theme}: --bg alternates with the tints`);
    // MeshGradient draws weighted averages of its colours (sRGB, weights summing to 1), so check
    // mixtures too: in the light theme the darkest mixture can lie between the colours. Its grain
    // overlay then mixes at most 0.35 * grainOverlay^0.8 of white or black in (mesh-gradient.js).
    const grain = 0.35 * PARAMS.grainOverlay ** 0.8;
    for (const color of mixtures(PALETTES[theme], 12, theme === 'dark' ? grain : -grain)) {
      for (const text of ['text', 'text-muted', 'text-dim']) {
        assert.ok(contrast(token(text), color) >= 4.5, `${theme}: --${text} ${token(text)} on ${color}: ${contrast(token(text), color).toFixed(2)}`);
      }
    }
    assert.ok(PALETTES[theme].length <= 10, 'MeshGradient takes at most 10 colours');
  }
});

test('the page has the shader container where the colour fields are, and loads the module last, versioned', () => {
  const html = source('index.html');
  assert.match(html, /<div class="bg-fluid" aria-hidden="true">[\s\S]*?<\/div>\n(?:<!--[^>]*-->\n)?<div class="bg-shader" aria-hidden="true"><\/div>/);
  const scripts = [...html.matchAll(/<script[^>]*src="([^"]+)"[^>]*><\/script>/g)].map(([tag, src]) => [tag, src]);
  const [tag, src] = scripts.at(-1);
  assert.equal(src.replace(/\?v=\d+$/, ''), '/static/bg-shader.mjs');
  assert.match(tag, /^<script type="module" src=/);
  assert.doesNotMatch(tag, /\basync\b/, 'runs after the page scripts, like a deferred one');
  for (const url of Object.values(LIBRARY)) assert.match(url, /^\/static\/vendor\/paper-shaders\/[\d.]+\/[a-z/-]+\.js\?v=\d+$/);
  assert.doesNotMatch(source('404.html'), /bg-shader/, 'the 404 page keeps the colour fields only');
});

test('the shader layer sits where the colour fields do and never takes input; screenshots hide it', () => {
  const css = source('style.css');
  const fields = css.match(/\n\.bg-fluid \{([^}]*)\}/)[1];
  const layer = css.match(/\n\.bg-shader \{([^}]*)\}/)[1];
  for (const declaration of ['position: fixed', 'inset: 0', 'z-index: -1', 'pointer-events: none']) {
    assert.ok(fields.includes(declaration) && layer.includes(declaration), declaration);
  }
  assert.match(css, /:root\.bg-shader-ready \.bg-fluid \{ visibility: hidden;/);
  assert.match(css, /@media \(forced-colors: active\) \{\n {2}\.bg-fluid, \.bg-shader,/);
  const reduced = css.slice(css.indexOf('/* ── Reduced motion'));
  assert.match(reduced, /\.bg-shader, :root\.bg-shader-ready \.bg-fluid \{ transition: none; \}/);
  const screenshot = readFileSync(new URL('../tools/visual/screenshot.css', import.meta.url), 'utf8');
  assert.match(screenshot, /\.bg-fluid, \.bg-shader \{ display: none !important; \}/);
});
