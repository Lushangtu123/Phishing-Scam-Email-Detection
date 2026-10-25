/* ──────────────────────────────────────────────────────────────────────────
   bg-shader.mjs – the homepage's animated background
   Draws Paper Shaders' MeshGradient (WebGL2; vendored, with one patch, in
   vendor/paper-shaders/0.0.81/) into .bg-shader, behind the page. It enhances
   the CSS colour fields (.bg-fluid): they stay unless the shader mounts and
   draws its first frame, and they come back if the WebGL context is lost.
   Nothing here throws; any failure leaves the page as it was.
   - The library is fetched after the load event, once the browser is idle, so
     it never competes with the first paint or the page scripts.
   - The colours follow <html data-theme> (theme-init.js, app-theme.js) live.
   - A still frame, with no animation loop, under prefers-reduced-motion:
     reduce or Save-Data; both are followed live.
   ────────────────────────────────────────────────────────────────────────── */

export const LIBRARY = {
  shaderMount: '/static/vendor/paper-shaders/0.0.81/shader-mount.js?v=1',
  meshGradient: '/static/vendor/paper-shaders/0.0.81/shaders/mesh-gradient.js?v=1',
};

// Set on <html> once the first frame is drawn: style.css then fades the canvas in and hides .bg-fluid.
export const READY_CLASS = 'bg-shader-ready';

// The page background (--bg), alternating with soft tints of the colour fields' --accent (cyan),
// --accent-2 (violet) and --accent2 (mint), so the tints read as glows. MeshGradient draws
// weighted averages of these colours, plus a faint grain; every such mix keeps --text,
// --text-muted and --text-dim at 4.5:1 or more (bg-shader.test.mjs checks it). The colour
// fields' brightest spots did not (--text-dim 3.96:1 in the light theme, 4.11:1 in the dark).
export const PALETTES = {
  dark: ['#0c1d2b', '#06080f', '#141731', '#06080f', '#091919', '#06080f'],
  light: ['#e2f4fd', '#f4f6fb', '#eef1fe', '#f4f6fb', '#e4f6f1', '#f4f6fb'],
};

export const PARAMS = {
  distortion: 0.3,
  swirl: 0.06,
  // A faint static grain (about ±1 of 255) dithers the 8-bit output, which otherwise shows
  // contour lines across such close colours.
  grainOverlay: 0.015,
  // MeshGradient's own default is 1. At 0.15 a colour takes about a minute to drift
  // across, like the CSS fields (46–58 s).
  speed: 0.15,
  // Where the animation starts (ms of shader time), and the still frame under reduced motion.
  frame: 30_000,
  // A smooth gradient scales up without visible loss: render at most one pixel per device
  // pixel, and at most 1.2 MP (about 1280 × 900) on large or high-density screens.
  minPixelRatio: 1,
  maxPixelCount: 1_200_000,
};

// Opaque, without the buffers a full-screen gradient does not use (ShaderMount 0.0.82 turns them
// off itself), on the low-power GPU, and never on a software renderer (no GPU, or a blocklisted
// one): a full-screen animation there costs real CPU time for decoration, so the fields stay.
const CONTEXT_ATTRIBUTES = {
  alpha: false, antialias: false, depth: false, stencil: false,
  powerPreference: 'low-power', failIfMajorPerformanceCaveat: true,
};
const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';

const hexToVec4 = hex => [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255).concat(1);

export function colorsFor(theme) {
  return PALETTES[theme === 'light' ? 'light' : 'dark'].map(hexToVec4);
}

export function uniformsFor(theme) {
  const colors = colorsFor(theme);
  return {
    u_colors: colors,
    u_colorsCount: colors.length,
    u_distortion: PARAMS.distortion,
    u_swirl: PARAMS.swirl,
    u_grainMixer: 0,
    u_grainOverlay: PARAMS.grainOverlay,
    // MeshGradient's default object sizing (shader-sizing.js): fit "contain" (1), the whole
    // gradient in view; outside its square the outermost colours continue.
    u_fit: 1,
    u_scale: 1,
    u_rotation: 0,
    u_offsetX: 0,
    u_offsetY: 0,
    u_originX: 0.5,
    u_originY: 0.5,
    u_worldWidth: 0,
    u_worldHeight: 0,
  };
}

function query(win, media) {
  try {
    return typeof win.matchMedia === 'function' ? win.matchMedia(media) : null;
  } catch {
    return null;
  }
}

export function speedFor(win) {
  const reduce = Boolean(query(win, REDUCED_MOTION)?.matches);
  const saveData = win.navigator?.connection?.saveData === true;
  return reduce || saveData ? 0 : PARAMS.speed;
}

// ShaderMount needs WebGL2 and ResizeObserver, and reads the global visualViewport without
// checking that it exists. In forced-colours mode the stylesheet hides the background.
export function canRunShader(win) {
  try {
    return typeof win.WebGL2RenderingContext === 'function'
      && typeof win.ResizeObserver === 'function'
      && Boolean(win.visualViewport)
      && !query(win, '(forced-colors: active)')?.matches;
  } catch {
    return false;
  }
}

function afterLoadAndIdle(win, doc) {
  return new Promise(resolve => {
    const idle = () => (typeof win.requestIdleCallback === 'function'
      ? win.requestIdleCallback(() => resolve(), {timeout: 1500})
      : win.setTimeout(resolve, 50));
    if (doc.readyState === 'complete') idle();
    else win.addEventListener('load', idle, {once: true});
  });
}

const loadLibrary = () => Promise.all([import(LIBRARY.shaderMount), import(LIBRARY.meshGradient)]);

function nextFrame(win) {
  return new Promise(resolve => {
    if (typeof win.requestAnimationFrame === 'function') win.requestAnimationFrame(() => resolve());
    else win.setTimeout(resolve, 16);
  });
}

// ShaderMount.render() clears resolutionChanged once it has drawn at the canvas size.
function hasDrawn(shader) {
  return Boolean(shader && !shader.hasBeenDisposed && shader.program && shader.resolutionChanged === false
    && shader.canvasElement?.width > 0 && !shader.gl?.isContextLost?.());
}

function loseContext(canvas) {
  try {
    canvas.getContext('webgl2')?.getExtension('WEBGL_lose_context')?.loseContext();
  } catch { /* nothing to release */ }
}

// Resolves to {shader, stop} once the first frame is drawn, or to null (the colour fields stay).
export async function startBackgroundShader({
  window: win = globalThis.window,
  document: doc = globalThis.document,
  load = loadLibrary,
  whenReady = afterLoadAndIdle,
  maxFrames = 30,
} = {}) {
  let container;
  let root;
  let shader = null;
  const cleanups = [];
  const stop = () => {
    try { root?.classList.remove(READY_CLASS); } catch { /* keep going */ }
    for (const cleanup of cleanups.splice(0)) {
      try { cleanup(); } catch { /* keep going */ }
    }
    const gl = shader?.gl;
    try { shader?.dispose(); } catch { /* keep going */ }
    // ShaderMount 0.0.81 does not release the context itself (0.0.82 does).
    try { if (gl && !gl.isContextLost()) gl.getExtension('WEBGL_lose_context')?.loseContext(); } catch { /* keep going */ }
    shader = null;
    // A ShaderMount whose constructor threw cannot be disposed; its canvas is still here.
    try {
      for (const canvas of [...container.querySelectorAll('canvas')]) {
        loseContext(canvas);
        canvas.remove();
      }
      container.removeAttribute('data-paper-shader');
      delete container.paperShaderMount;
    } catch { /* nothing left to remove */ }
  };

  try {
    container = doc?.querySelector?.('.bg-shader');
    root = doc?.documentElement;
    if (!container || !root || !win || !canRunShader(win)) return null;
    await whenReady(win, doc);
    const [{ShaderMount}, {meshGradientFragmentShader}] = await load();
    const theme = () => (root.dataset?.theme === 'light' ? 'light' : 'dark');
    let shownTheme = theme();
    shader = new ShaderMount(container, meshGradientFragmentShader, uniformsFor(shownTheme), CONTEXT_ATTRIBUTES,
      speedFor(win), PARAMS.frame, PARAMS.minPixelRatio, PARAMS.maxPixelCount);

    // Theme: every path (toggle, view transition, system change in auto mode) sets data-theme.
    if (typeof win.MutationObserver === 'function') {
      const observer = new win.MutationObserver(() => {
        if (theme() === shownTheme) return;
        shownTheme = theme();
        shader?.setUniforms({u_colors: colorsFor(shownTheme)});
      });
      observer.observe(root, {attributes: true, attributeFilter: ['data-theme']});
      cleanups.push(() => observer.disconnect());
    }
    const updateSpeed = () => shader?.setSpeed(speedFor(win));
    const motion = query(win, REDUCED_MOTION);
    const connection = win.navigator?.connection;
    for (const target of [motion, connection]) {
      if (typeof target?.addEventListener !== 'function') continue;
      target.addEventListener('change', updateSpeed);
      cleanups.push(() => target.removeEventListener('change', updateSpeed));
    }
    const canvas = shader.canvasElement;
    canvas.addEventListener('webglcontextlost', stop);
    cleanups.push(() => canvas.removeEventListener('webglcontextlost', stop));

    for (let frame = 0; frame < maxFrames && shader && !hasDrawn(shader); frame++) await nextFrame(win);
    if (!hasDrawn(shader)) {
      stop();
      return null;
    }
    root.classList.add(READY_CLASS);
    return {shader, stop};
  } catch {
    stop();
    return null;
  }
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') startBackgroundShader();
