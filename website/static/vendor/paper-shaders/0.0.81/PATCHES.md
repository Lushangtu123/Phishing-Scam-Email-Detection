# Paper Shaders 0.0.81: vendored files and the one patch

[Paper Shaders](https://github.com/paper-design/shaders), npm `@paper-design/shaders`
0.0.81, Apache-2.0 (`LICENSE`, `NOTICE`, both copied unchanged from the package).
`website/static/bg-shader.mjs` uses it to draw the homepage background (MeshGradient, WebGL2).

**Why 0.0.81 and not the newest release.** The repository uses only releases published at least
seven days earlier (`AGENTS.md`). 0.0.81 was published on 2026-09-17; 0.0.82 on 2026-10-21, so it
can be adopted on or after 2026-10-28. Of the five files below, 0.0.82 changes only
`ShaderMount` (`dist/shader-mount.js`): it creates the WebGL context with `antialias`, `depth` and
`stencil` off by default, releases the context in `dispose()`, and stops `setUniforms()` and
`setFrame()` from drawing an extra frame while the animation loop runs. `bg-shader.mjs` makes up
for the first two (it passes those attributes and releases the context itself); the third costs
one extra frame per theme change.

Only the files MeshGradient needs are copied, at their paths under the package's `dist/`,
so their relative imports work unchanged:

| File | Imports | Changed |
|---|---|---|
| `shader-mount.js` | `./vertex-shader.js` | yes, see below |
| `vertex-shader.js` | none | no |
| `shaders/mesh-gradient.js` | `../shader-sizing.js`, `../shader-utils.js` | no |
| `shader-sizing.js` | none | no |
| `shader-utils.js` | none | no |

Not copied: `index.js`, the other shaders, the TypeScript declarations and the source maps.
The files still end with `//# sourceMappingURL=…`; only DevTools requests those maps, and
gets a 404.

`vendored.json` records the npm tarball (its `sha512` integrity, the same as the
registry's, and its SHA-256) and, for each file, the SHA-256 of the file in the
tarball and of the copy here. `website/static/paper-shaders-vendor.test.mjs` fails
when any file differs from that record, when the patched file differs from the
upstream file other than by the patch below, when a file is added or missing, or
when this directory's name is not the recorded version.

## The patch: `shader-mount.js` (2 hunks)

The `ShaderMount` constructor adds a `<style data-paper-shader>` element to `<head>`.
The page's Content-Security-Policy (`style-src 'self'`) blocks any `<style>` element,
even an empty one, so every page load reported a `style-src-elem` violation. The
patch removes that block; the same rules (`defaultStyle`, still defined in the file
and now unused) are in `website/static/style.css` under the same
`@layer paper-shaders`, and the test checks that each of their declarations is there.
The first hunk is the modification notice Apache-2.0 asks for.

```diff
--- a/dist/shader-mount.js
+++ b/shader-mount.js
@@ -1,3 +1,7 @@
+/* MODIFIED FILE: changed by PhishGuard from @paper-design/shaders 0.0.81 (dist/shader-mount.js).
+ * The constructor no longer inserts a <style> element, which the page CSP (style-src 'self')
+ * blocks; the same rules are in website/static/style.css (@layer paper-shaders).
+ * See PATCHES.md in this directory. Apache-2.0: see LICENSE and NOTICE. */
 /* * * * * * * * * * * * * * * * * * * * * * * * * * * *
  *                    Paper Shaders                    *
  *       https://github.com/paper-design/shaders       *
@@ -46,12 +50,7 @@
       throw new Error("Paper Shaders: parent element must be an HTMLElement");
     }
     this.ownerDocument = parentElement.ownerDocument;
-    if (!this.ownerDocument.querySelector("style[data-paper-shader]")) {
-      const styleElement = this.ownerDocument.createElement("style");
-      styleElement.innerHTML = defaultStyle;
-      styleElement.setAttribute("data-paper-shader", "");
-      this.ownerDocument.head.prepend(styleElement);
-    }
+    // PhishGuard patch: no <style> injection (CSP style-src 'self'); defaultStyle is in style.css.
     const canvasElement = this.ownerDocument.createElement("canvas");
     this.canvasElement = canvasElement;
     this.parentElement.prepend(canvasElement);
```

## Upgrading

1. Check that the release is at least seven days old (`npm view @paper-design/shaders time`).
   Download the new tarball (`npm pack @paper-design/shaders@<version>`) into an empty
   directory, check its `sha512` against `npm view @paper-design/shaders@<version> dist.integrity`,
   and extract it there.
2. Create `website/static/vendor/paper-shaders/<version>/` and copy the files above from
   its `dist/`. Follow the imports of `dist/shader-mount.js` and
   `dist/shaders/mesh-gradient.js` again: copy every file they reach, and nothing else.
   Copy `LICENSE` and `NOTICE`.
3. Reapply the patch (the constructor's `<style>` block may have moved), update
   `defaultStyle` in `style.css` if it changed, and write `vendored.json` and this file
   for the new version. Delete the old version's directory.
4. Change the two URLs in `bg-shader.mjs` to the new directory (from 0.0.82 on, the context
   attributes and the `loseContext()` call there duplicate what `ShaderMount` does) and run
   `node website/tools/asset-versions/update.mjs`, then
   `node --test website/static/*.test.mjs`.

The version is part of every URL: the files that `shader-mount.js` and
`mesh-gradient.js` import are requested without `?v=` (revalidated, not cached for a
year), and a new directory means a browser can never combine files from two versions.
