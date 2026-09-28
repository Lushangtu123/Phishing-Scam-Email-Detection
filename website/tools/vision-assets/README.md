# Self-hosted browser recognition assets

Pinned packages are build dependencies; they can be installed in this tooling
directory or a task-local dependency directory. The application serves the
committed assets in `website/static/vendor/vision`; production does not run npm
or download OCR models on the server.

Rebuild (after approval to install/update dependencies):

```sh
cd website/tools/vision-assets
npm ci --ignore-scripts --no-audit --no-fund
node build.mjs
node verify.mjs
```

To keep installed dependencies outside the repository, copy `package.json` and
`package-lock.json` into a task-local directory, run the same `npm ci` command
there, and provide its absolute `node_modules` path:

```sh
node website/tools/vision-assets/build.mjs --node-modules /absolute/task/deps/node_modules
node website/tools/vision-assets/verify.mjs
```

`package-lock.json` pins npm integrity hashes; `manifest.json` records the
SHA-256 and byte length of each served asset. CI verifies that manifest without
installing npm packages. The build validates direct package versions before
copying assets. HTML/CSS parsers are bundled with pinned esbuild 0.28.2 for browser
ESM, with no runtime imports; other upstream assets are copied without changes.
No functional patches are applied to upstream parser sources.

## Sources and attribution

- [jsQR](https://github.com/cozmo/jsQR), 1.4.0, Apache-2.0. Its RGBA decoder is
  wrapped with bounded repeated masking and overlapping quadrant scans for
  multiple codes. Decoded strings are never followed as URLs.
- [Tesseract.js](https://github.com/naptha/tesseract.js), 6.0.1, Apache-2.0;
  [Tesseract.js-core](https://github.com/naptha/tesseract.js-core), 6.0.0,
  Apache-2.0. We follow the upstream self-hosting API with local worker/core/lang
  paths, LSTM-only models and `workerBlobURL: false`. Only LSTM and SIMD-LSTM
  engines are shipped. Upstream bundle license notices are retained.
- [postal-mime](https://github.com/postalsys/postal-mime), 3.0.0, MIT-0. The
  unmodified browser ESM source is used with strict parsing depth/header limits.
- [parse5](https://github.com/inikulin/parse5), 8.0.1, MIT, with
  [entities](https://github.com/fb55/entities), 8.1.0, BSD-2-Clause, pinned by the
  lockfile. `html-parser.mjs` exports `parse`, `parseFragment`, and
  `defaultTreeAdapter`, and `Parser` for HTML syntax parsing inside the browser worker. The
  default adapter can be wrapped to enforce budgets while constructing nodes.
  Per-instance tokenizer and open-element stack budget hooks in the consumer are
  tied to pinned parse5 8.0.1 and need regression verification when upgrading.
  No upstream parser source is patched. It builds an inert syntax tree and does not
  execute scripts or load resources from the parsed content.
- [CSSTree](https://github.com/csstree/csstree), 3.2.1, MIT. `css-parser.mjs`
  exports `parse`, `walk`, and `ident`, using the parser/walker entry points to avoid
  bundling the unused lexer dictionaries and source-map generator. CSS URL and
  string AST values already have CSS character escapes decoded; consumers must
  not decode them again. Property and function identifiers retain CSS escapes;
  use `ident.decode(name)` before comparing those names. Parsing does not fetch
  CSS URLs. Both parser bundles together add about 218 KB (uncompressed), with their upstream licenses kept
  in `licenses/`.
- [naptha/tessdata](https://github.com/naptha/tessdata), official npm packages
  `@tesseract.js-data/eng` and `@tesseract.js-data/chi_sim`, 1.0.0,
  `4.0.0_best_int` weights. npm package metadata declares MIT; the model repository
  supplies Apache-2.0. Both package attribution metadata and the upstream model
  license are included. `tessdata-LICENSE.txt` was retrieved from the official
  repository's `gh-pages` branch on 2026-09-20.

Asset size is about 19 MB including engines and both language models. Browser
requests for these assets use the application's own origin. Recognition inputs
are not written into Tesseract's language cache (`cacheMethod: none`).
