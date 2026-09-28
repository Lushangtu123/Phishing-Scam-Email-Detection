// Rebuild locally after npm ci --ignore-scripts; no package lifecycle scripts run.
import {cp, mkdir, readdir, readFile, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--node-modules' || !path.isAbsolute(args[1])))
  throw new Error('Usage: node build.mjs [--node-modules /absolute/path/to/node_modules]');
const nodeModules = args.length ? args[1] : path.join(root, 'node_modules');
const packages = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
for (const [name, version] of Object.entries({...packages.dependencies, ...packages.devDependencies})) {
  const installed = JSON.parse(await readFile(path.join(nodeModules, name, 'package.json'), 'utf8'));
  if (installed.version !== version) throw new Error(`Expected ${name}@${version}; found ${installed.version}`);
}
const {build} = await import(pathToFileURL(path.join(nodeModules, 'esbuild/lib/main.js')));
const output = path.resolve(root, '../../static/vendor/vision');
await mkdir(output, {recursive: true});
async function copy(source, dest) {
  const target = path.join(output, dest);
  await mkdir(path.dirname(target), {recursive: true});
  await cp(path.join(nodeModules, source), target, {recursive: true});
}
// The parser-only CSS entry points omit unused lexer dictionaries and source-map
// code. Both bundles are self-contained and have no browser runtime imports.
for (const [filename, contents, notice] of [
  ['html-parser.mjs', "export {parse, parseFragment, defaultTreeAdapter, Parser} from 'parse5';", 'parse5 8.0.1 (MIT); entities (BSD-2-Clause). See licenses/.'],
  ['css-parser.mjs', "export {default as parse} from 'css-tree/parser'; export {default as walk} from 'css-tree/walker'; export {ident} from 'css-tree/utils';", 'css-tree 3.2.1 (MIT). See licenses/.']
]) {
  const result = await build({
    stdin: {contents, resolveDir: path.dirname(nodeModules), sourcefile: filename},
    nodePaths: [nodeModules], bundle: true, platform: 'browser', format: 'esm',
    target: 'es2020', minify: true, legalComments: 'inline', write: false,
    banner: {js: `// ${notice} Rebuild with website/tools/vision-assets/build.mjs.`},
    metafile: true
  });
  if (Object.values(result.metafile.outputs).some(file => file.imports.length))
    throw new Error(`${filename} unexpectedly depends on runtime imports`);
  await writeFile(path.join(output, filename), result.outputFiles[0].contents);
}
await copy('parse5/LICENSE', 'licenses/parse5.txt');
await copy('entities/LICENSE', 'licenses/entities.txt');
await copy('css-tree/LICENSE', 'licenses/css-tree.txt');
for (const name of ['tesseract.esm.min.js', 'worker.min.js', 'worker.min.js.LICENSE.txt', 'tesseract.min.js.LICENSE.txt'])
  await copy('tesseract.js/dist/' + name, name);
await copy('tesseract.js/LICENSE.md', 'licenses/tesseract-js.txt');
for (const variant of ['lstm', 'simd-lstm']) {
  for (const extension of ['wasm.js', 'wasm'])
    await copy(`tesseract.js-core/tesseract-core-${variant}.${extension}`, `core/tesseract-core-${variant}.${extension}`);
}
await copy('tesseract.js-core/LICENSE', 'licenses/tesseract-core.txt');
await copy('jsqr/dist/jsQR.js', 'jsQR.js');
await copy('jsqr/LICENSE', 'licenses/jsqr.txt');
await copy('postal-mime/src', 'postal-mime');
await copy('postal-mime/LICENSE.txt', 'licenses/postal-mime.txt');
await writeFile(path.join(output, 'postal-mime/package.json'), '{"type":"module"}\n');
for (const lang of ['eng', 'chi_sim']) {
  await copy(`@tesseract.js-data/${lang}/4.0.0_best_int/${lang}.traineddata.gz`, `lang/${lang}.traineddata.gz`);
  await copy(`@tesseract.js-data/${lang}/package.json`, `licenses/${lang}-package.json`);
}
await cp(path.join(root, 'tessdata-LICENSE.txt'), path.join(output, 'licenses/tessdata.txt'));
const files = {};
async function walk(dir) {
  for (const entry of await readdir(dir, {withFileTypes: true})) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(file);
    else if (entry.name !== 'manifest.json') {
      const bytes = await readFile(file);
      files[path.relative(output, file)] = {bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex')};
    }
  }
}
await walk(output);
await writeFile(path.join(output, 'manifest.json'), JSON.stringify({files}, null, 2) + '\n');
console.log(`Prepared ${Object.keys(files).length} self-hosted assets (${Object.values(files).reduce((n, f) => n + f.bytes, 0)} bytes).`);
