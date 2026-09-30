#!/usr/bin/env node
/**
 * Falcon-1024 WebAssembly provenance check:
 * `node scripts/wasm-provenance.mjs [glue.js ...]`.
 *
 * `falcon-1024` embeds its WebAssembly in Emscripten glue as one string passed
 * to `binaryDecode`. This decodes that string as data, never as code, and
 * refuses anything but plain escapes and characters; it checks the installed
 * package's copy against the pinned baseline, then
 * compares each glue file given (by default the installed ESM and CJS
 * bundles; also rebuilt glue or the web build's `apps/web/dist/assets/*.js`)
 * with it byte for byte. It prints each module's WebAssembly sections
 * with their sizes and SHA-256, and on a mismatch the first differing offset
 * and the sections that differ. A copy of the baseline with one code byte
 * flipped must fail the same comparison. Exits 1 on any mismatch.
 *
 * Rebuild from the pinned sources on Linux x86_64 in a scratch directory, with
 * upstream's own build script (it compiles every `falcon/*.c` twice, into
 * `src/falcon_wasm.js` and `src/falcon_wasm_sync.js`):
 *
 *   git clone https://github.com/joe-p/falcon-1024-ts.git && cd falcon-1024-ts
 *   git checkout 4754f0a0ce0a3e11d4e3d7432fcbc434ebeac6ef
 *   git submodule update --init
 *     # emsdk 41190c21c662e9cc1962aea94e71cbae9fd2fc87 (tag 5.0.7),
 *     # falcon ce15e75bceb372867daf6b8e81918ab6978686eb
 *   ./emsdk/emsdk install 5.0.7 && ./emsdk/emsdk activate 5.0.7
 *     # emscripten-releases 6cd98e86d7749ff98b82b7f2ae78eb4f01942788
 *   ./emsdk/node/22.16.0_64bit/bin/node --experimental-strip-types scripts/build.ts
 *   node <falconer>/scripts/wasm-provenance.mjs src/falcon_wasm.js src/falcon_wasm_sync.js
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(ROOT, 'node_modules', 'falcon-1024', 'dist');
const INSTALLED = [path.join(DIST, 'index.js'), path.join(DIST, 'index.cjs')];
/** `falcon-1024` 0.2.0 as locked (REPO-05 provenance table). */
const BASELINE = { size: 95_438, sha256: '5c416483f859809e9fb90b483c43785cf28170ba52d4de7cfbf956bc69665a9a' };
const NAMES = ['custom', 'type', 'import', 'function', 'table', 'memory', 'global', 'export', 'start', 'element', 'code', 'data', 'datacount', 'tag'];

const sha256 = (/** @type {Uint8Array} */ b) => createHash('sha256').update(b).digest('hex');

/** @param {string} message @returns {never} */
function fail(message) {
  process.stderr.write(`\nwasm provenance check failed: ${message}\n`);
  process.exit(1);
}

/** The plain escapes a JavaScript string may use, as character codes. @type {Record<string, number>} */
const ESCAPES = { 0: 0, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, $: 36, "'": 39, '\\': 92, '`': 96 };

/**
 * The JavaScript string literal at `start`, read as data in one pass and
 * decoded as the glue's own `binaryDecode` does. It is never evaluated: a `${`
 * substitution, a raw character JavaScript would reject or normalize, any other
 * escape or a missing end quote returns the reason instead.
 * @param {string} text @param {number} start @returns {Uint8Array | string}
 */
function decode(text, start) {
  const quote = text[start], codes = [];
  for (let i = start + 1; i < text.length;) {
    const at = i, c = text[i++];
    if (c === quote) return Uint8Array.from(codes, (n) => ~n >> 8 & n);
    if (c === '\\') {
      const e = text[i++] ?? '', digits = e === 'x' ? 2 : e === 'u' ? 4 : 0, simple = ESCAPES[e];
      const hex = text.slice(i, i + digits);
      if (digits && hex.length === digits && /^[0-9a-f]+$/i.test(hex)) { codes.push(parseInt(hex, 16)); i += digits; }
      else if (simple !== undefined && !(e === '0' && /[0-9]/.test(text[i] ?? ''))) codes.push(simple);
      else return `unsupported escape at offset ${at}`;
    } else if (quote === '`' ? (c === '$' && text[i] === '{') || c === '\r' : c === '\n' || c === '\r') {
      return `not plain string data at offset ${at}`;
    } else codes.push(text.charCodeAt(at));
  }
  return 'unterminated string';
}

/** The embedded module. @param {string} file */
function extract(file) {
  const text = readFileSync(file, 'utf8');
  // emcc writes a quoted string with raw characters; bundlers re-quote it as an
  // escaped template and may rename `binaryDecode`, so find it by its magic.
  const calls = [...text.matchAll(/(['"`])(?:\\0|\\x00|\u0000)asm/g)];
  const [call] = calls;
  if (calls.length !== 1 || !call) fail(`${file}: expected one string starting with the WebAssembly magic, found ${calls.length}`);
  const bytes = decode(text, call.index);
  if (typeof bytes === 'string') fail(`${file}: ${bytes}`);
  return bytes;
}

/** Top-level sections of a WebAssembly module. @param {Uint8Array} b */
function sections(b) {
  if (Buffer.compare(b.subarray(0, 8), Uint8Array.of(0, 0x61, 0x73, 0x6d, 1, 0, 0, 0))) fail('not a WebAssembly 1 module');
  const out = [];
  let p = 8;
  const next = () => b[p++] ?? fail('truncated module');
  /** Unsigned LEB128 at `p`. */
  const leb = () => {
    let v = 0, shift = 0, byte;
    do { byte = next(); v += (byte & 0x7f) * 2 ** shift; shift += 7; } while (byte & 0x80);
    return v;
  };
  while (p < b.length) {
    const id = next(), size = leb(), body = p;
    let name = NAMES[id] ?? `id ${id}`;
    if (id === 0) { const n = leb(); name = `custom "${new TextDecoder().decode(b.subarray(p, p + n))}"`; }
    out.push({ name, offset: body, size, sha256: sha256(b.subarray(body, body + size)) });
    p = body + size;
  }
  if (p !== b.length) fail('section sizes overrun the module');
  return out;
}

/** @param {string} label @param {Uint8Array} ref @param {Uint8Array} got */
function differences(label, ref, got) {
  if (!Buffer.compare(ref, got)) return [];
  let i = 0;
  while (i < ref.length && i < got.length && ref[i] === got[i]) i++;
  const want = new Map(sections(ref).map((s) => [s.name, s]));
  const changed = sections(got)
    .filter((s) => want.get(s.name)?.sha256 !== s.sha256)
    .map((s) => `${s.name} (${want.get(s.name)?.size ?? 'absent'} -> ${s.size} bytes)`);
  return [`${label}: ${got.length} bytes vs ${ref.length}, first difference at offset ${i}; differing sections: ${changed.join(', ') || 'none by content (order or count)'}`];
}

const reference = extract(path.join(DIST, 'index.js'));
if (reference.length !== BASELINE.size || sha256(reference) !== BASELINE.sha256) {
  fail(`installed falcon-1024 WebAssembly is ${reference.length} bytes, sha256 ${sha256(reference)}; expected the pinned baseline`);
}
console.log(`baseline: ${BASELINE.size} bytes, sha256 ${BASELINE.sha256}`);
for (const s of sections(reference)) console.log(`  ${s.name.padEnd(12)} @${s.offset} ${s.size} bytes ${s.sha256}`);

const problems = [];
for (const file of process.argv.length > 2 ? process.argv.slice(2) : INSTALLED) {
  const got = extract(file);
  console.log(`${file}: ${got.length} bytes, sha256 ${sha256(got)}`);
  problems.push(...differences(file, reference, got));
}

// Decoder controls: escaped and raw data decode; anything else is refused
// unread, whatever the escape parity before a `${`.
const MAGIC = [0, 97, 115, 109];
/** @type {[string, number[] | null][]} */
const LITERALS = [
  ["'\\0asm\\x8c\\u00ff\\\\\\'\"'", [...MAGIC, 0x8c, 0xff, 92, 39, 34]],
  ["'\0asm\x8c'", [...MAGIC, 0x8c]],
  ['`\\0asm\\\\\\${x}$`', [...MAGIC, 92, 36, 123, 120, 125, 36]],
  ['`\\0asm\\\\${x}`', null],
  ['`\\0asm${x}`', null],
  ['`\\0asm\r`', null],
  ["'\\0asm\n'", null],
  ["'\\0asm\\u{61}'", null],
  ["'\\0asm\\x8'", null],
  ["'\\0asm\\01'", null],
  ["'\\0asm\\q'", null],
  ["'\\0asm", null],
];
for (const [literal, want] of LITERALS) {
  const got = decode(literal, 0);
  if (want ? typeof got === 'string' || Buffer.compare(got, Uint8Array.from(want)) : typeof got !== 'string') {
    fail(`decoder control ${JSON.stringify(literal)} gave ${typeof got === 'string' ? got : `[${got}]`}`);
  }
}
console.log(`decoder controls: ${LITERALS.length} passed`);

// Negative control: one flipped byte in the code section must be reported.
const code = sections(reference).find((s) => s.name === 'code');
if (!code) fail('baseline has no code section');
const altered = reference.slice();
const at = code.offset + (code.size >> 1);
altered[at] = (reference[at] ?? 0) ^ 0x01;
const control = differences('altered baseline', reference, altered);
if (control.length !== 1 || !control[0]?.includes('differing sections: code (')) fail(`altered-byte control was not detected: ${control}`);
console.log(`negative control detected: ${control[0]}`);

if (problems.length) fail(`\n${problems.join('\n')}`);
console.log('match: every module is byte-identical to the baseline');
