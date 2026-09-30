#!/usr/bin/env node
/**
 * Record `npm run demo -- --short` as a replayable cast and a self-contained SVG.
 *
 *   npm run record              # writes docs/terminal.cast and docs/terminal.svg
 *   npm run record -- --check   # exits 1 if they differ from what it would write
 *
 * The demo runs for real, against its fixture ledger, so every run prints
 * the same output, and the recording is made from it alone: line timings
 * follow the content, not the clock, and the cast carries no timestamp. The
 * files are therefore reproducible byte for byte, and `--check` shows they
 * are still what the tool prints. A demo that fails writes nothing.
 * Windows has no pty, so colour comes from FORCE_COLOR rather than a tty.
 */
import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, 'docs');
const check = process.argv.includes('--check');

/** The pause a command's output follows, as if it had just run. */
const RUN_S = 0.55;
/**
 * Give lines within a burst smooth spacing so output streams naturally.
 */
const LINE_S = 0.07;
/** Hold the finished frame before looping, so the end is readable. */
const HOLD_S = 4;
const ROWS = 20;
/** Floor and ceiling for the window width; the content picks the rest. */
const MIN_COLS = 84;
const MAX_COLS = 132;

/* ------------------------------------------------------------------ */
/* 1. Run the demo for real and capture it                             */
/* ------------------------------------------------------------------ */

function record() {
  return new Promise((resolve, reject) => {
    let output = '';
    // --short: the README wants the argument, not the full transcript.
    const child = spawn(process.execPath, [path.join(root, 'scripts', 'demo.mjs'), '--short'], {
      cwd: root,
      // Node warns if both are set, and that warning lands in the cast.
      // TERM=dumb would turn the CLI's colour off, and NODE_OPTIONS could
      // change how it starts; neither may change the recording.
      env: (() => {
        const env = { ...process.env, FORCE_COLOR: '1' };
        delete env.NO_COLOR;
        delete env.TERM;
        delete env.NODE_OPTIONS;
        return env;
      })(),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (buf) => (output += buf));
    child.stderr.on('data', (buf) => (output += buf));
    child.on('error', reject);
    child.on('close', (code) => {
      if (!output) reject(new Error('demo produced no output'));
      else resolve({ output, code });
    });
  });
}

/* ------------------------------------------------------------------ */
/* 2. asciicast v2                                                     */
/* ------------------------------------------------------------------ */

/** One event per line, at the time the SVG shows it. No timestamp: it would change every run. */
function toCast(lines, cols) {
  const header = {
    version: 2,
    width: cols,
    height: ROWS,
    env: { SHELL: '/bin/sh', TERM: 'xterm-256color' },
    title: 'Falconer in two minutes',
  };
  return (
    [JSON.stringify(header)]
      .concat(lines.map((l) => JSON.stringify([l.t, 'o', `${l.raw}\r\n`])))
      .join('\n') + '\n'
  );
}

/* ------------------------------------------------------------------ */
/* 3. ANSI -> styled lines                                             */
/* ------------------------------------------------------------------ */

const SGR = {
  '1': { bold: true },
  '2': { fill: '#7d8699' },
  '31': { fill: '#ff5964' },
  '32': { fill: '#3ddc84' },
  '33': { fill: '#ff9f43' },
  '35': { fill: '#d2a8ff' },
  '36': { fill: '#79c0ff' },
};
const BASE = { fill: '#c9d1d9', bold: false };

/**
 * Split captured output into lines of styled runs, each keeping its raw
 * text for the cast, and time them by what they say.
 */
function toLines(output) {
  const lines = [];
  let style = { ...BASE };
  for (const raw of output.replace(/\r/g, '').split('\n')) {
    const runs = [];
    let i = 0;
    while (i < raw.length) {
      const esc = raw.indexOf('\u001b[', i);
      const upto = esc === -1 ? raw.length : esc;
      if (upto > i) runs.push({ text: raw.slice(i, upto), ...style });
      if (esc === -1) break;
      const end = raw.indexOf('m', esc);
      if (end === -1) break;
      for (const code of raw.slice(esc + 2, end).split(';')) {
        if (code === '0' || code === '') style = { ...BASE };
        else if (SGR[code]) style = { ...style, ...SGR[code] };
      }
      i = end + 1;
    }
    lines.push({ t: 0, raw, runs });
  }
  // Trailing blank lines add height and say nothing.
  while (lines.length && !lines[lines.length - 1].runs.length) lines.pop();

  // Smooth streaming, with pauses where a person would see them.
  let clock = 0.05;
  let inCommand = false;
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i].runs.map((r) => r.text).join('').trim();
    const opens = text.startsWith('$ falconer');
    // A command wrapped with a trailing backslash continues on the next line.
    const command = opens || (inCommand && lines[i - 1].raw.trimEnd().endsWith('\\'));
    if (i === 0) {
      clock = 0.05;
    } else if (inCommand && !command) {
      // The command runs, then its output appears.
      clock += RUN_S;
    } else if (text.startsWith('# ') && i > 1) {
      // Natural breath before next section
      clock += 0.45;
    } else if (opens) {
      // Slight pause before typing the command
      clock += 0.3;
    } else if (text.startsWith('✔')) {
      // Pause before final verdict
      clock += 0.35;
    } else {
      clock += LINE_S;
    }
    inCommand = command;
    lines[i].t = Number(clock.toFixed(3));
  }

  return lines;
}

/* ------------------------------------------------------------------ */
/* 4. animated SVG                                                     */
/* ------------------------------------------------------------------ */

const esc = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** The widest line decides the window, so nothing is clipped. */
function widestLine(lines) {
  const widest = lines.reduce(
    (n, l) => Math.max(n, l.runs.reduce((w, r) => w + r.text.length, 0)),
    0,
  );
  return Math.min(MAX_COLS, Math.max(MIN_COLS, widest + 2));
}

function toSvg(lines, cols) {
  const fontSize = 13;
  const charW = fontSize * 0.6;
  const lineH = 19;
  const padX = 18;
  const padTop = 42; // room for the title bar
  const padBottom = 14;
  const width = Math.round(padX * 2 + cols * charW);
  const height = padTop + ROWS * lineH + padBottom;

  const last = lines[lines.length - 1].t;
  // The animation loops: a reader arriving part-way through still sees the
  // whole run, with a smooth fade reset before restarting.
  const total = Math.max(last + HOLD_S, 1);
  const pct = (t) => Math.min(100, Math.max(0, (t / total) * 100));

  const pFadeOut = pct(total - 0.55).toFixed(3);
  const pFadeEnd = pct(total - 0.15).toFixed(3);

  // Each line fades in smoothly over 80ms at the moment it was printed,
  // and fades out with the container loop reset so looping is seamless.
  const reveals = lines
    .map((l, i) => {
      const at = pct(l.t).toFixed(3);
      const before = Math.max(0, pct(l.t - 0.08)).toFixed(3);
      return (
        `@keyframes ln${i}{0%,${before}%{opacity:0}${at}%,${pFadeOut}%{opacity:1}${pFadeEnd}%,100%{opacity:0}}` +
        `.l${i}{animation:ln${i} ${total.toFixed(2)}s linear infinite}`
      );
    })
    .join('\n');

  // Build smooth scrolling keyframes:
  // Instead of harsh stepped teleportation, the scroller glides smoothly
  // during line bursts and holds steady during pauses.
  const keyframes = [];
  let currentDy = 0;
  let lastMoveEndT = 0;
  keyframes.push({ t: 0, dy: 0 });

  for (let i = 0; i < lines.length; i++) {
    const targetDy = -Math.max(0, i + 1 - ROWS) * lineH;
    if (targetDy !== currentDy) {
      const tEnd = lines[i].t;
      const prevLineT = i > 0 ? lines[i - 1].t : 0;
      const dt = tEnd - prevLineT;
      const scrollDur = Math.min(0.12, Math.max(0.06, dt * 0.85));
      const tStart = Math.max(lastMoveEndT, tEnd - scrollDur);

      if (tStart > lastMoveEndT + 0.005) {
        keyframes.push({ t: tStart, dy: currentDy, ease: true });
      }
      keyframes.push({ t: tEnd, dy: targetDy });
      currentDy = targetDy;
      lastMoveEndT = tEnd;
    }
  }

  // Hold position through the reading pause at the end
  const tFadeOut = total - 0.55;
  const tFadeEnd = total - 0.15;
  keyframes.push({ t: tFadeOut, dy: currentDy });
  // Reset translateY to 0 during the invisible fade-out window
  keyframes.push({ t: tFadeEnd, dy: 0 });
  keyframes.push({ t: total, dy: 0 });

  const scrollStops = keyframes.map((k) => {
    const p = pct(k.t).toFixed(3);
    const timing = k.ease
      ? 'animation-timing-function:cubic-bezier(0.25,1,0.5,1);'
      : '';
    return `${p}%{transform:translateY(${k.dy}px);${timing}}`;
  });
  const scroll = `@keyframes scroll{${scrollStops.join('')}}\n.scroller{animation:scroll ${total.toFixed(2)}s linear infinite;will-change:transform;}`;

  const body = lines
    .map((l, i) => {
      const y = padTop + (i + 1) * lineH - 5;
      const runs = l.runs.length
        ? l.runs
            .map(
              (r) =>
                `<tspan fill="${r.fill}"${r.bold ? ' font-weight="600"' : ''}>` +
                `${esc(r.text)}</tspan>`,
            )
            .join('')
        : '';
      return `<text class="l${i}" x="${padX}" y="${y}">${runs}</text>`;
    })
    .join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace" font-size="${fontSize}" xml:space="preserve" role="img" aria-label="Falconer demo: what one Algorand key really controls">
<style>
text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;text-rendering:geometricPrecision;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;}
.scroller text{white-space:pre;opacity:0;}
.loop-fade{animation:loopFade ${total.toFixed(2)}s ease-in-out infinite;}
@keyframes loopFade{0%{opacity:0}1.2%{opacity:1}${pFadeOut}%{opacity:1}${pFadeEnd}%{opacity:0}100%{opacity:0}}
${reveals}
${scroll}
</style>
<rect width="${width}" height="${height}" rx="10" fill="#0c0f14" stroke="#30363d" stroke-width="1"/>
<rect width="${width}" height="32" rx="10" fill="#161b22"/>
<rect y="16" width="${width}" height="16" fill="#161b22"/>
<line x1="0" y1="32" x2="${width}" y2="32" stroke="#21262d" stroke-width="1"/>
<circle cx="19" cy="16" r="5" fill="#ff5f56"/>
<circle cx="37" cy="16" r="5" fill="#ffbd2e"/>
<circle cx="55" cy="16" r="5" fill="#27c93f"/>
<text x="${width / 2}" y="20.5" text-anchor="middle" fill="#7d8699" font-size="11.5">falconer — post-quantum authority</text>
<clipPath id="view"><rect x="0" y="33" width="${width}" height="${height - 33}"/></clipPath>
<g clip-path="url(#view)"><g class="loop-fade"><g class="scroller">
${body}
</g></g></g>
</svg>
`;
}

/* ------------------------------------------------------------------ */

const { output, code } = await record();
if (code !== 0) {
  // A recording of a failure would be presented as the tool working.
  process.stderr.write(`${output}\ndemo exited ${code}; nothing was written\n`);
  process.exit(1);
}
const lines = toLines(output);
const cols = widestLine(lines);
const files = {
  'terminal.cast': toCast(lines, cols),
  'terminal.svg': toSvg(lines, cols),
};

if (check) {
  const stale = Object.entries(files)
    .filter(([name, text]) => {
      try {
        // A checkout may have turned line endings into CRLF; that is not drift.
        return readFileSync(path.join(outDir, name), 'utf8').replace(/\r\n/g, '\n') !== text;
      } catch {
        return true;
      }
    })
    .map(([name]) => `docs/${name}`);
  if (stale.length) {
    const verb = stale.length === 1 ? 'no longer matches' : 'no longer match';
    console.error(`${stale.join(' and ')} ${verb} what the demo prints. Run: npm run record`);
    process.exit(1);
  }
  console.log('docs/terminal.cast and docs/terminal.svg match what the demo prints');
  process.exit(0);
}

mkdirSync(outDir, { recursive: true });
for (const [name, text] of Object.entries(files)) writeFileSync(path.join(outDir, name), text);

const duration = lines[lines.length - 1].t + HOLD_S;
console.log(`${lines.length} lines, ${cols} cols, ${duration.toFixed(1)}s of playback`);
console.log('wrote docs/terminal.cast and docs/terminal.svg');
