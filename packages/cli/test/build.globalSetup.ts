import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROJECTS = [
  path.resolve(CLI_ROOT, '..', 'core', 'tsconfig.json'),
  path.join(CLI_ROOT, 'tsconfig.json'),
];

/**
 * Build core, then the CLI, exactly as `npm run build` does.
 *
 * The executable tests spawn `packages/cli/dist/index.js`, which imports
 * core's `dist`. Testing a build left over from an earlier checkout would
 * report on code that is no longer the code under test, so the suite builds
 * both first and fails outright if either build fails. `tsc` runs through the
 * current Node binary, with no shell, so this works the same on every
 * platform.
 */
export default function setup(): void {
  const require = createRequire(import.meta.url);
  const tsc = path.join(
    path.dirname(require.resolve('typescript/package.json')),
    'bin',
    'tsc',
  );
  for (const project of PROJECTS) {
    const res = spawnSync(process.execPath, [tsc, '-p', project], {
      encoding: 'utf8',
      timeout: 120_000,
    });
    if (res.error || res.signal || res.status !== 0) {
      const output = `${res.stdout ?? ''}${res.stderr ?? ''}`
        .trim()
        .split('\n')
        .slice(0, 20)
        .join('\n');
      throw new Error(
        `Building ${path.relative(CLI_ROOT, project)} for the executable tests ` +
          `failed (${res.error?.message ?? res.signal ?? `exit ${res.status}`}):\n` +
          output,
      );
    }
  }
}
