/**
 * Preloaded with `node --import` into every `falqoner` subprocess the
 * executable tests start.
 *
 * It records, then refuses, anything that could leave the machine or reveal a
 * secret: any `fetch`, any socket connection, and any read of the environment
 * variables named in FALCONER_TRAP_ENV (comma-separated). Each record is
 * appended to FALCONER_TRAP_LOG as it happens, so it outlives the process and
 * a test can assert that nothing was even attempted, including where the CLI
 * caught the error the trap threw. Only names are recorded, never values.
 *
 * With FALCONER_FIXTURE set, `fixture-ledger.mjs` answers the GET requests
 * it recognises, each recorded as `fixture GET <url>` (PQ-04). Everything
 * else is still recorded and refused.
 */
import { appendFileSync } from 'node:fs';
import net from 'node:net';

const log = process.env.FALCONER_TRAP_LOG;
if (!log) throw new Error('offline-trap: FALCONER_TRAP_LOG is not set');
const names = new Set(
  (process.env.FALCONER_TRAP_ENV ?? '').split(',').filter(Boolean),
);

/** @param {string} line */
const record = (line) => appendFileSync(log, `${line}\n`);

/**
 * @param {string | URL | Request} input
 * @param {RequestInit} [init]
 * @returns {Promise<Response>}
 */
async function refuseFetch(input, init) {
  const request = input instanceof Request ? input : undefined;
  const url = request ? request.url : String(input);
  const method = (init?.method ?? request?.method ?? 'GET').toUpperCase();
  const served = method === 'GET' ? fixture?.serve(url) : undefined;
  if (served) {
    record(`fixture ${method} ${url}`);
    return served;
  }
  record(`fetch ${method} ${url}`);
  throw new Error('offline trap: network request refused');
}
globalThis.fetch = refuseFetch;

/** @type {{ connect: (...args: unknown[]) => never }} */ (
  /** @type {unknown} */ (net.Socket.prototype)
).connect = () => {
  record('socket connect');
  throw new Error('offline trap: socket connection refused');
};

/** @param {string} kind @param {string | symbol} prop */
const noteEnv = (kind, prop) => {
  if (typeof prop === 'string' && names.has(prop)) record(`env ${kind} ${prop}`);
};

process.env = new Proxy(process.env, {
  get(target, prop, receiver) {
    noteEnv('get', prop);
    return Reflect.get(target, prop, receiver);
  },
  has(target, prop) {
    noteEnv('has', prop);
    return Reflect.has(target, prop);
  },
  getOwnPropertyDescriptor(target, prop) {
    noteEnv('descriptor', prop);
    return Reflect.getOwnPropertyDescriptor(target, prop);
  },
});

// Last, so the ledger and everything it imports load under the traps above.
const fixture = process.env.FALCONER_FIXTURE
  ? await import('./fixture-ledger.mjs')
  : undefined;
