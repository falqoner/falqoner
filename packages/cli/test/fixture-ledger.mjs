/**
 * A fixed ledger served through the provider's REST interface (PQ-04), for
 * the built executable and the demo's fixture mode.
 *
 * `offline-trap.mjs` loads it when FALCONER_FIXTURE is set, answers the GET
 * requests it recognises from here, and still records and refuses every
 * other request. Bodies are JSON as algod and the indexer send it, so the
 * CLI decodes them through algosdk exactly as it would a real provider's,
 * big integers included. Every network is answered alike: output naming a
 * network names the one asked for, and this ledger only stands in for its
 * provider. Transaction ids start with FIXTURE, so its records say what
 * they are wherever they are printed.
 *
 * Nothing here holds a secret. Falcon evidence is built from fixed public
 * keys, and every other address is a fixed hash with no known private key.
 */
import { createHash } from 'node:crypto';
import algosdk from 'algosdk';
import { classifyAddressShape, derivePqAddress, NETWORKS } from '@falconer/core';

/** @typedef {'on-curve' | 'off-curve'} Shape */

/**
 * The first address with `shape` among the hashes of `label`.
 * @param {string} label @param {Shape} shape
 */
function hashed(label, shape) {
  for (let i = 0; i < 256; i++) {
    const digest = createHash('sha512-256').update(`falconer PQ-04 ${label} ${i}`).digest();
    const address = new algosdk.Address(new Uint8Array(digest)).toString();
    if (classifyAddressShape(address) === shape) return address;
  }
  throw new Error(`no ${shape} address for ${label}`);
}

/** A Falcon-1024 authority from a fixed public key. There is no private key. @param {number} fill */
function falcon(fill) {
  const publicKey = new Uint8Array(1793).fill(fill);
  return { ...derivePqAddress(publicKey), publicKey };
}

/** A real 2-of-3 multisig address over fixed members, off the curve. */
function multisig() {
  for (let i = 0; i < 256; i++) {
    const addrs = [1, 2, 3].map((m) => hashed(`multisig member ${m} ${i}`, 'on-curve'));
    const address = algosdk.multisigAddress({ version: 1, threshold: 2, addrs }).toString();
    if (classifyAddressShape(address) === 'off-curve') return { address, addrs };
  }
  throw new Error('no off-curve multisig address');
}

/** A real contract-account address: `int k`, the first k landing off the curve. */
function logicsig() {
  for (let k = 1; k < 128; k++) {
    const logic = Uint8Array.from([1, 32, 1, k, 34]); // #pragma version 1; int k
    const address = new algosdk.LogicSigAccount(logic).address().toString();
    if (classifyAddressShape(address) === 'off-curve') return { address, logic };
  }
  throw new Error('no off-curve logic signature address');
}

const PQ = falcon(3);
/** Its only record claims a scheme Falconer does not support. */
const ODD = falcon(5);
const MSIG = multisig();
const LSIG = logicsig();
/** Hash-derived, and has never signed anything. */
const SILENT = hashed('silent authority', 'off-curve');
/** Rekeyed to the incomplete-search account: exposed, like its authority. */
const BEHIND = hashed('rekeyed to the incomplete search', 'on-curve');

export const PROVIDER_ROUND = 100;
export const CONFIRMED_ROUND = 42;
/** An asset the manager account manages, whose clawback someone else holds. */
export const ASSET = 7001;
/** More than 2^53 microAlgos: exact only as a decimal string. */
export const WHALE_BALANCE = 9_007_199_254_740_993n;

/** @param {string} label letters A-Z only */
const txid = (label) => `FIXTURE${label}`.padEnd(52, 'A');

export const TXIDS = {
  postQuantum: txid('POSTQUANTUM'),
  multisig: txid('MULTISIG'),
  logicsig: txid('LOGICSIG'),
  rejected: txid('UNSUPPORTEDSCHEME'),
};

export const FIXTURE = {
  /** Signs for itself from an on-curve address. */
  classical: hashed('classical', 'on-curve'),
  /** Classical, 0.3 ALGO, and the manager of ASSET. */
  manager: hashed('manager', 'on-curve'),
  /** Rekeyed to a Falcon authority, with a confirmed record binding it. */
  postQuantum: hashed('post-quantum', 'on-curve'),
  /** A multisig address signing for itself, with a confirmed record. */
  multisig: MSIG.address,
  /** A contract account signing for itself, with a confirmed record. */
  logicsig: LSIG.address,
  /** Rekeyed to a hash-derived authority that has never signed. */
  unconfirmed: hashed('unconfirmed', 'on-curve'),
  /** Rekeyed to an authority whose only record is in an unsupported scheme. */
  rejected: hashed('rejected', 'on-curve'),
  /** Its history search fails with HTTP 503. */
  unavailable: hashed('unavailable', 'on-curve'),
  /** Its history search answers with a transaction list that is not a list. */
  malformed: hashed('malformed', 'on-curve'),
  /** Holds WHALE_BALANCE. */
  whale: hashed('whale', 'on-curve'),
  /** Its incoming search returns one page, then fails. */
  brokenSearch: hashed('broken search', 'on-curve'),
  /** Its account read fails with HTTP 404 (CORE-04). */
  accountMissing: hashed('account missing', 'on-curve'),
  /** Its account record reports more held assets than it lists (CORE-04). */
  accountUnusable: hashed('account unusable', 'on-curve'),
  /** A plan target: off-curve, as a Falcon address always is. */
  target: falcon(9).address,
};

/** @type {Record<string, { amount: bigint, authAddr?: string }>} */
const ACCOUNTS = {
  [FIXTURE.classical]: { amount: 5_000_000n },
  [FIXTURE.manager]: { amount: 300_000n },
  [FIXTURE.postQuantum]: { amount: 5_000_000n, authAddr: PQ.address },
  [FIXTURE.multisig]: { amount: 5_000_000n },
  [FIXTURE.logicsig]: { amount: 5_000_000n },
  [FIXTURE.unconfirmed]: { amount: 5_000_000n, authAddr: SILENT },
  [FIXTURE.rejected]: { amount: 5_000_000n, authAddr: ODD.address },
  [FIXTURE.unavailable]: { amount: 5_000_000n, authAddr: SILENT },
  [FIXTURE.malformed]: { amount: 5_000_000n, authAddr: SILENT },
  [FIXTURE.whale]: { amount: WHALE_BALANCE },
  [FIXTURE.brokenSearch]: { amount: 5_000_000n },
  [BEHIND]: { amount: 2_000_000n, authAddr: FIXTURE.brokenSearch },
};

const b64 = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString('base64');
const decode = (/** @type {string} */ address) => algosdk.decodeAddress(address).publicKey;

/**
 * A confirmed transaction `sender` sent, authorised as `signature` says.
 * @param {string} id @param {string} sender @param {string | undefined} authAddr @param {object} signature
 */
const record = (id, sender, authAddr, signature) => ({
  id,
  sender,
  ...(authAddr ? { 'auth-addr': authAddr } : {}),
  'confirmed-round': CONFIRMED_ROUND,
  fee: 1000,
  'first-valid': 1,
  'last-valid': 1000,
  'tx-type': 'pay',
  signature,
});

/** @param {ReturnType<typeof falcon>} authority @param {string} scheme */
const pqsig = (authority, scheme = 'f1') => ({
  pqsig: {
    scheme,
    'public-key': b64(authority.publicKey),
    salt: authority.salt,
    // Real-length signature bytes. Falconer never examines their content.
    signature: b64(new Uint8Array(1230).fill(9)),
  },
});

/** @type {Record<string, unknown[]>} */
const HISTORY = {
  [FIXTURE.postQuantum]: [record(TXIDS.postQuantum, FIXTURE.postQuantum, PQ.address, pqsig(PQ))],
  [FIXTURE.rejected]: [record(TXIDS.rejected, FIXTURE.rejected, ODD.address, pqsig(ODD, 'f9'))],
  [FIXTURE.multisig]: [
    record(TXIDS.multisig, FIXTURE.multisig, undefined, {
      multisig: {
        version: 1,
        threshold: 2,
        subsignature: MSIG.addrs.map((a, i) => ({
          'public-key': b64(decode(a)),
          ...(i < 2 ? { signature: b64(new Uint8Array(64).fill(i + 1)) } : {}),
        })),
      },
    }),
  ],
  [FIXTURE.logicsig]: [
    record(TXIDS.logicsig, FIXTURE.logicsig, undefined, { logicsig: { logic: b64(LSIG.logic) } }),
  ],
};

/** The asset the manager account manages. */
const ASSET_PARAMS = {
  creator: FIXTURE.target,
  manager: FIXTURE.manager,
  reserve: FIXTURE.target,
  clawback: FIXTURE.target,
  name: 'Fixture Dollar',
  'unit-name': 'FXD',
  total: 1_000_000_000_000,
  decimals: 6,
};

/** @param {number} status @param {unknown} body */
const json = (status, body) =>
  new Response(typeof body === 'string' ? body : algosdk.stringifyJSON(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

/** @param {string} address */
function account(address) {
  if (address === FIXTURE.accountMissing) return json(404, { message: 'no accounts found for address' });
  const a = ACCOUNTS[address] ?? { amount: 0n };
  return json(200, {
    address,
    amount: a.amount,
    'amount-without-pending-rewards': a.amount,
    'min-balance': 100_000,
    ...(a.authAddr ? { 'auth-addr': a.authAddr } : {}),
    round: PROVIDER_ROUND,
    status: 'Offline',
    ...(address === FIXTURE.accountUnusable ? { 'total-assets-opted-in': 2 } : {}),
    assets: [],
    'created-assets': [],
    'created-apps': [],
    'apps-local-state': [],
  });
}

/** @param {URL} u */
function algod(u) {
  const [, version, kind, id] = u.pathname.split('/');
  if (version !== 'v2' || !id) return undefined;
  if (kind === 'accounts') return account(id);
  if (kind === 'assets') {
    return id === String(ASSET)
      ? json(200, { index: ASSET, params: ASSET_PARAMS })
      : json(404, { message: 'asset does not exist' });
  }
  if (kind === 'applications') return json(404, { message: 'application does not exist' });
  return undefined;
}

/** @param {URL} u */
function indexer(u) {
  const q = u.searchParams;
  if (u.pathname === '/v2/transactions' && q.get('address-role') === 'sender') {
    const sender = q.get('address') ?? '';
    if (sender === FIXTURE.unavailable) return json(503, { message: 'fixture: indexer unavailable' });
    if (sender === FIXTURE.malformed) {
      return json(200, `{"current-round":${PROVIDER_ROUND},"transactions":"not a list"}`);
    }
    return json(200, { 'current-round': PROVIDER_ROUND, transactions: HISTORY[sender] ?? [] });
  }
  if (u.pathname === '/v2/accounts' && q.has('auth-addr')) {
    const auth = q.get('auth-addr');
    if (auth === FIXTURE.brokenSearch && q.has('next')) {
      return json(503, { message: 'fixture: indexer unavailable' });
    }
    const accounts = Object.entries(ACCOUNTS)
      .filter(([, a]) => a.authAddr === auth)
      .map(([address, a]) => ({ address, amount: a.amount }));
    return json(200, {
      'current-round': PROVIDER_ROUND,
      accounts,
      ...(auth === FIXTURE.brokenSearch ? { 'next-token': 'page-2' } : {}),
    });
  }
  return undefined;
}

const origin = (/** @type {string} */ url) => new URL(url).origin;
const ALGOD = new Set(Object.values(NETWORKS).map((n) => origin(n.algodUrl)));
const INDEXER = new Set(Object.values(NETWORKS).flatMap((n) => (n.indexerUrl ? [origin(n.indexerUrl)] : [])));

/**
 * This ledger's answer to a GET request, or undefined when it has none.
 * @param {string} url @returns {Response | undefined}
 */
export function serve(url) {
  const u = new URL(url);
  if (ALGOD.has(u.origin)) return algod(u);
  if (INDEXER.has(u.origin)) return indexer(u);
  return undefined;
}
