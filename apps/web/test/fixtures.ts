/**
 * Fixtures for the migration tests (SAFE-02a).
 *
 * Nothing here is a real recovery phrase. The signing key comes from a fixed,
 * public seed and exists only for these tests. A fixture identity's "phrase"
 * is 25 placeholder tokens that no wallet would accept, bound to an address
 * derived from a fixed public key with no private key behind it.
 */
import algosdk from 'algosdk';
import {
  prepareControlProof,
  prepareFunding,
  prepareProof,
  prepareRekey,
  type AttemptEvidence,
  type PqIdentity,
  type TransactionAttempt,
} from '@falconer/core';
import { falconAuthority } from '../../../packages/core/test/fake-provider';
import { scriptedLedger } from '../../../packages/core/test/scripted-ledger';

/** A fixed-seed Algorand account: the key that signs the funding and rekey. */
export function signingFixture(fill: number) {
  const phrase = algosdk.mnemonicFromSeed(new Uint8Array(32).fill(fill));
  return { phrase, address: algosdk.mnemonicToSecretKey(phrase).addr.toString() };
}

/** A post-quantum identity whose phrase is placeholders: `<label>01 … <label>25`. */
export function identityFixture(fill: number, label: string): PqIdentity {
  const authority = falconAuthority(fill);
  return {
    scheme: new Uint8Array([0x66, 0x31]),
    publicKey: authority.publicKey,
    privateKey: new Uint8Array(0),
    address: authority.address,
    salt: authority.salt,
    mnemonic: Array.from({ length: 25 }, (_, i) => `${label}${String(i + 1).padStart(2, '0')}`).join(' '),
  };
}

export const TESTNET_GENESIS = {
  genesisID: 'testnet-v1.0',
  genesisHash: algosdk.base64ToBytes('SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI='),
};
export const MAINNET_GENESIS = {
  genesisID: 'mainnet-v1.0',
  genesisHash: algosdk.base64ToBytes('wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8='),
};
export const LOCAL_GENESIS = {
  genesisID: 'dockernet-v1',
  genesisHash: new Uint8Array(32).fill(3),
};

export interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(err: unknown): void;
}

export function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** A LockManager stand-in shared by "tabs". */
export function fakeLocks() {
  let holder: object | null = null;
  return {
    manager: {
      request: async (_name: string, options: { ifAvailable: true }, cb: (lock: unknown) => Promise<void> | void) => {
        if (holder && options.ifAvailable) return cb(null);
        const lock = {};
        holder = lock;
        try {
          return await cb(lock);
        } finally {
          holder = null;
        }
      },
    },
    held: () => holder !== null,
  };
}

/** One real attempt per stage, prepared by core against a scripted ledger. */
export async function stageAttempts(
  sender: string,
  target: string,
  { round = 1000n, genesis = LOCAL_GENESIS }: { round?: bigint; genesis?: { genesisID: string; genesisHash: Uint8Array } } = {},
): Promise<Record<'funding' | 'proof' | 'rekey' | 'verification', TransactionAttempt>> {
  const { clients } = scriptedLedger({ genesis, round, accounts: { [sender]: {} } });
  return {
    funding: (await prepareFunding(clients, { address: sender }, target)).attempt,
    proof: (await prepareProof(clients, target)).attempt,
    rekey: (await prepareRekey(clients, { address: sender }, target)).attempt,
    verification: (await prepareControlProof(clients, sender, target)).attempt,
  };
}

const evidence = (a: TransactionAttempt, patch: Partial<AttemptEvidence>): AttemptEvidence => ({
  txId: a.txId,
  outcome: 'unknown',
  confirmedRound: null,
  observedRound: a.firstValid,
  source: 'none',
  nonInclusion: false,
  detail: 'fixture',
  ...patch,
});
export const confirmedEvidence = (a: TransactionAttempt) =>
  evidence(a, { outcome: 'confirmed', confirmedRound: a.firstValid + 1n, source: 'algod-pending' });
export const neverLandedEvidence = (a: TransactionAttempt) =>
  evidence(a, { outcome: 'expired', nonInclusion: true, observedRound: a.lastValid + 1n, source: 'algod-block' });
export const unknownEvidence = (a: TransactionAttempt) => evidence(a, {});
