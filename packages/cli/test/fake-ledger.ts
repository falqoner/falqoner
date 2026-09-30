/**
 * A deterministic offline ledger for the CLI's in-process tests, and the
 * records that let a test assert on everything the CLI touched.
 *
 * The ledger answers exactly the reads `analyzeAccount` makes, per network,
 * from fixed fixtures, and the parameter and status reads a plan's budget is
 * priced from (SAFE-03a). Every other provider method is a trap: calling it
 * records the call and throws. That covers every way to submit or simulate a
 * transaction (`sendRawTransaction`, simulation) and anything nobody
 * expected; the core entry points that build a signable transaction are
 * trapped separately (`FORBIDDEN_CORE`). Core turns some provider errors into
 * "unavailable", so tests assert on the records, not only on exit codes.
 *
 * Nothing here holds a secret. Post-quantum evidence is built from a fixed
 * 1793-byte public key, because address binding is all Falconer checks
 * locally and it needs no private key. The on-curve addresses are fixed
 * points with no known private key.
 *
 * This module imports core's source files directly, never `@falqoner/core`:
 * the dispatch tests mock that specifier, and this is where the mock's traps
 * come from.
 */
import algosdk from 'algosdk';
import jsSha512 from 'js-sha512';
import { classifyAddressShape, derivePqAddress } from '../../core/src/falcon.js';
import { NETWORKS, type FalconerClients } from '../../core/src/networks.js';
import { httpError } from '../../core/test/fake-provider.js';
import { txid } from '../../core/test/fixtures.js';

export type NetworkName = keyof typeof NETWORKS;

/** Calls the CLI must never make, in the order they were attempted. */
export const trapped: string[] = [];
/** Networks the CLI created provider clients for, in order. */
export const requested: NetworkName[] = [];
/** Provider reads the ledger answered, as `<network> <method> <subject>`. */
export const reads: string[] = [];

export function resetRecords(): void {
  trapped.length = 0;
  requested.length = 0;
  reads.length = 0;
}

/**
 * A function that records `name` and throws whenever it is called. Its
 * arguments are never recorded: they could be the very secrets being kept
 * out of the output.
 */
export function forbidden(name: string): (...args: unknown[]) => never {
  return () => {
    trapped.push(name);
    throw new Error(`read-only trap: ${name} must never be called`);
  };
}

/**
 * Core entry points that recover or create an identity, sign, or build and
 * submit transactions. The dispatch tests replace each with a trap, so any
 * CLI path reaching one fails loudly.
 */
export const FORBIDDEN_CORE = [
  'pqIdentityFromMnemonic',
  'verifyMnemonicRestores',
  'generatePqIdentity',
  'preflight',
  'selfTestIdentity',
  'makeFalconSigner',
  'fundPqAddress',
  'proveControl',
  'rekeyToPq',
  'verifyMigration',
  // The prepared-attempt path the migration helpers are built on (SAFE-02b),
  // and the budgeted one (SAFE-03a). Pricing a plan builds nothing signable.
  'prepareAttempt',
  'prepareStage',
  'signStage',
  'budgetedSigner',
  'quoteStage',
  'prepareFunding',
  'prepareProof',
  'prepareRekey',
  'prepareControlProof',
  'signAttempt',
  'sendAttempt',
  'submitAndConfirm',
  // The guarded ceremony (SAFE-03b): the only supported way to execute.
  'openCeremony',
  // Clients that would reach a real provider. The CLI must use `clientsFor`,
  // which the tests replace with this ledger.
  'createClients',
] as const;

/* ---------------------------------------------------------------- */

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

/** A Falcon-1024 authority from a fixed public key. There is no private key. */
function falconAuthority(fill: number) {
  const publicKey = new Uint8Array(1793).fill(fill);
  const { address, salt } = derivePqAddress(publicKey);
  return { address, publicKey, salt };
}

/** A fixed on-curve address: the first Ed25519 point hashed from `label`. */
function onCurve(label: string): string {
  for (let i = 0; i < 256; i++) {
    const bytes = Uint8Array.from(
      jsSha512.sha512_256.array(`falconer SAFE-01 ${label} ${i}`),
    );
    const address = new algosdk.Address(bytes).toString();
    if (classifyAddressShape(address) === 'on-curve') return address;
  }
  throw new Error(`no on-curve address for ${label}`);
}

/** A fixed hash-derived address, standing in for a multisig or program. */
function offCurve(label: string): string {
  for (let i = 0; i < 256; i++) {
    const bytes = Uint8Array.from(jsSha512.sha512_256.array(`falconer PQ-04 ${label} ${i}`));
    const address = new algosdk.Address(bytes).toString();
    if (classifyAddressShape(address) === 'off-curve') return address;
  }
  throw new Error(`no off-curve address for ${label}`);
}

const PQ = falconAuthority(3);
/** An authority whose only record claims a scheme Falconer does not support. */
const ODD = falconAuthority(5);
/** A hash-derived authority that has never signed anything. */
const SILENT = falconAuthority(7).address;
/** A post-quantum address that signs for itself, and for one other account. */
const SIGNER = falconAuthority(11);

/** A plan target: off-curve, as a Falcon address always is. */
export const TARGET = falconAuthority(9).address;

/** Accounts that are rekeyed to a scanned address, not scanned themselves. */
const PROTECTED_INCOMING = onCurve('protected incoming');
const BEYOND_PAGE_ONE = onCurve('found on page one');

export const ACCOUNTS = {
  /** Rekeyed to a Falcon authority, with a confirmed record binding it. */
  postQuantum: onCurve('post-quantum'),
  /** Signs for itself from an on-curve address. */
  classical: onCurve('classical'),
  /** Rekeyed to a hash-derived authority that has never signed. */
  unconfirmed: onCurve('unconfirmed'),
  /** Rekeyed to an authority whose only record is in an unsupported scheme. */
  rejected: onCurve('rejected'),
  /** Its history search is answered with a malformed response. */
  malformed: onCurve('malformed'),
  /** Its history search fails. */
  unavailable: onCurve('unavailable'),
  /** A post-quantum address signing only for an account that is itself protected. */
  protectedSigner: SIGNER.address,
  /** A classical account that created an application. */
  appCreator: onCurve('app creator'),
  /** Its incoming search returns one page, then fails. */
  brokenSearch: onCurve('broken search'),
  /** A hash-derived address with a confirmed multisig record of its own. */
  multisig: offCurve('multisig'),
  /** A hash-derived address with a confirmed logic-signature record of its own. */
  logicsig: offCurve('logic signature'),
} as const;

/** An application the app creator created; its state names nobody. */
export const APP_REF = 9001n;
/** An asset id the provider answers 404 for. */
export const MISSING_ASSET = 7404n;
/** An asset id whose read fails. */
export const BROKEN_ASSET = 7500n;
/** An asset id answered with parameters that cannot be read. */
export const MALFORMED_ASSET = 7600n;
/**
 * An asset id answered with the record for MANAGED_ASSET, which would give
 * the classical account a seizing manager role if taken at face value.
 */
export const WRONG_ID_ASSET = 7700n;
/** An application whose global state holds an entry that cannot be read. */
export const MALFORMED_APP = 9002n;

/** The current round every history search reports. */
export const PROVIDER_ROUND = 100;
/** The round every fixture record confirmed in. */
export const CONFIRMED_ROUND = 42;
export const PQ_EVIDENCE_TXID = txid('SAFE-01 post-quantum');
export const REJECTED_TXID = txid('SAFE-01 unsupported scheme');
export const MULTISIG_TXID = txid('PQ-04 multisig');
export const LOGICSIG_TXID = txid('PQ-04 logic signature');

/** An asset the classical account manages, for `scan --assets`. */
export const MANAGED_ASSET = 7001n;

/** Real-length signature bytes. Falconer never examines their content. */
const SIGNATURE = b64(new Uint8Array(1230).fill(9));

function falconRecord(
  id: string,
  sender: string,
  authority: { address: string; publicKey: Uint8Array; salt: number },
  scheme = 'f1',
) {
  return {
    id,
    sender,
    'auth-addr': authority.address,
    'confirmed-round': CONFIRMED_ROUND,
    signature: {
      pqsig: {
        scheme,
        'public-key': b64(authority.publicKey),
        salt: authority.salt,
        signature: SIGNATURE,
      },
    },
  };
}

const LEDGER: Record<
  string,
  { amount: bigint; authAddr?: string; createdApps?: bigint[] }
> = {
  [ACCOUNTS.postQuantum]: { amount: 5_000_000n, authAddr: PQ.address },
  [ACCOUNTS.classical]: { amount: 5_000_000n },
  [ACCOUNTS.unconfirmed]: { amount: 5_000_000n, authAddr: SILENT },
  [ACCOUNTS.rejected]: { amount: 5_000_000n, authAddr: ODD.address },
  [ACCOUNTS.malformed]: { amount: 5_000_000n, authAddr: SILENT },
  [ACCOUNTS.unavailable]: { amount: 5_000_000n, authAddr: SILENT },
  [ACCOUNTS.protectedSigner]: { amount: 1_000_000n },
  [PROTECTED_INCOMING]: { amount: 4_000_000n, authAddr: SIGNER.address },
  [ACCOUNTS.appCreator]: { amount: 5_000_000n, createdApps: [APP_REF] },
  [ACCOUNTS.brokenSearch]: { amount: 5_000_000n },
  [ACCOUNTS.multisig]: { amount: 5_000_000n },
  [ACCOUNTS.logicsig]: { amount: 5_000_000n },
};

/** A self-authorised record, which carries no auth-addr, signed as `signature` says. */
const selfSigned = (id: string, sender: string, signature: unknown) => ({
  id,
  sender,
  'confirmed-round': CONFIRMED_ROUND,
  signature,
});

const HISTORY: Record<string, unknown[]> = {
  [ACCOUNTS.postQuantum]: [
    falconRecord(PQ_EVIDENCE_TXID, ACCOUNTS.postQuantum, PQ),
  ],
  [ACCOUNTS.rejected]: [
    falconRecord(REJECTED_TXID, ACCOUNTS.rejected, ODD, 'f9'),
  ],
  [ACCOUNTS.multisig]: [
    selfSigned(MULTISIG_TXID, ACCOUNTS.multisig, {
      multisig: { version: 1, threshold: 2, subsignature: [{}, {}, {}] },
    }),
  ],
  [ACCOUNTS.logicsig]: [
    selfSigned(LOGICSIG_TXID, ACCOUNTS.logicsig, { logicsig: { logic: b64(Uint8Array.of(1, 32, 1, 1, 34)) } }),
  ],
  // Self-authorised, so the record carries no auth-addr.
  [ACCOUNTS.protectedSigner]: [
    {
      ...falconRecord(txid('SAFE-01 signer'), SIGNER.address, SIGNER),
      'auth-addr': undefined,
    },
  ],
};

/* ---------------------------------------------------------------- */

/** `methods`, with every other method replaced by a trap. */
function guard<T extends object>(label: string, methods: T): T {
  return new Proxy(methods, {
    get(target, prop, receiver) {
      if (typeof prop !== 'string' || prop in target) {
        return Reflect.get(target, prop, receiver);
      }
      return forbidden(`${label}.${prop}`);
    },
  });
}

/** The genesis each network's node reports, for the parameters a budget reads. */
const GENESIS: Record<NetworkName, { genesisID: string; genesisHash: Uint8Array }> = {
  mainnet: { genesisID: 'mainnet-v1.0', genesisHash: algosdk.base64ToBytes('wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=') },
  testnet: { genesisID: 'testnet-v1.0', genesisHash: algosdk.base64ToBytes('SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=') },
  localnet: { genesisID: 'dockernet-v1', genesisHash: new Uint8Array(32).fill(3) },
};
/** The protocol algod 5.0.2 reports on all three networks (consensus v42). */
export const PROTOCOL = 'https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f';

function algod(network: NetworkName) {
  return guard(`${network} algod`, {
    accountInformation: (address: string) => ({
      do: async () => {
        reads.push(`${network} accountInformation ${address}`);
        if (!algosdk.isValidAddress(address)) throw new Error('no accounts found for address');
        // As algod answers for an address with no record: nothing, and what creating it takes.
        const account = LEDGER[address] ?? { amount: 0n };
        return {
          address,
          amount: account.amount,
          minBalance: 100_000n,
          authAddr: account.authAddr,
          round: BigInt(PROVIDER_ROUND),
          assets: [],
          createdAssets: [],
          createdApps: (account.createdApps ?? []).map((id) => ({ id })),
          appsLocalState: [],
        };
      },
    }),
    // Read-only: what a budget is priced from. Building or sending a
    // transaction is still a trap.
    getTransactionParams: () => ({
      do: async () => {
        reads.push(`${network} getTransactionParams`);
        return {
          flatFee: false,
          fee: 0n,
          minFee: 1000n,
          firstValid: BigInt(PROVIDER_ROUND),
          lastValid: BigInt(PROVIDER_ROUND) + 1000n,
          ...GENESIS[network],
          consensusVersion: PROTOCOL,
        };
      },
    }),
    status: () => ({
      do: async () => {
        reads.push(`${network} status`);
        return {
          lastRound: BigInt(PROVIDER_ROUND),
          catchupTime: 0n,
          lastVersion: PROTOCOL,
          nextVersion: PROTOCOL,
          nextVersionRound: BigInt(PROVIDER_ROUND) + 1n,
        };
      },
    }),
    getAssetByID: (id: number | bigint) => ({
      do: async () => {
        reads.push(`${network} getAssetByID ${id}`);
        // A read that fails is a failure, and only a 404 is an absence.
        if (BigInt(id) === BROKEN_ASSET) throw httpError(500);
        // Answers, but not ones that say anything about the id asked for.
        if (BigInt(id) === MALFORMED_ASSET) return { index: MALFORMED_ASSET, params: {} };
        if (BigInt(id) === WRONG_ID_ASSET) return { index: MANAGED_ASSET, params: MANAGED_PARAMS };
        if (BigInt(id) !== MANAGED_ASSET) throw httpError(404);
        return { index: MANAGED_ASSET, params: MANAGED_PARAMS };
      },
    }),
    getApplicationByID: (id: number | bigint) => ({
      do: async () => {
        reads.push(`${network} getApplicationByID ${id}`);
        if (BigInt(id) === MALFORMED_APP) {
          return {
            id: MALFORMED_APP,
            params: { creator: ACCOUNTS.appCreator, globalState: [null] },
          };
        }
        if (BigInt(id) !== APP_REF) throw httpError(404);
        // State that names nobody: the creator is granted nothing here.
        return {
          id: APP_REF,
          params: { creator: ACCOUNTS.appCreator, globalState: [] },
        };
      },
    }),
  });
}

/**
 * The classical account manages this asset, whose clawback is live and held
 * by someone else, so manager authority reaches every holder.
 */
const MANAGED_PARAMS = {
  creator: TARGET,
  manager: ACCOUNTS.classical,
  clawback: TARGET,
  name: 'Fixture Coin',
  unitName: 'FIX',
  total: 1_000n,
  decimals: 0,
};

function indexer(network: NetworkName) {
  return guard(`${network} indexer`, {
    searchAccounts: () => ({
      authAddr: (authAddr: string) => ({
        limit: () => {
          let token: string | undefined;
          const query = {
            nextToken: (t: string) => {
              token = t;
              return query;
            },
            do: async () => {
              reads.push(`${network} searchAccounts ${authAddr}${token ? ` ${token}` : ''}`);
              if (authAddr === ACCOUNTS.brokenSearch) {
                // One page, then the provider fails on the next.
                if (token) throw httpError(503);
                return {
                  accounts: [{ address: BEYOND_PAGE_ONE, amount: 2_000_000n }],
                  'next-token': 'page-2',
                };
              }
              return {
                accounts: Object.entries(LEDGER)
                  .filter(([, a]) => a.authAddr === authAddr)
                  .map(([address, a]) => ({ address, amount: a.amount })),
              };
            },
          };
          return query;
        },
      }),
    }),
    searchForAssets: () => ({
      limit: () => ({
        do: async () => {
          reads.push(`${network} searchForAssets`);
          // The whole of this small ledger, in one page.
          return { assets: [{ index: MANAGED_ASSET, params: MANAGED_PARAMS }] };
        },
      }),
    }),
    searchForTransactions: () => ({
      address: (sender: string) => ({
        addressRole: (role: string) => ({
          limit: () => ({
            do: async () => {
              reads.push(`${network} searchForTransactions ${role} ${sender}`);
              if (sender === ACCOUNTS.unavailable) {
                throw new Error('indexer unavailable');
              }
              if (sender === ACCOUNTS.malformed) {
                return { 'current-round': PROVIDER_ROUND, transactions: 'not a list' };
              }
              return {
                'current-round': PROVIDER_ROUND,
                transactions: HISTORY[sender] ?? [],
              };
            },
          }),
        }),
      }),
    }),
  });
}

/**
 * Stands in for core's `clientsFor`. The network configuration is the real
 * one, so provenance names the real network and indexer; only the transport
 * is replaced.
 */
export function fakeClientsFor(network: NetworkName): FalconerClients {
  requested.push(network);
  return {
    algod: algod(network) as unknown as FalconerClients['algod'],
    indexer: indexer(network) as unknown as FalconerClients['indexer'],
    network: NETWORKS[network],
  };
}
