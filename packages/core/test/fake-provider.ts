/**
 * A scriptable offline provider for coverage tests (CORE-03).
 *
 * Every read the scan makes can be scripted to succeed, fail with an HTTP
 * status, throw, or answer with something malformed: incoming-search pages
 * per authority, asset and application reads by id, and ledger-sample pages.
 * Unscripted reads fall back to a well-formed answer built from `accounts`.
 * Every request is recorded, so a test can count what the scan asked for.
 *
 * Nothing here holds a secret. Falcon evidence is built from fixed public
 * keys, because address binding is all Falconer checks locally, and the
 * other addresses are fixed points with no known private key.
 */
import algosdk from 'algosdk';
import jsSha512 from 'js-sha512';
import { classifyAddressShape, derivePqAddress } from '../src/falcon.js';
import type { FalconerClients } from '../src/networks.js';
import { txid } from './fixtures.js';

/** An error shaped like algosdk's, carrying an HTTP status. */
export function httpError(status: number): Error {
  return Object.assign(
    new Error(`Network request error. Received status ${status} (provider)`),
    { response: { status } },
  );
}

const hash = (label: string) =>
  Uint8Array.from(jsSha512.sha512_256.array(`fake-provider ${label}`));

/** A deterministic valid address. No key exists for it. */
export function addressFor(label: string): string {
  return new algosdk.Address(hash(label)).toString();
}

/** A deterministic on-curve address, so it reads as a classical key. */
export function onCurveAddress(label: string): string {
  for (let i = 0; i < 256; i++) {
    const address = addressFor(`${label} ${i}`);
    if (classifyAddressShape(address) === 'on-curve') return address;
  }
  throw new Error(`no on-curve address for ${label}`);
}

/** A Falcon-1024 authority from a fixed public key. There is no private key. */
export function falconAuthority(fill: number) {
  const publicKey = new Uint8Array(1793).fill(fill);
  const { address, salt } = derivePqAddress(publicKey);
  return { address, publicKey, salt };
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

/**
 * A confirmed transaction `sender` sent, authorised by the Falcon key behind
 * `authority`. Self-authorised when the sender is the authority itself.
 */
export function falconRecord(
  label: string,
  sender: string,
  authority: ReturnType<typeof falconAuthority>,
): Record<string, unknown> {
  return {
    id: txid(label),
    sender,
    'confirmed-round': 42,
    ...(sender === authority.address ? {} : { 'auth-addr': authority.address }),
    signature: {
      pqsig: {
        scheme: 'f1',
        'public-key': b64(authority.publicKey),
        salt: authority.salt,
        signature: b64(new Uint8Array(1230).fill(9)),
      },
    },
  };
}

/** A scripted answer: a value, an error to throw, or a function of the call. */
type Script<A extends unknown[]> = unknown | Error | ((...args: A) => unknown);

export interface FakeAccount {
  amount?: bigint;
  authAddr?: string;
  /** Ids of assets held. */
  assets?: bigint[];
  createdAssets?: Array<{ index: bigint; params: Record<string, unknown> }>;
  createdApps?: bigint[];
  optedInApps?: bigint[];
}

export interface FakeSpec {
  accounts?: Record<string, FakeAccount>;
  /** Transactions each sender sent, newest first. */
  history?: Record<string, unknown[]>;
  /**
   * Incoming-search pages per authority, in request order. A function is
   * called with the page number (from 1) and the continuation token sent.
   */
  incoming?: Record<string, unknown[] | ((page: number, token?: string) => unknown)>;
  /** Asset reads by id. Unscripted ids answer 404. */
  assets?: Record<string, Script<[]>>;
  /** Application reads by id. Unscripted ids answer 404. */
  apps?: Record<string, Script<[]>>;
  /**
   * Ledger-sample pages, in request order; past the end, an empty page. A
   * function is called with the page number (from 1) and the token sent.
   */
  sample?: unknown[] | ((page: number, token?: string) => unknown);
  /** No indexer configured at all. */
  noIndexer?: boolean;
}

export interface FakeProvider {
  clients: FalconerClients;
  /** Every request, as `<method> <subject>`. */
  requests: string[];
}

async function answer(script: unknown, ...args: unknown[]): Promise<unknown> {
  if (script instanceof Error) throw script;
  if (typeof script === 'function') {
    const out = await (script as (...a: unknown[]) => unknown)(...args);
    if (out instanceof Error) throw out;
    return out;
  }
  return script;
}

export function fakeProvider(spec: FakeSpec): FakeProvider {
  const requests: string[] = [];
  const accounts = spec.accounts ?? {};
  const incomingCalls = new Map<string, number>();
  let samplePage = 0;

  const algod = {
    accountInformation: (address: string) => ({
      do: async () => {
        requests.push(`accountInformation ${address}`);
        // As algod answers an address it has no record for: an empty account.
        const a = accounts[address] ?? { amount: 0n };
        return {
          amount: a.amount ?? 1_000_000n,
          minBalance: 100_000n,
          authAddr: a.authAddr,
          assets: (a.assets ?? []).map((assetId) => ({ assetId, amount: 1n })),
          createdAssets: a.createdAssets ?? [],
          createdApps: (a.createdApps ?? []).map((id) => ({ id })),
          appsLocalState: (a.optedInApps ?? []).map((id) => ({ id })),
        };
      },
    }),
    getAssetByID: (id: bigint) => ({
      do: async () => {
        requests.push(`getAssetByID ${id}`);
        const script = spec.assets?.[String(id)];
        if (script === undefined) throw httpError(404);
        return answer(script);
      },
    }),
    getApplicationByID: (id: bigint) => ({
      do: async () => {
        requests.push(`getApplicationByID ${id}`);
        const script = spec.apps?.[String(id)];
        if (script === undefined) throw httpError(404);
        return answer(script);
      },
    }),
  };

  const indexer = {
    searchAccounts: () => ({
      authAddr: (auth: string) => ({
        limit: (limit: number) => {
          let token: string | undefined;
          const query = {
            nextToken: (t: string) => {
              token = t;
              return query;
            },
            do: async () => {
              const page = (incomingCalls.get(auth) ?? 0) + 1;
              incomingCalls.set(auth, page);
              requests.push(`searchAccounts ${auth} page ${page} limit ${limit}${token ? ` token ${token}` : ''}`);
              const script = spec.incoming?.[auth];
              if (script === undefined) {
                return {
                  accounts: Object.entries(accounts)
                    .filter(([, a]) => a.authAddr === auth)
                    .map(([address, a]) => ({ address, amount: a.amount ?? 1_000_000n })),
                };
              }
              if (typeof script === 'function') return answer(script, page, token);
              // Past the scripted pages, an empty one. A scripted null is kept:
              // it is exactly the kind of malformed page a test asks for.
              return answer(page <= script.length ? script[page - 1] : { accounts: [] });
            },
          };
          return query;
        },
      }),
    }),
    searchForTransactions: () => ({
      address: (sender: string) => ({
        addressRole: () => ({
          limit: () => ({
            do: async () => {
              requests.push(`searchForTransactions ${sender}`);
              return {
                'current-round': 100,
                transactions: spec.history?.[sender] ?? [],
              };
            },
          }),
        }),
      }),
    }),
    searchForAssets: () => ({
      limit: (limit: number) => {
        let token: string | undefined;
        const query = {
          nextToken: (t: string) => {
            token = t;
            return query;
          },
          do: async () => {
            samplePage++;
            requests.push(
              `searchForAssets page ${samplePage} limit ${limit}${token ? ` token ${token}` : ''}`,
            );
            const pages = spec.sample ?? [];
            if (typeof pages === 'function') return answer(pages, samplePage, token);
            return answer(samplePage <= pages.length ? pages[samplePage - 1] : { assets: [] });
          },
        };
        return query;
      },
    }),
  };

  return {
    clients: {
      algod: algod as any,
      indexer: spec.noIndexer ? undefined : (indexer as any),
      network: {
        name: 'localnet',
        algodUrl: 'http://localhost:4001',
        algodToken: '',
        indexerUrl: spec.noIndexer ? undefined : 'http://localhost:8980',
      },
    },
    requests,
  };
}

/** An account record for an incoming-search page. */
export const accountRecord = (address: string, amount = 1_000_000n) => ({
  address,
  amount,
});
