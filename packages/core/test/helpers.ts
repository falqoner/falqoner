import algosdk from 'algosdk';
import { clientsFor, type FalconerClients } from '../src/networks.js';
import { assessAuthority } from '../src/authority.js';
import type { AuthorityAssessment } from '../src/authority.js';

export const localnet = (): FalconerClients => clientsFor('localnet');

export interface LocalAccount {
  address: string;
  sk: Uint8Array;
  signer: algosdk.TransactionSigner;
}

function toAccount(address: string, sk: Uint8Array): LocalAccount {
  return {
    address,
    sk,
    signer: algosdk.makeBasicAccountTransactionSigner({
      addr: algosdk.decodeAddress(address),
      sk,
    } as any),
  };
}

/**
 * The KMD wallet account used purely as a funder. It is never rekeyed, so
 * repeated test runs against the same LocalNet stay repeatable.
 */
export async function dispenser(
  clients: FalconerClients,
): Promise<LocalAccount> {
  const kmd = new algosdk.Kmd('a'.repeat(64), 'http://localhost', 4002);
  const wallets = await kmd.listWallets();
  const wallet = wallets.wallets.find(
    (w: any) => w.name === 'unencrypted-default-wallet',
  );
  if (!wallet) throw new Error('LocalNet default wallet not found');
  const handle = (await kmd.initWalletHandle(wallet.id, '')).wallet_handle_token;
  const { addresses } = await kmd.listKeys(handle);
  for (const address of addresses) {
    const info: any = await clients.algod.accountInformation(address).do();
    if (BigInt(info.amount ?? 0) > 100_000_000n && !info.authAddr) {
      const { private_key } = await kmd.exportKey(handle, '', address);
      return toAccount(address, private_key);
    }
  }
  throw new Error(
    'No un-rekeyed funded LocalNet account in the default wallet. Check the ' +
      'wallet with `npm run localnet:status`; recovering chain state is a ' +
      'deliberate, destructive step (see docs/LOCAL_TESTING.md).',
  );
}

/** Create a fresh account funded from the dispenser. */
export async function fundedAccount(
  clients: FalconerClients,
  from: LocalAccount,
  microAlgos = 10_000_000n,
): Promise<LocalAccount> {
  const fresh = algosdk.generateAccount();
  const sp = await clients.algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: from.address,
    receiver: fresh.addr.toString(),
    amount: microAlgos,
    suggestedParams: sp,
  });
  const { txid } = await clients.algod
    .sendRawTransaction(txn.signTxn(from.sk))
    .do();
  await algosdk.waitForConfirmation(clients.algod, txid, 10);
  return toAccount(fresh.addr.toString(), fresh.sk);
}

/** Create an ASA whose roles all point at `owner`. */
export async function createAsset(
  clients: FalconerClients,
  owner: LocalAccount,
  opts: { unitName?: string; clawback?: string | undefined; total?: bigint } = {},
): Promise<bigint> {
  const sp = await clients.algod.getTransactionParams().do();
  const txn = algosdk.makeAssetCreateTxnWithSuggestedParamsFromObject({
    sender: owner.address,
    total: opts.total ?? 1_000_000n,
    decimals: 0,
    defaultFrozen: false,
    unitName: opts.unitName ?? 'TST',
    assetName: 'Falconer Test Asset',
    manager: owner.address,
    reserve: owner.address,
    freeze: owner.address,
    clawback: 'clawback' in opts ? opts.clawback : owner.address,
    suggestedParams: sp,
  });
  const { txid } = await clients.algod
    .sendRawTransaction(txn.signTxn(owner.sk))
    .do();
  const res = await algosdk.waitForConfirmation(clients.algod, txid, 10);
  return BigInt(res.assetIndex ?? 0);
}

/**
 * Rekey `account` to `target`, using the account's own current key.
 * Returns the transaction id, so a caller can wait for exactly it.
 */
export async function rekey(
  clients: FalconerClients,
  account: LocalAccount,
  target: string,
): Promise<string> {
  const sp = await clients.algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: account.address,
    receiver: account.address,
    amount: 0,
    rekeyTo: target,
    suggestedParams: sp,
  });
  const { txid } = await clients.algod
    .sendRawTransaction(txn.signTxn(account.sk))
    .do();
  await algosdk.waitForConfirmation(clients.algod, txid, 10);
  return txid;
}

/** Wait until the LocalNet indexer has caught up to algod's latest round. */
export async function waitForIndexer(
  clients: FalconerClients,
  timeoutMs = 30_000,
): Promise<boolean> {
  if (!clients.indexer) return false;
  const status = await clients.algod.status().do();
  const target = BigInt(status.lastRound ?? 0);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const health: any = await clients.indexer.makeHealthCheck().do();
      if (BigInt(health.round ?? 0) >= target) return true;
    } catch {
      /* indexer still starting */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

/**
 * Block until a specific transaction is visible to the indexer.
 *
 * Comparing rounds races the conduit pipeline, which made this suite flaky.
 * Waiting for the exact transaction the assertion depends on is
 * deterministic.
 */
export async function waitForIndexedTxn(
  clients: FalconerClients,
  txId: string,
  timeoutMs = 30_000,
): Promise<boolean> {
  if (!clients.indexer) return false;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await clients.indexer.lookupTransactionByID(txId).do();
      return true;
    } catch {
      /* not indexed yet */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

/**
 * Poll until the indexer lists exactly `expected` as the accounts rekeyed to
 * `authAddr`.
 *
 * Waits on the query `analyzeAccount` itself runs to find incoming accounts,
 * so an assertion about them cannot race the indexer's account state.
 */
export async function waitForIncoming(
  clients: FalconerClients,
  authAddr: string,
  expected: string[],
  timeoutMs = 30_000,
): Promise<void> {
  const want = [...expected].sort().join(',');
  const deadline = Date.now() + timeoutMs;
  let seen = '';
  while (Date.now() < deadline) {
    try {
      const res: any = await clients.indexer!
        .searchAccounts()
        .authAddr(authAddr)
        .limit(1000)
        .do();
      seen = (res.accounts ?? [])
        .map((a: any) => String(a.address))
        .filter((a: string) => a !== authAddr)
        .sort()
        .join(',');
      if (seen === want) return;
    } catch {
      /* indexer still catching up */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(
    `waitForIncoming timed out for ${authAddr}: expected [${want}], ` +
      `indexer lists [${seen}], indexerLag=${await indexerLag(clients)} rounds`,
  );
}

/** Rounds the indexer is behind algod, or -1 when it cannot be read. */
export async function indexerLag(clients: FalconerClients): Promise<number> {
  try {
    const status = await clients.algod.status().do();
    const health: any = await clients.indexer!.makeHealthCheck().do();
    return Number(BigInt(status.lastRound ?? 0) - BigInt(health.round ?? 0));
  } catch {
    return -1;
  }
}

/**
 * Poll until the indexer can answer the authority question.
 *
 * This waits on the exact query `assessAuthority` runs rather than a proxy
 * for it, and reports indexer lag on timeout so an infrastructure problem is
 * not mistaken for a wrong classification.
 *
 * Only for hash-derived authorities. `proven` means a confirmed record was
 * observed, and an on-curve authority is classified by its shape without
 * one, so waiting on it would time out rather than return.
 */
export async function waitForProvenAuthority(
  clients: FalconerClients,
  address: string,
  timeoutMs = 45_000,
): Promise<AuthorityAssessment> {
  const deadline = Date.now() + timeoutMs;
  let last: AuthorityAssessment | undefined;
  while (Date.now() < deadline) {
    const info: any = await clients.algod.accountInformation(address).do();
    const authAddr = info.authAddr?.toString?.() ?? info.authAddr;
    last = await assessAuthority(clients, address, authAddr);
    if (last.proven) return last;
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(
    `waitForProvenAuthority timed out for ${address}: ` +
      `class=${last?.authorityClass} ` +
      `evidenceUnavailable=${last?.evidenceUnavailable} ` +
      `indexerLag=${await indexerLag(clients)} rounds`,
  );
}
