/**
 * A scripted ledger for submission tests (SAFE-02b).
 *
 * `fake-provider.ts` answers the reads a scan makes. This one models what a
 * submission meets instead: a pool, blocks, validity windows, and each
 * account's authority, which a rekey changes. A send is decoded and checked
 * the way algod checks it - network, validity window, duplicates and which
 * address authorised it - but signatures are not verified.
 *
 * Any request can be made to fail, hang, lose its request or lose its
 * response, one call at a time, so a test can put a fault exactly where it
 * wants one. Every request is recorded, and so is every transaction that
 * reached the ledger, so a test can count sends and check what was sent.
 *
 * Nothing here holds a secret.
 */
import algosdk from 'algosdk';
import type { FalconerClients } from '../src/networks.js';

export const LEDGER_GENESIS = {
  genesisID: 'scripted-v1',
  genesisHash: new Uint8Array(32).fill(7),
};

/** An error shaped like algosdk's, with an HTTP status and algod's text. */
export function httpFailure(status: number, text: string): Error {
  return Object.assign(
    new Error(`Network request error. Received status ${status}: ${text}`),
    { response: { status } },
  );
}

/** What a browser or Node reports when a request or its response is lost. */
export const networkFailure = () => new TypeError('fetch failed');

export type Method = 'params' | 'status' | 'send' | 'pending' | 'block' | 'account' | 'indexer';

export type Fault =
  /** Fails as a network error. Nothing reaches the ledger. */
  | 'lose-request'
  /** Reaches the ledger, then fails as a network error. */
  | 'lose-response'
  /** Never answers. */
  | 'hang'
  | 'not-found'
  | 'server-error'
  /** Answers with something that is not a valid answer. */
  | 'malformed'
  /** A send reaches the ledger, and answers with another id. */
  | { wrongId: string }
  /** Waits for `until`, then goes ahead. */
  | { until: Promise<unknown> }
  /** Waits for `until`, then reaches the ledger and loses the response. */
  | { until: Promise<unknown>; thenLose: true }
  /** Answers with exactly this, and nothing reaches the ledger. */
  | { answer: unknown };

/** The consensus protocol algod 5.0.2 reports (v42). */
export const LEDGER_PROTOCOL =
  'https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f';
/** v42's minimum balance for an account holding only Algos. */
export const BASE_MIN_BALANCE = 100_000n;

export interface LedgerSpec {
  genesis?: { genesisID: string; genesisHash: Uint8Array };
  round?: bigint;
  accounts?: Record<string, { authAddr?: string; amount?: bigint; minBalance?: bigint }>;
  /** Put each accepted send in a block at once, as dev-mode LocalNet does. */
  autoConfirm?: boolean;
  /** How many rounds the indexer trails algod. */
  indexerLag?: bigint;
  noIndexer?: boolean;
}

interface Account {
  authAddr?: string;
  amount: bigint;
  /** Its minimum balance once it exists; the base minimum unless set. */
  minBalance?: bigint;
}

export function scriptedLedger(spec: LedgerSpec = {}) {
  let genesis = spec.genesis ?? LEDGER_GENESIS;
  let round = spec.round ?? 1000n;
  let autoConfirm = spec.autoConfirm ?? true;
  let indexerLag = spec.indexerLag ?? 0n;
  let catchingUp = false;
  // Fee conditions. A nonzero fee per byte is *simulated* congestion: the
  // pool's per-byte charge, applied here to each send's signed length.
  let protocol = LEDGER_PROTOCOL;
  let minFee = 1000n;
  let feePerByte = 0n;
  let upgrade: { protocol: string; round: bigint } | null = null;
  const blocks = new Map<bigint, string[]>();
  const pruned = new Set<bigint>();
  /** Block answers a test replaced, by round. */
  const blockAnswers = new Map<bigint, unknown>();
  const confirmed = new Map<string, { round: bigint; stxn: algosdk.SignedTransaction }>();
  const pool = new Map<string, algosdk.SignedTransaction>();
  const dropped = new Map<string, { stxn: algosdk.SignedTransaction; error: string }>();
  const accounts = new Map<string, Account>(
    Object.entries(spec.accounts ?? {}).map(([a, v]) => [
      a,
      { authAddr: v.authAddr, amount: v.amount ?? 10_000_000n, minBalance: v.minBalance },
    ]),
  );
  const faults: Array<{ method: Method; fault: Fault; when?: (subject: string, arg?: unknown) => boolean }> = [];
  const requests: string[] = [];
  /** Every transaction that reached the ledger, in order. */
  const landed: algosdk.SignedTransaction[] = [];
  const sendHooks: Array<(stxn: algosdk.SignedTransaction) => void> = [];

  const account = (address: string): Account => {
    let a = accounts.get(address);
    if (!a) {
      a = { amount: 0n };
      accounts.set(address, a);
    }
    return a;
  };

  function mineBlock(ids: string[]) {
    round++;
    blocks.set(round, ids);
    for (const id of ids) {
      const stxn = pool.get(id)!;
      pool.delete(id);
      confirmed.set(id, { round, stxn });
      const t = stxn.txn;
      const sender = t.sender.toString();
      const from = account(sender);
      from.amount -= t.fee + (t.payment?.amount ?? 0n);
      if (t.payment) account(t.payment.receiver.toString()).amount += t.payment.amount;
      if (t.rekeyTo) {
        const to = t.rekeyTo.toString();
        from.authAddr = to === sender ? undefined : to;
      }
    }
  }

  const minOf = (a: Account) => a.minBalance ?? BASE_MIN_BALANCE;

  /** What the pool already holds against `address`: debits and credits not yet in a block. */
  function pendingNet(address: string): bigint {
    let net = 0n;
    for (const p of pool.values()) {
      const t = p.txn;
      if (t.sender.toString() === address) net -= t.fee + (t.payment?.amount ?? 0n);
      if (t.payment && t.payment.receiver.toString() === address) net += t.payment.amount;
    }
    return net;
  }

  /**
   * The fee checks algod makes: consensus requires `minFee` times the fee
   * factor, one plus 2 for a Falcon-1024 signature (go-algorand
   * `PQSchemeFeeContribution`); the pool requires the fee per byte times
   * the signed length (`checkSufficientFee`). Independent of budget.ts.
   */
  function checkFee(id: string, stxn: algosdk.SignedTransaction, length: number) {
    const factorMicros = 1_000_000n + (stxn.pqsig ? 2_000_000n : 0n);
    const consensus = (minFee * factorMicros + 999_999n) / 1_000_000n;
    const fee = stxn.txn.fee;
    if (fee < consensus) {
      throw httpFailure(400, `TransactionPool.Remember: transaction ${id}: txgroup with ${fee} fees is less than ${consensus}`);
    }
    const perByte = feePerByte * BigInt(length);
    if (fee < perByte) {
      throw httpFailure(400, `TransactionPool.Remember: transaction ${id}: fee ${fee} below threshold ${perByte} (${feePerByte} per byte * ${length} bytes)`);
    }
  }

  /** The minimum-balance checks algod makes on a payment's sender and receiver. */
  function checkBalances(id: string, t: algosdk.Transaction) {
    const sender = t.sender.toString();
    const from = account(sender);
    const amount = t.payment?.amount ?? 0n;
    const after = from.amount + pendingNet(sender) - t.fee - amount;
    if (after < minOf(from)) {
      throw httpFailure(400, `TransactionPool.Remember: transaction ${id}: account ${sender} balance ${after} below min ${minOf(from)}`);
    }
    if (t.payment) {
      const receiver = t.payment.receiver.toString();
      if (receiver === sender) return;
      const to = account(receiver);
      const credited = to.amount + pendingNet(receiver) + amount;
      if (credited > 0n && credited < minOf(to)) {
        throw httpFailure(400, `TransactionPool.Remember: transaction ${id}: account ${receiver} balance ${credited} below min ${minOf(to)}`);
      }
    }
  }

  /** Take the send into the pool, as algod does, or refuse it as algod would. */
  function admit(bytes: Uint8Array): { txid: string } {
    const stxn = algosdk.decodeSignedTransaction(bytes);
    const t = stxn.txn;
    const id = t.txID();
    if (t.genesisID !== genesis.genesisID || algosdk.bytesToBase64(t.genesisHash!) !== algosdk.bytesToBase64(genesis.genesisHash)) {
      throw httpFailure(400, `TransactionPool.Remember: genesis mismatch for ${id}`);
    }
    if (confirmed.has(id)) {
      throw httpFailure(400, `TransactionPool.Remember: transaction already in ledger: ${id}`);
    }
    if (pool.has(id)) return { txid: id };
    const next = round + 1n;
    if (next < t.firstValid || next > t.lastValid) {
      throw httpFailure(400, `TransactionPool.Remember: txn dead: round ${next} outside of ${t.firstValid}--${t.lastValid}`);
    }
    const sender = t.sender.toString();
    const expected = account(sender).authAddr ?? sender;
    const actual = stxn.sgnr?.toString() ?? sender;
    if (expected !== actual) {
      throw httpFailure(
        400,
        `TransactionPool.Remember: transaction ${id}: should have been authorized by ${expected} but was actually authorized by ${actual}`,
      );
    }
    checkFee(id, stxn, bytes.length);
    checkBalances(id, t);
    pool.set(id, stxn);
    landed.push(stxn);
    for (const hook of sendHooks) hook(stxn);
    if (autoConfirm) mineBlock([id]);
    return { txid: id };
  }

  function takeFault(method: Method, subject: string, arg?: unknown): Fault | undefined {
    const i = faults.findIndex((f) => f.method === method && (!f.when || f.when(subject, arg)));
    if (i < 0) return undefined;
    return faults.splice(i, 1)[0]!.fault;
  }

  async function call<T>(method: Method, subject: string, answer: () => T, arg?: unknown): Promise<T> {
    requests.push(`${method} ${subject}`.trim());
    const fault = takeFault(method, subject, arg);
    if (fault === 'hang') return new Promise<T>(() => undefined);
    if (fault === 'lose-request') throw networkFailure();
    if (fault === 'not-found') throw httpFailure(404, 'not found');
    if (fault === 'server-error') throw httpFailure(500, 'internal error');
    if (fault === 'malformed') return { malformed: true } as T;
    if (fault && typeof fault === 'object' && 'answer' in fault) return fault.answer as T;
    if (fault && typeof fault === 'object' && 'until' in fault) {
      await fault.until;
      if ('thenLose' in fault) {
        answer();
        throw networkFailure();
      }
    }
    if (fault === 'lose-response') {
      answer();
      throw networkFailure();
    }
    if (fault && typeof fault === 'object' && 'wrongId' in fault) {
      answer();
      return { txid: fault.wrongId } as T;
    }
    return answer();
  }

  const idOf = (bytes: Uint8Array) => {
    try {
      return algosdk.decodeSignedTransaction(bytes).txn.txID();
    } catch {
      return '(undecodable)';
    }
  };

  const algod = {
    getTransactionParams: () => ({
      do: () =>
        call('params', '', () => ({
          fee: feePerByte,
          minFee,
          flatFee: false,
          firstValid: round,
          lastValid: round + 1000n,
          genesisID: genesis.genesisID,
          genesisHash: genesis.genesisHash,
          consensusVersion: protocol,
        })),
    }),
    status: () => ({
      do: () =>
        call('status', '', () => ({
          lastRound: round,
          catchupTime: catchingUp ? 5_000_000_000n : 0n,
          timeSinceLastRound: 0n,
          lastVersion: protocol,
          nextVersion: upgrade ? upgrade.protocol : protocol,
          nextVersionRound: upgrade ? upgrade.round : round + 1n,
        })),
    }),
    sendRawTransaction: (bytes: Uint8Array) => ({
      do: () => call('send', idOf(bytes), () => admit(bytes), bytes),
    }),
    pendingTransactionInformation: (id: string) => ({
      do: () =>
        call('pending', id, () => {
          const c = confirmed.get(id);
          // algod answers for confirmed transactions from its last 1000 rounds only.
          if (c && round - c.round <= 1000n) return { confirmedRound: c.round, poolError: '', txn: c.stxn };
          const p = pool.get(id);
          if (p) return { poolError: '', txn: p };
          const d = dropped.get(id);
          if (d) return { poolError: d.error, txn: d.stxn };
          throw httpFailure(
            404,
            'could not find the transaction in the transaction pool or in the last 1000 confirmed rounds',
          );
        }),
    }),
    getBlockTxids: (r: bigint | number) => ({
      do: () =>
        call('block', String(r), () => {
          const at = BigInt(r);
          if (at > round || pruned.has(at)) throw httpFailure(404, 'failed to retrieve information from the ledger');
          if (blockAnswers.has(at)) return blockAnswers.get(at);
          return { blocktxids: [...(blocks.get(at) ?? [])] };
        }),
    }),
    accountInformation: (address: string) => ({
      do: () =>
        call('account', address, () => {
          const a = account(address);
          return {
            address,
            amount: a.amount,
            // As algod: an absent account reports what creating it requires.
            minBalance: a.amount > 0n ? minOf(a) : BASE_MIN_BALANCE,
            authAddr: a.authAddr ? algosdk.Address.fromString(a.authAddr) : undefined,
            round,
          };
        }),
    }),
  };

  const indexer = {
    lookupTransactionByID: (id: string) => ({
      do: () =>
        call('indexer', id, () => {
          const c = confirmed.get(id);
          const indexed = round - indexerLag;
          if (!c || c.round > indexed) throw httpFailure(404, 'no transaction found for transaction id');
          const s = c.stxn;
          // As algosdk decodes the indexer's record: a salt of 0 is absent.
          const pqsig = s.pqsig && {
            scheme: new TextDecoder().decode(s.pqsig.sch),
            publicKey: s.pqsig.pk,
            signature: s.pqsig.sig,
            ...(s.pqsig.slt ? { salt: s.pqsig.slt } : {}),
          };
          return {
            currentRound: indexed,
            transaction: {
              id,
              confirmedRound: c.round,
              genesisId: genesis.genesisID,
              genesisHash: genesis.genesisHash,
              sender: s.txn.sender.toString(),
              ...(s.sgnr ? { authAddr: s.sgnr } : {}),
              signature: { sig: s.sig, multisig: s.msig, logicsig: s.lsig, pqsig },
            },
          };
        }),
    }),
  };

  const clients = {
    algod,
    indexer: spec.noIndexer ? undefined : indexer,
    network: {
      name: 'localnet',
      algodUrl: 'scripted://algod',
      algodToken: '',
      indexerUrl: spec.noIndexer ? undefined : 'scripted://indexer',
    },
  } as unknown as FalconerClients;

  return {
    clients,
    requests,
    landed,
    get round() {
      return round;
    },
    /**
     * Queue a fault for the next matching call of `method`. `when` sees the
     * call's subject (an id, round or address) and, for a send, its bytes.
     */
    fail(method: Method, fault: Fault, when?: (subject: string, arg?: unknown) => boolean) {
      faults.push({ method, fault, when });
    },
    /** Queue `fault` for the next `times` calls of `method`. */
    failTimes(method: Method, fault: Fault, times: number) {
      for (let i = 0; i < times; i++) faults.push({ method, fault });
    },
    pendingFaults: () => faults.length,
    /** Drop every fault still queued. */
    clearFaults() {
      faults.length = 0;
    },
    /** Mine `n` blocks with nothing in them. */
    advance(n = 1n) {
      for (let i = 0n; i < n; i++) mineBlock([]);
    },
    /** Put everything in the pool into one block. */
    mine() {
      mineBlock([...pool.keys()]);
    },
    /** Drop a pooled transaction with a pool error, as algod does. */
    drop(id: string, error: string) {
      const stxn = pool.get(id);
      if (!stxn) throw new Error(`not in the pool: ${id}`);
      pool.delete(id);
      dropped.set(id, { stxn, error });
    },
    setAutoConfirm(on: boolean) {
      autoConfirm = on;
    },
    setIndexerLag(lag: bigint) {
      indexerLag = lag;
    },
    setCatchingUp(on: boolean) {
      catchingUp = on;
    },
    setGenesis(g: { genesisID: string; genesisHash: Uint8Array }) {
      genesis = g;
    },
    prune(from: bigint, to: bigint) {
      for (let r = from; r <= to; r++) pruned.add(r);
    },
    unprune() {
      pruned.clear();
    },
    /** Answer every read of block `round` with `answer`, whatever it holds. */
    setBlockAnswer(round: bigint, answer: unknown) {
      blockAnswers.set(round, answer);
    },
    setAuthority(address: string, authAddr: string | undefined) {
      account(address).authAddr = authAddr;
    },
    /** Set an account's balance directly, as a transfer from outside this test would. */
    setBalance(address: string, amount: bigint) {
      account(address).amount = amount;
    },
    balance(address: string): bigint {
      return account(address).amount;
    },
    setMinBalance(address: string, min: bigint) {
      account(address).minBalance = min;
    },
    setMinFee(fee: bigint) {
      minFee = fee;
    },
    /** Simulated congestion: the pool's per-byte charge. */
    setFeePerByte(fee: bigint) {
      feePerByte = fee;
    },
    setProtocol(p: string) {
      protocol = p;
    },
    scheduleUpgrade(next: { protocol: string; round: bigint } | null) {
      upgrade = next;
    },
    authority(address: string): string {
      return account(address).authAddr ?? address;
    },
    confirmedRound(id: string): bigint | undefined {
      return confirmed.get(id)?.round;
    },
    onSend(hook: (stxn: algosdk.SignedTransaction) => void) {
      sendHooks.push(hook);
    },
    /** Sends of each kind that reached the ledger, by the shape of the transaction. */
    sends(filter: (t: algosdk.Transaction, s: algosdk.SignedTransaction) => boolean) {
      return landed.filter((s) => filter(s.txn, s));
    },
    count(method: Method) {
      return requests.filter((r) => r === method || r.startsWith(`${method} `)).length;
    },
  };
}

export type ScriptedLedger = ReturnType<typeof scriptedLedger>;
