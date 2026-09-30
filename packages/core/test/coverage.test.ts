/**
 * Coverage and capability accuracy (CORE-03).
 *
 * A scan used to read one page of accounts rekeyed to an address and call it
 * complete, swallow failed asset and application reads, count attempts as
 * reads, and treat creating an application as holding delete and update
 * powers. These drive `analyzeAccount` against a scripted provider and check
 * that every shortfall is named, kept out of a clean verdict, and never
 * mistaken for an empty result - and that references are never scored or
 * described as privileges.
 */
import { describe, expect, it } from 'vitest';
import algosdk from 'algosdk';
import {
  analyzeAccount,
  assessRisk,
  riskVerdict,
  OPTED_IN_LIMIT,
} from '../src/exposure.js';
import {
  coverageLines,
  describeReach,
  INCOMING_ACCOUNT_LIMIT,
  INCOMING_REQUEST_LIMIT,
  sampleAssets,
  sampleRequestLimit,
} from '../src/coverage.js';
import { planMigration } from '../src/migrate.js';
import type { AccountExposure } from '../src/types.js';
import {
  accountRecord,
  addressFor,
  falconAuthority,
  falconRecord,
  fakeProvider,
  httpError,
  onCurveAddress,
  type FakeSpec,
} from './fake-provider.js';

/** A classical account holding 5 ALGO and nothing else, unless told otherwise. */
const K = onCurveAddress('classical scanned account');

async function scan(spec: FakeSpec, options: Parameters<typeof analyzeAccount>[2] = {}) {
  const provider = fakeProvider({
    ...spec,
    accounts: { [K]: { amount: 5_000_000n }, ...spec.accounts },
  });
  const e = await analyzeAccount(provider.clients, K, options);
  return { e, requests: provider.requests };
}

/** Every exposure a test produced, checked for consistency at the end. */
const seen: AccountExposure[] = [];
const keep = (e: AccountExposure) => (seen.push(e), e);

const incomingRequests = (requests: string[]) =>
  requests.filter((r) => r.startsWith('searchAccounts'));

/** `n` distinct accounts rekeyed to K, as page records. */
const records = (from: number, n: number) =>
  Array.from({ length: n }, (_, i) => accountRecord(addressFor(`incoming ${from + i}`)));

describe('incoming accounts, page by page', () => {
  it('reads every page until the provider has no more', async () => {
    const { e, requests } = await scan({
      incoming: {
        [K]: [
          { accounts: records(0, 2), 'next-token': 't1' },
          { accounts: records(2, 2), 'next-token': 't2' },
          { accounts: records(4, 1) },
        ],
      },
    });
    keep(e);
    expect(e.controlsAccounts).toHaveLength(5);
    expect(e.coverage.incoming).toMatchObject({
      status: 'complete',
      found: 5,
      requests: 3,
      exhausted: true,
    });
    expect(e.incomingScan).toBe('complete');
    // The continuation token is sent back as given.
    expect(incomingRequests(requests)[1]).toContain('token t1');
    expect(e.risk.incomingUnverified).toBe(false);
  });

  it(`keeps the ${INCOMING_ACCOUNT_LIMIT}-account limit and says more remain`, async () => {
    const { e } = await scan({
      incoming: {
        [K]: [
          { accounts: records(0, 400), 'next-token': 'a' },
          { accounts: records(400, 400), 'next-token': 'b' },
          { accounts: records(800, 400), 'next-token': 'c' },
        ],
      },
    });
    keep(e);
    expect(e.controlsAccounts).toHaveLength(INCOMING_ACCOUNT_LIMIT);
    expect(e.coverage.incoming.status).toBe('partial');
    expect(e.coverage.incoming.exhausted).toBe(false);
    expect(e.coverage.incoming.detail).toContain('the most one scan reads');
    expect(e.risk.complete).toBe(false);
    expect(e.risk.uncertainties.join(' ')).toContain(
      `stopped at ${INCOMING_ACCOUNT_LIMIT}, with more remaining`,
    );
    expect(riskVerdict(e.risk).score).toMatch(/\+$/);
  });

  it('is complete when the limit is met exactly and nothing remains', async () => {
    const { e } = await scan({
      incoming: {
        [K]: [
          { accounts: records(0, 600), 'next-token': 'a' },
          { accounts: records(600, 400) },
        ],
      },
    });
    keep(e);
    expect(e.controlsAccounts).toHaveLength(INCOMING_ACCOUNT_LIMIT);
    expect(e.coverage.incoming.status).toBe('complete');
  });

  it(`stops at ${INCOMING_REQUEST_LIMIT} requests when pages never end`, async () => {
    const { e, requests } = await scan({
      incoming: {
        [K]: (page) => ({ accounts: records(page, 1), 'next-token': `t${page}` }),
      },
    });
    keep(e);
    expect(incomingRequests(requests)).toHaveLength(INCOMING_REQUEST_LIMIT);
    expect(e.controlsAccounts).toHaveLength(INCOMING_REQUEST_LIMIT);
    expect(e.coverage.incoming.status).toBe('partial');
    expect(e.coverage.incoming.detail).toContain(`in ${INCOMING_REQUEST_LIMIT} requests`);
  });

  it('stops at a repeated continuation token instead of looping', async () => {
    const { e, requests } = await scan({
      incoming: { [K]: (page) => ({ accounts: records(page * 10, 2), 'next-token': 'same' }) },
    });
    keep(e);
    expect(incomingRequests(requests)).toHaveLength(2);
    expect(e.coverage.incoming.status).toBe('invalid-response');
    expect(e.coverage.incoming.errors).toContain('the provider repeated a continuation token');
    // What the pages before it found is kept.
    expect(e.controlsAccounts).toHaveLength(4);
  });

  it('drops duplicates across pages, so no balance counts twice', async () => {
    const [a, b, c] = [0, 1, 2].map((i) => addressFor(`dup ${i}`));
    const { e } = await scan({
      incoming: {
        [K]: [
          { accounts: [accountRecord(a!, 5_000_000n), accountRecord(b!, 3_000_000n)], 'next-token': 'x' },
          { accounts: [accountRecord(b!, 3_000_000n), accountRecord(c!, 2_000_000n)] },
        ],
      },
    });
    keep(e);
    expect(e.controlsAccounts).toEqual([a, b, c]);
    expect(e.coverage.incoming.duplicates).toBe(1);
    expect(e.risk.directMicroAlgos).toBe(5_000_000n + 10_000_000n);
    expect(e.coverage.incoming.status).toBe('complete');
  });

  it('keeps earlier pages when a later request fails', async () => {
    const { e } = await scan({
      incoming: { [K]: [{ accounts: records(0, 2), 'next-token': 'n' }, httpError(503)] },
    });
    keep(e);
    expect(e.controlsAccounts).toHaveLength(2);
    expect(e.incomingScan).toBe('partial');
    expect(e.coverage.incoming.errors).toEqual(['HTTP 503']);
    expect(e.coverage.incoming.detail).toContain('before a later request failed (HTTP 503)');
    const f = e.findings.find((x) => x.title.includes('did not finish'));
    expect(f).toBeDefined();
    expect(e.risk.complete).toBe(false);
  });

  it('reads a failed first request as unavailable, never as none', async () => {
    const { e } = await scan({ incoming: { [K]: [httpError(500)] } });
    keep(e);
    expect(e.incomingScan).toBe('unavailable');
    expect(e.controlsAccounts).toEqual([]);
    expect(e.findings.some((f) => f.title.includes('could not be checked'))).toBe(true);
    expect(e.risk.band).not.toBe('safe');
  });

  const MALFORMED: Array<[string, unknown, string]> = [
    ['a response that is not an object', null, 'response is not an object'],
    ['no account list', {}, 'no account list'],
    ['an account list that is not a list', { accounts: 'none' }, 'account list is not a list'],
    ['a continuation token that is not text', { accounts: [], 'next-token': 7 }, 'malformed continuation token'],
    ['an empty continuation token', { accounts: [], 'next-token': '' }, 'malformed continuation token'],
  ];
  it.each(MALFORMED)('refuses %s as an empty, complete search', async (_name, page, fault) => {
    const { e } = await scan({ incoming: { [K]: [page] } });
    keep(e);
    expect(e.coverage.incoming.status).toBe('invalid-response');
    expect(e.coverage.incoming.errors).toEqual([fault]);
    expect(e.risk.complete).toBe(false);
    expect(riskVerdict(e.risk).safe).toBe(false);
  });

  it('keeps valid records from a page with malformed ones, and says so', async () => {
    const good = addressFor('good record');
    const { e } = await scan({
      incoming: {
        [K]: [
          {
            accounts: [
              accountRecord(good),
              { address: 'not-an-address', amount: 1 },
              { address: addressFor('negative'), amount: -1 },
            ],
          },
        ],
      },
    });
    keep(e);
    expect(e.controlsAccounts).toEqual([good]);
    expect(e.coverage.incoming.status).toBe('invalid-response');
    expect(e.coverage.incoming.errors).toEqual(['2 malformed account record(s)']);
  });

  it('reads a valid empty list as a finished search that found none', async () => {
    const { e } = await scan({ incoming: { [K]: [{ accounts: [] }] } });
    keep(e);
    expect(e.coverage.incoming).toMatchObject({ status: 'complete', found: 0, exhausted: true });
    expect(e.risk.complete).toBe(true);
  });
});

describe('without an indexer', () => {
  it('claims nothing about rekeyed accounts or signing history', async () => {
    const pq = falconAuthority(21);
    const provider = fakeProvider({
      accounts: { [K]: { amount: 5_000_000n, authAddr: pq.address } },
      noIndexer: true,
    });
    const e = keep(await analyzeAccount(provider.clients, K));
    expect(e.coverage.incoming.status).toBe('unavailable');
    expect(e.coverage.incoming.detail).toContain('No indexer is configured');
    // An off-curve authority needs its history, and it could not be read.
    expect(e.coverage.history.status).toBe('unavailable');
    expect(e.risk.complete).toBe(false);
    expect(e.risk.uncertainties).toEqual(
      expect.arrayContaining([
        'accounts rekeyed to this address could not be checked',
        'what signs for this account could not be checked',
      ]),
    );
  });

  it('makes a requested ledger sample visibly unavailable', async () => {
    const provider = fakeProvider({ accounts: { [K]: {} }, noIndexer: true });
    const e = keep(await analyzeAccount(provider.clients, K, { deepScan: true }));
    expect(e.coverage.assets.sample.status).toBe('unavailable');
    expect(e.coverage.assets.sample.detail).toContain('could not run');
    expect(e.risk.uncertainties).toContain('the requested ledger sample could not run');
  });
});

describe('reads by id', () => {
  const PARAMS = { creator: addressFor('someone'), total: 10n, decimals: 0 };

  it('reads a 404 for a named asset as established absence', async () => {
    const { e } = await scan({}, { assetIds: [404n] });
    keep(e);
    expect(e.coverage.assets.named).toMatchObject({ requested: 1, attempted: 1, notFound: 1, read: 0 });
    expect(e.coverage.assets.status).toBe('complete');
    expect(e.coverage.assets.detail).toContain('1 asset id asked for does not exist');
    expect(e.risk.complete).toBe(true);
  });

  it.each([
    ['a provider error', httpError(500), 'HTTP 500'],
    ['a timeout', new Error('The operation was aborted due to timeout'), 'The operation was aborted due to timeout'],
  ])('never reads %s on a named asset as absence', async (_name, error, reason) => {
    const { e } = await scan({ assets: { '9': error } }, { assetIds: [9n] });
    keep(e);
    expect(e.coverage.assets.named).toMatchObject({ failed: 1, notFound: 0 });
    expect(e.coverage.assets.errors).toEqual([reason]);
    expect(e.risk.complete).toBe(false);
    expect(e.risk.uncertainties).toContain('1 named asset read failed');
  });

  it('treats a malformed asset record as unusable, not as an asset with no roles', async () => {
    const { e } = await scan({ assets: { '9': { index: 9n } } }, { assetIds: [9n] });
    keep(e);
    expect(e.coverage.assets.named.invalid).toBe(1);
    expect(e.coverage.assets.status).toBe('invalid-response');
    expect(e.coverage.assets.errors).toEqual(['malformed asset record']);
  });

  it('counts successful reads, not attempts', async () => {
    const { e } = await scan({
      accounts: { [K]: { amount: 5_000_000n, assets: [1n, 2n] } },
      assets: { '1': { index: 1n, params: PARAMS }, '2': httpError(502) },
    });
    keep(e);
    expect(e.coverage.assets.held).toMatchObject({ requested: 2, attempted: 2, read: 1, failed: 1 });
    // Examined used to count the failed attempt too.
    expect(e.roleScan.assetsExamined).toBe(1);
    expect(e.roleScan.optedInChecked).toBe(1);
    expect(e.roleScan.incomplete).toBe(true);
  });

  it(`reads at most ${OPTED_IN_LIMIT} held assets and says how many were left`, async () => {
    const held = Array.from({ length: OPTED_IN_LIMIT + 3 }, (_, i) => BigInt(i + 1));
    const assets = Object.fromEntries(held.map((id) => [String(id), { index: id, params: PARAMS }]));
    const { e, requests } = await scan({ accounts: { [K]: { amount: 5_000_000n, assets: held } }, assets });
    keep(e);
    expect(requests.filter((r) => r.startsWith('getAssetByID'))).toHaveLength(OPTED_IN_LIMIT);
    expect(e.coverage.assets.held).toMatchObject({ requested: OPTED_IN_LIMIT + 3, attempted: OPTED_IN_LIMIT });
    expect(e.coverage.assets.held.read).toBe(OPTED_IN_LIMIT);
    expect(e.coverage.assets.status).toBe('partial');
    expect(e.risk.uncertainties).toContain(`3 held assets were not read, past the limit of ${OPTED_IN_LIMIT}`);
  });

  it('keeps an application read failure visible, and a 404 as absence', async () => {
    const { e } = await scan({ apps: { '31': httpError(500) } }, { appIds: [31n, 32n] });
    keep(e);
    expect(e.coverage.apps.reads).toMatchObject({ requested: 2, failed: 1, notFound: 1, read: 0 });
    expect(e.coverage.apps.status).toBe('partial');
    expect(e.coverage.apps.detail).toContain('1 application id asked for does not exist');
    expect(e.risk.uncertainties).toContain('1 application read failed');
  });
});

describe('the ledger sample', () => {
  const CREATOR = addressFor('sampled asset creator');
  const asset = (id: number) => ({
    index: BigInt(id),
    params: { creator: CREATOR, total: 1n, decimals: 0 },
  });
  const sampleRequests = (requests: string[]) =>
    requests.filter((r) => r.startsWith('searchForAssets'));

  /** The sampler on its own, with every asset it visits, in order. */
  async function sample(pages: FakeSpec['sample'], limit: number) {
    const provider = fakeProvider({ sample: pages });
    const visited: bigint[] = [];
    const s = await sampleAssets(
      provider.clients,
      limit,
      (id) => visited.push(id),
      () => {},
      'localnet',
    );
    return { s, visited, requests: sampleRequests(provider.requests) };
  }

  it('reads exactly its limit, never asking for more than it still wants', async () => {
    // The provider serves two assets a page whatever it is asked for. This
    // used to read four for a limit of three.
    const { e, requests } = await scan(
      { sample: [{ assets: [asset(1), asset(2)], 'next-token': 'p' }, { assets: [asset(3), asset(4)], 'next-token': 'q' }] },
      { deepScan: true, scanLimit: 3 },
    );
    keep(e);
    expect(e.coverage.assets.sample).toMatchObject({
      status: 'complete',
      read: 3,
      limit: 3,
      requests: 2,
      exhaustive: false,
    });
    expect(e.roleScan.sampled).toBe(3);
    expect(sampleRequests(requests)).toEqual([
      'searchForAssets page 1 limit 3',
      'searchForAssets page 2 limit 1 token p',
    ]);
    expect(e.risk.complete).toBe(true);
  });

  it('visits nothing past its limit, even from a page holding more', async () => {
    const { s, visited } = await sample([{ assets: [asset(1), asset(2), asset(3)] }], 1);
    expect(visited).toEqual([1n]);
    // That page ended the list, but two assets on it went unexamined.
    expect(s).toMatchObject({ status: 'complete', read: 1, limit: 1, exhaustive: false });
  });

  it('counts a repeated asset once, and never visits it twice', async () => {
    const { s, visited } = await sample(
      [{ assets: [asset(1)], 'next-token': 'a' }, { assets: [asset(1)], 'next-token': 'b' }],
      2,
    );
    expect(visited).toEqual([1n]);
    // One distinct asset cannot complete a sample of two.
    expect(s).toMatchObject({ status: 'partial', read: 1, duplicates: 1, exhaustive: false });
  });

  it('stops pages of repeats at its request bound, however fresh the tokens', async () => {
    const limit = 2_500;
    const bound = sampleRequestLimit(limit);
    const { s, visited, requests } = await sample(
      (page) => ({ assets: [asset(1)], 'next-token': `t${page}` }),
      limit,
    );
    expect(requests).toHaveLength(bound);
    expect(visited).toEqual([1n]);
    expect(s).toMatchObject({
      status: 'partial',
      read: 1,
      duplicates: bound - 1,
      requests: bound,
      requestLimit: bound,
    });
    expect(s.detail).toContain(`${bound - 1} repeated records were dropped`);
  });

  it('follows an empty page that still points onward, rather than calling it the end', async () => {
    const { s, visited, requests } = await sample(
      [{ assets: [], 'next-token': 'more' }, { assets: [asset(2)] }],
      10,
    );
    expect(requests[1]).toContain('token more');
    expect(visited).toEqual([2n]);
    expect(s).toMatchObject({ status: 'complete', read: 1, exhaustive: true });
  });

  it('never certifies an empty ledger from empty pages that keep pointing onward', async () => {
    const { e } = await scan(
      { sample: (page) => ({ assets: [], 'next-token': `e${page}` }) },
      { deepScan: true, scanLimit: 10 },
    );
    keep(e);
    expect(e.coverage.assets.sample).toMatchObject({
      status: 'partial',
      read: 0,
      requests: sampleRequestLimit(10),
      exhaustive: false,
    });
    expect(e.risk.complete).toBe(false);
  });

  it('reads a valid empty list as a complete sample of the whole list', async () => {
    const { s, requests } = await sample([], 10);
    expect(s).toMatchObject({ status: 'complete', read: 0, requests: 1, exhaustive: true });
    expect(requests).toEqual(['searchForAssets page 1 limit 10']);
  });

  it('is a census when the list ends exactly at its limit', async () => {
    const { s } = await sample([{ assets: [asset(1), asset(2)] }], 2);
    expect(s).toMatchObject({ status: 'complete', read: 2, exhaustive: true });
  });

  it('says so when it reached the end of the asset list', async () => {
    const { e, requests } = await scan({ sample: [{ assets: [asset(1)], 'next-token': 'p' }, { assets: [] }] }, { deepScan: true, scanLimit: 10 });
    keep(e);
    expect(e.coverage.assets.sample).toMatchObject({ status: 'complete', read: 1, exhaustive: true });
    expect(e.coverage.assets.sample.detail).toContain('reached the end of the asset list');
    expect(sampleRequests(requests)[1]).toBe('searchForAssets page 2 limit 9 token p');
  });

  it('keeps what it read when a later page fails, and is incomplete', async () => {
    const { e } = await scan({ sample: [{ assets: [asset(1)], 'next-token': 'p' }, httpError(500)] }, { deepScan: true, scanLimit: 1500 });
    keep(e);
    expect(e.coverage.assets.sample).toMatchObject({ status: 'partial', read: 1 });
    expect(e.roleScan.sampled).toBe(1);
    expect(e.risk.uncertainties).toContain('the requested ledger sample stopped early, after 1 assets');
  });

  it('stops at a repeated continuation token, keeping what it read', async () => {
    const { s, visited } = await sample(
      [{ assets: [asset(1)], 'next-token': 'p' }, { assets: [asset(2)], 'next-token': 'p' }],
      5_000,
    );
    expect(visited).toEqual([1n, 2n]);
    expect(s).toMatchObject({ status: 'invalid-response', read: 2, exhaustive: false });
    expect(s.errors).toEqual(['the provider repeated a continuation token']);
  });

  it('checks sampled records as a read by id is checked, keeping the usable ones', async () => {
    const { e } = await scan(
      {
        accounts: { [K]: { amount: 0n } },
        sample: [{ assets: [asset(1), { index: 2n, params: {} }, asset(3)] }],
      },
      { deepScan: true, scanLimit: 10 },
    );
    keep(e);
    expect(e.coverage.assets.sample).toMatchObject({
      status: 'invalid-response',
      read: 2,
      exhaustive: false,
    });
    expect(e.coverage.assets.sample.errors).toEqual(['1 malformed asset record(s)']);
    expect(e.risk).toMatchObject({ complete: false, band: 'unverified' });
  });

  it('finds a role in a page of Indexer models', async () => {
    const page = new algosdk.indexerModels.AssetsResponse({
      currentRound: 7n,
      assets: [
        new algosdk.indexerModels.Asset({
          index: 12n,
          params: new algosdk.indexerModels.AssetParams({
            creator: CREATOR,
            total: 5n,
            decimals: 0,
            clawback: K,
          }),
        }),
      ],
    });
    const { e } = await scan({ sample: [page] }, { deepScan: true, scanLimit: 10 });
    keep(e);
    expect(e.coverage.assets.sample).toMatchObject({ status: 'complete', read: 1, exhaustive: true });
    expect(e.reach.seize).toEqual([12n]);
  });

  it('refuses a limit it cannot read, rather than sampling nothing', async () => {
    await expect(scan({}, { deepScan: true, scanLimit: Number.NaN })).rejects.toThrow('scanLimit');
    const provider = fakeProvider({});
    for (const limit of [0, -1, 1.5, Number.NaN]) {
      await expect(
        sampleAssets(provider.clients, limit, () => {}, () => {}, 'localnet'),
      ).rejects.toThrow('positive integer limit');
    }
    expect(provider.requests).toEqual([]);
  });
});

describe('usable records', () => {
  // Every answer here is well-formed JSON, and none says anything about the
  // id that was asked for. Each has to keep the verdict from being clean.
  const CREATOR = addressFor('record creator');
  const PARAMS = { creator: CREATOR, total: 10n, decimals: 0 };
  /** An otherwise clean account: nothing held, nothing to score. */
  const EMPTY = { [K]: { amount: 0n } };
  const pk = algosdk.decodeAddress(K).publicKey;
  const b64 = (v: string | Uint8Array) => Buffer.from(v).toString('base64');
  const bytesEntry = (key: string, bytes: Uint8Array) => ({
    key: b64(key),
    value: { type: 1, bytes: b64(bytes), uint: 0 },
  });
  const uintEntry = (key: string, uint: number) => ({
    key: b64(key),
    value: { type: 2, bytes: '', uint },
  });

  const UNUSABLE_ASSETS: Array<[string, unknown, string]> = [
    ['empty parameters', { index: 9n, params: {} }, 'malformed asset parameters'],
    ['a record for another asset', { index: 10n, params: PARAMS }, 'asset record for a different id'],
    ['no id', { params: PARAMS }, 'malformed asset record'],
    ['parameters that are not an object', { index: 9n, params: 'none' }, 'malformed asset record'],
    ['a creator that is not an address', { index: 9n, params: { ...PARAMS, creator: 'someone' } }, 'malformed asset parameters'],
    ['a role that is not an address', { index: 9n, params: { ...PARAMS, clawback: 'nobody' } }, 'malformed asset parameters'],
    ['a role that is not text', { index: 9n, params: { ...PARAMS, freeze: 7 } }, 'malformed asset parameters'],
    ['a negative total', { index: 9n, params: { ...PARAMS, total: -1 } }, 'malformed asset parameters'],
    ['decimals out of range', { index: 9n, params: { ...PARAMS, decimals: 20 } }, 'malformed asset parameters'],
    ['a name that is not text', { index: 9n, params: { ...PARAMS, name: 5 } }, 'malformed asset parameters'],
  ];

  it.each(UNUSABLE_ASSETS)('keeps a named asset read as %s unverified', async (_name, record, fault) => {
    const { e } = await scan({ accounts: EMPTY, assets: { '9': record } }, { assetIds: [9n] });
    keep(e);
    expect(e.coverage.assets.named).toMatchObject({ attempted: 1, read: 0, invalid: 1 });
    expect(e.coverage.assets.status).toBe('invalid-response');
    expect(e.coverage.assets.errors).toEqual([fault]);
    expect(e.foreignRoles).toEqual([]);
    expect(e.risk).toMatchObject({ complete: false, band: 'unverified' });
    expect(e.risk.uncertainties).toContain('1 named asset record was unusable');
    expect(riskVerdict(e.risk).safe).toBe(false);
  });

  it('holds a held asset to the same standard', async () => {
    const { e } = await scan({
      accounts: { [K]: { amount: 0n, assets: [9n] } },
      assets: { '9': { index: 10n, params: { ...PARAMS, clawback: K } } },
    });
    keep(e);
    expect(e.coverage.assets.held).toMatchObject({ read: 0, invalid: 1 });
    expect(e.reach.seize).toEqual([]);
    expect(e.risk.complete).toBe(false);
  });

  it.each([
    [
      'an algod model',
      () =>
        new algosdk.modelsv2.Asset({
          index: 9n,
          params: new algosdk.modelsv2.AssetParams({
            creator: CREATOR,
            total: 10n,
            decimals: 2,
            unitName: 'SDK',
            manager: K,
          }),
        }),
      'SDK',
    ],
    [
      'a REST record',
      () => ({
        index: 9,
        params: {
          creator: CREATOR,
          total: 10,
          decimals: 2,
          'unit-name': 'REST',
          'default-frozen': false,
          manager: K,
        },
      }),
      'REST',
    ],
  ])('reads %s for the id asked for', async (_name, record, unitName) => {
    const { e } = await scan({ accounts: EMPTY, assets: { '9': record() } }, { assetIds: [9n] });
    keep(e);
    expect(e.coverage.assets).toMatchObject({ status: 'complete', named: { read: 1, invalid: 0 } });
    expect(e.foreignRoles).toMatchObject([{ assetId: 9n, unitName, roles: ['manager'] }]);
  });

  it('reads an asset that grants no roles as complete, not as unusable', async () => {
    const { e } = await scan({ accounts: EMPTY, assets: { '9': { index: 9n, params: PARAMS } } }, { assetIds: [9n] });
    keep(e);
    expect(e.coverage.assets).toMatchObject({ status: 'complete', named: { read: 1 } });
    expect(e.foreignRoles).toEqual([]);
    expect(e.risk).toMatchObject({ complete: true, band: 'safe' });
  });

  const UNUSABLE_APPS: Array<[string, unknown, string]> = [
    ['a state entry that is null', { id: 77n, params: { creator: CREATOR, globalState: [null] } }, 'malformed global state'],
    ['a record for another application', { id: 78n, params: { creator: CREATOR, globalState: [] } }, 'application record for a different id'],
    ['no id', { params: { creator: CREATOR } }, 'malformed application record'],
    ['no parameters', { id: 77n }, 'malformed application record'],
    ['parameters without a creator', { id: 77n, params: { globalState: [] } }, 'malformed application record'],
    ['state that is not a list', { id: 77n, params: { creator: CREATOR, globalState: {} } }, 'malformed global state'],
    [
      'an entry naming this address but with no type',
      { id: 77n, params: { creator: CREATOR, globalState: [{ key: b64('admin'), value: { bytes: b64(pk) } }] } },
      'malformed global state',
    ],
    [
      'an entry of an unknown type',
      { id: 77n, params: { creator: CREATOR, globalState: [{ key: b64('admin'), value: { type: 3, bytes: b64(pk), uint: 0 } }] } },
      'malformed global state',
    ],
    [
      'a byte value that is not base64',
      { id: 77n, params: { creator: CREATOR, globalState: [{ key: b64('admin'), value: { type: 1, bytes: 'not base64!', uint: 0 } }] } },
      'malformed global state',
    ],
    [
      'a key that is not bytes',
      { id: 77n, params: { creator: CREATOR, globalState: [{ key: 5, value: { type: 1, bytes: b64(pk), uint: 0 } }] } },
      'malformed global state',
    ],
    [
      'a negative uint',
      { id: 77n, params: { creator: CREATOR, globalState: [uintEntry('count', -1)] } },
      'malformed global state',
    ],
  ];

  it.each(UNUSABLE_APPS)('keeps a named application read as %s unverified', async (_name, record, fault) => {
    const { e } = await scan({ accounts: EMPTY, apps: { '77': record } }, { appIds: [77n] });
    keep(e);
    expect(e.coverage.apps.reads).toMatchObject({ attempted: 1, read: 0, invalid: 1 });
    expect(e.coverage.apps.status).toBe('invalid-response');
    expect(e.coverage.apps.errors).toEqual([fault]);
    expect(e.appAdminRoles).toEqual([]);
    expect(e.risk).toMatchObject({ complete: false, band: 'unverified' });
    expect(e.risk.uncertainties).toContain('1 application record was unusable');
  });

  it.each([
    [
      'an algod model',
      () =>
        new algosdk.modelsv2.Application({
          id: 77n,
          params: new algosdk.modelsv2.ApplicationParams({
            approvalProgram: new Uint8Array([6, 129, 1]),
            clearStateProgram: new Uint8Array([6, 129, 1]),
            creator: CREATOR,
            globalState: [
              new algosdk.modelsv2.TealKeyValue({
                key: new TextEncoder().encode('count'),
                value: new algosdk.modelsv2.TealValue({ type: 2, uint: 5n, bytes: new Uint8Array() }),
              }),
              new algosdk.modelsv2.TealKeyValue({
                key: new TextEncoder().encode('admin'),
                value: new algosdk.modelsv2.TealValue({ type: 1, bytes: pk, uint: 0n }),
              }),
            ],
          }),
        }),
    ],
    [
      'a REST record',
      () => ({
        id: 77,
        params: {
          creator: CREATOR,
          'approval-program': 'BoEB',
          'clear-state-program': 'BoEB',
          'global-state': [uintEntry('count', 5), bytesEntry('admin', pk)],
        },
      }),
    ],
  ])('finds this address in %s, and reads the other entries as naming nobody', async (_name, record) => {
    const { e } = await scan({ accounts: EMPTY, apps: { '77': record() } }, { appIds: [77n] });
    keep(e);
    expect(e.coverage.apps).toMatchObject({ status: 'complete', reads: { read: 1, invalid: 0 } });
    expect(e.appAdminRoles).toEqual([
      { appId: 77n, key: 'admin', createdByThisAccount: false, permission: 'unverified' },
    ]);
  });

  it('reads an application with no global state as naming nobody, not as unusable', async () => {
    const { e } = await scan(
      { accounts: EMPTY, apps: { '77': { id: 77n, params: { creator: CREATOR } } } },
      { appIds: [77n] },
    );
    keep(e);
    expect(e.coverage.apps).toMatchObject({ status: 'complete', reads: { read: 1 } });
    expect(e.appAdminRoles).toEqual([]);
    expect(e.risk).toMatchObject({ complete: true, band: 'safe' });
  });
});

describe('application references', () => {
  const APP = 77n;
  // State that names nobody: the creator is granted nothing by this app.
  const noPrivilege = { id: APP, params: { creator: K, globalState: [] } };

  it('treats a created app as a reference: no points, no reach, no promised fix', async () => {
    const plain = keep((await scan({})).e);
    const { e } = await scan({
      accounts: { [K]: { amount: 5_000_000n, createdApps: [APP] } },
      apps: { [String(APP)]: noPrivilege },
    });
    keep(e);
    const f = e.findings.find((x) => x.kind === 'app-creator');
    expect(f).toMatchObject({ severity: 'medium', thirdParty: false, fixedByRekey: false });
    expect(f!.title).toContain('permissions unverified');
    expect(f!.detail).not.toMatch(/can (delete|update)/);
    // Nothing is added to the score for it...
    expect(e.risk.score).toBe(plain.risk.score);
    // ...but the verdict is not complete, so the score is a lower bound.
    expect(e.risk.complete).toBe(false);
    expect(e.risk.uncertainties).toContain('1 application reference with unverified permissions');
    expect(riskVerdict(e.risk).score).toBe(`${plain.risk.score}+`);
    expect(e.coverage.appPermissions).toBe('unverified');
    expect(e.edges.find((x) => x.relation === 'app-creator')).toMatchObject({ basis: 'reference' });
    expect(e.reach.appReferences).toBe(1);
    expect(e.risk.systemic).toBe(false);
  });

  it('never lets a reference alone read as a clean verdict', async () => {
    const provider = fakeProvider({
      accounts: { [K]: { amount: 0n, createdApps: [APP] } },
      apps: { [String(APP)]: noPrivilege },
    });
    const e = keep(await analyzeAccount(provider.clients, K));
    expect(e.risk.score).toBe(0);
    expect(e.risk.band).toBe('unverified');
    expect(riskVerdict(e.risk).safe).toBe(false);
  });

  it('treats an address named in app state the same way', async () => {
    const pk = algosdk.decodeAddress(K).publicKey;
    const state = [
      {
        key: Buffer.from('admin').toString('base64'),
        value: { type: 1, bytes: Buffer.from(pk).toString('base64'), uint: 0 },
      },
    ];
    const { e } = await scan(
      { apps: { '88': { id: 88n, params: { creator: addressFor('deployer'), globalState: state } } } },
      { appIds: [88n] },
    );
    keep(e);
    expect(e.appAdminRoles).toEqual([
      { appId: 88n, key: 'admin', createdByThisAccount: false, permission: 'unverified' },
    ]);
    const f = e.findings.find((x) => x.kind === 'app-admin');
    expect(f).toMatchObject({ severity: 'medium', thirdParty: false, fixedByRekey: false });
    expect(f!.title).toContain('permissions unverified');
    expect(e.edges.find((x) => x.relation === 'app-admin')).toMatchObject({ basis: 'reference' });
  });

  it('plans without promising anything about references', async () => {
    const { e } = await scan({
      accounts: { [K]: { amount: 5_000_000n, createdApps: [APP] } },
      apps: { [String(APP)]: noPrivilege },
    });
    const plan = planMigration(e, falconAuthority(40).address);
    const text = plan.warnings.join(' ');
    expect(text).toContain('does not analyse application programs');
    expect(text).not.toMatch(/app\w* (role|privilege)s? carr/i);
  });

  it('reports no unverified permissions when there are no references', async () => {
    const { e } = await scan({});
    keep(e);
    expect(e.coverage.appPermissions).toBe('no-references');
    expect(coverageLines(e).some((l) => l.check === 'app-permissions')).toBe(false);
  });
});

describe('reach', () => {
  it('describes a post-quantum address signing only for protected accounts as exactly that', async () => {
    const C = falconAuthority(51);
    const B = addressFor('protected incoming');
    const provider = fakeProvider({
      accounts: {
        [C.address]: { amount: 1_000_000n },
        [B]: { amount: 4_000_000n, authAddr: C.address },
      },
      history: { [C.address]: [falconRecord('C-SELF', C.address, C)] },
    });
    const c = keep(await analyzeAccount(provider.clients, C.address));
    expect(c.isPostQuantum).toBe(true);
    expect(c.reach).toMatchObject({ seize: [], freeze: [], incomingProtected: 1, incomingExposed: 0 });
    const notice = describeReach(c)!;
    expect(notice.exposed).toBe(false);
    expect(notice.text).toContain('signs for 1 account rekeyed to it with a post-quantum key');
    expect(notice.text).not.toMatch(/freeze|seize|Breaking/);
    // Still a complete, clean verdict: reach through a protected key is not exposure.
    expect(c.risk.band).toBe('safe');
    expect(c.risk.systemic).toBe(true);
    const info = c.findings.find((f) => f.kind === 'controls-account');
    expect(info).toMatchObject({ severity: 'info', thirdParty: false });
    expect(info!.title).not.toContain('verified');
    expect(c.edges.find((e) => e.relation === 'controls-account')).toMatchObject({ protected: true });
  });

  it('names the asset power and the exposed authority behind it', async () => {
    const { e } = await scan({
      accounts: {
        [K]: {
          amount: 5_000_000n,
          createdAssets: [{ index: 5n, params: { creator: K, manager: K, clawback: K, unitName: 'CLW', total: 10n, decimals: 0 } }],
        },
      },
    });
    keep(e);
    expect(e.reach.seize).toEqual([5n]);
    const notice = describeReach(e)!;
    expect(notice.exposed).toBe(true);
    expect(notice.text).toContain('can seize 1 asset from any holder');
    expect(notice.text).toContain('not established as post-quantum');
  });

  it('never gives a classical key signing for protected accounts asset powers it lacks', async () => {
    // X is a Falcon address whose own account was rekeyed to a classical key;
    // Y is rekeyed to X and has moved under X's Falcon key, so Y is protected
    // while X itself is classical. X holds no asset role at all.
    const X = falconAuthority(61);
    const classical = onCurveAddress('classical authority of X');
    const Y = addressFor('protected under X');
    const provider = fakeProvider({
      accounts: {
        [X.address]: { amount: 2_000_000n, authAddr: classical },
        [Y]: { amount: 9_000_000n, authAddr: X.address },
      },
      history: { [Y]: [falconRecord('Y-UNDER-X', Y, X)] },
    });
    const x = keep(await analyzeAccount(provider.clients, X.address));
    expect(x.authority.authorityClass).toBe('classical-key');
    expect(x.incoming[0]!.authority.quantumSafe).toBe(true);
    expect(x.risk.summary).not.toMatch(/assets other people hold|freeze|seize/);
    // Only X's own 2 ALGO is exposed; Y's balance is protected.
    expect(x.risk.summary).toContain('2 ALGO');
    const notice = describeReach(x)!;
    expect(notice.exposed).toBe(false);
    expect(notice.text).not.toMatch(/freeze|seize/);
  });
});

describe('the account record (CORE-04)', () => {
  const B = onCurveAddress('account record authority');
  const ACCOUNT = { address: K, amount: 5_000_000n, minBalance: 100_000n };
  /** The scan of K, with its account read answered by `answer`. */
  const answering = (answer: () => unknown) => {
    const p = fakeProvider({});
    Object.assign(p.clients.algod, { accountInformation: () => ({ do: async () => answer() }) });
    return analyzeAccount(p.clients, K);
  };
  /** An account record as algod sends it, decoded by algosdk as its client does. */
  const decoded = (json: object) => answering(() => algosdk.decodeJSON(JSON.stringify(json), algosdk.modelsv2.Account));

  // The first two are REPO-01's reproduction: both were read as an empty account.
  it.each([
    ['a message naming 404', new Error('Network request error. Received status 404 (Not Found): route not found')],
    ['a message saying no accounts found', new Error('no accounts found for address')],
    ['a 404 message on a 500 response', Object.assign(new Error('upstream said 404'), { response: { status: 500 } })],
    ['an HTTP 404', httpError(404)],
    ['an HTTP 429', httpError(429)],
    ['an HTTP 500', httpError(500)],
  ])('throws a failed read with %s rather than reading an empty account', async (_name, err) => {
    await expect(answering(() => { throw err; })).rejects.toBe(err);
  });

  const MALFORMED: Array<[string, unknown, string]> = [
    ["REPO-01's fields", { amount: 'not-a-number', minBalance: 1.5, authAddr: '' }, 'malformed account balance'],
    ['no record', null, 'malformed account record'],
    ['a record for another account', { ...ACCOUNT, address: B }, 'account record for a different address'],
    ['no balance', { address: K, minBalance: 100_000n }, 'malformed account balance'],
    ['a negative balance', { ...ACCOUNT, amount: -1n }, 'malformed account balance'],
    ['a fractional balance', { ...ACCOUNT, amount: 1.5 }, 'malformed account balance'],
    ['an inexact balance', { ...ACCOUNT, amount: 2 ** 53 }, 'malformed account balance'],
    ['a fractional minimum balance', { ...ACCOUNT, minBalance: 1.5 }, 'malformed account minimum balance'],
    ['an empty authority', { ...ACCOUNT, authAddr: '' }, 'malformed account authority'],
    ['an authority that is not an address', { ...ACCOUNT, authAddr: 'nobody' }, 'malformed account authority'],
    ['holdings that are not a list', { ...ACCOUNT, assets: {} }, 'malformed account asset holdings'],
    ['a holding without an id', { ...ACCOUNT, assets: [{ amount: 1n }] }, 'malformed account asset holdings'],
    ['holdings withheld behind their total', { ...ACCOUNT, totalAssetsOptedIn: 2 }, 'malformed account asset holdings'],
    ['holdings short of their total', { ...ACCOUNT, totalAssetsOptedIn: 2, assets: [{ assetId: 9n }] }, 'malformed account asset holdings'],
    ['a total that is not a count', { ...ACCOUNT, totalAssetsOptedIn: -1, assets: [] }, 'malformed account asset holdings'],
    ['a created asset without a creator', { ...ACCOUNT, createdAssets: [{ index: 5n, params: { clawback: K, total: 1n, decimals: 0 } }] }, 'malformed account created assets'],
    ['a created application with a negative id', { ...ACCOUNT, createdApps: [{ id: -1 }] }, 'malformed account created applications'],
    ['created applications withheld behind their total', { ...ACCOUNT, totalCreatedApps: 1 }, 'malformed account created applications'],
    ['an opt-in without an id', { ...ACCOUNT, appsLocalState: [{}] }, 'malformed account application opt-ins'],
  ];

  it.each(MALFORMED)('refuses %s instead of judging it', async (_name, record, fault) => {
    await expect(answering(() => record)).rejects.toThrow(`unusable account record (${fault}). Nothing was judged.`);
  });

  it('refuses what algosdk decodes but the ledger could not have said', async () => {
    const base = { address: K, amount: 5_000_000, 'min-balance': 100_000 };
    await expect(decoded({ ...base, address: B })).rejects.toThrow('account record for a different address');
    await expect(decoded({ ...base, 'total-created-assets': 1 })).rejects.toThrow('malformed account created assets');
  });

  it('reads an empty account as algod sends one, with its omitted fields', async () => {
    const e = keep(await decoded({ address: K, 'min-balance': 100_000, round: 5 }));
    expect(e).toMatchObject({ microAlgos: 0n, minBalance: 100_000n, assetsHeld: 0, appsOptedIn: 0 });
    expect(e.authAddr).toBeUndefined();
    expect(e.risk.complete).toBe(true);
  });

  it('reads a funded, rekeyed account with holdings, roles and opt-ins exactly', async () => {
    const e = keep(await decoded({
      address: K,
      amount: 5_000_000,
      'min-balance': 300_000,
      'auth-addr': B,
      'total-assets-opted-in': 1,
      'total-created-assets': 1,
      'total-apps-opted-in': 1,
      assets: [{ 'asset-id': 9, amount: 1, 'is-frozen': false }],
      'created-assets': [{ index: 5, params: { creator: K, total: 10, decimals: 0, manager: K, clawback: K, 'unit-name': 'CLW' } }],
      'apps-local-state': [{ id: 8, schema: { 'num-uint': 0, 'num-byte-slice': 0 } }],
    }));
    expect(e).toMatchObject({ microAlgos: 5_000_000n, minBalance: 300_000n, authAddr: B, assetsHeld: 1, appsOptedIn: 1 });
    expect(e.createdAssets.map((a) => [a.assetId, a.roles])).toEqual([[5n, ['manager', 'clawback']]]);
    expect(e.reach.seize).toEqual([5n]);
    // The held asset and the opted-in app are still read by id: 404 there is an established absence.
    expect(e.coverage.assets.held).toMatchObject({ requested: 1, notFound: 1 });
    expect(e.coverage.apps.status).toBe('complete');
  });
});

describe('one verdict, one coverage model', () => {
  it('is complete exactly when no coverage line falls short', () => {
    expect(seen.length).toBeGreaterThan(20);
    for (const e of seen) {
      const blocking = coverageLines(e).filter((l) => l.blocking);
      expect(e.risk.complete, e.address).toBe(blocking.length === 0);
      if (riskVerdict(e.risk).safe) expect(blocking).toEqual([]);
    }
  });

  it('keeps a direct caller of assessRisk honest about references', () => {
    const r = assessRisk({
      alreadyPq: false,
      microAlgos: 0n,
      controlledValue: 0n,
      assetsHeld: 0,
      appCount: 2,
      seizable: 0,
      freezable: 0,
      controlsCount: 0,
    });
    expect(r.score).toBe(0);
    expect(r.band).toBe('unverified');
    expect(r.uncertainties).toEqual(['2 application references with unverified permissions']);
  });
});
