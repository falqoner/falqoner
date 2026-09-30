import { describe, it, expect, afterEach } from 'vitest';
import { NETWORKS } from '../src/networks.js';
import {
  LOCALNET,
  MIN_ALGOD_MAJOR,
  MAX_INDEXER_LAG_ROUNDS,
  MAX_INDEXER_LEAD_ROUNDS,
  SUPPORTED_GENESIS_IDS,
  SUPPORTED_PROTOCOLS,
  hasFalconSupport,
  isSupportedNetwork,
  isSupportedProtocol,
  preflightLocalnet,
} from '../../../scripts/localnet-preflight.mjs';

/**
 * The readiness probe is dependency-free so it can run before anything is
 * built, which means it carries its own copy of the LocalNet endpoints. This
 * is the guard against the two copies drifting: a probe that checks a
 * different algod than the suite talks to would clear a run that then fails,
 * or block one that would have worked.
 *
 * Offline by design - it compares constants and contacts nothing.
 */
describe('LocalNet preflight endpoints', () => {
  it('probes the same services the core library uses', () => {
    expect(LOCALNET.algodUrl).toBe(NETWORKS.localnet.algodUrl);
    expect(LOCALNET.algodToken).toBe(NETWORKS.localnet.algodToken);
    expect(LOCALNET.indexerUrl).toBe(NETWORKS.localnet.indexerUrl);
    expect(LOCALNET.indexerToken).toBe(NETWORKS.localnet.indexerToken);
  });

  it('keeps the LocalNet probe off every public network', () => {
    const urls = [LOCALNET.algodUrl, LOCALNET.indexerUrl, LOCALNET.kmdUrl];
    for (const url of urls) {
      expect(new URL(url).hostname).toBe('localhost');
    }
  });

  /**
   * The capability gate cannot be checked by running against an old node - a
   * test run cannot downgrade algod - so the decision itself is tested here.
   */
  it('requires an algod new enough for native Falcon-1024 accounts', () => {
    expect(MIN_ALGOD_MAJOR).toBe(5);
    expect(hasFalconSupport(MIN_ALGOD_MAJOR)).toBe(true);
    expect(hasFalconSupport(MIN_ALGOD_MAJOR + 1)).toBe(true);
    expect(hasFalconSupport(MIN_ALGOD_MAJOR - 1)).toBe(false);
  });

  it('treats an unreadable algod version as unsupported, not as supported', () => {
    // -1 is what the probe records when /versions could not be parsed.
    expect(hasFalconSupport(-1)).toBe(false);
    expect(hasFalconSupport(Number.NaN)).toBe(false);
    expect(hasFalconSupport(5.5)).toBe(false);
  });

  it('accepts only the networks and protocols it has been verified against', () => {
    expect(SUPPORTED_GENESIS_IDS).toContain('dockernet-v1');
    expect(isSupportedNetwork('dockernet-v1')).toBe(true);
    expect(isSupportedNetwork('mainnet-v1.0')).toBe(false);
    expect(isSupportedNetwork('testnet-v1.0')).toBe(false);
    expect(isSupportedNetwork('somenet-v9')).toBe(false);
    expect(isSupportedNetwork(undefined)).toBe(false);

    expect(SUPPORTED_PROTOCOLS).toContain('future');
    expect(isSupportedProtocol('future')).toBe(true);
    expect(isSupportedProtocol('v7')).toBe(false);
    expect(isSupportedProtocol(undefined)).toBe(false);
  });
});

/**
 * Regressions for the readiness false positives found in review (A-02a-01,
 * A-02a-02, A-02a-03): a service answering HTTP 200 was treated as ready
 * regardless of what it actually said.
 *
 * These drive the real `preflightLocalnet()` with controlled responses rather
 * than testing the decision helpers in isolation, because the defect was in
 * how the probe assembled its verdict, not in the helpers. `fetch` is replaced
 * per test and restored afterwards; nothing contacts a service.
 */
describe('LocalNet preflight verdict', () => {
  interface Responses {
    status?: unknown;
    version?: unknown;
    health?: unknown;
    kmdVersions?: unknown;
    wallets?: unknown;
  }

  const healthy: Required<Responses> = {
    status: { 'last-round': 100, 'last-version': 'future' },
    version: {
      build: { major: 5, minor: 0, build_number: 2 },
      genesis_id: 'dockernet-v1',
      genesis_hash_b64: 'hrTYMij0o2G+5qjc+dj3IuPJ/rX28z/v7K+smcRbICk=',
    },
    health: { round: 100, version: '3.10.0', 'db-available': true },
    kmdVersions: { versions: ['v1'] },
    wallets: { wallets: [{ name: 'unencrypted-default-wallet' }] },
  };

  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  /** Every request the stub saw, so GET-only can be asserted afterwards. */
  let seen: { method: string; url: URL }[] = [];

  function stub(overrides: Responses = {}): void {
    const r = { ...healthy, ...overrides };
    seen = [];
    globalThis.fetch = (async (input: unknown, init?: { method?: string }) => {
      const url = new URL(String(input));
      seen.push({ method: init?.method ?? 'GET', url });
      if (url.hostname !== 'localhost') {
        throw new Error(`probe reached a non-local host: ${url.hostname}`);
      }
      const route = `${url.port}${url.pathname}`;
      const body =
        route === '4001/v2/status'
          ? r.status
          : route === '4001/versions'
            ? r.version
            : route === '8980/health'
              ? r.health
              : route === '4002/versions'
                ? r.kmdVersions
                : route === '4002/v1/wallets'
                  ? r.wallets
                  : undefined;
      if (body === undefined) throw new Error(`unexpected route: ${route}`);
      return new Response(JSON.stringify(body), { status: 200 });
    }) as typeof globalThis.fetch;
  }

  /** The named check, so a regression cannot pass by the check disappearing. */
  function check(
    report: Awaited<ReturnType<typeof preflightLocalnet>>,
    service: string,
  ) {
    const found = report.checks.find((c) => c.service === service);
    expect(found, `report has no ${service} check`).toBeDefined();
    return found!;
  }

  it('reports ready for a healthy local node', async () => {
    stub();
    const report = await preflightLocalnet();
    expect(report.ok).toBe(true);
    for (const c of report.checks) {
      expect(c.ok, `${c.service}: ${c.detail}`).toBe(true);
    }
    expect(report.checks.map((c) => c.service)).toEqual([
      'algod',
      'network',
      'falcon-1024',
      'indexer',
      'kmd',
    ]);
  });

  it('issues nothing but GET requests', async () => {
    stub();
    await preflightLocalnet();
    expect(seen.length).toBeGreaterThan(0);
    for (const request of seen) {
      expect(request.method).toBe('GET');
      expect(request.url.hostname).toBe('localhost');
    }
  });

  // A-02a-01: HTTP 200 with empty objects used to report ready, and a missing
  // build major skipped the capability check entirely.
  it('fails closed when algod answers without readiness metadata', async () => {
    stub({ status: {}, version: {} });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'algod').ok).toBe(false);
    // The capability verdict must still be present and negative, not skipped.
    expect(check(report, 'falcon-1024').ok).toBe(false);
    expect(check(report, 'falcon-1024').detail).toContain('unverified');
    expect(check(report, 'network').ok).toBe(false);
  });

  it('rejects a malformed algod round rather than reading it as zero', async () => {
    stub({ status: { 'last-round': -1, 'last-version': 'future' } });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'algod').ok).toBe(false);
    expect(check(report, 'algod').detail).toContain('last-round');
  });

  it('rejects a partial build version', async () => {
    stub({
      version: { build: { major: 5 }, genesis_id: 'dockernet-v1' },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'algod').ok).toBe(false);
  });

  // A-02a-02: loopback does not establish the network, and a build major alone
  // does not establish the capability.
  it('refuses a public network served on the LocalNet port', async () => {
    stub({
      version: { ...(healthy.version as object), genesis_id: 'mainnet-v1.0' },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    const network = check(report, 'network');
    expect(network.ok).toBe(false);
    expect(network.detail).toContain('public network');
    expect(network.detail).toContain('mainnet-v1.0');
  });

  it('refuses an unrecognised network instead of assuming it is local', async () => {
    stub({
      version: { ...(healthy.version as object), genesis_id: 'somenet-v9' },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'network').ok).toBe(false);
  });

  it('refuses an unverified active protocol on a new enough build', async () => {
    stub({ status: { 'last-round': 100, 'last-version': 'v7' } });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    const capability = check(report, 'falcon-1024');
    expect(capability.ok).toBe(false);
    expect(capability.detail).toContain('v7');
    // The build really is new enough; the protocol is what fails.
    expect(check(report, 'algod').ok).toBe(true);
  });

  it('refuses a pending upgrade to an unverified protocol', async () => {
    stub({
      status: {
        'last-round': 100,
        'last-version': 'future',
        'next-version': 'v-something-new',
      },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'falcon-1024').detail).toContain('pending upgrade');
  });

  it('accepts a next-version equal to the active protocol', async () => {
    stub({
      status: {
        'last-round': 100,
        'last-version': 'future',
        'next-version': 'future',
      },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(true);
  });

  it('refuses a build that predates native Falcon-1024 accounts', async () => {
    stub({
      version: {
        ...(healthy.version as object),
        build: { major: 4, minor: 1, build_number: 1 },
      },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'falcon-1024').detail).toContain('predates');
  });

  // A-02a-03: an unhealthy indexer reported ready, and lag never affected it.
  it('rejects an indexer whose database is unavailable', async () => {
    stub({ health: { round: -1, version: '3.10.0', 'db-available': false } });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    const indexer = check(report, 'indexer');
    expect(indexer.ok).toBe(false);
    expect(indexer.detail).toContain('db-available');
    expect(indexer.detail).toContain('not a valid round');
  });

  it('rejects an indexer that is still migrating', async () => {
    stub({
      health: { ...(healthy.health as object), 'is-migrating': true },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'indexer').detail).toContain('is-migrating');
  });

  it('rejects an indexer reporting errors', async () => {
    stub({
      health: { ...(healthy.health as object), errors: ['conduit stalled'] },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'indexer').detail).toContain('conduit stalled');
  });

  it('tolerates lag inside the bound, because trailing is normal', async () => {
    stub({
      health: {
        ...(healthy.health as object),
        round: 100 - MAX_INDEXER_LAG_ROUNDS,
      },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(true);
    expect(check(report, 'indexer').detail).toContain(
      `lag ${MAX_INDEXER_LAG_ROUNDS}`,
    );
  });

  it('rejects lag beyond the bound with a retryable diagnostic', async () => {
    stub({
      health: {
        ...(healthy.health as object),
        round: 100 - (MAX_INDEXER_LAG_ROUNDS + 1),
      },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    const indexer = check(report, 'indexer');
    expect(indexer.detail).toContain(`${MAX_INDEXER_LAG_ROUNDS}-round bound`);
    expect(indexer.hint).toContain('re-run');
  });

  it('tolerates the indexer being a round ahead, which the read order allows', async () => {
    stub({
      health: {
        ...(healthy.health as object),
        round: 100 + MAX_INDEXER_LEAD_ROUNDS,
      },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(true);
  });

  it('rejects an indexer far ahead of algod, which means a different chain', async () => {
    stub({
      health: {
        ...(healthy.health as object),
        round: 100 + MAX_INDEXER_LEAD_ROUNDS + 1,
      },
    });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'indexer').detail).toContain('ahead of algod');
  });

  it('rejects a KMD without the wallet the suite funds from', async () => {
    stub({ wallets: { wallets: [{ name: 'some-other-wallet' }] } });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'kmd').detail).toContain('some-other-wallet');
  });

  it('fails closed when KMD answers without its API versions', async () => {
    stub({ kmdVersions: {} });
    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    expect(check(report, 'kmd').ok).toBe(false);
  });

  it('fails closed when a service is unreachable', async () => {
    stub();
    const reachable = globalThis.fetch;
    globalThis.fetch = (async (input: unknown, init?: { method?: string }) => {
      const url = new URL(String(input));
      if (url.port === '4002') {
        throw Object.assign(new Error('fetch failed'), {
          cause: { code: 'ECONNREFUSED' },
        });
      }
      return reachable(input as string, init as RequestInit);
    }) as typeof globalThis.fetch;

    const report = await preflightLocalnet();
    expect(report.ok).toBe(false);
    const kmd = check(report, 'kmd');
    expect(kmd.detail).toContain('ECONNREFUSED');
    expect(check(report, 'algod').ok).toBe(true);
  });
});
