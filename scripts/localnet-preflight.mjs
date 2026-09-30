#!/usr/bin/env node
/**
 * Bounded, read-only readiness probe for a local AlgoKit LocalNet.
 *
 * This is the single source of truth for "is the integration suite allowed to
 * run", used both by `npm run localnet:status` and by the LocalNet vitest
 * global setup. It only ever reads: it never starts, stops, resets or deletes
 * LocalNet state, and it never falls back to a public network. Starting the
 * node stays an explicit human action (`npm run localnet:start`).
 *
 * Plain fetch against the three service endpoints keeps it dependency-free, so
 * it runs before anything is built and stays cheap enough to gate every
 * LocalNet run.
 *
 * Every check fails closed. A service that answers is not a service that is
 * ready: readiness metadata that is absent, malformed or unrecognised is a
 * failure, never a pass, because the alternative is a green run against a node
 * that cannot do what the suite assumes. Reachability, a loopback address and a
 * build number are each insufficient on their own.
 */
import process from 'node:process';
import { pathToFileURL } from 'node:url';

/**
 * LocalNet service endpoints. algod and indexer mirror `NETWORKS.localnet` in
 * `packages/core/src/networks.ts`; KMD has no entry there because the core
 * library never talks to it. `test/preflight.test.ts` fails offline if
 * the two copies drift apart.
 */
export const LOCALNET = {
  algodUrl: 'http://localhost:4001',
  algodToken: 'a'.repeat(64),
  indexerUrl: 'http://localhost:8980',
  indexerToken: '',
  kmdUrl: 'http://localhost:4002',
  kmdToken: 'a'.repeat(64),
};

/**
 * Genesis ids this harness has actually been run against.
 *
 * A loopback URL says nothing about the chain behind it: an SSH tunnel or a
 * local proxy can serve MainNet on `localhost:4001`. The network is therefore
 * identified by what algod reports, against a list that is deliberately narrow
 * — this is a tested-policy allowlist, not universal network detection. An
 * AlgoKit LocalNet that legitimately reports a different genesis is rejected
 * until someone verifies it and adds it here.
 *
 * `dockernet-v1`: AlgoKit 2.10.2 LocalNet, algod 5.0.2. Verified by the 20
 * integration tests passing against it.
 */
export const SUPPORTED_GENESIS_IDS = ['dockernet-v1'];

/** Recognised only to say "this is a public network" instead of "unknown". */
export const PUBLIC_GENESIS_IDS = ['mainnet-v1.0', 'testnet-v1.0', 'betanet-v1.0'];

/**
 * Active consensus protocols verified to provide native Falcon-1024 accounts.
 *
 * A build major of 5 means the binary contains the feature; it does not mean
 * the chain it is running has it switched on, which is a property of the active
 * protocol. Both are therefore required.
 *
 * - `future`: the protocol name algod reports for unreleased consensus in
 *   LocalNet dev mode.
 * - the pinned spec revision: what algod 5.0.2's LocalNet image reports as its
 *   active and next protocol, verified by the 20 integration tests passing
 *   against it.
 *
 * An unlisted protocol is rejected rather than assumed capable. That is
 * deliberately brittle: a LocalNet image upgrade fails this check with a
 * diagnostic asking for re-verification, which is the safe direction.
 */
export const SUPPORTED_PROTOCOLS = [
  'future',
  'https://github.com/algorandfoundation/specs/tree/268b63433a907455d439995bf916f6b296018f4f',
];

/** Native Falcon-1024 accounts first ship in algod 5.0 (README documents 5.0.2+). */
export const MIN_ALGOD_MAJOR = 5;

/**
 * Bounded indexer synchronization policy.
 *
 * Not every round difference is corruption: the indexer trails algod by design,
 * and algod's round is read first, so it can legitimately appear a round or two
 * behind this probe's own snapshot. Past the lag bound the authority proofs the
 * suite asserts on would time out, so the run fails fast and retryably instead.
 * An indexer meaningfully *ahead* of algod is a different problem - stale algod
 * or a different chain - and is never waited out.
 */
export const MAX_INDEXER_LAG_ROUNDS = 5;
export const MAX_INDEXER_LEAD_ROUNDS = 2;

/** The wallet `test/helpers.ts` funds accounts from. */
export const DEFAULT_WALLET = 'unencrypted-default-wallet';

const REQUEST_TIMEOUT_MS = 5_000;
const DIAGNOSTIC_CHARS = 200;

/**
 * Whether an algod build is new enough to contain native Falcon-1024 accounts.
 *
 * Necessary but not sufficient: see `SUPPORTED_PROTOCOLS`. Kept pure so the
 * gate is testable without a downgraded node.
 * @param {number} major algod's reported build major version
 * @returns {boolean}
 */
export function hasFalconSupport(major) {
  return Number.isInteger(major) && major >= MIN_ALGOD_MAJOR;
}

/**
 * Whether an active consensus protocol is one this harness has been verified
 * against.
 * @param {unknown} protocol
 * @returns {boolean}
 */
export function isSupportedProtocol(protocol) {
  return (
    typeof protocol === 'string' && SUPPORTED_PROTOCOLS.includes(protocol)
  );
}

/**
 * Whether a genesis id is a local network this harness has been run against.
 * @param {unknown} genesisId
 * @returns {boolean}
 */
export function isSupportedNetwork(genesisId) {
  return (
    typeof genesisId === 'string' && SUPPORTED_GENESIS_IDS.includes(genesisId)
  );
}

/**
 * A round number, or undefined when the value is absent or not a usable one.
 * Negative and non-integer rounds are malformed, not small.
 * @param {unknown} value
 * @returns {number | undefined}
 */
function roundOf(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  return undefined;
}

/**
 * @param {unknown} value
 * @returns {number | undefined}
 */
function intOf(value) {
  return typeof value === 'number' && Number.isInteger(value)
    ? value
    : undefined;
}

/**
 * @param {unknown} value
 * @returns {string | undefined}
 */
function textOf(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

/**
 * Collapse any thrown value into one short line. Network failures carry the
 * useful part in `cause.code` (ECONNREFUSED, ENOTFOUND, TimeoutError).
 * @param {unknown} err
 * @returns {string}
 */
function brief(err) {
  let raw;
  if (err instanceof Error) {
    const code = /** @type {{ code?: unknown }} */ (err.cause ?? {}).code;
    raw = code === undefined ? err.message : `${code}`;
  } else {
    raw = String(err);
  }
  const line = raw.replace(/\s+/g, ' ').trim();
  return line.length > DIAGNOSTIC_CHARS
    ? `${line.slice(0, DIAGNOSTIC_CHARS)}...`
    : line;
}

/**
 * One bounded GET. Rejects with a short, already-formatted message so no
 * caller ever has to print a response body.
 *
 * GET is the only verb this file can issue, which is what makes "read-only"
 * structural rather than a promise in a comment. KMD in particular routes
 * wallet *creation* through POST on the same path that lists them.
 * @param {string} url
 * @param {Record<string, string>} [headers]
 * @returns {Promise<Record<string, any>>}
 */
async function get(url, headers = {}) {
  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`GET ${url}: ${brief(err)}`);
  }
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  try {
    return /** @type {Record<string, any>} */ (await res.json());
  } catch (err) {
    throw new Error(`GET ${url}: unreadable response (${brief(err)})`);
  }
}

const START_HINT =
  'Start it explicitly: npm run localnet:start (see docs/LOCAL_TESTING.md).';

const POLICY_HINT =
  'See the supported-network and protocol policy in docs/LOCAL_TESTING.md.';

/**
 * @typedef {{ service: string, ok: boolean, detail: string, hint?: string }} Check
 * @typedef {{ ok: boolean, checks: Check[], versions: Record<string, string> }} Report
 */

/**
 * Probe algod, the network identity, the Falcon-1024 consensus capability,
 * indexer synchronization and KMD.
 *
 * Returns a report rather than throwing, so one run can name every missing
 * prerequisite instead of revealing them one failed run at a time. Every check
 * is always present in the report: a check that could not be evaluated is
 * reported as failed, never omitted.
 * @returns {Promise<Report>}
 */
export async function preflightLocalnet() {
  /** @type {Check[]} */
  const checks = [];
  /** @type {Record<string, string>} */
  const versions = { node: process.version };

  /** @type {number | undefined} */ let algodRound;
  /** @type {string | undefined} */ let genesisId;
  /** @type {string | undefined} */ let protocol;
  /** @type {string | undefined} */ let nextProtocol;
  /** @type {number | undefined} */ let buildMajor;
  /** @type {string | undefined} */ let buildVersion;
  /** @type {string | undefined} */ let algodError;

  try {
    const status = await get(`${LOCALNET.algodUrl}/v2/status`, {
      'X-Algo-API-Token': LOCALNET.algodToken,
    });
    const v = await get(`${LOCALNET.algodUrl}/versions`, {
      'X-Algo-API-Token': LOCALNET.algodToken,
    });

    algodRound = roundOf(status['last-round']);
    protocol = textOf(status['last-version']);
    nextProtocol = textOf(status['next-version']);
    genesisId = textOf(v['genesis_id']);

    const build = v['build'] ?? {};
    buildMajor = intOf(build.major);
    const minor = intOf(build.minor);
    const buildNumber = intOf(build.build_number);
    if (buildMajor !== undefined && minor !== undefined && buildNumber !== undefined) {
      buildVersion = `${buildMajor}.${minor}.${buildNumber}`;
      versions.algod = buildVersion;
    }
    if (genesisId !== undefined) versions.genesisId = genesisId;
    if (protocol !== undefined) versions.consensus = protocol;
    const genesisHash = textOf(v['genesis_hash_b64']);
    // Recorded as evidence only. Pinning it would break on every image
    // refresh, and the network policy is expressed in terms of genesis id.
    if (genesisHash !== undefined) versions.genesisHash = genesisHash;
  } catch (err) {
    algodError = brief(err);
  }

  if (algodError !== undefined) {
    checks.push({
      service: 'algod',
      ok: false,
      detail: algodError,
      hint: START_HINT,
    });
  } else {
    /** @type {string[]} */
    const missing = [];
    if (algodRound === undefined) missing.push('/v2/status last-round');
    if (protocol === undefined) missing.push('/v2/status last-version');
    if (genesisId === undefined) missing.push('/versions genesis_id');
    if (buildVersion === undefined) missing.push('/versions build');

    checks.push(
      missing.length === 0
        ? {
            service: 'algod',
            ok: true,
            detail: `build ${buildVersion} genesis ${genesisId} round ${algodRound}`,
          }
        : {
            service: 'algod',
            ok: false,
            detail: `answered but did not report ${missing.join(', ')}`,
            hint:
              'A reachable algod with unreadable readiness metadata is not a ' +
              'ready node; check `npm run localnet:start` finished and that ' +
              'nothing is proxying port 4001.',
          },
    );
  }

  // The network behind the port. Always evaluated: an unidentified network is
  // rejected, so absent metadata cannot pass this by being skipped.
  if (genesisId === undefined) {
    checks.push({
      service: 'network',
      ok: false,
      detail: 'algod did not report a genesis id, so the network is unverified',
      hint: POLICY_HINT,
    });
  } else if (PUBLIC_GENESIS_IDS.includes(genesisId)) {
    checks.push({
      service: 'network',
      ok: false,
      detail: `refusing to run against the public network ${genesisId}`,
      hint:
        'The suite creates assets, rekeys accounts and signs transactions. ' +
        'Point it at an AlgoKit LocalNet, never a public network.',
    });
  } else if (!isSupportedNetwork(genesisId)) {
    checks.push({
      service: 'network',
      ok: false,
      detail:
        `genesis ${genesisId} is not a verified local network ` +
        `(supported: ${SUPPORTED_GENESIS_IDS.join(', ')})`,
      hint: POLICY_HINT,
    });
  } else {
    checks.push({
      service: 'network',
      ok: true,
      detail: `genesis ${genesisId} is a verified AlgoKit LocalNet`,
    });
  }

  // Capability, not liveness. Always evaluated, so an algod that hid its
  // version cannot skip the rejection: unverified is not supported.
  const buildOk = buildMajor !== undefined && hasFalconSupport(buildMajor);
  const protocolOk = isSupportedProtocol(protocol);
  // An absent next-version means no pending upgrade. A pending upgrade to an
  // unverified protocol means the capability is about to stop being verified.
  const upgradeOk =
    nextProtocol === undefined ||
    nextProtocol === protocol ||
    isSupportedProtocol(nextProtocol);

  if (buildOk && protocolOk && upgradeOk) {
    checks.push({
      service: 'falcon-1024',
      ok: true,
      // The protocol is named, not just approved: it is the evidence a run
      // should be recorded against, and the reason the build alone is not.
      detail: `algod ${buildVersion} on verified protocol ${protocol}`,
    });
  } else {
    /** @type {string[]} */
    const reasons = [];
    if (buildMajor === undefined) {
      reasons.push('algod build version unavailable');
    } else if (!buildOk) {
      reasons.push(
        `algod ${buildVersion ?? buildMajor} predates native Falcon-1024 ` +
          `accounts (need >= ${MIN_ALGOD_MAJOR}.0)`,
      );
    }
    if (protocol === undefined) {
      reasons.push('active consensus protocol unavailable');
    } else if (!protocolOk) {
      reasons.push(`active protocol ${protocol} is not a verified one`);
    }
    if (!upgradeOk) {
      reasons.push(`pending upgrade to unverified protocol ${nextProtocol}`);
    }
    checks.push({
      service: 'falcon-1024',
      ok: false,
      detail: `capability unverified: ${reasons.join('; ')}`,
      hint:
        buildOk === false && buildMajor !== undefined
          ? 'Upgrading the LocalNet image replaces local chain state, so run it deliberately: python -m algokit localnet reset --update'
          : POLICY_HINT,
    });
  }

  try {
    const health = await get(`${LOCALNET.indexerUrl}/health`);
    const round = roundOf(health['round']);
    const dbAvailable = health['db-available'];
    const migrating = health['is-migrating'];
    const errors = health['errors'];
    const version = textOf(health['version']);
    if (version !== undefined) versions.indexer = version;

    /** @type {string[]} */
    const problems = [];
    if (dbAvailable !== true) problems.push(`db-available ${dbAvailable}`);
    if (migrating === true) problems.push('is-migrating true');
    if (Array.isArray(errors) && errors.length > 0) {
      problems.push(`errors ${brief(errors.join('; '))}`);
    }
    if (round === undefined) problems.push(`round ${health['round']} is not a valid round`);

    // The synchronization bound. Unverifiable is not satisfied: if algod's
    // round is unknown there is nothing to measure the indexer against.
    /** @type {string} */
    let lagDetail;
    if (round === undefined || algodRound === undefined) {
      lagDetail = 'lag unverified';
      if (round !== undefined && algodRound === undefined) {
        problems.push('lag unverifiable because algod did not report a round');
      }
    } else {
      const lag = algodRound - round;
      lagDetail = `lag ${lag}`;
      if (lag > MAX_INDEXER_LAG_ROUNDS) {
        problems.push(
          `lag ${lag} exceeds the ${MAX_INDEXER_LAG_ROUNDS}-round bound`,
        );
      } else if (lag < -MAX_INDEXER_LEAD_ROUNDS) {
        problems.push(`indexer is ${-lag} rounds ahead of algod`);
      }
    }

    checks.push(
      problems.length === 0
        ? {
            service: 'indexer',
            ok: true,
            detail: `version ${versions.indexer ?? 'unknown'} round ${round} ${lagDetail}`,
          }
        : {
            service: 'indexer',
            ok: false,
            detail: `unhealthy: ${problems.join('; ')}`,
            hint:
              'A lag inside the bound clears on its own - re-run ' +
              '`npm run localnet:status` in a moment. Anything else means the ' +
              'indexer or conduit container needs attention; see ' +
              'docs/LOCAL_TESTING.md.',
          },
    );
  } catch (err) {
    checks.push({
      service: 'indexer',
      ok: false,
      detail: brief(err),
      hint: START_HINT,
    });
  }

  try {
    const v = await get(`${LOCALNET.kmdUrl}/versions`, {
      'X-KMD-API-Token': LOCALNET.kmdToken,
    });
    const apiVersions = v['versions'];
    const api =
      Array.isArray(apiVersions) && apiVersions.length > 0
        ? apiVersions.map((/** @type {unknown} */ s) => String(s)).join(',')
        : undefined;
    if (api !== undefined) versions.kmd = api;

    const listed = await get(`${LOCALNET.kmdUrl}/v1/wallets`, {
      'X-KMD-API-Token': LOCALNET.kmdToken,
    });
    const wallets = listed['wallets'];

    if (api === undefined) {
      checks.push({
        service: 'kmd',
        ok: false,
        detail: 'answered but did not report its API versions',
        hint: START_HINT,
      });
    } else if (!Array.isArray(wallets)) {
      checks.push({
        service: 'kmd',
        ok: false,
        detail: `api ${api} but the wallet list was not readable`,
        hint: START_HINT,
      });
    } else {
      /** @type {string[]} */
      const names = wallets.map((/** @type {{ name?: unknown }} */ w) =>
        String(w?.name),
      );
      const present = names.includes(DEFAULT_WALLET);
      checks.push({
        service: 'kmd',
        ok: present,
        detail: present
          ? `api ${api} wallet ${DEFAULT_WALLET} present`
          : `api ${api} but ${DEFAULT_WALLET} is missing ` +
            `(wallets: ${names.join(', ') || 'none'})`,
        hint: present
          ? undefined
          : 'This LocalNet was not created by AlgoKit, or the wallet was renamed; see docs/LOCAL_TESTING.md.',
      });
    }
  } catch (err) {
    checks.push({
      service: 'kmd',
      ok: false,
      detail: brief(err),
      hint: START_HINT,
    });
  }

  return { ok: checks.every((c) => c.ok), checks, versions };
}

/**
 * Render the report as the bounded diagnostic both callers print.
 * @param {Report} report
 * @returns {string}
 */
export function formatPreflight(report) {
  const lines = ['LocalNet preflight (read-only; nothing is started or reset)'];
  for (const c of report.checks) {
    lines.push(`  ${c.service.padEnd(11)} ${c.ok ? 'OK  ' : 'FAIL'} ${c.detail}`);
    if (!c.ok && c.hint) lines.push(`  ${' '.repeat(16)} hint ${c.hint}`);
  }
  const missing = report.checks.filter((c) => !c.ok).map((c) => c.service);
  lines.push(
    report.ok
      ? `  => ready (node ${report.versions.node})`
      : `  => NOT ready: ${missing.join(', ')}. ` +
        'LocalNet tests are required, not optional, so this run fails.',
  );
  return lines.join('\n');
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  const report = await preflightLocalnet();
  process.stdout.write(`${formatPreflight(report)}\n`);
  process.exit(report.ok ? 0 : 1);
}
