/**
 * Authority analysis.
 *
 * A classical key on Algorand controls far more than its own balance. It can
 * hold roles on assets other people own, administer applications, and act for
 * other accounts that were rekeyed to it. Falconer walks that authority graph
 * so a migration can be scoped to what the key actually controls.
 *
 * Those are two different kinds of reach, and a rekey treats them
 * differently. Asset and application roles are exercised by transactions
 * this account sends, so they follow this account's own authority and move
 * when it is rekeyed. An account rekeyed *to* this one is authorised by the
 * key behind this address: Algorand checks a signature against the sender's
 * auth-addr directly and never follows that address's own auth-addr. Rekeying
 * this account therefore leaves those accounts exactly where they were, and
 * every authorisation here is resolved directly, never through a chain.
 */
import algosdk from 'algosdk';
import type {
  AccountExposure,
  AppAdminRole,
  AssetRoleSummary,
  AuthorityEdge,
  CoverageStatus,
  ExposureCoverage,
  Finding,
  IdReadTally,
  IncomingAccount,
  Reach,
  RiskAssessment,
  RoleScanCoverage,
  SampleCoverage,
} from './types.js';
import { assessAuthority } from './authority.js';
import type { AuthorityAssessment } from './authority.js';
import {
  accountRecordOf,
  appStateOf,
  assetRecordOf,
  combineStatus,
  countRead,
  historyCoverage,
  historyGap,
  incomingCoverage,
  incomingGap,
  isShortfall,
  newTally,
  readById,
  sampleAssets,
  sampleDetail,
  sampleGap,
  searchIncoming,
  tallyGaps,
  tallyStatus,
  type AssetRecord,
  type ReadOutcome,
} from './coverage.js';
import { isHashDerivedAddress } from './falcon.js';
import type { FalconerClients } from './networks.js';

const ZERO_ADDRESS = algosdk.ALGORAND_ZERO_ADDRESS_STRING;

export interface AnalyzeOptions {
  /**
   * Also scan the ledger for assets where this account holds a role it did
   * not create. Indexer cannot filter assets by role, so this pages through
   * the asset list and is bounded by `scanLimit`.
   */
  deepScan?: boolean;
  /** Maximum assets to examine during a deep scan. */
  scanLimit?: number;
  /**
   * Assets to check exactly, by id. The operator usually knows which assets
   * matter to them, and checking a named list is exact and immediate where
   * sweeping the ledger is neither.
   */
  assetIds?: bigint[];
  /**
   * Applications to read the global state of, by id. Same blind spot as
   * assets: there is no query for applications whose state names a given
   * address, so the caller has to say which ones matter.
   */
  appIds?: bigint[];
  /**
   * Skip the automatic check of assets this account has opted into. Those
   * are checked by default because holding an asset is the common reason to
   * have been granted a role on it, and the check is exact.
   */
  skipOptedIn?: boolean;
  onProgress?: (message: string) => void;
}

/** Cap on the opted-in check, so an account with huge holdings still returns. */
export const OPTED_IN_LIMIT = 250;

/** Cap on assets named by the caller, so a long list cannot run unbounded. */
export const NAMED_ASSET_LIMIT = 250;

/** Cap on application state reads, for the same reason. */
export const APP_SCAN_LIMIT = 250;

/** Assets a ledger sample reads when no limit is given. */
const DEFAULT_SAMPLE_LIMIT = 50_000;

/** A global-state key, as text when it is printable and hex when it is not. */
function stateKeyLabel(bytes: Uint8Array): string {
  if (!bytes.length) return '(empty)';
  const text = new TextDecoder().decode(bytes);
  return /^[\x20-\x7e]+$/.test(text)
    ? text
    : Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

type AssetParams = {
  creator?: string;
  manager?: string;
  reserve?: string;
  freeze?: string;
  clawback?: string;
  name?: string;
  unitName?: string;
  total?: bigint | number;
  decimals?: number;
  defaultFrozen?: boolean;
};

/**
 * Coerce a number that arrived over the wire into a bigint.
 *
 * algod and Indexer return these as bigints, but a proxy or a non-standard
 * endpoint can hand back a float or a decimal string, and `BigInt(1.5)` is a
 * RangeError. A malformed field on one asset must not abort the whole scan.
 */
function big(v: unknown): bigint {
  if (typeof v === 'bigint') return v;
  if (v === undefined || v === null || v === '') return 0n;
  try {
    if (typeof v === 'number') {
      return Number.isFinite(v) ? BigInt(Math.trunc(v)) : 0n;
    }
    return BigInt(String(v).trim().split('.')[0] || '0');
  } catch {
    return 0n;
  }
}

const str = (v: unknown): string | undefined => {
  if (v === undefined || v === null) return undefined;
  const s = typeof v === 'string' ? v : String(v);
  return s.length ? s : undefined;
};

/** A role address only confers power when it is set to a real account. */
function holdsRole(roleAddr: unknown, address: string): boolean {
  const s = str(roleAddr);
  return !!s && s !== ZERO_ADDRESS && s === address;
}

function rolesFor(params: AssetParams, address: string) {
  const roles: AssetRoleSummary['roles'] = [];
  if (holdsRole(params.manager, address)) roles.push('manager');
  if (holdsRole(params.reserve, address)) roles.push('reserve');
  if (holdsRole(params.freeze, address)) roles.push('freeze');
  if (holdsRole(params.clawback, address)) roles.push('clawback');
  return roles;
}

/**
 * An asset manager can rewrite the asset's own role addresses. If clawback is
 * not permanently disabled, the manager can point clawback at itself and then
 * seize the asset from every holder. Treating "manager" as a lesser role than
 * "clawback" understates the real blast radius.
 */
function managerCanSeize(params: AssetParams): boolean {
  const clawback = str(params.clawback);
  return !!clawback && clawback !== ZERO_ADDRESS;
}

function managerCanFreeze(params: AssetParams): boolean {
  const freeze = str(params.freeze);
  return !!freeze && freeze !== ZERO_ADDRESS;
}

function summarize(
  assetId: bigint,
  params: AssetParams,
  address: string,
): AssetRoleSummary {
  return {
    assetId,
    name: str(params.name),
    unitName: str(params.unitName),
    total: big(params.total),
    decimals: Number(params.decimals ?? 0),
    roles: rolesFor(params, address),
    defaultFrozen: params.defaultFrozen,
  };
}

/* ------------------------------------------------------------------ */

export async function analyzeAccount(
  clients: FalconerClients,
  address: string,
  options: AnalyzeOptions = {},
): Promise<AccountExposure> {
  if (!algosdk.isValidAddress(address)) {
    throw new Error(`Not a valid Algorand address: ${address}`);
  }
  const progress = options.onProgress ?? (() => {});
  const sampleLimit = options.scanLimit ?? DEFAULT_SAMPLE_LIMIT;
  if (!Number.isSafeInteger(sampleLimit) || sampleLimit < 1) {
    // A limit that cannot be read would sample nothing and still read as a
    // sample, so it is refused rather than quietly replaced.
    throw new Error(`scanLimit must be a positive integer, not ${options.scanLimit}`);
  }

  progress('Reading account state');
  // Everything below is derived from this record, so it is read and checked
  // before anything else (CORE-04). A failed read, a 404 included, is thrown:
  // algod answers an address it has no record for with an empty account, so
  // only that answer is an empty account. An unusable record is refused
  // rather than read as zeros or as no authority.
  const read = accountRecordOf(await clients.algod.accountInformation(address).do(), address);
  if (!read.ok) {
    throw new Error(`The node answered with an unusable account record (${read.fault}). Nothing was judged.`);
  }
  const info = read.value;

  const microAlgos = info.amount;
  const minBalance = info.minBalance;
  const authAddr = info.authAddr;
  const assetsHeld = info.heldAssetIds.length;
  const appsOptedIn = info.optedInAppIds.length;

  const findings: Finding[] = [];
  const edges: AuthorityEdge[] = [];

  /* --- assets this account created, and the roles it kept ---------- */
  const createdAssets: AssetRoleSummary[] = [];
  const rawParamsById = new Map<string, AssetParams>();
  for (const { assetId, params } of info.createdAssets) {
    rawParamsById.set(assetId.toString(), params);
    const summary = summarize(assetId, params, address);
    if (summary.roles.length) createdAssets.push(summary);
    for (const role of summary.roles) {
      edges.push({
        from: address,
        to: `asset:${assetId}`,
        relation: ('asa-' + role) as Finding['kind'],
        label: `${role} of ${summary.unitName ?? summary.name ?? 'ASA ' + assetId}`,
        refId: assetId,
        basis: 'capability',
      });
    }
  }

  /* --- created applications ---------------------------------------- */
  // A reference only. On Algorand, creating an application confers nothing
  // by itself: updates, deletion and anything its account can spend are
  // decided by the approval program, which Falconer does not analyse.
  const createdApps: bigint[] = [...new Set(info.createdAppIds)];
  for (const appId of createdApps) {
    edges.push({
      from: address,
      to: `app:${appId}`,
      relation: 'app-creator',
      label: `created app ${appId}`,
      refId: appId,
      basis: 'reference',
    });
  }

  /* --- accounts rekeyed to this one -------------------------------- */
  // Only discovered here. What signs for each of them is resolved below,
  // once this account's own authority is known, because the answer for them
  // is about this *address* and may differ from the answer for this account.
  progress('Looking for accounts rekeyed to this address');
  const search = await searchIncoming(clients, address);
  const controlsAccounts: string[] = [];
  const incomingRaw: Array<{ address: string; microAlgos: bigint }> = [];
  const incomingEdges = new Map<string, AuthorityEdge>();
  let controlledValue = 0n;
  for (const acct of search.accounts) {
    controlsAccounts.push(acct.address);
    incomingRaw.push(acct);
    controlledValue += acct.microAlgos;
    const edge: AuthorityEdge = {
      from: address,
      to: acct.address,
      relation: 'controls-account',
      label: 'signing authority',
      basis: 'capability',
    };
    incomingEdges.set(acct.address, edge);
    edges.push(edge);
  }

  /* --- roles on assets this account did not create ------------------ */
  // Every read ends as a record, an established absence (404), a failure or
  // an unusable response, and only the first two count as done. Created
  // assets are already known from the account record, so they are not read
  // again; any other id is read at most once, whichever source asked first.
  const foreignRoles: AssetRoleSummary[] = [];
  const createdIds = new Set(rawParamsById.keys());
  const assetOutcomes = new Map<string, ReadOutcome<AssetRecord>>();
  const assetsRead = new Set<string>();
  const assetErrors: string[] = [];
  const held = newTally();
  const named = newTally();

  /** Record any role this account holds on one asset. */
  const recordRoles = (assetId: bigint, params: AssetParams, note: string) => {
    const summary = summarize(assetId, params, address);
    if (!summary.roles.length) return;
    rawParamsById.set(assetId.toString(), params);
    foreignRoles.push(summary);
    for (const role of summary.roles) {
      edges.push({
        from: address,
        to: `asset:${assetId}`,
        relation: ('asa-' + role) as Finding['kind'],
        label: `${role} of ASA ${assetId} (${note})`,
        refId: assetId,
        basis: 'capability',
      });
    }
  };

  const readAsset = async (assetId: bigint, tally: IdReadTally, note: string) => {
    const key = assetId.toString();
    let outcome = assetOutcomes.get(key);
    if (!outcome) {
      // The record has to be for this id: one for another asset says
      // nothing about this one, however well-formed it is.
      outcome = await readById(
        () => clients.algod.getAssetByID(assetId).do(),
        (raw) => assetRecordOf(raw, assetId),
      );
      assetOutcomes.set(key, outcome);
      if (outcome.kind === 'read') {
        assetsRead.add(key);
        recordRoles(assetId, outcome.value.params, note);
      }
    }
    countRead(tally, outcome, assetErrors);
  };

  /** Distinct positive ids, in order, leaving out assets this account created. */
  const toRead = (ids: bigint[]) =>
    [...new Set(ids.filter((id) => id > 0n).map(String))]
      .filter((key) => !createdIds.has(key))
      .map((key) => BigInt(key));

  // 1. Assets this account holds. Exact, and the common way an account ends
  //    up holding a role on an asset it did not create.
  if (!options.skipOptedIn) {
    const heldIds = toRead(info.heldAssetIds);
    held.requested = heldIds.length;
    const take = heldIds.slice(0, OPTED_IN_LIMIT);
    if (take.length) progress(`Checking ${take.length} held asset(s) for roles`);
    for (const id of take) await readAsset(id, held, 'held, not creator');
  }

  // 2. Assets the caller named. Exact, immediate, and the answer an operator
  //    who knows their own asset list actually wants.
  const namedIds = toRead(options.assetIds ?? []);
  named.requested = namedIds.length;
  if (namedIds.length) {
    const take = namedIds.slice(0, NAMED_ASSET_LIMIT);
    progress(`Checking ${take.length} named asset(s) for roles`);
    for (const id of take) await readAsset(id, named, 'named, not creator');
  }

  // 3. The ledger sweep. There is no query for assets where this account is
  //    clawback, so this reads assets in id order and filters locally. On
  //    MainNet it stops far short of the end, which is why it is reported
  //    as a sample rather than presented as a scan.
  let sample: SampleCoverage;
  if (options.deepScan) {
    progress(`Sampling up to ${sampleLimit.toLocaleString()} assets from the ledger`);
    sample = await sampleAssets(
      clients,
      sampleLimit,
      (assetId, params) => {
        const key = assetId.toString();
        if (createdIds.has(key) || assetsRead.has(key)) return;
        assetOutcomes.set(key, { kind: 'read', value: { assetId, params } });
        assetsRead.add(key);
        recordRoles(assetId, params, 'sampled');
      },
      progress,
      clients.network.name,
    );
  } else {
    sample = {
      status: 'not-requested',
      detail: sampleDetail('not-requested', 0, false, clients.network.name),
      errors: [],
      limit: 0,
      read: 0,
      requests: 0,
      requestLimit: 0,
      duplicates: 0,
      exhaustive: false,
    };
  }

  /* --- applications whose global state names this address ----------- */
  // An app may keep an admin or treasury address in state and gate calls on
  // it. There is no query for applications whose state names an address, so
  // the same three sources apply: apps created, apps opted into, apps named.
  // A match is a reference: what it permits is up to the program.
  const appAdminRoles: AppAdminRole[] = [];
  const ownPublicKey = algosdk.decodeAddress(address).publicKey;
  const apps = newTally();
  const appErrors: string[] = [];

  const sameBytes = (a: Uint8Array, b: Uint8Array) =>
    a.length === b.length && a.every((x, i) => x === b[i]);

  const readAppState = async (appId: bigint, createdHere: boolean) => {
    // Every entry has been checked by the time it gets here: state that
    // could not be read makes the whole record unusable, rather than being
    // skipped as though it named nobody.
    const outcome = await readById(
      () => clients.algod.getApplicationByID(appId).do(),
      (raw) => appStateOf(raw, appId),
    );
    countRead(apps, outcome, appErrors);
    if (outcome.kind !== 'read') return;
    for (const entry of outcome.value) {
      if (!entry.bytes || entry.bytes.length !== 32) continue;
      if (!sameBytes(entry.bytes, ownPublicKey)) continue;
      appAdminRoles.push({
        appId,
        key: stateKeyLabel(entry.key),
        createdByThisAccount: createdHere,
        permission: 'unverified',
      });
    }
  };

  // Distinct ids, first source wins, so an app this account created is
  // read as created even when it is also opted into or named.
  const appTargets = new Map<string, [bigint, boolean]>();
  const addTarget = (id: bigint, createdHere: boolean) => {
    if (id > 0n && !appTargets.has(id.toString())) {
      appTargets.set(id.toString(), [id, createdHere]);
    }
  };
  for (const id of createdApps) addTarget(id, true);
  for (const id of info.optedInAppIds) addTarget(id, false);
  for (const id of options.appIds ?? []) addTarget(id, false);
  apps.requested = appTargets.size;
  if (appTargets.size) {
    const take = [...appTargets.values()].slice(0, APP_SCAN_LIMIT);
    progress(`Reading global state of ${take.length} application(s)`);
    for (const [id, createdHere] of take) await readAppState(id, createdHere);
  }

  for (const role of appAdminRoles) {
    edges.push({
      from: address,
      to: `app:${role.appId}`,
      relation: 'app-admin',
      label: `named as ${role.key} in app ${role.appId}`,
      refId: role.appId,
      basis: 'reference',
    });
  }

  const heldStatus: CoverageStatus = options.skipOptedIn
    ? 'not-requested'
    : tallyStatus(held);
  const namedStatus = tallyStatus(named, { requestedByCaller: true });
  // Only checks that had something to read speak for the whole: an account
  // holding nothing must not dilute a named read's failure into "partial".
  // With nothing to read anywhere, the created assets in the account
  // record are the whole of the declared scope, and that is complete.
  const assetsCombined = combineStatus([
    held.requested ? heldStatus : 'not-requested',
    namedStatus,
    sample.status,
  ]);
  const assetsStatus: CoverageStatus =
    assetsCombined === 'not-requested' ? 'complete' : assetsCombined;
  const appsStatus = tallyStatus(apps);
  const assetsText = assetsDetail(held, named, sample, assetErrors);
  const appsText = appsDetail(apps, appErrors);

  const roleScan: RoleScanCoverage = {
    assetsExamined: assetsRead.size,
    appsExamined: apps.read,
    optedInChecked: held.read,
    explicitChecked: named.read,
    sampled: sample.read,
    incomplete: isShortfall(assetsStatus) || isShortfall(appsStatus),
    detail: `${assetsText} ${appsText}`,
  };

  /* --- what actually controls this account -------------------------- */
  progress('Establishing what controls this account');
  const authority = await assessAuthority(clients, address, authAddr);
  const alreadyPq = authority.quantumSafe;

  /* --- what actually signs for each account rekeyed to this one ------ */
  if (incomingRaw.length) {
    progress('Establishing what signs for accounts rekeyed to this address');
  }
  const incoming = await assessIncomingAuthority(
    clients,
    address,
    { authAddr, authority },
    incomingRaw,
  );
  for (const acct of incoming) {
    const edge = incomingEdges.get(acct.address);
    if (!edge) continue;
    const who = `${acct.address.slice(0, 6)}…`;
    edge.protected = acct.authority.quantumSafe;
    edge.label = acct.authority.quantumSafe
      ? `signs for ${who} (post-quantum)`
      : `signs for ${who} (needs its own rekey)`;
  }
  // Asset roles are exercised by transactions this account sends, so they
  // are exactly as protected as this account's own authority.
  for (const edge of edges) {
    if (edge.relation.startsWith('asa-')) edge.protected = alreadyPq;
  }
  const residual = incoming.filter((i) => !i.authority.quantumSafe);
  const residualUnconfirmed = residual.filter((i) => !isClassical(i.authority));
  const residualClassical = residual.filter((i) => isClassical(i.authority));
  const protectedIncoming = incoming.filter((i) => i.authority.quantumSafe);
  const sum = (xs: IncomingAccount[]) =>
    xs.reduce((total, i) => total + i.microAlgos, 0n);

  if (authAddr) {
    edges.push({
      from: authAddr,
      to: address,
      relation: 'rekeyed-away',
      label: 'authorises',
      basis: 'capability',
      protected: alreadyPq,
    });
  }

  /* --- what every check covered -------------------------------------- */
  // An incoming account whose own authority could not be looked up counts
  // as exposed, and also keeps the incoming check from being complete.
  const authorityUnchecked = incoming.filter(
    (i) => i.authority.evidenceUnavailable,
  ).length;
  const foreignAppIds = new Set(
    appAdminRoles
      .filter((r) => !r.createdByThisAccount)
      .map((r) => r.appId.toString()),
  );
  const appReferences = new Set([
    ...createdApps.map(String),
    ...foreignAppIds,
  ]).size;
  const coverage: ExposureCoverage = {
    history: historyCoverage(authority),
    incoming: incomingCoverage(search, authorityUnchecked),
    assets: {
      status: assetsStatus,
      detail: assetsText,
      errors: [...new Set([...assetErrors, ...sample.errors])],
      held,
      named,
      sample,
    },
    apps: { status: appsStatus, detail: appsText, errors: appErrors, reads: apps },
    appPermissions: appReferences ? 'unverified' : 'no-references',
  };
  const incomingScan = coverage.incoming.status as AccountExposure['incomingScan'];
  // The same shortfalls, as phrases for the verdict. Incoming and
  // application permissions are stated by assessRisk itself.
  const coverageGaps = [
    historyGap(authority),
    ...(isShortfall(heldStatus) ? tallyGaps(held, 'held asset', OPTED_IN_LIMIT) : []),
    ...(isShortfall(namedStatus)
      ? tallyGaps(named, 'named asset', NAMED_ASSET_LIMIT)
      : []),
    sampleGap(sample),
    ...(isShortfall(appsStatus) ? tallyGaps(apps, 'application', APP_SCAN_LIMIT) : []),
  ].filter((g): g is string => !!g);

  if (authority.authorityClass === 'post-quantum') {
    findings.push({
      kind: 'already-pq',
      severity: 'info',
      title: 'Post-quantum authority, on a provider-confirmed record',
      detail: authority.detail,
      accounts: authAddr ? [authAddr] : undefined,
      fixedByRekey: false,
    });
    // The one way a completed migration silently comes undone. A rekey
    // lives in the account's ledger record, not in the address, so closing
    // the account out deletes it along with everything else.
    findings.push({
      kind: 'closeout-reverts',
      severity: 'medium',
      title: 'Closing this account out would undo the migration',
      detail:
        'The authorised address is part of this account’s ledger ' +
        'record, not a property of the address itself. If the account is ' +
        'ever closed out that record is deleted, and funding the same ' +
        'address again recreates it under its original Ed25519 key, with ' +
        'no rekey and no warning. Anything that sweeps balances to zero ' +
        'with a close-remainder-to can trigger this.',
      accounts: authAddr ? [authAddr] : undefined,
      fixedByRekey: false,
    });
  } else if (authority.authorityClass === 'unknown-hash-derived') {
    findings.push({
      kind: 'authority-unproven',
      severity: 'medium',
      title: 'Authority is hash-derived but unidentified',
      detail: authority.detail,
      accounts: authAddr ? [authAddr] : undefined,
      fixedByRekey: false,
    });
  } else if (authority.authorityClass === 'classical-multisig') {
    findings.push({
      kind: 'classical-multisig',
      severity: 'high',
      title: 'Authority is a classical multisignature account',
      detail: authority.detail,
      accounts: authAddr ? [authAddr] : undefined,
      fixedByRekey: true,
    });
  } else if (authority.authorityClass === 'logicsig') {
    findings.push({
      kind: 'authority-unproven',
      severity: 'medium',
      title: 'Authority is a logic signature, delegation type unconfirmed',
      detail: authority.detail,
      accounts: authAddr ? [authAddr] : undefined,
      fixedByRekey: false,
    });
  }

  if (!alreadyPq) {
    if (authAddr && authority.authorityClass === 'classical-key') {
      findings.push({
        kind: 'rekeyed-away',
        severity: 'medium',
        title: 'Controlled by another classical key',
        detail:
          `Authority for this account belongs to ${authAddr}, which is an ` +
          'Ed25519 address. Migrating that address would not change this: ' +
          "Algorand checks this account's signatures against " +
          `${authAddr} itself and never follows where that address is ` +
          'rekeyed, so its original key keeps signing for this account ' +
          'either way. This account needs its own rekey, signed by that key.',
        accounts: [authAddr],
        fixedByRekey: true,
      });
    }

    if (microAlgos > 0n) {
      // Who can actually spend this depends on whether the account was
      // rekeyed. Saying "this account's own key" when authority sits
      // elsewhere would name the wrong key as the thing to protect. And only
      // an on-curve address has an Ed25519 private key behind it: one off
      // the curve that signs for itself is a multisig, a program or not yet
      // identified, so no private key is named for it (PQ-04).
      const ownKey = !authAddr && authority.authorityClass === 'classical-key';
      const detail = authAddr
        ? `${formatAlgos(microAlgos)} ALGO is spendable by whoever controls ` +
          `${authAddr}, which is this account's authority. The account's own ` +
          'Ed25519 key can no longer move it.'
        : ownKey
          ? `${formatAlgos(microAlgos)} ALGO is spendable by whoever holds this ` +
            "account's Ed25519 private key. On Algorand the address is the " +
            'public key, so this key’s public half is already permanently ' +
            'published on-chain.'
          : `${formatAlgos(microAlgos)} ALGO is spendable by whatever authorises ` +
            'this hash-derived address, which signs for itself and is not ' +
            'established as post-quantum.';
      findings.push({
        kind: 'self-custody',
        severity: microAlgos > 1_000_000_000n ? 'high' : 'medium',
        title: ownKey
          ? 'Balance held under a classical key'
          : 'Balance held under an authority not established as post-quantum',
        detail,
        microAlgos,
        fixedByRekey: true,
      });
    }

    if (assetsHeld > 0) {
      findings.push({
        kind: 'asa-holdings',
        severity: 'medium',
        title: `${assetsHeld} asset position${assetsHeld === 1 ? '' : 's'} held`,
        detail:
          'Token and NFT balances move with the account. A rekey preserves ' +
          'every opt-in, so none of these need to be transferred.',
        assetIds: info.heldAssetIds,
        fixedByRekey: true,
      });
    }
  }

  /* Role findings apply whether or not the account is already migrated,
     because they describe what the address controls. */
  const allRoles = [...createdAssets, ...foreignRoles];
  const seizable = new Set<string>();
  const freezable = new Set<string>();

  for (const asset of allRoles) {
    const raw = rawParamsById.get(asset.assetId.toString()) ?? {};
    const label = asset.unitName ?? asset.name ?? `ASA ${asset.assetId}`;

    if (asset.roles.includes('clawback')) {
      seizable.add(asset.assetId.toString());
      findings.push({
        kind: 'asa-clawback',
        severity: 'critical',
        title: `Clawback authority over ${label}`,
        detail:
          `This key can move ${label} out of any holder's account without ` +
          'their consent. Compromise of this key puts every holder of this ' +
          'asset at risk, not just this account.',
        assetIds: [asset.assetId],
        thirdParty: true,
        fixedByRekey: true,
      });
    }

    if (asset.roles.includes('freeze')) {
      freezable.add(asset.assetId.toString());
      findings.push({
        kind: 'asa-freeze',
        severity: 'high',
        title: `Freeze authority over ${label}`,
        detail:
          `This key can freeze or unfreeze ${label} in any holder's account, ` +
          'halting transfers for the entire asset.',
        assetIds: [asset.assetId],
        thirdParty: true,
        fixedByRekey: true,
      });
    }

    if (asset.roles.includes('manager')) {
      // Whether a live clawback exists is a fact about the asset, not about
      // who holds the role. Suppressing it when this key holds clawback
      // itself made the detail claim clawback was permanently disabled on an
      // asset whose clawback is live and pointed at this very key.
      const clawbackLive = managerCanSeize(raw);
      const freezeLive = managerCanFreeze(raw);
      const holdsClawback = asset.roles.includes('clawback');
      if (clawbackLive) seizable.add(asset.assetId.toString());
      if (freezeLive) freezable.add(asset.assetId.toString());
      findings.push({
        kind: 'asa-manager',
        severity: clawbackLive ? 'critical' : 'high',
        title: `Manager of ${label}`,
        detail: !clawbackLive
          ? `This key can reconfigure ${label}'s manager, reserve and freeze ` +
            'addresses. Clawback is permanently disabled, so it cannot be ' +
            'used to seize holdings.'
          : holdsClawback
            ? `Clawback is live on ${label} and this key already holds it. ` +
              'Manager authority also lets this key reassign clawback, so no ' +
              'one else can close the seizure path while this key manages ' +
              'the asset.'
            : `This key can reassign ${label}'s clawback address to itself ` +
              'and then seize the asset from every holder. Clawback is not ' +
              'disabled on this asset, so manager authority is equivalent ' +
              'to clawback authority.',
        assetIds: [asset.assetId],
        thirdParty: clawbackLive || freezeLive,
        fixedByRekey: true,
      });
    }

    if (asset.roles.includes('reserve')) {
      findings.push({
        kind: 'asa-reserve',
        severity: 'low',
        title: `Reserve address for ${label}`,
        detail:
          'Units held at the reserve address are reported as un-minted ' +
          'supply. This is a labelling role and confers no direct authority.',
        assetIds: [asset.assetId],
        fixedByRekey: true,
      });
    }
  }

  /* Application relationships are references. Without program analysis no
     permission is established, so these findings claim no privilege, no
     reach over other people and no fix from a rekey: they state what was
     found and keep the verdict from being complete. */
  if (createdApps.length) {
    const n = createdApps.length;
    findings.push({
      kind: 'app-creator',
      severity: 'medium',
      title: `Created ${n} application${n === 1 ? '' : 's'}; permissions unverified`,
      detail:
        'On Algorand, creating an application confers nothing by itself: ' +
        "updates, deletion and anything the application's account can spend " +
        'are decided by its approval program, which Falconer does not ' +
        'analyse. What this address can do there is not established, so ' +
        'this is a reference, not a privilege. It adds nothing to the score, ' +
        'and it keeps the verdict from being complete.',
      appIds: createdApps,
      thirdParty: false,
      fixedByRekey: false,
    });
  }

  const foreignAdminApps = appAdminRoles.filter((r) => !r.createdByThisAccount);
  if (foreignAdminApps.length) {
    const keys = [...new Set(foreignAdminApps.map((r) => r.key))];
    const n = foreignAppIds.size;
    findings.push({
      kind: 'app-admin',
      severity: 'medium',
      title:
        `Named in the state of ${n} application${n === 1 ? '' : 's'} it did ` +
        'not create; permissions unverified',
      detail:
        `This address is stored in application global state under ` +
        `${keys.map((k) => `"${k}"`).join(', ')}. An application can gate ` +
        'calls on an address held in state, but whether this one does is up ' +
        'to its program, which Falconer does not analyse. What is ' +
        'established is that the address is there: a reference, not a ' +
        'privilege. It adds nothing to the score, and it keeps the verdict ' +
        'from being complete.',
      appIds: [...foreignAppIds].map((id) => BigInt(id)),
      thirdParty: false,
      fixedByRekey: false,
    });
  }

  /* Accounts rekeyed to this address. None of these is fixed by rekeying
     this account: what signs for them is the key behind this address, and a
     rekey of this account changes only what signs for this account. Each
     balance is reported in exactly one of these findings. */
  const plural = (n: number) => (n === 1 ? '' : 's');
  // Naming the account's own authority, when it is somewhere else, is what
  // stops a reader assuming the incoming accounts moved along with it.
  const notWhereThisIsRekeyed = authAddr
    ? `, not by ${authAddr}, which is what signs for this account`
    : '';

  const them = (n: number) => (n === 1 ? 'it' : 'them');
  const each = (n: number) => (n === 1 ? 'It needs' : 'Each needs');

  if (residualClassical.length) {
    const value = sum(residualClassical);
    const n = residualClassical.length;
    findings.push({
      kind: 'controls-account',
      severity: 'critical',
      title:
        `Signing authority over ${residualClassical.length} other ` +
        `account${plural(residualClassical.length)}`,
      detail:
        `${formatAlgos(value)} ALGO sits in ${residualClassical.length} ` +
        `account${plural(residualClassical.length)} rekeyed to this address, ` +
        `authorised by the classical key behind ${address} itself` +
        `${notWhereThisIsRekeyed}. Algorand never follows an authority's own ` +
        `rekey, so migrating this account does not move ${them(n)}. ` +
        `${each(n)} its own rekey, signed by that key - which also means ` +
        `that key must be kept until ${n === 1 ? 'it has' : 'they have'} one.`,
      microAlgos: value,
      accounts: residualClassical.map((i) => i.address),
      thirdParty: true,
      fixedByRekey: false,
    });
  }

  if (residualUnconfirmed.length) {
    const value = sum(residualUnconfirmed);
    findings.push({
      kind: 'controls-account',
      severity: 'medium',
      title:
        `Authority over ${residualUnconfirmed.length} other ` +
        `account${plural(residualUnconfirmed.length)} is unconfirmed`,
      detail:
        `${formatAlgos(value)} ALGO sits in ${residualUnconfirmed.length} ` +
        `account${plural(residualUnconfirmed.length)} rekeyed to this address, ` +
        `authorised by ${address} itself${notWhereThisIsRekeyed}. That address ` +
        'is hash-derived, but nothing on chain establishes that the key ' +
        'behind it is post-quantum rather than a multisig or logic ' +
        'signature built from classical keys. Migrating this account does ' +
        `not change what signs for ${them(residualUnconfirmed.length)}.`,
      microAlgos: value,
      accounts: residualUnconfirmed.map((i) => i.address),
      thirdParty: true,
      fixedByRekey: false,
    });
  }

  if (protectedIncoming.length) {
    findings.push({
      kind: 'controls-account',
      severity: 'info',
      title:
        `Authorises ${protectedIncoming.length} other ` +
        `account${plural(protectedIncoming.length)} with a post-quantum ` +
        'key, on a provider-confirmed record',
      detail:
        `${protectedIncoming.length} account${plural(protectedIncoming.length)} ` +
        `rekeyed to this address ${protectedIncoming.length === 1 ? 'is' : 'are'} ` +
        `authorised by ${address} itself, and a provider-confirmed ` +
        'Falcon-1024 record re-derives that address locally. They are ' +
        'protected by that key ' +
        'directly, not by anything this account has been rekeyed to.',
      microAlgos: sum(protectedIncoming),
      accounts: protectedIncoming.map((i) => i.address),
      // Nobody is exposed through these: the key signing for them is
      // established post-quantum, so this is reach, not a third-party risk.
      thirdParty: false,
      fixedByRekey: false,
    });
  }

  if (search.stop) {
    // The search did not reach the end of the provider's results. Whatever
    // it missed is unknown, which is never the same as none.
    findings.push({
      kind: 'controls-account',
      severity: 'medium',
      title: incomingScan === 'unavailable'
        ? 'Accounts rekeyed to this address could not be checked'
        : 'The search for accounts rekeyed to this address did not finish',
      detail:
        `${coverage.incoming.detail} That is not evidence there are no ` +
        'others, and none of them would be covered by this account’s own ' +
        'migration.',
      fixedByRekey: false,
    });
  }

  const risk = assessRisk({
    alreadyPq,
    authorityUnproven: authority.authorityClass === 'unknown-hash-derived',
    microAlgos,
    controlledValue,
    assetsHeld,
    appCount: createdApps.length,
    appAdminCount: foreignAppIds.size,
    seizable: seizable.size,
    freezable: freezable.size,
    controlsCount: controlsAccounts.length,
    residualCount: residual.length,
    residualValue: sum(residual),
    residualUnconfirmed: residualUnconfirmed.length,
    incomingUnverified: coverage.incoming.status !== 'complete',
    incomingGap: incomingGap(search, authorityUnchecked),
    coverageGaps,
  });

  const byId = (a: bigint, b: bigint) => (a < b ? -1 : a > b ? 1 : 0);
  const reach: Reach = {
    seize: [...seizable].map((id) => BigInt(id)).sort(byId),
    freeze: [...freezable].map((id) => BigInt(id)).sort(byId),
    assetRolesExposed: !alreadyPq,
    incomingExposed: residual.length,
    incomingProtected: protectedIncoming.length,
    appReferences,
  };

  return {
    address,
    authAddr,
    authority,
    isPostQuantum: alreadyPq,
    microAlgos,
    minBalance,
    assetsHeld,
    appsOptedIn,
    createdAssets,
    createdApps,
    foreignRoles,
    appAdminRoles,
    roleScan,
    controlsAccounts,
    incoming,
    incomingScan,
    coverage,
    reach,
    findings: sortFindings(findings),
    edges,
    risk,
  };
}

/* ------------------------------------------------------------------ */

function isClassical(a: AuthorityAssessment): boolean {
  return (
    a.authorityClass === 'classical-key' ||
    a.authorityClass === 'classical-multisig'
  );
}

/**
 * Evidence lookups spent on accounts rekeyed to one address before the rest
 * are reported as unchecked. On-curve authorities need none, and one proven
 * lookup answers for every account, so this only binds for a hash-derived
 * address that has never been seen signing.
 */
export const INCOMING_LOOKUP_LIMIT = 25;

/** Describe what signs for an account rekeyed to `authoriser`. */
function incomingDetail(a: AuthorityAssessment, authoriser: string): string {
  const who =
    `Authorised by ${authoriser} itself, not by anything that address has ` +
    'been rekeyed to.';
  switch (a.authorityClass) {
    case 'post-quantum':
      return (
        `${who} The provider reported a confirmed Falcon-1024 record whose ` +
        `scheme, public key and salt re-derive ${authoriser} locally, so ` +
        'the key behind it is post-quantum on that evidence.'
      );
    case 'classical-key':
      return (
        `${who} ${authoriser} is a point on the Ed25519 curve, so the key ` +
        'behind it is classical.'
      );
    case 'classical-multisig':
      return `${who} ${authoriser} is a classical multisignature address.`;
    case 'logicsig':
      return (
        `${who} ${authoriser} is a logic signature, and its delegation type ` +
        'is unconfirmed.'
      );
    case 'unknown-hash-derived':
      return a.evidenceUnavailable
        ? `${who} ${authoriser} is hash-derived, and its type could not be ` +
            'checked. This is not evidence of safety.'
        : `${who} ${authoriser} is hash-derived, but no signature from it ` +
            'has been found, so its type is unconfirmed.';
  }
}

/**
 * Resolve what signs for each account rekeyed to `address`.
 *
 * The authority for every one of them is `address` itself - the key behind
 * that address - because Algorand checks a signature against the sender's
 * auth-addr and never follows that address's own auth-addr. So the scanned
 * account's own authority is *not* their authority when the scanned account
 * has been rekeyed: that assessment is about a different key, and reusing it
 * would be exactly the transitive mistake this function exists to avoid.
 *
 * The kind of key behind an address is a property of the address, so one
 * proven assessment of it answers for every account it authorises. It is
 * taken from the scanned account's own assessment only when that account
 * signs for itself, which is the one case where its own evidence is evidence
 * about this address; otherwise it comes from the incoming accounts' own
 * transactions, looked up with the unchanged conservative evidence model.
 * Anything not established stays unconfirmed.
 */
export async function assessIncomingAuthority(
  clients: FalconerClients,
  address: string,
  own: { authAddr?: string; authority: AuthorityAssessment },
  accounts: Array<{ address: string; microAlgos: bigint }>,
): Promise<IncomingAccount[]> {
  if (!accounts.length) return [];

  const asIncoming = (a: AuthorityAssessment): AuthorityAssessment => ({
    ...a,
    authAddr: address,
    detail: incomingDetail(a, address),
  });

  // Self-authorised: the scanned account's own evidence was gathered for
  // exactly this address as an authority.
  let shared: AuthorityAssessment | undefined =
    !own.authAddr && own.authority.proven ? own.authority : undefined;

  const resolved: Array<AuthorityAssessment | undefined> = [];
  let lookups = 0;
  for (const acct of accounts) {
    if (shared) {
      resolved.push(shared);
      continue;
    }
    // On-curve needs no lookup, so the limit only counts real ones.
    if (isHashDerivedAddress(address)) {
      if (lookups >= INCOMING_LOOKUP_LIMIT) {
        resolved.push(undefined);
        continue;
      }
      lookups++;
    }
    const a = await assessAuthority(clients, acct.address, address);
    if (a.proven) shared = a;
    resolved.push(a);
  }

  const notChecked: AuthorityAssessment = {
    authAddr: address,
    authorityClass: 'unknown-hash-derived',
    quantumSafe: false,
    proven: false,
    evidenceUnavailable: true,
    evidence: {
      // Never asked: the lookup limit was spent on earlier accounts.
      basis: 'none',
      lookup: 'unavailable',
      examined: 0,
      guarantees: {
        providerConfirmedRecord: false,
        localAddressBinding: false,
        independentSignatureVerification: false,
      },
      rejected: [],
    },
    detail: '',
  };

  return accounts.map((acct, i) => {
    // A class proven for this address holds for every account it
    // authorises, including ones assessed before it was found.
    const a = shared ?? resolved[i] ?? notChecked;
    return { ...acct, authority: asIncoming(a) };
  });
}

/* ------------------------------------------------------------------ */

/** Shortfall phrases as one sentence, with the reasons recorded for them. */
function shortfallSentence(gaps: string[], errors: string[]): string {
  const text = gaps.join('; ');
  const reasons = errors.length ? ` (${errors.join(', ')})` : '';
  return `${text[0]!.toUpperCase()}${text.slice(1)}${reasons}.`;
}

/**
 * State what the asset checks covered, in the terms that matter to someone
 * reading a report that has no findings in it: what was read exactly, what
 * was only sampled or not searched at all, and what fell short.
 */
function assetsDetail(
  held: IdReadTally,
  named: IdReadTally,
  sample: SampleCoverage,
  errors: string[],
): string {
  const exact: string[] = [];
  if (held.read) exact.push(`${held.read} held`);
  if (named.read) exact.push(`${named.read} named`);
  const parts: string[] = [];
  if (exact.length) parts.push(`Checked ${exact.join(' and ')} asset(s) exactly.`);
  const absent = held.notFound + named.notFound;
  if (absent) {
    parts.push(
      `${absent} asset id${absent === 1 ? '' : 's'} asked for ` +
        `${absent === 1 ? 'does' : 'do'} not exist.`,
    );
  }
  const gaps = [
    ...tallyGaps(held, 'held asset', OPTED_IN_LIMIT),
    ...tallyGaps(named, 'named asset', NAMED_ASSET_LIMIT),
  ];
  if (gaps.length) parts.push(shortfallSentence(gaps, errors));
  parts.push(sample.detail);
  return parts.join(' ');
}

/** State what the application reads covered, and what fell short. */
function appsDetail(t: IdReadTally, errors: string[]): string {
  const parts = [
    t.read
      ? `Read the global state of ${t.read} application(s). Applications ` +
        'this account neither created, opted into, nor named were not read.'
      : 'No application global state was read, so an address held in ' +
        "application state, such as an app admin's, would not have been seen.",
  ];
  if (t.notFound) {
    parts.push(
      `${t.notFound} application id${t.notFound === 1 ? '' : 's'} asked for ` +
        `${t.notFound === 1 ? 'does' : 'do'} not exist.`,
    );
  }
  const gaps = tallyGaps(t, 'application', APP_SCAN_LIMIT);
  if (gaps.length) parts.push(shortfallSentence(gaps, errors));
  return parts.join(' ');
}

const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}

export function formatAlgos(microAlgos: bigint): string {
  // Spendable balance is negative whenever an account sits below its minimum
  // balance, so the sign has to be carried rather than left in the digits:
  // -900000 formatted per-part reads '0.-9'.
  const negative = microAlgos < 0n;
  const magnitude = negative ? -microAlgos : microAlgos;
  const sign = negative ? '-' : '';
  const whole = magnitude / 1_000_000n;
  const frac = magnitude % 1_000_000n;
  if (frac === 0n) return `${sign}${whole.toLocaleString()}`;
  const decimals = frac.toString().padStart(6, '0').replace(/0+$/, '');
  return `${sign}${whole.toLocaleString()}.${decimals}`;
}

export interface RiskInputs {
  alreadyPq: boolean;
  /**
   * Authority is hash-derived but its type is unconfirmed, so it may still be
   * a multisig or logic signature built from classical keys.
   */
  authorityUnproven?: boolean;
  microAlgos: bigint;
  controlledValue: bigint;
  assetsHeld: number;
  /**
   * Applications this address created. A reference: without program
   * analysis no permission is established, so these add no points, but
   * they keep the verdict from being complete.
   */
  appCount: number;
  /**
   * Applications naming this address in global state that it did not
   * create. The same kind of reference, treated the same way.
   */
  appAdminCount?: number;
  seizable: number;
  freezable: number;
  controlsCount: number;
  /**
   * Of `controlsCount`, the accounts rekeyed to this address whose authority
   * is not proven post-quantum, and their combined balance - a subset of
   * `controlledValue`. Both default to every controlled account: when their
   * authority has not been resolved, the conservative reading is that none
   * of them is protected.
   */
  residualCount?: number;
  residualValue?: bigint;
  /** Of `residualCount`, how many are unconfirmed rather than classical. */
  residualUnconfirmed?: number;
  /**
   * The search for accounts rekeyed to this address did not complete, or
   * what signs for some of them could not be checked. The accounts it would
   * have found are unknown, so they are neither counted nor assumed absent:
   * the verdict simply cannot be `safe`.
   */
  incomingUnverified?: boolean;
  /** How the incoming search fell short, as a phrase; a generic one otherwise. */
  incomingGap?: string;
  /**
   * The other checks that fell short - signing history, asset and
   * application reads, a requested ledger sample - one phrase each. Any
   * entry keeps the verdict from being complete.
   */
  coverageGaps?: string[];
}

/** The incoming shortfall, stated when the caller gives no detail. */
const INCOMING_GAP = 'accounts rekeyed to this address could not be checked';

/**
 * How a summary states own post-quantum authority: with its basis, since the
 * provider's confirmed record and a local address binding are what establish
 * it - not a signature Falconer verified itself.
 */
const OWN_PQ =
  'Authority for this account is a Falcon-1024 key: the provider reported a ' +
  'confirmed Falcon-signed transaction from it, and its address binding ' +
  'checks out locally, ';

/**
 * Score urgency, not just value.
 *
 * A key holding a small balance but clawback authority over a widely-held
 * asset is a larger problem than a key holding a large balance and nothing
 * else, because breaking it compromises people who never chose to trust it.
 *
 * Two authorities are in play and only what is actually exposed is scored.
 * This account's balance, holdings and roles are exercised under its own
 * authority, so they stop counting once that is proven post-quantum.
 * Accounts rekeyed to this address are authorised by the key behind the
 * address, not by this account's authority, so this account's migration
 * never clears them: they count until each is protected in its own right.
 */
export function assessRisk(input: RiskInputs): RiskAssessment {
  const directMicroAlgos = input.microAlgos + input.controlledValue;
  const residualCount = input.residualCount ?? input.controlsCount;
  const residualValue = input.residualValue ?? input.controlledValue;
  const residualUnconfirmed = Math.min(
    input.residualUnconfirmed ?? 0,
    residualCount,
  );
  const residualClassical = residualCount - residualUnconfirmed;
  const thirdPartyAssets = input.seizable + input.freezable;
  const systemic =
    input.seizable > 0 || input.freezable > 0 || input.controlsCount > 0;
  const incomingUnverified = !!input.incomingUnverified;
  const s = (n: number) => (n === 1 ? '' : 's');

  // Everything that keeps this verdict from being complete. Application
  // references are among them: they may carry permissions nobody has
  // established, so they cannot count toward the score or toward "safe".
  const appReferences = input.appCount + (input.appAdminCount ?? 0);
  const uncertainties = [
    ...(incomingUnverified ? [input.incomingGap ?? INCOMING_GAP] : []),
    ...(input.coverageGaps ?? []),
    ...(appReferences
      ? [
          `${appReferences} application reference${s(appReferences)} with ` +
            'unverified permissions',
        ]
      : []),
  ];
  const complete = uncertainties.length === 0;
  const residual = {
    residualAccounts: residualCount,
    residualMicroAlgos: residualValue,
    incomingUnverified,
    complete,
    uncertainties,
  };
  const unchecked = complete
    ? ''
    : ` Not established: ${uncertainties.join('; ')}. This is not a safe verdict.`;

  if (input.alreadyPq && residualCount === 0 && !complete) {
    // Own authority is proven; what it does not cover could not be
    // established. Nothing is invented for it, and nothing is concluded
    // from it.
    return {
      score: 0,
      band: 'unverified',
      directMicroAlgos,
      systemic,
      thirdPartyAssets,
      ...residual,
      summary:
        OWN_PQ +
        'so it cannot be recovered from the address by a quantum adversary.' +
        unchecked,
    };
  }

  if (input.alreadyPq && residualCount === 0) {
    // Migrating does not give up any role. What changed is that a quantum
    // adversary can no longer take them, which is what the score reports;
    // saying the reach is gone would be a different and false claim.
    return {
      score: 0,
      band: 'safe',
      directMicroAlgos,
      systemic,
      thirdPartyAssets,
      ...residual,
      summary:
        OWN_PQ +
        'so it cannot be recovered from the address by a quantum adversary.' +
        (input.seizable > 0 || input.freezable > 0
          ? ' The asset roles this address holds are unchanged, and are ' +
            'now exercised under that key.'
          : '') +
        (input.controlsCount > 0
          ? ` The ${input.controlsCount} account${s(input.controlsCount)} ` +
            'rekeyed to this address ' +
            `${input.controlsCount === 1 ? 'is' : 'are'} authorised ` +
            'directly by a post-quantum key, on the same kind of evidence.'
          : ''),
    };
  }

  const ownExposed = !input.alreadyPq;
  const exposedValue = (ownExposed ? input.microAlgos : 0n) + residualValue;
  const exposedHoldings = ownExposed ? input.assetsHeld : 0;

  let score = 0;
  // Value this key can spend, not just value sitting in its own balance:
  // a treasury that holds nothing directly and signs for every satellite
  // account is not a low-value key.
  const holdsValue = exposedValue > 0n || exposedHoldings > 0;
  if (holdsValue) score += 25;

  // A hash-derived authority of unknown type is better than a bare key -
  // it is at least not trivially recoverable from the address - but it is
  // not safety, so the base exposure is discounted rather than removed. Only
  // when *every* exposed authority is unconfirmed, though: a classical
  // account rekeyed to this address is fully exposed whatever this account's
  // own authority turns out to be.
  const unprovenDiscount =
    residualClassical === 0 &&
    (ownExposed ? !!input.authorityUnproven : residualUnconfirmed > 0)
      ? 0.5
      : 1;

  // Value contributes on a log scale: each 10x adds 5 points, capped at 25.
  // Balances in accounts rekeyed to this one are spendable by the key behind
  // this address, so they belong in the value term and not only in the flat
  // systemic bonus.
  const algos = Number(exposedValue / 1_000_000n);
  if (algos > 0) score += Math.min(25, Math.round(Math.log10(algos + 1) * 5));

  if (residualCount > 0) score += 10;
  // Only established capabilities score. Application references are not
  // among them, whatever the program may turn out to allow.
  if (ownExposed) {
    if (input.freezable > 0) score += 15;
    if (input.seizable > 0) score += 30;
  }

  score = Math.round(score * unprovenDiscount);
  score = Math.max(0, Math.min(100, score));

  const scored: RiskAssessment['band'] =
    score >= 75
      ? 'critical'
      : score >= 50
        ? 'high'
        : score >= 25
          ? 'elevated'
          : score > 0
            ? 'low'
            : 'safe';
  // Established exposure keeps its real band, as a lower bound. Only "safe"
  // is withheld: nothing found exposed is not the same as nothing exposed
  // when part of what this address authorises was never established.
  const band: RiskAssessment['band'] =
    !complete && scored === 'safe' ? 'unverified' : scored;

  const notCovered =
    residualCount > 0
      ? ` The ${residualCount} account${s(residualCount)} rekeyed to this ` +
        'address would not be covered by that migration: each needs its own ' +
        'rekey.'
      : '';

  let summary: string;
  if (score === 0 && !complete) {
    summary = 'Nothing checked is exposed under this key.';
  } else if (score === 0) {
    summary = 'Nothing of value is held under this key.';
  } else if (!ownExposed) {
    summary =
      OWN_PQ +
      `but that does not cover the ${residualCount} account` +
      `${s(residualCount)} rekeyed to this address. ` +
      `${residualCount === 1 ? 'It is' : 'They are'} authorised by the key ` +
      'behind this address itself' +
      (residualClassical > 0
        ? ', which is classical,'
        : ', whose type is unconfirmed,') +
      ' and migrating this account did not move ' +
      `${residualCount === 1 ? 'it' : 'them'}. ` +
      `${residualCount === 1 ? 'It needs its' : 'Each needs its'} own rekey.`;
  } else if (input.authorityUnproven && residualClassical === 0) {
    summary =
      'Authority is hash-derived, so it is not a bare classical key, but ' +
      'nothing on chain confirms it is post-quantum rather than a multisig ' +
      'or logic signature.';
  } else if (input.seizable > 0) {
    summary =
      `This key can seize ${input.seizable} asset${s(input.seizable)} ` +
      'from any holder, so breaking it harms people who never chose to trust ' +
      'it. Migrate this key before any that only hold their own balance.' +
      notCovered;
  } else if (residualCount > 0 && input.freezable === 0) {
    summary =
      `The key behind this address signs for ${residualCount} other ` +
      `account${s(residualCount)}. Migrating this account will not move ` +
      `${residualCount === 1 ? 'it' : 'them'}: ` +
      `${residualCount === 1 ? 'it needs its' : 'each needs its'} own rekey.`;
  } else if (input.freezable > 0) {
    // Named for the role actually found. Signing for accounts that are
    // already protected is not authority over anyone's assets.
    summary =
      `This key can freeze ${input.freezable} asset${s(input.freezable)} in ` +
      "any holder's account, and migrating it protects that role." +
      notCovered;
  } else {
    summary =
      `${formatAlgos(exposedValue)} ALGO plus ${input.assetsHeld} asset ` +
      `position${s(input.assetsHeld)} are held under a classical key.`;
  }
  summary += unchecked;

  return {
    score,
    band,
    directMicroAlgos,
    systemic,
    thirdPartyAssets,
    ...residual,
    summary,
  };
}

/** How a risk verdict should be stated, shared by every presentation. */
export interface RiskVerdict {
  /** Headline for the aggregate verdict, e.g. "No exposure found". */
  headline: string;
  /**
   * The score as shown: `?` when nothing established is exposed but the
   * verdict is incomplete, and `N+` when the score is only a lower bound.
   */
  score: string;
  /**
   * True only for a complete verdict with no exposure found. Even then it
   * covers the checks listed and nothing else: it is not a certification.
   */
  safe: boolean;
}

/**
 * The words and number a report should lead with.
 *
 * Kept here, next to the scoring, so the CLI and the web app cannot drift
 * into presenting an incomplete verdict as clean, or a clean one as more
 * than "nothing exposed was found in what was checked".
 */
export function riskVerdict(risk: RiskAssessment): RiskVerdict {
  if (risk.band === 'unverified') {
    return { headline: 'Exposure not verified', score: '?', safe: false };
  }
  if (risk.band === 'safe') {
    return { headline: 'No exposure found', score: String(risk.score), safe: true };
  }
  const name = `${risk.band[0]!.toUpperCase()}${risk.band.slice(1)}`;
  // Anything short of complete makes the score a lower bound. The fallback
  // reads a verdict produced before `complete` existed.
  const complete = risk.complete ?? !risk.incomingUnverified;
  return !complete
    ? {
        headline: `${name} exposure, at least`,
        score: `${risk.score}+`,
        safe: false,
      }
    : { headline: `${name} exposure`, score: String(risk.score), safe: false };
}
