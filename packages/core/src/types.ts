/**
 * Core domain types for Falconer.
 *
 * Falconer analyses how much authority a classical Ed25519 key holds on
 * Algorand, and migrates that authority to a Falcon-1024 post-quantum key
 * without changing the account address.
 */

import type { AuthorityAssessment } from './authority.js';
import type { MigrationBudget } from './budget.js';

/** A Falcon-1024 keypair plus the Algorand address it authorises. */
export interface PqIdentity {
  /** 2-byte scheme id; `f1` for Falcon-1024. */
  scheme: Uint8Array;
  /** Falcon-1024 public key (1793 bytes). */
  publicKey: Uint8Array;
  /** Falcon-1024 private key (2305 bytes). Never leaves the client. */
  privateKey: Uint8Array;
  /** Post-quantum account address, derived from the public key. */
  address: string;
  /** Canonical salt chosen so the derived address is an off-curve point. */
  salt: number;
  /** 25-word phrase this identity was derived from, when applicable. */
  mnemonic?: string;
}

/** Why an account is exposed, and by how much. */
export type FindingKind =
  | 'self-custody'        // the account's own balance
  | 'asa-holdings'        // fungible/NFT balances held
  | 'asa-manager'         // can reconfigure an asset
  | 'asa-clawback'        // can seize the asset from ANY holder
  | 'asa-freeze'          // can freeze the asset for ANY holder
  | 'asa-reserve'         // named as the reserve for an asset
  | 'app-creator'         // created an application: a reference, permissions unverified
  | 'app-admin'           // stored in an app's global state: a reference, permissions unverified
  | 'controls-account'    // another account is rekeyed to this one
  | 'rekeyed-away'        // this account's authority lives elsewhere
  | 'classical-multisig'  // authority is a multisig of Ed25519 keys
  | 'authority-unproven'  // authority is hash-derived but unidentified
  | 'already-pq'          // authority is proven post-quantum
  | 'closeout-reverts';   // a close-out would undo the migration

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  kind: FindingKind;
  severity: Severity;
  title: string;
  detail: string;
  /** Value under this key's control, in microAlgos, when quantifiable. */
  microAlgos?: bigint;
  /** Asset ids implicated. */
  assetIds?: bigint[];
  /** Application ids implicated. */
  appIds?: bigint[];
  /** Other accounts implicated. */
  accounts?: string[];
  /** True when the exposure extends to assets other people hold. */
  thirdParty?: boolean;
  /** Whether a single rekey of this account resolves the finding. */
  fixedByRekey: boolean;
}

/** An edge in the authority graph. */
export interface AuthorityEdge {
  from: string;
  to: string;
  relation: FindingKind;
  label: string;
  /** Asset or app id behind the edge, when relevant. */
  refId?: bigint;
  /**
   * `capability`: a power the ledger establishes - an asset role, signing
   * for an account rekeyed here, or the authority over this account.
   * `reference`: an application this address created or is named in, whose
   * permissions are unverified because Falconer does not analyse programs.
   */
  basis: 'capability' | 'reference';
  /**
   * For a capability: whether the key exercising it is established as
   * post-quantum on a provider-confirmed record.
   */
  protected?: boolean;
}

/**
 * This address found stored in an application's global state.
 *
 * Applications often keep an admin or treasury address in state and gate
 * calls on it, so the address may carry power over an app it did not create.
 * Whether it does depends on the program, which Falconer does not analyse:
 * what is established is that the address is there, so this is a reference
 * and its permissions are unverified.
 */
export interface AppAdminRole {
  appId: bigint;
  /** The global-state key holding this address, decoded when printable. */
  key: string;
  /** True when this account also created the application. */
  createdByThisAccount: boolean;
  /** Never established without program analysis. */
  permission: 'unverified';
}

export interface AssetRoleSummary {
  assetId: bigint;
  name?: string;
  unitName?: string;
  total: bigint;
  decimals: number;
  roles: Array<'manager' | 'reserve' | 'freeze' | 'clawback'>;
  /** Number of accounts holding this asset, when known. */
  holders?: number;
  /** Whether the asset is frozen by default. */
  defaultFrozen?: boolean;
}

/**
 * What the search for non-creator asset roles actually covered.
 *
 * Indexer cannot filter assets by manager, clawback or freeze, and role
 * addresses are not indexed as participants in the transaction that grants
 * them, so there is no query for "assets where this account is clawback".
 * The only exhaustive method is sweeping every asset on the ledger, which is
 * not feasible against MainNet. A report therefore has to say what it looked
 * at, or a clean result reads as "nothing found" when it means "barely
 * looked".
 */
export interface RoleScanCoverage {
  /** Assets whose parameters were successfully read. Attempts that failed do not count. */
  assetsExamined: number;
  /** Applications whose global state was successfully read. */
  appsExamined: number;
  /** Assets the account holds that were read exactly. */
  optedInChecked: number;
  /** Assets named explicitly by the caller and read exactly. */
  explicitChecked: number;
  /** Assets read from the ledger sweep, which is a sample, not a census. */
  sampled: number;
  /**
   * True when an asset or application check fell short of its declared
   * scope: a read failed or came back malformed, a cap left ids unread, or a
   * requested ledger sample could not run or stopped early. A sample that
   * read its full limit is complete for its scope; `coverage.assets.sample`
   * says whether it reached the end of the ledger.
   */
  incomplete: boolean;
  /** Plain statement of what was and was not covered. */
  detail: string;
}

/** How far one check got, against the scope it declared. */
export type CoverageStatus =
  /** Finished everything it set out to read, within its declared scope. */
  | 'complete'
  /**
   * Stopped short: at a result or request cap with more remaining, or after
   * a later request failed. What was read is kept.
   */
  | 'partial'
  /** Could not run: no provider, or the provider failed before answering. */
  | 'unavailable'
  /** The provider answered with something that is not a usable result. */
  | 'invalid-response'
  /** Deliberately not run, because it was not asked for. */
  | 'not-requested';

/** One check: how far it got, what it covered, and why it stopped. */
export interface CoverageCheck {
  status: CoverageStatus;
  /** What was covered and what was not, in plain words. */
  detail: string;
  /** Short, sanitised reasons for failures and malformed responses. */
  errors: string[];
}

/** Exact reads of ids, assets or applications, counted by outcome. */
export interface IdReadTally {
  /** Distinct ids this check set out to read. */
  requested: number;
  /** Ids actually requested from the provider; the rest were skipped at a cap. */
  attempted: number;
  /** Reads that returned a usable record. */
  read: number;
  /** Ids the provider answered do not exist (HTTP 404): an established absence. */
  notFound: number;
  /** Reads that failed or timed out. Never evidence of absence. */
  failed: number;
  /** Reads that returned an unusable record. Never evidence of absence. */
  invalid: number;
}

/** The search for accounts rekeyed to this address. */
export interface IncomingCoverage extends CoverageCheck {
  /** Distinct accounts found. */
  found: number;
  /** The most distinct accounts one scan reads. */
  limit: number;
  /** Requests made, and the most one scan makes. */
  requests: number;
  requestLimit: number;
  /** Records repeated across pages, dropped so no balance is counted twice. */
  duplicates: number;
  /** Of `found`, accounts whose own signing authority could not be checked. */
  authorityUnchecked: number;
  /**
   * True when the search reached the end of the provider's results, so
   * `found` is every such account the provider knows of, not a lower bound.
   */
  exhausted: boolean;
}

/** The optional ledger sweep for asset roles, which is a sample, never a census. */
export interface SampleCoverage extends CoverageCheck {
  /** Distinct assets the sample was allowed to read. */
  limit: number;
  /** Distinct assets read and examined; never more than `limit`. */
  read: number;
  /** Requests made, and the most this sample makes. */
  requests: number;
  requestLimit: number;
  /** Records repeated across pages, dropped so no asset is counted twice. */
  duplicates: number;
  /**
   * True only when the sweep read every asset up to the end of the ledger's
   * asset list, so no asset the provider serves went unexamined.
   */
  exhaustive: boolean;
}

/**
 * What a scan read, check by check. Every verdict is only as complete as
 * this: a check that fell short keeps the verdict from being clean, and no
 * combination of complete checks is a census of the whole ledger.
 */
export interface ExposureCoverage {
  /**
   * The search of this account's own transactions for evidence of what
   * signs for it. A view of `authority.evidence`, not a second verdict.
   */
  history: CoverageCheck;
  /** The search for accounts rekeyed to this address, and what signs for them. */
  incoming: IncomingCoverage;
  /**
   * Asset roles. Assets held and assets named are read exactly; others only
   * by the optional ledger sample.
   */
  assets: CoverageCheck & {
    held: IdReadTally;
    named: IdReadTally;
    sample: SampleCoverage;
  };
  /** Global state of applications this account created, opted into or named. */
  apps: CoverageCheck & { reads: IdReadTally };
  /**
   * What application relationships establish. Falconer does not analyse
   * programs, so creating an application or being named in its state is a
   * reference, and its permissions stay unverified.
   */
  appPermissions: 'unverified' | 'no-references';
}

/**
 * What this address reaches beyond its own balance, as found, and whether
 * the key exercising each part is established as post-quantum.
 */
export interface Reach {
  /**
   * Assets whose units this address can seize from any holder: clawback
   * held, or manager of an asset whose clawback is live.
   */
  seize: bigint[];
  /**
   * Assets this address can freeze in any holder's account: freeze held, or
   * manager of an asset whose freeze is live.
   */
  freeze: bigint[];
  /**
   * Asset roles are exercised by transactions this account sends, under its
   * own authority. True unless that authority is established post-quantum.
   */
  assetRolesExposed: boolean;
  /** Accounts rekeyed to this address whose signing key is not established post-quantum. */
  incomingExposed: number;
  /** Accounts rekeyed to this address signed for by an established post-quantum key. */
  incomingProtected: number;
  /** Applications created or naming this address: references, never capabilities. */
  appReferences: number;
}

/**
 * An account rekeyed to the scanned address, and what actually signs for it.
 *
 * Algorand checks a transaction's signature against its sender's auth-addr
 * and never follows that address's own auth-addr. An account rekeyed to X is
 * therefore authorised by the key behind X's *address* - not by whatever X
 * has since been rekeyed to - so migrating X does not move it. Each one needs
 * its own rekey.
 */
export interface IncomingAccount {
  address: string;
  microAlgos: bigint;
  /**
   * The scanned address assessed as an authority in its own right. Never the
   * scanned account's own auth-addr: that describes a different key.
   */
  authority: AuthorityAssessment;
}

export interface AccountExposure {
  address: string;
  /** Present when the account has already been rekeyed. */
  authAddr?: string;
  /**
   * What signs for *this account*, and how well that is established. A claim
   * about this account alone: it says nothing about accounts rekeyed to it.
   */
  authority: AuthorityAssessment;
  /**
   * True only when post-quantum authority over *this account* has been
   * *proven* by a Falcon signature observed on chain. An off-curve auth-addr
   * is not sufficient. Accounts rekeyed to this address can remain classical
   * while this is true; see `incoming` and `risk.residualAccounts`.
   */
  isPostQuantum: boolean;
  /** Spendable balance in microAlgos. */
  microAlgos: bigint;
  minBalance: bigint;
  assetsHeld: number;
  appsOptedIn: number;
  createdAssets: AssetRoleSummary[];
  /**
   * Applications this account created. A reference: on Algorand creating an
   * app confers nothing by itself, and its permissions are unverified.
   */
  createdApps: bigint[];
  /** Assets where this account holds a role it did not create. */
  foreignRoles: AssetRoleSummary[];
  /** Applications whose global state names this address. References. */
  appAdminRoles: AppAdminRole[];
  /** What the asset and application checks covered. Kept for compatibility; see `coverage`. */
  roleScan: RoleScanCoverage;
  /** Accounts whose auth-addr is this account, as far as the search got. */
  controlsAccounts: string[];
  /**
   * The same accounts, each with the authority that actually signs for it.
   * `controlsAccounts` is kept for callers that only need the addresses.
   */
  incoming: IncomingAccount[];
  /**
   * How far the search for accounts rekeyed to this address got; the same
   * as `coverage.incoming.status`. Anything but `complete` means the
   * accounts found are not all there are, and an empty list is not "none".
   */
  incomingScan: Exclude<CoverageStatus, 'not-requested'>;
  /** What every check covered, and what it could not. */
  coverage: ExposureCoverage;
  /** What this address reaches beyond its own balance, as found. */
  reach: Reach;
  findings: Finding[];
  edges: AuthorityEdge[];
  /**
   * Exposure across everything this address authorises: this account, the
   * asset and application roles it holds, and the accounts rekeyed to it.
   * Distinct from `authority` and `isPostQuantum`, which describe this
   * account alone - a migrated account can still carry residual exposure
   * through accounts that did not migrate with it.
   */
  risk: RiskAssessment;
}

export interface RiskAssessment {
  /** 0 (safe) to 100 (maximum exposure). */
  score: number;
  /**
   * `unverified` means nothing that was checked is exposed, but part of what
   * this address authorises could not be checked, so no safe verdict is
   * possible. It is never used when established exposure alone places the
   * account in a real band: that band is kept, as a lower bound, and
   * `incomingUnverified` says so.
   */
  band: 'safe' | 'low' | 'elevated' | 'high' | 'critical' | 'unverified';
  /**
   * True only when every required and requested check finished within its
   * declared scope and no application permission was left unverified. Only
   * then can the band be `safe`; otherwise an established band is a lower
   * bound. Never a claim about checks nobody asked for: roles on assets and
   * applications outside the scan stay a stated scope limit.
   */
  complete: boolean;
  /** Why the verdict is not complete, one short phrase each. Empty when complete. */
  uncertainties: string[];
  /** Own funds directly at risk. */
  directMicroAlgos: bigint;
  /**
   * Whether this address reaches beyond its own account at all: asset roles
   * over other holders, or accounts rekeyed to it. True whether or not the
   * key behind that reach is exposed, so it is not an alert on its own; see
   * `AccountExposure.reach` and `describeReach` for what was found.
   */
  systemic: boolean;
  /** Count of distinct third parties whose assets this key can seize. */
  thirdPartyAssets: number;
  /**
   * Accounts rekeyed to this address whose authority is not proven
   * post-quantum, and their combined balance - a subset of the value in
   * `directMicroAlgos`, never added to it again. This exposure does not
   * depend on this account's own authority, so migrating this account does
   * not reduce it: each of these accounts needs its own rekey.
   */
  residualAccounts: number;
  residualMicroAlgos: bigint;
  /**
   * The search for accounts rekeyed to this address did not complete, or
   * what signs for some of them could not be checked, so the score covers
   * only what was established and is a lower bound. Nothing is invented for
   * the unchecked part: `residualAccounts` and `residualMicroAlgos` count
   * only accounts actually found.
   */
  incomingUnverified: boolean;
  summary: string;
}

export interface MigrationPlan {
  address: string;
  targetAuthAddr: string;
  /** Ordered steps required to complete the migration. */
  steps: MigrationStep[];
  /**
   * Every network fee of the migration in microAlgos, from `budget`. Null
   * when no budget could be priced. The transfer to the new address is not a
   * fee and is not in it.
   */
  estimatedFeeMicroAlgos: bigint | null;
  /**
   * One Falcon-signed zero-value payment from the migrated account, at the
   * parameters the budget read. Not a fixed price: it follows the network's
   * minimum fee and, under congestion, the transaction's size. Null without
   * a budget.
   */
  postMigrationFeeMicroAlgos: bigint | null;
  /** What each step costs, who pays, and what each address keeps. */
  budget: MigrationBudget;
  warnings: string[];
  blockers: string[];
}

export interface MigrationStep {
  index: number;
  kind: 'rekey' | 'fund' | 'verify' | 'manual';
  title: string;
  detail: string;
  /** Null when no budget could be priced. */
  feeMicroAlgos: bigint | null;
}

export interface NetworkConfig {
  name: 'mainnet' | 'testnet' | 'localnet' | 'custom';
  algodUrl: string;
  algodToken: string;
  indexerUrl?: string;
  indexerToken?: string;
}
