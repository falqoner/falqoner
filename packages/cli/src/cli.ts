/**
 * Falconer CLI.
 *
 * Treasury operators live in terminals and CI, not dashboards. Everything the
 * web app can do to inspect an account is available here, plus JSON output so
 * quantum exposure can be asserted on in a pipeline.
 *
 * Inspection is read-only on every network, MainNet included: `scan`, `plan`,
 * `verify` and `inspect` never load a key or recovery phrase, sign, or submit
 * a transaction. `keygen` is the one command that produces a secret, and it
 * says so. There is no migrate command.
 *
 * Nothing here runs on import, so dispatch and option parsing can be tested
 * in-process. `index.ts` is the executable.
 */
import { parseArgs } from 'node:util';
import {
  analyzeAccount,
  clientsFor,
  generatePqIdentity,
  planMigration,
  planProblem,
  preflight,
  formatAlgos,
  classifyAddressShape,
  quoteMigration,
  signerFromAuthority,
  type MigrationBudget,
  riskVerdict,
  authorityVerdict,
  describeEvidence,
  describeReach,
  coverageLines,
  SCORE_SCOPE,
  type AccountExposure,
  type AuthorityAssessment,
  type AuthorityVerdict,
  type CoverageLine,
  type Finding,
} from '@falqoner/core';

/* ---------------------------------------------------------------- */

// NO_COLOR always wins. FORCE_COLOR lets a recorder or a CI log keep the
// colour a bare pipe would otherwise strip, and FORCE_COLOR=0 or false turns
// it off, as it does for Node. Each stream is decided on its own, so stderr
// redirected to a file gets plain text even when stdout is a terminal.
const force = process.env.FORCE_COLOR;
const colorOn = (stream: NodeJS.WriteStream) =>
  !process.env.NO_COLOR &&
  process.env.TERM !== 'dumb' &&
  (force === undefined ? !!stream.isTTY : force !== '0' && force !== 'false');
const useColor = colorOn(process.stdout);
const errColor = colorOn(process.stderr);
const c = (code: string) => (s: string) =>
  useColor ? `\u001b[${code}m${s}\u001b[0m` : s;

/** A notice on stderr, plain unless stderr itself may carry colour. */
function warn(s: string): void {
  console.error(errColor ? s : s.replace(/\u001b\[[0-9;]*m/g, ''));
}

const bold = c('1');
const dim = c('2');
const red = c('31');
const yellow = c('33');
const green = c('32');
const blue = c('36');
const magenta = c('35');

const SEVERITY_STYLE: Record<Finding['severity'], (s: string) => string> = {
  critical: red,
  high: yellow,
  medium: blue,
  low: dim,
  info: green,
};

const BAND_STYLE: Record<string, (s: string) => string> = {
  critical: red,
  high: yellow,
  elevated: yellow,
  low: blue,
  safe: green,
  unverified: yellow,
};

/**
 * The risk line, from the shared verdict so a score that is incomplete or
 * only a lower bound is never printed as if it were the whole answer, and a
 * clean one never reads as more than "nothing exposed was found".
 */
function riskLine(e: AccountExposure): string {
  const band = BAND_STYLE[e.risk.band] ?? dim;
  const v = riskVerdict(e.risk);
  return `${band(bold(v.score.padStart(3)))}${dim('/100')}  ${band(v.headline)}`;
}

const STATUS_STYLE: Record<CoverageLine['status'], (s: string) => string> = {
  complete: green,
  'not-requested': dim,
  partial: yellow,
  unavailable: yellow,
  'invalid-response': yellow,
  unverified: yellow,
};

/** A coverage status as printed: words, not the JSON identifier. */
const statusText = (s: CoverageLine['status']) => s.replace('-', ' ');

/** The one line compact output gives coverage. */
function coverageSummary(e: AccountExposure): string {
  const short = coverageLines(e).filter((l) => l.blocking);
  return short.length
    ? yellow(`incomplete: ${short.map((l) => `${l.label} ${statusText(l.status)}`).join(', ')}`)
    : green('complete for the checks run');
}

/**
 * Stop the command with a usage error or a failure it cannot get past.
 * Thrown rather than exiting here: `run` prints it as one line and returns
 * exit code 1, so nothing past the failure runs and nothing tears the
 * process down mid-command.
 */
function die(message: string): never {
  throw new Error(message);
}

type NetworkName = 'mainnet' | 'testnet' | 'localnet';
function network(value: string | undefined): NetworkName {
  const n = (value ?? 'mainnet').toLowerCase();
  if (n !== 'mainnet' && n !== 'testnet' && n !== 'localnet') {
    die(`Unknown network "${value}". Use mainnet, testnet or localnet.`);
  }
  return n;
}

/** BigInt-safe JSON for pipelines. */
function toJson(value: unknown): string {
  return JSON.stringify(
    value,
    (_k, v) => (typeof v === 'bigint' ? v.toString() : v),
    2,
  );
}

/* ---------------------------------------------------------------- */

const TONE_STYLE: Record<AuthorityVerdict['tone'], (s: string) => string> = {
  'post-quantum': green,
  exposed: red,
  unproven: yellow,
};

/**
 * What signs for this account, in the shared words for its verdict, wrapped
 * and styled line by line. Being rekeyed says nothing about the kind of key:
 * an account rekeyed to a plain Ed25519 address is exactly as classical as
 * before.
 */
function ownAuthorityLines(e: AccountExposure, width: number): string[] {
  const v = authorityVerdict(e.authority);
  const via = e.authAddr ? ` via ${e.authAddr.slice(0, 12)}...` : '';
  return wrap(`${v.label}${via}`, width).map(TONE_STYLE[v.tone]);
}

/** A record the verdict rests on is evidence; one it refused is not. */
const recordName = (a: AuthorityAssessment) =>
  a.evidence.basis === 'provider-record' ? 'evidence' : 'rejected';

/**
 * Accounts rekeyed to this address, stated separately from this account's
 * own authority: they are signed for by the key behind the address, so this
 * account being post-quantum says nothing about them.
 */
function incomingLabel(e: AccountExposure): string {
  if (e.incomingScan === 'unavailable') return yellow('not checked');
  const total = e.controlsAccounts.length;
  const exposed = e.risk.residualAccounts;
  // A search that stopped early found a floor, not a count.
  const found = e.coverage.incoming.exhausted ? String(total) : `at least ${total}`;
  const unfinished = e.coverage.incoming.exhausted ? '' : yellow(', search incomplete');
  if (!total) return e.coverage.incoming.exhausted ? '0' : yellow('none found, search incomplete');
  return exposed
    ? `${red(`${found} (${exposed} not post-quantum)`)}${unfinished}`
    : `${green(`${found} (all post-quantum)`)}${unfinished}`;
}

/** What this address reaches, from the shared model, styled by exposure. */
function printReach(e: AccountExposure, width: number): void {
  const reach = describeReach(e);
  if (!reach) return;
  console.log('');
  const style = reach.exposed ? red : dim;
  const mark = reach.exposed ? red('!') : dim('-');
  for (const [i, line] of wrap(reach.text, width).entries()) {
    console.log(`  ${i ? ' ' : mark} ${style(line)}`);
  }
}

/** Every check and how far it got, from the shared coverage model. */
function printCoverage(e: AccountExposure): void {
  console.log('');
  console.log(`  ${dim('coverage')}`);
  for (const l of coverageLines(e)) {
    const status = STATUS_STYLE[l.status](statusText(l.status));
    console.log(`    ${dim(l.label.padEnd(16))} ${status}`);
    for (const line of wrap(l.detail, 66)) {
      console.log(`      ${l.blocking ? yellow(line) : dim(line)}`);
    }
  }
  console.log('');
  for (const line of wrap(SCORE_SCOPE, 70)) console.log(`    ${dim(line)}`);
}

/**
 * What the own-authority verdict rests on, in one short line for compact
 * output. The full scan's basis row and `verify --compact` print the
 * complete `describeEvidence` statement, and full `verify` prints the
 * assessment detail, which states the same basis. This keeps the same facts
 * from the same evidence model, and on any record-based verdict keeps the
 * one limit that must never be dropped: Falconer does not verify the
 * signature itself.
 */
function evidenceBrief(a: AuthorityAssessment): string {
  const e = a.evidence;
  switch (e.basis) {
    case 'provider-record':
      return (
        `${e.provider?.network ?? 'provider'} indexer record, round ` +
        `${e.confirmedRound}` +
        (e.guarantees.localAddressBinding
          ? '; address binding checked locally'
          : '') +
        '; signature not verified by Falconer'
      );
    case 'address-shape':
      return 'address shape only; account type not observed';
    case 'none':
      switch (e.lookup) {
        case 'unavailable':
          return 'not checked: transaction history could not be read';
        case 'invalid-response':
          return `not checked: malformed provider response (${e.responseFault})`;
        case 'history-limited':
          return `no acceptable record in the last ${e.lookback} transactions`;
        default:
          return e.rejected.length
            ? `no acceptable record; ${e.rejected.length} rejected`
            : 'no acceptable record found';
      }
  }
}

function residualNotice(e: AccountExposure): string | undefined {
  const n = e.risk.residualAccounts;
  if (!n) return undefined;
  // A search that stopped early found a floor, not a count.
  return (
    `${e.coverage.incoming.exhausted ? '' : 'At least '}` +
    `${n} account${n === 1 ? '' : 's'} rekeyed to this address ` +
    `${n === 1 ? 'is' : 'are'} signed for by the key behind it, not by this ` +
    "account's own authority, and migrating this account does not move " +
    `${n === 1 ? 'it. It needs' : 'them. Each needs'} its own rekey.`
  );
}

function renderExposure(
  e: AccountExposure,
  { compact = false }: { compact?: boolean } = {},
): void {
  if (compact) {
    console.log('');
    console.log(`  ${dim('account')}    ${bold(e.address)}`);
    console.log(`  ${dim('balance')}    ${formatAlgos(e.microAlgos)} ALGO`);
    for (const [i, line] of ownAuthorityLines(e, 60).entries()) {
      console.log(`  ${dim(i ? '         ' : 'authority')}  ${line}`);
    }
    // The verdict's basis, right under it: compact drops the findings and
    // summary that carry it in the full view, so it is stated here instead.
    for (const [i, line] of wrap(evidenceBrief(e.authority), 60).entries()) {
      console.log(`  ${dim(i ? '         ' : 'basis    ')}  ${dim(line)}`);
    }
    if (e.controlsAccounts.length || e.incomingScan !== 'complete') {
      console.log(`  ${dim('signs for')}  ${incomingLabel(e)}`);
    }
    console.log(`  ${dim('risk')}       ${riskLine(e)}`);
    // Compact omits the medium findings where most uncertainty lives, so
    // what the verdict does not cover is stated here instead.
    for (const [i, line] of wrap(coverageSummary(e), 60).entries()) {
      console.log(`  ${dim(i ? '         ' : 'coverage ')}  ${line}`);
    }

    const severe = e.findings.filter(
      (f) => f.severity === 'high' || f.severity === 'critical',
    );
    if (severe.length) {
      console.log('');
      console.log(`  ${bold('Findings')}`);
      for (const f of severe) {
        const style = SEVERITY_STYLE[f.severity];
        console.log(`  ${style('▲')} ${style(f.severity.padEnd(8))} ${f.title}`);
      }
    }

    printReach(e, 66);
    const residual = residualNotice(e);
    if (residual) {
      console.log('');
      for (const line of wrap(residual, 66)) console.log(`  ${yellow(line)}`);
    }
    if (!e.risk.complete) {
      console.log('');
      for (const line of wrap(`Not established: ${e.risk.uncertainties.join('; ')}. This is not a safe verdict.`, 66)) {
        console.log(`  ${yellow(line)}`);
      }
    }
    console.log('');
    return;
  }

  console.log('');
  console.log(`  ${bold(e.address)}`);
  console.log(`  ${dim('risk')}  ${riskLine(e)}`);
  // Every other block here wraps; this one ran to 155 characters and off
  // the edge of any normal terminal.
  for (const line of wrap(e.risk.summary, 70)) console.log(`  ${dim(line)}`);
  console.log('');

  // A value may wrap; its continuation lines leave the label column blank.
  const row = (label: string, lines: string[]) =>
    lines.forEach((line, i) => console.log(`  ${dim((i ? '' : label).padEnd(18))} ${line}`));
  row('balance', [`${formatAlgos(e.microAlgos)} ALGO`]);
  row('assets held', [String(e.assetsHeld)]);
  row('assets created', [String(e.createdAssets.length)]);
  row('apps created', [String(e.createdApps.length)]);
  row('app references', [
    e.reach.appReferences ? yellow(`${e.reach.appReferences} (permissions unverified)`) : '0',
  ]);
  row('own authority', ownAuthorityLines(e, 50));
  // What the own-authority verdict rests on, stated right under it.
  row('authority basis', wrap(describeEvidence(e.authority), 50).map((l) => dim(l)));
  row('signs for accounts', [incomingLabel(e)]);

  printReach(e, 70);
  const residual = residualNotice(e);
  if (residual) {
    console.log('');
    for (const line of wrap(residual, 70)) console.log(`  ${yellow(line)}`);
  }

  printCoverage(e);

  if (e.findings.length) {
    console.log('');
    console.log(`  ${bold('Findings')}`);
    for (const f of e.findings) {
      const style = SEVERITY_STYLE[f.severity];
      console.log(`  ${style('*')} ${style(f.severity.padEnd(8))} ${f.title}`);
      for (const line of wrap(f.detail, 70)) {
        console.log(`    ${dim(line)}`);
      }
    }
  }
  console.log('');
}

function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    if (line.length + w.length + 1 > width) {
      lines.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) lines.push(line);
  return lines;
}

/* ---------------------------------------------------------------- */

async function cmdScan(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      network: { type: 'string', short: 'n' },
      deep: { type: 'boolean' },
      'scan-limit': { type: 'string' },
      assets: { type: 'string' },
      apps: { type: 'string' },
      json: { type: 'boolean' },
      'fail-on': { type: 'string' },
      compact: { type: 'boolean' },
    },
  });

  const address = positionals[0];
  if (!address) die('Usage: falqoner scan <address> [--network testnet] [--deep]');

  // Checking a named list is exact and immediate, which is what an
  // operator who knows their own assets actually wants. Sweeping the
  // ledger is neither.
  const idList = (raw: string | undefined, flag: string) => {
    if (raw === undefined) return undefined;
    const ids = raw
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean);
    // A dropped or unreadable id would come back as a clean report on an
    // asset nobody looked at, so anything but a positive integer is refused.
    if (!ids.length || !ids.every((x) => /^[0-9]+$/.test(x) && BigInt(x) > 0n)) {
      die(`${flag} takes a comma-separated list of positive numeric ids.`);
    }
    return ids.map((x) => BigInt(x));
  };
  const assetIds = idList(values.assets, '--assets');
  const appIds = idList(values.apps, '--apps');
  const rawLimit = values['scan-limit'];
  if (rawLimit !== undefined && !/^[1-9][0-9]*$/.test(rawLimit.trim())) {
    die('--scan-limit takes a positive whole number of assets to sample.');
  }
  const scanLimit = rawLimit === undefined ? undefined : Number(rawLimit.trim());
  if (scanLimit !== undefined && !Number.isSafeInteger(scanLimit)) {
    die('--scan-limit is too large.');
  }

  // Refuse a bad threshold before reading anything, not after.
  const order = ['safe', 'low', 'elevated', 'high', 'critical'];
  const threshold = values['fail-on'];
  const want = threshold === undefined ? -1 : order.indexOf(threshold.toLowerCase());
  if (threshold !== undefined) {
    if (want < 0) die(`--fail-on must be one of ${order.slice(1).join(', ')}`);
    if (want === 0) {
      die(
        '--fail-on safe would fail every account, including a fully ' +
          'migrated one, because every band meets it. Use low, elevated, ' +
          'high or critical.',
      );
    }
  }

  const clients = clientsFor(network(values.network));
  const exposure = await analyzeAccount(clients, address, {
    deepScan: values.deep,
    scanLimit,
    assetIds,
    appIds,
    // Progress redraws a single line with a carriage return, which only
    // works on a terminal. Piped or captured, the messages concatenate
    // into one run-on line, so stay quiet unless someone is watching.
    onProgress:
      values.json || !process.stderr.isTTY
        ? undefined
        : (m) => process.stderr.write(`${dim(m)}\r`),
  });
  if (!values.json && process.stderr.isTTY) {
    process.stderr.write(' '.repeat(60) + '\r');
  }

  if (values.json) console.log(toJson(exposure));
  else renderExposure(exposure, { compact: values.compact });

  // Let CI gate on exposure.
  if (threshold !== undefined) {
    // Established exposure at or over the threshold fails the gate on its
    // own: an incomplete verdict is a lower bound, never an overstatement.
    if (order.indexOf(exposure.risk.band) >= want) {
      warn(
        red(
          `Exposure ${exposure.risk.band}${exposure.risk.complete ? '' : ' (at least)'} ` +
            `meets or exceeds ${threshold}.`,
        ),
      );
      return 2;
    }
    // Fail closed. An incomplete verdict cannot show exposure is below any
    // threshold, and `unverified` has no place in the ordering: indexOf
    // would return -1 and quietly pass the gate. Checks nobody asked for,
    // such as a ledger sample, are a stated scope limit and do not count.
    if (!exposure.risk.complete) {
      warn(
        red(
          `Exposure could not be evaluated against ${threshold}: ` +
            `${exposure.risk.uncertainties.join('; ')}.`,
        ),
      );
      return 2;
    }
  }
  return 0;
}

/**
 * Printed to stderr by `keygen --json`, whose stdout carries the phrase. The
 * warning stays out of the JSON, so it remains parseable, and the secret stays
 * out of the warning.
 */
const KEYGEN_JSON_NOTICE =
  'The JSON on stdout contains the recovery phrase for this account. ' +
  'Anyone who reads it controls the account: keep it out of logs, CI ' +
  'output and shared terminals.';

/**
 * The only honest advice about a phrase nothing can check (SAFE-01, PQ-03):
 * the CLI has no command that reads one back, and the web app checks only
 * the key it generated itself.
 */
const KEYGEN_UNCHECKED =
  'the CLI has no command that reads a phrase back, and the web app checks ' +
  'only a key it generates itself. Use this address as a planning target ' +
  '(falqoner plan --to reads only), and rekey nothing to it unless you can ' +
  'reproduce the key from what you wrote down.';

async function cmdKeygen(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean' } },
  });

  const identity = generatePqIdentity();
  // No transcription exists yet at keygen time, so preflight is called
  // without one. Passing identity.mnemonic here would re-derive the string
  // that is about to be printed and always pass, which proves nothing about
  // what ends up written down.
  const checks = preflight(identity);
  if (!checks.ok) die('Generated key failed its own pre-flight checks.');

  if (values.json) {
    warn(`${yellow('secret')}  ${KEYGEN_JSON_NOTICE}`);
    console.log(
      toJson({
        address: identity.address,
        salt: identity.salt,
        mnemonic: identity.mnemonic,
        scheme: 'falcon-1024',
      }),
    );
    return 0;
  }

  console.log('');
  console.log(`  ${bold('Falcon-1024 post-quantum account')}`);
  console.log('');
  console.log(`  ${dim('address')}   ${bold(identity.address)}`);
  console.log(`  ${dim('salt')}      ${identity.salt}`);
  console.log(
    `  ${dim('key size')}  ${identity.publicKey.length} byte public / ${identity.privateKey.length} byte private`,
  );
  console.log('');
  console.log(`  ${bold('Recovery phrase')} ${dim('(25 words, secret)')}`);
  console.log('');
  const words = identity.mnemonic!.split(' ');
  for (let i = 0; i < words.length; i += 5) {
    const row = words
      .slice(i, i + 5)
      .map((w, j) => `${dim(String(i + j + 1).padStart(2))} ${w.padEnd(9)}`)
      .join('');
    console.log(`    ${row}`);
  }
  console.log('');
  console.log(
    `  ${yellow('This phrase is the only way to recover the account.')}`,
  );
  console.log(
    `  ${dim('The 2305-byte Falcon private key is re-derived from it, so the')}`,
  );
  console.log(`  ${dim('phrase alone is a complete backup. Nothing else is.')}`);
  console.log(
    `  ${yellow('Anyone who reads it controls the account.')} ${dim('Keep it out of')}`,
  );
  console.log(`  ${dim('logs, CI output, screenshots and shared terminals.')}`);
  console.log('');
  // preflight ran without a transcription, so the phrase check was reported
  // as not performed. Saying so is the point: nothing here has seen what
  // the operator actually wrote down, and no Falconer command can.
  console.log(`  ${yellow('Nothing has checked what you wrote down, and Falconer cannot:')}`);
  for (const line of wrap(KEYGEN_UNCHECKED, 66)) console.log(`  ${dim(line)}`);
  console.log('');
  return 0;
}

async function cmdPlan(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      network: { type: 'string', short: 'n' },
      to: { type: 'string' },
      json: { type: 'boolean' },
      'no-drill': { type: 'boolean' },
    },
  });

  const address = positionals[0];
  if (!address) die('Usage: falqoner plan <address> --to <pq-address>');
  if (!values.to) die('Missing --to <pq-address>. Generate one with: falqoner keygen');
  // Refused before anything is read, like every other malformed argument. A
  // valid target that cannot hold post-quantum authority is the plan's
  // blocker to report, not a usage error.
  if (classifyAddressShape(values.to) === 'invalid') {
    die(`--to is not a valid Algorand address: ${values.to}`);
  }

  const clients = clientsFor(network(values.network));
  const exposure = await analyzeAccount(clients, address);
  const drill = !values['no-drill'];
  const authorizer = exposure.authAddr ?? exposure.address;
  const spec = {
    sender: exposure.address,
    authorizer,
    target: values.to,
    drill,
    signer: signerFromAuthority(exposure.authority, authorizer),
  };
  // Priced from the network's own parameters, balances and minimum balances.
  // Read-only: nothing is built that could be signed, and no key is loaded.
  const budget = await quoteMigration(clients, spec);
  const plan = planMigration(exposure, values.to, { drill, budget });
  const problem = planProblem(plan);

  if (values.json) {
    console.log(toJson(plan));
    return problem ? 2 : 0;
  }

  console.log('');
  console.log(`  ${bold('Migration plan')}`);
  console.log(`  ${dim('account')}  ${plan.address}`);
  console.log(`  ${dim('to')}       ${plan.targetAuthAddr}`);
  console.log('');
  for (const step of plan.steps) {
    console.log(`  ${magenta(String(step.index))}. ${bold(step.title)}`);
    for (const line of wrap(step.detail, 70)) console.log(`     ${dim(line)}`);
  }
  renderBudget(plan.budget, plan.address, plan.targetAuthAddr);

  for (const w of plan.warnings) {
    console.log('');
    console.log(`  ${yellow('note')}  ${wrap(w, 68).join('\n        ')}`);
  }
  for (const b of plan.blockers) {
    console.log('');
    console.log(`  ${red('blocked')}  ${wrap(b, 66).join('\n           ')}`);
  }
  if (plan.budget.status === 'unavailable') {
    console.log('');
    console.log(`  ${red('no budget')}  ${wrap(plan.budget.problems.join(' '), 64).join('\n             ')}`);
  }
  console.log('');
  return problem ? 2 : 0;
}

const STEP_NAME: Record<string, string> = {
  funding: 'fund the new address',
  proof: 'prove its key',
  rekey: 'rekey',
  verification: 'verify',
};

/**
 * The budget, as the shared model computed it. The same figures are in the
 * JSON under `budget`; nothing here computes one of its own.
 */
function renderBudget(b: MigrationBudget, account: string, target: string): void {
  const algos = (m: bigint) => `${formatAlgos(m)} ALGO`;
  const who = (a: string) => (a === account ? 'account' : a === target ? 'new address' : a.slice(0, 10));
  console.log('');
  const status = b.status === 'available' ? green(b.status) : b.status === 'blocked' ? red(b.status) : yellow(b.status);
  console.log(`  ${bold('Budget')}  ${status}`);
  if (b.stages.length) {
    for (const s of b.stages) {
      console.log(
        `  ${dim(STEP_NAME[s.stage]!.padEnd(21))}` +
          `${dim('paid by')} ${who(s.sender).padEnd(12)}` +
          `${dim('sends')} ${algos(s.amount).padEnd(14)}` +
          `${dim('fee')} ${algos(s.fee)}`,
      );
    }
  }
  const t = b.totals;
  if (t && b.source && b.target) {
    console.log(`  ${dim('fees')}            ${algos(t.feeExpense)}: the account ${algos(t.sourceFees)}, the new address ${algos(t.targetProofExpense)}`);
    console.log(`  ${dim('account pays')}    ${algos(t.sourceDebit)} (sends ${algos(t.transfer)}, fees ${algos(t.sourceFees)}); keeps ${algos(t.sourceRetained)} of ${algos(b.source.balance)}, minimum ${algos(b.source.minBalance)}`);
    console.log(`  ${dim('new address')}     keeps ${algos(t.targetRetained)}, minimum ${algos(b.target.minBalance)}${t.reserve ? `, reserve ${algos(t.reserve)}` : ''}; movable only with its 25 words`);
  }
  if (b.postMigrationFee !== null) {
    console.log(`  ${dim('afterwards')}      ${algos(b.postMigrationFee)} for a Falcon-signed zero-value payment, at these parameters`);
  }
  if (b.observed) {
    console.log(`  ${dim('read')}            round ${b.observed.round} on ${b.observed.genesis.id}, consensus ${b.observed.rules}; usable until round ${b.observed.validThroughRound}`);
  }
  for (const a of b.assumptions) {
    for (const [i, line] of wrap(a, 66).entries()) console.log(`  ${dim(i ? '    ' : '  - ')}${dim(line)}`);
  }
}

/**
 * `verify --mnemonic-env VAR` used to read a Falcon recovery phrase from the
 * environment and send a Falcon-signed transaction to prove control, on
 * whichever network it was pointed at, default MainNet included. That path
 * is gone, and the option is refused by name before anything else runs: no
 * environment variable is read and no provider is contacted. The value given
 * is never echoed either. It names a variable that holds a phrase, and a
 * mistaken invocation could pass the phrase itself.
 */
const MNEMONIC_ENV_REMOVED =
  'verify no longer accepts --mnemonic-env. verify is read-only: it reports ' +
  "what the provider's records establish about the account's authority, and " +
  'never loads a recovery phrase, signs or submits a transaction.';

function refuseRemovedOptions(argv: string[]): void {
  // A lenient pass declaring no options sees every option-like token by
  // name, in every spelling: `--mnemonic-env VAR`, `--mnemonic-env=VAR`, or
  // with the value missing. Anything after `--` stays a positional, as it
  // does in the strict parse that follows.
  const { tokens } = parseArgs({
    args: argv,
    strict: false,
    allowPositionals: true,
    tokens: true,
  });
  if (tokens.some((t) => t.kind === 'option' && t.name === 'mnemonic-env')) {
    die(MNEMONIC_ENV_REMOVED);
  }
}

async function cmdVerify(argv: string[]): Promise<number> {
  refuseRemovedOptions(argv);
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      network: { type: 'string', short: 'n' },
      json: { type: 'boolean' },
      compact: { type: 'boolean' },
    },
  });

  const address = positionals[0];
  if (!address) die('Usage: falqoner verify <address> [-n network] [--compact] [--json]');
  const clients = clientsFor(network(values.network));

  // Report what the ledger alone establishes. The label must track the
  // evidence, not the shape of the address.
  const exposure = await analyzeAccount(clients, address);
  const a = exposure.authority;
  const result = {
    address,
    authAddr: a.authAddr ?? null,
    authorityClass: a.authorityClass,
    quantumSafe: a.quantumSafe,
    proven: a.proven,
    // What the verdict rests on, and which guarantees back it. The
    // signature bytes are never verified locally, and this says so.
    basis: a.evidence.basis,
    evidence: a.evidence,
    evidenceUnavailable: a.evidenceUnavailable ?? false,
    evidenceTxId: a.evidenceTxId ?? null,
    note: a.detail,
  };
  // The verdict and exit code describe this account's own authority only.
  // Accounts rekeyed to this address are signed for by a different key, so
  // they are reported alongside, never folded into the pass.
  const residual = residualNotice(exposure);
  if (values.json) console.log(toJson(result));
  else if (values.compact) {
    console.log('');
    console.log(`  ${dim('account')}    ${address}`);
    for (const [i, line] of ownAuthorityLines(exposure, 60).entries()) {
      console.log(`  ${dim(i ? '         ' : 'authority')}  ${line}`);
    }
    if (a.evidenceTxId) {
      console.log(`  ${dim(recordName(a).padEnd(11))}tx/${a.evidenceTxId.slice(0, 36)}...`);
    }
    console.log(
      `  ${dim('verdict')}    ${
        a.quantumSafe
          ? green('✔ post-quantum, on a provider-confirmed record')
          : red('✖ not established as post-quantum')
      }`,
    );
    for (const [i, line] of wrap(describeEvidence(a), 62).entries()) {
      console.log(`  ${dim(i ? '         ' : 'basis    ')}  ${dim(line)}`);
    }
    if (residual) {
      for (const line of wrap(residual, 66)) console.log(`  ${yellow(line)}`);
    }
    console.log('');
  } else {
    console.log('');
    console.log(`  ${bold(address)}`);
    for (const line of ownAuthorityLines(exposure, 70)) console.log(`  ${line}`);
    for (const line of wrap(a.detail, 70)) console.log(`  ${line}`);
    // The detail above already states the evidence basis and, for a
    // record-based verdict, the signature-verification limit; compact and
    // JSON, which omit it, carry the basis instead.
    if (a.evidenceTxId) console.log(`  ${dim(recordName(a))}  ${a.evidenceTxId}`);
    if (residual) {
      console.log('');
      for (const line of wrap(residual, 70)) console.log(`  ${yellow(line)}`);
    }
    console.log('');
  }
  // Only post-quantum authority established by a provider record passes.
  return a.quantumSafe ? 0 : 2;
}

function cmdInspect(argv: string[]): number {
  const address = argv[0];
  if (!address) die('Usage: falqoner inspect <address>');
  // A string that does not decode is not an on-curve address. Reporting it
  // as "a valid Ed25519 point" states something about a value that was
  // never a value.
  const shape = classifyAddressShape(address);
  if (shape === 'invalid') {
    die(`Not a valid Algorand address: ${address}`);
  }
  const offCurve = shape === 'off-curve';
  console.log('');
  console.log(`  ${bold(address)}`);
  // Neither shape is a verdict. Off the curve rules out a bare Ed25519 key
  // and nothing more: a multisig is hash-derived too.
  console.log(`  ${yellow(offCurve ? 'off-curve' : 'on-curve')}`);
  for (const line of wrap(
    offCurve
      ? 'hash-derived: a post-quantum, multisig, logic-signature or ' +
          'application address, and the shape cannot tell which. Run verify ' +
          'for what the records establish.'
      : 'a valid Ed25519 point, so a classical private key may control it',
    70,
  )) {
    console.log(`  ${dim(line)}`);
  }
  console.log('');
  return 0;
}

/* ---------------------------------------------------------------- */

const USAGE = `
  ${bold('falqoner')} ${dim('- post-quantum readiness for Algorand')}

  Read-only on every network, MainNet included: these commands never load
  a key or recovery phrase, sign, or submit a transaction.

  ${bold('scan')}    <address> [-n network] [--assets ids] [--apps ids] [--deep]
          [--scan-limit n] [--compact] [--json] [--fail-on band]
          Map what a key controls and score the exposure, stating
          what each check covered. Roles on assets the account
          created or holds are found exactly; apps it created,
          opted into or named are read, and a match there is a
          reference with unverified permissions. --assets 31566704
          and --apps 1234 check named ids exactly. --deep also
          samples the ledger, which is never a census and says so.
          --fail-on exits 2 at the band, and whenever an incomplete
          check means the band cannot be evaluated. Scores are a
          heuristic for the checks listed, not a certification.

  ${bold('plan')}    <address> --to <pq-address> [-n network] [--no-drill] [--json]
          Show the migration steps and blockers, and a budget priced
          from the network's fees, balances and minimum balances:
          each step's fee and payer, the transfer, and what each
          address keeps. Reads only; sends nothing.

  ${bold('verify')}  <address> [-n network] [--compact] [--json]
          Report what the provider's records establish about the
          account's own authority. Accounts rekeyed to it are
          reported beside the verdict, never folded into it.

  ${bold('inspect')} <address>
          Report whether an address is on or off the Ed25519 curve,
          which is never a verdict. Works offline.

  Secret output:

  ${bold('keygen')}  [--json]
          Create a Falcon-1024 account and print its recovery phrase,
          in both formats. Anyone who reads the output controls the
          account: keep it out of logs, CI and shared terminals.
          No Falconer command can check a written-down phrase.

  There is no migrate command. The web app migrates on TestNet and
  LocalNet, handling recovery phrases in the page. On MainNet, sign the
  rekey in a wallet you trust.

  --json prints JSON alone on stdout and overrides --compact; notices
  go to stderr. NO_COLOR turns colour off, FORCE_COLOR keeps it when
  piped.

  ${bold('Exit codes')}
    scan     0  printed; without --fail-on, whatever it found
             2  --fail-on met, or not evaluable on an incomplete verdict
    verify   0  post-quantum authority on a confirmed Falcon-1024 record
             2  anything else: a classical key or multisig, a logic
                signature, no record or only rejected ones, or history
                that could not be read
    plan     0  no blockers, and a budget priced from the network
             2  blocked, or no budget could be priced
    inspect, keygen, help
             0  printed
    any      1  usage error, or a failure it could not get past, such as
                an account that could not be read; nothing was judged

  ${dim('Networks: mainnet (default), testnet, localnet')}
`;

/**
 * Run one command line (without the node and script arguments) and return
 * its exit code, as the usage text's table states:
 *
 * - 0: `scan` printed its report and, with `--fail-on`, stayed under it on a
 *   complete verdict; `verify` established post-quantum authority on a
 *   provider record; `plan` found no blockers and priced an available
 *   budget; `inspect`, `keygen` and `help` printed.
 * - 1: a usage error (unknown command or option, a missing or invalid
 *   argument, the removed `--mnemonic-env`) or a failure the command could
 *   not get past, such as an account read the provider refused.
 * - 2: a verdict CI can gate on. `verify` did not establish post-quantum
 *   authority, whether the evidence is classical, unconfirmed, rejected,
 *   malformed or unavailable. `plan` has blockers, or its budget is blocked
 *   or could not be priced. `scan` met its `--fail-on` threshold or could
 *   not evaluate exposure against it.
 */
export async function run(argv: string[]): Promise<number> {
  try {
    return await dispatch(argv);
  } catch (err: any) {
    warn(`${red('error')}  ${String(err?.message ?? err)}`);
    return 1;
  }
}

async function dispatch(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case 'scan':
      return cmdScan(rest);
    case 'keygen':
      return cmdKeygen(rest);
    case 'plan':
      return cmdPlan(rest);
    case 'verify':
      return cmdVerify(rest);
    case 'inspect':
      return cmdInspect(rest);
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      console.log(USAGE);
      return 0;
    default:
      die(`Unknown command "${command}". Run: falqoner help`);
  }
}
