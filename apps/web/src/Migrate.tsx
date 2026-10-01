import { useEffect, useMemo, useRef, useState, type RefObject } from 'react';
import {
  exceedsApproved,
  formatAlgos,
  planMigration,
  preflight,
  type AccountExposure,
  type MigrationBudget,
} from '@falqoner/core';
import {
  STAGES,
  STAGE_LABEL,
  approvalRefusal,
  continuationOf,
  quoteFrom,
  refusal,
  stageState,
  viewOf,
  type Operation,
  type OperationCommands,
  type OperationState,
  type Stage,
} from './operation';
import { isResolved, stageStatus, type AttemptState } from './journal';

/**
 * The migration ceremony, and the one place in Falconer that handles
 * recovery material.
 *
 * Key generation happens in the page, in WebAssembly. On TestNet and LocalNet
 * the page also takes the 25-word phrase of the key that signs the rekey. The
 * Falcon private key, both phrases and the signing key never touch the
 * network or this browser's storage, and the page has no backend to send
 * them to: only signed transactions leave it. What is saved is a public
 * record of each transaction, so a reload can pick the migration up again.
 *
 * The operation itself belongs to `App` (see `operation.ts`), so this panel
 * can re-render or remount without losing it. The panel only holds what is
 * being typed, and every command it sends is checked again by the operation.
 */
export function Migrate({
  exposure,
  operation,
  commands,
  completedTarget,
  headingRef,
  onGenerate,
  onDismiss,
}: {
  /** The latest scan of the account on screen. Used only before a key exists. */
  exposure: AccountExposure | null;
  operation: OperationState;
  commands: OperationCommands;
  /** This account was migrated to that address earlier in this session. */
  completedTarget: string | null;
  /** The heading of the panel shown before a key exists, where focus goes after a dismissal. */
  headingRef: RefObject<HTMLHeadingElement>;
  onGenerate: () => void;
  onDismiss: (acknowledged: boolean) => void;
}) {
  if (operation.status === 'idle') {
    if (!exposure) return null;
    return (
      <Intro
        exposure={exposure}
        completedTarget={completedTarget}
        headingRef={headingRef}
        blocked={commands.journalProblem()}
        onGenerate={onGenerate}
      />
    );
  }
  return (
    <Ceremony op={operation} commands={commands} onGenerate={onGenerate} onDismiss={onDismiss} />
  );
}

function Intro({
  exposure,
  completedTarget,
  headingRef,
  blocked,
  onGenerate,
}: {
  exposure: AccountExposure;
  completedTarget: string | null;
  headingRef: RefObject<HTMLHeadingElement>;
  blocked: string | null;
  onGenerate: () => void;
}) {
  if (completedTarget) {
    // Indexer may not show the new authority yet, but this page rekeyed the
    // account itself. Offering another key here would invite a second
    // migration of an account that has just been migrated.
    return (
      <div className="panel">
        <h2 ref={headingRef} tabIndex={-1}>Migration</h2>
        <p className="dim">
          This account was migrated to {completedTarget} earlier in this
          session, and its recovery words were acknowledged and removed from
          this page. There is nothing more to do here for this account.
        </p>
      </div>
    );
  }

  if (exposure.isPostQuantum) {
    return (
      <div className="panel">
        <h2 ref={headingRef} tabIndex={-1}>Migration</h2>
        <p className="dim">
          This account is already under post-quantum authority, on a
          provider-confirmed record. There is nothing to migrate for this
          account.
        </p>
        {exposure.risk.residualAccounts > 0 && (
          <div className="callout danger">
            {exposure.risk.residualAccounts} account
            {exposure.risk.residualAccounts === 1 ? '' : 's'} rekeyed to this
            address {exposure.risk.residualAccounts === 1 ? 'is' : 'are'} not
            covered by that. {exposure.risk.residualAccounts === 1 ? 'It is' : 'They are'}{' '}
            signed for by the key behind this address, not by its post-quantum
            authority, so keep that key: each needs its own rekey, signed by
            it. Falconer does not migrate other accounts on this
            account&rsquo;s behalf.
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="panel">
      <h2 ref={headingRef} tabIndex={-1}>Migration</h2>
      <p className="dim" style={{ marginTop: 8 }}>
        A migration is one rekey transaction. The address does not change,
        so every asset opt-in, application state and role this address
        holds carries over untouched.
      </p>
      <div className="callout warn" data-experimental>
        Migration from this page is experimental, and Falconer has not been
        externally audited: try the migration on TestNet first.
      </div>
      <div className="callout">
        The Falcon-1024 key and its recovery phrase are generated here, in
        this page, using WebAssembly. Migrating on TestNet or LocalNet also
        asks for the 25-word phrase of the key that signs the rekey. Both
        stay in this page&rsquo;s memory and are never transmitted or saved
        &mdash; there is no server to transmit them to. Only signed
        transactions are sent, and a public record of each is kept in this
        browser so a reload can finish the migration.
      </div>
      {blocked ? (
        <p className="dim" data-blocked>
          No new migration can start from this page until the saved record
          above is dealt with.
        </p>
      ) : (
        <button onClick={onGenerate}>Generate a post-quantum key</button>
      )}
    </div>
  );
}

const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;

function Ceremony({
  op,
  commands,
  onGenerate,
  onDismiss,
}: {
  op: Operation;
  commands: OperationCommands;
  onGenerate: () => void;
  onDismiss: (acknowledged: boolean) => void;
}) {
  // Everything below reads the operation's own context, never the latest
  // scan: a refresh after the rekey must not change what is shown here.
  const { plan: basePlan, sender, authorizer, network, targetAddress, exposure } = op.context;
  // The plan as priced by the budget that covers every step: the one on
  // screen, or once steps have run, the one this run was approved on.
  const fullBudget =
    op.quote?.spec.from === 'funding' ? op.quote : op.approved?.spec.from === 'funding' ? op.approved : null;
  const plan = useMemo(
    () => (basePlan && exposure && fullBudget ? planMigration(exposure, targetAddress, { budget: fullBudget }) : basePlan),
    [basePlan, exposure, targetAddress, fullBudget],
  );
  const identity = op.identity;
  const canExecute = network === 'localnet' || network === 'testnet';
  const session = op.origin === 'session';

  /**
   * Where keyboard focus goes when the control that was used is disabled or
   * removed: the panel's heading for a new key, the status line for a step.
   * Tab then goes on to the controls that follow it.
   */
  const headingRef = useRef<HTMLHeadingElement>(null);
  const statusRef = useRef<HTMLParagraphElement>(null);
  const toStatus = () => statusRef.current?.focus();
  useEffect(() => {
    if (session && document.activeElement === document.body) headingRef.current?.focus();
  }, [session]);

  /** The new phrase, typed back from what the operator wrote down. */
  const [confirmPhrase, setConfirmPhrase] = useState('');
  const [signingPhrase, setSigningPhrase] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);

  /** A step has been entered, so something may have reached the network. */
  const sent = op.stage !== null || op.record !== null;
  /** Inputs can change only while nothing is running and nothing was sent. */
  const editable =
    session && !sent && !op.inFlight && (op.status === 'prepared' || op.status === 'failed');

  // The signing key has no further use once a step has been entered: the
  // operation holds the signer it needs, and nothing may start over.
  useEffect(() => {
    if (sent) setSigningPhrase('');
  }, [sent]);

  // Without a transcription this reports the phrase check as not performed.
  const initialChecks = useMemo(
    () => (session && identity ? preflight(identity) : null),
    [session, identity],
  );
  // Re-deriving a Falcon key takes long enough to be felt, so the
  // transcription is only checked once a full phrase has been typed rather
  // than on every keystroke.
  const typedWords = words(confirmPhrase);
  const confirmation = useMemo(
    () => (identity && typedWords === 25 ? preflight(identity, confirmPhrase) : null),
    [identity, confirmPhrase, typedWords],
  );
  // The rekey is irreversible, so it is gated on every check passing and on
  // the phrase actually re-deriving this address - not on the operator
  // asserting that it does. The operation checks all of it again.
  const phraseConfirmed =
    confirmation?.ok === true && confirmation.transcriptionConfirmed === true;
  // Migrating approves the budget on screen, so it must be one that can be approved.
  const budgetRefusal = approvalRefusal(op, 'funding');
  const canMigrate =
    editable &&
    canExecute &&
    plan !== null &&
    plan.blockers.length === 0 &&
    budgetRefusal === null &&
    phraseConfirmed &&
    words(signingPhrase) === 25;
  const shown = confirmation ?? initialChecks;
  const dismissRefusal = refusal(op, { type: 'dismiss', acknowledged: true });
  const dismissable = dismissRefusal === null;
  // Settled as far as the steps go, but something still stands in the way:
  // say what, rather than just not offering it.
  const view = viewOf(op);
  const dismissBlocked =
    !dismissable && !op.inFlight && view && isResolved(view) && op.status !== 'outcome-unknown' ? dismissRefusal : null;

  return (
    <div
      className="panel"
      data-operation={op.id}
      data-status={op.status}
      data-stage={op.stage ?? ''}
      data-origin={op.origin}
    >
      <h2 ref={headingRef} tabIndex={-1}>
        {session ? 'Migration' : 'Unfinished migration'}
      </h2>
      {!session && (
        <p className="dim" style={{ marginTop: 8 }} data-recovered>
          This page found a saved record of a migration of {sender} on{' '}
          {network === 'testnet' ? 'TestNet' : 'LocalNet'}, from before it
          was reloaded. What it did is read from the ledger, not from the
          record: the record only says which transactions to ask about.
        </p>
      )}
      <p className="dim" style={{ marginTop: 8 }}>
        New post-quantum address
      </p>
      <p className="mono" style={{ color: 'var(--accent)' }}>
        {targetAddress}
      </p>

      <OperationAlert op={op} />

      {session && identity ? (
        <>
          <div className="callout danger">
            These 25 words are the only backup. The 2,305-byte Falcon private
            key is re-derived from them, and nothing else can recover this
            account. If the account is rekeyed to a key you cannot reproduce,
            it is lost permanently. This page never saves them.
          </div>

          <div className="phrase" data-recovery-phrase>
            {identity.mnemonic!.split(' ').map((w, i) => (
              <div key={i}>
                <i>{i + 1}</i>
                {w}
              </div>
            ))}
          </div>
        </>
      ) : (
        <div className="callout danger" data-words-not-stored>
          The 25 words of {targetAddress} are the only way to recover this
          key, and this page never saved them.{' '}
          {identity
            ? 'They were restored from what you typed, and stay in this page’s memory only.'
            : 'Continuing needs them typed in again, from what you wrote down.'}
        </div>
      )}

      {session && !sent && (
        <>
          <p className="dim" style={{ marginTop: 16, marginBottom: 6 }}>
            Now type those 25 words back, from what you wrote down. They are
            re-derived from scratch and checked against the address above, so
            a mis-transcription fails here instead of after the account
            depends on it.
          </p>
          <textarea
            aria-label="Recovery phrase, typed back"
            rows={3}
            style={{ width: '100%' }}
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            placeholder="Type the 25 words you just wrote down"
            value={confirmPhrase}
            disabled={!editable}
            onChange={(ev) => {
              if (editable) setConfirmPhrase(ev.target.value);
            }}
          />
          {typedWords > 0 && typedWords !== 25 && (
            <p className="faint" style={{ fontSize: 13, marginTop: 4 }}>
              {typedWords} of 25 words.
            </p>
          )}
        </>
      )}

      {shown && (
        <div style={{ margin: '14px 0' }}>
          {shown.checks.map((c) => (
            <div className="check" key={c.name}>
              <span className={c.passed ? 'ok' : 'no'}>{c.passed ? '✓' : '✕'}</span>
              <span>
                <b style={{ fontWeight: 600 }}>{c.name}</b>{' '}
                <span className="faint">{c.detail}</span>
              </span>
            </div>
          ))}
        </div>
      )}

      {plan && (
        <>
          <h2 style={{ marginTop: 22 }}>Plan</h2>
          <ol className="steps">
            {plan.steps.map((s) => (
              <li className="step" key={s.index}>
                <div className="n">{s.index}</div>
                <div>
                  <h4>{s.title}</h4>
                  <p>{s.detail}</p>
                </div>
              </li>
            ))}
          </ol>
          {plan.warnings.map((w, i) => (
            <div className="callout" key={i}>
              {w}
            </div>
          ))}
          {plan.blockers.map((b, i) => (
            <div className="callout danger" key={i}>
              {b}
            </div>
          ))}
        </>
      )}

      <BudgetPanel op={op} commands={commands} />

      {(!plan || plan.blockers.length === 0) && (
        <>
          <h2 style={{ marginTop: 22 }}>Execute</h2>
          {!canExecute ? (
            <p className="dim">
              Execution from this page is limited to TestNet and LocalNet.
              On MainNet, sign the rekey in a wallet you trust, so the
              signing key never enters a browser. The{' '}
              <span className="mono">falqoner</span> CLI only inspects and
              plans: it never signs or submits.
            </p>
          ) : (
            <>
              {session && !sent && (
                <>
                  <div className="check" style={{ marginBottom: 10 }}>
                    <span className={phraseConfirmed ? 'ok' : 'no'}>
                      {phraseConfirmed ? '✓' : '✕'}
                    </span>
                    <span>
                      {phraseConfirmed
                        ? 'The phrase you typed re-derives this address. '
                        : 'Type the 25 new words back above before migrating. '}
                      <span className="faint">
                        Rekeying to a key you cannot reproduce loses the
                        account permanently.
                      </span>
                    </span>
                  </div>
                  <SigningNote network={network} sender={sender} authorizer={authorizer} />
                  <textarea
                    aria-label="Signing key phrase"
                    rows={3}
                    style={{ width: '100%', marginTop: 6 }}
                    spellCheck={false}
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    placeholder={
                      authorizer !== sender
                        ? '25-word phrase for this account’s current authority'
                        : '25-word phrase for the account being migrated'
                    }
                    value={signingPhrase}
                    disabled={!editable}
                    onChange={(ev) => {
                      if (editable) setSigningPhrase(ev.target.value);
                    }}
                  />
                  <div style={{ marginTop: 12, display: 'flex', gap: 10 }}>
                    <button
                      onClick={() => {
                        toStatus();
                        commands.execute({ transcription: confirmPhrase, signingPhrase });
                      }}
                      disabled={!canMigrate}
                    >
                      {op.inFlight && <span className="spinner" />}
                      {op.inFlight ? 'Checking…' : 'Migrate'}
                    </button>
                    <button className="ghost" onClick={onGenerate} disabled={!editable}>
                      Generate a different key
                    </button>
                  </div>
                  <p className="faint" style={{ fontSize: 13, marginTop: 8 }} data-approval>
                    {budgetRefusal && !op.quoting
                      ? `Not yet: ${budgetRefusal}`
                      : 'Migrating approves the budget above. Before each step it is read again, and a step that would cost more is not sent.'}
                  </p>
                </>
              )}

              <Progress op={op} statusRef={statusRef} />
              {sent && <Settle op={op} commands={commands} onAct={toStatus} />}
            </>
          )}
        </>
      )}

      {dismissBlocked && (
        <p className="faint" style={{ fontSize: 13, marginTop: 12 }} data-dismiss-blocked>
          Not yet dismissable: {dismissBlocked}
        </p>
      )}
      {dismissable && (
        <Dismissal
          op={op}
          acknowledged={acknowledged}
          onAcknowledge={setAcknowledged}
          onDismiss={() => onDismiss(acknowledged)}
        />
      )}

      {op.error && (
        <div className="err" style={{ marginTop: 14 }} data-error>
          {op.error}
        </div>
      )}
    </div>
  );
}

function SigningNote({ network, sender, authorizer }: { network: string; sender: string; authorizer: string }) {
  return (
    <p className="faint" style={{ fontSize: 13 }}>
      {network === 'testnet' ? 'TestNet' : 'LocalNet'} signing key for{' '}
      {authorizer.slice(0, 10)}&hellip; (25-word phrase)
      {authorizer !== sender ? ', the authority this account is already rekeyed to' : ''}
      . Test networks only &mdash; never paste a MainNet phrase into a web
      page. It is held in memory for the steps it signs, and never saved.
    </p>
  );
}

const ATTEMPT_STATE: Record<AttemptState, string> = {
  recorded: 'recorded before sending; not yet read from the ledger',
  confirmed: 'confirmed',
  pending: 'pending in the node’s pool',
  rejected: 'dropped by the node, and may still land',
  expired: 'past its validity window; whether it landed is not established',
  'not-included': 'never landed, and can no longer land',
  unknown: 'unknown',
  conflict: 'contradicted by what the ledger says',
};

/**
 * Where a migration that has sent something stands, from the ledger: each
 * attempt, the account's authority, and what may be done next.
 */
function Settle({ op, commands, onAct }: { op: Operation; commands: OperationCommands; onAct: () => void }) {
  const [restorePhrase, setRestorePhrase] = useState('');
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [signing, setSigning] = useState('');
  // Whatever was typed goes once a run starts: the operation holds what it needs.
  useEffect(() => {
    if (op.inFlight) setSigning('');
  }, [op.inFlight]);
  const next = continuationOf(op);
  const approval = next.next ? approvalRefusal(op, next.next) : null;
  const record = op.record;
  // What this session read of each attempt; the saved label is shown beside it as a claim.
  const view = viewOf(op);

  return (
    <div style={{ marginTop: 16 }} data-settle>
      {record && (
        <div data-attempts>
          <p className="dim" style={{ marginBottom: 6 }}>
            Transactions this migration recorded before sending, as the ledger
            was read in this session
          </p>
          {view!.attempts.map((a, i) => {
            const saved = record.attempts[i]!;
            const read = !!op.evidence[a.txId];
            return (
              <div
                className="check"
                key={a.txId}
                data-attempt={a.txId}
                data-attempt-state={read ? a.state : 'unread'}
                data-saved-state={saved.state}
              >
                <span className={a.state === 'confirmed' ? 'ok' : a.state === 'not-included' ? 'faint' : 'no'}>
                  {a.state === 'confirmed' ? '✓' : a.state === 'not-included' ? '·' : '?'}
                </span>
                <span>
                  <b style={{ fontWeight: 600 }}>{STAGE_LABEL[a.stage]}</b>{' '}
                  <span className="mono" style={{ fontSize: 12 }}>{a.txId}</span>{' '}
                  <span className="faint">
                    valid in rounds {a.firstValid.toString()}–{a.lastValid.toString()}:{' '}
                    {read ? ATTEMPT_STATE[a.state] : 'not yet read from the ledger in this session'}
                    {a.confirmedRound !== null ? ` in round ${a.confirmedRound}` : ''}
                    {read && a.checkedRound !== null ? ` (read at round ${a.checkedRound}, ${a.source})` : ''}.
                    {saved.state !== a.state || !read ? ` The saved record says ${saved.state}.` : ''}
                    {read && a.state !== 'confirmed' ? ` ${op.evidence[a.txId]!.detail}` : ''}
                  </span>
                </span>
              </div>
            );
          })}
        </div>
      )}

      {op.authority && (
        <p className="faint" style={{ fontSize: 13, marginTop: 8 }} data-authority>
          At round {op.authority.round.toString()}, {op.context.sender} answers to{' '}
          {op.authority.authority}
          {op.authority.authority === op.context.targetAddress
            ? ', the new post-quantum key.'
            : op.authority.authority === op.context.authorizer
              ? ', the key that controlled it before this migration.'
              : ', which this migration did not set.'}
        </p>
      )}

      {op.notice && (
        <div className="callout warn" data-notice>
          {op.notice}
        </div>
      )}
      {op.conflict && (
        <div className="callout danger" role="alert" data-conflict>
          <strong>Stopped: the ledger contradicts this migration.</strong> {op.conflict} Nothing
          will be sent from this page for it.
        </div>
      )}
      {op.readOnly && (
        <div className="callout warn" data-read-only>
          {op.readOnly}
        </div>
      )}

      {record && !op.inFlight && (
        <button
          className="ghost"
          style={{ marginTop: 12 }}
          onClick={() => {
            onAct();
            void commands.reconcile();
          }}
        >
          Check the ledger
        </button>
      )}

      {next.next && next.needsIdentity && (
        <div style={{ marginTop: 14 }} data-restore>
          <p className="dim" style={{ marginBottom: 6 }}>
            To go on, type the 25 words of {op.context.targetAddress}. They
            are re-derived here and must produce that address; they are not
            saved.
          </p>
          <textarea
            aria-label="Recovery phrase of the new key"
            rows={3}
            style={{ width: '100%' }}
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            value={restorePhrase}
            onChange={(ev) => setRestorePhrase(ev.target.value)}
          />
          <button
            style={{ marginTop: 8 }}
            disabled={words(restorePhrase) !== 25}
            onClick={() => {
              const why = commands.restore(restorePhrase);
              setRestoreError(why);
              if (!why) {
                setRestorePhrase('');
                onAct();
              }
            }}
          >
            Restore the key
          </button>
          {restoreError && (
            <div className="err" style={{ marginTop: 8 }} data-restore-error>
              {restoreError}
            </div>
          )}
        </div>
      )}

      {next.next && !next.needsIdentity && (
        <div style={{ marginTop: 14 }} data-continue>
          {next.needsSigner && (
            <>
              <SigningNote network={op.context.network} sender={op.context.sender} authorizer={op.context.authorizer} />
              <textarea
                aria-label="Signing key phrase"
                rows={3}
                style={{ width: '100%', marginTop: 6 }}
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                value={signing}
                onChange={(ev) => setSigning(ev.target.value)}
              />
            </>
          )}
          <button
            style={{ marginTop: 12 }}
            disabled={(next.needsSigner && words(signing) !== 25) || approval !== null}
            onClick={() => {
              onAct();
              void commands.resume({ signingPhrase: signing });
            }}
          >
            {op.status === 'failed' && next.next === 'verification'
              ? 'Retry verification'
              : `Continue: ${STAGE_LABEL[next.next].toLowerCase()}`}
          </button>
          <p className="faint" style={{ fontSize: 13, marginTop: 8 }} data-approval>
            {approval && !op.quoting
              ? `Not yet: ${approval}`
              : 'Continuing approves the budget above for the remaining steps. Before each step it is read again, and a step that would cost more is not sent.'}
          </p>
        </div>
      )}
    </div>
  );
}

const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const algos = (m: bigint) => `${formatAlgos(m)} ALGO`;

/**
 * The budget for the steps still to run: what each costs, who pays it, and
 * what each address keeps. Every figure comes from the shared budget model,
 * read from the network; nothing here computes one.
 */
function BudgetPanel({ op, commands }: { op: Operation; commands: OperationCommands }) {
  const from = quoteFrom(op);
  // With nothing left to run, what this run was approved on, if anything.
  const settled = !from && !op.inFlight && op.approved !== null;
  const q: MigrationBudget | null = settled ? op.approved : op.quote;
  if (!q && !op.quoting && !from) return null;
  const { sender, targetAddress } = op.context;
  const who = (a: string) => (a === sender ? 'the account' : a === targetAddress ? 'the new address' : short(a));
  // A reading above what this run approved: going on approves it.
  const beyond = !settled && op.approved && q ? exceedsApproved(op.approved, q) : null;
  const t = q?.totals;

  return (
    <div
      style={{ marginTop: 22 }}
      data-budget
      data-budget-status={q?.status ?? 'none'}
      data-budget-from={q?.spec.from ?? ''}
      data-budget-approved={settled ? '' : undefined}
    >
      <h2>Budget</h2>
      {settled && (
        <p className="dim" data-budget-settled>
          The budget this run was approved on. Each step was read again before it was sent, and none went beyond it.
        </p>
      )}
      {op.quoting && (
        <p className="dim" data-budget-reading>
          Reading fees, balances and minimum balances from the network. Nothing is signed or sent.
        </p>
      )}
      {q && (
        <>
          {q.status !== 'available' && (
            <div className="callout danger" data-budget-problems>
              {q.status === 'unavailable' ? 'The budget is unavailable, so nothing can be approved: ' : 'This budget cannot go ahead: '}
              {q.problems.join(' ')}
              {q.status === 'unavailable' && !op.inFlight && from && ' Reading the budget sends nothing, so it is safe to read it again.'}
            </div>
          )}
          {q.stages.length > 0 && (
            <table className="budget-table">
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Paid by</th>
                  <th className="signed">Signed with</th>
                  <th className="num">Sends</th>
                  <th className="num">Fee</th>
                </tr>
              </thead>
              <tbody>
                {q.stages.map((s) => (
                  <tr key={s.stage} data-budget-stage={s.stage} data-amount={s.amount.toString()} data-fee={s.fee.toString()}>
                    <td>{STAGE_LABEL[s.stage]}</td>
                    <td>{who(s.sender)}</td>
                    <td className="signed">
                      {s.scheme === 'falcon-1024' ? 'Falcon-1024' : 'Ed25519'}
                      {s.authorizer !== s.sender ? `, by ${who(s.authorizer)}` : ''}
                    </td>
                    <td className="num">{algos(s.amount)}</td>
                    <td className="num">{algos(s.fee)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {t && q.source && q.target && (
            <ul className="budget-lines" data-budget-totals>
              <li>
                <b>Fees, every step:</b> {algos(t.feeExpense)}. The account pays {algos(t.sourceFees)}
                {t.targetProofExpense > 0n ? `; the new address pays its proof, ${algos(t.targetProofExpense)}, from what it holds` : ''}.
              </li>
              <li data-budget-source>
                <b>The account</b> sends {algos(t.transfer)} to the new address and pays {algos(t.sourceFees)} in fees:{' '}
                {algos(t.sourceDebit)} in all. It holds {algos(q.source.balance)} and must keep{' '}
                {algos(q.source.minBalance)}, so it keeps {algos(t.sourceRetained)}.
              </li>
              <li data-budget-target>
                <b>The new address</b> {q.target.exists ? `holds ${algos(q.target.balance)}` : 'does not exist yet'} and must keep{' '}
                {algos(q.target.minBalance)}
                {t.reserve > 0n ? `; the transfer includes a reserve of ${algos(t.reserve)}` : ''}. It keeps{' '}
                {algos(t.targetRetained)}, movable only with its 25 words. The transfer is not a fee.
              </li>
              {q.postMigrationFee !== null && (
                <li>
                  <b>Afterwards</b> a Falcon-signed zero-value payment from the account needs {algos(q.postMigrationFee)} at
                  these parameters; more under congestion, or for a larger transaction.
                </li>
              )}
            </ul>
          )}
          {q.observed && (
            <p className="faint" style={{ fontSize: 12.5, marginTop: 8 }} data-budget-observed>
              Read at round {q.observed.round.toString()} on {q.observed.genesis.id}, consensus {q.observed.rules}; usable
              until round {q.observed.validThroughRound.toString()}. {q.assumptions.join(' ')}
            </p>
          )}
          {beyond && (
            <div className="callout warn" role="alert" data-budget-changed>
              <strong>The budget changed since this run was approved.</strong> {beyond} Nothing was sent against it.{' '}
              {q.status === 'available'
                ? 'Going on approves this reading.'
                : 'Nothing can go ahead until a reading can be approved.'}
            </div>
          )}
        </>
      )}
      {/* Busy, not removed, so keyboard focus stays on it while it reads. */}
      {!op.inFlight && from && (
        <button
          className="ghost"
          style={{ marginTop: 10 }}
          aria-disabled={op.quoting}
          onClick={() => void commands.refreshQuote()}
        >
          Read the budget again
        </button>
      )}
    </div>
  );
}

function Dismissal({
  op,
  acknowledged,
  onAcknowledge,
  onDismiss,
}: {
  op: Operation;
  acknowledged: boolean;
  onAcknowledge: (v: boolean) => void;
  onDismiss: () => void;
}) {
  const { sender, targetAddress } = op.context;
  // Only what this session read counts here, never the saved labels.
  const view = viewOf(op);
  if (!view || !isResolved(view)) return null;
  const verified = stageStatus(view, 'verification') === 'confirmed';
  const funded = stageStatus(view, 'funding') === 'confirmed';
  return (
    <div className="callout" style={{ borderColor: verified ? 'var(--safe)' : undefined }} data-dismissal>
      {verified ? (
        <>
          <strong>Migrated.</strong> {sender} is unchanged and every role it
          held carried over. Authority is now {targetAddress}. Its 25 words
          are the only way to recover this account &mdash; make sure they are
          written down before you close this page.
          <br />
          <br />
          The verdict above may still read as exposed for a few moments.
          Post-quantum authority is only claimed once a Falcon signature has
          been served by Indexer, which lags the chain slightly. The rekey
          itself is already final.
        </>
      ) : (
        <>
          <strong>Settled without a rekey.</strong> Every transaction this
          migration recorded is settled, and the rekey never landed, so{' '}
          {sender} answers to the same key as before.
          {funded
            ? ` The funding sent to ${targetAddress} can only be moved with its 25 words.`
            : ' Nothing it sent reached the ledger.'}
        </>
      )}
      <label className="check" style={{ marginTop: 12 }}>
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(ev) => onAcknowledge(ev.target.checked)}
        />
        <span>
          I have written down the 25 words and checked them. Once
          dismissed, this page no longer shows them or this migration&rsquo;s
          record.
        </span>
      </label>
      <button className="ghost" style={{ marginTop: 8 }} disabled={!acknowledged} onClick={onDismiss}>
        Dismiss and remove the words from this page
      </button>
    </div>
  );
}

/** What the operator must know before anything else on the panel. */
function OperationAlert({ op }: { op: Operation }) {
  const { sender, targetAddress } = op.context;
  const words = op.identity && op.origin === 'session' ? 'the 25 words below are' : 'its 25 words are';
  const keep =
    'If this tab is closed or reloaded, the saved record lets the page pick ' +
    'this up again, but the 25 words are not saved: write them down.';
  if (op.origin === 'recovered' && Object.keys(op.evidence).length === 0) {
    return (
      <div className="callout danger" role="alert" data-alert="unchecked">
        <strong>Not yet checked against the ledger.</strong> This page found a
        saved record of this migration. What it says about each transaction is
        not trusted until the ledger has been read, so nothing can continue or
        be dismissed before then. {keep}
      </div>
    );
  }
  if (op.status === 'outcome-unknown') {
    const step: Record<Stage, string> = {
      funding: 'The payment funding the new address may or may not have been sent.',
      proof: 'The proof payment from the new address may or may not have been sent.',
      rekey: '',
      verification: 'The verification payment may or may not have been sent.',
    };
    // The step named is only the first one unsettled. After a reload that
    // could not read the ledger, a rekey recorded later is unsettled too, so
    // what is said of the account comes from every attempt, as read here.
    const rekeyOpen = viewOf(op)?.attempts.some((a) => a.stage === 'rekey' && a.state !== 'not-included');
    const account = op.rekeyConfirmed
      ? `The rekey already succeeded: ${sender} is controlled by ${targetAddress}, and ${words} the only way to control it.`
      : rekeyOpen
        ? `The rekey may have taken effect. If it did, ${sender} is now controlled only by ${targetAddress}, and ${words} the only way to control it.`
        : 'The account itself has not been rekeyed.';
    return (
      <div className="callout danger" role="alert" data-alert="outcome-unknown">
        <strong>Outcome unknown.</strong> {step[op.stage!]} {account} Check the ledger to
        settle it: that reads the ledger and signs or sends nothing. Until it
        is settled the migration stays locked: no retry, no new key and no
        other scan. {keep}
      </div>
    );
  }
  if (op.rekeyConfirmed && op.verification !== 'passed') {
    return (
      <div className="callout danger" role="alert" data-alert="rekeyed">
        <strong>The rekey already succeeded.</strong> {sender} is now
        controlled by {targetAddress}, and {words} the only way to control
        it.{' '}
        {op.status === 'submitted'
          ? 'It is being verified now.'
          : 'Verification did not finish, which does not undo the rekey and ' +
            'does not put the account back under its old key. Write the words ' +
            `down before you leave this page, then retry the verification. ${keep}`}
      </div>
    );
  }
  return null;
}

function statusText(op: Operation): string {
  const label = op.stage ? STAGE_LABEL[op.stage] : '';
  if (op.task === 'reconcile') return 'Checking the ledger. Nothing is signed or sent while it does.';
  if (op.task === 'checks' && op.record) {
    return 'Checking the network and the account before going on. Nothing has been sent for the next step.';
  }
  switch (op.status) {
    case 'prepared':
      return op.inFlight
        ? 'Checking which network the node is on. Nothing has been sent yet.'
        : 'Nothing has been sent.';
    case 'submitted':
      return `${label}: sending, and waiting for confirmation. It may already have reached the network.`;
    case 'confirmed':
      if (op.stage === 'verification') return 'Migrated and verified.';
      return op.inFlight ? `${label}: confirmed.` : `${label}: confirmed. The next step has not started.`;
    case 'failed':
      if (op.stage === null) return 'Stopped before anything was sent.';
      return op.stage === 'verification' && op.rekeyConfirmed
        ? 'The rekey is confirmed. Verification stopped before sending anything.'
        : `${label}: stopped. Nothing of it is in the ledger, so it can be sent again.`;
    case 'outcome-unknown':
      return `${label}: outcome unknown.`;
  }
}

const MARK = {
  'not-reached': '·',
  'in-flight': '…',
  confirmed: '✓',
  unknown: '?',
  failed: '✕',
} as const;

const STATE_NOTE = {
  'not-reached': '',
  'in-flight': 'Sending, and waiting for confirmation.',
  confirmed: '',
  unknown: 'Outcome unknown: it may or may not have been sent.',
  failed: 'Stopped, with nothing of it in the ledger.',
} as const;

/** Where each step stands. */
function Progress({ op, statusRef }: { op: Operation; statusRef: RefObject<HTMLParagraphElement> }) {
  return (
    <div style={{ marginTop: 16 }}>
      <p ref={statusRef} tabIndex={-1} className="dim" role="status" data-status-text style={{ marginBottom: 6 }}>
        {op.inFlight && <span className="spinner" />}
        {statusText(op)}
      </p>
      {(op.stage !== null || op.record) &&
        STAGES.map((s) => {
          const state = stageState(op, s);
          return (
            <div className="check" key={s} data-step={s} data-state={state}>
              <span className={state === 'confirmed' ? 'ok' : state === 'not-reached' ? 'faint' : 'no'}>
                {MARK[state]}
              </span>
              <span>
                <b style={{ fontWeight: 600 }}>{STAGE_LABEL[s]}</b>{' '}
                <span className="faint">{op.results[s] ?? STATE_NOTE[state]}</span>
              </span>
            </div>
          );
        })}
    </div>
  );
}
