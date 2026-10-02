import { useEffect, useRef, useState } from 'react';
import algosdk from 'algosdk';
import {
  analyzeAccount,
  clientsFor,
  publicMessage,
  riskVerdict,
  type AccountExposure,
} from '@falqoner/core';
import {
  Mark,
  Verdict,
  AuthorityBanner,
  Stats,
  Findings,
  CoverageNote,
  ReachNote,
  ResidualNote,
  AuthorityGraph,
} from './components';
import { Migrate } from './Migrate';
import {
  lockReason,
  useMigrationOperation,
  type NetworkName,
  type Operation,
  type OperationOptions,
  type ScanRequest,
} from './operation';

const SAMPLES: Array<{
  label: string;
  address: string;
  network: NetworkName;
  /** Ids to check exactly, because these accounts are dull without them. */
  assets?: string;
  apps?: string;
}> = [
  {
    label: 'USDC reserve',
    address: '2UEQTE5QDNXPI7M3TU44G6SYKLFWLPQO7EBZM7K7MHMQQMFI4QJPLHQFHM',
    network: 'mainnet',
  },
  {
    label: 'USDC manager',
    address: '37XL3M57AXBUJARWMT5R7M35OERXMH3Q22JMMEFLBYNDXXADGFN625HAL4',
    network: 'mainnet',
    // Holds 0.3 ALGO and created nothing. Naming USDC is what reveals it.
    assets: '31566704',
  },
];

/**
 * Parse a comma-separated id list.
 *
 * A silently dropped id would be the worst outcome here: the report
 * would come back clean and the reader would never learn that the asset
 * they cared about was never checked.
 */
function parseIds(raw: string): { ids?: bigint[]; error?: string } {
  const trimmed = raw.trim();
  if (!trimmed) return {};
  const ids: bigint[] = [];
  for (const part of trimmed.split(',').map((x) => x.trim())) {
    if (!part) continue;
    if (!/^[0-9]+$/.test(part)) return { error: `"${part}" is not an id.` };
    ids.push(BigInt(part));
  }
  return ids.length ? { ids } : {};
}

type ParsedScan =
  | { request: ScanRequest; ids: { assetIds?: bigint[]; appIds?: bigint[] } }
  | { error: string };

function parseScan(r: ScanRequest): ParsedScan {
  const address = r.address.trim();
  if (!algosdk.isValidAddress(address)) {
    return { error: 'That is not a valid Algorand address.' };
  }
  const assets = parseIds(r.assets);
  const apps = parseIds(r.apps);
  if (assets.error) return { error: `Asset ids: ${assets.error}` };
  if (apps.error) return { error: `App ids: ${apps.error}` };
  return { request: { ...r, address }, ids: { assetIds: assets.ids, appIds: apps.ids } };
}

/** A finished scan, and exactly what was asked for. */
interface Scanned {
  exposure: AccountExposure;
  request: ScanRequest;
}

/** A migration verified and dismissed in this session. Public data only. */
interface Completed {
  sender: string;
  network: NetworkName;
  target: string;
}

/** Test seams: storage, the tab lock and timing. The page itself uses the browser's. */
export type AppProps = Pick<OperationOptions, 'journal' | 'tabLock' | 'timing'>;

export default function App({ journal, tabLock, timing }: AppProps = {}) {
  const [address, setAddress] = useState('');
  const [network, setNetwork] = useState<NetworkName>('mainnet');
  const [assetsText, setAssetsText] = useState('');
  const [appsText, setAppsText] = useState('');
  const [scanned, setScannedState] = useState<Scanned | null>(null);
  const [busy, setBusyState] = useState(false);
  const [progress, setProgress] = useState('');
  /** What went wrong and what to do, and for a failed read, the provider's words, bounded. */
  const [error, setError] = useState<{ text: string; detail?: string } | null>(null);
  const [completed, setCompleted] = useState<Completed[]>([]);
  const errorBox = useRef<HTMLDivElement>(null);

  // Handlers read these, not a render's copy, so two events in one turn see
  // each other.
  const scannedRef = useRef<Scanned | null>(null);
  const busyRef = useRef(false);
  /**
   * A dismissal removes the panel, and the button that had focus with it.
   * Set by a dismissal, so the render that follows gives focus to the panel
   * shown in its place, or to the scan form when there is none.
   */
  const dismissed = useRef(false);
  const migrationHeading = useRef<HTMLHeadingElement>(null);
  const addressInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!dismissed.current) return;
    dismissed.current = false;
    (migrationHeading.current ?? addressInput.current)?.focus();
  });
  const setScanned = (s: Scanned | null) => {
    scannedRef.current = s;
    setScannedState(s);
  };
  const setBusy = (b: boolean) => {
    busyRef.current = b;
    setBusyState(b);
  };
  /**
   * Bumped by every scan and every network change. A callback from an older
   * scan - its result, error, progress or finally - changes nothing.
   */
  const scanSeq = useRef(0);

  // The one owner of the migration, above the conditional render of its
  // panel. See operation.ts.
  const { state: operation, commands } = useMigrationOperation({
    onVerified: (op) => refresh(op),
    journal,
    tabLock,
    timing,
  });
  const lock = lockReason(operation);
  // The form's alert sits below its fields, out of sight once a scan the
  // operator started fails. It is scrolled to, and focus stays put. A refresh
  // failing behind a migration panel moves nothing.
  useEffect(() => {
    if (error && commands.current().status === 'idle') errorBox.current?.scrollIntoView?.({ block: 'nearest' });
  }, [error, commands]);
  // A saved record this page cannot use blocks a new migration, not the audit.
  const journalProblem = commands.journalProblem();

  // A migration recovered after a reload shows its own network and account
  // in the scan controls, which stay locked, rather than the page defaults.
  const recoveredId = operation.status !== 'idle' && operation.origin === 'recovered' ? operation.id : null;
  useEffect(() => {
    const op = commands.current();
    if (!recoveredId || op.status === 'idle') return;
    setNetwork(op.context.network);
    setAddress(op.context.sender);
    setAssetsText(op.context.scan.assets);
    setAppsText(op.context.scan.apps);
  }, [recoveredId, commands]);

  function startScan(
    parsed: Extract<ParsedScan, { request: ScanRequest }>,
    keep: boolean,
    failure = 'The scan could not finish, so nothing was judged. Check the address and network, then scan again.',
  ) {
    const seq = ++scanSeq.current;
    const current = () => seq === scanSeq.current;
    setBusy(true);
    setError(null);
    setProgress('');
    // A refresh after migrating keeps the results mounted, so the success
    // state and the recovery phrase reminder stay on screen. Clearing them
    // at the exact moment a key becomes the only way back into an account
    // would be the worst possible time to do it.
    if (!keep) setScanned(null);
    analyzeAccount(clientsFor(parsed.request.network), parsed.request.address, {
      ...parsed.ids,
      onProgress: (m) => {
        if (current()) setProgress(m);
      },
    })
      .then(
        (exposure) => {
          if (current()) setScanned({ exposure, request: parsed.request });
        },
        (err: any) => {
          if (current()) setError({ text: failure, detail: publicMessage(err) });
        },
      )
      .finally(() => {
        if (current()) {
          setBusy(false);
          setProgress('');
        }
      });
  }

  /** A scan the operator asked for. */
  function scan(request: ScanRequest) {
    // Nothing on the page may replace a migration that is running, or whose
    // outcome is unresolved.
    if (commands.lockReason()) return;
    const parsed = parseScan(request);
    if ('error' in parsed) {
      setError({ text: parsed.error });
      return;
    }
    // A key prepared against the previous scan never sent anything.
    commands.discard();
    startScan(parsed, false);
  }

  /** Read the migrated account again, exactly as it was scanned. */
  function refresh(op: Operation) {
    const cur = commands.current();
    if (cur.status === 'idle' || cur.id !== op.id) return;
    const parsed = parseScan(op.context.scan);
    if ('error' in parsed) return;
    startScan(
      parsed,
      true,
      'The migration stands, but the account could not be read again, so no report on this page shows ' +
        'its new authority yet. Once the migration is dismissed, scan the account again.',
    );
  }

  function changeNetwork(next: NetworkName) {
    if (commands.lockReason()) return;
    commands.discard();
    // The report on screen was read from the network it was scanned on.
    // Keeping it while the client points somewhere else invites acting on
    // one network's findings against another's ledger - and so would a scan
    // still running against the old network, landing after the switch.
    scanSeq.current++;
    setBusy(false);
    setProgress('');
    setNetwork(next);
    setScanned(null);
  }

  function generate() {
    const s = scannedRef.current;
    // Only against a finished scan that is still the one on screen.
    if (!s || busyRef.current) return;
    commands.prepare({
      network: s.request.network,
      scan: s.request,
      exposure: s.exposure,
      sender: s.exposure.address,
      authorizer: s.exposure.authAddr ?? s.exposure.address,
      clients: clientsFor(s.request.network),
    });
  }

  function dismiss(acknowledged: boolean) {
    const done = commands.dismiss(acknowledged);
    if (!done) return;
    dismissed.current = true;
    const { sender, network: net, targetAddress } = done.context;
    // Only a verified migration is remembered as done; one that never
    // rekeyed leaves the account as it was.
    if (done.verification === 'passed') {
      setCompleted((c) => [...c, { sender, network: net, target: targetAddress }]);
    }
  }

  const request = (): ScanRequest => ({ address, network, assets: assetsText, apps: appsText });
  const exposure = scanned?.exposure ?? null;
  const panelExposure = operation.status === 'idle' ? exposure : operation.context.exposure;
  const completedTarget =
    scanned && operation.status === 'idle'
      ? (completed.find(
          (c) => c.sender === scanned.exposure.address && c.network === scanned.request.network,
        )?.target ?? null)
      : null;

  return (
    <div className="wrap">
      <header className="site">
        <div className="brand">
          <Mark />
          Falconer
        </div>
        <div className="tagline">post-quantum readiness for Algorand</div>
      </header>

      <section className="hero">
        <h1>
          Find out what one key really controls &mdash; then, when you choose,
          move it to <em>Falcon-1024</em>.
        </h1>
        <p>
          An ordinary Algorand account&rsquo;s address <strong>is</strong> its
          Ed25519 public key, so the key is public as soon as the address is:
          an attacker can record it now and try to forge signatures with it
          later. Multisig, logic-signature, application and post-quantum
          addresses are hashes instead, which rules out a bare key but proves
          nothing post-quantum on its own.
        </p>
        <p>
          Algorand accepts Falcon-1024 accounts from its v42 consensus upgrade,
          shipped in algod 5.0.0, once that upgrade has taken effect on a
          network. Because Algorand can rotate an account&rsquo;s signing key
          without changing its address, one rekey moves an account &mdash; and
          every asset role and application it holds &mdash; onto post-quantum
          authority.
          Accounts rekeyed <em>to</em> it do not move with it: each is still
          signed for by the original key, and needs its own rekey.
        </p>
        <p>
          Most accounts should not rekey yet: a migrated account must sign
          every transaction with Falcon, at a higher fee, and not every wallet
          and dApp can do that. Audit now, so the decision is yours to time
          rather than one you make under pressure.
        </p>

        <div className="search">
          <label className="field">
            <span>Algorand address</span>
            <input
              ref={addressInput}
              type="text"
              value={address}
              spellCheck={false}
              disabled={!!lock}
              onChange={(e) => {
                if (!commands.lockReason()) setAddress(e.target.value);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') scan(request());
              }}
            />
          </label>
          <select
            aria-label="Network"
            value={network}
            disabled={!!lock}
            onChange={(e) => changeNetwork(e.target.value as NetworkName)}
          >
            <option value="mainnet">MainNet</option>
            <option value="testnet">TestNet</option>
            <option value="localnet">LocalNet</option>
          </select>
          {/* Busy, not disabled, so keyboard focus stays on it while it scans. */}
          <button onClick={() => !busy && scan(request())} disabled={!!lock} aria-disabled={busy}>
            {busy && <span className="spinner" />}
            {busy ? 'Scanning' : 'Scan'}
          </button>
        </div>

        {network === 'mainnet' && (
          <p className="callout" data-mainnet-read-only>
            MainNet is read-only in this beta. Key generation and migration are
            disabled. Use TestNet or LocalNet to try them.
          </p>
        )}

        <div className="search" style={{ marginTop: 0 }}>
          <label className="field" style={{ minWidth: 210 }}>
            <span>Asset ids to check exactly</span>
            <input
              type="text"
              placeholder="comma-separated, e.g. 31566704"
              value={assetsText}
              spellCheck={false}
              disabled={!!lock}
              onChange={(e) => {
                if (!commands.lockReason()) setAssetsText(e.target.value);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') scan(request());
              }}
            />
          </label>
          <label className="field" style={{ minWidth: 180 }}>
            <span>App ids to check exactly</span>
            <input
              type="text"
              placeholder="comma-separated"
              value={appsText}
              spellCheck={false}
              disabled={!!lock}
              onChange={(e) => {
                if (!commands.lockReason()) setAppsText(e.target.value);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') scan(request());
              }}
            />
          </label>
        </div>
        <p className="faint" style={{ fontSize: 12.5, margin: '2px 0 0' }}>
          Roles on assets and apps this account created or holds are found
          automatically. A granted role cannot be searched for &mdash; Indexer
          does not index role addresses as participants &mdash; so name the ids
          you care about and they are checked exactly.
        </p>

        <div className="samples">
          <span>Try:</span>
          {SAMPLES.map((s) => (
            <button
              key={s.address}
              disabled={!!lock}
              onClick={() => {
                if (commands.lockReason()) return;
                const sample: ScanRequest = {
                  address: s.address,
                  network: s.network,
                  assets: s.assets ?? '',
                  apps: s.apps ?? '',
                };
                if (s.network !== network) changeNetwork(s.network);
                setAddress(sample.address);
                setAssetsText(sample.assets);
                setAppsText(sample.apps);
                scan(sample);
              }}
            >
              {s.label}
            </button>
          ))}
        </div>

        {lock && (
          <div className="callout warn" role="status" data-lock style={{ marginTop: 14 }}>
            <strong>Migration locked.</strong> {lock} Scanning, and changing
            the network or an example, are disabled so nothing on this page
            can replace it. If this tab is closed or reloaded, the public
            record of the migration stays in this browser and the page picks
            it up again; the 25 words do not, so keep them written down.
          </div>
        )}
        {journalProblem && (
          <div className="callout danger" role="alert" data-journal-problem style={{ marginTop: 14 }}>
            <strong>Saved migration unreadable.</strong> {journalProblem}
          </div>
        )}
        {/* Always mounted, so each change is announced. */}
        <p className={busy && progress ? 'faint' : 'sr-only'} role="status" style={{ fontSize: 13, marginTop: 10 }}>
          {busy ? progress : exposure ? `Scan finished: ${riskVerdict(exposure.risk).headline}.` : ''}
        </p>
        {error && (
          <div ref={errorBox} className="err" role="alert" style={{ marginTop: 14 }}>
            {error.text}
            {error.detail && (
              <div className="mono" style={{ marginTop: 6 }} data-error-detail>
                Details: {error.detail}
              </div>
            )}
          </div>
        )}
      </section>

      {exposure && (
        <>
          <div className="panel">
            <h2>Verdict</h2>
            <Verdict e={exposure} />
            <Stats e={exposure} />
            <div style={{ marginTop: 18 }}>
              <p className="faint" style={{ fontSize: 13, marginBottom: 6 }}>
                This account&rsquo;s own authority
              </p>
              <AuthorityBanner a={exposure.authority} />
            </div>
            <ResidualNote e={exposure} />
            <ReachNote e={exposure} />
          </div>

          {exposure.edges.some((e) => e.from === exposure.address) && (
            <div className="panel">
              <h2>Authority graph</h2>
              <p className="dim" style={{ marginTop: 6, marginBottom: 10 }}>
                Everything this address was found to reach. Asset roles carry
                over on a rekey, because they are exercised by transactions
                this account sends. Accounts rekeyed to this address do not:
                they are signed for by the key behind the address itself, and
                each needs its own rekey. Application references are marked
                &ldquo;reference: permissions unverified&rdquo;, because
                programs are not analysed.
              </p>
              <AuthorityGraph e={exposure} />
            </div>
          )}

          <div className="panel">
            <h2>Findings</h2>
            <CoverageNote e={exposure} />
            <Findings findings={exposure.findings} />
          </div>
        </>
      )}

      {(panelExposure || operation.status !== 'idle') && (
        <Migrate
          // A new operation gets a fresh panel, with nothing typed into it.
          key={operation.status === 'idle' ? 'idle' : operation.id}
          network={scanned?.request.network ?? network}
          exposure={exposure ?? panelExposure}
          operation={operation}
          commands={commands}
          completedTarget={completedTarget}
          headingRef={migrationHeading}
          onGenerate={generate}
          onDismiss={dismiss}
        />
      )}

      <footer className="site">
        <p>
          Falconer reads public chain data through algod and Indexer, and
          trusts the records that provider reports as confirmed. The audit
          only reads. On TestNet and LocalNet, the migration panel handles
          recovery phrases: it generates a Falcon key and its phrase in your
          browser with WebAssembly, and takes the phrase of the key that signs
          the rekey. Neither is ever transmitted; only signed
          transactions are. Post-quantum authority is only reported when the
          provider reports a confirmed transaction authorised by a
          Falcon-1024 signature, and Falconer checks locally that the key and
          salt in that record derive the account&rsquo;s authority address.
          Falconer does not verify the signature itself. An off-curve address
          alone is never treated as evidence, because multisignature and
          logic-signature addresses are hash-derived too.
        </p>
      </footer>
    </div>
  );
}
