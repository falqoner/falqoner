import type {
  AccountExposure,
  AuthorityAssessment,
  AuthorityEdge,
  AuthorityVerdict,
  Finding,
} from '@falqoner/core';
import {
  authorityVerdict,
  coverageLines,
  describeReach,
  formatAlgos,
  riskVerdict,
  SCORE_SCOPE,
} from '@falqoner/core';

const BAND_COLOR: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  elevated: 'var(--high)',
  low: 'var(--medium)',
  safe: 'var(--safe)',
  // Not the safe colour: an incomplete verdict must not read as a clean one.
  unverified: 'var(--high)',
};

export function Mark() {
  // A stylised falcon silhouette in a stoop.
  return (
    <svg className="mark" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 6.2 9.1a1 1 0 0 0 .75 1.66h2.2l-4 6.9a1 1 0 0 0 1.2 1.45l5.15-1.9v3.3h1.4v-3.3l5.15 1.9a1 1 0 0 0 1.2-1.45l-4-6.9h2.2a1 1 0 0 0 .75-1.66Z"
        fill="currentColor"
      />
    </svg>
  );
}

/**
 * `label` is what the dial prints, which differs from `score` when the score
 * is incomplete (`?`) or only a lower bound (`28+`). The arc still draws the
 * established score, so an unverified verdict shows an empty dial with a
 * question mark rather than a clean zero.
 */
export function Gauge({
  score,
  band,
  label = String(score),
}: {
  score: number;
  band: string;
  label?: string;
}) {
  const r = 56;
  const c = 2 * Math.PI * r;
  const filled = (score / 100) * c;
  const color = BAND_COLOR[band] ?? 'var(--low)';
  return (
    <div className="gauge">
      {/* The dial only draws the score printed beside it. */}
      <svg width="132" height="132" viewBox="0 0 132 132" aria-hidden="true">
        <circle
          cx="66"
          cy="66"
          r={r}
          fill="none"
          stroke="var(--border-bright)"
          strokeWidth="9"
        />
        <circle
          cx="66"
          cy="66"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${c}`}
          style={{ transition: 'stroke-dasharray 0.7s cubic-bezier(.2,.8,.2,1)' }}
        />
      </svg>
      <div className="score">
        <b style={{ color }}>{label}</b>
        <span>exposure</span>
      </div>
    </div>
  );
}

/**
 * The aggregate verdict, from the shared model: the dial, the headline and
 * the summary, which names anything the verdict could not establish.
 */
export function Verdict({ e }: { e: AccountExposure }) {
  const v = riskVerdict(e.risk);
  return (
    <div className="verdict">
      <Gauge score={e.risk.score} label={v.score} band={e.risk.band} />
      <div className="verdict-body">
        <h3 className={`band-${e.risk.band}`}>{v.headline}</h3>
        <p>{e.risk.summary}</p>
        <p className="mono faint" style={{ marginTop: 8 }}>
          {e.address}
        </p>
      </div>
    </div>
  );
}

/** The shared verdict's tone, as the banner's class and icon. */
const TONE: Record<AuthorityVerdict['tone'], [string, string]> = {
  'post-quantum': ['pq', '✓'],
  exposed: ['bad', '✕'],
  unproven: ['warn', '?'],
};

export function AuthorityBanner({ a }: { a: AuthorityAssessment }) {
  // The same words the CLI prints, from core; only the styling is local.
  const v = authorityVerdict(a);
  const [tone, icon] = TONE[v.tone];

  return (
    <div className={`authority ${tone}`} data-tone={v.tone}>
      <div className="icon">{icon}</div>
      <div>
        <h4>{v.label[0]!.toUpperCase() + v.label.slice(1)}</h4>
        {/* The detail states the evidence basis for every class - for a
            post-quantum verdict, whose record it is, the local address
            binding, and that Falconer does not verify the signature - so it
            is not repeated in a second line here. */}
        <p>{a.detail}</p>
        {a.evidenceTxId && (
          <p className="mono faint" style={{ marginTop: 6 }}>
            {/* A record the verdict refused is not its evidence. */}
            {a.evidence.basis === 'provider-record' ? 'evidence' : 'rejected record'}:{' '}
            {a.evidenceTxId}
          </p>
        )}
      </div>
    </div>
  );
}

export function Stats({ e }: { e: AccountExposure }) {
  // A search that stopped early found a floor, not a count.
  const signsFor = e.coverage.incoming.exhausted
    ? String(e.controlsAccounts.length)
    : `${e.controlsAccounts.length}+`;
  const items: Array<[string, string]> = [
    ['balance', `${formatAlgos(e.microAlgos)} ALGO`],
    ['assets held', String(e.assetsHeld)],
    ['assets created', String(e.createdAssets.length)],
    ['apps created', String(e.createdApps.length)],
    // A reference is not administration: what an app lets this address do
    // is up to its program, which is not analysed.
    ['app references', String(e.reach.appReferences)],
    [
      'accounts it signs for',
      e.incomingScan === 'unavailable'
        ? 'not checked'
        : e.risk.residualAccounts
          ? `${signsFor} (${e.risk.residualAccounts} exposed)`
          : signsFor,
    ],
  ];
  return (
    <div className="stats">
      {items.map(([label, value]) => (
        <div className="stat" key={label}>
          <b>{value}</b>
          <span>{label}</span>
        </div>
      ))}
    </div>
  );
}


/**
 * Exposure that this account's own authority does not cover.
 *
 * Accounts rekeyed to this address are signed for by the key behind the
 * address, not by this account's authority, so a post-quantum
 * banner directly above would otherwise read as covering them too.
 */
export function ResidualNote({ e }: { e: AccountExposure }) {
  const n = e.risk.residualAccounts;
  if (!n) return null;
  return (
    <div className="callout danger">
      {n} account{n === 1 ? '' : 's'} rekeyed to this address{' '}
      {n === 1 ? 'is' : 'are'} signed for by the key behind it, not by this
      account&rsquo;s own authority &mdash;{' '}
      {formatAlgos(e.risk.residualMicroAlgos)} ALGO in all. Migrating this
      account does not move {n === 1 ? 'it: it needs' : 'them: each needs'}{' '}
      its own rekey, signed by that key.
    </div>
  );
}

/**
 * What this address reaches beyond its own balance.
 *
 * Stated as found, from the shared model: each capability, and separately
 * whether the key behind it is exposed. Only exposed reach is shown as a
 * danger, so an address that signs for protected accounts is never dressed
 * up as holding asset powers or classical exposure it does not have.
 */
export function ReachNote({ e }: { e: AccountExposure }) {
  const reach = describeReach(e);
  if (!reach) return null;
  return (
    <div className={`callout${reach.exposed ? ' danger' : ''}`} data-reach={reach.exposed ? 'exposed' : 'protected'}>
      {reach.text}
    </div>
  );
}

/**
 * What every check covered, and what it could not.
 *
 * A report with no findings in it is only meaningful next to a statement
 * of what was looked at. Without this the web app would show an empty
 * list and let the reader supply their own, far more optimistic, caption.
 * The lines come from the same model the CLI prints, so the two agree.
 */
export function CoverageNote({ e }: { e: AccountExposure }) {
  const lines = coverageLines(e);
  const short = lines.some((l) => l.blocking);
  const s = e.roleScan;
  return (
    <div
      className={`callout coverage${short ? ' warn' : ''}`}
      style={{ marginTop: 0, marginBottom: 14 }}
    >
      <strong>What was searched</strong>
      {lines.map((l) => (
        <div className="coverage-row" key={l.check} data-check={l.check}>
          <span className="coverage-label">{l.label}</span>
          <span className={`coverage-status ${l.blocking ? 'short' : l.status}`}>
            {l.status.replace('-', ' ')}
          </span>
          <span className="coverage-detail">{l.detail}</span>
        </div>
      ))}
      <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>
        {s.assetsExamined} asset{s.assetsExamined === 1 ? '' : 's'} &middot;{' '}
        {s.appsExamined} application{s.appsExamined === 1 ? '' : 's'} read
        {s.sampled > 0 && `, of which ${s.sampled.toLocaleString()} sampled`}.{' '}
        {SCORE_SCOPE}
      </div>
    </div>
  );
}

export function Findings({ findings }: { findings: Finding[] }) {
  if (!findings.length) {
    return <p className="dim">No findings in what was checked.</p>;
  }
  return (
    <div>
      {findings.map((f, i) => (
        <div className="finding" key={i}>
          <div className={`sev ${f.severity}`}>{f.severity}</div>
          <div>
            <h4>{f.title}</h4>
            <p>{f.detail}</p>
            <div>
              {f.thirdParty && (
                <span className="tag danger">affects third parties</span>
              )}
              {f.fixedByRekey && <span className="tag">fixed by one rekey</span>}
              {f.assetIds?.slice(0, 4).map((id) => (
                <span className="tag" key={String(id)}>
                  ASA {String(id)}
                </span>
              ))}
              {f.appIds?.slice(0, 4).map((id) => (
                <span className="tag" key={String(id)}>
                  app {String(id)}
                </span>
              ))}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * The authority graph.
 *
 * The point this makes visually is that one address reaches well past its
 * own balance. Before a migration a single Ed25519 key holds all of it; after
 * one, roles sit behind the new key while accounts rekeyed to this address
 * are still signed for by the original, which is why their edges say so.
 */
export function AuthorityGraph({ e }: { e: AccountExposure }) {
  const targets = e.edges.filter((edge) => edge.from === e.address);
  if (!targets.length) return null;

  const shown = targets.slice(0, 12);
  const rowH = 34;
  const height = Math.max(140, shown.length * rowH + 40);
  const midY = height / 2;
  const leftX = 96;
  const rightX = 430;

  // A reference is drawn apart from a capability: its permissions are
  // unverified, so it gets no severity colour. A capability exercised by a
  // key established as post-quantum is drawn as protected, not as a threat.
  const color = (edge: AuthorityEdge) =>
    edge.basis === 'reference'
      ? 'var(--text-faint)'
      : edge.protected
        ? 'var(--safe)'
        : edge.relation === 'asa-clawback' || edge.relation === 'controls-account'
          ? 'var(--critical)'
          : edge.relation === 'asa-freeze' || edge.relation === 'asa-manager'
            ? 'var(--high)'
            : 'var(--low)';

  return (
    <div className="graph">
      {/* Labels start at rightX + 12 and run to 46 characters at 12px, so
          the box has to be wide enough to hold them without clipping. */}
      <svg width="100%" height={height} viewBox={`0 0 780 ${height}`} aria-hidden="true">
        {shown.map((edge, i) => {
          const y = 24 + i * rowH + rowH / 2;
          const c = color(edge);
          const reference = edge.basis === 'reference';
          return (
            <g key={i} data-basis={edge.basis} data-protected={edge.protected ? 'yes' : 'no'}>
              <path
                d={`M ${leftX} ${midY} C ${leftX + 110} ${midY}, ${rightX - 110} ${y}, ${rightX} ${y}`}
                fill="none"
                stroke={c}
                strokeWidth="1.3"
                strokeDasharray={reference ? '4 4' : undefined}
                opacity="0.55"
              />
              <circle cx={rightX} cy={y} r="3.5" fill={reference ? 'none' : c} stroke={c} />
              <text
                x={rightX + 12}
                y={reference ? y - 1 : y + 4}
                fill="var(--text-dim)"
                fontSize="12"
                fontFamily="var(--sans)"
              >
                {edge.label.length > 46
                  ? edge.label.slice(0, 45) + '…'
                  : edge.label}
              </text>
              {reference && (
                <text
                  x={rightX + 12}
                  y={y + 12}
                  fill="var(--text-faint)"
                  fontSize="10.5"
                  fontFamily="var(--sans)"
                >
                  reference: permissions unverified
                </text>
              )}
            </g>
          );
        })}
        <circle
          cx={leftX}
          cy={midY}
          r="26"
          fill="var(--bg-raised)"
          stroke="var(--accent)"
          strokeWidth="1.5"
        />
        <text
          x={leftX}
          y={midY - 2}
          textAnchor="middle"
          fill="var(--accent)"
          fontSize="10"
          fontFamily="var(--mono)"
        >
          {e.address.slice(0, 4)}
        </text>
        <text
          x={leftX}
          y={midY + 10}
          textAnchor="middle"
          fill="var(--text-faint)"
          fontSize="9"
          fontFamily="var(--mono)"
        >
          address
        </text>
      </svg>
      {targets.length > shown.length && (
        <p className="faint graph-more" style={{ fontSize: 13 }} aria-hidden="true">
          and {targets.length - shown.length} more
        </p>
      )}
      {/* Every edge in words, labels uncut. */}
      <ul className="graph-list sr-only">
        {targets.map((edge, i) => (
          <li key={i}>
            {edge.label}
            {edge.basis === 'reference' ? ' (reference: permissions unverified)' : ''}
          </li>
        ))}
      </ul>
    </div>
  );
}
