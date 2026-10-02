/**
 * The web views, rendered (CORE-03).
 *
 * Each exposure comes from the real core model run against a scripted
 * offline provider, and each component is rendered to static markup exactly
 * as React would render it in the page. These check what a reader sees:
 * uncertainty is shown, references are drawn as references, and protected
 * reach is never dressed up as exposure.
 */
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ReactElement } from 'react';
import { analyzeAccount, assessAuthority, SCORE_SCOPE, type AccountExposure } from '@falqoner/core';
import { txid } from '../../../packages/core/test/fixtures';
import {
  accountRecord,
  addressFor,
  falconAuthority,
  falconRecord,
  fakeProvider,
  httpError,
  onCurveAddress,
  type FakeSpec,
} from '../../../packages/core/test/fake-provider';
import {
  AuthorityBanner,
  AuthorityGraph,
  CoverageNote,
  Findings,
  ReachNote,
  Stats,
  Verdict,
} from '../src/components';

async function exposure(
  address: string,
  spec: FakeSpec,
  options: Parameters<typeof analyzeAccount>[2] = {},
): Promise<AccountExposure> {
  return analyzeAccount(fakeProvider(spec).clients, address, options);
}

const html = (el: ReactElement) => renderToStaticMarkup(el);

/** What a reader sees: the markup's text, entities decoded, spacing collapsed. */
function text(el: ReactElement): string {
  return html(el)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    // Decode ampersands last so literal entity text is not decoded twice.
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

it('preserves literal entity text when reading rendered markup', () => {
  const literal = '&lt; &gt; &amp; &quot; &#x27; &amp;lt; <tag> "quoted"';
  expect(text(<span>{literal}</span>)).toBe(literal);
});

// A post-quantum address, signing for itself and for one protected account.
const C = falconAuthority(71);
const B = addressFor('web protected incoming');
const signer = () =>
  exposure(C.address, {
    accounts: {
      [C.address]: { amount: 1_000_000n },
      [B]: { amount: 4_000_000n, authAddr: C.address },
    },
    history: { [C.address]: [falconRecord('WEB-C-SELF', C.address, C)] },
  });

// A classical account that created an application naming nobody.
const K = onCurveAddress('web app creator');
const appCreator = () =>
  exposure(K, {
    accounts: { [K]: { amount: 5_000_000n, createdApps: [55n] } },
    apps: { '55': { id: 55n, params: { creator: K, globalState: [] } } },
  });

// A classical account whose incoming search fails on its second page.
const P = onCurveAddress('web partial search');
const partialSearch = () =>
  exposure(P, {
    accounts: { [P]: { amount: 5_000_000n } },
    incoming: {
      [P]: [
        { accounts: [accountRecord(addressFor('web page one'))], 'next-token': 'n' },
        httpError(503),
      ],
    },
  });

// A classical account holding clawback over an asset it created.
const Q = onCurveAddress('web clawback');
const clawback = () =>
  exposure(Q, {
    accounts: {
      [Q]: {
        amount: 5_000_000n,
        createdAssets: [
          { index: 6n, params: { creator: Q, manager: Q, clawback: Q, unitName: 'CLW', total: 5n, decimals: 0 } },
        ],
      },
    },
  });

// An account holding nothing, whose named asset is answered with a record for
// another asset (one that would make it clawback), and whose named
// application's state cannot be read.
const U = onCurveAddress('web unusable records');
const unusable = () =>
  exposure(
    U,
    {
      accounts: { [U]: { amount: 0n } },
      assets: {
        '9': { index: 10n, params: { creator: addressFor('web creator'), total: 1n, decimals: 0, clawback: U } },
      },
      apps: { '77': { id: 77n, params: { creator: addressFor('web creator'), globalState: [null] } } },
    },
    { assetIds: [9n], appIds: [77n] },
  );

/**
 * The authority banner (PQ-04), for every class and every way evidence can
 * fail. The labels are the ones the CLI tests expect, word for word: both
 * views print core's `authorityVerdict`, so a change to one is a change to
 * both.
 */
describe('the authority banner', () => {
  const self = (label: string, sender: string, signature: unknown) => ({
    id: txid(label),
    sender,
    'confirmed-round': 42,
    signature,
  });
  const M = falconAuthority(73).address;
  const L = falconAuthority(75).address;
  const H = falconAuthority(77).address;
  const R = falconAuthority(79);
  const rejected = falconRecord('WEB-REJECTED', R.address, R) as any;
  rejected.signature.pqsig.scheme = 'f9';

  // [case, address, provider, tone, the shared label, whether a record is shown and how]
  const CASES: Array<[string, string, FakeSpec, string, string, string | null]> = [
    ['post-quantum', C.address, { history: { [C.address]: [falconRecord('WEB-C-SELF', C.address, C)] } },
      'pq', 'Post-quantum, on a provider-confirmed record', 'evidence:'],
    ['classical by shape', K, {}, 'bad', 'Classical, by address shape: on the Ed25519 curve', null],
    ['a multisig record', M, { history: { [M]: [self('WEB-MSIG', M, { multisig: { threshold: 2, subsignature: [{}, {}, {}] } })] } },
      'bad', 'Classical multisignature, on a provider-confirmed record', 'evidence:'],
    ['a logic-signature record', L, { history: { [L]: [self('WEB-LSIG', L, { logicsig: { logic: 'ASABASI=' } })] } },
      'warn', 'Logic signature, safety unproven', 'evidence:'],
    ['no record', H, {}, 'warn', 'Hash-derived, type unconfirmed', null],
    ['only a rejected record', R.address, { history: { [R.address]: [rejected] } },
      'warn', 'Hash-derived, a record rejected', 'rejected record:'],
    ['a malformed response', H, { history: { [H]: 'not a list' as any } }, 'warn', 'Could not be checked', null],
    ['no indexer', H, { noIndexer: true }, 'warn', 'Could not be checked', null],
  ];

  it.each(CASES)('%s', async (_name, address, spec, tone, label, record) => {
    const a = await assessAuthority(fakeProvider(spec).clients, address, undefined);
    const markup = html(<AuthorityBanner a={a} />);
    expect(markup).toContain(`class="authority ${tone}"`);
    expect(markup).toContain(`<h4>${label}</h4>`);
    const t = text(<AuthorityBanner a={a} />);
    if (record) expect(t).toContain(`${record} ${a.evidenceTxId}`);
    else expect(t).not.toMatch(/evidence:|rejected record:/);
    if (record === 'rejected record:') expect(t).not.toContain('evidence:');
  });
});

describe('the verdict', () => {
  it('leads a complete, clean verdict with "No exposure found"', async () => {
    const t = text(<Verdict e={await signer()} />);
    expect(t).toContain('No exposure found');
    expect(t).not.toContain('Not exposed');
  });

  it('marks a score as a lower bound while anything is unverified', async () => {
    for (const e of [await appCreator(), await partialSearch()]) {
      const t = text(<Verdict e={e} />);
      expect(t).toContain(`${e.risk.score}+`);
      expect(t).toContain('exposure, at least');
      expect(t).toContain('This is not a safe verdict.');
    }
  });

  it('never shows unusable records as a clean verdict', async () => {
    const t = text(<Verdict e={await unusable()} />);
    expect(t).toContain('Exposure not verified');
    expect(t).not.toContain('No exposure found');
    expect(t).toContain('1 named asset record was unusable');
    expect(t).toContain('1 application record was unusable');
  });
});

describe('unusable records', () => {
  it('marks each check an invalid response, with its reason', async () => {
    const e = await unusable();
    const markup = html(<CoverageNote e={e} />);
    expect(markup).toContain('callout coverage warn');
    expect(markup).toMatch(/data-check="assets".*?class="coverage-status short">invalid response</);
    expect(markup).toMatch(/data-check="apps".*?class="coverage-status short">invalid response</);
    const t = text(<CoverageNote e={e} />);
    expect(t).toContain('asset record for a different id');
    expect(t).toContain('malformed global state');
    expect(t).toContain('0 assets · 0 applications read');
  });

  it('draws and claims nothing from a record for another asset', async () => {
    const e = await unusable();
    // Taken at face value, that record would draw a clawback edge and a
    // danger notice. Read for the id asked for, there is nothing to draw.
    expect(html(<AuthorityGraph e={e} />)).toBe('');
    expect(html(<ReachNote e={e} />)).toBe('');
    expect(text(<Findings findings={e.findings} />)).not.toMatch(/Clawback|seize/);
  });
});

describe('what was searched', () => {
  it('shows every check complete, and the scope of the score, for a clean scan', async () => {
    const e = await signer();
    const markup = html(<CoverageNote e={e} />);
    const t = text(<CoverageNote e={e} />);
    for (const label of ['signing history', 'rekeyed to it', 'asset roles', 'app state']) {
      expect(t).toContain(`${label} complete`);
    }
    expect(markup).not.toContain('coverage-status short');
    expect(markup).not.toContain('callout coverage warn');
    expect(t).toContain(SCORE_SCOPE);
  });

  it('shows unverified application permissions as a shortfall', async () => {
    const markup = html(<CoverageNote e={await appCreator()} />);
    expect(markup).toContain('callout coverage warn');
    expect(markup).toMatch(
      /data-check="app-permissions".*?class="coverage-status short">unverified</,
    );
  });

  it('shows an unfinished incoming search as partial, with its reason', async () => {
    const e = await partialSearch();
    const markup = html(<CoverageNote e={e} />);
    expect(markup).toMatch(/data-check="incoming".*?class="coverage-status short">partial</);
    expect(text(<CoverageNote e={e} />)).toContain('before a later request failed (HTTP 503)');
    // A floor, not a count.
    expect(text(<Stats e={e} />)).toContain('1+ (1 exposed) accounts it signs for');
  });
});

describe('reach', () => {
  it('shows protected reach as information, with no asset power claimed', async () => {
    const markup = html(<ReachNote e={await signer()} />);
    expect(markup).toContain('data-reach="protected"');
    expect(markup).not.toContain('danger');
    const t = text(<ReachNote e={await signer()} />);
    expect(t).toContain('signs for 1 account rekeyed to it with a post-quantum key');
    expect(t).not.toMatch(/freeze|seize|Breaking/);
  });

  it('shows exposed reach as a danger, naming the power found', async () => {
    const e = await clawback();
    const markup = html(<ReachNote e={e} />);
    expect(markup).toContain('data-reach="exposed"');
    expect(markup).toContain('callout danger');
    expect(text(<ReachNote e={e} />)).toContain('can seize 1 asset from any holder');
  });
});

describe('the authority graph', () => {
  it('draws an application reference dashed, labelled as unverified', async () => {
    const markup = html(<AuthorityGraph e={await appCreator()} />);
    expect(markup).toContain('data-basis="reference"');
    expect(markup).toContain('stroke-dasharray="4 4"');
    expect(markup).toContain('created app 55');
    expect(markup).toContain('reference: permissions unverified');
    // In words too: read out beside the drawing, shown instead of it on a narrow screen.
    expect(text(<AuthorityGraph e={await appCreator()} />)).toContain(
      'created app 55 (reference: permissions unverified)',
    );
  });

  it('draws signing for a protected account in the protected colour', async () => {
    const markup = html(<AuthorityGraph e={await signer()} />);
    expect(markup).toMatch(/data-protected="yes"><path[^>]*stroke="var\(--safe\)"/);
    expect(markup).not.toContain('var(--critical)');
  });
});

describe('findings and stats', () => {
  it('states an application reference without a privilege, a third-party tag or a promised fix', async () => {
    const e = await appCreator();
    const t = text(<Findings findings={e.findings} />);
    expect(t).toContain('Created 1 application; permissions unverified');
    expect(t).not.toMatch(/can (delete|update)/);
    const markup = html(<Findings findings={e.findings.filter((f) => f.kind === 'app-creator')} />);
    expect(markup).not.toContain('affects third parties');
    expect(markup).not.toContain('fixed by one rekey');
    expect(text(<Stats e={e} />)).toContain('1 app references');
  });
});
