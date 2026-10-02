#!/usr/bin/env node
/**
 * Built-page smoke check: the production web bundle in a real browser.
 *
 *   npm run build && npm run test:web-smoke
 *
 * Serves `apps/web/dist` with `vite preview` and drives the installed Google
 * Chrome through playwright-core, which downloads no browser. Every request
 * that leaves the page's own origin is answered by the CLI's fixed ledger
 * (`packages/cli/test/fixture-ledger.mjs`) or refused and reported, so no run
 * reaches a network and every run reads the same ledger.
 *
 * It checks only what the jsdom suites cannot: that the built bundle loads and
 * works in a browser. The page loads with nothing logged; MainNet is
 * read-only, with key generation disabled for a classical account, nothing to
 * migrate for a post-quantum one, and recovery phrases limited to test
 * networks in the footer; a scan shows a
 * post-quantum authority with the record that proves it, announces its
 * verdict, and fits a 390 px wide screen; an authority whose history the
 * provider cannot serve is shown as unproven, not safe; an invalid address is
 * refused in an alert. Behaviour is covered by the web offline suite.
 */
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { preview } from 'vite';
import { FIXTURE, TXIDS, serve } from '../packages/cli/test/fixture-ledger.mjs';

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'apps', 'web');

const server = await preview({ root: WEB, logLevel: 'warn', preview: { host: '127.0.0.1' } });
const base = server.resolvedUrls?.local[0];
if (!base) throw new Error('vite preview did not report a local URL');
const browser = await chromium.launch({ channel: 'chrome' });

/** Anything that is not the page or the fixed ledger. */
const problems = [];
let served = 0;

try {
  const page = await browser.newPage();
  page.on('pageerror', (err) => problems.push(`page error: ${err.message}`));
  await page.route('**/*', async (route) => {
    const req = route.request();
    if (req.url().startsWith(base)) return route.continue();
    const res = req.method() === 'GET' ? serve(req.url()) : undefined;
    if (!res) {
      problems.push(`refused ${req.method()} ${req.url()}`);
      return route.abort();
    }
    served++;
    return route.fulfill({
      status: res.status,
      headers: { ...Object.fromEntries(res.headers), 'access-control-allow-origin': '*' },
      body: await res.text(),
    });
  });

  /** @param {string} address */
  const scan = async (address) => {
    await page.getByLabel('Algorand address').fill(address);
    await page.getByRole('button', { name: 'Scan', exact: true }).click();
  };

  /** Console errors before any scan; later ones include the ledger's own failures. */
  const logged = [];
  const onConsole = (/** @type {import('playwright-core').ConsoleMessage} */ m) => {
    if (m.type() === 'error' || m.type() === 'warning') logged.push(m.text());
  };
  page.on('console', onConsole);
  await page.goto(base);
  await page.getByRole('heading', { level: 1, name: /Falcon-1024/ }).waitFor();
  page.off('console', onConsole);
  if (logged.length) problems.push(`logged on load: ${logged.join(' | ')}`);
  console.log(`web smoke: page loaded in Chrome ${browser.version()}`);

  await page.locator('[data-mainnet-read-only]').waitFor();
  await scan(FIXTURE.classical);
  const generate = page.getByRole('button', { name: 'Generate a post-quantum key', exact: true });
  await generate.waitFor();
  if (!(await generate.isDisabled())) problems.push('MainNet key generation is enabled');
  if (await page.locator('[data-recovery-phrase], textarea').count()) problems.push('MainNet shows a secret flow');
  const footer = await page.locator('footer').innerText();
  if (!/On TestNet and LocalNet, the migration panel handles\s+recovery phrases/.test(footer)) {
    problems.push('the footer does not limit recovery phrases to TestNet and LocalNet');
  }
  console.log('web smoke: MainNet scan works with key generation disabled, no secret fields, footer scoped');

  await scan(FIXTURE.postQuantum);
  await page.locator('[data-tone="post-quantum"]', { hasText: TXIDS.postQuantum }).waitFor();
  await page.getByRole('status').filter({ hasText: 'Scan finished: ' }).waitFor({ state: 'attached' });
  await page.getByText('already under post-quantum authority').waitFor();
  if (await generate.count()) problems.push('MainNet offers a key to an account that is already post-quantum');
  // Addresses and transaction ids wrap: nothing is pushed off a phone's screen.
  await page.setViewportSize({ width: 390, height: 844 });
  const width = await page.evaluate(() => document.documentElement.scrollWidth);
  if (width > 390) problems.push(`page is ${width} px wide at a 390 px viewport`);
  await page.setViewportSize({ width: 1280, height: 800 });
  console.log('web smoke: post-quantum authority shown with its evidence, nothing to migrate, announced, and fits 390 px');

  await scan(FIXTURE.unavailable);
  await page.locator('[data-tone="unproven"]', { hasText: 'could not be checked' }).waitFor();
  console.log('web smoke: unavailable history shown as unproven');

  await scan('not an address');
  await page.getByRole('alert').filter({ hasText: 'That is not a valid Algorand address.' }).waitFor();
  console.log('web smoke: invalid address refused in an alert');
} catch (err) {
  problems.push(String(err));
} finally {
  await browser.close();
  await server.close();
}

if (problems.length > 0 || served === 0) {
  console.error(`web smoke failed (${served} fixture responses):\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log(`web smoke: 5 checks passed, ${served} fixture responses, nothing refused`);
