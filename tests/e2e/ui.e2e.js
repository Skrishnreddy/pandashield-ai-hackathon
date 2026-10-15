// Browser end-to-end tests (Playwright + Chromium) for the main workflow,
// persistence across reloads, mobile layout and console errors.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const BASE = process.env.E2E_BASE_URL || 'http://127.0.0.1:8090';
const SHOTS = path.resolve(process.env.E2E_SHOTS || 'test-results/e2e');
fs.mkdirSync(SHOTS, { recursive: true });

let browser;
const consoleErrors = [];
const serverErrors = [];

before(async () => { browser = await chromium.launch(); });
after(async () => { await browser.close(); });

function watch(page) {
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('pageerror', (e) => consoleErrors.push(String(e)));
  page.on('response', (r) => { if (r.status() >= 500) serverErrors.push(`${r.status()} ${r.url()}`); });
}

test('landing page renders sign-in and explains the product', async () => {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  watch(page);
  await page.goto(BASE);
  await page.getByRole('heading', { name: /AI security analyst/i }).waitFor();
  assert.ok(await page.getByRole('button', { name: /Sign in with Google/i }).isVisible());
  await page.screenshot({ path: `${SHOTS}/01-landing-desktop.png` });
  await page.close();
});

test('main workflow: sign in, scan, review, triage actions, ask, reload, report', async () => {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  watch(page);
  await page.goto(BASE);
  await page.getByTestId('emulator-signin').click();
  await page.getByRole('heading', { name: /security scan/i }).waitFor();
  await page.screenshot({ path: `${SHOTS}/02-new-scan.png` });

  await page.getByTestId('run-scan').click();
  await page.waitForURL(/#\/scan\//, { timeout: 60000 });
  await page.getByText('Gemini analysis').waitFor();
  await page.getByText(/\[TEST STUB\] \d+ findings reviewed/).waitFor();
  const rows = page.locator('.finding-row');
  assert.ok((await rows.count()) >= 20, 'expected the planted vulnerabilities');
  await page.screenshot({ path: `${SHOTS}/03-scan-results.png` });

  await rows.first().click();
  await page.locator('.detail').getByText('[TEST STUB] explanation', { exact: false }).waitFor();
  await page.locator('.detail').getByRole('button', { name: 'Mark fixed' }).click();
  await page.locator('.detail .chip.on', { hasText: 'Mark fixed' }).waitFor();
  await page.locator('.detail input[aria-label="Question for Gemini"]').fill('How do I test this?');
  await page.locator('.detail').getByRole('button', { name: 'Ask' }).click();
  await page.locator('.detail').getByText('[TEST STUB] answer to: How do I test this?').waitFor();
  await page.screenshot({ path: `${SHOTS}/04-finding-detail.png` });

  // Report download
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download report' }).click()]);
  const md = fs.readFileSync(await download.path(), 'utf8');
  assert.match(md, /PandaShield AI Security Report/);
  assert.ok(!md.includes('IOSFODNN7EXAMPLE'), 'report must not contain raw secrets');

  // Persistence: reload and confirm history (Firestore) and saved status/Q&A (API)
  const url = page.url();
  await page.reload();
  await page.locator('.history a').first().waitFor();
  assert.ok((await page.locator('.history a').count()) >= 1);
  await page.goto(url);
  await page.locator('.finding-row').first().waitFor();
  await page.selectOption('select[aria-label="Status"]', 'fixed');
  assert.equal(await page.locator('.finding-row').count(), 1, 'the fixed finding persisted');
  await page.locator('.finding-row').first().click();
  await page.locator('.detail').getByText('[TEST STUB] answer to: How do I test this?').waitFor();

  // System status page
  await page.goto(`${BASE}/#/status`);
  await page.getByText(/Healthy · revision/).waitFor();
  await ctx.close();
});

test('input validation is shown to the user', async () => {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await ctx.newPage();
  watch(page);
  await page.goto(BASE);
  await page.getByTestId('emulator-signin').click();
  await page.getByRole('tab', { name: 'Paste code' }).click();
  await page.locator('textarea.mono').fill('const ok = 1;');
  await page.locator('input[placeholder="app.py"]').fill('../../etc/passwd');
  await page.getByTestId('run-scan').click();
  await page.getByRole('alert').getByText(/may not contain/).waitFor();
  await ctx.close();
});

test('mobile layout has no horizontal overflow and the history drawer works', async () => {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  watch(page);
  await page.goto(BASE);
  await page.getByRole('heading', { name: /AI security analyst/i }).waitFor();
  await page.screenshot({ path: `${SHOTS}/05-landing-mobile.png`, fullPage: false });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'landing overflows horizontally');
  await page.getByTestId('emulator-signin').click();
  await page.getByRole('heading', { name: /security scan/i }).waitFor();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'app overflows horizontally');
  await page.getByRole('button', { name: 'Open scan history' }).click();
  await page.locator('.sidebar.open').waitFor();
  await page.locator('.history a').first().click();
  await page.locator('.finding-row').first().waitFor();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'scan view overflows horizontally');
  await page.screenshot({ path: `${SHOTS}/06-scan-mobile.png` });
  await ctx.close();
});

test('no browser console errors or server errors occurred during the tests', () => {
  assert.deepEqual(serverErrors, []);
  // Expected 400s: the deliberate invalid-path test, and the emulator sign-in
  // probing for an existing test user before creating it.
  const relevant = consoleErrors.filter((e) => !/favicon|fonts\.g(oogle|static)|ERR_TUNNEL|net::ERR_|status of 400/i.test(e));
  if (relevant.length) console.log('CONSOLE ERRORS:', JSON.stringify(relevant, null, 1));
  assert.deepEqual(relevant, []);
});
