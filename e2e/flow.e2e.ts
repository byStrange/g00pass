// Browser end-to-end run of the built app (dist/) against an in-memory GitHub.
//   npm run e2e        (builds first; screenshots go to docs/e2e/)
// Two browser profiles: the global admin and a newcomer. Flow: pin anchors,
// decrypt, invite, enroll + request, approve, newcomer decrypts, remove
// member + rotation checklist.
import { mkdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { extname, join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Browser, BrowserContext, Locator, Page } from 'playwright';
import { buildDemoStore, type DemoStore } from '../scripts/seed/demo';
import { FakeGitHubServer } from './fake-github';

const { chromium } = createRequire(import.meta.url)('playwright') as typeof import('playwright');

const APP = 'https://vault.test/';
const STORE = 'acme/demo-store';
const REQUESTS = 'acme/demo-requests';
const ADMIN_TOKEN = 'github_pat_ADMIN_' + 'a'.repeat(40);
const INVITE_TOKEN = 'github_pat_INVITE_' + 'b'.repeat(40);
const READER_TOKEN = 'github_pat_READER_' + 'c'.repeat(40);
const dist = resolve('dist');
const shots = resolve('docs/e2e');

const TYPES: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png' };
const csp = readFileSync(join(dist, '_headers'), 'utf8').split('\n').find((l) => /Content-Security-Policy:/.test(l))!.replace(/^\s*Content-Security-Policy:\s*/, '').trim();

let browser: Browser;
let gh: FakeGitHubServer;
let demo: DemoStore;
const errors: string[] = [];

async function profile(): Promise<{ ctx: BrowserContext; page: Page }> {
  const ctx = await browser.newContext({ serviceWorkers: 'block', deviceScaleFactor: 2, viewport: { width: 900, height: 1000 } });
  await ctx.route('https://api.github.com/**', async (route) => {
    const req = route.request();
    const res = gh.handle(req.method(), req.url(), await req.allHeaders(), req.postData());
    await route.fulfill({ status: res.status, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(res.body) });
  });
  await ctx.route(`${APP}**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    const file = join(dist, path === '/' ? 'index.html' : path);
    try {
      await route.fulfill({ status: 200, contentType: TYPES[extname(file)] ?? 'application/octet-stream', headers: { 'content-security-policy': csp, 'referrer-policy': 'no-referrer' }, body: readFileSync(file) });
    } catch {
      await route.fulfill({ status: 404, body: 'not found' });
    }
  });
  const page = await ctx.newPage();
  pages.push(page);
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => m.type() === 'error' && !/Failed to load resource/.test(m.text()) && errors.push(`console: ${m.text()}`));
  // Expected 404s: GitHub probes (over-scope check) and denied reads; anything else is a bug.
  page.on('response', (r) => r.status() === 404 && !r.url().startsWith('https://api.github.com/') && errors.push(`404: ${r.url()}`));
  return { ctx, page };
}

const status = (p: Page) => p.locator('p.status');
async function waitStatus(p: Page, re: RegExp, timeout = 60_000) {
  await expect.poll(async () => (await status(p).textContent()) ?? '', { timeout, interval: 200 }).toMatch(re);
}
const card = (p: Page, title: string) => p.locator('section.card', { has: p.locator('h2', { hasText: title }) });
const pages: Page[] = [];
async function count(l: Locator, n: number, timeout = 30_000) {
  try {
    await expect.poll(() => l.count(), { timeout, interval: 200 }).toBe(n);
  } catch (e) {
    for (const [i, pg] of pages.entries()) {
      console.error(`[page ${i}] status: ${await pg.locator('p.status').textContent()}`);
      await pg.screenshot({ path: join(shots, `failure-${i}.png`), fullPage: true });
    }
    console.error(gh.log.slice(-15).join('\n'));
    throw e;
  }
}
const shot = (l: Locator, name: string) => l.screenshot({ path: join(shots, `${name}.png`) });

async function configure(p: Page, token: string) {
  await p.fill('input[name=owner]', 'acme');
  await p.fill('input[name=repo]', 'demo-store');
  await p.fill('input[name=branch]', 'main');
  await p.fill('input[name=requestsRepo]', REQUESTS);
  await p.fill('input[name=token]', token);
  await p.getByRole('button', { name: 'Save & load' }).click();
}

async function unlock(p: Page, passphrase: string) {
  const c = card(p, 'Device key');
  await c.getByPlaceholder('Passphrase').fill(passphrase);
  await c.getByRole('button', { name: 'Unlock' }).click();
  await waitStatus(p, /Unlocked/);
}

async function reveal(p: Page, entry: string): Promise<string> {
  await card(p, 'Entries').getByRole('button', { name: entry, exact: true }).click();
  const view = p.locator('section.entry');
  await view.getByRole('button', { name: 'Reveal / hide' }).click();
  return (await view.locator('code.secret').textContent()) ?? '';
}

beforeAll(async () => {
  mkdirSync(shots, { recursive: true });
  gh = new FakeGitHubServer();
  demo = await buildDemoStore({ storeId: 'acme/demo-store|' });
  gh.seed(STORE, 'main', demo.files);
  gh.repo(REQUESTS);
  gh.tokens.set(ADMIN_TOKEN, { [STORE]: { contents: 'write' }, [REQUESTS]: { issues: true } });
  gh.tokens.set(INVITE_TOKEN, { [REQUESTS]: { issues: true } });
  gh.tokens.set(READER_TOKEN, { [STORE]: { contents: 'read' } });
  browser = await chromium.launch();
}, 120_000);
afterAll(async () => {
  await browser?.close();
});

describe('g00pass in the browser (demo store, fake GitHub)', () => {
  it('admin pins anchors, decrypts, invites; newcomer enrolls; admin approves; newcomer decrypts; admin removes them', async () => {
    const admin = demo.identities.find((i) => i.role === 'admin')!;
    const A = await profile();
    const p = A.page;

    // ---- admin: connect, pin the global admins, import key, decrypt ----
    await p.goto(APP);
    await configure(p, ADMIN_TOKEN);
    const trust = card(p, 'Recipient trust');
    await trust.getByText('I compared these fingerprints with my admin and they match.').click();
    await shot(trust, '01-admin-pin-anchors');
    await trust.getByRole('button', { name: 'Pin these global admins' }).click();
    await count(trust.locator('li.ok'), 4);
    const keyCard = card(p, 'Device key');
    await keyCard.locator('textarea').fill(admin.privateKey);
    await keyCard.getByRole('button', { name: 'Store key' }).click();
    await waitStatus(p, /Key stored/);
    await unlock(p, admin.passphrase);
    expect(await reveal(p, 'team/wiki')).toBe('correct-horse-battery');
    await shot(p.locator('section.entry'), '02-admin-decrypt');

    // ---- admin: invite someone to team/ ----
    const folders = card(p, 'Manage folder');
    await folders.getByLabel('Folder', { exact: true }).selectOption('team');
    await folders.getByRole('button', { name: 'Open' }).click();
    await folders.getByText('Invite someone to team/').click();
    await folders.getByPlaceholder(/github_pat_/).fill(INVITE_TOKEN);
    await folders.getByRole('button', { name: 'Check token & create invite' }).click();
    const linkBox = folders.locator('textarea[readonly]');
    await count(linkBox, 1, 30_000);
    const link = await linkBox.inputValue();
    expect(link.startsWith(`${APP}#g00pass-invite=`)).toBe(true);
    await shot(folders, '03-admin-invite');

    // ---- newcomer: open the invite, pin anchors, create key, request ----
    const B = await profile();
    const q = B.page;
    await q.goto(link);
    expect(new URL(q.url()).hash).toBe(''); // fragment stripped at once
    const inv = card(q, 'You were invited');
    expect((await inv.locator('li.mono').allTextContents()).map((t) => t.replace(/\s+/g, ''))).toEqual([admin.fingerprint]);
    await shot(inv, '04-newcomer-invite');
    await inv.getByText('I compared these fingerprints with my admin and they match.').click();
    await inv.getByRole('button', { name: 'Accept invite' }).click();
    await waitStatus(q, /Invite accepted/);
    const enroll = card(q, 'Get access');
    const NEW_PASS = 'newcomer passphrase 4321';
    await enroll.getByLabel('Name').fill('Nora Newcomer');
    await enroll.getByLabel('E-mail').fill('nora@demo.g00pass.invalid');
    await enroll.getByLabel(/^Passphrase/).fill(NEW_PASS);
    await enroll.getByLabel('Confirm passphrase').fill(NEW_PASS);
    await enroll.getByRole('button', { name: 'Generate key' }).click();
    await waitStatus(q, /Key created/, 120_000);
    const fpr = ((await enroll.locator('.mono.fpr').textContent()) ?? '').replace(/\s+/g, '');
    expect(fpr).toMatch(/^[0-9A-F]{40}$/);
    expect(await enroll.getByLabel('Folder', { exact: true }).inputValue()).toBe('team');
    await enroll.getByLabel(/Key passphrase/).fill(NEW_PASS);
    await enroll.getByRole('button', { name: 'Sign & submit request' }).click();
    await waitStatus(q, /Request submitted/);
    await shot(enroll, '05-newcomer-request');
    expect(gh.repo(REQUESTS).issues).toHaveLength(1);
    expect(gh.repo(REQUESTS).issues[0]!.body).not.toContain('github_pat_');

    // ---- admin: inbox, confirm fingerprint, approve ----
    const inbox = card(p, 'Access requests');
    await inbox.getByRole('button', { name: 'Load access requests' }).click();
    const item = inbox.locator('article.request');
    await count(item, 1, 30_000);
    await count(item.locator('.badge.ok', { hasText: 'Invited' }), 1);
    await item.getByPlaceholder('last 16 characters').fill(fpr.slice(-16));
    await item.getByText('I reviewed the recipient change above').click();
    await shot(item, '06-admin-approve');
    await item.getByRole('button', { name: 'Approve' }).click();
    await waitStatus(p, /Approved in/, 60_000);
    const issue = gh.repo(REQUESTS).issues[0]!;
    expect(issue.state).toBe('closed');
    expect(issue.labels).toContain('g00pass:approved');
    const files = gh.head(STORE);
    expect([...files.keys()].some((k) => k.startsWith('.g00pass/invites/'))).toBe(false); // invite consumed
    expect(new TextDecoder().decode(files.get('team/.gpg-id')!)).toContain(fpr);

    // ---- newcomer: reader token, decrypt ----
    await configure(q, READER_TOKEN);
    await waitStatus(q, /Loaded \d+ entries/);
    await unlock(q, NEW_PASS);
    expect(await reveal(q, 'team/wiki')).toBe('correct-horse-battery');
    await shot(q.locator('section.entry'), '07-newcomer-decrypts');

    // ---- admin: remove the newcomer, rotation checklist ----
    await p.getByRole('button', { name: 'Save & load' }).click();
    await waitStatus(p, /Loaded/);
    await folders.getByLabel('Folder', { exact: true }).selectOption('team');
    await folders.getByRole('button', { name: 'Open' }).click();
    const row = folders.locator('li', { hasText: 'Nora Newcomer' });
    await row.getByRole('button', { name: 'Remove…' }).click();
    const box = folders.locator('div.request');
    await box.getByText('I reviewed this exact change and approve it.').click();
    await shot(box, '08-admin-remove');
    await box.getByRole('button', { name: 'Remove member' }).click();
    await waitStatus(p, /Removed/, 60_000);
    await folders.getByText(/Rotate after removing/).first().waitFor({ state: 'visible', timeout: 30_000 });
    await shot(folders.locator('div.checklist'), '09-rotation-checklist');
    expect(new TextDecoder().decode(gh.head(STORE).get('team/.gpg-id')!)).not.toContain(fpr);

    // The newcomer can no longer decrypt the (re-encrypted) entry.
    await q.getByRole('button', { name: 'Save & load' }).click();
    await waitStatus(q, /Loaded/);
    await card(q, 'Entries').getByRole('button', { name: 'team/wiki', exact: true }).click();
    await waitStatus(q, /Could not decrypt/);

    expect(errors.filter((e) => !/favicon|sw\.js|ServiceWorker/i.test(e))).toEqual([]);
  }, 600_000);
});
