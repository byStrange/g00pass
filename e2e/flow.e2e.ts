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
  page.on('dialog', (d) => void d.accept());
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
const shot = (p: Page, name: string) => p.screenshot({ path: join(shots, `${name}.png`) });


const screenTitle = (p: Page) => p.locator('.screen-title');
async function onScreen(p: Page, title: RegExp, timeout = 60_000) {
  await expect.poll(async () => ((await screenTitle(p).count()) ? ((await screenTitle(p).first().textContent()) ?? '') : ''), { timeout, interval: 200 }).toMatch(title);
}
async function tabTo(p: Page, name: string) {
  await p.getByRole('tab', { name: new RegExp(`^${name}`) }).click();
}
/** Wait until the requests panel finished loading (its Refresh button is enabled again). */
async function inboxIdle(p: Page) {
  await expect.poll(() => p.locator('.inbox').getByRole('button', { name: 'Refresh' }).isEnabled(), { timeout: 30_000, interval: 200 }).toBe(true);
}
async function unlock(p: Page, passphrase: string) {
  await onScreen(p, /Unlock/);
  await p.getByLabel('Passphrase').fill(passphrase);
  await p.getByRole('button', { name: 'Unlock' }).click();
  await p.getByRole('tab', { name: /^Secrets/ }).waitFor({ timeout: 60_000 });
}
async function reveal(p: Page, entry: string): Promise<string> {
  await p.getByRole('button', { name: entry, exact: true }).click();
  const detail = p.locator('section.detail');
  await detail.getByRole('button', { name: 'Show' }).click();
  return (await detail.locator('code.secret').textContent()) ?? '';
}
async function openFolder(p: Page, folder: string) {
  await tabTo(p, 'Access');
  await p.locator('.folder-btn', { hasText: new RegExp(`^${folder}$`) }).click();
  await p.locator('.folder-admin h3').first().waitFor({ timeout: 30_000 });
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
  it('admin sets up, decrypts, invites; newcomer joins; admin approves; newcomer decrypts; admin removes them', async () => {
    const admin = demo.identities.find((i) => i.role === 'admin')!;
    const A = await profile();
    const p = A.page;

    // ---- admin: setup wizard ----
    await p.goto(APP);
    await onScreen(p, /Connect your password store/);
    await p.getByLabel('Store repository').fill(STORE);
    await p.getByLabel('GitHub token').fill(ADMIN_TOKEN);
    await p.getByText('More settings').click();
    await p.getByLabel('Requests repository').fill(REQUESTS);
    await shot(p, '01-setup-connect');
    await p.getByRole('button', { name: 'Connect' }).click();

    await onScreen(p, /Check who the admins are/);
    await p.getByText('I compared the fingerprints and they match.').click();
    await shot(p, '02-setup-verify-admins');
    await p.getByRole('button', { name: /These are my admins/ }).click();

    await onScreen(p, /Your personal key/);
    await p.getByLabel('Paste your private key').fill(admin.privateKey);
    await shot(p, '03-setup-key');
    await p.getByRole('button', { name: 'Use this key' }).click();
    await unlock(p, admin.passphrase);
    expect(await reveal(p, 'team/wiki')).toBe('correct-horse-battery');
    await shot(p, '04-secrets');

    // ---- admin: add a secret, then change its password ----
    await p.getByRole('button', { name: '+ New secret' }).click();
    const detail = p.locator('section.detail');
    await detail.getByLabel('Folder', { exact: true }).selectOption('team');
    await detail.getByLabel('Name', { exact: true }).fill('github');
    await detail.getByRole('button', { name: 'Generate' }).click();
    expect((await detail.getByLabel('Password', { exact: true }).inputValue()).length).toBe(20);
    await detail.getByLabel('Notes').fill('user: deploy-bot');
    await detail.locator('.readers').getByText(/Demo Member/).waitFor();
    await shot(p, '05-new-secret');
    await detail.getByRole('button', { name: 'Add secret' }).click();
    await waitStatus(p, /Added team\/github/);
    await detail.getByRole('heading', { name: 'team/github' }).waitFor();
    await detail.getByRole('button', { name: 'Edit' }).click();
    await detail.getByLabel('Password', { exact: true }).fill('github-pass-v2');
    await detail.getByRole('button', { name: 'Save changes' }).click();
    await waitStatus(p, /recorded as a rotation/);
    expect(gh.head(STORE).has('team/.g00pass-rotation.gpg')).toBe(true); // the change is recorded for the password checklist

    // ---- admin: invite someone to team/ ----
    await openFolder(p, 'team/');
    await p.getByText('Invite someone to team/').click();
    await p.getByPlaceholder(/github_pat_/).fill(INVITE_TOKEN);
    await p.getByRole('button', { name: 'Check token & create invite' }).click();
    const linkBox = p.locator('textarea[readonly]');
    await count(linkBox, 1);
    const link = await linkBox.inputValue();
    expect(link.startsWith(`${APP}#g00pass-invite=`)).toBe(true);
    await shot(p, '06-access-invite');

    // ---- newcomer: invite flow ----
    const B = await profile();
    const q = B.page;
    await q.goto(link);
    expect(new URL(q.url()).hash).toBe(''); // fragment stripped at once
    await onScreen(q, /invited/);
    expect((await q.locator('.admin-list .mono').allTextContents()).map((t) => t.replace(/\s+/g, ''))).toEqual([admin.fingerprint]);
    await shot(q, '07-join-check-admins');
    await q.getByText('The fingerprint matches what my admin told me.').click();
    await q.getByRole('button', { name: 'Continue' }).click();

    await onScreen(q, /Create your key/);
    const NEW_PASS = 'newcomer passphrase 4321';
    await q.getByLabel('Your name').fill('Nora Newcomer');
    await q.getByLabel('E-mail').fill('nora@demo.g00pass.invalid');
    await q.getByLabel('Passphrase', { exact: true }).fill(NEW_PASS);
    await q.getByLabel('Repeat passphrase').fill(NEW_PASS);
    await q.getByRole('button', { name: 'Create my key' }).click();

    await onScreen(q, /Ask for access/, 120_000);
    expect(await q.getByLabel('Folder', { exact: true }).inputValue()).toBe('team');
    await q.getByLabel('Your key passphrase').fill(NEW_PASS);
    await q.getByRole('button', { name: 'Send request' }).click();
    await onScreen(q, /Waiting for approval/);
    const tail = ((await q.locator('.fpr-tail').textContent()) ?? '').replace(/\s+/g, '');
    expect(tail).toMatch(/^[0-9A-F]{16}$/);
    await shot(q, '08-join-waiting');
    expect(gh.repo(REQUESTS).issues).toHaveLength(1);
    expect(gh.repo(REQUESTS).issues[0]!.body).not.toContain('github_pat_');

    // ---- admin: approve ----
    await tabTo(p, 'Access');
    await inboxIdle(p);
    await p.locator('.inbox').getByRole('button', { name: 'Refresh' }).click();
    await inboxIdle(p);
    const item = p.locator('article.request');
    await count(item, 1);
    await count(item.locator('.badge.ok', { hasText: 'Invited' }), 1);
    await item.getByPlaceholder('last 16 characters').fill(tail);
    await item.getByText('I reviewed the member change above').click();
    await shot(p, '09-access-approve');
    await item.getByRole('button', { name: 'Approve' }).click();
    await waitStatus(p, /Approved in/);
    const issue = gh.repo(REQUESTS).issues[0]!;
    expect(issue.state).toBe('closed');
    expect(issue.labels).toContain('g00pass:approved');
    expect([...gh.head(STORE).keys()].some((k) => k.startsWith('.g00pass/invites/'))).toBe(false); // invite consumed

    // ---- newcomer: notices the approval, connects, decrypts ----
    await q.getByRole('button', { name: 'Check now' }).click();
    await onScreen(q, /You are approved/);
    await shot(q, '10-join-connect');
    await q.getByLabel('Read token for the store').fill(READER_TOKEN);
    await q.getByRole('button', { name: 'Connect' }).click();
    await unlock(q, NEW_PASS);
    expect(await reveal(q, 'team/wiki')).toBe('correct-horse-battery');
    expect(await reveal(q, 'team/github')).toBe('github-pass-v2');
    await shot(q, '11-newcomer-secrets');

    // ---- admin: remove the newcomer, rotation checklist ----
    await openFolder(p, 'team/');
    await p.locator('.folder-admin li', { hasText: 'Nora Newcomer' }).getByRole('button', { name: 'Remove…' }).click();
    const box = p.locator('.folder-admin div.request');
    await box.getByText('I reviewed this exact change and approve it.').click();
    await box.getByRole('button', { name: 'Remove member' }).click();
    await waitStatus(p, /Removed/);
    await p.getByText(/Change these passwords/).first().waitFor({ state: 'visible', timeout: 30_000 });
    expect(await p.locator('.checklist').textContent()).toContain('team/github');
    await shot(p, '12-access-rotation');

    // ---- admin: delete the secret ----
    await tabTo(p, 'Secrets');
    await p.getByRole('button', { name: 'team/github', exact: true }).click();
    await p.locator('section.detail').getByRole('button', { name: 'Delete' }).click();
    await waitStatus(p, /Deleted team\/github/);
    expect(gh.head(STORE).has('team/github.gpg')).toBe(false);
    expect(new TextDecoder().decode(gh.head(STORE).get('team/.gpg-id')!)).not.toContain(tail);

    // The newcomer reloads: no folder is readable any more.
    await q.reload();
    await unlock(q, NEW_PASS);
    await q.getByText("You don't have access to any folder yet").waitFor({ timeout: 30_000 });

    expect(errors).toEqual([]);
  }, 600_000);
});
