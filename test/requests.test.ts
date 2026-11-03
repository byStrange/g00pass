import { beforeAll, describe, expect, it } from 'vitest';
import { generateKey, readCleartextMessage, readKey, readPrivateKey, verify, type PrivateKey } from 'openpgp';
import {
  GitHubClient,
  REQUEST_LABEL,
  RequestBuildError,
  TokenStore,
  buildAccessRequest,
  checkPassphrase,
  createAccessRequestIssue,
  describeSubmitError,
  generateEnrollmentKey,
  inspectImportedKey,
  resolveRequestsRepo,
  unlockPrivateKey,
  GitHubApiError,
} from '../src/core';

const TOKEN = 'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH';
const PASS = 'correct horse battery staple';

let gen: Awaited<ReturnType<typeof generateEnrollmentKey>>;
let unlocked: PrivateKey;

beforeAll(async () => {
  gen = await generateEnrollmentKey({ name: 'Carol Example', email: 'carol@example.test', passphrase: PASS });
  unlocked = await unlockPrivateKey(gen.privateKeyArmored, PASS);
});

describe('enrollment key generation', () => {
  it('makes a v4 curve25519 key with iterated S2K that unlocks under default config', async () => {
    const k = await readPrivateKey({ armoredKey: gen.privateKeyArmored });
    expect(k.keyPacket.version).toBe(4);
    expect(k.isDecrypted()).toBe(false);
    expect(k.getAlgorithmInfo().algorithm).toBe('eddsaLegacy');
    // protected with iterated S2K (not Argon2): the s2k of the secret key packet
    const s2k = (k.keyPacket as unknown as { s2k: { type: string } }).s2k;
    expect(s2k.type).toBe('iterated');
    expect(unlocked.isDecrypted()).toBe(true);
    expect(gen.fingerprint).toMatch(/^[0-9A-F]{40}$/);
    expect(gen.userId).toBe('Carol Example <carol@example.test>');
    await expect(unlockPrivateKey(gen.privateKeyArmored, 'wrong passphrase!!')).rejects.toThrow();
  });
  it('public armor has no private material', () => {
    expect(gen.publicKeyArmored).toContain('PUBLIC KEY BLOCK');
    expect(gen.publicKeyArmored).not.toContain('PRIVATE');
  });
  it('rejects weak passphrases and bad identities without echoing the passphrase', async () => {
    expect(checkPassphrase('short')).not.toBeNull();
    expect(checkPassphrase('aaaaaaaaaaaaaaaa')).not.toBeNull();
    expect(checkPassphrase(PASS)).toBeNull();
    const err = await generateEnrollmentKey({ name: 'x', email: 'x@y.test', passphrase: 'hunter2' }).catch((e: Error) => e);
    expect((err as Error).message).not.toContain('hunter2');
    await expect(generateEnrollmentKey({ name: '', email: 'a@b.test', passphrase: PASS })).rejects.toThrow();
    await expect(generateEnrollmentKey({ name: 'A', email: 'nope', passphrase: PASS })).rejects.toThrow();
  });
  it('imports a protected key and refuses an unprotected one', async () => {
    const info = await inspectImportedKey(gen.privateKeyArmored);
    expect(info.fingerprint).toBe(gen.fingerprint);
    expect(info.publicKeyArmored).not.toContain('PRIVATE');
    const bare = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'U' }], format: 'armored' });
    await expect(inspectImportedKey(bare.privateKey)).rejects.toThrow(/not passphrase-protected/);
  });
});

describe('buildAccessRequest', () => {
  const now = new Date(Math.floor(Date.now() / 1000) * 1000 + 1000);
  const rnd = (n: number) => new Uint8Array(n).fill(7);
  const input = () => ({
    repo: 'acme/secrets',
    folder: '/infra/',
    role: 'reader' as const,
    name: 'Carol Example',
    note: null,
    inviteId: 'q3V1x0bN0m5Qm6cU2f5r9A',
    publicKey: gen.publicKeyArmored,
    fingerprint: gen.fingerprint,
  });

  it('matches the spec format and the signature verifies', async () => {
    const r = await buildAccessRequest(input(), unlocked, { now, randomBytes: rnd });
    expect(r.title).toBe(`[g00pass] Access request: infra (reader) ${gen.fingerprint.slice(-16)}`);
    const lines = r.body.split('\n');
    expect(lines[0]).toBe('<!-- g00pass:access-request v1 -->');
    expect(r.body).toContain('- Folder: `infra`');
    expect(r.body).toContain('- Role: reader');
    expect(r.body.match(/```g00pass-request/g)).toHaveLength(1);
    const m = /```g00pass-request\n([\s\S]*?)\n```/.exec(r.body);
    expect(m).not.toBeNull();
    const msg = await readCleartextMessage({ cleartextMessage: m![1]! });
    const text = msg.getText();
    expect(text).toBe(r.canonicalJson);
    expect(text.endsWith('}\n')).toBe(true);
    // canonical: sorted keys, 2-space indent
    const p = JSON.parse(text) as Record<string, unknown>;
    expect(Object.keys(p)).toEqual([...Object.keys(p)].sort());
    expect(JSON.stringify(p, null, 2) + '\n').toBe(text);
    expect(p).toMatchObject({
      type: 'g00pass.access-request',
      version: 1,
      repo: 'acme/secrets',
      storeRoot: '',
      folder: 'infra',
      role: 'reader',
      note: null,
      inviteId: 'q3V1x0bN0m5Qm6cU2f5r9A',
      createdAt: now.toISOString().replace('.000Z', 'Z'),
      fingerprint: gen.fingerprint,
      name: 'Carol Example',
      nonce: 'BwcHBwcHBwcHBwcHBwcHBw',
    });
    // no line of the signed text starts with '-' (no dash-escaping needed)
    expect(text.split('\n').some((l) => l.startsWith('-'))).toBe(false);
    // public key in payload is the one that verifies; contains no secret
    const pk = await readKey({ armoredKey: p.publicKey as string });
    expect(pk.isPrivate()).toBe(false);
    expect(pk.getFingerprint().toUpperCase()).toBe(gen.fingerprint);
    const v = await verify({ message: msg, verificationKeys: pk, date: now });
    await expect(v.signatures[0]!.verified).resolves.toBe(true);
    expect(r.body).not.toContain('PRIVATE');
  });

  it('wrong key does not verify', async () => {
    const other = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'O' }], format: 'object' });
    const r = await buildAccessRequest(input(), unlocked, { now });
    const msg = await readCleartextMessage({ cleartextMessage: /```g00pass-request\n([\s\S]*?)\n```/.exec(r.body)![1]! });
    const v = await verify({ message: msg, verificationKeys: other.publicKey });
    await expect(v.signatures[0]!.verified).rejects.toThrow();
  });

  it('null invite / note handling, folder-admin, validation', async () => {
    const r = await buildAccessRequest({ ...input(), inviteId: undefined, role: 'folder-admin', note: ' hi ' }, unlocked, { now });
    expect(r.payload).toMatchObject({ inviteId: null, note: 'hi', role: 'folder-admin' });
    const bad = (o: object) => buildAccessRequest({ ...input(), ...o }, unlocked, { now });
    await expect(bad({ folder: '' })).rejects.toBeInstanceOf(RequestBuildError);
    await expect(bad({ folder: '../x' })).rejects.toThrow();
    await expect(bad({ role: 'owner' })).rejects.toThrow();
    await expect(bad({ note: 'x'.repeat(501) })).rejects.toThrow();
    await expect(bad({ inviteId: 'short' })).rejects.toThrow();
    await expect(bad({ repo: 'nope' })).rejects.toThrow();
    await expect(bad({ fingerprint: 'A'.repeat(40) })).rejects.toThrow();
    await expect(bad({ publicKey: gen.privateKeyArmored })).rejects.toThrow();
  });

  it('refuses a locked key', async () => {
    const locked = await readPrivateKey({ armoredKey: gen.privateKeyArmored });
    await expect(buildAccessRequest(input(), locked, { now })).rejects.toThrow(/locked/);
  });
});

describe('issue creation', () => {
  function mock(status: number, json: unknown) {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const f = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(JSON.stringify(json), { status });
    }) as unknown as typeof fetch;
    return { f, calls };
  }
  const tokens = new TokenStore('memory', null);
  tokens.set(TOKEN);

  it('POSTs to the requests repo with the label; token only in header', async () => {
    const { f, calls } = mock(201, { number: 7, html_url: 'https://github.com/acme/reqs/issues/7', labels: [{ name: REQUEST_LABEL }] });
    const client = new GitHubClient({ token: tokens.get, fetch: f });
    const res = await createAccessRequestIssue(client, 'acme/reqs', { title: 'T', body: 'B' });
    expect(res).toEqual({ requestsRepo: 'acme/reqs', issueNumber: 7, url: 'https://github.com/acme/reqs/issues/7', labelled: true });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://api.github.com/repos/acme/reqs/issues');
    expect(calls[0]!.init.method).toBe('POST');
    expect(JSON.parse(calls[0]!.init.body as string)).toEqual({ title: 'T', body: 'B', labels: ['g00pass:access-request'] });
    expect(calls[0]!.url).not.toContain(TOKEN);
    expect(calls[0]!.init.body as string).not.toContain(TOKEN);
  });

  it('rejects bad repo names before any request', async () => {
    const { f, calls } = mock(201, {});
    const client = new GitHubClient({ token: tokens.get, fetch: f });
    await expect(createAccessRequestIssue(client, 'a/b/c', { title: 'T', body: 'B' })).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('errors are clear and never contain the token', async () => {
    const { f } = mock(403, { message: `Resource not accessible by personal access token ${TOKEN}` });
    const client = new GitHubClient({ token: tokens.get, fetch: f });
    const e = await createAccessRequestIssue(client, 'acme/reqs', { title: 'T', body: 'B' }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(GitHubApiError);
    expect((e as Error).message).not.toContain(TOKEN);
    const shown = describeSubmitError(e);
    expect(shown).toMatch(/cannot create issues/);
    expect(shown).not.toContain(TOKEN);
  });

  it('falls back to the store repo when requestsRepo is unset', () => {
    expect(resolveRequestsRepo('acme/secrets', undefined)).toEqual({ repo: 'acme/secrets', fallback: true });
    expect(resolveRequestsRepo('acme/secrets', ' acme/reqs ')).toEqual({ repo: 'acme/reqs', fallback: false });
  });
});

