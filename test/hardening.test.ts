import * as openpgp from 'openpgp';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  MAX_SIGNER_CANDIDATES,
  MemoryStore,
  MemoryWriter,
  ReencryptError,
  folderTrustStatus,
  parseAccessRequest,
  passThroughTrustHook,
  pinAnchors,
  reencryptFolder,
  resetTrustEnvironment,
  sanitizeDisplayText,
  setTrustHook,
  signatureTrustHook,
} from '../src/core';
import { Session, copyWithAutoClear, wipePrivateKey } from '../src/ui/session';
import { ORIGIN_ACK_KEY, acknowledgeOriginRisk, appBasePath, assessOrigin, isOriginRiskAcknowledged } from '../src/ui/origin';
import { type TestIdentity, encryptForTest, makeIdentity } from './helpers/keys';
import { buildBody } from './helpers/requests';
import { STORE_ID, countingSnapshot, derive, freshEnv, signedGpgId } from './helpers/trust';

let A: TestIdentity, M: TestIdentity, E: TestIdentity;
beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, M, E] = (await Promise.all(['A', 'M', 'E'].map((n) => makeIdentity(n, born)))) as [TestIdentity, TestIdentity, TestIdentity];
});
afterAll(() => {
  setTrustHook(passThroughTrustHook);
  resetTrustEnvironment();
});

async function identityWithUserId(name: string, email?: string): Promise<TestIdentity> {
  // openpgp validates `email`, so unsafe e-mails are smuggled in through the name part ("Name <addr>").
  const { privateKey, publicKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [email ? { name, email } : { name }], format: 'armored' });
  const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
  return { name: 'Requester', email: email ?? '', priv, armoredPublic: publicKey, fpr: priv.getFingerprint().toUpperCase() };
}

describe('L1: requester user ids and e-mail are sanitized', () => {
  const ctx = { repo: 'acme/secrets', storeRoot: '' };
  it('bidi overrides / zero-width characters in key user ids are replaced; an unsafe e-mail is dropped', async () => {
    const evil = await identityWithUserId('Bob \u202Egnp.exe <b\u200Bob@example.test>');
    const r = await parseAccessRequest(await buildBody(evil, { name: 'Bob' }), ctx);
    if (!r.ok) throw new Error(r.message);
    expect(r.request.userIds).toHaveLength(1);
    expect(r.request.userIds[0]).not.toMatch(/[\u200B\u202A-\u202E]/);
    expect(r.request.userIds[0]).toContain('\uFFFD');
    expect(r.request.email).toBeNull();
  });
  it('a clean user id passes through unchanged, with its e-mail', async () => {
    const ok = await identityWithUserId('Carol Example', 'carol@example.test');
    const r = await parseAccessRequest(await buildBody(ok, { name: 'Carol' }), ctx);
    if (!r.ok) throw new Error(r.message);
    expect(r.request.userIds).toEqual(['Carol Example <carol@example.test>']);
    expect(r.request.email).toBe('carol@example.test');
  });
  it('sanitizeDisplayText', () => {
    expect(sanitizeDisplayText('a\u2066b\u2069c\u200Dd\ne')).toBe('a\uFFFDb\uFFFDc\uFFFDd\uFFFDe');
    expect(sanitizeDisplayText('x'.repeat(10), 4)).toBe('xxxx…');
  });
});

describe('L3: the unlocked key is wiped on lock', () => {
  it('lock() clears the private parameters and calls onLock once', async () => {
    const id = await makeIdentity('Wipe');
    expect(id.priv.isDecrypted()).toBe(true);
    const onLock = vi.fn();
    const s = new Session(60_000, onLock);
    s.unlock(id.priv);
    s.lock();
    expect(s.unlockedKey).toBeNull();
    expect(id.priv.isDecrypted()).toBe(false);
    s.lock();
    expect(onLock).toHaveBeenCalledTimes(1);
    expect(() => wipePrivateKey(id.priv)).not.toThrow();
  });
  it('idle timeout locks and wipes', async () => {
    vi.useFakeTimers();
    try {
      const id = await makeIdentity('Idle');
      const s = new Session(1000, () => undefined);
      s.unlock(id.priv);
      vi.advanceTimersByTime(1001);
      expect(s.unlockedKey).toBeNull();
      expect(id.priv.isDecrypted()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('clipboard auto-clear only clears our own copy', () => {
  afterEach(() => vi.useRealTimers());
  interface FakeClipboard { value: string; writeText: (t: string) => Promise<void>; readText: () => Promise<string> }
  const fake = (readable: boolean): FakeClipboard => {
    const c: FakeClipboard = { value: '', writeText: vi.fn(async (t: string) => void (c.value = t)), readText: readable ? vi.fn(async () => c.value) : vi.fn(async () => Promise.reject(new Error('denied'))) };
    return c;
  };
  it('clears when it still holds the secret, leaves other content alone, clears if unreadable', async () => {
    vi.useFakeTimers();
    const a = fake(true);
    await copyWithAutoClear('s3cret', 1000, undefined, a);
    await vi.advanceTimersByTimeAsync(1001);
    expect(a.value).toBe('');
    const b = fake(true);
    await copyWithAutoClear('s3cret', 1000, undefined, b);
    b.value = 'something the user copied later';
    await vi.advanceTimersByTimeAsync(1001);
    expect(b.value).toBe('something the user copied later');
    const c = fake(false);
    await copyWithAutoClear('s3cret', 1000, undefined, c);
    c.value = 'other';
    await vi.advanceTimersByTimeAsync(1001);
    expect(c.value).toBe('');
  });
});

describe('M2: shared-origin detection', () => {
  const loc = (href: string) => {
    const u = new URL(href);
    return { hostname: u.hostname, origin: u.origin, pathname: u.pathname };
  };
  it('flags *.github.io and non-root paths; a dedicated origin root is fine', () => {
    expect(assessOrigin(loc('https://g00pass.example.org/')).risky).toBe(false);
    expect(assessOrigin(loc('https://g00pass.example.org/index.html')).risky).toBe(false);
    const gh = assessOrigin(loc('https://alice.github.io/g00pass/'));
    expect(gh.risky).toBe(true);
    expect(gh.reasons).toHaveLength(2);
    expect(gh.scope).toBe('https://alice.github.io/g00pass/');
    expect(assessOrigin(loc('https://alice.github.io/')).reasons).toHaveLength(1);
    expect(assessOrigin(loc('https://example.org/apps/g00pass/index.html')).risky).toBe(true);
    expect(appBasePath('/a/b/index.html')).toBe('/a/b/');
  });
  it('the acknowledgement is bound to origin + path', () => {
    const m = new Map<string, string>();
    const st = { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) };
    const r1 = assessOrigin(loc('https://alice.github.io/g00pass/'));
    const r2 = assessOrigin(loc('https://alice.github.io/other/'));
    expect(isOriginRiskAcknowledged(st, r1)).toBe(false);
    acknowledgeOriginRisk(st, r1);
    expect(m.get(ORIGIN_ACK_KEY)).toBe('https://alice.github.io/g00pass/');
    expect(isOriginRiskAcknowledged(st, r1)).toBe(true);
    expect(isOriginRiskAcknowledged(st, r2)).toBe(false);
  });
});

describe('L7: naming an unauthorized signer has bounded cost', () => {
  it('only key files matching the issuer are read, no matter how many a writer adds', async () => {
    setTrustHook(signatureTrustHook);
    freshEnv();
    pinAnchors(STORE_ID, [A.fpr], 'first-use');
    const decoys: Record<string, string> = {};
    for (let i = 0; i < 300; i++) decoys[`.public-keys/${(i.toString(16).padStart(8, '0') + 'F'.repeat(32)).toUpperCase()}`] = 'junk';
    const base = new MemoryStore({
      [`.public-keys/${A.fpr}`]: A.armoredPublic,
      [`.public-keys/${M.fpr}`]: M.armoredPublic,
      [`.public-keys/${E.fpr}`]: E.armoredPublic,
      ...decoys,
      ...(await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv, { children: ['team'] })),
      ...(await signedGpgId('team', `${A.fpr}\n${M.fpr}\n${E.fpr} # g00pass:escrow\n`, M.priv)),
    }, 'l7');
    const s = countingSnapshot(await derive(base, {}));
    const st = await folderTrustStatus(s, 'team');
    expect(st).toMatchObject({ verified: false, code: 'unknown-signer' });
    expect(st.reason).toContain(M.fpr);
    expect(s.reads.filter((p) => p in decoys)).toEqual([]);
    expect(MAX_SIGNER_CANDIDATES).toBeLessThan(10);
  });
});

describe('nit: extraChanges allowlist', () => {
  it("only the folder's own admins file (+ .sig) may ride along with a re-encrypt", async () => {
    setTrustHook(passThroughTrustHook);
    const mk = async () => {
      const s = new MemoryStore({ '.gpg-id': `${A.fpr}\n`, 'team/.gpg-id': `${A.fpr}\n`, [`.public-keys/${A.fpr}`]: A.armoredPublic });
      s.set('team/a.gpg', await encryptForTest('a', [A]));
      return s;
    };
    for (const path of ['.public-keys/' + M.fpr, 'other/.g00pass-admins.json', 'team/.g00pass/x', '.g00pass/config.json', 'team/sub/.g00pass-admins.json', 'team/.gpg-id.sig', 'team/a.gpg']) {
      const s = await mk();
      await expect(reencryptFolder('team', [A.fpr], { snapshot: s, writer: new MemoryWriter(s), decryptionKeys: [A.priv], extraChanges: [{ path, content: 'x' }] })).rejects.toBeInstanceOf(ReencryptError);
    }
    const s = await mk();
    await reencryptFolder('team', [A.fpr], {
      snapshot: s, writer: new MemoryWriter(s), decryptionKeys: [A.priv],
      extraChanges: [{ path: 'team/.g00pass-admins.json', content: '{}' }, { path: 'team/.g00pass-admins.json.sig', content: 'x' }],
    });
    expect(s.hasFile('team/.g00pass-admins.json')).toBe(true);
  });
});
