import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  MemoryWriter,
  PASSWORD_CLASSES,
  deleteSecret,
  generatePassword,
  passThroughTrustHook,
  pinAnchors,
  readRotation,
  resetTrustEnvironment,
  saveSecret,
  secretPath,
  setTrustHook,
  signatureTrustHook,
} from '../src/core';
import { type TestIdentity, decryptText, enc, encryptForTest, makeIdentity } from './helpers/keys';
import { STORE_ID, derive, freshEnv, signedGpgId } from './helpers/trust';

let A: TestIdentity, C: TestIdentity, D: TestIdentity, M: TestIdentity, E: TestIdentity;
const keys = (...ids: TestIdentity[]) => Object.fromEntries(ids.map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic]));
const txt = (...ids: TestIdentity[]) => ids.map((i) => i.fpr).join('\n') + `\n${E.fpr} # g00pass:escrow\n`;
const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: unknown) => (e as { code?: string }).code ?? `other:${(e as Error).message}`);

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, C, D, M, E] = (await Promise.all(['A', 'C', 'D', 'M', 'E'].map((n) => makeIdentity(n, born)))) as [TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity];
  setTrustHook(signatureTrustHook);
});
afterAll(() => {
  setTrustHook(passThroughTrustHook);
  resetTrustEnvironment();
});
beforeEach(() => {
  freshEnv();
  pinAnchors(STORE_ID, [A.fpr], 'first-use');
});

async function store(sha: string) {
  return new MemoryStore({
    ...keys(A, C, D, M, E),
    ...(await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv, { children: ['team'] })),
    ...(await signedGpgId('team', txt(A, C), A.priv)),
    'team/old.gpg': await encryptForTest('old-pass\nuser: x', [A, C, E]),
  }, sha);
}
const opts = (s: MemoryStore, mode: 'create' | 'edit', key = C, now?: Date) => ({ loadSnapshot: async () => s, writer: new MemoryWriter(s), operatorKey: key.priv, mode, now });

describe('secrets: add / edit / delete from the app', () => {
  it('adds a secret for the folder members and records it for rotation; a duplicate name is refused', async () => {
    const s = await store('s0');
    const t = new Date('2026-11-04T10:00:00Z');
    const res = await saveSecret('team/github', enc('gh-pass\nuser: bot'), opts(s, 'create', C, t));
    expect(res).toMatchObject({ path: 'team/github.gpg', folder: 'team', rotated: true });
    expect(await decryptText((await s.readFile('team/github.gpg'))!, A)).toBe('gh-pass\nuser: bot');
    await expect(decryptText((await s.readFile('team/github.gpg'))!, D)).rejects.toThrow();
    expect((await readRotation(s, 'team', [A.priv])).entries.github).toEqual({ createdAt: '2026-11-04T10:00:00Z', rotatedAt: '2026-11-04T10:00:00Z', rotatedBy: C.fpr });
    expect(await code(saveSecret('team/github', enc('x'), opts(s, 'create')))).toBe('exists');
  });

  it('an edit counts as a rotation only when the password (first line) changes', async () => {
    const s = await store('s1');
    const t1 = new Date('2026-11-04T10:00:00Z');
    const t2 = new Date('2026-11-04T11:00:00Z');
    expect((await saveSecret('team/old', enc('old-pass\nuser: y'), opts(s, 'edit', C, t1))).rotated).toBe(false);
    expect((await readRotation(s, 'team', [A.priv])).entries.old).toEqual({ createdAt: null, rotatedAt: null, rotatedBy: null });
    expect((await saveSecret('team/old', enc('new-pass\nuser: y'), opts(s, 'edit', C, t2))).rotated).toBe(true);
    expect((await readRotation(s, 'team', [A.priv])).entries.old).toMatchObject({ rotatedAt: '2026-11-04T11:00:00Z', rotatedBy: C.fpr });
    expect(await decryptText((await s.readFile('team/old.gpg'))!, A)).toBe('new-pass\nuser: y');
    expect(await code(saveSecret('team/missing', enc('x'), opts(s, 'edit')))).toBe('not-found');
  });

  it('delete removes the entry and its rotation metadata in one commit', async () => {
    const s = await store('s2');
    await saveSecret('team/github', enc('p'), opts(s, 'create'));
    const w = new MemoryWriter(s);
    await deleteSecret('team/github', { loadSnapshot: async () => s, writer: w, operatorKey: C.priv });
    expect(w.commits).toHaveLength(1);
    expect(s.hasFile('team/github.gpg')).toBe(false);
    expect((await readRotation(s, 'team', [A.priv])).entries.github).toBeUndefined();
  });

  it('a non-member cannot edit (cannot read the current value)', async () => {
    const s = await store('s3');
    expect(await code(saveSecret('team/old', enc('x'), opts(s, 'edit', D)))).toBe('not-readable');
  });

  it('writing into a folder whose member list was tampered with is refused (trust choke-point)', async () => {
    const s0 = await store('s4');
    const s = await derive(s0, { 'team/.gpg-id': txt(A, C, M) });
    expect(await code(saveSecret('team/new', enc('x'), opts(s, 'create')))).toBe('signature-invalid');
    expect(s.hasFile('team/new.gpg')).toBe(false);
  });

  it('names: hidden, reserved, traversal and empty names are refused', () => {
    expect(secretPath(' team/github ')).toBe('team/github.gpg');
    expect(secretPath('team/github.gpg')).toBe('team/github.gpg');
    for (const bad of ['', '.hidden', 'team/.rotation', '.public-keys/x', '.g00pass/invites/x', 'a/../b', 'a\\b', 'a\u0007b']) {
      expect(() => secretPath(bad), bad).toThrow();
    }
  });
});

describe('password generator', () => {
  it('has the requested length and uses every enabled class', () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword({ length: 16 });
      expect(p).toHaveLength(16);
      for (const c of Object.values(PASSWORD_CLASSES)) expect([...p].some((x) => c.includes(x))).toBe(true);
    }
    const n = generatePassword({ length: 30, symbols: false });
    expect([...n].some((x) => PASSWORD_CLASSES.symbols.includes(x))).toBe(false);
    expect(generatePassword({ length: 2 })).toHaveLength(8);
    expect(new Set(Array.from({ length: 20 }, () => generatePassword())).size).toBe(20);
  });
});
