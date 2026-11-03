import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  CHILD_NOTATION,
  MemoryStore,
  MemoryWriter,
  changeFolderRecipients,
  folderTrustStatus,
  knownBoundaries,
  parseDetachedSignature,
  passThroughTrustHook,
  pinAnchors,
  planFolderRecipientChange,
  reencryptFolder,
  resetTrustEnvironment,
  setTrustHook,
  signDetached,
  signGpgId,
  signatureTrustHook,
  verifyRecipients,
  writeEntry,
} from '../src/core';
import { type TestIdentity, enc, encryptForTest, makeIdentity } from './helpers/keys';
import { STORE_ID, derive, freshEnv, signedGpgId } from './helpers/trust';

/** Signed child-boundary declarations (gpg-id-signatures.md §Child boundaries). */
let A: TestIdentity, C: TestIdentity, D: TestIdentity, M: TestIdentity, N: TestIdentity, E: TestIdentity;
const keys = (...ids: TestIdentity[]) => Object.fromEntries(ids.map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic]));
const txt = (...ids: TestIdentity[]) => ids.map((i) => i.fpr).join('\n') + `\n${E.fpr} # g00pass:escrow\n`;
const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: unknown) => (e as { code?: string }).code ?? `other:${(e as Error).message}`);
const write = (s: MemoryStore, entry: string) => writeEntry({ snapshot: s, writer: new MemoryWriter(s), entry, plaintext: enc('v') });

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, C, D, M, N, E] = (await Promise.all(['A', 'C', 'D', 'M', 'N', 'E'].map((n) => makeIdentity(n, born)))) as [
    TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity,
  ];
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

async function store(sha: string, infraChildren: string[] = ['infra/prod'], extra: Record<string, string | Uint8Array> = {}) {
  return new MemoryStore({
    ...keys(A, C, D, M, N, E),
    ...(await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv, { children: ['infra'] })),
    ...(await signedGpgId('infra', txt(A, C, D), A.priv, { children: infraChildren })),
    ...(await signedGpgId('infra/prod', txt(A, C), A.priv)),
    'infra/x.gpg': await encryptForTest('x', [A, C, D, E]),
    'infra/prod/p.gpg': await encryptForTest('p', [A, C, E]),
    ...extra,
  }, sha);
}

async function approveN(s: MemoryStore, folder = 'infra') {
  const change = { add: [{ fingerprint: N.fpr, publicKey: N.armoredPublic }] };
  const plan = await planFolderRecipientChange(s, folder, change, { operatorFingerprint: A.fpr });
  await changeFolderRecipients(folder, change, { snapshot: s, writer: new MemoryWriter(s), operatorKey: A.priv, approvedPlanDigest: plan.digest });
  return plan;
}

describe('child boundary declarations', () => {
  it('an approval in the parent re-signs WITH the child declarations; the child stays writable', async () => {
    const s = await store('b0');
    const plan = await approveN(s);
    expect(plan.childBoundaries).toEqual(['infra/prod']);
    const sig = await parseDetachedSignature((await s.readFile('infra/.gpg-id.sig'))!);
    expect(sig.notations.get(CHILD_NOTATION)).toEqual(['/infra/prod']);
    expect((await verifyRecipients(s, { folder: 'infra' })).fingerprints).toContain(N.fpr);
    expect(await code(write(s, 'infra/prod/new'))).toBe('ok');
    expect(knownBoundaries(STORE_ID)).toEqual(['infra', 'infra/prod']);
  });

  it('an undeclared nested .gpg-id is not writable; a validly signed one is adopted by the next parent re-sign', async () => {
    const s = await store('b1', []);
    expect(await code(write(s, 'infra/prod/new'))).toBe('boundary-undeclared');
    expect(await folderTrustStatus(s, 'infra/prod')).toMatchObject({ verified: false, code: 'boundary-undeclared' });
    const plan = await approveN(s);
    expect(plan.childBoundaries).toEqual(['infra/prod']);
    expect(await code(write(s, 'infra/prod/new'))).toBe('ok');
  });

  it('an undeclared nested .gpg-id that is NOT validly signed blocks re-signing the parent (never silently adopted or absorbed)', async () => {
    const s = await store('b2', [], {
      ...(await signedGpgId('infra/evil', txt(A, C, M), M.priv)),
      'infra/evil/moved.gpg': await encryptForTest('moved', [A, C, D, E]),
    });
    const err = (await planFolderRecipientChange(s, 'infra', {}, { operatorFingerprint: A.fpr }).catch((e: unknown) => e)) as Error & { code?: string };
    expect(err).toMatchObject({ code: 'folder-not-verified' });
    expect(err.message).toContain('infra/evil/');
  });

  it('a proposed signature that declares the wrong children is refused', async () => {
    const s = await store('b3');
    const run = (children: string[]) =>
      reencryptFolder('infra', [A.fpr, C.fpr, D.fpr], {
        snapshot: s, writer: new MemoryWriter(s), decryptionKeys: [A.priv],
        gpgIdSignature: (t) => signGpgId(t, 'infra', A.priv, { children }),
      });
    expect(await code(run([]))).toBe('boundary-undeclared');
    expect(await code(run(['infra/prod', 'infra/other']))).toBe('boundary-undeclared');
    expect(await code(run(['infra/prod']))).toBe('ok');
  });

  it('a malformed child declaration makes the signature invalid', async () => {
    const s0 = await store('b4');
    for (const bad of ['/clients', '/infra', 'infra/prod', '/infra/../x']) {
      const text = txt(A, C, D);
      const sig = await signDetached(enc(text), A.priv, { notations: [['folder@g00pass', '/infra'], [CHILD_NOTATION, bad]] });
      const s = await derive(s0, { 'infra/.gpg-id': text, 'infra/.gpg-id.sig': sig });
      expect(await folderTrustStatus(s, 'infra')).toMatchObject({ verified: false, code: 'signature-invalid' });
    }
    // nested declarations (not direct children) are rejected too
    const text = txt(A, C, D);
    const sig = await signDetached(enc(text), A.priv, { notations: [['folder@g00pass', '/infra'], [CHILD_NOTATION, '/infra/prod'], [CHILD_NOTATION, '/infra/prod/x']] });
    expect(await folderTrustStatus(await derive(s0, { 'infra/.gpg-id': text, 'infra/.gpg-id.sig': sig }), 'infra')).toMatchObject({ code: 'signature-invalid' });
    await expect(signGpgId(text, 'infra', A.priv, { children: ['clients'] })).rejects.toThrow();
  });

  it('a new boundary must be declared by its parent first (declare, then create)', async () => {
    const s = await store('b5', ['infra/prod'], { 'infra/new/a.gpg': await encryptForTest('a', [A, C, D, E]) });
    const create = (snap: MemoryStore) =>
      reencryptFolder('infra/new', [A.fpr], {
        snapshot: snap, writer: new MemoryWriter(snap), decryptionKeys: [A.priv],
        gpgIdSignature: (t, c) => signGpgId(t, 'infra/new', A.priv, { children: c.children }),
      });
    expect(await code(create(s))).toBe('boundary-undeclared');
    // The parent declares it: until it exists, writes there are refused (fail closed) ...
    const declared = await derive(s, await signedGpgId('infra', txt(A, C, D), A.priv, { children: ['infra/new', 'infra/prod'] }));
    expect(await code(write(declared, 'infra/new/b'))).toBe('boundary-vanished');
    // ... and creating it is now accepted.
    expect(await code(create(declared))).toBe('ok');
    expect(await code(write(declared, 'infra/new/b'))).toBe('ok');
  });

  it('a companion file inside a vanished boundary is refused', async () => {
    const s = await derive(await store('b6'), { 'infra/prod/.gpg-id': null, 'infra/prod/.gpg-id.sig': null });
    const r = writeEntry({ snapshot: s, writer: new MemoryWriter(s), entry: 'infra/y', plaintext: enc('y'), companions: [{ path: 'infra/prod/.g00pass-rotation', plaintext: enc('r') }] });
    expect(await code(r)).toBe('boundary-vanished');
    expect(s.hasFile('infra/y.gpg')).toBe(false);
  });

  it('deleting an intermediate boundary (infra) is caught via the root declaration', async () => {
    const s = await derive(await store('b7'), { 'infra/.gpg-id': null, 'infra/.gpg-id.sig': null });
    expect(await code(write(s, 'infra/x'))).toBe('boundary-vanished');
    expect(await code(write(s, 'infra/prod/q'))).toBe('boundary-vanished');
    expect(await code(write(s, 'top'))).toBe('ok');
  });

  it('existing device: a replayed older parent signature is refused once the chain was verified', async () => {
    const hourAgo = new Date(Date.now() - 3600_000);
    const old = await signedGpgId('infra', txt(A, C, D), A.priv, { date: hourAgo });
    const s = await store('b8');
    expect(await code(write(s, 'infra/prod/z'))).toBe('ok'); // verifies prod's chain (raises infra's mark)
    const replay = await derive(s, { ...old, 'infra/prod/.gpg-id': null, 'infra/prod/.gpg-id.sig': null });
    expect(await code(write(replay, 'infra/prod/new'))).toBe('replayed');
  });
});
