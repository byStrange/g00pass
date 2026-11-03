import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  MemoryWriter,
  REMOVED_NOTATION,
  CHILD_NOTATION,
  changeFolderRecipients,
  createSubfolder,
  folderTrustStatus,
  knownBoundaries,
  parseDetachedSignature,
  passThroughTrustHook,
  pinAnchors,
  planCreateSubfolder,
  planFolderRecipientChange,
  planRemoveSubfolder,
  readRotation,
  reencryptFolder,
  removeSubfolder,
  resetTrustEnvironment,
  rotationChecklist,
  setTrustHook,
  signGpgId,
  signatureTrustHook,
  verifyRecipients,
  writeEntry,
} from '../src/core';
import { type TestIdentity, decryptText, enc, encryptForTest, makeIdentity } from './helpers/keys';
import { STORE_ID, derive, freshEnv, signedGpgId } from './helpers/trust';

let A: TestIdentity, C: TestIdentity, D: TestIdentity, M: TestIdentity, E: TestIdentity, N: TestIdentity;
const keys = (...ids: TestIdentity[]) => Object.fromEntries(ids.map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic]));
const txt = (...ids: TestIdentity[]) => ids.map((i) => i.fpr).join('\n') + `\n${E.fpr} # g00pass:escrow\n`;
const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: unknown) => (e as { code?: string }).code ?? `other:${(e as Error).message}`);
const write = (s: MemoryStore, entry: string) => writeEntry({ snapshot: s, writer: new MemoryWriter(s), entry, plaintext: enc('v') });
const notations = async (s: MemoryStore, path: string) => (await parseDetachedSignature((await s.readFile(path))!)).notations;

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, C, D, M, E, N] = (await Promise.all(['A', 'C', 'D', 'M', 'E', 'N'].map((n) => makeIdentity(n, born)))) as [
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

async function store(sha: string) {
  return new MemoryStore({
    ...keys(A, C, D, M, N, E),
    ...(await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv, { children: ['infra'] })),
    ...(await signedGpgId('infra', txt(A, C, D), A.priv, { children: ['infra/prod'] })),
    ...(await signedGpgId('infra/prod', txt(A, C), A.priv)),
    'infra/x.gpg': await encryptForTest('x', [A, C, D, E]),
    'infra/new/a.gpg': await encryptForTest('new-a', [A, C, D, E]),
    'infra/prod/p.gpg': await encryptForTest('prod', [A, C, E]),
  }, sha);
}
const opts = (s: MemoryStore, digest: string, key = A) => ({ loadSnapshot: async () => s, writer: new MemoryWriter(s), operatorKey: key.priv, approvedPlanDigest: digest });

describe('create sub-folder (one commit: parent declares, child signed, entries moved)', () => {
  it('creates infra/new for [A, C]: D loses access to the moved entry and is on the checklist', async () => {
    const s = await store('c0');
    const plan = await planCreateSubfolder(s, 'infra/new', [A.fpr, C.fpr], { operatorFingerprint: A.fpr });
    expect(plan).toMatchObject({ parent: 'infra', parentChildrenAfter: ['infra/new', 'infra/prod'], entries: ['infra/new/a.gpg'], losingAccess: [D.fpr] });
    const w = new MemoryWriter(s);
    await createSubfolder('infra/new', [A.fpr, C.fpr], { ...opts(s, plan.digest), writer: w });
    expect(w.commits).toHaveLength(1);
    expect((await notations(s, 'infra/.gpg-id.sig')).get(CHILD_NOTATION)).toEqual(['/infra/new', '/infra/prod']);
    expect([...(await verifyRecipients(s, { folder: 'infra/new' })).fingerprints].sort()).toEqual([A.fpr, C.fpr, E.fpr].sort());
    expect(await decryptText((await s.readFile('infra/new/a.gpg'))!, C)).toBe('new-a');
    await expect(decryptText((await s.readFile('infra/new/a.gpg'))!, D)).rejects.toThrow();
    expect(await code(write(s, 'infra/new/b'))).toBe('ok');
    expect(await code(write(s, 'infra/y'))).toBe('ok');
    const list = rotationChecklist(await readRotation(s, 'infra/new', [A.priv]), s);
    expect(list.map((m) => m.fingerprint)).toEqual([D.fpr]);
    expect(list[0]!.open.map((i) => i.path)).toContain('infra/new/a.gpg');
  });

  it('refuses: not an admin of the parent, an existing boundary, a changed plan', async () => {
    const s = await store('c1');
    expect(await code(planCreateSubfolder(s, 'infra/new', [A.fpr], { operatorFingerprint: D.fpr }))).toBe('not-admin');
    expect(await code(planCreateSubfolder(s, 'infra/prod', [A.fpr], { operatorFingerprint: A.fpr }))).toBe('invalid-change');
    expect(await code(planCreateSubfolder(s, 'infra', [A.fpr], { operatorFingerprint: A.fpr }))).toBe('invalid-change'); // exists
    const plan = await planCreateSubfolder(s, 'infra/new', [A.fpr, C.fpr], { operatorFingerprint: A.fpr });
    expect(await code(createSubfolder('infra/new', [A.fpr], opts(s, plan.digest)))).toBe('plan-changed');
  });

  it('the raw engine refuses a parent declaration that is forged, wrong, or for the wrong parent', async () => {
    const s = await store('c2');
    const pText = (await s.readFile('infra/.gpg-id'))!;
    const run = (sig: Uint8Array, parent = 'infra') =>
      reencryptFolder('infra/new', [A.fpr], {
        snapshot: s, writer: new MemoryWriter(s), decryptionKeys: [A.priv],
        newBoundary: { parent, signature: sig },
        gpgIdSignature: (t, c) => signGpgId(t, 'infra/new', A.priv, { children: c.children }),
      });
    expect(await code(run(await signGpgId(pText, 'infra', M.priv, { children: ['infra/new', 'infra/prod'] })))).toBe('unknown-signer');
    expect(await code(run(await signGpgId(pText, 'infra', A.priv, { children: ['infra/new'] })))).toBe('boundary-undeclared'); // drops prod
    expect(await code(run(await signGpgId(pText, 'infra', A.priv, { children: ['infra/prod'] })))).toBe('boundary-undeclared'); // no new
    expect(await code(run(await signGpgId((await s.readFile('.gpg-id'))!, '', A.priv, { children: ['infra'] }), ''))).toBe('boundary-undeclared'); // wrong parent
    expect(s.hasFile('infra/new/.gpg-id')).toBe(false);
    expect(await code(run(await signGpgId(pText, 'infra', A.priv, { children: ['infra/new', 'infra/prod'] })))).toBe('ok');
  });
});

describe('remove sub-folder (explicit signed removal)', () => {
  it('merges infra/prod into infra; a device that knew prod accepts the signed removal', async () => {
    const s = await store('r0');
    expect(await code(write(s, 'infra/prod/q'))).toBe('ok'); // this device now knows infra/prod
    expect(knownBoundaries(STORE_ID)).toContain('infra/prod');
    const plan = await planRemoveSubfolder(s, 'infra/prod', { operatorFingerprint: A.fpr });
    expect(plan).toMatchObject({ parent: 'infra', gainingAccess: [D.fpr], parentChildrenAfter: [], parentRemovedAfter: ['infra/prod'] });
    const w = new MemoryWriter(s);
    await removeSubfolder('infra/prod', { ...opts(s, plan.digest), writer: w });
    expect(w.commits).toHaveLength(1);
    expect(s.hasFile('infra/prod/.gpg-id')).toBe(false);
    expect((await notations(s, 'infra/.gpg-id.sig')).get(REMOVED_NOTATION)).toEqual(['/infra/prod']);
    expect(await decryptText((await s.readFile('infra/prod/p.gpg'))!, D)).toBe('prod');

    expect(await folderTrustStatus(s, 'infra')).toMatchObject({ verified: true, warnings: [] });
    expect(knownBoundaries(STORE_ID)).not.toContain('infra/prod');
    expect(await code(write(s, 'infra/prod/r'))).toBe('ok');

    // The next re-sign of infra (an approval) carries the removal forward.
    const change = { add: [{ fingerprint: N.fpr, publicKey: N.armoredPublic }] };
    const p2 = await planFolderRecipientChange(s, 'infra', change, { operatorFingerprint: A.fpr });
    await changeFolderRecipients('infra', change, { snapshot: s, writer: new MemoryWriter(s), operatorKey: A.priv, approvedPlanDigest: p2.digest });
    expect((await notations(s, 'infra/.gpg-id.sig')).get(REMOVED_NOTATION)).toEqual(['/infra/prod']);
  });

  it('without the signed removal (child deleted, parent re-signed without it by an attacker) the device still refuses', async () => {
    const s0 = await store('r1');
    expect(await code(write(s0, 'infra/prod/q'))).toBe('ok');
    const forged = await derive(s0, {
      'infra/prod/.gpg-id': null,
      'infra/prod/.gpg-id.sig': null,
      'infra/.gpg-id.sig': await signGpgId((await s0.readFile('infra/.gpg-id'))!, 'infra', M.priv, { removed: ['infra/prod'] }),
    });
    expect(await code(write(forged, 'infra/prod/r'))).toBe('unknown-signer');
    // Replaying the parent's pre-removal signature after a legitimate removal is a rollback.
    const s = await store('r2');
    const oldSig = (await s.readFile('infra/.gpg-id.sig'))!;
    expect(await code(write(s, 'infra/prod/q'))).toBe('ok');
    const plan = await planRemoveSubfolder(s, 'infra/prod', { operatorFingerprint: A.fpr });
    await new Promise((r) => setTimeout(r, 1100)); // signature times have 1 s resolution
    await removeSubfolder('infra/prod', opts(s, plan.digest));
    expect(await code(write(s, 'infra/y'))).toBe('ok');
    const replay = await derive(s, { 'infra/.gpg-id.sig': oldSig });
    expect(await code(write(replay, 'infra/y'))).toBe('replayed');
  });

  it('refuses: nested boundaries inside, non-admin, non-recipient of the child, changed plan', async () => {
    const s = await store('r3');
    expect(await code(planRemoveSubfolder(s, 'infra', { operatorFingerprint: A.fpr }))).toBe('invalid-change'); // contains prod
    expect(await code(planRemoveSubfolder(s, 'infra/prod', { operatorFingerprint: D.fpr }))).toBe('not-admin');
    const plan = await planRemoveSubfolder(s, 'infra/prod', { operatorFingerprint: A.fpr });
    expect(await code(removeSubfolder('infra/prod', opts(s, 'sha256:' + '0'.repeat(64))))).toBe('plan-changed');
    expect(plan.digest).toMatch(/^sha256:/);
  });
});
