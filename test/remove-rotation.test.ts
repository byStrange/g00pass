import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  MemoryWriter,
  approveAccessRequest,
  commitMarkRotated,
  emptyRotation,
  folderTrustStatus,
  isVerifiedFolderAdmin,
  markRotated,
  memberAccessElsewhere,
  parseAccessRequest,
  parseRotation,
  passThroughTrustHook,
  pinAnchors,
  previewApproval,
  previewRemoval,
  readRotation,
  recordEntryMoved,
  recordEntryWrite,
  recordMemberAdded,
  recordMemberRemoved,
  removeMember,
  resetTrustEnvironment,
  rotationChecklist,
  serializeRotation,
  setTrustHook,
  signatureTrustHook,
  verifyAdminsFile,
  verifyRecipients,
} from '../src/core';
import { type TestIdentity, decryptText, enc, encryptForTest, makeIdentity } from './helpers/keys';
import { buildBody } from './helpers/requests';
import { STORE_ID, adminsFiles, freshEnv, signedGpgId } from './helpers/trust';

let A: TestIdentity, C: TestIdentity, D: TestIdentity, E: TestIdentity, N: TestIdentity;
const keys = (...ids: TestIdentity[]) => Object.fromEntries(ids.map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic]));
const txt = (...ids: TestIdentity[]) => ids.map((i) => i.fpr).join('\n') + `\n${E.fpr} # g00pass:escrow\n`;
const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: unknown) => (e as { code?: string }).code ?? `other:${(e as Error).message}`);

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, C, D, E, N] = (await Promise.all(['A', 'C', 'D', 'E', 'N'].map((n) => makeIdentity(n, born)))) as [TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity];
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

/** root(A) -> team(A,C,D; admins [C] by A) -> team/prod(A,C; signed by C, admins [C] by C). */
async function teamStore(sha: string) {
  const s = new MemoryStore({
    ...keys(A, C, D, E, N),
    ...(await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv, { children: ['team'] })),
    ...(await signedGpgId('team', txt(A, C, D), A.priv, { children: ['team/prod'] })),
    'team/db.gpg': await encryptForTest('db-pass', [A, C, D, E]),
    'team/web/admin.gpg': await encryptForTest('web', [A, C, D, E]),
  }, sha);
  for (const [p, c] of Object.entries(await adminsFiles(s, 'team', [C.fpr], A.priv))) s.set(p, c);
  for (const [p, c] of Object.entries(await signedGpgId('team/prod', txt(A, C), C.priv))) s.set(p, c);
  s.set('team/prod/p.gpg', await encryptForTest('prod', [A, C, E]));
  for (const [p, c] of Object.entries(await adminsFiles(s, 'team/prod', [C.fpr], C.priv))) s.set(p, c);
  return s;
}

describe('remove member', () => {
  it('removes C from team (recipient + admin), re-encrypts, re-signs what C signed below, records the removal', async () => {
    const s = await teamStore('rm0');
    expect(await folderTrustStatus(s, 'team/prod')).toMatchObject({ verified: true });
    const plan = await previewRemoval(s, 'team', C.fpr, A.fpr);
    expect(plan.removed).toEqual([C.fpr]);
    expect(plan.admins).toEqual({ before: [C.fpr], after: null });
    expect(plan.resign).toEqual([{ folder: 'team/prod', gpgId: true, adminsFile: true }]);
    const w = new MemoryWriter(s);
    const now = new Date();
    await removeMember('team', C.fpr, { loadSnapshot: async () => s, writer: w, operatorKey: A.priv, approvedPlanDigest: plan.digest, now });
    expect(w.commits).toHaveLength(1);

    const v = await verifyRecipients(s, { folder: 'team' });
    expect(v.fingerprints).not.toContain(C.fpr);
    expect(await decryptText((await s.readFile('team/db.gpg'))!, D)).toBe('db-pass');
    await expect(decryptText((await s.readFile('team/db.gpg'))!, C)).rejects.toThrow();
    expect(s.hasFile('team/.g00pass-admins.json')).toBe(false);
    expect(await isVerifiedFolderAdmin(s, 'team', C.fpr)).toBe(false);
    // C's signatures below team were replaced by A's: prod stays verified and writable.
    expect(await folderTrustStatus(s, 'team/prod')).toMatchObject({ verified: true });
    expect(await verifyAdminsFile(s, 'team/prod')).toMatchObject({ status: 'valid', signer: A.fpr, admins: [C.fpr] });
    // prod is NOT covered: C is still a recipient (and listed admin) there.
    expect(await memberAccessElsewhere(s, C.fpr, 'team')).toEqual([{ folder: 'team/prod', recipient: true, admin: true }]);

    const doc = await readRotation(s, 'team', [A.priv]);
    expect(doc.members).toEqual([expect.objectContaining({ fingerprint: C.fpr, addedAt: null, removedBy: A.fpr })]);
    const list = rotationChecklist(doc, s);
    expect(list).toHaveLength(1);
    expect(list[0]!.open.map((i) => i.path)).toEqual(['team/db.gpg', 'team/web/admin.gpg']);

    // "Mark rotated" closes an item (rotation file is a normal encrypted write).
    const later = new Date(now.getTime() + 60_000);
    await commitMarkRotated({ snapshot: s, writer: w, folder: 'team', entries: ['team/db.gpg'], operatorKey: A.priv, now: later });
    const after = rotationChecklist(await readRotation(s, 'team', [A.priv]), s);
    expect(after[0]!.open.map((i) => i.path)).toEqual(['team/web/admin.gpg']);
    expect(after[0]!.done.map((i) => i.path)).toEqual(['team/db.gpg']);
    expect(await decryptText((await s.readFile('team/.g00pass-rotation.gpg'))!, D)).toContain('"g00pass.rotation"');
  });

  it('refuses: escrow, self, non-admin operator, non-member, changed plan', async () => {
    const s = await teamStore('rm1');
    expect(await code(previewRemoval(s, 'team', E.fpr, A.fpr))).toBe('escrow');
    expect(await code(previewRemoval(s, 'team', A.fpr, A.fpr))).toBe('self');
    expect(await code(previewRemoval(s, 'team', C.fpr, D.fpr))).toBe('not-admin');
    expect(await code(previewRemoval(s, 'team', N.fpr, A.fpr))).toBe('not-member');
    const plan = await previewRemoval(s, 'team', D.fpr, A.fpr);
    expect(plan.admins).toBeNull();
    expect(plan.resign).toEqual([]);
    const other = await previewRemoval(s, 'team', C.fpr, A.fpr);
    expect(await code(removeMember('team', D.fpr, { loadSnapshot: async () => s, writer: new MemoryWriter(s), operatorKey: A.priv, approvedPlanDigest: other.digest }))).toBe('plan-changed');
  });

  it('a folder admin (not an anchor) can remove a reader; the anchor-signed parts stay valid', async () => {
    const s = await teamStore('rm2');
    const plan = await previewRemoval(s, 'team', D.fpr, C.fpr);
    await removeMember('team', D.fpr, { loadSnapshot: async () => s, writer: new MemoryWriter(s), operatorKey: C.priv, approvedPlanDigest: plan.digest });
    expect((await verifyRecipients(s, { folder: 'team' })).fingerprints).toEqual(expect.not.arrayContaining([D.fpr]));
    expect(await folderTrustStatus(s, 'team/prod')).toMatchObject({ verified: true });
  });
});

describe('approval records the member and an admin grant is part of the reviewed plan', () => {
  it('folder-admin role: plan shows admins before → after; rotation file gets the member', async () => {
    const s = await teamStore('ap0');
    const r = await parseAccessRequest(await buildBody(N, { folder: 'team', role: 'folder-admin' }), { repo: 'acme/secrets', storeRoot: '' });
    if (!r.ok) throw new Error(r.message);
    const plan = await previewApproval(s, r.request, A.fpr);
    expect(plan.admins).toEqual({ before: [C.fpr], after: [C.fpr, N.fpr].sort() });
    // A reader plan (no admin grant) has a different digest: approving it as folder-admin is refused.
    const reader = await parseAccessRequest(await buildBody(N, { folder: 'team', role: 'reader' }), { repo: 'acme/secrets', storeRoot: '' });
    if (!reader.ok) throw new Error(reader.message);
    const readerPlan = await previewApproval(s, reader.request, A.fpr);
    expect(readerPlan.digest).not.toBe(plan.digest);
    const opts = (digest: string) => ({
      loadSnapshot: async () => s, writer: new MemoryWriter(s), operatorKey: A.priv, requestRef: 'acme/requests#3',
      confirmation: { fingerprintSuffix: N.fpr.slice(-16), acknowledgeUninvited: true, approvedPlan: digest },
    });
    expect(await code(approveAccessRequest(r.request, opts(readerPlan.digest)))).toBe('plan-changed');
    await approveAccessRequest(r.request, opts(plan.digest));
    expect(await isVerifiedFolderAdmin(s, 'team', N.fpr)).toBe(true);
    const doc = await readRotation(s, 'team', [N.priv]);
    expect(doc.members).toEqual([expect.objectContaining({ fingerprint: N.fpr, addedBy: A.fpr, request: 'acme/requests#3', removedAt: null })]);
  });
});

describe('rotation tracking (rotation.md §Tests)', () => {
  const R = new Date('2026-06-01T00:00:00Z');
  const before = new Date('2026-05-01T00:00:00Z');
  const after = new Date('2026-07-01T00:00:00Z');
  const snap = () => new MemoryStore({ 'f/.gpg-id': 'x', 'f/a.gpg': 'x', 'f/b.gpg': 'x', 'f/c.gpg': 'x', 'f/d.gpg': 'x', 'f/sub/.gpg-id': 'x', 'f/sub/z.gpg': 'x' });
  const op = 'A'.repeat(40);
  const X = 'B'.repeat(40);

  it('1. exposure with null, before-R and after-R timestamps', () => {
    let d = emptyRotation('f');
    d = recordEntryWrite(d, 'f/b.gpg', null, enc('1'), op, before); // created before R, never rotated -> open
    d = recordEntryWrite(d, 'f/c.gpg', null, enc('1'), op, after); // created after R -> not exposed
    d = recordEntryWrite(d, 'f/d.gpg', null, enc('1'), op, before);
    d = markRotated(d, 'f/d.gpg', op, after); // rotated after R -> done
    d = recordMemberAdded(d, { fingerprint: X, name: 'X', addedBy: op, request: null }, before);
    d = recordMemberRemoved(d, X, op, R);
    const [m] = rotationChecklist(d, snap());
    expect(m!.open.map((i) => i.path)).toEqual(['f/a.gpg', 'f/b.gpg']); // a: no metadata (unknown) -> open
    expect(m!.done.map((i) => i.path)).toEqual(['f/d.gpg']);
    expect([...m!.open, ...m!.done].some((i) => i.path.startsWith('f/sub/'))).toBe(false); // nested boundary excluded
  });

  it('2. a member re-added after removal has no open checklist; removal again uses the new record', () => {
    let d = emptyRotation('f');
    d = recordMemberAdded(d, { fingerprint: X, name: null, addedBy: op, request: null }, before);
    d = recordMemberRemoved(d, X, op, R);
    d = recordMemberAdded(d, { fingerprint: X, name: null, addedBy: op, request: 'o/r#2' }, after);
    expect(rotationChecklist(d, snap())).toEqual([]);
    d = recordMemberRemoved(d, X, op, new Date('2026-08-01T00:00:00Z'));
    expect(d.members).toHaveLength(2);
    expect(d.members[1]).toMatchObject({ request: 'o/r#2', removedAt: '2026-08-01T00:00:00Z' });
  });

  it('3. a rename keeps the metadata', () => {
    let d = recordEntryWrite(emptyRotation('f'), 'f/a.gpg', null, enc('1'), op, before);
    d = recordEntryMoved(d, 'f/a.gpg', 'f/renamed.gpg');
    expect(d.entries).toEqual({ renamed: { createdAt: '2026-05-01T00:00:00Z', rotatedAt: '2026-05-01T00:00:00Z', rotatedBy: op } });
  });

  it('5. a missing file is treated as empty; 6. only a changed first line counts as rotation', async () => {
    expect(await readRotation(new MemoryStore({}), 'f', [])).toEqual(emptyRotation('f'));
    let d = recordEntryWrite(emptyRotation('f'), 'f/a.gpg', null, enc('pw\nuser: x'), op, before);
    d = recordEntryWrite(d, 'f/a.gpg', enc('pw\nuser: x'), enc('pw\nuser: y'), op, R);
    expect(d.entries.a!.rotatedAt).toBe('2026-05-01T00:00:00Z');
    d = recordEntryWrite(d, 'f/a.gpg', enc('pw\nuser: y'), enc('pw2\nuser: y'), op, after);
    expect(d.entries.a!.rotatedAt).toBe('2026-07-01T00:00:00Z');
    expect(parseRotation(serializeRotation(d), 'f')).toEqual(d);
    expect(() => parseRotation(serializeRotation(d), 'other')).toThrow();
  });
});
