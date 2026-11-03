import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import {
  ApprovalError,
  MemoryStore,
  MemoryWriter,
  approveAccessRequest,
  buildInbox,
  changeFolderRecipients,
  checkFolderAdmin,
  isVerifiedFolderAdmin,
  pinAnchors,
  resetTrustEnvironment,
  signatureTrustHook,
  verifyRecipients,
  parseAccessRequest,
  passThroughTrustHook,
  planFolderRecipientChange,
  previewApproval,
  setTrustHook,
  type RecipientChange,
  type IssueSummary,
  type ParsedAccessRequest,
  type ReencryptProgress,
} from '../src/core';
import { type TestIdentity, dec, decryptText, encryptForTest, makeIdentity } from './helpers/keys';
import { buildBody } from './helpers/requests';
import { STORE_ID, adminsFiles, derive, freshEnv, signedGpgId } from './helpers/trust';

let alice: TestIdentity, bob: TestIdentity, carol: TestIdentity, dave: TestIdentity, escrow: TestIdentity;
let store: MemoryStore;
let writer: MemoryWriter;
const secrets: Record<string, string> = { 'team/db.gpg': 'db-pass', 'team/api/token.gpg': 'tok', '.g00pass-x.gpg': 'root-hidden' };
const ctx = { repo: 'acme/secrets', storeRoot: '' };

beforeAll(async () => {
  // Keys are back-dated so signatures made "now" are valid under the signer-valid-now rule.
  const born = new Date(Date.now() - 2 * 86400_000);
  [alice, bob, carol, dave, escrow] = (await Promise.all(['Alice', 'Bob', 'Carol', 'Dave', 'Escrow'].map((n) => makeIdentity(n, born)))) as [
    TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity,
  ];
});

afterEach(() => {
  setTrustHook(passThroughTrustHook);
  resetTrustEnvironment();
});

beforeEach(async () => {
  setTrustHook(passThroughTrustHook);
  freshEnv();
  // Alice is the pinned global admin (trust anchor); root and team/.gpg-id carry her folder-bound signatures.
  pinAnchors(STORE_ID, [alice.fpr], 'first-use');
  const rootText = `${alice.fpr}\n${escrow.fpr} # g00pass:escrow\n`;
  const teamText = `${alice.fpr}\n${carol.fpr}\n${escrow.fpr} # g00pass:escrow\n`;
  store = new MemoryStore({
    ...(await signedGpgId('', rootText, alice.priv, { children: ['team'] })),
    ...(await signedGpgId('team', teamText, alice.priv)),
    ...Object.fromEntries([alice, carol, escrow, dave].map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic])),
  });
  store.set('team/db.gpg', await encryptForTest(secrets['team/db.gpg']!, [alice, carol, escrow]));
  store.set('team/api/token.gpg', await encryptForTest(secrets['team/api/token.gpg']!, [alice, carol, escrow]));
  writer = new MemoryWriter(store);
});

async function request(id: TestIdentity, over: Record<string, unknown> = {}): Promise<ParsedAccessRequest> {
  const r = await parseAccessRequest(await buildBody(id, over), ctx);
  if (!r.ok) throw new Error(r.message);
  return r.request;
}
/** Approve options as the UI builds them: typed suffix + digest of the plan the operator reviewed. */
const approveOpts = async (req: ParsedAccessRequest, over: Record<string, unknown> = {}) => {
  const operatorKey = (over.operatorKey as typeof alice.priv | undefined) ?? alice.priv;
  const plan = await previewApproval(store, req, operatorKey.getFingerprint().toUpperCase()).catch(() => null);
  return {
    loadSnapshot: async () => store,
    writer,
    operatorKey,
    confirmation: { fingerprintSuffix: req.fingerprint.slice(-16), acknowledgeUninvited: true, approvedPlan: plan?.digest ?? 'sha256:none' },
    requestRef: 'acme/requests#7',
    ...over,
  };
};
/** changeFolderRecipients with the plan computed (and "approved") first. */
async function change(folder: string, ch: RecipientChange, over: Record<string, unknown> = {}) {
  const operatorKey = (over.operatorKey as typeof alice.priv | undefined) ?? alice.priv;
  const plan = await planFolderRecipientChange(store, folder, ch, { operatorFingerprint: operatorKey.getFingerprint().toUpperCase() });
  return changeFolderRecipients(folder, ch, { snapshot: store, writer, operatorKey, approvedPlanDigest: plan.digest, ...over });
}

describe('approveAccessRequest', () => {
  it('adds the requester, keeps everyone + escrow, signs .gpg-id, one commit', async () => {
    const req = await request(bob);
    const progress: ReencryptProgress[] = [];
    const res = await approveAccessRequest(req, await approveOpts(req, { onProgress: (p: ReencryptProgress) => progress.push(p) }));

    expect(writer.commits).toHaveLength(1);
    expect(writer.commits[0]!.message).toBe(`g00pass: grant ${bob.fpr.slice(-16)} reader on team (acme/requests#7)`);
    expect(res.commitSha).toBe(store.commitSha);
    for (const p of ['team/db.gpg', 'team/api/token.gpg']) {
      const ct = (await store.readFile(p))!;
      for (const who of [bob, alice, carol, escrow]) expect(await decryptText(ct, who)).toBe(secrets[p]);
    }
    const gpgId = dec((await store.readFile('team/.gpg-id'))!);
    expect(gpgId).toBe(`${alice.fpr}\n${carol.fpr}\n${bob.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    expect(gpgId).toContain(`${escrow.fpr} # g00pass:escrow`);
    expect(gpgId).toContain(bob.fpr);
    expect(dec((await store.readFile(`.public-keys/${bob.fpr}`))!)).toContain('BEGIN PGP PUBLIC KEY BLOCK');
    expect(progress.at(-1)).toMatchObject({ phase: 'done' });

    // .gpg-id.sig verifies with the approver's key over the exact committed bytes
    const sig = (await store.readFile('team/.gpg-id.sig'))!;
    const v = await openpgp.verify({
      message: await openpgp.createMessage({ binary: (await store.readFile('team/.gpg-id'))! }),
      signature: await openpgp.readSignature({ binarySignature: sig }),
      verificationKeys: alice.priv.toPublic(),
    });
    await expect(v.signatures[0]!.verified).resolves.toBe(true);
  });

  it('uses armored inline output above the entry threshold', async () => {
    const req = await request(bob);
    await approveAccessRequest(req, await approveOpts(req, { armor: true }));
    const ct = (await store.readFile('team/db.gpg'))!;
    expect(dec(ct)).toContain('-----BEGIN PGP MESSAGE-----');
  });

  it('retries on conflict with a fresh snapshot', async () => {
    const req = await request(bob);
    let n = 0;
    const stale = new MemoryStore({}, 'stale');
    for (const p of store.listFiles()) stale.set(p, (await store.readFile(p))!);
    const res = await approveAccessRequest(req, await approveOpts(req, { loadSnapshot: async () => (n++ === 0 ? stale : store) }));
    expect(n).toBe(2);
    expect(writer.commits).toHaveLength(1);
    expect(res.commitSha).toBe('mem-1');
  });

  it('refuses without the typed fingerprint suffix (L4) or without the approved plan', async () => {
    const req = await request(bob);
    const base = await approveOpts(req);
    for (const fingerprintSuffix of ['', carol.fpr.slice(-16), req.fingerprint, req.fingerprint.slice(-8), req.fingerprint.slice(-15), 'zzzzzzzzzzzzzzzz']) {
      await expect(approveAccessRequest(req, { ...base, confirmation: { ...base.confirmation, fingerprintSuffix } })).rejects.toMatchObject({ code: 'fingerprint-not-confirmed' });
    }
    await expect(approveAccessRequest(req, { ...base, confirmation: { ...base.confirmation, acknowledgeUninvited: false } })).rejects.toMatchObject({
      code: 'invite-not-acknowledged',
    });
    await expect(approveAccessRequest(req, { ...base, confirmation: { ...base.confirmation, approvedPlan: '' } })).rejects.toMatchObject({ code: 'plan-changed' });
    expect(writer.commits).toHaveLength(0);
  });

  it('C1: refuses when the recipient change differs from the plan the operator approved', async () => {
    const req = await request(bob);
    const reviewed = await approveOpts(req);
    // Someone (validly, under the pass-through hook) adds dave after the operator reviewed the plan.
    store.set('team/.gpg-id', `${alice.fpr}\n${carol.fpr}\n${dave.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    store.set('team/db.gpg', await encryptForTest('db-pass', [alice, carol, dave, escrow]));
    store.set('team/api/token.gpg', await encryptForTest('tok', [alice, carol, dave, escrow]));
    await expect(approveAccessRequest(req, reviewed)).rejects.toMatchObject({ code: 'plan-changed' });
    expect(writer.commits).toHaveLength(0);
    const plan = await previewApproval(store, req, alice.fpr);
    expect(plan.before.map((p) => p.fingerprint)).toEqual([alice.fpr, carol.fpr, dave.fpr, escrow.fpr]);
    expect(plan.after.map((p) => p.fingerprint)).toEqual([alice.fpr, carol.fpr, dave.fpr, bob.fpr, escrow.fpr]);
    expect(plan.added).toEqual([bob.fpr]);
    expect(plan.removed).toEqual([]);
    expect(plan.after.find((p) => p.fingerprint === bob.fpr)?.userIds).toEqual([`Bob <bob@example.test>`]);
    expect(plan.after.at(-1)).toMatchObject({ fingerprint: escrow.fpr, escrow: true });
    await approveAccessRequest(req, { ...reviewed, confirmation: { ...reviewed.confirmation, approvedPlan: plan.digest } });
    expect(writer.commits).toHaveLength(1);
  });

  it('refuses requests not produced by the parser', async () => {
    const req = { ...(await request(bob)) } as ParsedAccessRequest;
    await expect(approveAccessRequest(req, await approveOpts(await request(bob)))).rejects.toBeInstanceOf(ApprovalError);
  });

  it('refuses a non-admin recipient, a non-recipient, a missing folder and an existing recipient', async () => {
    const req = await request(bob);
    // carol is a recipient but neither folder admin nor global admin
    await expect(approveAccessRequest(req, await approveOpts(req, { operatorKey: carol.priv }))).rejects.toMatchObject({ code: 'not-admin' });
    // dave: not a recipient
    await expect(approveAccessRequest(req, await approveOpts(req, { operatorKey: dave.priv }))).rejects.toMatchObject({ code: 'not-recipient' });
    const nreq = await request(bob, { folder: 'nope' });
    await expect(approveAccessRequest(nreq, await approveOpts(nreq))).rejects.toMatchObject({ code: 'no-such-folder' });
    const creq = await request(carol);
    await expect(approveAccessRequest(creq, await approveOpts(creq))).rejects.toMatchObject({ code: 'already-recipient' });
    expect(writer.commits).toHaveLength(0);
  });

  it('makes a folder admin when listed in a verified admins file; folder-admin role writes a signed admins file', async () => {
    for (const [p, c] of Object.entries(await adminsFiles(store, 'team', [carol.fpr], alice.priv))) store.set(p, c);
    const req = await request(bob);
    // carol (folder admin via signed file, and a recipient) may approve; the operator key must decrypt
    await approveAccessRequest(req, await approveOpts(req, { operatorKey: carol.priv }));
    expect(writer.commits).toHaveLength(1);

    const req2 = await request(dave, { role: 'folder-admin' });
    await approveAccessRequest(req2, await approveOpts(req2));
    const file = JSON.parse(dec((await store.readFile('team/.g00pass-admins.json'))!));
    expect(file).toMatchObject({ admins: [carol.fpr, dave.fpr].sort(), serial: 2, updatedBy: alice.fpr, folder: 'team' });
    expect(file.previous).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await store.readFile('team/.g00pass-admins.json.sig')).not.toBeNull();
    expect(await isVerifiedFolderAdmin(store, 'team', dave.fpr)).toBe(true);
  });

  it('refuses when the root is not trusted (no pinned anchors), even for a recipient anchor', async () => {
    pinAnchors(STORE_ID, [dave.fpr], 'manual');
    const req = await request(bob);
    await expect(approveAccessRequest(req, await approveOpts(req))).rejects.toMatchObject({ code: 'not-admin' });
    expect(writer.commits).toHaveLength(0);
  });

  it('a global admin who is not a recipient cannot approve', async () => {
    store.set('.gpg-id', `${alice.fpr}\n${dave.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    const req = await request(bob);
    await expect(approveAccessRequest(req, await approveOpts(req, { operatorKey: dave.priv }))).rejects.toMatchObject({ code: 'not-recipient' });
  });

  it('nothing is committed when an entry cannot be decrypted', async () => {
    store.set('team/other.gpg', await encryptForTest('x', [carol, escrow]));
    const req = await request(bob);
    await expect(approveAccessRequest(req, await approveOpts(req))).rejects.toMatchObject({ name: 'ReencryptError' });
    expect(writer.commits).toHaveLength(0);
  });

  it('encryption goes through the trust hook (a rejecting hook blocks approval)', async () => {
    const req = await request(bob);
    const o = await approveOpts(req);
    // Rejects the CURRENT set: refused up front (C1), before anything is signed.
    setTrustHook({ name: 'deny', verify: async () => ({ ok: false, code: 'unknown-signer', reason: 'no' }) });
    await expect(approveAccessRequest(req, o)).rejects.toMatchObject({ code: 'folder-not-verified' });
    // Accepts the current set, rejects the proposed one: the re-encrypt is refused by the hook.
    setTrustHook({ name: 'deny-proposed', verify: async (r) => (r.proposed ? { ok: false, code: 'unknown-signer', reason: 'no' } : { ok: true }) });
    await expect(approveAccessRequest(req, o)).rejects.toMatchObject({ name: 'TrustError' });
    expect(writer.commits).toHaveLength(0);
  });
});

describe('changeFolderRecipients (shared with remove-member)', () => {
  const opts = () => ({ snapshot: store, writer, operatorKey: alice.priv, approvedPlanDigest: 'unused' });

  it('removes a member: old ciphertext key no longer a recipient, escrow cannot be removed', async () => {
    await change('team', { remove: [carol.fpr] });
    const ct = (await store.readFile('team/db.gpg'))!;
    expect(await decryptText(ct, alice)).toBe('db-pass');
    expect(await decryptText(ct, escrow)).toBe('db-pass');
    await expect(decryptText(ct, carol)).rejects.toThrow();
    expect(dec((await store.readFile('team/.gpg-id'))!)).not.toContain(carol.fpr);
    await expect(changeFolderRecipients('team', { remove: [escrow.fpr] }, opts())).rejects.toThrow(/escrow/i);
    await expect(changeFolderRecipients('team', { remove: [dave.fpr] }, opts())).rejects.toThrow(/not a recipient/);
  });

  it('refuses root, unknown folders, duplicates and mismatched keys', async () => {
    await expect(changeFolderRecipients('', { add: [] }, opts())).rejects.toThrow();
    await expect(changeFolderRecipients('nope', { add: [] }, opts())).rejects.toThrow(/no .gpg-id/);
    await expect(changeFolderRecipients('team', { add: [{ fingerprint: carol.fpr, publicKey: carol.armoredPublic }] }, opts())).rejects.toThrow(/Already/);
    await expect(changeFolderRecipients('team', { add: [{ fingerprint: bob.fpr, publicKey: dave.armoredPublic }] }, opts())).rejects.toThrow();
    await expect(changeFolderRecipients('team', { add: [] }, { ...opts(), operatorKey: dave.priv })).rejects.toThrow(/not a recipient/);
    expect(writer.commits).toHaveLength(0);
  });

  it('is cancellable', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(change('team', { remove: [carol.fpr] }, { signal: ac.signal })).rejects.toMatchObject({ name: 'AbortError' });
    expect(writer.commits).toHaveLength(0);
  });
});

describe('verified folder admin check', () => {
  it('without an admins file only anchors are admins; escrow never', async () => {
    expect(await isVerifiedFolderAdmin(store, 'team', alice.fpr)).toBe(true);
    expect(await isVerifiedFolderAdmin(store, 'team', carol.fpr)).toBe(false);
    expect(await isVerifiedFolderAdmin(store, 'team', escrow.fpr)).toBe(false);
    expect((await checkFolderAdmin(store, 'team', carol.fpr)).reason).toMatch(/not a verified admin/);
  });
  it('grants via a signed admins file (inherited); unsigned or garbage files grant nothing', async () => {
    const files = await adminsFiles(store, 'team', [carol.fpr], alice.priv);
    const signed = await derive(store, files); // new commit sha per state (verification is cached per commit)
    expect(await isVerifiedFolderAdmin(signed, 'team', carol.fpr)).toBe(true);
    expect(await isVerifiedFolderAdmin(signed, 'team/api', carol.fpr)).toBe(true);
    const unsigned = await derive(signed, { 'team/.g00pass-admins.json.sig': null });
    expect(await isVerifiedFolderAdmin(unsigned, 'team', carol.fpr)).toBe(false);
    const garbage = await derive(signed, { 'team/.g00pass-admins.json': '{not json' });
    expect(await isVerifiedFolderAdmin(garbage, 'team', carol.fpr)).toBe(false);
  });
});

describe('approval with the REAL signatureTrustHook', () => {
  it('anchor-signed root + folder admin approves; the commit passes verifyRecipients', async () => {
    setTrustHook(signatureTrustHook);
    for (const [p, c] of Object.entries(await adminsFiles(store, 'team', [carol.fpr], alice.priv))) store.set(p, c);
    const req = await request(bob);
    // carol is a folder admin (signed file) and a recipient; her .gpg-id signature must verify.
    const res = await approveAccessRequest(req, await approveOpts(req, { operatorKey: carol.priv }));
    expect(writer.commits).toHaveLength(1);
    expect(res.commitSha).toBe(store.commitSha);
    expect(dec((await store.readFile('team/.gpg-id'))!)).toContain(bob.fpr);
    const v = await verifyRecipients(store, { folder: 'team' });
    expect(v.hook).toBe('gpg-id signatures v1');
    expect(v.fingerprints).toContain(bob.fpr);
    expect(await decryptText((await store.readFile('team/db.gpg'))!, bob)).toBe('db-pass');
  });

  it('a folder-admin approval writes an admins file the verifier accepts', async () => {
    setTrustHook(signatureTrustHook);
    const req = await request(dave, { role: 'folder-admin' });
    await approveAccessRequest(req, await approveOpts(req));
    expect(await isVerifiedFolderAdmin(store, 'team', dave.fpr)).toBe(true);
  });

  it('refuses a non-admin recipient before anything is written', async () => {
    setTrustHook(signatureTrustHook);
    const req = await request(bob);
    await expect(approveAccessRequest(req, await approveOpts(req, { operatorKey: carol.priv }))).rejects.toMatchObject({ code: 'not-admin' });
    expect(writer.commits).toHaveLength(0);
  });
});

describe('buildInbox', () => {
  const issue = (number: number, body: string | null, extra: Partial<IssueSummary> = {}): IssueSummary => ({
    number, title: 't', body, state: 'open', labels: [], author: 'x', htmlUrl: null, createdAt: null, ...extra,
  });

  it('shows actionable requests only; flags invalid; hides foreign folders', async () => {
    store.set('other/.gpg-id', `${dave.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    const good = await buildBody(bob);
    const inbox = await buildInbox({
      issues: [
        issue(1, good),
        issue(2, await buildBody(bob, { folder: 'other' })), // alice is not a recipient of other
        issue(3, (await buildBody(bob)).replace('"folder": "team"', '"folder": "prod"')), // tampered
        issue(4, 'unrelated bug report'),
        issue(5, await buildBody(carol)), // already a recipient
        issue(6, await buildBody(bob, { folder: 'ghost' })), // folder without .gpg-id
        issue(7, good, { state: 'closed' }),
      ],
      snapshot: store,
      store: ctx,
      operatorFingerprint: alice.fpr,
    });
    expect(inbox.actionable.map((i) => i.issue.number)).toEqual([1]);
    expect(inbox.hidden).toBe(1);
    expect(inbox.hiddenReasons.map((r) => r.issue.number)).toEqual([2]);
    expect(inbox.invalid.map((i) => [i.issue.number, i.code])).toEqual([
      [3, 'bad-signature'],
      [5, 'already-recipient'],
      [6, 'no-such-folder'],
    ]);
  });
});
