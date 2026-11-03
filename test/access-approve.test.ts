import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import {
  ApprovalError,
  MemoryStore,
  MemoryWriter,
  approveAccessRequest,
  buildInbox,
  changeFolderRecipients,
  isFolderAdmin,
  parseAccessRequest,
  passThroughTrustHook,
  setTrustHook,
  type IssueSummary,
  type ParsedAccessRequest,
  type ReencryptProgress,
} from '../src/core';
import { type TestIdentity, dec, decryptText, encryptForTest, makeIdentity } from './helpers/keys';
import { buildBody } from './helpers/requests';

let alice: TestIdentity, bob: TestIdentity, carol: TestIdentity, dave: TestIdentity, escrow: TestIdentity;
let store: MemoryStore;
let writer: MemoryWriter;
const secrets: Record<string, string> = { 'team/db.gpg': 'db-pass', 'team/api/token.gpg': 'tok', '.g00pass-x.gpg': 'root-hidden' };
const ctx = { repo: 'acme/secrets', storeRoot: '' };

beforeAll(async () => {
  [alice, bob, carol, dave, escrow] = (await Promise.all(['Alice', 'Bob', 'Carol', 'Dave', 'Escrow'].map(makeIdentity))) as [
    TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity,
  ];
});

beforeEach(async () => {
  setTrustHook(passThroughTrustHook);
  store = new MemoryStore({
    '.gpg-id': `${alice.fpr}\n${escrow.fpr} # g00pass:escrow\n`,
    'team/.gpg-id': `${alice.fpr}\n${carol.fpr}\n${escrow.fpr} # g00pass:escrow\n`,
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
const approveOpts = (req: ParsedAccessRequest, over: Record<string, unknown> = {}) => ({
  loadSnapshot: async () => store,
  writer,
  operatorKey: alice.priv,
  confirmation: { confirmedFingerprint: req.fingerprint, acknowledgeUninvited: true },
  requestRef: 'acme/requests#7',
  ...over,
});

describe('approveAccessRequest', () => {
  it('adds the requester, keeps everyone + escrow, signs .gpg-id, one commit', async () => {
    const req = await request(bob);
    const progress: ReencryptProgress[] = [];
    const res = await approveAccessRequest(req, approveOpts(req, { onProgress: (p: ReencryptProgress) => progress.push(p) }));

    expect(writer.commits).toHaveLength(1);
    expect(writer.commits[0]!.message).toBe(`g00pass: grant ${bob.fpr.slice(-16)} reader on team (acme/requests#7)`);
    expect(res.commitSha).toBe(store.commitSha);
    for (const p of ['team/db.gpg', 'team/api/token.gpg']) {
      const ct = (await store.readFile(p))!;
      for (const who of [bob, alice, carol, escrow]) expect(await decryptText(ct, who)).toBe(secrets[p]);
    }
    const gpgId = dec((await store.readFile('team/.gpg-id'))!);
    expect(gpgId).toBe(`${alice.fpr}\n${carol.fpr}\n${escrow.fpr} # g00pass:escrow\n${bob.fpr}\n`);
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
    await approveAccessRequest(req, approveOpts(req, { armor: true }));
    const ct = (await store.readFile('team/db.gpg'))!;
    expect(dec(ct)).toContain('-----BEGIN PGP MESSAGE-----');
  });

  it('retries on conflict with a fresh snapshot', async () => {
    const req = await request(bob);
    let n = 0;
    const stale = new MemoryStore({}, 'stale');
    for (const p of store.listFiles()) stale.set(p, (await store.readFile(p))!);
    const res = await approveAccessRequest(req, approveOpts(req, { loadSnapshot: async () => (n++ === 0 ? stale : store) }));
    expect(n).toBe(2);
    expect(writer.commits).toHaveLength(1);
    expect(res.commitSha).toBe('mem-1');
  });

  it('refuses without the out-of-band fingerprint confirmation', async () => {
    const req = await request(bob);
    for (const confirmation of [
      { confirmedFingerprint: '' , acknowledgeUninvited: true },
      { confirmedFingerprint: carol.fpr, acknowledgeUninvited: true },
    ]) {
      await expect(approveAccessRequest(req, approveOpts(req, { confirmation }))).rejects.toMatchObject({ code: 'fingerprint-not-confirmed' });
    }
    await expect(approveAccessRequest(req, approveOpts(req, { confirmation: { confirmedFingerprint: req.fingerprint } }))).rejects.toMatchObject({
      code: 'invite-not-acknowledged',
    });
    expect(writer.commits).toHaveLength(0);
  });

  it('accepts a spaced, lower-case confirmation of the same fingerprint', async () => {
    const req = await request(bob);
    const spaced = req.fingerprint.toLowerCase().replace(/(.{4})/g, '$1 ');
    await approveAccessRequest(req, approveOpts(req, { confirmation: { confirmedFingerprint: spaced, acknowledgeUninvited: true } }));
    expect(writer.commits).toHaveLength(1);
  });

  it('refuses requests not produced by the parser', async () => {
    const req = { ...(await request(bob)) } as ParsedAccessRequest;
    await expect(approveAccessRequest(req, approveOpts(req))).rejects.toBeInstanceOf(ApprovalError);
  });

  it('refuses a non-admin recipient, a non-recipient, a missing folder and an existing recipient', async () => {
    const req = await request(bob);
    // carol is a recipient but neither folder admin nor global admin
    await expect(approveAccessRequest(req, approveOpts(req, { operatorKey: carol.priv }))).rejects.toMatchObject({ code: 'not-admin' });
    // dave: not a recipient
    await expect(approveAccessRequest(req, approveOpts(req, { operatorKey: dave.priv }))).rejects.toMatchObject({ code: 'not-recipient' });
    const nreq = await request(bob, { folder: 'nope' });
    await expect(approveAccessRequest(nreq, approveOpts(nreq))).rejects.toMatchObject({ code: 'no-such-folder' });
    const creq = await request(carol);
    await expect(approveAccessRequest(creq, approveOpts(creq))).rejects.toMatchObject({ code: 'already-recipient' });
    expect(writer.commits).toHaveLength(0);
  });

  it('makes a folder admin when listed in the admins file; folder-admin role writes a signed admins file', async () => {
    store.set('team/.g00pass-admins.json', JSON.stringify({ admins: [carol.fpr], folder: 'team', serial: 1, type: 'g00pass.folder-admins', version: 1 }));
    const req = await request(bob);
    // carol (folder admin via file, and a recipient) may approve; the operator key must decrypt
    await approveAccessRequest(req, approveOpts(req, { operatorKey: carol.priv }));
    expect(writer.commits).toHaveLength(1);

    const req2 = await request(dave, { role: 'folder-admin' });
    await approveAccessRequest(req2, approveOpts(req2));
    const file = JSON.parse(dec((await store.readFile('team/.g00pass-admins.json'))!));
    expect(file).toMatchObject({ admins: [carol.fpr, dave.fpr].sort(), serial: 2, updatedBy: alice.fpr, folder: 'team' });
    expect(file.previous).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await store.readFile('team/.g00pass-admins.json.sig')).not.toBeNull();
  });

  it('a global admin who is not a recipient cannot approve', async () => {
    store.set('.gpg-id', `${alice.fpr}\n${dave.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    const req = await request(bob);
    await expect(approveAccessRequest(req, approveOpts(req, { operatorKey: dave.priv }))).rejects.toMatchObject({ code: 'not-recipient' });
  });

  it('nothing is committed when an entry cannot be decrypted', async () => {
    store.set('team/other.gpg', await encryptForTest('x', [carol, escrow]));
    const req = await request(bob);
    await expect(approveAccessRequest(req, approveOpts(req))).rejects.toMatchObject({ name: 'ReencryptError' });
    expect(writer.commits).toHaveLength(0);
  });

  it('encryption goes through the trust hook (a rejecting hook blocks approval)', async () => {
    setTrustHook({ name: 'deny', verify: async () => ({ ok: false, code: 'unknown-signer', reason: 'no' }) });
    const req = await request(bob);
    await expect(approveAccessRequest(req, approveOpts(req))).rejects.toMatchObject({ name: 'TrustError' });
    expect(writer.commits).toHaveLength(0);
  });
});

describe('changeFolderRecipients (shared with remove-member)', () => {
  const opts = () => ({ snapshot: store, writer, operatorKey: alice.priv });

  it('removes a member: old ciphertext key no longer a recipient, escrow cannot be removed', async () => {
    await changeFolderRecipients('team', { remove: [carol.fpr] }, opts());
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
    await expect(changeFolderRecipients('team', { remove: [carol.fpr] }, { ...opts(), signal: ac.signal })).rejects.toMatchObject({ name: 'AbortError' });
    expect(writer.commits).toHaveLength(0);
  });
});

describe('isFolderAdmin (fail-closed placeholder)', () => {
  it('missing admins file: only global admins', async () => {
    expect(await isFolderAdmin(store, 'team', alice.fpr)).toBe(true);
    expect(await isFolderAdmin(store, 'team', carol.fpr)).toBe(false);
    expect(await isFolderAdmin(store, 'team', escrow.fpr)).toBe(false); // escrow is not a global admin
  });
  it('reads the nearest admins file; invalid or foreign-folder files grant nothing', async () => {
    store.set('team/.g00pass-admins.json', JSON.stringify({ admins: [carol.fpr], folder: 'team', type: 'g00pass.folder-admins', version: 1 }));
    expect(await isFolderAdmin(store, 'team', carol.fpr)).toBe(true);
    expect(await isFolderAdmin(store, 'team/api', carol.fpr)).toBe(true);
    store.set('team/.g00pass-admins.json', JSON.stringify({ admins: [carol.fpr], folder: 'other', type: 'g00pass.folder-admins', version: 1 }));
    expect(await isFolderAdmin(store, 'team', carol.fpr)).toBe(false);
    store.set('team/.g00pass-admins.json', '{not json');
    expect(await isFolderAdmin(store, 'team', carol.fpr)).toBe(false);
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
    expect(inbox.invalid.map((i) => [i.issue.number, i.code])).toEqual([
      [3, 'bad-signature'],
      [5, 'already-recipient'],
      [6, 'no-such-folder'],
    ]);
  });
});
