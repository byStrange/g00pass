// Regression tests for the Phase 1 security review (C1, H1, H2, M1).
// Started from the reviewer's probes (/tmp/g00pass-probe.test.ts), which
// demonstrated each attack against the REAL signatureTrustHook. Every test
// here asserts that the attack is REFUSED; against the pre-fix code each one
// fails (the attack succeeded).
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  MemoryWriter,
  TrustError,
  approveAccessRequest,
  buildInbox,
  changeFolderRecipients,
  isVerifiedFolderAdmin,
  parseAccessRequest,
  passThroughTrustHook,
  pinAnchors,
  planFolderRecipientChange,
  reencryptFolder,
  resetTrustEnvironment,
  setTrustHook,
  signAdminsFile,
  signGpgId,
  signatureTrustHook,
  verifyAdminsFile,
  verifyRecipients,
  writeEntry,
} from '../src/core';
import { type TestIdentity, decryptText, enc, encryptForTest, makeIdentity } from './helpers/keys';
import { buildBody } from './helpers/requests';
import { FakeHistory, STORE_ID, derive, freshEnv, signedGpgId, type EnvHandle } from './helpers/trust';

let A: TestIdentity, C: TestIdentity, D: TestIdentity, M: TestIdentity, E: TestIdentity, N: TestIdentity, E2: TestIdentity;
let env: EnvHandle;
const ctx = { repo: 'acme/secrets', storeRoot: '' };

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, C, D, M, E, N, E2] = (await Promise.all(['A', 'C', 'D', 'M', 'E', 'N', 'E2'].map((n) => makeIdentity(n, born)))) as TestIdentity[] as [
    TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity,
  ];
  setTrustHook(signatureTrustHook);
});
afterAll(() => {
  setTrustHook(passThroughTrustHook);
  resetTrustEnvironment();
});
beforeEach(() => {
  env = freshEnv();
  pinAnchors(STORE_ID, [A.fpr], 'first-use');
});

const keys = (...ids: TestIdentity[]) => Object.fromEntries(ids.map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic]));
const rootText = () => `${A.fpr}\n${E.fpr} # g00pass:escrow\n`;
const txt = (...ids: TestIdentity[]) => ids.map((i) => i.fpr).join('\n') + `\n${E.fpr} # g00pass:escrow\n`;
const refusal = (p: Promise<unknown>) =>
  p.then(
    () => 'ok',
    (e: unknown) => (e as { code?: string }).code ?? `other:${(e as Error).message}`,
  );
const issue = (body: string) => ({ number: 1, title: 't', body, state: 'open' as const, labels: [], author: null, htmlUrl: null, createdAt: null });

describe('C1: approval must not re-sign an attacker-edited .gpg-id', () => {
  it('attacker appends own key to team/.gpg-id; inbox blocks it, approval and plan refuse, nothing is committed', async () => {
    const s0 = new MemoryStore({
      ...keys(A, C, D, E),
      ...(await signedGpgId('', rootText(), A.priv, { children: ['team'] })),
      ...(await signedGpgId('team', txt(A, C), A.priv)),
      'team/db.gpg': await encryptForTest('db-pass', [A, C, E]),
    }, 'c0');
    const tampered = new TextDecoder().decode((await s0.readFile('team/.gpg-id'))!) + `${M.fpr}\n`;
    const store = await derive(s0, { 'team/.gpg-id': tampered, ...keys(M) });
    await expect(verifyRecipients(store, { folder: 'team' })).rejects.toMatchObject({ code: 'signature-invalid' });

    const body = await buildBody(D, { folder: 'team' });
    const r = await parseAccessRequest(body, ctx);
    if (!r.ok) throw new Error(r.message);
    const inbox = await buildInbox({ issues: [issue(body)], snapshot: store, store: ctx, operatorFingerprint: A.fpr });
    expect(inbox.actionable).toHaveLength(0);
    expect(inbox.blocked).toHaveLength(1);
    expect(inbox.blocked[0]).toMatchObject({ code: 'folder-not-verified' });
    expect(inbox.blocked[0]!.reason).toContain('signature-invalid');

    await expect(planFolderRecipientChange(store, 'team', { add: [{ fingerprint: D.fpr, publicKey: D.armoredPublic }] }, { operatorFingerprint: A.fpr }))
      .rejects.toMatchObject({ code: 'folder-not-verified' });

    const writer = new MemoryWriter(store);
    expect(
      await refusal(
        approveAccessRequest(r.request, {
          loadSnapshot: async () => store,
          writer,
          operatorKey: A.priv,
          confirmation: { fingerprintSuffix: D.fpr.slice(-16), acknowledgeUninvited: true, approvedPlan: 'sha256:' + '0'.repeat(64) },
          requestRef: 'x#1',
        }),
      ),
    ).toBe('folder-not-verified');
    expect(
      await refusal(changeFolderRecipients('team', { add: [{ fingerprint: D.fpr, publicKey: D.armoredPublic }] }, { snapshot: store, writer, operatorKey: A.priv, approvedPlanDigest: 'x' })),
    ).toBe('folder-not-verified');
    expect(writer.commits).toHaveLength(0);
    expect(new TextDecoder().decode((await store.readFile('team/.gpg-id'))!)).toBe(tampered); // still unsigned/invalid
    await expect(decryptText((await store.readFile('team/db.gpg'))!, M)).rejects.toThrow();
    await expect(writeEntry({ snapshot: store, writer, entry: 'team/new', plaintext: enc('future') })).rejects.toMatchObject({ code: 'signature-invalid' });
  });
});

describe('H1: a removed folder admin cannot fork the admins chain', () => {
  async function setup(sha: string) {
    const s0 = new MemoryStore({
      ...keys(A, C, M, E),
      ...(await signedGpgId('', rootText(), A.priv, { children: ['infra'] })),
      ...(await signedGpgId('infra', txt(A, C), A.priv)),
    }, sha);
    const sign = async (base: MemoryStore, admins: string[], k: TestIdentity) => {
      const f = await signAdminsFile({ snapshot: base, folder: 'infra', admins, signingKey: k.priv });
      return derive(base, { [f.path]: f.content, [f.sigPath]: f.signature });
    };
    const v1 = await sign(s0, [C.fpr, M.fpr], A);
    const v2 = await sign(v1, [C.fpr], C); // M removed
    return { s0, sign, v1, v2 };
  }

  it("V1(A:[C,M]) -> V2(C:[C]); M commits V2'(M) + V3'(M): refused on a device that cached V2, cache not poisoned", async () => {
    const { sign, v1, v2 } = await setup('p0');
    env.history = new FakeHistory([v2, v1]);
    expect(await verifyAdminsFile(v2, 'infra')).toMatchObject({ status: 'valid', serial: 2 });
    expect(await isVerifiedFolderAdmin(v2, 'infra', M.fpr)).toBe(false);

    const v2f = await sign(v1, [M.fpr], M); // serial 2, previous = digest(V1)
    const v2fOnHead = await derive(v2, {
      'infra/.g00pass-admins.json': (await v2f.readFile('infra/.g00pass-admins.json'))!,
      'infra/.g00pass-admins.json.sig': (await v2f.readFile('infra/.g00pass-admins.json.sig'))!,
    });
    const v3f = await sign(v2fOnHead, [M.fpr], M); // serial 3, previous = digest(V2')
    env.history = new FakeHistory([v3f, v2fOnHead, v2, v1]);
    expect(await verifyAdminsFile(v3f, 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('fork') });
    expect(await isVerifiedFolderAdmin(v3f, 'infra', M.fpr)).toBe(false);

    const pwn = await derive(v3f, await signedGpgId('infra', txt(A, C, M), M.priv));
    expect(await refusal(writeEntry({ snapshot: pwn, writer: new MemoryWriter(pwn), entry: 'infra/new', plaintext: enc('future') }))).toBe('unknown-signer');

    // The legitimate V2 still verifies (the fork did not overwrite the cache).
    env.history = new FakeHistory([v2, v1]);
    expect(await verifyAdminsFile(await derive(v2, {}), 'infra')).toMatchObject({ status: 'valid', serial: 2 });
  });

  it("fresh device: V2' alone (on top of V2 in history) is refused", async () => {
    const { sign, v1, v2 } = await setup('q0');
    const v2f = await derive(v2, {});
    const forked = await sign(v1, [M.fpr], M);
    v2f.set('infra/.g00pass-admins.json', (await forked.readFile('infra/.g00pass-admins.json'))!);
    v2f.set('infra/.g00pass-admins.json.sig', (await forked.readFile('infra/.g00pass-admins.json.sig'))!);
    env.history = new FakeHistory([v2f, v2, v1]);
    expect(await isVerifiedFolderAdmin(v2f, 'infra', M.fpr)).toBe(false);
    expect(await verifyAdminsFile(v2f, 'infra')).toMatchObject({ status: 'invalid' });
  });

  it('fresh device: restoring the anchor-signed V1 bytes (rollback) is refused when history shows V2', async () => {
    const { v1, v2 } = await setup('r0');
    const reverted = await derive(v2, {
      'infra/.g00pass-admins.json': (await v1.readFile('infra/.g00pass-admins.json'))!,
      'infra/.g00pass-admins.json.sig': (await v1.readFile('infra/.g00pass-admins.json.sig'))!,
    });
    env.history = new FakeHistory([reverted, v2, v1]);
    expect(await verifyAdminsFile(reverted, 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('rolled back') });
    expect(await isVerifiedFolderAdmin(reverted, 'infra', M.fpr)).toBe(false);
  });

  it('fresh device: a sibling fork elsewhere in reachable history invalidates the file', async () => {
    const { sign, v1, v2 } = await setup('f0');
    const v2f = await sign(v1, [M.fpr], M);
    // History: V3 (by C, cites V2) on top, with M's sibling V2' committed in between.
    const mid = await derive(v2, {
      'infra/.g00pass-admins.json': (await v2f.readFile('infra/.g00pass-admins.json'))!,
      'infra/.g00pass-admins.json.sig': (await v2f.readFile('infra/.g00pass-admins.json.sig'))!,
    });
    const v3 = await sign(v2, [C.fpr], C);
    const head = await derive(mid, {
      'infra/.g00pass-admins.json': (await v3.readFile('infra/.g00pass-admins.json'))!,
      'infra/.g00pass-admins.json.sig': (await v3.readFile('infra/.g00pass-admins.json.sig'))!,
    });
    env.history = new FakeHistory([head, mid, v2, v1]);
    expect(await verifyAdminsFile(head, 'infra')).toMatchObject({ status: 'invalid' });
  });
});

describe('H2: deleting a nested .gpg-id must not widen access', () => {
  async function prodStore(sha: string, opts: { declare?: boolean } = {}) {
    const declare = opts.declare ?? true;
    return new MemoryStore({
      ...keys(A, C, D, N, E),
      ...(await signedGpgId('', rootText(), A.priv, { children: ['infra'] })),
      ...(await signedGpgId('infra', txt(A, C, D), A.priv, { children: declare ? ['infra/prod'] : [] })),
      ...(await signedGpgId('infra/prod', txt(A, C), A.priv)),
      'infra/x.gpg': await encryptForTest('infra-secret', [A, C, D, E]),
      'infra/prod/root-pw.gpg': await encryptForTest('prod-secret', [A, C, E]),
    }, sha);
  }
  const addN = (s: MemoryStore) =>
    planFolderRecipientChange(s, 'infra', { add: [{ fingerprint: N.fpr, publicKey: N.armoredPublic }] }, { operatorFingerprint: A.fpr }).then((plan) =>
      changeFolderRecipients('infra', { add: [{ fingerprint: N.fpr, publicKey: N.armoredPublic }] }, { snapshot: s, writer: new MemoryWriter(s), operatorKey: A.priv, approvedPlanDigest: plan.digest }),
    );

  it('fresh device: member D deletes infra/prod/.gpg-id(.sig); prod writes and an infra approval are refused', async () => {
    const s = await derive(await prodStore('n0'), { 'infra/prod/.gpg-id': null, 'infra/prod/.gpg-id.sig': null });
    expect(await refusal(writeEntry({ snapshot: s, writer: new MemoryWriter(s), entry: 'infra/prod/new', plaintext: enc('future-prod') }))).toBe('boundary-vanished');
    expect(s.hasFile('infra/prod/new.gpg')).toBe(false);
    const err = (await addN(s).catch((e: unknown) => e)) as Error & { code?: string };
    expect(err).toMatchObject({ code: 'folder-not-verified' });
    expect(String(err.message)).toContain('deleted');
    // The engine itself refuses too (even when called directly).
    const direct = reencryptFolder('infra', [A.fpr, C.fpr, D.fpr, N.fpr], {
      snapshot: s, writer: new MemoryWriter(s), decryptionKeys: [A.priv],
      pendingKeys: new Map([[N.fpr, N.armoredPublic]]),
      gpgIdSignature: (t, c) => signGpgId(t, 'infra', A.priv, { children: c.children }),
    });
    expect(await refusal(direct)).toBe('boundary-vanished');
    await expect(decryptText((await s.readFile('infra/prod/root-pw.gpg'))!, D)).rejects.toThrow();
    // Writing elsewhere in infra still works.
    await writeEntry({ snapshot: s, writer: new MemoryWriter(s), entry: 'infra/other', plaintext: enc('ok') });
  });

  it('existing device: even if the parent never declared prod, the device-local high-water set refuses', async () => {
    const legacy = await prodStore('n1', { declare: false });
    // Undeclared nested boundary: not writable (it must be declared first).
    expect(await refusal(writeEntry({ snapshot: legacy, writer: new MemoryWriter(legacy), entry: 'infra/prod/y', plaintext: enc('y') }))).toBe('boundary-undeclared');
    // Declare it (admin re-signs infra) and use it once on this device.
    const declared = await derive(legacy, await signedGpgId('infra', txt(A, C, D), A.priv, { children: ['infra/prod'] }));
    await writeEntry({ snapshot: declared, writer: new MemoryWriter(declared), entry: 'infra/prod/y', plaintext: enc('y') });
    // Attacker replays the OLD (genuine, undeclaring) infra signature and deletes prod.
    const s = await derive(declared, {
      'infra/.gpg-id.sig': (await legacy.readFile('infra/.gpg-id.sig'))!,
      'infra/prod/.gpg-id': null,
      'infra/prod/.gpg-id.sig': null,
    });
    expect(await refusal(writeEntry({ snapshot: s, writer: new MemoryWriter(s), entry: 'infra/prod/new', plaintext: enc('z') }))).not.toBe('ok');
    // Even with a NEWER infra signature that "forgot" the declaration, the known set refuses.
    const forgot = await derive(declared, {
      ...(await signedGpgId('infra', txt(A, C, D), A.priv, { date: new Date(Date.now() + 1000) })),
      'infra/prod/.gpg-id': null,
      'infra/prod/.gpg-id.sig': null,
    });
    expect(await refusal(writeEntry({ snapshot: forgot, writer: new MemoryWriter(forgot), entry: 'infra/prod/new', plaintext: enc('z') }))).toBe('boundary-vanished');
    expect(await refusal(addN(forgot))).toBe('folder-not-verified');
  });

  it('fresh device, worst case (parent signature never declared prod, prod deleted): re-encrypting infra refuses to absorb prod entries (PKESK check)', async () => {
    const legacy = await prodStore('n2', { declare: false });
    const s = await derive(legacy, { 'infra/prod/.gpg-id': null, 'infra/prod/.gpg-id.sig': null });
    const err = (await addN(s).catch((e: unknown) => e)) as Error & { failedPaths?: string[] };
    expect(err).toMatchObject({ name: 'ReencryptError' });
    expect(err.failedPaths).toEqual(['infra/prod/root-pw.gpg']);
    expect(err.message).toContain(D.fpr);
    await expect(decryptText((await s.readFile('infra/prod/root-pw.gpg'))!, D)).rejects.toThrow();
  });

  it("deleting the child AND forging the parent's declaration away needs an authorized signer", async () => {
    const s = await derive(await prodStore('n3'), {
      ...(await signedGpgId('infra', txt(A, C, D), D.priv)), // D is a member, not an admin
      'infra/prod/.gpg-id': null,
      'infra/prod/.gpg-id.sig': null,
    });
    expect(await refusal(writeEntry({ snapshot: s, writer: new MemoryWriter(s), entry: 'infra/prod/new', plaintext: enc('z') }))).toBe('unknown-signer');
  });
});

describe('M1: a retired escrow key is dropped on re-encrypt', () => {
  it('root escrow rotated E -> E2; approval in team drops E and adds E2', async () => {
    const s = new MemoryStore({
      ...keys(A, D, E, E2),
      ...(await signedGpgId('', `${A.fpr}\n${E2.fpr} # g00pass:escrow\n`, A.priv, { children: ['team'] })),
      ...(await signedGpgId('team', txt(A), A.priv)),
      'team/x.gpg': await encryptForTest('x', [A, E]),
    }, 'e0');
    const change = { add: [{ fingerprint: D.fpr, publicKey: D.armoredPublic }] };
    const plan = await planFolderRecipientChange(s, 'team', change, { operatorFingerprint: A.fpr });
    expect(plan.droppedEscrow).toEqual([E.fpr]);
    expect(plan.warnings).toContain('escrow-missing');
    expect(plan.after.map((p) => p.fingerprint)).toEqual([A.fpr, D.fpr, E2.fpr]);
    await changeFolderRecipients('team', change, { snapshot: s, writer: new MemoryWriter(s), operatorKey: A.priv, approvedPlanDigest: plan.digest });
    const t = new TextDecoder().decode((await s.readFile('team/.gpg-id'))!);
    expect(t).not.toContain(E.fpr);
    expect(t).toBe(`${A.fpr}\n${D.fpr}\n${E2.fpr} # g00pass:escrow\n`);
    await expect(decryptText((await s.readFile('team/x.gpg'))!, E)).rejects.toThrow();
    expect(await decryptText((await s.readFile('team/x.gpg'))!, E2)).toBe('x');
    expect((await verifyRecipients(s, { folder: 'team' })).fingerprints).not.toContain(E.fpr);
  });

  it('the escrow repair path is only open when everything except escrow verifies', async () => {
    const s = new MemoryStore({
      ...keys(A, D, E, E2, M),
      ...(await signedGpgId('', `${A.fpr}\n${E2.fpr} # g00pass:escrow\n`, A.priv, { children: ['team'] })),
      ...(await signedGpgId('team', txt(A, M), M.priv)), // escrow-missing AND wrong signer
    }, 'e1');
    await expect(planFolderRecipientChange(s, 'team', {}, { operatorFingerprint: A.fpr })).rejects.toMatchObject({ code: 'folder-not-verified' });
    expect(TrustError).toBeDefined();
  });
});
