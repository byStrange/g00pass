import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as openpgp from 'openpgp';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  MemoryWriter,
  RecipientKeyError,
  TrustError,
  allFolderTrustStatus,
  checkFolderAdmin,
  evaluateRootTrust,
  folderTrustStatus,
  getPinnedAnchors,
  isVerifiedFolderAdmin,
  parseDetachedSignature,
  passThroughTrustHook,
  pinAnchors,
  reencryptFolder,
  resetAnchors,
  resetTrustEnvironment,
  setTrustHook,
  sha256Digest,
  signAdminsFile,
  signGpgId,
  signatureTrustHook,
  verifyAdminsFile,
  verifyProposedRecipients,
  verifyRecipients,
  writeEntry,
} from '../src/core';
import { type TestIdentity, decryptText, enc, encryptForTest, makeIdentity } from './helpers/keys';
import { FakeHistory, STORE_ID, adminsFiles, derive, freshEnv, signedGpgId, type EnvHandle } from './helpers/trust';

/**
 * Threat-model tests for the production trust policy
 * (docs/specs/gpg-id-signatures.md, folder-admins.md, store-layout.md).
 * Cast: A, B = pinned global admins (anchors); C = folder admin of infra;
 * D = plain member of infra; M = attacker with repo write; E = escrow.
 */
let A: TestIdentity, B: TestIdentity, C: TestIdentity, D: TestIdentity, M: TestIdentity, E: TestIdentity;
let base: MemoryStore;
let env: EnvHandle;

const rootText = () => `${A.fpr}\n${B.fpr}\n${E.fpr} # g00pass:escrow\n`;
const infraText = (...ids: TestIdentity[]) => ids.map((i) => i.fpr).join('\n') + `\n${E.fpr} # g00pass:escrow\n`;

async function write(store: MemoryStore, entry: string) {
  return writeEntry({ snapshot: store, writer: new MemoryWriter(store), entry, plaintext: enc('s3cret') });
}
const code = (p: Promise<unknown>) =>
  p.then(
    () => 'ok',
    (e: unknown) => (e instanceof TrustError ? e.code : e instanceof RecipientKeyError ? 'recipient-key' : `other:${(e as Error).message}`),
  );

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, B, C, D, M, E] = (await Promise.all(['A', 'B', 'C', 'D', 'M', 'E'].map((n) => makeIdentity(n, born)))) as TestIdentity[] as [TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity];
  setTrustHook(signatureTrustHook);
  freshEnv();
  const keys: Record<string, string> = {};
  for (const i of [A, B, C, D, M, E]) keys[`.public-keys/${i.fpr}`] = i.armoredPublic;
  const s0 = new MemoryStore({ ...keys, ...(await signedGpgId('', rootText(), A.priv)) }, 'c-base0');
  base = await derive(s0, {
    ...(await adminsFiles(s0, 'infra', [C.fpr], A.priv)),
    ...(await signedGpgId('infra', infraText(A, C, D), C.priv)),
    ...(await signedGpgId('infra/prod', infraText(C), C.priv)),
    'infra/db.gpg': await encryptForTest('db-pw', [A, C, D, E]),
  });
});
afterAll(() => {
  setTrustHook(passThroughTrustHook);
  resetTrustEnvironment();
});
beforeEach(() => {
  env = freshEnv();
  pinAnchors(STORE_ID, [A.fpr, B.fpr], 'first-use');
});

describe('baseline: correctly signed store', () => {
  it('writes in root, folder (direct admin) and sub-folder (inherited admin)', async () => {
    for (const e of ['top', 'infra/new', 'infra/prod/x']) {
      const s = await derive(base, {});
      const r = await write(s, e);
      expect(r.warnings).toEqual([]);
    }
    const s = await derive(base, {});
    const v = await verifyRecipients(s, { entry: 'infra/db' });
    expect(v.hook).toBe('gpg-id signatures v1');
    const ct = (await write(s, 'infra/db')).commitSha;
    expect(ct).toBeTruthy();
    expect(await decryptText((await s.readFile('infra/db.gpg'))!, E)).toBe('s3cret');
  });

  it('per-folder status for the UI matches the write path', async () => {
    const st = await allFolderTrustStatus(await derive(base, {}));
    expect(st.map((s) => [s.folder, s.verified])).toEqual([
      ['', true],
      ['infra', true],
      ['infra/prod', true],
    ]);
  });

  it('isVerifiedFolderAdmin / checkFolderAdmin', async () => {
    const s = await derive(base, {});
    expect(await isVerifiedFolderAdmin(s, 'infra', A.fpr)).toBe(true); // anchor
    expect(await isVerifiedFolderAdmin(s, 'infra', C.fpr)).toBe(true);
    expect(await isVerifiedFolderAdmin(s, 'infra/prod', C.fpr)).toBe(true); // inherited
    expect(await isVerifiedFolderAdmin(s, 'infra', D.fpr)).toBe(false);
    expect(await isVerifiedFolderAdmin(s, 'infra', M.fpr)).toBe(false);
    expect(await isVerifiedFolderAdmin(s, 'infra', E.fpr)).toBe(false); // escrow never admin
    expect(await isVerifiedFolderAdmin(s, '', C.fpr)).toBe(false); // root: anchors only
    expect(await isVerifiedFolderAdmin(s, 'infra', C.fpr.slice(-16))).toBe(false); // key id is not a fingerprint
    expect(await checkFolderAdmin(s, 'infra/prod', C.fpr)).toMatchObject({ admin: true, via: 'admins-file', grantedBy: 'infra' });
  });

  it('refuses everything when no anchors are pinned (first use)', async () => {
    resetAnchors(STORE_ID);
    expect(await code(write(await derive(base, {}), 'infra/x'))).toBe('untrusted');
    expect(await isVerifiedFolderAdmin(base, 'infra', A.fpr)).toBe(false);
  });
});

describe('threat: attacker with repo write edits a folder .gpg-id', () => {
  it('adds own key, no signature -> signature-missing', async () => {
    const s = await derive(base, { 'infra/.gpg-id': infraText(A, C, D, M), 'infra/.gpg-id.sig': null });
    expect(await code(write(s, 'infra/x'))).toBe('signature-missing');
  });

  it('adds own key, leaves old signature -> signature-invalid', async () => {
    const s = await derive(base, { 'infra/.gpg-id': infraText(A, C, D, M) });
    expect(await code(write(s, 'infra/x'))).toBe('signature-invalid');
  });

  it('adds own key and signs with own key -> unknown-signer', async () => {
    const s = await derive(base, await signedGpgId('infra', infraText(A, C, D, M), M.priv));
    const st = await folderTrustStatus(s, 'infra');
    expect(st).toMatchObject({ verified: false, code: 'unknown-signer' });
    expect(st.reason).toContain(M.fpr);
  });

  it('signature by a non-admin recipient -> unknown-signer', async () => {
    const s = await derive(base, await signedGpgId('infra', infraText(A, C, D, M), D.priv));
    expect(await code(write(s, 'infra/x'))).toBe('unknown-signer');
  });

  it('copies another folder’s .gpg-id + .sig (cross-folder replay) -> signature-invalid', async () => {
    // infra/prod's anchor-trusted signer C signed a list; copy infra's pair over infra/prod
    const s = await derive(base, {
      'infra/prod/.gpg-id': (await base.readFile('infra/.gpg-id'))!,
      'infra/prod/.gpg-id.sig': (await base.readFile('infra/.gpg-id.sig'))!,
    });
    const st = await folderTrustStatus(s, 'infra/prod');
    expect(st).toMatchObject({ verified: false, code: 'signature-invalid' });
    expect(st.reason).toContain('made for folder "/infra"');
  });

  it('escrow recipient removed (even by a real admin) -> escrow-missing', async () => {
    const s = await derive(base, await signedGpgId('infra', `${A.fpr}\n${C.fpr}\n`, C.priv));
    expect(await code(write(s, 'infra/x'))).toBe('escrow-missing');
  });

  it('weak ids (long key id / e-mail) in a signed .gpg-id -> weak-recipient', async () => {
    const longId = D.priv.getKeyID().toHex().toUpperCase();
    for (const id of [longId, D.email]) {
      const s = await derive(base, {
        [`.public-keys/${id}`]: D.armoredPublic, // resolvable, but the signed id is still weak
        ...(await signedGpgId('infra', `${C.fpr}\n${id}\n${E.fpr} # g00pass:escrow\n`, C.priv)),
      });
      expect(await code(write(s, 'infra/x'))).toBe('weak-recipient');
    }
  });

  it('recipient key file swapped under .public-keys (fingerprint mismatch) -> refused', async () => {
    const s = await derive(base, { [`.public-keys/${D.fpr}`]: M.armoredPublic });
    expect(await code(write(s, 'infra/x'))).toBe('recipient-key');
  });

  it('signer key file swapped (attacker key under the admin’s fingerprint) -> refused', async () => {
    const s = await derive(base, {
      [`.public-keys/${C.fpr}`]: M.armoredPublic,
      ...(await signedGpgId('infra/prod', infraText(M), M.priv)),
    });
    expect(await code(write(s, 'infra/prod/x'))).not.toBe('ok');
  });

  it('escrow key may not sign', async () => {
    const s = await derive(base, await signedGpgId('infra', infraText(A, C, M), E.priv));
    expect(await code(write(s, 'infra/x'))).toBe('unknown-signer');
  });
});

describe('threat: replay of an old .gpg-id + .gpg-id.sig (same folder)', () => {
  it('rejected on a device that has seen the newer version; accepted on a fresh device (documented limit)', async () => {
    const hourAgo = new Date(Date.now() - 3600_000);
    const old = await derive(base, await signedGpgId('infra', infraText(A, C, D), C.priv, hourAgo));
    const now = await derive(base, await signedGpgId('infra', infraText(A, C), C.priv));
    expect((await folderTrustStatus(now, 'infra')).verified).toBe(true);
    expect(await folderTrustStatus(old, 'infra')).toMatchObject({ verified: false, code: 'replayed' });

    env = freshEnv();
    pinAnchors(STORE_ID, [A.fpr, B.fpr], 'first-use');
    expect((await folderTrustStatus(old, 'infra')).verified).toBe(true); // NOT prevented without local history
  });
});

describe('threat: signer key state', () => {
  it('expired signer key (signature made while valid) -> refused', async () => {
    const past = new Date(Date.now() - 10 * 86400_000);
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'X' }], date: past, keyExpirationTime: 86400, format: 'object',
    });
    const X = privateKey.getFingerprint().toUpperCase();
    const s0 = await derive(base, { [`.public-keys/${X}`]: publicKey.armor() });
    const s = await derive(s0, {
      ...(await adminsFiles(s0, 'infra', [C.fpr, X], A.priv)),
      ...(await signedGpgId('infra', infraText(A, C), privateKey, new Date(past.getTime() + 3600_000))),
    });
    expect(await isVerifiedFolderAdmin(s, 'infra', X)).toBe(true);
    expect(await code(write(s, 'infra/x'))).toBe('signature-invalid');
  });

  it('revoked signer key -> refused (even for signatures dated before the revocation)', async () => {
    const R = await makeIdentity('R');
    const s0 = await derive(base, { [`.public-keys/${R.fpr}`]: R.armoredPublic });
    const s1 = await derive(s0, {
      ...(await adminsFiles(s0, 'infra', [C.fpr, R.fpr], A.priv)),
      ...(await signedGpgId('infra', infraText(A, C), R.priv)),
    });
    expect((await folderTrustStatus(s1, 'infra')).verified).toBe(true);
    const { publicKey: revoked } = await openpgp.revokeKey({ key: R.priv, format: 'armored' });
    env = freshEnv();
    pinAnchors(STORE_ID, [A.fpr, B.fpr], 'first-use');
    const s2 = await derive(s1, { [`.public-keys/${R.fpr}`]: revoked });
    expect(await code(write(s2, 'infra/x'))).toBe('signature-invalid');
  });

  it('signing subkey is accepted by PRIMARY fingerprint', async () => {
    const { privateKey } = await openpgp.generateKey({
      type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'S' }], subkeys: [{}, { sign: true }], format: 'object',
    });
    const S = privateKey.getFingerprint().toUpperCase();
    const s0 = await derive(base, { [`.public-keys/${S}`]: privateKey.toPublic().armor() });
    const files = await signedGpgId('infra', infraText(A, C), privateKey);
    const parsed = await parseDetachedSignature(files['infra/.gpg-id.sig'] as Uint8Array);
    expect(privateKey.getSubkeys().map((k) => k.getKeyID().toHex().toUpperCase())).toContain(parsed.issuerKeyId);
    const s = await derive(s0, { ...(await adminsFiles(s0, 'infra', [C.fpr, S], A.priv)), ...files });
    expect((await folderTrustStatus(s, 'infra')).verified).toBe(true);
  });

  it('future-dated signature (> 5 min) -> refused', async () => {
    const s = await derive(base, await signedGpgId('infra', infraText(A, C), C.priv, new Date(Date.now() + 3600_000)));
    expect(await code(write(s, 'infra/x'))).toBe('signature-invalid');
  });
});

describe('signature format', () => {
  it('accepts armored, rejects text-mode, multi-packet and garbage signatures', async () => {
    const text = infraText(A, C);
    const bin = await signGpgId(text, 'infra', C.priv);
    const sig = await openpgp.readSignature({ binarySignature: bin });
    const armored = await derive(base, { 'infra/.gpg-id': text, 'infra/.gpg-id.sig': sig.armor() });
    expect((await folderTrustStatus(armored, 'infra')).verified).toBe(true);

    const textSig = await openpgp.sign({ message: await openpgp.createMessage({ text }), signingKeys: C.priv, detached: true, format: 'binary' });
    const t = await derive(base, { 'infra/.gpg-id': text, 'infra/.gpg-id.sig': textSig as Uint8Array });
    expect((await folderTrustStatus(t, 'infra')).code).toBe('signature-invalid');

    const two = new Uint8Array([...bin, ...(await signGpgId(text, 'infra', A.priv))]);
    const tw = await derive(base, { 'infra/.gpg-id': text, 'infra/.gpg-id.sig': two });
    expect((await folderTrustStatus(tw, 'infra')).reason).toContain('exactly one');

    const g = await derive(base, { 'infra/.gpg-id': text, 'infra/.gpg-id.sig': enc('nope') });
    expect((await folderTrustStatus(g, 'infra')).code).toBe('signature-invalid');
  });

  it('gpg --detach-sign fixture (offline, folder-bound) verifies; plain pass signature is not folder-bound', async () => {
    const fx = (f: string) => readFileSync(join(__dirname, 'fixtures/gpg', f));
    const GPG = '1C7F172FAFB0F0461DC02D26075D719D60EADF3D';
    const s0 = new MemoryStore(
      {
        [`.public-keys/${A.fpr}`]: A.armoredPublic,
        [`.public-keys/${GPG}`]: fx('public-key.asc'),
        ...(await signedGpgId('', `${A.fpr}\n`, A.priv)),
        'ops/.gpg-id': fx('ops.gpg-id'),
        'ops/.gpg-id.sig': fx('ops.gpg-id.sig'),
      },
      'fx0',
    );
    pinAnchors(STORE_ID, [A.fpr], 'manual');
    const s = await derive(s0, await adminsFiles(s0, 'ops', [GPG], A.priv));
    expect(await folderTrustStatus(s, 'ops')).toMatchObject({ verified: true });
    const p = await derive(s, { 'ops/.gpg-id.sig': fx('ops.gpg-id.pass-style.sig') });
    const st = await folderTrustStatus(p, 'ops');
    expect(st).toMatchObject({ verified: false, code: 'signature-invalid' });
    expect(st.reason).toContain('not bound to a folder');
  });
});

describe('root .gpg-id vs pinned anchors', () => {
  it('root changed without signature -> anchor-mismatch, and NO folder is writable', async () => {
    const s = await derive(base, { '.gpg-id': `${A.fpr}\n${B.fpr}\n${M.fpr}\n${E.fpr} # g00pass:escrow\n` });
    expect(await code(write(s, 'top'))).toBe('anchor-mismatch');
    expect(await code(write(s, 'infra/x'))).toBe('anchor-mismatch');
    const r = await evaluateRootTrust(s);
    expect(r).toMatchObject({ ok: false, added: [M.fpr], removed: [] });
  });

  it('root self-signed by the attacker -> anchor-mismatch', async () => {
    const s = await derive(base, await signedGpgId('', `${M.fpr}\n${E.fpr} # g00pass:escrow\n`, M.priv));
    expect(await code(write(s, 'infra/x'))).toBe('anchor-mismatch');
  });

  it('attacker swaps the escrow line (same admins) -> refused', async () => {
    const s = await derive(base, { '.gpg-id': `${A.fpr}\n${B.fpr}\n${M.fpr} # g00pass:escrow\n` });
    expect(await code(write(s, 'infra/x'))).toBe('signature-invalid');
  });

  it('root signed by a non-anchor (folder admin) -> refused', async () => {
    const s = await derive(base, await signedGpgId('', rootText(), C.priv));
    expect(await code(write(s, 'top'))).toBe('unknown-signer');
  });

  it('pinned escrow fingerprint still cannot sign the root', async () => {
    pinAnchors(STORE_ID, [A.fpr, B.fpr, E.fpr], 'manual');
    const s = await derive(base, await signedGpgId('', `${A.fpr}\n${B.fpr}\n${E.fpr} # g00pass:escrow\n`, E.priv));
    expect(await code(write(s, 'top'))).not.toBe('ok');
  });

  it('anchor rollover: a validly signed change re-pins; removed anchors lose authority', async () => {
    const s = await derive(base, await signedGpgId('', `${A.fpr}\n${C.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv));
    const r = await evaluateRootTrust(s);
    expect(r).toMatchObject({ ok: true, rolledOver: true, signer: A.fpr });
    expect(getPinnedAnchors(STORE_ID)?.anchors).toEqual([A.fpr, C.fpr].sort());
    expect(getPinnedAnchors(STORE_ID)?.source).toBe('rollover');
    expect(await isVerifiedFolderAdmin(s, 'infra', B.fpr)).toBe(false);
    // B re-signing the same list is now refused
    const s2 = await derive(s, await signedGpgId('', `${A.fpr}\n${C.fpr}\n${E.fpr} # g00pass:escrow\n`, B.priv));
    expect(await code(write(s2, 'top'))).toBe('unknown-signer');
  });

  it('anchor may sign themselves out; the rolled-over root stays trusted', async () => {
    const s = await derive(base, await signedGpgId('', `${B.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv));
    expect((await evaluateRootTrust(s)).ok).toBe(true);
    expect((await evaluateRootTrust(s)).ok).toBe(true);
    expect(getPinnedAnchors(STORE_ID)?.anchors).toEqual([B.fpr]);
    expect(await code(write(s, 'top'))).toBe('ok');
  });

  it('replayed old root after a rollover is rejected', async () => {
    const hourAgo = new Date(Date.now() - 3600_000);
    const s0 = await derive(base, await signedGpgId('', rootText(), A.priv, hourAgo));
    expect((await evaluateRootTrust(s0)).ok).toBe(true);
    const s1 = await derive(base, await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv));
    expect((await evaluateRootTrust(s1)).ok).toBe(true);
    expect(getPinnedAnchors(STORE_ID)?.anchors).toEqual([A.fpr]);
    expect(await evaluateRootTrust(s0)).toMatchObject({ ok: false, code: 'replayed' }); // older root signature
  });
});

describe('folder admins file (folder-admins.md tests)', () => {
  async function chain(n: number, folderSigner: TestIdentity = C) {
    const states: MemoryStore[] = [];
    let cur = await derive(base, { 'infra/.g00pass-admins.json': null, 'infra/.g00pass-admins.json.sig': null });
    for (let i = 1; i <= n; i++) {
      cur = await derive(cur, await adminsFiles(cur, 'infra', i === n ? [D.fpr, C.fpr] : [C.fpr], i === 1 ? A.priv : folderSigner.priv));
      states.unshift(cur);
    }
    return states;
  }

  it('chain of three valid versions; cache hit and cache miss', async () => {
    const states = await chain(3);
    const head = states[0]!;
    env.history = new FakeHistory(states);
    expect(await verifyAdminsFile(head, 'infra')).toMatchObject({ status: 'valid', serial: 3, via: 'chain' });
    expect(await isVerifiedFolderAdmin(head, 'infra', D.fpr)).toBe(true);
    // cache hit: same device, no history needed
    env.history = null;
    const again = await derive(head, {});
    expect(await verifyAdminsFile(again, 'infra')).toMatchObject({ status: 'valid', via: 'cache' });
    // cache miss on a new device without history: unverifiable
    env = freshEnv();
    pinAnchors(STORE_ID, [A.fpr, B.fpr], 'first-use');
    expect(await verifyAdminsFile(await derive(head, {}), 'infra')).toMatchObject({ status: 'invalid' });
    expect(await isVerifiedFolderAdmin(await derive(head, {}), 'infra', D.fpr)).toBe(false);
  });

  it('forged serial jump', async () => {
    const s1 = (await chain(2))[1]!;
    const forged = await signAdminsFile({ snapshot: s1, folder: 'infra', admins: [C.fpr, M.fpr], signingKey: C.priv });
    const doc = { ...forged.document, serial: 3 };
    const bytes = JSON.stringify(Object.fromEntries(Object.entries(doc).sort()), null, 2) + '\n';
    const s = await derive(s1, { 'infra/.g00pass-admins.json': bytes, 'infra/.g00pass-admins.json.sig': await signDetachedFor(bytes, C) });
    env.history = new FakeHistory([s, s1]);
    expect(await verifyAdminsFile(s, 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('serial jump') });
  });

  it('previous mismatch', async () => {
    const states = await chain(1);
    const s1 = states[0]!;
    const doc = {
      admins: [C.fpr, M.fpr].sort(), folder: 'infra', previous: await sha256Digest(enc('other')), serial: 2,
      type: 'g00pass.folder-admins', updatedAt: '2026-11-02T10:00:00Z', updatedBy: C.fpr, version: 1,
    };
    const bytes = JSON.stringify(doc, null, 2) + '\n';
    const s = await derive(s1, { 'infra/.g00pass-admins.json': bytes, 'infra/.g00pass-admins.json.sig': await signDetachedFor(bytes, C) });
    env.history = new FakeHistory([s, s1]);
    expect(await verifyAdminsFile(s, 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('chain of custody broken') });
  });

  it('tampered admins file (attacker adds self, keeps signature) grants nothing', async () => {
    const bytes = new TextDecoder().decode((await base.readFile('infra/.g00pass-admins.json'))!);
    const tampered = bytes.replace(`"${C.fpr}"`, `"${C.fpr}",\n    "${M.fpr}"`);
    const s = await derive(base, {
      'infra/.g00pass-admins.json': tampered,
      ...(await signedGpgId('infra', infraText(A, C, D, M), M.priv)),
    });
    expect(await verifyAdminsFile(s, 'infra')).toMatchObject({ status: 'invalid' });
    expect(await isVerifiedFolderAdmin(s, 'infra', M.fpr)).toBe(false);
    expect(await code(write(s, 'infra/x'))).toBe('unknown-signer');
  });

  it('self-signed first version by a non-anchor non-delegate is invalid', async () => {
    const s0 = await derive(base, { 'infra/.g00pass-admins.json': null, 'infra/.g00pass-admins.json.sig': null });
    const s = await derive(s0, await adminsFiles(s0, 'infra', [M.fpr], M.priv));
    expect(await verifyAdminsFile(s, 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('serial 1') });
  });

  it('file copied from another folder is invalid', async () => {
    const s = await derive(base, {
      ...(await signedGpgId('clients', infraText(A), A.priv)),
      'clients/.g00pass-admins.json': (await base.readFile('infra/.g00pass-admins.json'))!,
      'clients/.g00pass-admins.json.sig': (await base.readFile('infra/.g00pass-admins.json.sig'))!,
    });
    expect(await verifyAdminsFile(s, 'clients')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('folder') });
  });

  it('delegation from a parent folder', async () => {
    const s = await derive(base, {
      ...(await adminsFiles(base, 'infra/prod', [D.fpr], C.priv)),
    });
    const s2 = await derive(s, await signedGpgId('infra/prod', infraText(C, D), D.priv));
    expect(await verifyAdminsFile(s2, 'infra/prod')).toMatchObject({ status: 'valid', via: 'ancestor-admin' });
    expect((await folderTrustStatus(s2, 'infra/prod')).verified).toBe(true);
    expect(await isVerifiedFolderAdmin(s2, 'infra', D.fpr)).toBe(false); // delegation flows down only
  });

  it('history walk limited by depth (20 versions)', async () => {
    const states = await chain(22);
    env.history = new FakeHistory(states.slice(1)); // head = serial 21
    expect(await verifyAdminsFile(states[1]!, 'infra')).toMatchObject({ status: 'valid', serial: 21 });
    env = freshEnv();
    pinAnchors(STORE_ID, [A.fpr, B.fpr], 'first-use');
    env.history = new FakeHistory(states);
    expect(await verifyAdminsFile(states[0]!, 'infra')).toMatchObject({ status: 'invalid' });
  }, 60_000);

  it('rollback to an older (validly signed) version is rejected on a device that saw the newer one', async () => {
    const states = await chain(2);
    env.history = new FakeHistory(states);
    expect(await verifyAdminsFile(states[0]!, 'infra')).toMatchObject({ status: 'valid', serial: 2 });
    expect(await verifyAdminsFile(await derive(states[1]!, {}), 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('rolled back') });
  });

  it('signAdminsFile round trip: serial/previous follow the current file', async () => {
    const f = await signAdminsFile({ snapshot: base, folder: 'infra', admins: [D.fpr, C.fpr], signingKey: C.priv });
    expect(f.document.serial).toBe(2);
    expect(f.document.previous).toBe(await sha256Digest((await base.readFile('infra/.g00pass-admins.json'))!));
    expect(f.document.admins).toEqual([C.fpr, D.fpr].sort());
    const s = await derive(base, { [f.path]: f.content, [f.sigPath]: f.signature });
    env.history = new FakeHistory([s, base]);
    expect(await verifyAdminsFile(s, 'infra')).toMatchObject({ status: 'valid', serial: 2 });
  });
});

describe('proposed recipients (approve / remove / re-encrypt)', () => {
  const run = async (s: MemoryStore, signer: TestIdentity | null, lines: string[], folder = 'infra', sigFolder = folder, extra = {}) => {
    const w = new MemoryWriter(s);
    const r = reencryptFolder(folder, lines, {
      snapshot: s,
      writer: w,
      decryptionKeys: [C.priv],
      gpgIdSignature: signer ? (t) => signGpgId(t, sigFolder, signer.priv) : undefined,
      ...extra,
    });
    return { r, w };
  };

  it('folder admin removes a member: signed, committed, and the result verifies', async () => {
    const s = await derive(base, {});
    const { r, w } = await run(s, C, [A.fpr, C.fpr]);
    const res = await r;
    expect(res.gpgIdText).toBe(infraText(A, C));
    expect(w.commits[0]!.changes.map((c) => c.path)).toContain('infra/.gpg-id.sig');
    const after = await derive(s, {});
    expect((await folderTrustStatus(after, 'infra')).verified).toBe(true);
  });

  it('non-admin recipient cannot change recipients; nothing is committed', async () => {
    const s = await derive(base, {});
    const { r, w } = await run(s, D, [A.fpr, C.fpr, D.fpr, M.fpr]);
    expect(await code(r)).toBe('unknown-signer');
    expect(w.commits).toEqual([]);
  });

  it('no signature -> signature-missing; signature bound to another folder -> signature-invalid', async () => {
    expect(await code((await run(await derive(base, {}), null, [C.fpr])).r)).toBe('signature-missing');
    expect(await code((await run(await derive(base, {}), C, [C.fpr], 'infra', 'infra/prod')).r)).toBe('signature-invalid');
  });

  it('an admins file added in the same commit does not authorize its own signer', async () => {
    const s = await derive(base, {});
    const af = await signAdminsFile({ snapshot: s, folder: 'infra', admins: [M.fpr], signingKey: M.priv });
    const { r, w } = await run(s, M, [A.fpr, C.fpr, M.fpr], 'infra', 'infra', { extraChanges: af.changes });
    expect(await code(r)).toBe('unknown-signer');
    expect(w.commits).toEqual([]);
  });

  it('root changes need an anchor', async () => {
    const s = await derive(base, {});
    const sig = (k: TestIdentity) => async (t: string) => signGpgId(t, '', k.priv);
    expect(await code(verifyProposedRecipients(s, '', [A.fpr, C.fpr], { signature: sig(C) }))).toBe('unknown-signer');
    const ok = await verifyProposedRecipients(s, '', [A.fpr, B.fpr, C.fpr], { signature: sig(B) });
    expect(ok.verified.fingerprints).toContain(E.fpr);
  });

  it('the verified set is bound to the snapshot it was verified on', async () => {
    const s = await derive(base, {});
    const p = await verifyProposedRecipients(s, 'infra', [C.fpr], { signature: (t) => signGpgId(t, 'infra', C.priv) });
    expect(p.verified.snapshotSha).toBe(s.commitSha);
  });
});

async function signDetachedFor(text: string, id: TestIdentity): Promise<Uint8Array> {
  return (await openpgp.sign({
    message: await openpgp.createMessage({ binary: enc(text) }),
    signingKeys: id.priv,
    detached: true,
    format: 'binary',
  })) as Uint8Array;
}

