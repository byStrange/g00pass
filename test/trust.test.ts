import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  TrustError,
  encryptToVerified,
  isVerifiedRecipientSet,
  passThroughTrustHook,
  setTrustHook,
  verifyProposedRecipients,
  verifyRecipients,
  type RecipientVerificationRequest,
} from '../src/core';
import { type TestIdentity, decryptText, enc, makeIdentity } from './helpers/keys';

let alice: TestIdentity, bob: TestIdentity, escrow: TestIdentity;
let store: MemoryStore;
beforeAll(async () => {
  [alice, bob, escrow] = await Promise.all([makeIdentity('Alice'), makeIdentity('Bob'), makeIdentity('Escrow')]);
  store = new MemoryStore({
    '.gpg-id': `${alice.fpr}\n${escrow.fpr} # org recovery g00pass:escrow\n`,
    'team/.gpg-id': `${bob.fpr}\n`,
    'team/.gpg-id.sig': new Uint8Array([1, 2, 3]),
    [`.public-keys/${alice.fpr}`]: alice.armoredPublic,
    [`.public-keys/${bob.fpr}`]: bob.armoredPublic,
    [`.public-keys/${escrow.fpr}`]: escrow.armoredPublic,
  });
});
afterEach(() => setTrustHook(passThroughTrustHook));

describe('trust choke-point', () => {
  it('verifyRecipients uses the nearest .gpg-id and passes signature bytes to the hook', async () => {
    const seen: RecipientVerificationRequest[] = [];
    setTrustHook({ name: 'spy', verify: async (r) => (seen.push(r), { ok: true }) });
    const v = await verifyRecipients(store, { entry: 'team/sub/x' });
    expect(v.gpgIdPath).toBe('team/.gpg-id');
    expect(v.fingerprints).toEqual([bob.fpr]);
    expect(v.hook).toBe('spy');
    expect(v.warnings).toContain('escrow-missing'); // existing folder lacking escrow -> warning
    expect(seen[0]!.proposed).toBe(false);
    expect([...seen[0]!.gpgIdSignature!]).toEqual([1, 2, 3]);
    expect(Object.isFrozen(v)).toBe(true);
  });

  it('pass-through hook flags results as unverified', async () => {
    const v = await verifyRecipients(store, { entry: 'x' });
    expect(v.warnings).toContain('recipient-signatures-not-verified');
    expect(v.fingerprints).toEqual([alice.fpr, escrow.fpr]);
  });

  it('a rejecting or throwing hook blocks (fail closed)', async () => {
    setTrustHook({ name: 'no', verify: async () => ({ ok: false, code: 'signature-invalid', reason: 'bad sig' }) });
    await expect(verifyRecipients(store, { entry: 'x' })).rejects.toMatchObject({ code: 'signature-invalid' });
    setTrustHook({ name: 'boom', verify: async () => { throw new Error('kaput'); } });
    await expect(verifyRecipients(store, { entry: 'x' })).rejects.toThrow(TrustError);
    setTrustHook({ name: 'weird', verify: async () => ({}) as never });
    await expect(verifyRecipients(store, { entry: 'x' })).rejects.toThrow(TrustError);
  });

  it('encryptToVerified refuses anything not minted by the choke-point', async () => {
    const v = await verifyRecipients(store, { entry: 'x' });
    expect(isVerifiedRecipientSet(v)).toBe(true);
    const forged = { ...v };
    expect(isVerifiedRecipientSet(forged)).toBe(false);
    await expect(encryptToVerified(enc('s3cret'), forged)).rejects.toMatchObject({ code: 'not-verified' });
    const ct = await encryptToVerified(enc('s3cret'), v);
    expect(await decryptText(ct as Uint8Array, alice)).toBe('s3cret');
    expect(await decryptText(ct as Uint8Array, escrow)).toBe('s3cret');
  });

  it('proposed sets always include escrow recipients from root .gpg-id', async () => {
    const p = await verifyProposedRecipients(store, 'team', [bob.fpr, alice.fpr]);
    expect(p.gpgIdText).toBe(`${bob.fpr}\n${alice.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    expect(p.verified.fingerprints).toEqual([bob.fpr, alice.fpr, escrow.fpr]);
    expect(p.verified.proposed).toBe(true);
  });

  it('signer callback receives the exact final text', async () => {
    let signed = '';
    const p = await verifyProposedRecipients(store, 'team', [bob.fpr], {
      signature: async (t) => ((signed = t), enc('SIG')),
    });
    expect(signed).toBe(p.gpgIdText);
    expect(p.gpgIdSignature).toEqual(enc('SIG'));
  });
});
