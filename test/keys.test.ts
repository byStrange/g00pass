import { beforeAll, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import { MemoryStore, RecipientKeyError, resolveRecipient, resolveRecipients } from '../src/core';
import { type TestIdentity, makeIdentity } from './helpers/keys';

let alice: TestIdentity;
let bob: TestIdentity;
beforeAll(async () => {
  [alice, bob] = await Promise.all([makeIdentity('Alice'), makeIdentity('Bob')]);
});

describe('public key resolution (.public-keys/<id>, gopass convention)', () => {
  it('resolves a fingerprint id from .public-keys/<id>', async () => {
    const s = new MemoryStore({ [`.public-keys/${alice.fpr}`]: alice.armoredPublic });
    const r = await resolveRecipient(s, alice.fpr);
    expect(r.fingerprint).toBe(alice.fpr);
    expect(r.source).toBe(`.public-keys/${alice.fpr}`);
  });

  it('falls back to the normalized id filename, then legacy .gpg-keys/', async () => {
    const s = new MemoryStore({ [`.public-keys/${alice.fpr}`]: alice.armoredPublic });
    const r = await resolveRecipient(s, '0x' + alice.fpr.toLowerCase());
    expect(r.source).toBe(`.public-keys/${alice.fpr}`);
    const legacy = new MemoryStore({ [`.gpg-keys/${bob.email}`]: bob.armoredPublic });
    expect((await resolveRecipient(legacy, bob.email)).fingerprint).toBe(bob.fpr);
  });

  it('accepts e-mail and long key id recipients and binary key files', async () => {
    const longId = alice.priv.getKeyID().toHex().toUpperCase();
    const bin = alice.priv.toPublic().write();
    const s = new MemoryStore({ [`.public-keys/${alice.email}`]: alice.armoredPublic, [`.public-keys/${longId}`]: bin });
    expect((await resolveRecipient(s, alice.email)).fingerprint).toBe(alice.fpr);
    expect((await resolveRecipient(s, longId)).fingerprint).toBe(alice.fpr);
  });

  it('rejects missing keys, mismatched keys, and private key files', async () => {
    await expect(resolveRecipient(new MemoryStore(), alice.fpr)).rejects.toThrow(RecipientKeyError);
    const wrong = new MemoryStore({ [`.public-keys/${alice.fpr}`]: bob.armoredPublic });
    await expect(resolveRecipient(wrong, alice.fpr)).rejects.toThrow(/exactly one key matching/);
    const priv = new MemoryStore({ [`.public-keys/${alice.fpr}`]: alice.priv.armor() });
    await expect(resolveRecipient(priv, alice.fpr)).rejects.toThrow(/PRIVATE/);
    const junk = new MemoryStore({ [`.public-keys/${alice.fpr}`]: 'hello' });
    await expect(resolveRecipient(junk, alice.fpr)).rejects.toThrow(/unreadable/);
  });

  it('rejects keys without a usable encryption subkey (expired)', async () => {
    const { publicKey } = await openpgp.generateKey({
      type: 'ecc',
      curve: 'curve25519Legacy',
      userIDs: [{ email: 'old@example.test' }],
      keyExpirationTime: 1,
      date: new Date(Date.now() - 86_400_000),
    });
    const k = await openpgp.readKey({ armoredKey: publicKey });
    const fpr = k.getFingerprint().toUpperCase();
    const s = new MemoryStore({ [`.public-keys/${fpr}`]: publicKey });
    await expect(resolveRecipient(s, fpr)).rejects.toThrow(/no valid encryption subkey/);
  });

  it('uses pending keys (same-commit additions) only when no store file exists', async () => {
    const pending = new Map([[bob.fpr, bob.armoredPublic]]);
    const r = await resolveRecipient(new MemoryStore(), bob.fpr, { pending });
    expect(r.source).toBe('pending');
    const bad = new Map([[alice.fpr, bob.armoredPublic]]);
    await expect(resolveRecipient(new MemoryStore(), bob.fpr, { pending: bad })).rejects.toThrow(/pending key/);
  });

  it('resolveRecipients dedupes by fingerprint', async () => {
    const s = new MemoryStore({
      [`.public-keys/${alice.fpr}`]: alice.armoredPublic,
      [`.public-keys/${alice.email}`]: alice.armoredPublic,
    });
    const r = await resolveRecipients(s, [alice.fpr, alice.email]);
    expect(r).toHaveLength(1);
  });
});
