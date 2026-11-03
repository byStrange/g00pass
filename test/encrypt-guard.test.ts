import * as openpgp from 'openpgp';
import { beforeAll, describe, expect, it } from 'vitest';
import { MemoryStore, TrustError, encryptToVerified, installEncryptGuard, isEncryptGuardInstalled, verifyRecipients } from '../src/core';
import { type TestIdentity, decryptText, makeIdentity } from './helpers/keys';

// Own file: the guard patches openpgp's Message class for the whole module graph.
let alice: TestIdentity;
beforeAll(async () => {
  alice = await makeIdentity('Alice');
  installEncryptGuard();
});

describe('L5: runtime encrypt guard (installEncryptGuard)', () => {
  it('blocks openpgp.encrypt / Message#encrypt / encryptSessionKey outside encryptToVerified', async () => {
    expect(isEncryptGuardInstalled()).toBe(true);
    const message = await openpgp.createMessage({ text: 'x' });
    await expect(openpgp.encrypt({ message, encryptionKeys: alice.priv.toPublic() })).rejects.toThrow(/blocked/);
    await expect(openpgp.encrypt({ message, passwords: ['pw'] })).rejects.toThrow(/blocked/);
    await expect(message.encrypt([alice.priv.toPublic()])).rejects.toBeInstanceOf(TrustError);
    await expect(
      openpgp.encryptSessionKey({ data: new Uint8Array(32), algorithm: 'aes256', encryptionKeys: alice.priv.toPublic() }),
    ).rejects.toThrow(/blocked/);
  });

  it('cannot be undone by reassigning or redefining the wrapped methods', () => {
    const M = openpgp.Message as unknown as { prototype: Record<string, unknown>; encryptSessionKey: unknown };
    expect(() => {
      'use strict';
      M.prototype.encrypt = () => 'pwned';
    }).toThrow(TypeError);
    expect(() => Object.defineProperty(M, 'encryptSessionKey', { value: () => 'pwned' })).toThrow(TypeError);
  });

  it('encryptToVerified still works', async () => {
    const store = new MemoryStore({ '.gpg-id': `${alice.fpr}\n`, [`.public-keys/${alice.fpr}`]: alice.armoredPublic });
    const set = await verifyRecipients(store, { folder: '' });
    const ct = await encryptToVerified(new TextEncoder().encode('hello'), set);
    expect(await decryptText(ct, alice)).toBe('hello');
    const armored = await encryptToVerified(new TextEncoder().encode('hello'), set, { armor: true });
    expect(await decryptText(armored, alice)).toBe('hello');
  });

  it('re-review: blocks assembling a message from packets (PKESK.encrypt / SKESK.encrypt) outside encryptToVerified', async () => {
    const enc = (await alice.priv.toPublic().getEncryptionKey()).keyPacket;
    type Encryptable = { encrypt(k: unknown): Promise<void> };
    const PK = openpgp.PublicKeyEncryptedSessionKeyPacket as unknown as { fromObject(o: object): Encryptable };
    const pkesk = PK.fromObject({
      version: 3,
      encryptionKeyPacket: enc,
      anonymousRecipient: false,
      sessionKey: new Uint8Array(32),
      sessionKeyAlgorithm: openpgp.enums.symmetric.aes256,
    });
    await expect(pkesk.encrypt(enc)).rejects.toThrow(/blocked/);
    const skesk = new openpgp.SymEncryptedSessionKeyPacket() as unknown as Encryptable;
    await expect(skesk.encrypt('pw')).rejects.toThrow(/blocked/);
    // An authorized encryption to the same key does not leave it authorized afterwards.
    const store = new MemoryStore({ '.gpg-id': `${alice.fpr}\n`, [`.public-keys/${alice.fpr}`]: alice.armoredPublic });
    await encryptToVerified(new TextEncoder().encode('x'), await verifyRecipients(store, { folder: '' }));
    await expect(pkesk.encrypt(enc)).rejects.toThrow(/blocked/);
  });
});
