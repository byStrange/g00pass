import * as openpgp from 'openpgp';
import type { PrivateKey } from 'openpgp';

export interface TestIdentity {
  name: string;
  email: string;
  priv: PrivateKey;
  armoredPublic: string;
  fpr: string;
}

/** v4 curve25519 keys (gpg/gopass compatible), unprotected for test speed. */
export async function makeIdentity(name: string): Promise<TestIdentity> {
  const email = `${name.toLowerCase()}@example.test`;
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519Legacy',
    userIDs: [{ name, email }],
    format: 'armored',
  });
  const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
  return { name, email, priv, armoredPublic: publicKey, fpr: priv.getFingerprint().toUpperCase() };
}

export async function encryptForTest(text: string, ids: TestIdentity[]): Promise<Uint8Array> {
  // binary literal, like `echo ... | gpg -e` (what pass/gopass produce)
  const message = await openpgp.createMessage({ binary: new TextEncoder().encode(text) });
  // Tests may encrypt directly to build fixtures; production code may not.
  return (await openpgp.encrypt({
    message,
    encryptionKeys: ids.map((i) => i.priv.toPublic()),
    format: 'binary',
  })) as Uint8Array;
}

export async function decryptText(ct: Uint8Array | string, id: TestIdentity): Promise<string> {
  const message =
    typeof ct === 'string'
      ? await openpgp.readMessage({ armoredMessage: ct })
      : await openpgp.readMessage({ binaryMessage: ct });
  const { data } = await openpgp.decrypt({ message, decryptionKeys: id.priv, format: 'binary' });
  return new TextDecoder().decode(data as Uint8Array);
}

export const enc = (s: string) => new TextEncoder().encode(s);
export const dec = (b: Uint8Array) => new TextDecoder().decode(b);
