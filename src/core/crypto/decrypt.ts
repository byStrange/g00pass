import { decrypt, decryptKey, readMessage as pgpReadMessage, readPrivateKey, type Message, type PrivateKey } from 'openpgp';
import { DecryptError, G00passError } from '../errors';

export class KeyUnlockError extends G00passError {}

/** Read a passphrase-protected armored private key WITHOUT unlocking it. */
export async function readProtectedPrivateKey(armored: string): Promise<PrivateKey> {
  let key: PrivateKey;
  try {
    key = await readPrivateKey({ armoredKey: armored });
  } catch {
    throw new KeyUnlockError('Not a valid armored OpenPGP private key');
  }
  if (key.isDecrypted()) {
    throw new KeyUnlockError('Private key is not passphrase-protected; refusing to store it');
  }
  return key;
}

/** Unlock a passphrase-protected private key. The result lives in memory only. */
export async function unlockPrivateKey(armored: string, passphrase: string): Promise<PrivateKey> {
  const key = await readProtectedPrivateKey(armored);
  try {
    return await decryptKey({ privateKey: key, passphrase });
  } catch {
    throw new KeyUnlockError('Wrong passphrase or unsupported key');
  }
}

/** Decrypt an entry (binary or armored). `path` is used for error messages only. */
export async function decryptEntry(
  ciphertext: Uint8Array,
  decryptionKeys: readonly PrivateKey[],
  path = '<entry>',
): Promise<Uint8Array> {
  try {
    const message = await readMessage(ciphertext);
    const { data } = await decrypt({ message, decryptionKeys: [...decryptionKeys], format: 'binary' });
    return data as Uint8Array;
  } catch (e) {
    throw new DecryptError(path, { cause: e });
  }
}

async function readMessage(ciphertext: Uint8Array): Promise<Message<Uint8Array>> {
  const head = new TextDecoder().decode(ciphertext.subarray(0, 64));
  if (head.trimStart().startsWith('-----BEGIN PGP MESSAGE')) {
    return (await pgpReadMessage({ armoredMessage: new TextDecoder().decode(ciphertext) })) as Message<Uint8Array>;
  }
  return pgpReadMessage({ binaryMessage: ciphertext });
}

/** Best-effort wipe of a plaintext buffer once it is no longer needed. */
export function wipe(buf: Uint8Array | null | undefined): void {
  buf?.fill(0);
}
