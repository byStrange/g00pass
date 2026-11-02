import { createMessage, sign, type PrivateKey } from 'openpgp';
import { G00passError } from '../errors';

/**
 * Detached binary signature (type 0x00) over the exact bytes, as produced by
 * `gpg --detach-sign` and expected for `.gpg-id.sig` and `*.json.sig`
 * (docs/specs/store-layout.md §Detached signatures).
 */
export async function signDetached(data: string | Uint8Array, key: PrivateKey): Promise<Uint8Array> {
  if (!key.isDecrypted()) throw new G00passError('Signing key is locked');
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const message = await createMessage({ binary: bytes });
  return (await sign({ message, signingKeys: key, detached: true, format: 'binary' })) as Uint8Array;
}
