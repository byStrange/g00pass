import * as openpgp from 'openpgp';
import { TrustError } from '../errors';
import { type VerifiedRecipientSet, isVerifiedRecipientSet } from '../trust';

/**
 * THE ONLY place in g00pass that calls openpgp.encrypt (enforced by ESLint
 * and by test/choke-point.test.ts). Accepts only a VerifiedRecipientSet
 * minted by src/core/trust.ts.
 *
 * Output is binary OpenPGP (what pass/gopass write to `*.gpg`), or ASCII
 * armor when `armor` is set (gpg, pass and gopass decrypt both).
 */
export async function encryptToVerified(
  plaintext: Uint8Array,
  recipients: VerifiedRecipientSet,
  opts: { armor?: boolean } = {},
): Promise<Uint8Array | string> {
  if (!isVerifiedRecipientSet(recipients)) {
    throw new TrustError('?', 'recipient set was not produced by verifyRecipients()', 'not-verified');
  }
  if (recipients.keys.length === 0) throw new TrustError(recipients.folder, 'empty recipient set');
  const message = await openpgp.createMessage({ binary: plaintext });
  if (opts.armor) {
    return openpgp.encrypt({ message, encryptionKeys: [...recipients.keys], format: 'armored' });
  }
  return openpgp.encrypt({ message, encryptionKeys: [...recipients.keys], format: 'binary' });
}
