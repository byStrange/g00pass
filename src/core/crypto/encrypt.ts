import * as openpgp from 'openpgp';
import { TrustError } from '../errors';
import { type VerifiedRecipientSet, isVerifiedRecipientSet } from '../trust';

/**
 * THE ONLY place in g00pass that calls openpgp.encrypt (enforced by ESLint,
 * by the static scan in test/guards.test.ts, and at runtime by
 * installEncryptGuard()). Accepts only a VerifiedRecipientSet minted by
 * src/core/trust.ts.
 *
 * Output is binary OpenPGP (what pass/gopass write to `*.gpg`), or ASCII
 * armor when `armor` is set (gpg, pass and gopass decrypt both).
 */

/** Key arrays handed to openpgp by encryptToVerified (identity, not contents). */
const authorizedKeyLists = new WeakSet<object>();
let guardInstalled = false;

function refuse(): never {
  throw new TrustError('?', 'OpenPGP encryption outside encryptToVerified() is blocked', 'not-verified');
}

/**
 * Runtime backstop for the choke-point (src/main.ts calls it at start-up):
 * openpgp's `Message#encrypt` and `Message.encryptSessionKey` (which
 * `openpgp.encrypt` and `openpgp.encryptSessionKey` use) are replaced by
 * non-writable, non-configurable wrappers that only proceed for the exact key
 * array encryptToVerified passed in, and never for passwords. Code that
 * reaches openpgp some other way (e.g. a namespace import) therefore cannot
 * encrypt to an unverified set. Idempotent.
 */
export function installEncryptGuard(): void {
  if (guardInstalled) return;
  const M = openpgp.Message as unknown as {
    prototype: { encrypt: (this: unknown, keys?: unknown, passwords?: unknown, ...rest: unknown[]) => Promise<unknown> };
    encryptSessionKey: (this: unknown, sk: unknown, alg: unknown, aead: unknown, keys?: unknown, passwords?: unknown, ...rest: unknown[]) => Promise<unknown>;
  };
  const check = (keys: unknown, passwords: unknown) => {
    if (typeof keys !== 'object' || keys === null || !authorizedKeyLists.has(keys)) refuse();
    if (Array.isArray(passwords) ? passwords.length > 0 : passwords != null) refuse();
  };
  const encrypt = M.prototype.encrypt;
  const encryptSessionKey = M.encryptSessionKey;
  Object.defineProperty(M.prototype, 'encrypt', {
    value: async function guardedEncrypt(this: unknown, keys?: unknown, passwords?: unknown, ...rest: unknown[]) {
      check(keys, passwords);
      return encrypt.call(this, keys, passwords, ...rest);
    },
    writable: false,
    configurable: false,
  });
  Object.defineProperty(M, 'encryptSessionKey', {
    value: async function guardedEncryptSessionKey(this: unknown, sk: unknown, alg: unknown, aead: unknown, keys?: unknown, passwords?: unknown, ...rest: unknown[]) {
      check(keys, passwords);
      return encryptSessionKey.call(this, sk, alg, aead, keys, passwords, ...rest);
    },
    writable: false,
    configurable: false,
  });
  guardInstalled = true;
}

export function isEncryptGuardInstalled(): boolean {
  return guardInstalled;
}

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
  const encryptionKeys = [...recipients.keys];
  authorizedKeyLists.add(encryptionKeys);
  try {
    if (opts.armor) {
      return await openpgp.encrypt({ message, encryptionKeys, format: 'armored' });
    }
    return await openpgp.encrypt({ message, encryptionKeys, format: 'binary' });
  } finally {
    authorizedKeyLists.delete(encryptionKeys);
  }
}
