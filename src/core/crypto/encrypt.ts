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
/**
 * Key packets (primary + subkeys) of the set encryptToVerified is currently
 * encrypting to, reference-counted (concurrent calls may share keys). The
 * packet-level guard only lets a PKESK be encrypted to one of these.
 */
const authorizedKeyPackets = new WeakMap<object, number>();
let guardInstalled = false;

function keyPacketsOf(keys: readonly { getKeys(): { keyPacket: object }[] }[]): object[] {
  return keys.flatMap((k) => k.getKeys().map((x) => x.keyPacket));
}

function refuse(): never {
  throw new TrustError('?', 'OpenPGP encryption outside encryptToVerified() is blocked', 'not-verified');
}

/**
 * Runtime backstop for the choke-point (src/main.ts calls it at start-up):
 * openpgp's `Message#encrypt` and `Message.encryptSessionKey` (which
 * `openpgp.encrypt` and `openpgp.encryptSessionKey` use) are replaced by
 * non-writable, non-configurable wrappers that only proceed for the exact key
 * array encryptToVerified passed in, and never for passwords; the
 * session-key packet classes are guarded the same way. Code that
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
  // Packet level: openpgp also exports the packet classes, so a message can be
  // assembled by hand (PKESK.encrypt(keyPacket) + SEIPD.encrypt(sessionKey))
  // without ever calling Message#encrypt. Guard the session-key packets too:
  // a PKESK only for a key packet of the set being encrypted right now, and
  // password-based SKESKs never.
  const PK = openpgp.PublicKeyEncryptedSessionKeyPacket as unknown as { prototype: { encrypt: (this: unknown, key: unknown, ...rest: unknown[]) => Promise<unknown> } };
  const SK = openpgp.SymEncryptedSessionKeyPacket as unknown as { prototype: { encrypt: (this: unknown, ...rest: unknown[]) => Promise<unknown> } };
  const pkEncrypt = PK.prototype.encrypt;
  Object.defineProperty(PK.prototype, 'encrypt', {
    value: async function guardedPkeskEncrypt(this: unknown, key: unknown, ...rest: unknown[]) {
      if (typeof key !== 'object' || key === null || !authorizedKeyPackets.has(key)) refuse();
      return pkEncrypt.call(this, key, ...rest);
    },
    writable: false,
    configurable: false,
  });
  Object.defineProperty(SK.prototype, 'encrypt', {
    value: async function guardedSkeskEncrypt() {
      refuse();
    },
    writable: false,
    configurable: false,
  });
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
  const packets = keyPacketsOf(encryptionKeys);
  for (const p of packets) authorizedKeyPackets.set(p, (authorizedKeyPackets.get(p) ?? 0) + 1);
  try {
    if (opts.armor) {
      return await openpgp.encrypt({ message, encryptionKeys, format: 'armored' });
    }
    return await openpgp.encrypt({ message, encryptionKeys, format: 'binary' });
  } finally {
    authorizedKeyLists.delete(encryptionKeys);
    for (const p of packets) {
      const n = (authorizedKeyPackets.get(p) ?? 1) - 1;
      if (n > 0) authorizedKeyPackets.set(p, n);
      else authorizedKeyPackets.delete(p);
    }
  }
}
