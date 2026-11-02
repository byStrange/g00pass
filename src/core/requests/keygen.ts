import { generateKey } from 'openpgp';
import { G00passError } from '../errors';
import { readProtectedPrivateKey } from '../crypto/decrypt';

/**
 * Enrollment key generation (core-api.md §Crypto).
 *
 * v4 curve25519 (ed25519 + cv25519), passphrase-protected with openpgp.js's
 * DEFAULT iterated-and-salted S2K. Argon2 is deliberately not used: unlocking
 * it needs WebAssembly, which the CSP blocks.
 *
 * Neither the passphrase nor the unprotected key is ever returned, stored or
 * logged here; callers get the passphrase-protected armored key only.
 */

export const MIN_PASSPHRASE_LENGTH = 12;

export class EnrollmentKeyError extends G00passError {}

export interface GenerateEnrollmentKeyParams {
  name: string;
  email: string;
  passphrase: string;
}

export interface GeneratedEnrollmentKey {
  /** Passphrase-protected armored private key. Safe to store on the device. */
  privateKeyArmored: string;
  publicKeyArmored: string;
  /** Upper-case 40-hex v4 fingerprint. */
  fingerprint: string;
  userId: string;
}

/** Returns an error message, or null when acceptable. Never echoes the passphrase. */
export function checkPassphrase(passphrase: string): string | null {
  if ([...passphrase].length < MIN_PASSPHRASE_LENGTH) return `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`;
  if (new Set(passphrase).size < 5) return 'Passphrase is too repetitive.';
  return null;
}

const EMAIL_RE = /^[^\s<>@"]+@[^\s<>@"]+\.[^\s<>@"]+$/;

export function validateIdentity(name: string, email: string): string | null {
  if (!name.trim()) return 'Name is required.';
  if (name.length > 100 || /[<>\n\r\0]/.test(name)) return 'Name is invalid.';
  if (!EMAIL_RE.test(email.trim()) || email.length > 200) return 'A valid e-mail address is required.';
  return null;
}

export async function generateEnrollmentKey(p: GenerateEnrollmentKeyParams): Promise<GeneratedEnrollmentKey> {
  const pwErr = checkPassphrase(p.passphrase);
  if (pwErr) throw new EnrollmentKeyError(pwErr);
  const idErr = validateIdentity(p.name, p.email);
  if (idErr) throw new EnrollmentKeyError(idErr);
  const name = p.name.trim();
  const email = p.email.trim();
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    curve: 'curve25519Legacy',
    userIDs: [{ name, email }],
    passphrase: p.passphrase,
    format: 'armored',
    config: { v6Keys: false },
  });
  const key = await readProtectedPrivateKey(privateKey);
  return {
    privateKeyArmored: privateKey,
    publicKeyArmored: publicKey,
    fingerprint: key.getFingerprint().toUpperCase(),
    userId: key.getUserIDs()[0] ?? `${name} <${email}>`,
  };
}

export interface ImportedKeyInfo {
  fingerprint: string;
  publicKeyArmored: string;
  userIds: string[];
}

/**
 * Validate an imported armored private key for enrollment: must be protected,
 * v4, and an algorithm approvers accept (Ed25519/Cv25519 or RSA >= 3072).
 */
export async function inspectImportedKey(armored: string): Promise<ImportedKeyInfo> {
  const key = await readProtectedPrivateKey(armored);
  if (key.keyPacket.version !== 4) throw new EnrollmentKeyError('Only OpenPGP v4 keys are supported.');
  const info = key.getAlgorithmInfo();
  const algo = String(info.algorithm);
  const ok =
    (algo === 'eddsaLegacy' || algo === 'eddsa') ||
    (algo.startsWith('rsa') && (info.bits ?? 0) >= 3072);
  if (!ok) throw new EnrollmentKeyError('Unsupported key algorithm (need Ed25519 or RSA >= 3072).');
  return {
    fingerprint: key.getFingerprint().toUpperCase(),
    publicKeyArmored: key.toPublic().armor(),
    userIds: key.getUserIDs(),
  };
}

