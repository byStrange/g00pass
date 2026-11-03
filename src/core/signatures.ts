import {
  createMessage,
  enums,
  readSignature,
  sign,
  verify,
  type PrivateKey,
  type PublicKey,
  type Signature,
  type SignaturePacket,
} from 'openpgp';
import { G00passError } from './errors';
import { fingerprintOf, parsePublicKey } from './keys';
import { PUBLIC_KEYS_DIR, isWithin, joinPath, normalizePath } from './paths';
import type { StoreSnapshot } from './store';

/**
 * Detached OpenPGP signatures over exact file bytes (store-layout.md
 * §Detached signatures). Format is what `gpg --detach-sign` writes and what
 * pass uses for `.gpg-id.sig`: one v4/v6 signature packet of type 0x00
 * (binary document), binary or ASCII-armored.
 *
 * `.gpg-id.sig` additionally carries a signed, non-critical notation
 * `folder@g00pass=/<folder>` that binds the signature to the folder it was
 * made for (gpg-id-signatures.md §Folder binding). gpg/pass ignore it.
 */

export const FOLDER_NOTATION = 'folder@g00pass';
/**
 * Child-boundary declaration (gpg-id-signatures.md §Child boundaries): one
 * hashed notation `child@g00pass=/<child folder>` per DIRECT nested folder
 * that has its own `.gpg-id`. Makes the set of trust boundaries part of the
 * signed state, so deleting a nested `.gpg-id` cannot silently widen access.
 */
export const CHILD_NOTATION = 'child@g00pass';
/**
 * Explicit, signed removal of a former child boundary (gpg-id-signatures.md
 * §Removing a sub-folder): `removed@g00pass=/<folder>`. Devices that verified
 * that boundary before accept its absence only when the parent's current
 * verified signature carries this notation; re-signs carry it forward.
 */
export const REMOVED_NOTATION = 'removed@g00pass';
/** Allowed clock skew for signature creation times in the future. */
export const MAX_FUTURE_SKEW_MS = 5 * 60_000;
const MAX_SIGNATURE_BYTES = 16 * 1024;

export class SignatureFormatError extends G00passError {}

/** Notation value binding a `.gpg-id.sig` to `folder`: "/" for the root, "/infra" for "infra". */
export function folderNotationValue(folder: string): string {
  return '/' + normalizePath(folder);
}

export interface ParsedDetachedSignature {
  readonly signature: Signature;
  readonly packet: SignaturePacket;
  readonly created: Date;
  /** Upper-case 16-hex issuer key id (may name a subkey). */
  readonly issuerKeyId: string;
  /** Upper-case issuer fingerprint subpacket, if present (may name a subkey). */
  readonly issuerFingerprint: string | null;
  /** All values per notation name (hashed area only: openpgp.js only parses hashed notations). */
  readonly notations: ReadonlyMap<string, readonly string[]>;
}

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();

function looksArmored(b: Uint8Array): boolean {
  const head = new TextDecoder().decode(b.subarray(0, 64)).trimStart();
  return head.startsWith('-----BEGIN PGP SIGNATURE-----');
}

/** Parse and structurally validate a detached signature. Throws SignatureFormatError. */
export async function parseDetachedSignature(bytes: Uint8Array): Promise<ParsedDetachedSignature> {
  if (bytes.length === 0 || bytes.length > MAX_SIGNATURE_BYTES) throw new SignatureFormatError('signature file has an invalid size');
  let signature: Signature;
  try {
    signature = looksArmored(bytes)
      ? await readSignature({ armoredSignature: new TextDecoder().decode(bytes) })
      : await readSignature({ binarySignature: bytes });
  } catch {
    throw new SignatureFormatError('signature does not parse as an OpenPGP signature');
  }
  if (signature.packets.length !== 1) throw new SignatureFormatError('expected exactly one signature packet');
  const packet = signature.packets[0] as SignaturePacket;
  if (packet.signatureType !== enums.signature.binary) {
    throw new SignatureFormatError('signature must be a binary-document (type 0x00) signature');
  }
  if (packet.version !== 4 && packet.version !== 6) throw new SignatureFormatError('unsupported signature version');
  if (!packet.created) throw new SignatureFormatError('signature has no creation time');
  const notations = new Map<string, string[]>();
  for (const n of packet.rawNotations ?? []) {
    let v: string;
    try {
      v = new TextDecoder('utf-8', { fatal: true }).decode(n.value);
    } catch {
      v = '�';
    }
    notations.set(n.name, [...(notations.get(n.name) ?? []), v]);
  }
  return {
    signature,
    packet,
    created: packet.created,
    issuerKeyId: packet.issuerKeyID.toHex().toUpperCase(),
    issuerFingerprint: packet.issuerFingerprint ? hex(packet.issuerFingerprint) : null,
    notations,
  };
}

export interface SignerMatch {
  /** Primary key fingerprint of the signer (what authorization compares against). */
  readonly fingerprint: string;
  /** Fingerprint of the key/subkey that made the signature. */
  readonly signingKeyFingerprint: string;
  readonly created: Date;
}

export type DetachedVerification =
  | { ok: true; signer: SignerMatch }
  | { ok: false; reason: string };

/**
 * Verify `parsed` over the exact `data` bytes against each candidate key.
 * Accepted only if, for one candidate:
 *  - the issuer (key id, and the issuer-fingerprint subpacket if present)
 *    names that key's primary key or one of its subkeys,
 *  - the signature verifies cryptographically (openpgp.js also checks that
 *    the signing (sub)key was valid at the signature creation time, incl.
 *    subkey binding + primary-key back-signature),
 *  - the signing (sub)key is ALSO valid now (not revoked, not expired).
 *    Creation times are chosen by the signer, so validity "at signing time"
 *    alone would let the holder of an expired key back-date signatures,
 *  - the creation time is at most MAX_FUTURE_SKEW_MS in the future.
 */
export async function verifyDetached(
  data: Uint8Array,
  parsed: ParsedDetachedSignature,
  candidates: readonly PublicKey[],
  now: Date,
): Promise<DetachedVerification> {
  if (parsed.created.getTime() > now.getTime() + MAX_FUTURE_SKEW_MS) {
    return { ok: false, reason: 'signature creation time is in the future' };
  }
  let lastReason = 'signature was not made by an authorized key';
  for (const key of candidates) {
    const issuerKeys = key.getKeys(parsed.packet.issuerKeyID);
    if (issuerKeys.length === 0) continue;
    const signingKey = issuerKeys[0]!;
    const signingFpr = signingKey.getFingerprint().toUpperCase();
    if (parsed.issuerFingerprint !== null && parsed.issuerFingerprint !== signingFpr) continue;
    try {
      const res = await verify({
        message: await createMessage({ binary: data }),
        signature: parsed.signature,
        verificationKeys: [key],
        format: 'binary',
        date: new Date(now.getTime() + MAX_FUTURE_SKEW_MS),
      });
      if (res.signatures.length !== 1) continue;
      await res.signatures[0]!.verified;
    } catch {
      lastReason = 'signature does not verify';
      continue;
    }
    try {
      await key.getSigningKey(signingKey.getKeyID(), now);
    } catch {
      lastReason = `signer key ${fingerprintOf(key)} is revoked, expired or not signing-capable now`;
      continue;
    }
    return { ok: true, signer: { fingerprint: fingerprintOf(key), signingKeyFingerprint: signingFpr, created: parsed.created } };
  }
  return { ok: false, reason: lastReason };
}

/**
 * Load the public key for a full primary fingerprint from `.public-keys/<FPR>`
 * in `snapshot`. Returns null unless the file holds exactly one public key
 * whose PRIMARY fingerprint equals `fpr` (a swapped key file never matches).
 */
export async function loadKeyByFingerprint(
  snapshot: StoreSnapshot,
  fpr: string,
  signal?: AbortSignal,
): Promise<PublicKey | null> {
  if (!/^[0-9A-F]{40}$|^[0-9A-F]{64}$/.test(fpr)) return null;
  const data = await snapshot.readFile(joinPath(PUBLIC_KEYS_DIR, fpr), signal);
  if (!data) return null;
  try {
    const keys = await parsePublicKey(data, fpr);
    if (keys.length !== 1 || fingerprintOf(keys[0]!) !== fpr) return null;
    return keys[0]!;
  } catch {
    return null;
  }
}

/** Binary detached signature (type 0x00) over `data`, optionally with notations. */
export async function signDetached(
  data: Uint8Array,
  signingKey: PrivateKey,
  opts: { notations?: Readonly<Record<string, string>> | readonly (readonly [string, string])[]; date?: Date } = {},
): Promise<Uint8Array> {
  if (!signingKey.isPrivate() || !signingKey.isDecrypted()) throw new G00passError('signing key must be an unlocked private key');
  const pairs: readonly (readonly [string, string])[] = Array.isArray(opts.notations)
    ? (opts.notations as readonly (readonly [string, string])[])
    : Object.entries(opts.notations ?? {});
  const notations = pairs.map(([name, value]) => ({
    name,
    value: new TextEncoder().encode(value),
    humanReadable: true,
    critical: false,
  }));
  return sign({
    message: await createMessage({ binary: data }),
    signingKeys: signingKey,
    detached: true,
    format: 'binary',
    date: opts.date,
    signatureNotations: notations.length ? notations : undefined,
  });
}

/**
 * Validate the `child@g00pass` values of a `.gpg-id.sig` made for `folder`.
 * Each value is `/<folder>`: normalized, a STRICT descendant of `folder`,
 * unique, and no value lies inside another (only direct children).
 * Returns the sorted store-relative child folders, or an error message.
 */
export function childBoundariesFromNotations(values: readonly string[], folder: string): string[] | string {
  const f = normalizePath(folder);
  const out: string[] = [];
  for (const v of values) {
    if (!v.startsWith('/') || v === '/') return `invalid ${CHILD_NOTATION} value "${v}"`;
    let c: string;
    try {
      c = normalizePath(v.slice(1));
    } catch {
      return `invalid ${CHILD_NOTATION} value "${v}"`;
    }
    if (c !== v.slice(1) || c === f || !isWithin(c, f)) return `${CHILD_NOTATION} "${v}" is not a folder below "${folderNotationValue(f)}"`;
    if (out.includes(c)) return `duplicate ${CHILD_NOTATION} "${v}"`;
    out.push(c);
  }
  for (const a of out) {
    if (out.some((b) => b !== a && isWithin(a, b))) return `${CHILD_NOTATION} "/${a}" is not a direct child (it lies inside another declared child)`;
  }
  return out.sort();
}

/**
 * Validate the `removed@g00pass` values of a `.gpg-id.sig` for `folder`:
 * normalized strict descendants, unique, and not also declared as children.
 */
export function removedBoundariesFromNotations(values: readonly string[], folder: string, children: readonly string[]): string[] | string {
  const f = normalizePath(folder);
  const out: string[] = [];
  for (const v of values) {
    let c: string;
    try {
      c = v.startsWith('/') ? normalizePath(v.slice(1)) : '';
    } catch {
      c = '';
    }
    if (c === '' || c !== v.slice(1) || c === f || !isWithin(c, f)) return `${REMOVED_NOTATION} "${v}" is not a folder below "${folderNotationValue(f)}"`;
    if (out.includes(c)) return `duplicate ${REMOVED_NOTATION} "${v}"`;
    if (children.includes(c)) return `${REMOVED_NOTATION} "${v}" is also declared as a child`;
    out.push(c);
  }
  return out.sort();
}

/**
 * Sign a `.gpg-id` exactly as g00pass verifies it: binary detached signature
 * over the exact bytes, bound to `folder` by the `folder@g00pass` notation,
 * declaring the direct child boundaries with one `child@g00pass` notation
 * each. Compatible with pass (`gpg --verify` ignores non-critical notations).
 *
 * Use as reencryptFolder's
 * `gpgIdSignature: (text, { folder, children }) => signGpgId(text, folder, key, { children })`.
 */
export async function signGpgId(
  gpgId: string | Uint8Array,
  folder: string,
  signingKey: PrivateKey,
  opts: { date?: Date; children?: readonly string[]; removed?: readonly string[] } = {},
): Promise<Uint8Array> {
  const bytes = typeof gpgId === 'string' ? new TextEncoder().encode(gpgId) : gpgId;
  const children = [...new Set((opts.children ?? []).map((c) => normalizePath(c)))].sort();
  const bad = childBoundariesFromNotations(children.map(folderNotationValue), folder);
  if (typeof bad === 'string') throw new G00passError(bad);
  const removed = [...new Set((opts.removed ?? []).map((c) => normalizePath(c)))].sort();
  const badR = removedBoundariesFromNotations(removed.map(folderNotationValue), folder, children);
  if (typeof badR === 'string') throw new G00passError(badR);
  const notations: [string, string][] = [
    [FOLDER_NOTATION, folderNotationValue(folder)],
    ...children.map((c): [string, string] => [CHILD_NOTATION, folderNotationValue(c)]),
    ...removed.map((c): [string, string] => [REMOVED_NOTATION, folderNotationValue(c)]),
  ];
  return signDetached(bytes, signingKey, { notations, date: opts.date });
}
