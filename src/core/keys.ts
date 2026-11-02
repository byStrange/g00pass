import { readKeys, type Key, type PublicKey } from 'openpgp';
import { RecipientKeyError } from './errors';
import { keyIdKind, normalizeKeyId } from './gpgid';
import { LEGACY_PUBLIC_KEYS_DIR, PUBLIC_KEYS_DIR, joinPath } from './paths';
import type { StoreSnapshot } from './store';

/**
 * Public key resolution. Deterministic source, matching gopass
 * (internal/store/leaf/crypto.go, recipients.go):
 *
 *   1. `.public-keys/<id>`   (id byte-for-byte as written in `.gpg-id`)
 *   2. `.public-keys/<normalized id>`  (upper-case hex, no 0x) if different
 *   3. `.gpg-keys/<id>`      (gopass legacy directory)
 *   4. `pending` keys supplied by the caller (keys being added in the same
 *      commit, e.g. an approved requester), keyed by fingerprint.
 *
 * The first file that exists is used; it must contain exactly one public key
 * that matches the id. No browser keyring / keyserver lookups ever.
 */

export interface ResolvedRecipient {
  /** Id as written in `.gpg-id`. */
  id: string;
  /** Primary key fingerprint, upper-case hex. */
  fingerprint: string;
  key: PublicKey;
  /** Where the key came from, e.g. ".public-keys/ABC..." or "pending". */
  source: string;
}

export interface ResolveOptions {
  /** Keys not yet in the store, by upper-case fingerprint -> armored public key. */
  pending?: ReadonlyMap<string, string>;
  /** Evaluate expiry at this date (tests). */
  date?: Date;
  signal?: AbortSignal;
}

export async function parsePublicKey(data: Uint8Array | string, id = '<key>'): Promise<PublicKey[]> {
  let keys: Key[];
  try {
    const text = typeof data === 'string' ? data : null;
    const asText = text ?? tryAscii(data as Uint8Array);
    keys =
      asText !== null && asText.includes('-----BEGIN PGP')
        ? await readKeys({ armoredKeys: asText })
        : await readKeys({ binaryKeys: data as Uint8Array });
  } catch {
    throw new RecipientKeyError(id, 'unreadable public key file');
  }
  for (const k of keys) {
    if (k.isPrivate()) throw new RecipientKeyError(id, 'key file contains PRIVATE key material; refusing to use it');
  }
  return keys as PublicKey[];
}

function tryAscii(b: Uint8Array): string | null {
  const head = b.subarray(0, 64);
  for (const c of head) if (c > 0x7e || (c < 0x20 && c !== 0x0a && c !== 0x0d && c !== 0x09)) return null;
  return new TextDecoder().decode(b);
}

export function fingerprintOf(key: Key): string {
  return key.getFingerprint().toUpperCase();
}

/** Does `key` match recipient id `id` the way gpg would select it? */
export function keyMatchesId(key: Key, id: string): boolean {
  const n = normalizeKeyId(id);
  switch (keyIdKind(id)) {
    case 'fingerprint':
      return fingerprintOf(key) === n || key.getSubkeys().some((s) => s.getFingerprint().toUpperCase() === n);
    case 'long-id':
      return key.getKeyIDs().some((k) => k.toHex().toUpperCase() === n);
    case 'short-id':
      return key.getKeyIDs().some((k) => k.toHex().toUpperCase().endsWith(n));
    case 'user-id': {
      const want = n.replace(/^<|>$/g, '');
      return key.getUserIDs().some((u) => {
        const l = u.toLowerCase();
        return l === want || l.includes(`<${want}>`);
      });
    }
  }
}

export async function resolveRecipient(
  snapshot: StoreSnapshot,
  id: string,
  opts: ResolveOptions = {},
): Promise<ResolvedRecipient> {
  const norm = normalizeKeyId(id);
  const candidates = [...new Set([joinPath(PUBLIC_KEYS_DIR, id.trim()), joinPath(PUBLIC_KEYS_DIR, norm), joinPath(LEGACY_PUBLIC_KEYS_DIR, id.trim())])];
  let keys: PublicKey[] | null = null;
  let source = '';
  for (const path of candidates) {
    const data = await snapshot.readFile(path, opts.signal);
    if (data) {
      keys = await parsePublicKey(data, id);
      source = path;
      break;
    }
  }
  if (!keys && opts.pending) {
    for (const [fpr, armored] of opts.pending) {
      const parsed = await parsePublicKey(armored, id);
      if (parsed.some((k) => keyMatchesId(k, id))) {
        keys = parsed;
        source = 'pending';
        if (fingerprintOf(parsed[0] as PublicKey) !== fpr.toUpperCase())
          throw new RecipientKeyError(id, `pending key does not have fingerprint ${fpr}`);
        break;
      }
    }
  }
  if (!keys) throw new RecipientKeyError(id, `no public key at ${candidates.join(' or ')}`);
  const matching = keys.filter((k) => keyMatchesId(k, id));
  if (matching.length !== 1) {
    throw new RecipientKeyError(id, `${source} must contain exactly one key matching the id (found ${matching.length})`);
  }
  const key = matching[0] as PublicKey;
  try {
    await key.getEncryptionKey(undefined, opts.date ?? new Date());
  } catch {
    throw new RecipientKeyError(id, `key ${fingerprintOf(key)} has no valid encryption subkey (expired, revoked or sign-only)`);
  }
  return { id, fingerprint: fingerprintOf(key), key, source };
}

/** Resolve every id; fails on the first unresolvable one. Dedupes by fingerprint. */
export async function resolveRecipients(
  snapshot: StoreSnapshot,
  ids: readonly string[],
  opts: ResolveOptions = {},
): Promise<ResolvedRecipient[]> {
  const out: ResolvedRecipient[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const r = await resolveRecipient(snapshot, id, opts);
    if (seen.has(r.fingerprint)) continue;
    seen.add(r.fingerprint);
    out.push(r);
  }
  return out;
}
