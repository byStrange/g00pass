import { ESCROW_FLAG, keyIdKind, normalizeKeyId, parseGpgId } from '../gpgid';
import { GPG_ID, ancestorsInclusive, joinPath, normalizePath } from '../paths';
import type { StoreSnapshot } from '../store';

/**
 * Who may act on a folder. Read-only helpers over one snapshot.
 *
 * TODO(trust): everything in this file reads `.gpg-id` and
 * `.g00pass-admins.json` WITHOUT verifying their signatures, chain of custody
 * or the pinned trust anchors. Agent C's verified check
 * (docs/specs/folder-admins.md, gpg-id-signatures.md) must replace
 * `isFolderAdmin` / `globalAdmins`. Until then these answers only decide what
 * the UI offers; the actual write is still gated by the trust hook inside
 * reencryptFolder, and everything here FAILS CLOSED (missing/invalid file means
 * "not an admin").
 */

export const ADMINS_FILE = '.g00pass-admins.json';
export const ADMINS_SIG_FILE = '.g00pass-admins.json.sig';
const FPR_RE = /^[0-9A-F]{40}$/;

/** Does recipient id `id` (as written in `.gpg-id`) denote the key with fingerprint `fpr`? Weak ids (short ids, e-mail) never match. */
export function idMatchesFingerprint(id: string, fpr: string): boolean {
  const n = normalizeKeyId(id);
  const f = fpr.toUpperCase();
  switch (keyIdKind(id)) {
    case 'fingerprint':
      return n === f;
    case 'long-id':
      return f.endsWith(n);
    default:
      return false;
  }
}

export async function readRecipientLines(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal) {
  const bytes = await snapshot.readFile(joinPath(normalizePath(folder), GPG_ID), signal);
  return bytes ? parseGpgId(new TextDecoder().decode(bytes)) : null;
}

/** True iff `folder`'s OWN `.gpg-id` lists `fingerprint` (approving needs to decrypt, so this is required). */
export async function isFolderRecipient(snapshot: StoreSnapshot, folder: string, fingerprint: string): Promise<boolean> {
  const lines = await readRecipientLines(snapshot, folder);
  return !!lines && lines.some((l) => idMatchesFingerprint(l.id, fingerprint));
}

/** Non-escrow fingerprint-kind recipients of the root `.gpg-id`. TODO(trust): use pinned anchors. */
export async function globalAdmins(snapshot: StoreSnapshot): Promise<string[]> {
  const lines = await readRecipientLines(snapshot, '');
  return (lines ?? [])
    .filter((l) => !l.flags.includes(ESCROW_FLAG) && keyIdKind(l.id) === 'fingerprint')
    .map((l) => normalizeKeyId(l.id));
}

/**
 * Admins of the NEAREST `.g00pass-admins.json` at `folder`, `parent`, ... (stopping before the root).
 * Returns null when no file exists; an invalid file yields an empty list (grants nothing).
 * TODO(trust): signature + chain verification (Agent C).
 */
export async function folderAdminsFromFile(
  snapshot: StoreSnapshot,
  folder: string,
): Promise<{ folder: string; admins: string[] } | null> {
  for (const f of ancestorsInclusive(normalizePath(folder))) {
    if (f === '') break;
    const bytes = await snapshot.readFile(joinPath(f, ADMINS_FILE));
    if (!bytes) continue;
    return { folder: f, admins: parseAdminsFile(bytes, f) };
  }
  return null;
}

export function parseAdminsFile(bytes: Uint8Array, folder: string): string[] {
  try {
    const j = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    if (j.type !== 'g00pass.folder-admins' || j.version !== 1 || j.folder !== folder) return [];
    if (!Array.isArray(j.admins) || j.admins.length === 0) return [];
    if (!j.admins.every((a) => typeof a === 'string' && FPR_RE.test(a))) return [];
    return j.admins as string[];
  } catch {
    return [];
  }
}

/**
 * Is `fingerprint` allowed to approve requests for `folder`? Fail-closed:
 * listed in the folder's admins file, or a global admin (root `.gpg-id`).
 * TODO(trust): replace with C's verified check.
 */
export async function isFolderAdmin(snapshot: StoreSnapshot, folder: string, fingerprint: string): Promise<boolean> {
  const fpr = fingerprint.toUpperCase();
  if ((await globalAdmins(snapshot)).includes(fpr)) return true;
  const file = await folderAdminsFromFile(snapshot, folder);
  return !!file && file.admins.includes(fpr);
}
