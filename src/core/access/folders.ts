import { keyIdKind, normalizeKeyId, parseGpgId } from '../gpgid';
import { GPG_ID, joinPath, normalizePath } from '../paths';
import type { StoreSnapshot } from '../store';

/**
 * Read-only recipient helpers over one snapshot. Authority (who is an admin)
 * is NOT decided here: use `checkFolderAdmin` / `isVerifiedFolderAdmin`
 * (src/core/admins.ts), which verify signatures against the pinned anchors.
 */

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
