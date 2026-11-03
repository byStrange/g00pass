import type { PrivateKey } from 'openpgp';
import { decryptEntry } from './crypto/decrypt';
import { encryptToVerified } from './crypto/encrypt';
import { G00passError } from './errors';
import { findGpgIdForEntry } from './gpgid';
import { entryFile, normalizePath } from './paths';
import type { CommitResult, StoreSnapshot, StoreWriter } from './store';
import { verifyRecipients } from './trust';

/** Read path: fetch and decrypt one entry from a snapshot. Plaintext is returned, never stored. */
export async function readEntry(
  snapshot: StoreSnapshot,
  entry: string,
  decryptionKeys: readonly PrivateKey[],
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const path = entryFile(entry);
  const ct = await snapshot.readFile(path, signal);
  if (!ct) throw new G00passError(`No such entry: ${path}`);
  return decryptEntry(ct, decryptionKeys, path);
}

export interface WriteEntryOptions {
  snapshot: StoreSnapshot;
  writer: StoreWriter;
  /** Entry name ("a/b") or file ("a/b.gpg"). */
  entry: string;
  plaintext: Uint8Array;
  /**
   * Other encrypted files for the SAME commit (e.g. the folder's
   * `.g00pass-rotation.gpg`). Each must be governed by the same `.gpg-id`
   * as the entry; they are encrypted to the same verified set.
   */
  companions?: readonly { path: string; plaintext: Uint8Array }[];
  message?: string;
  armor?: boolean;
  signal?: AbortSignal;
}

export interface WriteEntryResult extends CommitResult {
  path: string;
  /** Governing `.gpg-id` used. */
  gpgIdPath: string;
  fingerprints: readonly string[];
  warnings: readonly string[];
}

/**
 * Write path for new and edited entries: encrypts to the recipients of the
 * NEAREST `.gpg-id` (walking up from the entry's folder), through the trust
 * choke-point, and commits atomically on top of `snapshot.commitSha`.
 * On ConflictError: reload the snapshot and call again (withConflictRetry).
 */
export async function writeEntry(opts: WriteEntryOptions): Promise<WriteEntryResult> {
  const path = entryFile(opts.entry);
  const verified = await verifyRecipients(opts.snapshot, { entry: path }, { signal: opts.signal });
  const changes = [{ path, content: await encryptToVerified(opts.plaintext, verified, { armor: opts.armor }) }];
  const has = (p: string) => opts.snapshot.hasFile(p);
  for (const c of opts.companions ?? []) {
    const cp = entryFile(normalizePath(c.path));
    if (cp === path || changes.some((x) => x.path === cp)) throw new G00passError(`Duplicate path "${cp}"`);
    if (findGpgIdForEntry(has, cp) !== verified.gpgIdPath) {
      throw new G00passError(`Companion "${cp}" is not governed by ${verified.gpgIdPath}`);
    }
    // Each companion's own location goes through the choke-point too (it may
    // lie in a different sub-folder, e.g. inside a vanished child boundary).
    const own = await verifyRecipients(opts.snapshot, { entry: cp }, { signal: opts.signal });
    changes.push({ path: cp, content: await encryptToVerified(c.plaintext, own, { armor: opts.armor }) });
  }
  const res = await opts.writer.commit(changes, {
    baseSha: opts.snapshot.commitSha,
    message: opts.message ?? `g00pass: update ${path}`,
    signal: opts.signal,
  });
  return { ...res, path, gpgIdPath: verified.gpgIdPath, fingerprints: verified.fingerprints, warnings: verified.warnings };
}
