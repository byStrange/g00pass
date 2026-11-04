import type { PrivateKey } from 'openpgp';
import { decryptEntry, wipe } from './crypto/decrypt';
import { encryptToVerified } from './crypto/encrypt';
import { writeEntry } from './entries';
import { G00passError } from './errors';
import { withConflictRetry } from './github/commit';
import { findGpgIdForEntry, gpgIdFolder } from './gpgid';
import { fingerprintOf } from './keys';
import { NON_ENTRY_DIRS, dirname, entryFile, entryName, isEntryFile, isHiddenEntry, normalizePath } from './paths';
import { readRotation, recordEntryDeleted, recordEntryWrite, rotationPath, serializeRotation } from './rotation';
import type { CommitResult, StoreSnapshot, StoreWriter } from './store';
import { verifyRecipients } from './trust';
import { trustEnvironment } from './trust-env';

/**
 * Create / edit / delete a secret (an entry) from the app, with rotation
 * tracking (docs/specs/rotation.md) in the SAME commit:
 *  - new entries: createdAt = rotatedAt = now;
 *  - edits: rotatedAt = now only when the first line (the password) changed;
 *  - deletes: the entry's metadata is dropped.
 * Encryption goes through the trust choke-point (writeEntry ->
 * verifyRecipients -> encryptToVerified): writing into a folder whose member
 * list does not verify is refused. Each call retries on a moved branch with
 * a fresh snapshot.
 */

export class SecretError extends G00passError {
  constructor(
    public readonly code: 'invalid-name' | 'exists' | 'not-found' | 'not-readable',
    message: string,
  ) {
    super(message);
  }
}

/** Normalize + validate a secret name ("team/github" or "team/github.gpg") -> "team/github.gpg". */
export function secretPath(name: string): string {
  let n: string;
  try {
    n = normalizePath(name.trim());
  } catch (e) {
    throw new SecretError('invalid-name', (e as Error).message);
  }
  if (!n) throw new SecretError('invalid-name', 'Enter a name.');
  const p = entryFile(n);
  if (!isEntryFile(p)) throw new SecretError('invalid-name', 'That name is not allowed.');
  if (isHiddenEntry(p)) throw new SecretError('invalid-name', 'Names may not start with "." (reserved for g00pass files).');
  if (NON_ENTRY_DIRS.some((d) => p === d || p.startsWith(d + '/'))) throw new SecretError('invalid-name', 'That folder is reserved.');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(p)) throw new SecretError('invalid-name', 'Names may not contain control characters.');
  return p;
}

/** The folder whose member list governs `path` (nearest `.gpg-id`). */
export function governingFolder(snapshot: StoreSnapshot, path: string): string {
  return gpgIdFolder(findGpgIdForEntry((p) => snapshot.hasFile(p), path));
}

export interface SaveSecretOptions {
  loadSnapshot: (signal?: AbortSignal) => Promise<StoreSnapshot>;
  writer: StoreWriter;
  /** Unlocked key: decrypts the old value (edit) and the rotation file. */
  operatorKey: PrivateKey;
  /** 'create' refuses an existing name; 'edit' requires one. */
  mode: 'create' | 'edit';
  now?: Date;
  signal?: AbortSignal;
}

export interface SavedSecret extends CommitResult {
  readonly path: string;
  readonly folder: string;
  /** True when the first line changed (counts as a rotation). */
  readonly rotated: boolean;
}

export async function saveSecret(name: string, plaintext: Uint8Array, opts: SaveSecretOptions): Promise<SavedSecret> {
  const path = secretPath(name);
  const op = fingerprintOf(opts.operatorKey);
  return withConflictRetry(
    async () => {
      const snapshot = await opts.loadSnapshot(opts.signal);
      const exists = snapshot.hasFile(path);
      if (opts.mode === 'create' && exists) throw new SecretError('exists', `"${entryName(path)}" already exists. Open it to edit it.`);
      if (opts.mode === 'edit' && !exists) throw new SecretError('not-found', `"${entryName(path)}" no longer exists.`);
      const folder = governingFolder(snapshot, path);
      const now = opts.now ?? trustEnvironment().now();
      let old: Uint8Array | null = null;
      try {
        if (exists) {
          try {
            old = await decryptEntry((await snapshot.readFile(path, opts.signal))!, [opts.operatorKey], path);
          } catch {
            throw new SecretError('not-readable', 'You cannot read the current value, so you cannot edit it.');
          }
        }
        const rotated = !old || firstLine(old) !== firstLine(plaintext);
        let doc;
        try {
          doc = await readRotation(snapshot, folder, [opts.operatorKey], opts.signal);
        } catch {
          throw new SecretError('not-readable', `You are not a member of ${folder ? folder + '/' : 'the root'}, so you cannot save secrets there.`);
        }
        doc = recordEntryWrite(doc, path, old, plaintext, op, now);
        const res = await writeEntry({
          snapshot,
          writer: opts.writer,
          entry: path,
          plaintext,
          companions: [{ path: rotationPath(folder), plaintext: serializeRotation(doc) }],
          message: `g00pass: ${exists ? 'update' : 'add'} ${entryName(path)}`,
          signal: opts.signal,
        });
        return { commitSha: res.commitSha, treeSha: res.treeSha, path, folder, rotated };
      } finally {
        wipe(old);
      }
    },
    { signal: opts.signal },
  );
}

export async function deleteSecret(name: string, opts: Omit<SaveSecretOptions, 'mode'>): Promise<CommitResult & { path: string }> {
  const path = secretPath(name);
  return withConflictRetry(
    async () => {
      const snapshot = await opts.loadSnapshot(opts.signal);
      if (!snapshot.hasFile(path)) throw new SecretError('not-found', `"${entryName(path)}" does not exist.`);
      const folder = governingFolder(snapshot, path);
      let doc;
      try {
        doc = await readRotation(snapshot, folder, [opts.operatorKey], opts.signal);
      } catch {
        throw new SecretError('not-readable', `You are not a member of ${folder ? folder + '/' : 'the root'}, so you cannot delete secrets there.`);
      }
      doc = recordEntryDeleted(doc, path);
      // The rotation file goes through the trust choke-point like any write.
      const rot = rotationPath(folder);
      const verified = await verifyRecipients(snapshot, { entry: rot }, { signal: opts.signal });
      const res = await opts.writer.commit(
        [
          { path, delete: true },
          { path: rot, content: await encryptToVerified(serializeRotation(doc), verified) },
        ],
        { baseSha: snapshot.commitSha, message: `g00pass: delete ${entryName(path)}`, signal: opts.signal },
      );
      return { ...res, path };
    },
    { signal: opts.signal },
  );
}

function firstLine(b: Uint8Array): string {
  const t = new TextDecoder().decode(b);
  const i = t.indexOf('\n');
  return (i === -1 ? t : t.slice(0, i)).replace(/\r$/, '');
}

/** Folder part of a secret name ("team/email/smtp" -> "team/email"). */
export const secretDir = (p: string) => dirname(entryFile(p));
