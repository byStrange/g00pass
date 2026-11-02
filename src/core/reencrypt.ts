import type { PrivateKey } from 'openpgp';
import { decryptEntry, wipe } from './crypto/decrypt';
import { encryptToVerified } from './crypto/encrypt';
import { DecryptError, ReencryptError, throwIfAborted } from './errors';
import type { GpgIdLine } from './gpgid';
import { parsePublicKey, fingerprintOf } from './keys';
import { GPG_ID_SIG, PUBLIC_KEYS_DIR, joinPath, normalizePath } from './paths';
import { type CommitResult, type FileChange, type StoreSnapshot, type StoreWriter, listGovernedEntries } from './store';
import { verifyProposedRecipients } from './trust';

export interface ReencryptProgress {
  phase: 'verifying' | 'reencrypting' | 'committing' | 'done';
  /** Entries processed so far (decrypted + re-encrypted). */
  done: number;
  total: number;
}

export interface ReencryptOptions {
  /** Snapshot to read from; its commitSha is the optimistic-concurrency base. */
  snapshot: StoreSnapshot;
  writer: StoreWriter;
  /** Unlocked private key(s) of the operator; must decrypt EVERY governed entry. */
  decryptionKeys: readonly PrivateKey[];
  /**
   * Public keys that are not in the store yet (e.g. an approved requester),
   * upper-case fingerprint -> armored key. Written to `.public-keys/<FPR>`
   * in the same commit (gopass convention) unless already present.
   */
  pendingKeys?: ReadonlyMap<string, string>;
  /**
   * Detached signature for the new `.gpg-id` or a signer callback receiving
   * the exact text. If none, an existing `.gpg-id.sig` is deleted (a stale
   * signature must never sit next to a changed `.gpg-id`).
   */
  gpgIdSignature?: Uint8Array | ((gpgIdText: string) => Promise<Uint8Array>);
  /** Additional files for the same commit (e.g. admin metadata). Must not touch entries/.gpg-id. */
  extraChanges?: readonly FileChange[];
  message?: string;
  /** Entries per chunk between progress callbacks / event-loop yields (default 20). */
  chunkSize?: number;
  /** Write ASCII-armored ciphertext instead of binary. */
  armor?: boolean;
  onProgress?: (p: ReencryptProgress) => void;
  signal?: AbortSignal;
}

export interface ReencryptResult extends CommitResult {
  folder: string;
  entries: readonly string[];
  fingerprints: readonly string[];
  gpgIdText: string;
  warnings: readonly string[];
}

const yieldToEventLoop = () => new Promise<void>((r) => setTimeout(r, 0));

/**
 * Re-encrypt every entry governed by `folder` (not descending into nested
 * folders that have their own `.gpg-id`) to `newRecipients`, and commit the
 * entries + new `.gpg-id` (+ signature, + new public keys) as ONE commit.
 *
 * Guarantees:
 *  - recipients go through the trust choke-point (verifyProposedRecipients);
 *    escrow recipients from the root `.gpg-id` are always kept
 *  - plaintext only ever exists in memory and is wiped after use
 *  - if ANY entry fails to decrypt, nothing is committed (ReencryptError
 *    lists the failed paths)
 *  - cancellable via `signal` up to the moment the ref is updated
 *  - ConflictError if the branch moved; retry with a fresh snapshot
 */
export async function reencryptFolder(
  path: string,
  newRecipients: readonly (GpgIdLine | string)[],
  opts: ReencryptOptions,
): Promise<ReencryptResult> {
  const { snapshot, signal } = opts;
  const folder = normalizePath(path);
  const chunkSize = Math.max(1, opts.chunkSize ?? 20);
  throwIfAborted(signal);

  // Validate pending keys before anything else.
  const pending = new Map<string, string>();
  for (const [fpr, armored] of opts.pendingKeys ?? []) {
    const keys = await parsePublicKey(armored, fpr);
    if (keys.length !== 1 || fingerprintOf(keys[0]!) !== fpr.toUpperCase()) {
      throw new ReencryptError(`Pending key for ${fpr} must contain exactly that one public key`);
    }
    pending.set(fpr.toUpperCase(), armored);
  }

  const entries = listGovernedEntries(snapshot, folder);
  const total = entries.length;
  opts.onProgress?.({ phase: 'verifying', done: 0, total });

  const proposed = await verifyProposedRecipients(snapshot, folder, newRecipients, {
    pending,
    signature: opts.gpgIdSignature ?? null,
    signal,
  });

  const out: FileChange[] = [];
  const failed: string[] = [];
  let done = 0;
  for (let i = 0; i < entries.length; i += chunkSize) {
    for (const p of entries.slice(i, i + chunkSize)) {
      throwIfAborted(signal);
      const ct = await snapshot.readFile(p, signal);
      if (!ct) {
        failed.push(p);
        continue;
      }
      let plain: Uint8Array | null = null;
      try {
        plain = await decryptEntry(ct, opts.decryptionKeys, p);
        if (failed.length === 0) {
          out.push({ path: p, content: await encryptToVerified(plain, proposed.verified, { armor: opts.armor }) });
        }
      } catch (e) {
        if (e instanceof DecryptError) failed.push(p);
        else throw e;
      } finally {
        wipe(plain);
      }
      done++;
    }
    opts.onProgress?.({ phase: 'reencrypting', done, total });
    await yieldToEventLoop();
  }
  if (failed.length) {
    throw new ReencryptError(
      `Refusing to re-encrypt "${folder || '/'}": ${failed.length} entr${failed.length === 1 ? 'y' : 'ies'} could not be decrypted with your key`,
      failed,
    );
  }

  const changes: FileChange[] = [...out, { path: proposed.gpgIdPath, content: proposed.gpgIdText }];
  const sigPath = joinPath(folder, GPG_ID_SIG);
  if (proposed.gpgIdSignature) changes.push({ path: sigPath, content: proposed.gpgIdSignature });
  else if (snapshot.hasFile(sigPath)) changes.push({ path: sigPath, delete: true });
  for (const [fpr, armored] of pending) {
    const kp = joinPath(PUBLIC_KEYS_DIR, fpr);
    if (!snapshot.hasFile(kp)) changes.push({ path: kp, content: armored });
  }
  const reserved = new Set(changes.map((c) => normalizePath(c.path)));
  for (const c of opts.extraChanges ?? []) {
    const p = normalizePath(c.path);
    if (reserved.has(p) || p.endsWith('.gpg') || p.endsWith('.gpg-id')) {
      throw new ReencryptError(`extraChanges may not touch "${p}"`);
    }
    reserved.add(p);
    changes.push(c);
  }

  throwIfAborted(signal);
  opts.onProgress?.({ phase: 'committing', done, total });
  const res = await opts.writer.commit(changes, {
    baseSha: snapshot.commitSha,
    message: opts.message ?? `g00pass: re-encrypt ${folder || '/'} (${total} entries, ${proposed.verified.fingerprints.length} recipients)`,
    signal,
  });
  opts.onProgress?.({ phase: 'done', done, total });
  return {
    ...res,
    folder,
    entries,
    fingerprints: proposed.verified.fingerprints,
    gpgIdText: proposed.gpgIdText,
    warnings: proposed.verified.warnings,
  };
}
