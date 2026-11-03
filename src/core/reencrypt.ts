import { readMessage, type PrivateKey, type PublicKey } from 'openpgp';
import { decryptEntry, wipe } from './crypto/decrypt';
import { encryptToVerified } from './crypto/encrypt';
import { DecryptError, ReencryptError, throwIfAborted } from './errors';
import { ESCROW_FLAG, type GpgIdLine, findGpgIdForFolder, normalizeKeyId, parseGpgId } from './gpgid';
import { parsePublicKey, fingerprintOf, resolveRecipient } from './keys';
import { GPG_ID, GPG_ID_SIG, PUBLIC_KEYS_DIR, entryFile, isWithin, joinPath, normalizePath } from './paths';
import {
  type CommitResult,
  type FileChange,
  type StoreSnapshot,
  type StoreWriter,
  directNestedGpgIdFolders,
  listGovernedEntries,
  nestedGpgIdFolders,
} from './store';
import { type GpgIdSigner, escrowRecipientIds, verifyProposedRecipients } from './trust';

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
   * the exact text and the child boundaries to declare, e.g.
   * `(text, { folder, children }) => signGpgId(text, folder, key, { children })`.
   * If none, an existing `.gpg-id.sig` is deleted (a stale signature must
   * never sit next to a changed `.gpg-id`).
   */
  gpgIdSignature?: Uint8Array | GpgIdSigner;
  /**
   * New plaintext for governed entries (e.g. the folder's `.g00pass-rotation.gpg`
   * with an updated member list), encrypted to the NEW verified recipient set
   * instead of re-encrypting the old content. Paths may be new. Each must be
   * governed by `folder` (not inside a nested `.gpg-id` folder).
   */
  replaceEntries?: readonly { path: string; plaintext: Uint8Array }[];
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
 * Keys of the CURRENT governing recipients of `folder` (its own `.gpg-id`, or
 * the nearest ancestor's when it has none), minus escrow (root-flagged or
 * flagged in that file). Every governed entry must already be encrypted to
 * each of them; an entry that is not belongs to some other (narrower)
 * recipient set, e.g. a nested boundary whose `.gpg-id` was deleted.
 * Ids that do not resolve to a key are skipped (they cannot be encrypted to
 * either, so the proposed set would fail on them anyway).
 */
async function currentGoverningKeys(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal): Promise<{ path: string; keys: PublicKey[] }> {
  const path = findGpgIdForFolder((p) => snapshot.hasFile(p), folder);
  const bytes = await snapshot.readFile(path, signal);
  const escrow = new Set((await escrowRecipientIds(snapshot, signal)).map(normalizeKeyId));
  const keys: PublicKey[] = [];
  for (const r of parseGpgId(new TextDecoder().decode(bytes ?? new Uint8Array()))) {
    if (r.flags.includes(ESCROW_FLAG) || escrow.has(normalizeKeyId(r.id))) continue;
    try {
      keys.push((await resolveRecipient(snapshot, r.id, { signal })).key);
    } catch {
      /* unresolvable: cannot be checked (nor encrypted to) */
    }
  }
  return { path, keys };
}

/** Recipients in `keys` the message is NOT encrypted to (by PKESK key id); null if not checkable (anonymous recipient). */
async function missingRecipients(ct: Uint8Array, keys: readonly PublicKey[]): Promise<PublicKey[] | null> {
  let ids: string[];
  try {
    const head = new TextDecoder().decode(ct.subarray(0, 64)).trimStart();
    const msg = head.startsWith('-----BEGIN PGP MESSAGE-----')
      ? await readMessage({ armoredMessage: new TextDecoder().decode(ct) })
      : await readMessage({ binaryMessage: ct });
    ids = msg.getEncryptionKeyIDs().map((k) => k.toHex().toUpperCase());
  } catch {
    return []; // unreadable: decryption reports it
  }
  if (ids.some((i) => /^0+$/.test(i))) return null; // gpg --throw-keyids: recipients not visible
  return keys.filter((k) => !k.getKeyIDs().some((kid) => ids.includes(kid.toHex().toUpperCase())));
}

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

  const replacements = new Map<string, Uint8Array>();
  const boundaries = nestedGpgIdFolders(snapshot, folder);
  for (const r of opts.replaceEntries ?? []) {
    const p = entryFile(r.path);
    if (!isWithin(p, folder) || boundaries.some((b) => isWithin(p, b)) || replacements.has(p)) {
      throw new ReencryptError(`replaceEntries path "${p}" is not governed by "${folder || '/'}" or is duplicated`);
    }
    replacements.set(p, r.plaintext);
  }

  const entries = listGovernedEntries(snapshot, folder).filter((p) => !replacements.has(p));
  const total = entries.length;
  opts.onProgress?.({ phase: 'verifying', done: 0, total });

  const governing = await currentGoverningKeys(snapshot, folder, signal);

  const proposed = await verifyProposedRecipients(snapshot, folder, newRecipients, {
    pending,
    signature: opts.gpgIdSignature ?? null,
    signal,
  });

  // Trust boundaries: never absorb entries of a child boundary. The policy
  // already refused vanished / undeclared ones; this is the core-side check
  // that the declared children are exactly the nested boundaries we skip.
  const declared = proposed.verified.childBoundaries;
  if (declared) {
    const gone = declared.filter((c) => !snapshot.hasFile(joinPath(c, GPG_ID)));
    if (gone.length) throw new ReencryptError(`Refusing to re-encrypt "${folder || '/'}": declared boundary ${gone.map((g) => `"${g}"`).join(', ')} has no .gpg-id`);
    const present = directNestedGpgIdFolders(snapshot, folder);
    const extra = present.filter((p) => !declared.includes(p));
    if (extra.length) throw new ReencryptError(`Refusing to re-encrypt "${folder || '/'}": nested ${extra.map((g) => `"${g}"`).join(', ')} not declared by the new signature`);
  }

  const out: FileChange[] = [];
  const failed: string[] = [];
  const misfits: string[] = [];
  let done = 0;
  for (let i = 0; i < entries.length; i += chunkSize) {
    for (const p of entries.slice(i, i + chunkSize)) {
      throwIfAborted(signal);
      const ct = await snapshot.readFile(p, signal);
      if (!ct) {
        failed.push(p);
        continue;
      }
      const missing = await missingRecipients(ct, governing.keys);
      if (missing && missing.length) {
        misfits.push(`${p} (not encrypted to ${missing.map(fingerprintOf).join(', ')})`);
        failed.push(p);
        done++;
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
  if (misfits.length) {
    throw new ReencryptError(
      `Refusing to re-encrypt "${folder || '/'}": ${misfits.length} entr${misfits.length === 1 ? 'y is' : 'ies are'} not encrypted to every current recipient of ${governing.path}, so ${misfits.length === 1 ? 'it' : 'they'} may belong to a deleted nested boundary: ${misfits.slice(0, 5).join('; ')}`,
      failed,
    );
  }
  if (failed.length) {
    throw new ReencryptError(
      `Refusing to re-encrypt "${folder || '/'}": ${failed.length} entr${failed.length === 1 ? 'y' : 'ies'} could not be decrypted with your key`,
      failed,
    );
  }

  for (const [p, plain] of replacements) {
    throwIfAborted(signal);
    out.push({ path: p, content: await encryptToVerified(plain, proposed.verified, { armor: opts.armor }) });
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
    entries: [...entries, ...replacements.keys()].sort(),
    fingerprints: proposed.verified.fingerprints,
    gpgIdText: proposed.gpgIdText,
    warnings: proposed.verified.warnings,
  };
}
