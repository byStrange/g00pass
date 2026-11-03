import type { PrivateKey } from 'openpgp';
import { checkFolderAdmin, ADMINS_FILE, ADMINS_SIG } from '../admins';
import { checkGpgIdSignature, evaluateRootTrust } from '../anchors';
import { allowedSigners, expectedChildBoundaries, parentBoundary } from '../boundaries';
import { canonicalJson, sha256Digest } from '../canonical';
import { decryptEntry, wipe } from '../crypto/decrypt';
import { encryptToVerified } from '../crypto/encrypt';
import { DecryptError, G00passError, RecipientKeyError, TrustError, throwIfAborted } from '../errors';
import { withConflictRetry } from '../github/commit';
import { ESCROW_FLAG, normalizeKeyId } from '../gpgid';
import { fingerprintOf } from '../keys';
import { GPG_ID, GPG_ID_SIG, joinPath, normalizePath } from '../paths';
import { type ReencryptResult, missingRecipients, reencryptFolder } from '../reencrypt';
import { emptyRotation, readRotation, recordMemberRemoved, rotationKey, rotationPath, serializeRotation } from '../rotation';
import { signGpgId } from '../signatures';
import { type CommitResult, type FileChange, type StoreSnapshot, type StoreWriter, listEntries, listGovernedEntries, nestedGpgIdFolders } from '../store';
import { escrowRecipientIds, verifyRecipients } from '../trust';
import { trustEnvironment } from '../trust-env';
import { idMatchesFingerprint, isFolderRecipient, readRecipientLines } from './folders';

/**
 * CREATE / REMOVE SUB-FOLDER (gpg-id-signatures.md §Creating a sub-folder,
 * §Removing a sub-folder). Both are ONE commit each:
 *
 * Create C below its parent boundary P: P is re-signed (unchanged `.gpg-id`)
 * declaring C as a child, C gets its signed `.gpg-id`, and every entry
 * already under C (until now governed by P) is re-encrypted to C's set.
 * P's recipients that are not in C could read those entries: they are
 * recorded as removed in C's rotation file, so the checklist lists them.
 *
 * Remove C (merge into P): C must not contain nested boundaries; every entry
 * under C is re-encrypted to P's verified recipients, C's `.gpg-id`, `.sig`
 * and admins file are deleted, and P is re-signed without the child and
 * WITH an explicit `removed@g00pass=/C` declaration, which is what lets
 * devices that knew C accept that it is gone.
 */

export class SubfolderError extends G00passError {
  constructor(
    public readonly code: 'invalid-change' | 'not-admin' | 'not-recipient' | 'folder-not-verified' | 'plan-changed' | 'decrypt-failed',
    message: string,
  ) {
    super(message);
  }
}

const FPR_RE = /^[0-9A-F]{40}$|^[0-9A-F]{64}$/;

async function digestOf(v: unknown): Promise<string> {
  return sha256Digest(new TextEncoder().encode(canonicalJson(v)));
}

async function mustVerify(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal) {
  try {
    const v = await verifyRecipients(snapshot, { folder }, { signal });
    if (v.folder !== folder) throw new SubfolderError('folder-not-verified', `"${folder || '/'}" is not governed by its own .gpg-id`);
    return v;
  } catch (e) {
    if (e instanceof TrustError || e instanceof RecipientKeyError) {
      throw new SubfolderError('folder-not-verified', `The recipients of "${folder || '/'}" are not verified (${e instanceof TrustError ? e.reason : e.message}); an authorized admin must re-sign it first`);
    }
    throw e;
  }
}

async function assertAdminRecipient(snapshot: StoreSnapshot, folder: string, operatorFpr: string, what: string) {
  const admin = await checkFolderAdmin(snapshot, folder, operatorFpr);
  if (!admin.admin) throw new SubfolderError('not-admin', `You are not a verified admin of "${folder || '/'}" (${admin.reason})`);
  if (!(await isFolderRecipient(snapshot, folder, operatorFpr))) throw new SubfolderError('not-recipient', `You are not a recipient of "${folder || '/'}", so you cannot ${what}`);
}

// ---------------------------------------------------------------- create

export interface CreateSubfolderPlan {
  readonly folder: string;
  readonly parent: string;
  /** Recipients of the new `.gpg-id` (full fingerprints; escrow merged in by the core). */
  readonly recipients: readonly string[];
  readonly escrow: readonly string[];
  /** Child boundaries P declares before → after. */
  readonly parentChildrenBefore: readonly string[];
  readonly parentChildrenAfter: readonly string[];
  /** Entries already under the folder that move from P's recipients to the new set. */
  readonly entries: readonly string[];
  /** P's recipients NOT in the new set: they could read those entries (recorded for rotation). */
  readonly losingAccess: readonly string[];
  readonly digest: string;
}

export async function planCreateSubfolder(
  snapshot: StoreSnapshot,
  folder: string,
  recipients: readonly string[],
  opts: { operatorFingerprint: string; signal?: AbortSignal },
): Promise<CreateSubfolderPlan & { readonly parentRemovedAfter: readonly string[] }> {
  const f = normalizePath(folder);
  if (f === '') throw new SubfolderError('invalid-change', 'The store root already exists');
  if (snapshot.hasFile(joinPath(f, GPG_ID))) throw new SubfolderError('invalid-change', `"${f}" already has its own .gpg-id`);
  if (nestedGpgIdFolders(snapshot, f).length) throw new SubfolderError('invalid-change', `"${f}" contains folders with their own .gpg-id; create the boundary below them or remove them first`);
  const p = parentBoundary(snapshot, f);
  const op = opts.operatorFingerprint.toUpperCase();
  await assertAdminRecipient(snapshot, p, op, 're-encrypt the entries that move');
  const vP = await mustVerify(snapshot, p, opts.signal);
  const exp = await expectedChildBoundaries(snapshot, p, opts.signal);
  if (!exp.ok) throw new SubfolderError('folder-not-verified', `Cannot re-sign "${p || '/'}": ${exp.reason}`);

  const escrow = (await escrowRecipientIds(snapshot, opts.signal)).map(normalizeKeyId);
  const set = [...new Set(recipients.map((r) => r.toUpperCase()))].filter((r) => !escrow.includes(r)).sort();
  if (!set.length) throw new SubfolderError('invalid-change', 'A sub-folder needs at least one recipient besides the escrow key');
  for (const r of set) if (!FPR_RE.test(r)) throw new SubfolderError('invalid-change', `"${r}" is not a full fingerprint`);

  const entries = listGovernedEntries(snapshot, p).filter((e) => e.startsWith(f + '/'));
  const losingAccess = vP.fingerprints.filter((x) => !escrow.includes(x) && !set.includes(x)).sort();
  const parentChildrenAfter = [...new Set([...exp.children, f])].sort();
  const parentRemovedAfter = exp.removed.filter((r) => r !== f);
  const base = { folder: f, parent: p, recipients: set, escrow, parentChildrenBefore: [...exp.children], parentChildrenAfter, entries, losingAccess };
  const digest = await digestOf({ ...base, parentRemovedAfter, type: 'g00pass.create-subfolder' });
  return { ...base, parentRemovedAfter, digest };
}

export interface SubfolderOptions {
  loadSnapshot: (signal?: AbortSignal) => Promise<StoreSnapshot>;
  writer: StoreWriter;
  operatorKey: PrivateKey;
  /** Digest of the plan the operator reviewed. */
  approvedPlanDigest: string;
  armor?: boolean;
  now?: Date;
  onConflict?: (attempt: number) => void;
  signal?: AbortSignal;
}

export async function createSubfolder(folder: string, recipients: readonly string[], opts: SubfolderOptions): Promise<ReencryptResult> {
  const op = fingerprintOf(opts.operatorKey);
  return withConflictRetry(
    async () => {
      const snapshot = await opts.loadSnapshot(opts.signal);
      const plan = await planCreateSubfolder(snapshot, folder, recipients, { operatorFingerprint: op, signal: opts.signal });
      if (plan.digest !== opts.approvedPlanDigest) throw new SubfolderError('plan-changed', 'The change differs from the one you reviewed (the store changed); review it again');
      const now = opts.now ?? trustEnvironment().now();
      const pText = (await snapshot.readFile(joinPath(plan.parent, GPG_ID), opts.signal))!;
      const parentSig = await signGpgId(pText, plan.parent, opts.operatorKey, { children: plan.parentChildrenAfter, removed: plan.parentRemovedAfter, date: now });

      // Rotation file of the new folder: carry the moved entries' metadata
      // over and record P's recipients that lose access as removed now.
      const parentDoc = await readRotation(snapshot, plan.parent, [opts.operatorKey], opts.signal);
      let doc = emptyRotation(plan.folder);
      for (const e of plan.entries) {
        const meta = parentDoc.entries[rotationKey(plan.parent, e)];
        if (meta && e !== rotationPath(plan.folder)) doc.entries[rotationKey(plan.folder, e)] = meta;
      }
      for (const x of plan.losingAccess) doc = recordMemberRemoved(doc, x, op, now);

      return reencryptFolder(plan.folder, plan.recipients, {
        snapshot,
        writer: opts.writer,
        decryptionKeys: [opts.operatorKey],
        newBoundary: { parent: plan.parent, signature: parentSig },
        gpgIdSignature: (t, c) => signGpgId(t, plan.folder, opts.operatorKey, { children: c.children, removed: c.removed, date: now }),
        replaceEntries: [{ path: rotationPath(plan.folder), plaintext: serializeRotation(doc) }],
        armor: opts.armor,
        message: `g00pass: create sub-folder ${plan.folder} (${plan.recipients.length} recipients)`,
        signal: opts.signal,
      });
    },
    { signal: opts.signal, onConflict: (_e, n) => opts.onConflict?.(n) },
  );
}

// ---------------------------------------------------------------- remove

export interface RemoveSubfolderPlan {
  readonly folder: string;
  readonly parent: string;
  /** Recipients of the folder today (non-escrow). */
  readonly before: readonly string[];
  /** Recipients after the merge = the parent's (non-escrow). */
  readonly after: readonly string[];
  /** Parent recipients that could NOT read the folder's entries and now can. */
  readonly gainingAccess: readonly string[];
  readonly entries: readonly string[];
  readonly parentChildrenAfter: readonly string[];
  readonly parentRemovedAfter: readonly string[];
  readonly digest: string;
}

export async function planRemoveSubfolder(
  snapshot: StoreSnapshot,
  folder: string,
  opts: { operatorFingerprint: string; signal?: AbortSignal },
): Promise<RemoveSubfolderPlan> {
  const f = normalizePath(folder);
  if (f === '') throw new SubfolderError('invalid-change', 'The store root cannot be removed');
  if (!snapshot.hasFile(joinPath(f, GPG_ID))) throw new SubfolderError('invalid-change', `"${f}" has no .gpg-id of its own`);
  if (nestedGpgIdFolders(snapshot, f).length) throw new SubfolderError('invalid-change', `"${f}" contains folders with their own .gpg-id; remove those first`);
  const p = parentBoundary(snapshot, f);
  const op = opts.operatorFingerprint.toUpperCase();
  await assertAdminRecipient(snapshot, p, op, 're-sign it');
  if (!(await isFolderRecipient(snapshot, f, op))) throw new SubfolderError('not-recipient', `You are not a recipient of "${f}", so you cannot re-encrypt its entries`);
  const vF = await mustVerify(snapshot, f, opts.signal);
  // No declared or device-known boundary below C may be missing: its entries
  // were encrypted to a NARROWER set and must not be merged into P's.
  const own = await expectedChildBoundaries(snapshot, f, opts.signal);
  if (!own.ok) throw new SubfolderError('folder-not-verified', `Cannot remove "${f}": ${own.reason}`);
  if (own.children.length) throw new SubfolderError('invalid-change', `"${f}" declares sub-folders with their own recipients; remove those first`);
  if (vF.warnings.some((w) => w.startsWith('boundary-vanished:'))) throw new SubfolderError('folder-not-verified', `Cannot remove "${f}": a sub-folder boundary below it was deleted`);
  const vP = await mustVerify(snapshot, p, opts.signal);
  const exp = await expectedChildBoundaries(snapshot, p, opts.signal);
  if (!exp.ok) throw new SubfolderError('folder-not-verified', `Cannot re-sign "${p || '/'}": ${exp.reason}`);
  if (!exp.children.includes(f)) throw new SubfolderError('invalid-change', `"${f}" is not a declared child of "${p || '/'}"`);
  const escrow = (await escrowRecipientIds(snapshot, opts.signal)).map(normalizeKeyId);
  const before = vF.fingerprints.filter((x) => !escrow.includes(x)).sort();
  const after = vP.fingerprints.filter((x) => !escrow.includes(x)).sort();
  const base = {
    folder: f,
    parent: p,
    before,
    after,
    gainingAccess: after.filter((x) => !before.includes(x)),
    entries: listEntries(snapshot, f),
    parentChildrenAfter: exp.children.filter((c) => c !== f),
    parentRemovedAfter: [...new Set([...exp.removed, f])].sort(),
  };
  return { ...base, digest: await digestOf({ ...base, type: 'g00pass.remove-subfolder' }) };
}

export async function removeSubfolder(folder: string, opts: SubfolderOptions): Promise<CommitResult & { plan: RemoveSubfolderPlan }> {
  const op = fingerprintOf(opts.operatorKey);
  return withConflictRetry(
    async () => {
      const snapshot = await opts.loadSnapshot(opts.signal);
      const plan = await planRemoveSubfolder(snapshot, folder, { operatorFingerprint: op, signal: opts.signal });
      if (plan.digest !== opts.approvedPlanDigest) throw new SubfolderError('plan-changed', 'The change differs from the one you reviewed (the store changed); review it again');
      const now = opts.now ?? trustEnvironment().now();
      const vP = await mustVerify(snapshot, plan.parent, opts.signal);

      // The parent's new signature: unchanged `.gpg-id`, child dropped, removal declared.
      const pText = (await snapshot.readFile(joinPath(plan.parent, GPG_ID), opts.signal))!;
      const parentSig = await signGpgId(pText, plan.parent, opts.operatorKey, { children: plan.parentChildrenAfter, removed: plan.parentRemovedAfter, date: now });
      const root = await evaluateRootTrust(snapshot, opts.signal);
      if (!root.ok) throw new SubfolderError('folder-not-verified', root.reason);
      const { allowed } = await allowedSigners(snapshot, plan.parent, root, opts.signal);
      const chk = await checkGpgIdSignature(snapshot, plan.parent, pText, parentSig, allowed, opts.signal);
      if (!chk.ok) throw new SubfolderError('not-admin', `Your signature for "${plan.parent || '/'}" would not verify: ${chk.reason}`);

      const changes: FileChange[] = [];
      const failed: string[] = [];
      const misfits: string[] = [];
      const vF = await mustVerify(snapshot, plan.folder, opts.signal);
      const escrow = new Set((await escrowRecipientIds(snapshot, opts.signal)).map(normalizeKeyId));
      const fKeys = vF.keys.filter((_k, i) => !escrow.has(vF.fingerprints[i]!));
      for (const e of plan.entries) {
        throwIfAborted(opts.signal);
        const ct = await snapshot.readFile(e, opts.signal);
        let plain: Uint8Array | null = null;
        try {
          if (!ct) throw new DecryptError(e);
          // Every entry must already be readable by all of C's recipients;
          // otherwise it belongs to a narrower (e.g. deleted) boundary.
          const missing = await missingRecipients(ct, fKeys);
          if (missing === null || missing.length) {
            misfits.push(e);
            continue;
          }
          plain = await decryptEntry(ct, [opts.operatorKey], e);
          changes.push({ path: e, content: await encryptToVerified(plain, vP, { armor: opts.armor }) });
        } catch (err) {
          if (err instanceof DecryptError) failed.push(e);
          else throw err;
        } finally {
          wipe(plain);
        }
      }
      if (misfits.length) throw new SubfolderError('folder-not-verified', `Refusing to remove "${plan.folder}": ${misfits.length} entr${misfits.length === 1 ? 'y is' : 'ies are'} not encrypted to every current recipient of it (${misfits.slice(0, 5).join(', ')})`);
      if (failed.length) throw new SubfolderError('decrypt-failed', `Refusing to remove "${plan.folder}": ${failed.length} entr${failed.length === 1 ? 'y' : 'ies'} could not be decrypted with your key (${failed.slice(0, 5).join(', ')})`);

      for (const name of [GPG_ID, GPG_ID_SIG, ADMINS_FILE, ADMINS_SIG]) {
        const path = joinPath(plan.folder, name);
        if (snapshot.hasFile(path)) changes.push({ path, delete: true });
      }
      changes.push({ path: joinPath(plan.parent, GPG_ID_SIG), content: parentSig });
      throwIfAborted(opts.signal);
      const res = await opts.writer.commit(changes, {
        baseSha: snapshot.commitSha,
        message: `g00pass: remove sub-folder boundary ${plan.folder} (merged into ${plan.parent || '/'}, ${plan.entries.length} entries)`,
        signal: opts.signal,
      });
      return { ...res, plan };
    },
    { signal: opts.signal, onConflict: (_e, n) => opts.onConflict?.(n) },
  );
}

/** Recipients of `folder`'s own `.gpg-id` as full fingerprints (non-escrow lines), for the UI. */
export async function folderRecipientFingerprints(snapshot: StoreSnapshot, folder: string): Promise<string[]> {
  const lines = (await readRecipientLines(snapshot, folder)) ?? [];
  const escrow = await escrowRecipientIds(snapshot);
  return lines
    .filter((l) => !l.flags.includes(ESCROW_FLAG) && !escrow.some((e) => idMatchesFingerprint(e, normalizeKeyId(l.id))))
    .map((l) => normalizeKeyId(l.id));
}
