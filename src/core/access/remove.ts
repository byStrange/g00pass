import type { PrivateKey } from 'openpgp';
import { checkFolderAdmin, verifyAdminsFile } from '../admins';
import { G00passError } from '../errors';
import { withConflictRetry } from '../github/commit';
import { fingerprintOf } from '../keys';
import { GPG_ID, dirname, joinPath, normalizePath } from '../paths';
import type { ReencryptProgress, ReencryptResult } from '../reencrypt';
import { recordMemberRemoved } from '../rotation';
import type { StoreSnapshot, StoreWriter } from '../store';
import { trustEnvironment } from '../trust-env';
import { escrowRecipientIds } from '../trust';
import { idMatchesFingerprint, isFolderRecipient, readRecipientLines } from './folders';
import { type RecipientChangePlan, RecipientChangeError, changeFolderRecipients, planFolderRecipientChange } from './recipients';

/**
 * REMOVE MEMBER (docs/specs/rotation.md §"Remove member" flow).
 *
 * Reuses the recipient-change pipeline with `remove`: the member leaves F's
 * `.gpg-id` and F's own admins file, every governed entry is re-encrypted to
 * the remaining recipients, nested boundaries the member signed as an admin
 * are re-signed by the operator, and the rotation file records the removal,
 * all in ONE commit. Removing a key does NOT revoke access to anything the
 * member already decrypted: the rotation checklist lists what to rotate.
 */

export class RemovalError extends G00passError {
  constructor(
    public readonly code: 'not-admin' | 'not-recipient' | 'not-member' | 'escrow' | 'self' | 'folder-not-verified' | 'plan-changed' | 'invalid-change',
    message: string,
  ) {
    super(message);
  }
}

const FPR_RE = /^[0-9A-F]{40}$|^[0-9A-F]{64}$/;

const asRemovalError = (e: unknown): never => {
  if (e instanceof RecipientChangeError) throw new RemovalError(e.code, e.message);
  throw e;
};

/** Authority + target checks against `snapshot`; throws RemovalError. */
export async function assertCanRemove(snapshot: StoreSnapshot, folder: string, member: string, operatorFpr: string): Promise<void> {
  const f = normalizePath(folder);
  const fpr = member.toUpperCase();
  if (!FPR_RE.test(fpr)) throw new RemovalError('invalid-change', 'Not a full fingerprint');
  if (!snapshot.hasFile(joinPath(f, GPG_ID))) throw new RemovalError('invalid-change', `"${f}" has no .gpg-id of its own`);
  if (fpr === operatorFpr.toUpperCase()) throw new RemovalError('self', 'You cannot remove yourself; ask another admin');
  if ((await escrowRecipientIds(snapshot)).some((e) => idMatchesFingerprint(e, fpr))) throw new RemovalError('escrow', 'The escrow recipient can never be removed');
  if (!(await isFolderRecipient(snapshot, f, fpr))) throw new RemovalError('not-member', 'Not a recipient of this folder');
  if (!(await isFolderRecipient(snapshot, f, operatorFpr))) throw new RemovalError('not-recipient', 'You are not a recipient of this folder, so you cannot re-encrypt it');
  const admin = await checkFolderAdmin(snapshot, f, operatorFpr);
  if (!admin.admin) throw new RemovalError('not-admin', `You are not a verified admin of this folder: ${admin.reason}`);
}

/** Exact before → after plan of removing `member` from `folder` (review it; pass its digest to removeMember). */
export async function previewRemoval(snapshot: StoreSnapshot, folder: string, member: string, operatorFpr: string, signal?: AbortSignal): Promise<RecipientChangePlan> {
  await assertCanRemove(snapshot, folder, member, operatorFpr);
  return planFolderRecipientChange(snapshot, folder, { remove: [member.toUpperCase()] }, { operatorFingerprint: operatorFpr, signal }).catch(asRemovalError);
}

export interface RemoveMemberOptions {
  loadSnapshot: (signal?: AbortSignal) => Promise<StoreSnapshot>;
  writer: StoreWriter;
  operatorKey: PrivateKey;
  /** `digest` of the plan from previewRemoval that the operator reviewed. */
  approvedPlanDigest: string;
  armor?: boolean;
  now?: Date;
  onProgress?: (p: ReencryptProgress) => void;
  onConflict?: (attempt: number) => void;
  signal?: AbortSignal;
}

export async function removeMember(folder: string, member: string, opts: RemoveMemberOptions): Promise<ReencryptResult> {
  const f = normalizePath(folder);
  const fpr = member.toUpperCase();
  const op = fingerprintOf(opts.operatorKey);
  if (typeof opts.approvedPlanDigest !== 'string' || !opts.approvedPlanDigest) throw new RemovalError('plan-changed', 'Review the recipient change before removing');
  return withConflictRetry(
    async () => {
      const snapshot = await opts.loadSnapshot(opts.signal);
      await assertCanRemove(snapshot, f, fpr, op);
      const now = opts.now ?? trustEnvironment().now();
      return changeFolderRecipients(f, { remove: [fpr] }, {
        snapshot,
        writer: opts.writer,
        operatorKey: opts.operatorKey,
        approvedPlanDigest: opts.approvedPlanDigest,
        now,
        rotation: (doc) => recordMemberRemoved(doc, fpr, op, now),
        armor: opts.armor,
        message: `g00pass: remove ${fpr.slice(-16)} from ${f}`,
        onProgress: opts.onProgress,
        signal: opts.signal,
      }).catch(asRemovalError);
    },
    { signal: opts.signal, onConflict: (_e, n) => opts.onConflict?.(n) },
  );
}

export interface MemberAccess {
  readonly folder: string;
  readonly recipient: boolean;
  /** Listed in this folder's own (verified) admins file. */
  readonly admin: boolean;
}

/**
 * Every other folder with its own `.gpg-id` where `member` is still a
 * recipient or a listed admin (so the UI can offer removing them there too).
 * Nested folders are NOT covered by removing someone from a parent.
 */
export async function memberAccessElsewhere(snapshot: StoreSnapshot, member: string, except: string, signal?: AbortSignal): Promise<MemberAccess[]> {
  const fpr = member.toUpperCase();
  const out: MemberAccess[] = [];
  const folders = snapshot
    .listFiles()
    .filter((p) => p === GPG_ID || p.endsWith('/' + GPG_ID))
    .map(dirname)
    .filter((d) => d !== normalizePath(except))
    .sort();
  for (const d of folders) {
    const lines = (await readRecipientLines(snapshot, d, signal)) ?? [];
    const recipient = lines.some((l) => idMatchesFingerprint(l.id, fpr));
    const af = d === '' ? null : await verifyAdminsFile(snapshot, d, signal);
    const admin = !!af && af.status === 'valid' && af.admins.includes(fpr);
    if (recipient || admin) out.push({ folder: d, recipient, admin });
  }
  return out;
}
