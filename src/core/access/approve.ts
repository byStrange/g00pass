import type { PrivateKey } from 'openpgp';
import { G00passError } from '../errors';
import { fingerprintOf } from '../keys';
import {
  type IssueRepo,
  LABEL_APPROVED,
  LABEL_REJECTED,
  addIssueLabels,
  closeIssue,
  commentOnIssue,
} from '../github/issues';
import type { GitHubClient } from '../github/client';
import { withConflictRetry } from '../github/commit';
import { type ParsedAccessRequest, isParsedAccessRequest } from '../requests/parse';
import type { ReencryptProgress, ReencryptResult } from '../reencrypt';
import type { StoreSnapshot, StoreWriter } from '../store';
import { joinPath } from '../paths';
import { GPG_ID } from '../paths';
import { checkFolderAdmin, signAdminsFile, verifyAdminsFile } from '../admins';
import { isFolderRecipient } from './folders';
import { type RecipientChangePlan, RecipientChangeError, changeFolderRecipients, planFolderRecipientChange } from './recipients';

export type ApprovalErrorCode =
  | 'not-parsed'
  | 'fingerprint-not-confirmed'
  | 'invite-not-acknowledged'
  | 'no-such-folder'
  | 'not-admin'
  | 'not-recipient'
  | 'already-recipient'
  /** The folder's current `.gpg-id` does not verify (it may have been edited without authority). */
  | 'folder-not-verified'
  /** The before → after change differs from the one the operator approved. */
  | 'plan-changed'
  | 'invalid-change';

export class ApprovalError extends G00passError {
  constructor(
    public readonly code: ApprovalErrorCode,
    message: string,
  ) {
    super(message);
  }
}

/** What the operator explicitly confirmed. The UI must fill this only from what the operator typed / ticked. */
export interface ApprovalConfirmation {
  /**
   * The LAST 8 hex characters of the requester's fingerprint, TYPED by the
   * operator from what the requester told them out of band (spaces and case
   * ignored). Must match the request's fingerprint.
   */
  fingerprintSuffix: string;
  /** Extra confirmation for requests whose invite could not be verified (always, until invites ship). */
  acknowledgeUninvited?: boolean;
  /** `digest` of the RecipientChangePlan (before → after) the operator reviewed (previewApproval). */
  approvedPlan: string;
}

export const FINGERPRINT_SUFFIX_LENGTH = 8;

/** Does the typed suffix confirm `fingerprint`? */
export function fingerprintSuffixMatches(typed: string, fingerprint: string): boolean {
  const t = typed.replace(/\s+/g, '').toUpperCase();
  return /^[0-9A-F]{8}$/.test(t) && t === fingerprint.toUpperCase().slice(-FINGERPRINT_SUFFIX_LENGTH);
}

export interface ApproveOptions {
  /** Loads a FRESH snapshot on every (re)try. */
  loadSnapshot: (signal?: AbortSignal) => Promise<StoreSnapshot>;
  writer: StoreWriter;
  /** Unlocked operator key. */
  operatorKey: PrivateKey;
  confirmation: ApprovalConfirmation;
  /** e.g. `acme/requests#12`, used in the commit message. */
  requestRef: string;
  /** Set once invite records are verified (Phase 2); until then approving always needs the extra acknowledgement. */
  inviteVerified?: boolean;
  armor?: boolean;
  onProgress?: (p: ReencryptProgress) => void;
  onConflict?: (attempt: number) => void;
  signal?: AbortSignal;
  now?: Date;
}

export interface ApprovalResult {
  commitSha: string;
  operatorFingerprint: string;
  result: ReencryptResult;
}

/** Next signed admins file for `folder` with `add` merged into the currently VERIFIED admins of that exact folder. */
async function folderAdminsUpdate(
  snapshot: StoreSnapshot,
  folder: string,
  add: string,
  signingKey: PrivateKey,
  date: Date | undefined,
  signal: AbortSignal | undefined,
) {
  const file = await verifyAdminsFile(snapshot, folder, signal);
  if (file.status === 'invalid') throw new ApprovalError('not-admin', `Existing admins file is not valid: ${file.reason}`);
  const existing = file.status === 'valid' ? file.admins : [];
  return (await signAdminsFile({ snapshot, folder, admins: [...existing, add], signingKey, date, signal })).changes;
}

const asApprovalError = (e: unknown): never => {
  if (e instanceof RecipientChangeError) throw new ApprovalError(e.code, e.message);
  throw e;
};

/**
 * Re-check authority against `snapshot` and return the exact recipient change
 * (before → after, full fingerprints) the operator must review; throws
 * ApprovalError. Refuses when the folder's CURRENT recipients do not verify.
 */
export async function previewApproval(snapshot: StoreSnapshot, req: ParsedAccessRequest, operatorFpr: string, signal?: AbortSignal): Promise<RecipientChangePlan> {
  if (!isParsedAccessRequest(req)) throw new ApprovalError('not-parsed', 'Request was not produced by the verified parser');
  await assertCanApprove(snapshot, req, operatorFpr);
  return planFolderRecipientChange(snapshot, req.folder, { add: [{ fingerprint: req.fingerprint, publicKey: req.publicKey }] }, { operatorFingerprint: operatorFpr, signal }).catch(asApprovalError);
}

/** Re-check authority against `snapshot`; throws ApprovalError. */
export async function assertCanApprove(snapshot: StoreSnapshot, req: ParsedAccessRequest, operatorFpr: string): Promise<void> {
  if (!snapshot.hasFile(joinPath(req.folder, GPG_ID))) throw new ApprovalError('no-such-folder', `"${req.folder}" has no .gpg-id of its own`);
  if (await isFolderRecipient(snapshot, req.folder, req.fingerprint)) {
    throw new ApprovalError('already-recipient', 'Requester is already a recipient of this folder');
  }
  if (!(await isFolderRecipient(snapshot, req.folder, operatorFpr))) {
    throw new ApprovalError('not-recipient', 'You are not a recipient of this folder, so you cannot re-encrypt it');
  }
  const admin = await checkFolderAdmin(snapshot, req.folder, operatorFpr);
  if (!admin.admin) throw new ApprovalError('not-admin', `You are not a verified admin of this folder: ${admin.reason}`);
  // The current recipient list must itself be verified before anyone re-signs it.
  try {
    await planFolderRecipientChange(snapshot, req.folder, {}, { operatorFingerprint: operatorFpr });
  } catch (e) {
    if (!(e instanceof RecipientChangeError) || e.code !== 'invalid-change') asApprovalError(e);
  }
}

/**
 * Approve a parsed access request: add the requester to the folder's
 * recipients, re-encrypt, sign `.gpg-id`, and commit - all in ONE commit,
 * retried on branch conflicts with a fresh snapshot each time.
 *
 * Refuses unless the operator typed the requester's fingerprint suffix (the
 * only identity check, docs/specs/access-requests.md) and approved the exact
 * before → after recipient change (`confirmation.approvedPlan`, from
 * previewApproval), which is recomputed and compared on the snapshot that is
 * committed on. Does not touch the issue; call `finalizeApprovedIssue` afterwards.
 */
export async function approveAccessRequest(req: ParsedAccessRequest, opts: ApproveOptions): Promise<ApprovalResult> {
  if (!isParsedAccessRequest(req)) throw new ApprovalError('not-parsed', 'Request was not produced by the verified parser');
  if (typeof opts.confirmation.fingerprintSuffix !== 'string' || !fingerprintSuffixMatches(opts.confirmation.fingerprintSuffix, req.fingerprint)) {
    throw new ApprovalError('fingerprint-not-confirmed', `Type the last ${FINGERPRINT_SUFFIX_LENGTH} characters of the fingerprint the requester gave you out of band`);
  }
  if (typeof opts.confirmation.approvedPlan !== 'string' || !opts.confirmation.approvedPlan) {
    throw new ApprovalError('plan-changed', 'Review the recipient change before approving');
  }
  if ((req.inviteId === null || !opts.inviteVerified) && opts.confirmation.acknowledgeUninvited !== true) {
    throw new ApprovalError('invite-not-acknowledged', 'This request has no verified invite; explicit acknowledgement required');
  }
  const operatorFingerprint = fingerprintOf(opts.operatorKey);

  const result = await withConflictRetry(
    async () => {
      const snapshot = await opts.loadSnapshot(opts.signal);
      await assertCanApprove(snapshot, req, operatorFingerprint);
      const extraChanges =
        req.role === 'folder-admin'
          ? [...(await folderAdminsUpdate(snapshot, req.folder, req.fingerprint, opts.operatorKey, opts.now, opts.signal))]
          : [];
      return changeFolderRecipients(
        req.folder,
        { add: [{ fingerprint: req.fingerprint, publicKey: req.publicKey }] },
        {
          snapshot,
          writer: opts.writer,
          operatorKey: opts.operatorKey,
          extraChanges,
          approvedPlanDigest: opts.confirmation.approvedPlan,
          armor: opts.armor,
          message: `g00pass: grant ${req.fingerprint.slice(-16)} ${req.role} on ${req.folder} (${opts.requestRef})`,
          onProgress: opts.onProgress,
          signal: opts.signal,
        },
      ).catch(asApprovalError);
    },
    { signal: opts.signal, onConflict: (_e, n) => opts.onConflict?.(n) },
  );
  return { commitSha: result.commitSha, operatorFingerprint, result };
}

/** Best-effort follow-up after the commit succeeded; returns the steps that failed (the commit is the source of truth). */
export async function finalizeApprovedIssue(
  client: GitHubClient,
  repo: IssueRepo,
  issueNumber: number,
  approval: Pick<ApprovalResult, 'commitSha' | 'operatorFingerprint'>,
): Promise<string[]> {
  const failed: string[] = [];
  const step = async (name: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch {
      failed.push(name);
    }
  };
  await step('comment', () =>
    commentOnIssue(client, repo, issueNumber, `Approved in \`${approval.commitSha}\` by \`${approval.operatorFingerprint}\`.`),
  );
  await step('label', () => addIssueLabels(client, repo, issueNumber, [LABEL_APPROVED]));
  await step('close', () => closeIssue(client, repo, issueNumber, 'completed'));
  return failed;
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

/** Deny: comment with the optional reason, label, close as not planned. No store commit. */
export async function denyAccessRequest(
  client: GitHubClient,
  repo: IssueRepo,
  issueNumber: number,
  reason?: string,
): Promise<string[]> {
  const clean = (reason ?? '').replace(CONTROL, ' ').trim().slice(0, 500);
  const failed: string[] = [];
  const step = async (name: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch {
      failed.push(name);
    }
  };
  await step('comment', () => commentOnIssue(client, repo, issueNumber, clean ? `Access request denied.\n\nReason: ${clean}` : 'Access request denied.'));
  await step('label', () => addIssueLabels(client, repo, issueNumber, [LABEL_REJECTED]));
  await step('close', () => closeIssue(client, repo, issueNumber, 'not_planned'));
  return failed;
}
