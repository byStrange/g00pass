import type { PrivateKey } from 'openpgp';
import { canonicalJson, sha256Digest } from '../canonical';
import { G00passError, RecipientKeyError, TrustError } from '../errors';
import { ESCROW_FLAG, type GpgIdLine, normalizeKeyId } from '../gpgid';
import { fingerprintOf, parsePublicKey } from '../keys';
import { GPG_ID, PUBLIC_KEYS_DIR, joinPath, normalizePath } from '../paths';
import { type ReencryptOptions, type ReencryptProgress, type ReencryptResult, reencryptFolder } from '../reencrypt';
import { sanitizeDisplayText } from '../requests/parse';
import { type StoreSnapshot, type StoreWriter, listGovernedEntries } from '../store';
import { signGpgId } from '../signatures';
import { escrowRecipientIds, getTrustHook, verifyRecipients } from '../trust';
import { idMatchesFingerprint, readRecipientLines } from './folders';

export interface RecipientChange {
  /** Recipients to add; `publicKey` is committed to `.public-keys/<FPR>`. */
  add?: readonly { fingerprint: string; publicKey: string }[];
  /** Fingerprints (40 hex) to remove. The escrow recipient can never be removed. */
  remove?: readonly string[];
}

export type RecipientChangeErrorCode =
  | 'invalid-change'
  | 'not-recipient'
  /** The CURRENT `.gpg-id` of the folder does not verify; it must not be re-signed. */
  | 'folder-not-verified'
  /** The change differs from the plan the operator approved. */
  | 'plan-changed';

export class RecipientChangeError extends G00passError {
  constructor(
    public readonly code: RecipientChangeErrorCode,
    message: string,
  ) {
    super(message);
  }
}

/** One recipient line as shown to the operator. */
export interface PlannedRecipient {
  /** Full upper-case fingerprint. */
  readonly fingerprint: string;
  /** User ids from the key (display only, sanitized; never trusted). */
  readonly userIds: readonly string[];
  readonly escrow: boolean;
}

/**
 * The exact before → after recipient change of a folder, computed from one
 * snapshot. The operator must see `before`/`after` (full fingerprints) and
 * approve `digest`; `changeFolderRecipients` recomputes the plan on the
 * snapshot it commits on and refuses if the digest differs.
 */
export interface RecipientChangePlan {
  readonly folder: string;
  readonly before: readonly PlannedRecipient[];
  readonly after: readonly PlannedRecipient[];
  readonly added: readonly string[];
  readonly removed: readonly string[];
  /** Retired escrow lines (flagged, but no longer escrow in the root) that are dropped. */
  readonly droppedEscrow: readonly string[];
  /** Child boundaries the new signature will declare. */
  readonly childBoundaries: readonly string[];
  /** `sha256:` over the canonical {folder, before, after}: what the operator approves. */
  readonly digest: string;
  /** Warnings of the current set (e.g. `escrow-missing`, which this change repairs). */
  readonly warnings: readonly string[];
}

interface InternalPlan extends RecipientChangePlan {
  readonly lines: GpgIdLine[];
  readonly pending: Map<string, string>;
}

export interface ChangeRecipientsOptions {
  snapshot: StoreSnapshot;
  writer: StoreWriter;
  /** Unlocked operator key: decrypts every entry and signs the new `.gpg-id`. */
  operatorKey: PrivateKey;
  /**
   * `digest` of the RecipientChangePlan the operator reviewed and approved
   * (planFolderRecipientChange). Required: the core refuses a change the
   * operator did not see.
   */
  approvedPlanDigest: string;
  message?: string;
  /** Default: armored (single tree request) when the folder has more than 50 entries. */
  armor?: boolean;
  extraChanges?: ReencryptOptions['extraChanges'];
  replaceEntries?: ReencryptOptions['replaceEntries'];
  chunkSize?: number;
  onProgress?: (p: ReencryptProgress) => void;
  signal?: AbortSignal;
}

/** GitHub throttles content creation (~80/min); above this, armored inline content is used. */
export const ARMOR_THRESHOLD = 50;

const FPR_RE = /^[0-9A-F]{40}$/;

async function userIdsOf(snapshot: StoreSnapshot, fpr: string, pending: ReadonlyMap<string, string>): Promise<string[]> {
  try {
    const data = pending.get(fpr) ?? (await snapshot.readFile(joinPath(PUBLIC_KEYS_DIR, fpr)));
    if (!data) return [];
    const keys = await parsePublicKey(data, fpr);
    if (keys.length !== 1 || fingerprintOf(keys[0]!) !== fpr) return [];
    return keys[0]!.getUserIDs().slice(0, 5).map((u) => sanitizeDisplayText(u, 200));
  } catch {
    return [];
  }
}

/**
 * Compute (and validate) the recipient change of `folder` WITHOUT writing:
 *  - the folder's CURRENT `.gpg-id` must pass the trust choke-point
 *    (`verifyRecipients`): an approval must never re-sign a list someone
 *    edited without authority. The only tolerated failure is
 *    `escrow-missing` (the policy checks escrow last, so everything else
 *    passed), because re-encrypting is exactly how escrow is repaired;
 *  - escrow lines are rebuilt from the root: flagged lines whose fingerprint
 *    is no longer escrow in the root are dropped (recovery.md §Rotating);
 *  - the operator must be a recipient (they decrypt everything);
 *  - the child boundaries the new signature declares must be acceptable.
 */
export async function planFolderRecipientChange(
  snapshot: StoreSnapshot,
  folder: string,
  change: RecipientChange,
  opts: { operatorFingerprint: string; signal?: AbortSignal },
): Promise<RecipientChangePlan> {
  return buildPlan(snapshot, folder, change, opts);
}

async function buildPlan(
  snapshot: StoreSnapshot,
  folder: string,
  change: RecipientChange,
  opts: { operatorFingerprint: string; signal?: AbortSignal },
): Promise<InternalPlan> {
  const f = normalizePath(folder);
  if (f === '') throw new RecipientChangeError('invalid-change', 'Changing the root recipient list is not supported here');
  if (!snapshot.hasFile(joinPath(f, GPG_ID))) throw new RecipientChangeError('invalid-change', `"${f}" has no .gpg-id of its own`);

  let warnings: readonly string[];
  try {
    const v = await verifyRecipients(snapshot, { folder: f }, { signal: opts.signal });
    if (v.folder !== f) throw new RecipientChangeError('folder-not-verified', `"${f}" is not governed by its own .gpg-id`);
    warnings = v.warnings;
  } catch (e) {
    if (e instanceof TrustError && e.code === 'escrow-missing') {
      warnings = ['escrow-missing'];
    } else if (e instanceof TrustError || e instanceof RecipientKeyError) {
      const why = e instanceof TrustError ? `${e.code}: ${e.reason}` : e.message;
      throw new RecipientChangeError(
        'folder-not-verified',
        `The current recipients of "${f}" are not verified (${why}). Refusing to re-sign them: an authorized admin must review and re-sign ${f}/.gpg-id first.`,
      );
    } else {
      throw e;
    }
  }

  const current = await readRecipientLines(snapshot, f, opts.signal);
  if (!current) throw new RecipientChangeError('invalid-change', `"${f}" has no .gpg-id of its own`);
  const operatorFpr = opts.operatorFingerprint.toUpperCase();
  if (!current.some((l) => idMatchesFingerprint(l.id, operatorFpr))) {
    throw new RecipientChangeError('not-recipient', `Your key is not a recipient of "${f}", so you cannot decrypt it to change access`);
  }

  const escrow = (await escrowRecipientIds(snapshot, opts.signal)).map(normalizeKeyId);
  const escrowSet = new Set(escrow);
  const droppedEscrow: string[] = [];
  let lines: GpgIdLine[] = [];
  for (const l of current) {
    const n = normalizeKeyId(l.id);
    if (l.flags.includes(ESCROW_FLAG) && !escrowSet.has(n)) {
      droppedEscrow.push(n);
      continue;
    }
    if (escrowSet.has(n)) continue; // re-added (flagged) from the root below
    lines.push({ id: l.id, flags: l.flags.filter((x) => x !== ESCROW_FLAG) });
  }

  const remove = (change.remove ?? []).map((r) => r.toUpperCase());
  for (const r of remove) {
    if (!FPR_RE.test(r)) throw new RecipientChangeError('invalid-change', 'Invalid fingerprint to remove');
    if (escrow.some((e) => idMatchesFingerprint(e, r))) throw new RecipientChangeError('invalid-change', 'The escrow recipient cannot be removed');
    if (!lines.some((l) => idMatchesFingerprint(l.id, r))) throw new RecipientChangeError('invalid-change', 'Fingerprint to remove is not a recipient');
    lines = lines.filter((l) => !idMatchesFingerprint(l.id, r));
  }

  const pending = new Map<string, string>();
  const added: string[] = [];
  for (const a of change.add ?? []) {
    const fpr = a.fingerprint.toUpperCase();
    if (!FPR_RE.test(fpr)) throw new RecipientChangeError('invalid-change', 'Invalid fingerprint to add');
    if (lines.some((l) => idMatchesFingerprint(l.id, fpr)) || escrowSet.has(fpr)) throw new RecipientChangeError('invalid-change', 'Already a recipient');
    const keys = await parsePublicKey(a.publicKey, fpr);
    if (keys.length !== 1 || fingerprintOf(keys[0]!) !== fpr) throw new RecipientChangeError('invalid-change', 'Public key does not match fingerprint');
    pending.set(fpr, a.publicKey);
    lines.push({ id: fpr, flags: [] });
    added.push(fpr);
  }
  if (lines.length === 0) throw new RecipientChangeError('invalid-change', 'Refusing to leave the folder with only the escrow recipient');

  const hook = getTrustHook();
  let childBoundaries: readonly string[] = [];
  if (hook.childBoundaries) {
    const cb = await hook.childBoundaries(snapshot, f, opts.signal);
    if (!cb.ok) {
      throw new RecipientChangeError('folder-not-verified', `Cannot re-sign "${f}": ${cb.reason}`);
    }
    childBoundaries = cb.children;
  }

  const entry = async (id: string, isEscrow: boolean): Promise<PlannedRecipient> => {
    const n = normalizeKeyId(id);
    return { fingerprint: n, userIds: await userIdsOf(snapshot, n, pending), escrow: isEscrow };
  };
  const before: PlannedRecipient[] = [];
  for (const l of current) before.push(await entry(l.id, l.flags.includes(ESCROW_FLAG) || escrowSet.has(normalizeKeyId(l.id))));
  const after: PlannedRecipient[] = [];
  for (const l of lines) after.push(await entry(l.id, false));
  for (const e of escrow) after.push(await entry(e, true));
  const removed = before.filter((b) => !after.some((a) => a.fingerprint === b.fingerprint)).map((b) => b.fingerprint);

  const digest = await sha256Digest(
    new TextEncoder().encode(
      canonicalJson({
        after: after.map((a) => ({ escrow: a.escrow, fingerprint: a.fingerprint })),
        before: before.map((b) => ({ escrow: b.escrow, fingerprint: b.fingerprint })),
        childBoundaries: [...childBoundaries],
        folder: f,
        type: 'g00pass.recipient-change',
      }),
    ),
  );
  return { folder: f, before, after, added, removed, droppedEscrow, childBoundaries, digest, warnings, lines, pending };
}

/**
 * recipient-change + sign + re-encrypt + commit pipeline, shared by
 * "approve request" (add) and, in Phase 2, "remove member" (remove).
 *
 * Recomputes the plan on `opts.snapshot` (see planFolderRecipientChange for
 * the refusals) and refuses unless it equals `opts.approvedPlanDigest`.
 * One commit contains: all governed entries re-encrypted, the new `.gpg-id`,
 * its detached `.gpg-id.sig` (signed by `operatorKey`, bound to the folder
 * and declaring its child boundaries), new `.public-keys/*`, plus
 * `extraChanges`. Callers wrap this in `withConflictRetry` with a fresh
 * snapshot per attempt. Encryption goes through reencryptFolder, i.e. the
 * trust choke-point; escrow recipients are merged back in by the core.
 */
export async function changeFolderRecipients(
  folder: string,
  change: RecipientChange,
  opts: ChangeRecipientsOptions,
): Promise<ReencryptResult> {
  const { snapshot, operatorKey } = opts;
  const operatorFpr = fingerprintOf(operatorKey);
  const plan = await buildPlan(snapshot, folder, change, { operatorFingerprint: operatorFpr, signal: opts.signal });
  if (typeof opts.approvedPlanDigest !== 'string' || opts.approvedPlanDigest !== plan.digest) {
    throw new RecipientChangeError('plan-changed', 'The recipient change differs from the one you approved (the store changed); review it again');
  }
  const f = plan.folder;
  const pending = new Map(plan.pending);
  // The signer's public key must be in the store for signature verification.
  const opKeyPath = joinPath(PUBLIC_KEYS_DIR, operatorFpr);
  if (!snapshot.hasFile(opKeyPath) && !pending.has(operatorFpr)) pending.set(operatorFpr, operatorKey.toPublic().armor());

  const total = listGovernedEntries(snapshot, f).length;
  return reencryptFolder(f, plan.lines, {
    snapshot,
    writer: opts.writer,
    decryptionKeys: [operatorKey],
    pendingKeys: pending,
    gpgIdSignature: (text, ctx) => signGpgId(text, f, operatorKey, { children: ctx.children }),
    replaceEntries: opts.replaceEntries,
    extraChanges: opts.extraChanges,
    message: opts.message,
    chunkSize: opts.chunkSize,
    armor: opts.armor ?? total > ARMOR_THRESHOLD,
    onProgress: opts.onProgress,
    signal: opts.signal,
  });
}
