import type { PrivateKey } from 'openpgp';
import { canonicalJson, sha256Digest } from '../canonical';
import { G00passError, RecipientKeyError, TrustError } from '../errors';
import { ESCROW_FLAG, type GpgIdLine, normalizeKeyId } from '../gpgid';
import { fingerprintOf, parsePublicKey } from '../keys';
import { GPG_ID, GPG_ID_SIG, PUBLIC_KEYS_DIR, joinPath, normalizePath } from '../paths';
import { type ReencryptOptions, type ReencryptProgress, type ReencryptResult, reencryptFolder } from '../reencrypt';
import { sanitizeDisplayText } from '../requests/parse';
import { type FileChange, type StoreSnapshot, type StoreWriter, listGovernedEntries, nestedGpgIdFolders } from '../store';
import { ADMINS_FILE, ADMINS_SIG, signAdminsFile, verifyAdminsFile } from '../admins';
import { checkGpgIdSignature, evaluateRootTrust } from '../anchors';
import { allowedSigners } from '../boundaries';
import { type RotationDocument, readRotation, rotationPath, serializeRotation } from '../rotation';
import { trustEnvironment } from '../trust-env';
import { signGpgId } from '../signatures';
import { escrowRecipientIds, getTrustHook, verifyRecipients } from '../trust';
import { idMatchesFingerprint, readRecipientLines } from './folders';

export interface RecipientChange {
  /** Recipients to add; `publicKey` is committed to `.public-keys/<FPR>`. */
  add?: readonly { fingerprint: string; publicKey: string }[];
  /**
   * Fingerprints (40 hex) to remove. The escrow recipient can never be
   * removed. A removed recipient listed in the folder's own admins file is
   * removed from it too (removing someone removes all of their rights there).
   */
  remove?: readonly string[];
  /** Changes to the folder's own `.g00pass-admins.json` (signed in the same commit). */
  admins?: { add?: readonly string[]; remove?: readonly string[] };
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
  /**
   * The folder's own admins file before → after (verified admins; null =
   * no file), or null when the admins file does not change.
   */
  readonly admins: { readonly before: readonly string[] | null; readonly after: readonly string[] | null } | null;
  /**
   * Nested boundaries (`.gpg-id` and/or admins file) that are re-signed by the
   * operator in the same commit because their current signer loses admin
   * rights with this change (otherwise they would stop verifying).
   */
  readonly resign: readonly { readonly folder: string; readonly gpgId: boolean; readonly adminsFile: boolean }[];
  /** `sha256:` over the canonical {folder, before, after}: what the operator approves. */
  readonly digest: string;
  /** Warnings of the current set (e.g. `escrow-missing`, which this change repairs). */
  readonly warnings: readonly string[];
}

interface InternalPlan extends RecipientChangePlan {
  readonly lines: GpgIdLine[];
  readonly pending: Map<string, string>;
  /** Re-sign inputs: children / removals each nested `.gpg-id` declares now. */
  readonly resignChildren: ReadonlyMap<string, { children: readonly string[]; removed: readonly string[] }>;
  /** Current verified admins of nested admins files that are re-signed. */
  readonly resignAdmins: ReadonlyMap<string, readonly string[]>;
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
  /**
   * Update the folder's rotation file (rotation.md) in the same commit: gets
   * the current document (decrypted with `operatorKey`, or the empty default)
   * and returns the new one.
   */
  rotation?: (doc: RotationDocument) => RotationDocument;
  /** Clock for signatures / rotation timestamps (default: trust environment). */
  now?: Date;
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

  // ---- the folder's own admins file ----
  const adminsFile = await verifyAdminsFile(snapshot, f, opts.signal);
  const adminsBefore = adminsFile.status === 'valid' ? [...adminsFile.admins].sort() : null;
  const adminAdd = (change.admins?.add ?? []).map((a) => a.toUpperCase());
  const adminRemove = new Set((change.admins?.remove ?? []).map((a) => a.toUpperCase()));
  for (const r of remove) if (adminsBefore?.includes(r)) adminRemove.add(r);
  let admins: InternalPlan['admins'] = null;
  if (adminAdd.length || adminRemove.size) {
    if (adminsFile.status === 'invalid') {
      throw new RecipientChangeError('folder-not-verified', `The admins file of "${f}" is not valid (${adminsFile.reason}); a global admin must re-sign it first`);
    }
    for (const a of [...adminAdd, ...adminRemove]) if (!FPR_RE.test(a)) throw new RecipientChangeError('invalid-change', 'Invalid admin fingerprint');
    if (escrow.some((e) => adminAdd.includes(e))) throw new RecipientChangeError('invalid-change', 'The escrow key can never be an admin');
    if (adminRemove.has(operatorFpr)) throw new RecipientChangeError('invalid-change', 'You cannot remove yourself as an admin here; ask another admin');
    for (const r of adminRemove) if (!adminsBefore?.includes(r)) throw new RecipientChangeError('invalid-change', 'Fingerprint to remove is not an admin of this folder');
    const after = [...new Set([...(adminsBefore ?? []), ...adminAdd])].filter((a) => !adminRemove.has(a)).sort();
    admins = { before: adminsBefore, after: after.length ? after : null };
  }

  // ---- nested boundaries signed by someone who loses admin rights ----
  const resignChildren = new Map<string, { children: readonly string[]; removed: readonly string[] }>();
  const resignAdmins = new Map<string, readonly string[]>();
  if (adminRemove.size) {
    const root = await evaluateRootTrust(snapshot, opts.signal);
    const lost = [...adminRemove].filter((a) => !(root.ok && root.anchors.includes(a)));
    for (const d of nestedGpgIdFolders(snapshot, f)) {
      if (root.ok) {
        const content = await snapshot.readFile(joinPath(d, GPG_ID), opts.signal);
        const sig = await snapshot.readFile(joinPath(d, GPG_ID_SIG), opts.signal);
        const { allowed } = await allowedSigners(snapshot, d, root, opts.signal);
        const chk = content ? await checkGpgIdSignature(snapshot, d, content, sig, allowed, opts.signal) : null;
        if (chk?.ok && lost.includes(chk.signer)) resignChildren.set(d, { children: chk.children, removed: chk.removed });
      }
      const af = await verifyAdminsFile(snapshot, d, opts.signal);
      if (af.status === 'valid' && lost.includes(af.signer)) resignAdmins.set(d, af.admins);
    }
  }
  const resign = [...new Set([...resignChildren.keys(), ...resignAdmins.keys()])]
    .sort()
    .map((d) => ({ folder: d, gpgId: resignChildren.has(d), adminsFile: resignAdmins.has(d) }));

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
        admins,
        childBoundaries: [...childBoundaries],
        folder: f,
        resign,
        type: 'g00pass.recipient-change',
      }),
    ),
  );
  return { folder: f, before, after, added, removed, droppedEscrow, childBoundaries, admins, resign, digest, warnings, lines, pending, resignChildren, resignAdmins };
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

  const date = opts.now ?? trustEnvironment().now();
  const extra: FileChange[] = [...(opts.extraChanges ?? [])];
  if (plan.admins) {
    if (plan.admins.after) {
      extra.push(...(await signAdminsFile({ snapshot, folder: f, admins: plan.admins.after, signingKey: operatorKey, date, signal: opts.signal })).changes);
    } else {
      extra.push({ path: joinPath(f, ADMINS_FILE), delete: true }, { path: joinPath(f, ADMINS_SIG), delete: true });
    }
  }
  for (const [d, decl] of plan.resignChildren) {
    const text = await snapshot.readFile(joinPath(d, GPG_ID), opts.signal);
    if (text) extra.push({ path: joinPath(d, GPG_ID_SIG), content: await signGpgId(text, d, operatorKey, { ...decl, date }) });
  }
  for (const [d, admins] of plan.resignAdmins) {
    extra.push(...(await signAdminsFile({ snapshot, folder: d, admins, signingKey: operatorKey, date, signal: opts.signal })).changes);
  }
  const replaceEntries = [...(opts.replaceEntries ?? [])];
  if (opts.rotation) {
    const doc = opts.rotation(await readRotation(snapshot, f, [operatorKey], opts.signal));
    replaceEntries.push({ path: rotationPath(f), plaintext: serializeRotation(doc) });
  }

  const total = listGovernedEntries(snapshot, f).length;
  return reencryptFolder(f, plan.lines, {
    snapshot,
    writer: opts.writer,
    decryptionKeys: [operatorKey],
    pendingKeys: pending,
    gpgIdSignature: (text, ctx) => signGpgId(text, f, operatorKey, { children: ctx.children, removed: ctx.removed }),
    replaceEntries,
    extraChanges: extra,
    message: opts.message,
    chunkSize: opts.chunkSize,
    armor: opts.armor ?? total > ARMOR_THRESHOLD,
    onProgress: opts.onProgress,
    signal: opts.signal,
  });
}
