import type { PublicKey } from 'openpgp';
import { TrustError, type TrustErrorCode } from './errors';
import {
  ESCROW_FLAG,
  type GpgIdLine,
  findGpgIdForEntry,
  findGpgIdForFolder,
  gpgIdFolder,
  parseGpgId,
  recipientIds,
  serializeGpgId,
} from './gpgid';
import { type ResolvedRecipient, resolveRecipient, resolveRecipients } from './keys';
import { GPG_ID, GPG_ID_SIG, joinPath, normalizePath } from './paths';
import type { StoreSnapshot } from './store';

/**
 * TRUST CHOKE-POINT.
 *
 * Every encryption in g00pass takes a `VerifiedRecipientSet`, and the only way
 * to obtain one is `verifyRecipients()` / `verifyProposedRecipients()` below,
 * which always run the installed TrustHook. `encryptToVerified()` checks at
 * runtime that the set was minted here (module-private WeakSet), and ESLint
 * forbids calling openpgp.encrypt anywhere else (see eslint.config.js).
 *
 * The hook decides policy (signature checks on .gpg-id, admin lists...). The
 * core additionally enforces, independent of the hook:
 *   - escrow: a proposed recipient set must contain every escrow recipient
 *     flagged in the root .gpg-id (docs/specs/recovery.md)
 *   - fail closed: a hook that throws or returns anything but {ok:true} blocks.
 */

export interface RecipientVerificationRequest {
  /** Folder whose `.gpg-id` governs the encryption ("" = store root). */
  readonly folder: string;
  readonly gpgIdPath: string;
  /** Exact `.gpg-id` bytes (current, or the proposed new content). */
  readonly gpgIdContent: Uint8Array;
  /** Bytes of the detached signature `.gpg-id.sig` (current or proposed), if any. */
  readonly gpgIdSignature: Uint8Array | null;
  /** True when this `.gpg-id` is about to be written (approve / remove / re-encrypt). */
  readonly proposed: boolean;
  readonly recipients: readonly ResolvedRecipient[];
  /** Snapshot the request was computed from (for reading admin files, root .gpg-id...). */
  readonly snapshot: StoreSnapshot;
}

export type TrustDecision =
  | { ok: true; warnings?: readonly string[] }
  | { ok: false; code: TrustErrorCode; reason: string };

export interface TrustHook {
  readonly name: string;
  verify(req: RecipientVerificationRequest): Promise<TrustDecision>;
}

/**
 * TODO(trust): Phase 0 pass-through. Replace with the `.gpg-id.sig`
 * verification described in docs/specs/gpg-id-signatures.md (refuse on
 * missing/invalid signature). Until then the UI should show that recipient
 * signatures are NOT verified.
 */
export const passThroughTrustHook: TrustHook = {
  name: 'pass-through (UNVERIFIED)',
  async verify() {
    return { ok: true, warnings: ['recipient-signatures-not-verified'] };
  },
};

let installedHook: TrustHook = passThroughTrustHook;
let hookLocked = false;

/** Install the trust policy. Call once at app start-up (and in tests). Returns the previous hook. */
export function setTrustHook(hook: TrustHook): TrustHook {
  if (hookLocked) throw new TrustError('', 'trust hook is locked; it can only be set at start-up');
  const prev = installedHook;
  installedHook = hook;
  return prev;
}

/** Freeze the installed trust policy for the lifetime of the page (src/main.ts calls this). */
export function lockTrustHook(): void {
  hookLocked = true;
}

export function getTrustHook(): TrustHook {
  return installedHook;
}

export interface VerifiedRecipientSet {
  readonly folder: string;
  readonly gpgIdPath: string;
  readonly fingerprints: readonly string[];
  readonly keys: readonly PublicKey[];
  readonly snapshotSha: string;
  readonly proposed: boolean;
  readonly warnings: readonly string[];
  readonly hook: string;
}

const minted = new WeakSet<object>();

export function isVerifiedRecipientSet(x: unknown): x is VerifiedRecipientSet {
  return typeof x === 'object' && x !== null && minted.has(x);
}

async function runHook(req: RecipientVerificationRequest, extraWarnings: string[]): Promise<VerifiedRecipientSet> {
  if (req.recipients.length === 0) throw new TrustError(req.folder, 'empty recipient set');
  let decision: TrustDecision;
  try {
    decision = await installedHook.verify(req);
  } catch (e) {
    throw new TrustError(req.folder, `trust hook "${installedHook.name}" failed: ${(e as Error)?.message ?? 'error'}`);
  }
  if (!decision || decision.ok !== true) {
    const d = decision as { code?: TrustErrorCode; reason?: string } | undefined;
    throw new TrustError(req.folder, d?.reason ?? 'rejected by trust hook', d?.code ?? 'untrusted');
  }
  const set: VerifiedRecipientSet = Object.freeze({
    folder: req.folder,
    gpgIdPath: req.gpgIdPath,
    fingerprints: Object.freeze(req.recipients.map((r) => r.fingerprint)),
    keys: Object.freeze(req.recipients.map((r) => r.key)),
    snapshotSha: req.snapshot.commitSha,
    proposed: req.proposed,
    warnings: Object.freeze([...extraWarnings, ...(decision.warnings ?? [])]),
    hook: installedHook.name,
  });
  minted.add(set);
  return set;
}

/** Escrow (org recovery) recipient ids flagged `# g00pass:escrow` in the ROOT `.gpg-id`. */
export async function escrowRecipientIds(snapshot: StoreSnapshot, signal?: AbortSignal): Promise<string[]> {
  const root = await snapshot.readFile(GPG_ID, signal);
  if (!root) return [];
  return parseGpgId(new TextDecoder().decode(root))
    .filter((r) => r.flags.includes(ESCROW_FLAG))
    .map((r) => r.id);
}

async function escrowFingerprints(snapshot: StoreSnapshot, signal?: AbortSignal): Promise<string[]> {
  const ids = await escrowRecipientIds(snapshot, signal);
  const out: string[] = [];
  for (const id of ids) out.push((await resolveRecipient(snapshot, id, { signal })).fingerprint);
  return out;
}

export type VerifyTarget = { entry: string } | { folder: string };

/**
 * Verify the CURRENT recipients that govern an entry (nearest `.gpg-id`
 * walking up from the entry's directory) or a folder (folder itself first).
 * This is the write path for new/edited entries.
 */
export async function verifyRecipients(
  snapshot: StoreSnapshot,
  target: VerifyTarget,
  opts: { signal?: AbortSignal } = {},
): Promise<VerifiedRecipientSet> {
  const has = (p: string) => snapshot.hasFile(p);
  const gpgIdPath = 'entry' in target ? findGpgIdForEntry(has, target.entry) : findGpgIdForFolder(has, target.folder);
  const folder = gpgIdFolder(gpgIdPath);
  const content = await snapshot.readFile(gpgIdPath, opts.signal);
  if (!content) throw new TrustError(folder, `${gpgIdPath} disappeared from snapshot`);
  const sig = await snapshot.readFile(joinPath(folder, GPG_ID_SIG), opts.signal);
  const ids = recipientIds(parseGpgId(new TextDecoder().decode(content)));
  const recipients = await resolveRecipients(snapshot, ids, { signal: opts.signal });

  const warnings: string[] = [];
  const escrow = await escrowFingerprints(snapshot, opts.signal);
  const have = new Set(recipients.map((r) => r.fingerprint));
  if (escrow.some((f) => !have.has(f))) warnings.push('escrow-missing');

  return runHook(
    { folder, gpgIdPath, gpgIdContent: content, gpgIdSignature: sig, proposed: false, recipients, snapshot },
    warnings,
  );
}

export interface ProposedRecipients {
  /** The verified set to encrypt to. */
  verified: VerifiedRecipientSet;
  /** Exact new `.gpg-id` text (escrow lines merged in) to commit. */
  gpgIdText: string;
  gpgIdPath: string;
  /** Signature bytes to commit as `.gpg-id.sig` (null: none; delete any stale one). */
  gpgIdSignature: Uint8Array | null;
}

/**
 * Verify a NEW recipient list for `folder` (approve / remove member /
 * re-encrypt). Escrow recipients from the root `.gpg-id` are always merged in
 * (flagged), so callers cannot accidentally drop the recovery key.
 */
export async function verifyProposedRecipients(
  snapshot: StoreSnapshot,
  folder: string,
  lines: readonly (GpgIdLine | string)[],
  opts: {
    /** Keys being added in the same commit, by fingerprint -> armored. */
    pending?: ReadonlyMap<string, string>;
    /**
     * Detached signature for the new `.gpg-id`, or a signer that receives the
     * exact final gpgIdText (after escrow merge) and returns signature bytes.
     */
    signature?: Uint8Array | null | ((gpgIdText: string) => Promise<Uint8Array>);
    signal?: AbortSignal;
  } = {},
): Promise<ProposedRecipients> {
  const f = normalizePath(folder);
  const gpgIdPath = joinPath(f, GPG_ID);
  const escrowIds = await escrowRecipientIds(snapshot, opts.signal);
  const gpgIdText = serializeGpgId([...lines, ...escrowIds.map((id) => ({ id, flags: [ESCROW_FLAG] }))]);
  const ids = recipientIds(parseGpgId(gpgIdText));
  const recipients = await resolveRecipients(snapshot, ids, { pending: opts.pending, signal: opts.signal });

  const escrow = await escrowFingerprints(snapshot, opts.signal);
  const have = new Set(recipients.map((r) => r.fingerprint));
  if (escrow.some((fp) => !have.has(fp))) throw new TrustError(f, 'escrow recipient missing', 'escrow-missing');

  const signature =
    typeof opts.signature === 'function' ? await opts.signature(gpgIdText) : (opts.signature ?? null);

  const verified = await runHook(
    {
      folder: f,
      gpgIdPath,
      gpgIdContent: new TextEncoder().encode(gpgIdText),
      gpgIdSignature: signature,
      proposed: true,
      recipients,
      snapshot,
    },
    [],
  );
  return { verified, gpgIdText, gpgIdPath, gpgIdSignature: signature };
}
