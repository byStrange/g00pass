import { checkGpgIdSignature, evaluateRootTrust, folderLabel, gpgIdDigest, isReplayed, recordSeen } from './anchors';
import { allowedSigners, boundaryChain, expectedChildBoundaries, recordBoundaries, vanishedBoundaryFor, vanishedChildren } from './boundaries';
import { G00passError, RecipientKeyError, TrustError, type TrustErrorCode } from './errors';
import { keyIdKind, normalizeKeyId } from './gpgid';
import { GPG_ID, GPG_ID_SIG, dirname, joinPath } from './paths';
import type { StoreSnapshot } from './store';
import { type RecipientVerificationRequest, type TrustDecision, type TrustHook, verifyRecipients } from './trust';
import { trustEnvironment } from './trust-env';

/**
 * The production TrustHook (docs/specs/gpg-id-signatures.md). Installed in
 * src/main.ts. Every decision is computed from `req.snapshot` only (the same
 * snapshot the caller encrypts from and commits on), plus device-local state
 * (pinned anchors, replay high-water marks, admins cache).
 *
 * For folder F with `.gpg-id` bytes C and signature S (current or proposed):
 *  1. the root `.gpg-id` of the snapshot is trusted (signed by a pinned
 *     anchor; evaluateRootTrust). Escrow comes from that root, so nothing
 *     is encrypted while the root is untrusted;
 *  2. S verifies over exactly C, is bound to F (folder notation), and its
 *     signer is in allowed(F) = anchors (F = root) or
 *     anchors ∪ verified admins of F and its ancestors (F ≠ root);
 *     escrow keys are never signers;
 *  3. (committed sets only) S is not older than one this device accepted
 *     for F (rollback);
 *  4. every recipient id is a full PRIMARY fingerprint and resolved to the
 *     key with exactly that fingerprint (resolveRecipients already required
 *     a valid, unexpired encryption subkey);
 *  5. every escrow fingerprint of the root is a recipient;
 *  6. trust boundaries: F is declared (child@g00pass) by its parent
 *     boundary's verified signature up to the root; committed sets refuse a
 *     write into a declared or device-known child boundary whose `.gpg-id`
 *     vanished; a proposed signature declares exactly the expected children
 *     (src/core/boundaries.ts).
 *
 * Proposed sets (approve / remove / re-encrypt): authorization is evaluated
 * against the CURRENT snapshot (who is an admin now), never against files
 * the same commit would add, and S must be produced by such an admin over
 * the exact final text (signGpgId via reencryptFolder's gpgIdSignature).
 */
export const SIGNATURE_TRUST_HOOK_NAME = 'gpg-id signatures v1';

function sameBytes(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (!a || !b) return false;
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

const deny = (code: TrustErrorCode, reason: string): TrustDecision => ({ ok: false, code, reason });
const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

async function decide(req: RecipientVerificationRequest): Promise<TrustDecision> {
  const { snapshot, folder } = req;
  const storeId = trustEnvironment().storeId(snapshot);
  if (!storeId) return deny('untrusted', 'store identity unknown; nothing is trusted');

  const root = await evaluateRootTrust(snapshot);
  if (!root.ok) return deny(root.code, folder === '' ? root.reason : `root .gpg-id: ${root.reason}`);

  const { allowed, warnings } = await allowedSigners(snapshot, folder, root);

  // The committed root was just verified by evaluateRootTrust (which also
  // honours the signer of a rollover); only reuse that for the exact bytes.
  let seen: Date | null = null;
  let children: readonly string[];
  const isCommittedRoot =
    folder === '' &&
    !req.proposed &&
    sameBytes(req.gpgIdContent, await snapshot.readFile(GPG_ID)) &&
    sameBytes(req.gpgIdSignature, await snapshot.readFile(GPG_ID_SIG));
  if (isCommittedRoot) {
    children = root.children;
  } else {
    const chk = await checkGpgIdSignature(snapshot, folder, req.gpgIdContent, req.gpgIdSignature, allowed);
    if (!chk.ok) return deny(chk.code, chk.reason);
    if (!req.proposed && isReplayed(storeId, folder, chk.created)) {
      return deny('replayed', `${folderLabel(folder)}.gpg-id signature is older than one this device already accepted (rollback)`);
    }
    seen = chk.created;
    children = chk.children;
  }

  // Trust boundaries (gpg-id-signatures.md §Child boundaries).
  const chain = await boundaryChain(snapshot, folder);
  if (!chain.ok) return deny(chain.code, chain.reason);
  if (req.proposed) {
    const exp = await expectedChildBoundaries(snapshot, folder);
    if (!exp.ok) return deny(exp.code, exp.reason);
    if (!sameList(children, exp.children) || (req.childBoundaries && !sameList(req.childBoundaries, exp.children))) {
      const list = (l: readonly string[]) => (l.length ? l.map((c) => '/' + c).join(', ') : 'none');
      return deny(
        'boundary-undeclared',
        `the new ${folderLabel(folder)}.gpg-id.sig must declare exactly the child boundaries [${list(exp.children)}] (child@g00pass), but declares [${list(children)}]`,
      );
    }
  } else {
    const gone = vanishedBoundaryFor(snapshot, storeId, req.target, folder, children);
    if (gone) return deny(gone.code, gone.reason);
    for (const d of vanishedChildren(snapshot, storeId, folder, children)) warnings.push(`boundary-vanished:${d}`);
  }

  const fprs = new Set<string>();
  for (const r of req.recipients) {
    if (keyIdKind(r.id) !== 'fingerprint' || normalizeKeyId(r.id) !== r.fingerprint) {
      return deny('weak-recipient', `recipient "${r.id}" is not the full primary fingerprint of its key (${r.fingerprint})`);
    }
    fprs.add(r.fingerprint);
  }
  // Escrow is checked LAST on purpose: 'escrow-missing' therefore implies that
  // everything else (signature, authorization, boundaries, ids) passed, which
  // is what lets an admin repair a folder by re-encrypting (recipients.ts).
  const missing = root.escrow.filter((e) => !fprs.has(e));
  if (missing.length) return deny('escrow-missing', `escrow recipient ${missing.join(', ')} missing from ${folderLabel(folder)}.gpg-id`);

  if (!req.proposed) {
    if (seen) recordSeen(storeId, folder, seen, await gpgIdDigest(req.gpgIdContent, req.gpgIdSignature));
    // Parents whose signatures vouched for this boundary: raise their replay marks too.
    for (const p of chain.seen) {
      const c = await snapshot.readFile(joinPath(p.folder, GPG_ID));
      if (c) recordSeen(storeId, p.folder, p.created, await gpgIdDigest(c, await snapshot.readFile(joinPath(p.folder, GPG_ID_SIG))));
    }
    recordBoundaries(storeId, [folder, ...chain.parents]);
  }
  return { ok: true, warnings };
}

export const signatureTrustHook: TrustHook = Object.freeze({
  name: SIGNATURE_TRUST_HOOK_NAME,
  verify: decide,
  childBoundaries: (snapshot: StoreSnapshot, folder: string, signal?: AbortSignal) => expectedChildBoundaries(snapshot, folder, signal),
});

export interface FolderTrustStatus {
  /** Folder that owns the `.gpg-id` ("" = root). */
  readonly folder: string;
  readonly verified: boolean;
  readonly code?: TrustErrorCode | 'recipient-key' | 'error';
  readonly reason?: string;
  readonly warnings: readonly string[];
}

/**
 * Would writing in `folder` be allowed right now? Runs the real choke-point
 * (verifyRecipients) against `snapshot`, so the UI status is exactly the
 * write-path decision. Never throws.
 */
export async function folderTrustStatus(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal): Promise<FolderTrustStatus> {
  try {
    const v = await verifyRecipients(snapshot, { folder }, { signal });
    return { folder: v.folder, verified: true, warnings: v.warnings };
  } catch (e) {
    if (e instanceof TrustError) return { folder: e.folder, verified: false, code: e.code, reason: e.reason, warnings: [] };
    if (e instanceof RecipientKeyError) return { folder, verified: false, code: 'recipient-key', reason: e.message, warnings: [] };
    return { folder, verified: false, code: 'error', reason: e instanceof G00passError ? e.message : 'verification failed', warnings: [] };
  }
}

/** Status for every folder that has its own `.gpg-id`, root first. */
export async function allFolderTrustStatus(snapshot: StoreSnapshot, signal?: AbortSignal): Promise<FolderTrustStatus[]> {
  const folders = snapshot
    .listFiles()
    .filter((p) => p === GPG_ID || p.endsWith('/' + GPG_ID))
    .map(dirname)
    .sort();
  const out: FolderTrustStatus[] = [];
  for (const f of folders) out.push(await folderTrustStatus(snapshot, f, signal));
  return out;
}
