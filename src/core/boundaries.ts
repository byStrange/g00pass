import { verifiedFolderAdmins } from './admins';
import { BOUNDARIES_STORAGE_KEY, type RootTrust, checkGpgIdSignature, evaluateRootTrust, folderLabel, isReplayed } from './anchors';
import type { TrustErrorCode } from './errors';
import { GPG_ID, GPG_ID_SIG, dirname, isWithin, joinPath, normalizePath } from './paths';
import { type StoreSnapshot, directNestedGpgIdFolders } from './store';
import { readMap, trustEnvironment, updateMap } from './trust-env';

/**
 * TRUST BOUNDARIES (docs/specs/gpg-id-signatures.md §Child boundaries).
 *
 * A folder with its own `.gpg-id` is a trust boundary: entries below it are
 * encrypted to ITS recipients, not the parent's. pass/gopass find the
 * governing `.gpg-id` by file presence (nearest wins), so deleting a nested
 * `.gpg-id` silently hands its entries to the parent's (usually wider)
 * recipient list. g00pass therefore makes the boundary set part of the signed
 * state: every `.gpg-id.sig` declares its DIRECT child boundaries with one
 * hashed `child@g00pass=/<child>` notation each, and:
 *
 *  - a boundary is only trusted if its nearest parent boundary's verified
 *    signature declares it, all the way up to the root ("boundary chain");
 *  - a write whose target lies inside a declared (or, on this device, ever
 *    verified) boundary whose `.gpg-id` is gone is refused ("vanished");
 *  - a re-signature of F must declare exactly the expected children: the
 *    currently declared ones (all still present), plus nested `.gpg-id`s that
 *    are themselves validly signed (catch-up after a gpg bootstrap).
 *
 * Device-local defense in depth: every boundary this device verified is kept
 * in `g00pass.boundaries-seen.v1` and must keep existing.
 */

type Deny = { ok: false; code: TrustErrorCode; reason: string };
const deny = (code: TrustErrorCode, reason: string): Deny => ({ ok: false, code, reason });
type TrustedRoot = Extract<RootTrust, { ok: true }>;

// ---- device-local high-water set ----

interface KnownBoundary {
  since: number;
}
const isKnown = (v: unknown): v is KnownBoundary => !!v && typeof (v as KnownBoundary).since === 'number';

/** Boundaries this device has verified for `storeId` (store-relative folders, sorted). */
export function knownBoundaries(storeId: string): string[] {
  const prefix = storeId + '|';
  return Object.keys(readMap(BOUNDARIES_STORAGE_KEY, isKnown))
    .filter((k) => k.startsWith(prefix))
    .map((k) => k.slice(prefix.length))
    .sort();
}

/** Remember verified boundaries (never shrinks; reset with the pinned anchors). */
export function recordBoundaries(storeId: string, folders: readonly string[]): void {
  const fresh = folders.filter((f) => f !== '' && !knownBoundaries(storeId).includes(f));
  if (!fresh.length) return;
  const now = trustEnvironment().now().getTime();
  updateMap(BOUNDARIES_STORAGE_KEY, isKnown, (m) => {
    for (const f of fresh) m[`${storeId}|${f}`] = { since: now };
  });
}

const hasGpgId = (s: StoreSnapshot, f: string) => s.hasFile(joinPath(f, GPG_ID));

/** Nearest strict ancestor of `folder` that has its own `.gpg-id` (root if none). */
function parentBoundary(snapshot: StoreSnapshot, folder: string): string {
  let cur = folder;
  while (cur !== '') {
    cur = dirname(cur);
    if (cur === '' || hasGpgId(snapshot, cur)) return cur;
  }
  return '';
}

// ---- who may sign F/.gpg-id ----

/** allowed(F) = anchors (root) or anchors ∪ verified admins of F and its ancestors; never escrow. */
export async function allowedSigners(
  snapshot: StoreSnapshot,
  folder: string,
  root: TrustedRoot,
  signal?: AbortSignal,
): Promise<{ allowed: Set<string>; warnings: string[] }> {
  let allowed: Set<string>;
  let warnings: string[] = [];
  if (folder === '') {
    allowed = new Set(root.anchors);
  } else {
    const fa = await verifiedFolderAdmins(snapshot, folder, signal);
    allowed = new Set([...root.anchors, ...fa.admins]);
    warnings = fa.files.filter((f) => f.status === 'invalid').map((f) => `admins-file-unverified:${f.folder}`);
  }
  for (const e of root.escrow) allowed.delete(e);
  return { allowed, warnings };
}

// ---- declared children of a COMMITTED .gpg-id ----

export type DeclaredChildren = { ok: true; children: readonly string[]; created: Date | null } | Deny;

const memo = new WeakMap<StoreSnapshot, Map<string, Promise<DeclaredChildren>>>();

/**
 * Child boundaries declared by the committed `F/.gpg-id.sig` in `snapshot`,
 * if that signature is valid, authorized for F, folder-bound and not older
 * than one this device accepted. (Only the signature counts here: escrow or
 * weak ids do not make the declarations less authentic.)
 */
export async function declaredChildren(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal): Promise<DeclaredChildren> {
  const f = normalizePath(folder);
  const env = trustEnvironment();
  const storeId = env.storeId(snapshot);
  if (!storeId) return deny('untrusted', 'store identity unknown; nothing is trusted');
  const root = await evaluateRootTrust(snapshot, signal);
  if (!root.ok) return deny(root.code, `root .gpg-id: ${root.reason}`);
  if (f === '') return { ok: true, children: root.children, created: null };
  const key = `${storeId}#${snapshot.commitSha}#${f}#${root.anchors.join(',')}#${root.escrow.join(',')}`;
  let m = memo.get(snapshot);
  if (!m) memo.set(snapshot, (m = new Map()));
  let p = m.get(key);
  if (!p) {
    p = (async (): Promise<DeclaredChildren> => {
      const content = await snapshot.readFile(joinPath(f, GPG_ID), signal);
      if (!content) return deny('boundary-vanished', `${folderLabel(f)}.gpg-id does not exist`);
      const sig = await snapshot.readFile(joinPath(f, GPG_ID_SIG), signal);
      const { allowed } = await allowedSigners(snapshot, f, root, signal);
      const chk = await checkGpgIdSignature(snapshot, f, content, sig, allowed, signal);
      if (!chk.ok) return deny(chk.code, chk.reason);
      if (isReplayed(storeId, f, chk.created)) {
        return deny('replayed', `${folderLabel(f)}.gpg-id signature is older than one this device already accepted (rollback)`);
      }
      return { ok: true, children: chk.children, created: chk.created };
    })();
    m.set(key, p);
  }
  return p;
}

// ---- boundary chain: is `folder` an authorized boundary? ----

export type BoundaryChain = { ok: true; parents: readonly string[]; seen: readonly { folder: string; created: Date }[] } | Deny;

/**
 * `folder` (which has its own `.gpg-id`, or is about to get one) must be
 * declared by the verified signature of its nearest parent boundary, and that
 * parent by its own, up to the root. Returns the verified parent boundaries.
 */
export async function boundaryChain(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal): Promise<BoundaryChain> {
  const parents: string[] = [];
  const seen: { folder: string; created: Date }[] = [];
  let cur = normalizePath(folder);
  while (cur !== '') {
    const p = parentBoundary(snapshot, cur);
    const dc = await declaredChildren(snapshot, p, signal);
    if (!dc.ok) {
      return deny(dc.code, `cannot verify that ${folderLabel(cur)} is a declared boundary: ${folderLabel(p)}.gpg-id: ${dc.reason}`);
    }
    if (!dc.children.includes(cur)) {
      const gone = dc.children.find((d) => isWithin(cur, d));
      if (gone !== undefined) {
        return deny('boundary-vanished', `${folderLabel(gone)}.gpg-id was deleted, but ${folderLabel(p)}.gpg-id.sig still declares it as a boundary`);
      }
      return deny(
        'boundary-undeclared',
        `${folderLabel(cur)} has its own .gpg-id, but ${folderLabel(p)}.gpg-id.sig does not declare it (child@g00pass=/${cur}); an admin of ${folderLabel(p)} must re-sign`,
      );
    }
    parents.push(p);
    if (dc.created) seen.push({ folder: p, created: dc.created });
    cur = p;
  }
  return { ok: true, parents, seen };
}

/**
 * For a write whose target folder is `target`, governed (by file presence)
 * by `governing` whose verified signature declares `children`: refuse if the
 * target lies in a declared or device-known boundary whose `.gpg-id` is gone.
 * Returns null when fine.
 */
export function vanishedBoundaryFor(
  snapshot: StoreSnapshot,
  storeId: string,
  target: string,
  governing: string,
  children: readonly string[],
): Deny | null {
  for (const d of children) {
    if (isWithin(target, d) && !hasGpgId(snapshot, d)) {
      return deny('boundary-vanished', `${folderLabel(d)}.gpg-id was deleted, but ${folderLabel(governing)}.gpg-id.sig declares it as a boundary; writing here would encrypt to the wrong recipients`);
    }
  }
  for (const b of knownBoundaries(storeId)) {
    if (isWithin(target, b) && !hasGpgId(snapshot, b)) {
      return deny('boundary-vanished', `${folderLabel(b)}.gpg-id was deleted (this device verified it before); writing here would encrypt to ${folderLabel(governing)} instead`);
    }
  }
  return null;
}

/** Declared children of `governing` (or device-known boundaries below it) whose `.gpg-id` is gone. */
export function vanishedChildren(snapshot: StoreSnapshot, storeId: string, governing: string, children: readonly string[]): string[] {
  const known = knownBoundaries(storeId).filter((b) => b !== governing && isWithin(b, governing));
  return [...new Set([...children, ...known])].filter((d) => !hasGpgId(snapshot, d)).sort();
}

// ---- what a NEW signature of F must declare ----

export type ExpectedChildren = { ok: true; children: readonly string[] } | Deny;

/**
 * The child boundaries a re-signed `F/.gpg-id` must declare (approve, remove,
 * re-encrypt), computed from the CURRENT snapshot and device state:
 *  - every currently declared child (if F's committed signature verifies)
 *    and every device-known boundary below F must still exist;
 *  - a declared child must still be a DIRECT child (no new boundary between);
 *  - an undeclared nested `.gpg-id` is only adopted if its own signature
 *    verifies for its folder (otherwise: delete it or have an admin sign it);
 *  - a NEW boundary F (no `.gpg-id` yet) may not be created above existing
 *    nested boundaries.
 * Result: exactly the direct nested boundaries present in the snapshot.
 */
export async function expectedChildBoundaries(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal): Promise<ExpectedChildren> {
  const f = normalizePath(folder);
  const storeId = trustEnvironment().storeId(snapshot);
  if (!storeId) return deny('untrusted', 'store identity unknown; nothing is trusted');
  const present = directNestedGpgIdFolders(snapshot, f);
  const exists = f === '' || hasGpgId(snapshot, f);
  if (!exists && present.length) {
    return deny('boundary-undeclared', `cannot create a new boundary at ${folderLabel(f)} above existing boundaries (${present.map(folderLabel).join(', ')})`);
  }
  let declared: readonly string[] = [];
  if (exists) {
    const dc = await declaredChildren(snapshot, f, signal);
    if (dc.ok) declared = dc.children;
    else if (f === '') return dc;
  }
  const gone = vanishedChildren(snapshot, storeId, f, declared);
  if (gone.length) {
    return deny(
      'boundary-vanished',
      `${gone.map((g) => `${folderLabel(g)}.gpg-id`).join(', ')} ${gone.length === 1 ? 'was' : 'were'} deleted but ${gone.length === 1 ? 'is' : 'are'} still a declared or known boundary; restore ${gone.length === 1 ? 'it' : 'them'} before re-signing ${folderLabel(f)} (re-encrypting would hand those entries to the wrong recipients)`,
    );
  }
  for (const d of declared) {
    if (!present.includes(d)) {
      return deny('boundary-undeclared', `declared boundary ${folderLabel(d)} is no longer a direct child of ${folderLabel(f)}; re-sign the boundaries in between manually`);
    }
  }
  for (const p of present) {
    if (declared.includes(p)) continue;
    const own = await declaredChildren(snapshot, p, signal);
    if (!own.ok) {
      return deny(
        'boundary-undeclared',
        `${folderLabel(p)}.gpg-id is not declared by ${folderLabel(f)} and is not validly signed (${own.reason}); delete it or have an admin sign it first`,
      );
    }
  }
  return { ok: true, children: present };
}
