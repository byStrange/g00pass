import { sha256Digest } from './canonical';
import { G00passError, type TrustErrorCode } from './errors';
import type { GitHubRepo } from './github/client';
import { ESCROW_FLAG, keyIdKind, normalizeKeyId, parseGpgId } from './gpgid';
import { GPG_ID, GPG_ID_SIG } from './paths';
import {
  CHILD_NOTATION,
  FOLDER_NOTATION,
  SignatureFormatError,
  childBoundariesFromNotations,
  folderNotationValue,
  loadKeyByFingerprint,
  parseDetachedSignature,
  verifyDetached,
  type ParsedDetachedSignature,
} from './signatures';
import type { StoreSnapshot } from './store';
import { readMap, storeIdOf, trustEnvironment, updateMap } from './trust-env';
import type { PublicKey } from 'openpgp';

/**
 * PINNED TRUST ANCHORS (store-layout.md §Global admins and trust anchors).
 *
 * The root `.gpg-id` cannot vouch for itself: anyone with repo write could
 * replace it and sign it with their own key. Each device therefore pins, per
 * store, the full fingerprints of the global admins. The root `.gpg-id` is
 * trusted only if it carries a valid, folder-bound `.gpg-id.sig` by a pinned
 * anchor; then its non-escrow fingerprints become the effective (and newly
 * pinned: "rollover") anchor set.
 */

export const ANCHORS_STORAGE_KEY = 'g00pass.trust-anchors.v1';
export const SEEN_STORAGE_KEY = 'g00pass.gpgid-seen.v1';
export const ADMINS_CACHE_STORAGE_KEY = 'g00pass.admins-cache.v1';
/** Device-local high-water set of verified trust boundaries (folders with their own `.gpg-id`). */
export const BOUNDARIES_STORAGE_KEY = 'g00pass.boundaries-seen.v1';

export type AnchorSource = 'first-use' | 'invite' | 'manual' | 'rollover';

export interface PinnedAnchors {
  readonly anchors: readonly string[];
  readonly pinnedAt: string;
  readonly source: AnchorSource;
  /**
   * Rollover only: digest of the root `.gpg-id` + `.sig` that produced this
   * set, and who signed it. That signer stays allowed for exactly that root
   * version (an anchor may sign themselves out), and is still re-verified.
   */
  readonly rootDigest?: string;
  readonly rootSigner?: string;
}

const FPR_RE = /^[0-9A-F]{40}$|^[0-9A-F]{64}$/;
const SOURCES: readonly AnchorSource[] = ['first-use', 'invite', 'manual', 'rollover'];

function isPinned(v: unknown): v is PinnedAnchors {
  const o = v as PinnedAnchors;
  return (
    !!o &&
    Array.isArray(o.anchors) &&
    o.anchors.length > 0 &&
    o.anchors.every((a) => typeof a === 'string' && FPR_RE.test(a)) &&
    typeof o.pinnedAt === 'string' &&
    SOURCES.includes(o.source) &&
    (o.rootDigest === undefined || typeof o.rootDigest === 'string') &&
    (o.rootSigner === undefined || (typeof o.rootSigner === 'string' && FPR_RE.test(o.rootSigner)))
  );
}

type StoreRef = string | Pick<GitHubRepo, 'owner' | 'repo' | 'storeRoot'>;
const idOf = (s: StoreRef) => (typeof s === 'string' ? s : storeIdOf(s));

/** Normalize to sorted, unique, upper-case FULL fingerprints. Throws on anything else (no key ids, no e-mails). */
export function normalizeFingerprints(fprs: readonly string[]): string[] {
  const out = new Set<string>();
  for (const f of fprs) {
    const n = normalizeKeyId(f);
    if (keyIdKind(f) !== 'fingerprint' || !FPR_RE.test(n)) throw new G00passError(`"${f}" is not a full key fingerprint`);
    out.add(n);
  }
  return [...out].sort();
}

const sameSet = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

export function getPinnedAnchors(store: StoreRef): PinnedAnchors | null {
  return readMap(ANCHORS_STORAGE_KEY, isPinned)[idOf(store)] ?? null;
}

/** Drop everything this device derived for a store (seen signatures, admins cache). */
function clearDerivedState(storeId: string, what: { seen: boolean; admins: boolean }): void {
  const prefix = storeId + '|';
  const drop = (m: Record<string, unknown>) => {
    for (const k of Object.keys(m)) if (k.startsWith(prefix)) delete m[k];
  };
  if (what.seen) updateMap(SEEN_STORAGE_KEY, (_v): _v is unknown => true, drop);
  if (what.admins) updateMap(ADMINS_CACHE_STORAGE_KEY, (_v): _v is unknown => true, drop);
  if (what.seen) updateMap(BOUNDARIES_STORAGE_KEY, (_v): _v is unknown => true, drop);
}

/**
 * Pin the global-admin fingerprints for a store on this device. Callers MUST
 * have shown the full fingerprints and obtained explicit user confirmation
 * (first connect: compare out of band; invite: the invite's `anchors`).
 * Replacing a different pinned set clears derived trust state for the store.
 */
export function pinAnchors(store: StoreRef, fingerprints: readonly string[], source: Exclude<AnchorSource, 'rollover'>): PinnedAnchors {
  const anchors = normalizeFingerprints(fingerprints);
  if (anchors.length === 0) throw new G00passError('at least one anchor fingerprint is required');
  const id = idOf(store);
  const prev = getPinnedAnchors(id);
  const rec: PinnedAnchors = { anchors, pinnedAt: new Date(trustEnvironment().now()).toISOString(), source };
  updateMap(ANCHORS_STORAGE_KEY, isPinned, (m) => void (m[id] = rec));
  if (!prev || !sameSet(prev.anchors, anchors)) clearDerivedState(id, { seen: true, admins: true });
  return rec;
}

/** Forget pinned anchors and all derived trust state for a store (settings → reset). */
export function resetAnchors(store: StoreRef): void {
  const id = idOf(store);
  updateMap(ANCHORS_STORAGE_KEY, isPinned, (m) => void delete m[id]);
  clearDerivedState(id, { seen: true, admins: true });
}

// ---- replay high-water mark per folder ----

interface Seen {
  created: number;
  digest: string;
}
const isSeen = (v: unknown): v is Seen =>
  !!v && typeof (v as Seen).created === 'number' && typeof (v as Seen).digest === 'string';

/**
 * Rollback check for a committed `.gpg-id`: true if its signature is OLDER
 * than one this device already accepted for the same folder. (Equal creation
 * times are accepted: two legitimate signatures can share a second.)
 */
export function isReplayed(storeId: string, folder: string, created: Date): boolean {
  const prev = readMap(SEEN_STORAGE_KEY, isSeen)[`${storeId}|${folder}`];
  return !!prev && created.getTime() < prev.created;
}

/** Raise the high-water mark after a committed `.gpg-id` passed ALL checks. */
export function recordSeen(storeId: string, folder: string, created: Date, digest: string): void {
  const key = `${storeId}|${folder}`;
  const t = created.getTime();
  const prev = readMap(SEEN_STORAGE_KEY, isSeen)[key];
  if (!prev || t > prev.created) updateMap(SEEN_STORAGE_KEY, isSeen, (m) => void (m[key] = { created: t, digest }));
}

export async function gpgIdDigest(content: Uint8Array, sig: Uint8Array | null): Promise<string> {
  const buf = new Uint8Array(content.length + 1 + (sig?.length ?? 0));
  buf.set(content, 0);
  buf[content.length] = 0;
  if (sig) buf.set(sig, content.length + 1);
  return sha256Digest(buf);
}

// ---- `.gpg-id` signature check shared by root and folders ----

export type GpgIdSignatureCheck =
  | {
      ok: true;
      signer: string;
      created: Date;
      /** Direct child boundaries declared by the signature (`child@g00pass`), sorted. */
      children: readonly string[];
    }
  | { ok: false; code: TrustErrorCode; reason: string; signer?: string };

/**
 * Verify `sig` over exactly `content` for `folder`: must parse, be bound to
 * `folder` by the folder notation, and be made by one of `allowed` (full
 * primary fingerprints, keys from `.public-keys/<FPR>` in `snapshot`).
 * On failure, tries to name the actual signer for the UI (unknown-signer).
 */
export async function checkGpgIdSignature(
  snapshot: StoreSnapshot,
  folder: string,
  content: Uint8Array,
  sig: Uint8Array | null,
  allowed: ReadonlySet<string>,
  signal?: AbortSignal,
): Promise<GpgIdSignatureCheck> {
  if (!sig) return { ok: false, code: 'signature-missing', reason: `${folderLabel(folder)}.gpg-id is not signed (no .gpg-id.sig)` };
  let parsed: ParsedDetachedSignature;
  try {
    parsed = await parseDetachedSignature(sig);
  } catch (e) {
    return { ok: false, code: 'signature-invalid', reason: e instanceof SignatureFormatError ? e.message : 'unreadable signature' };
  }
  const now = trustEnvironment().now();
  const keys: PublicKey[] = [];
  for (const fpr of [...allowed].sort()) {
    const k = await loadKeyByFingerprint(snapshot, fpr, signal);
    if (k) keys.push(k);
  }
  const res = await verifyDetached(content, parsed, keys, now);
  if (!res.ok) {
    const actual = await identifySigner(snapshot, content, parsed, now, signal);
    if (actual) return { ok: false, code: 'unknown-signer', reason: `signed by ${actual}, who is not authorized for ${folderLabel(folder)}`, signer: actual };
    return { ok: false, code: 'signature-invalid', reason: res.reason };
  }
  const bound = parsed.notations.get(FOLDER_NOTATION) ?? [];
  if (bound.length !== 1 || bound[0] !== folderNotationValue(folder)) {
    return {
      ok: false,
      code: 'signature-invalid',
      reason:
        bound.length === 0
          ? `signature is not bound to a folder (missing ${FOLDER_NOTATION} notation)`
          : `signature was made for folder "${bound.join(', ')}", not "${folderNotationValue(folder)}"`,
      signer: res.signer.fingerprint,
    };
  }
  const children = childBoundariesFromNotations(parsed.notations.get(CHILD_NOTATION) ?? [], folder);
  if (typeof children === 'string') {
    return { ok: false, code: 'signature-invalid', reason: `invalid child boundary declaration: ${children}`, signer: res.signer.fingerprint };
  }
  return { ok: true, signer: res.signer.fingerprint, created: res.signer.created, children };
}

/** Best effort: which store key (if any) produced a valid signature? Only for error messages. */
async function identifySigner(
  snapshot: StoreSnapshot,
  content: Uint8Array,
  parsed: ParsedDetachedSignature,
  now: Date,
  signal?: AbortSignal,
): Promise<string | null> {
  const files = snapshot.listFiles().filter((p) => /^\.public-keys\/[0-9A-F]{40}$|^\.public-keys\/[0-9A-F]{64}$/.test(p)).slice(0, 500);
  for (const p of files) {
    const fpr = p.slice('.public-keys/'.length);
    const k = await loadKeyByFingerprint(snapshot, fpr, signal);
    if (!k || k.getKeys(parsed.packet.issuerKeyID).length === 0) continue;
    const r = await verifyDetached(content, parsed, [k], now);
    if (r.ok) return r.signer.fingerprint;
  }
  return null;
}

export const folderLabel = (f: string) => (f ? `${f}/` : '/');

// ---- root evaluation ----

export interface RootRecipients {
  /** Non-escrow full fingerprints (global admins), sorted. */
  readonly admins: readonly string[];
  /** Escrow full fingerprints, sorted. */
  readonly escrow: readonly string[];
  /** Ids that are not full fingerprints (make the root untrusted). */
  readonly weak: readonly string[];
}

export async function readRootRecipients(snapshot: StoreSnapshot, signal?: AbortSignal): Promise<RootRecipients | null> {
  const bytes = await snapshot.readFile(GPG_ID, signal);
  if (!bytes) return null;
  return rootRecipientsOf(bytes);
}

function rootRecipientsOf(bytes: Uint8Array): RootRecipients {
  const admins = new Set<string>();
  const escrow = new Set<string>();
  const weak: string[] = [];
  for (const r of parseGpgId(new TextDecoder().decode(bytes))) {
    if (keyIdKind(r.id) !== 'fingerprint') {
      weak.push(r.id);
      continue;
    }
    (r.flags.includes(ESCROW_FLAG) ? escrow : admins).add(normalizeKeyId(r.id));
  }
  for (const e of escrow) admins.delete(e);
  return { admins: [...admins].sort(), escrow: [...escrow].sort(), weak };
}

export type RootTrust =
  | {
      readonly ok: true;
      /** Effective anchors = non-escrow fingerprints of the verified root `.gpg-id`. */
      readonly anchors: readonly string[];
      readonly escrow: readonly string[];
      readonly signer: string;
      /** Direct child boundaries declared by the root `.gpg-id.sig`. */
      readonly children: readonly string[];
      /** True when this evaluation re-pinned the anchors (validly signed change). */
      readonly rolledOver: boolean;
      readonly root: RootRecipients;
    }
  | {
      readonly ok: false;
      readonly code: TrustErrorCode;
      readonly reason: string;
      readonly root: RootRecipients | null;
      readonly pinned: readonly string[] | null;
      /** Root admins not pinned / pinned anchors missing from the root (UI diff). */
      readonly added: readonly string[];
      readonly removed: readonly string[];
    };

/**
 * Is the root `.gpg-id` of `snapshot` trusted by this device?
 * Side effect (only after a successful check against the CURRENTLY pinned
 * anchors): if the root's admin set differs from the pinned set, the pinned
 * set is replaced by it (rollover), and derived admins state is cleared.
 */
export async function evaluateRootTrust(snapshot: StoreSnapshot, signal?: AbortSignal): Promise<RootTrust> {
  const env = trustEnvironment();
  const storeId = env.storeId(snapshot);
  const bytes = await snapshot.readFile(GPG_ID, signal);
  const root = bytes ? rootRecipientsOf(bytes) : null;
  const pinnedRec = storeId ? getPinnedAnchors(storeId) : null;
  const pinned = pinnedRec?.anchors ?? null;
  const fail = (code: TrustErrorCode, reason: string): RootTrust => ({
    ok: false,
    code,
    reason,
    root,
    pinned,
    added: root && pinned ? root.admins.filter((a) => !pinned.includes(a)) : [],
    removed: root && pinned ? pinned.filter((a) => !root.admins.includes(a)) : [],
  });
  if (!storeId) return fail('untrusted', 'store identity unknown; nothing is trusted');
  if (!bytes || !root) return fail('untrusted', 'store has no root .gpg-id');
  if (!pinnedRec || !pinned) return fail('untrusted', 'no trust anchors pinned on this device for this store');
  if (root.weak.length) return fail('weak-recipient', `root .gpg-id contains ids that are not full fingerprints: ${root.weak.join(', ')}`);
  if (root.admins.length === 0) return fail('untrusted', 'root .gpg-id lists no global admins');

  const sig = await snapshot.readFile(GPG_ID_SIG, signal);
  const digest = await gpgIdDigest(bytes, sig);
  const allowed = new Set(pinned);
  if (pinnedRec.rootDigest === digest && pinnedRec.rootSigner) allowed.add(pinnedRec.rootSigner);
  for (const e of root.escrow) allowed.delete(e);
  const chk = await checkGpgIdSignature(snapshot, '', bytes, sig, allowed, signal);
  if (!chk.ok) {
    const changed = !sameSet(root.admins, pinned);
    return fail(
      changed ? 'anchor-mismatch' : chk.code,
      changed
        ? `root .gpg-id differs from the pinned trust anchors and is not validly signed by a pinned anchor (${chk.reason})`
        : chk.reason,
    );
  }
  if (isReplayed(storeId, '', chk.created)) {
    return fail('replayed', 'root .gpg-id signature is older than one this device already accepted (rollback)');
  }
  recordSeen(storeId, '', chk.created, digest);
  let rolledOver = false;
  if (!sameSet(root.admins, pinned)) {
    const rec: PinnedAnchors = {
      anchors: [...root.admins],
      pinnedAt: env.now().toISOString(),
      source: 'rollover',
      rootDigest: digest,
      rootSigner: chk.signer,
    };
    updateMap(ANCHORS_STORAGE_KEY, isPinned, (m) => void (m[storeId] = rec));
    clearDerivedState(storeId, { seen: false, admins: true });
    rolledOver = true;
  }
  return { ok: true, anchors: root.admins, escrow: root.escrow, signer: chk.signer, children: chk.children, rolledOver, root };
}
