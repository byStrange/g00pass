import type { PrivateKey } from 'openpgp';
import { ADMINS_CACHE_STORAGE_KEY, evaluateRootTrust, normalizeFingerprints } from './anchors';
import { RFC3339_RE, canonicalJson, parseCanonicalJson, rfc3339, sha256Digest } from './canonical';
import { G00passError } from './errors';
import { keyIdKind, normalizeKeyId } from './gpgid';
import { GPG_ID, ancestorsInclusive, dirname, joinPath, normalizePath } from './paths';
import { loadKeyByFingerprint, parseDetachedSignature, signDetached, verifyDetached } from './signatures';
import type { FileChange, StoreSnapshot } from './store';
import { readMap, trustEnvironment, updateMap } from './trust-env';
import { fingerprintOf } from './keys';

/**
 * FOLDER ADMINS (docs/specs/folder-admins.md).
 *
 * `<F>/.g00pass-admins.json` (canonical JSON) + `.sig` (detached, over the
 * exact bytes). A version V(n) is valid when its signature by `updatedBy`
 * verifies and `updatedBy` is authorized:
 *   - a trust anchor (effective anchors of a verified root), or
 *   - a verified admin of a STRICT ancestor folder (delegation/hierarchy), or
 *   - (serial > 1) listed in V(n-1).admins, where V(n-1) is valid, has
 *     serial n-1, its bytes digest equals `previous`, AND it is the actual
 *     predecessor of V(n) in the git history reachable from the snapshot
 *     (chain of custody; ends at a self-authorized or cached version).
 * Removal is final: a version is invalid when reachable history holds a
 * genuine version with the same serial and other bytes (fork) or a higher
 * serial (rollback), or when anything at or below the cached serial is not
 * the cached version. The cache is written only after full validation.
 * Admin authority is hierarchical: admins(F) = union of the valid admins
 * files of F and its ancestors (the root has none; anchors cover it).
 * Invalid / unverifiable files grant nothing and never block reads.
 */

export const ADMINS_FILE = '.g00pass-admins.json';
export const ADMINS_SIG = '.g00pass-admins.json.sig';
export const ADMINS_TYPE = 'g00pass.folder-admins';
export const MAX_CHAIN_VERSIONS = 20;

export interface FolderAdminsDocument {
  admins: string[];
  folder: string;
  previous: string | null;
  serial: number;
  type: typeof ADMINS_TYPE;
  updatedAt: string;
  updatedBy: string;
  version: 1;
}

export type AdminsFileStatus =
  | { status: 'absent'; folder: string }
  | { status: 'valid'; folder: string; admins: readonly string[]; serial: number; digest: string; signer: string; via: 'anchor' | 'ancestor-admin' | 'chain' | 'cache' }
  | { status: 'invalid'; folder: string; reason: string };

const FPR_RE = /^[0-9A-F]{40}$|^[0-9A-F]{64}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/** Parse + validate the document (canonical bytes, schema, folder). Throws G00passError(reason). */
export function parseAdminsDocument(bytes: Uint8Array, folder: string): FolderAdminsDocument {
  let v: unknown;
  try {
    v = parseCanonicalJson(bytes);
  } catch {
    throw new G00passError('admins file is not canonical JSON');
  }
  const d = v as Partial<FolderAdminsDocument> & Record<string, unknown>;
  const keys = Object.keys(d ?? {}).sort().join(',');
  if (keys !== 'admins,folder,previous,serial,type,updatedAt,updatedBy,version') throw new G00passError('admins file has unexpected fields');
  if (d.type !== ADMINS_TYPE || d.version !== 1) throw new G00passError('unknown admins file type/version');
  if (d.folder !== normalizePath(folder) || d.folder === '') throw new G00passError(`admins file is for folder "${String(d.folder)}", not "${folder}"`);
  if (!Array.isArray(d.admins) || d.admins.length === 0) throw new G00passError('admins list is empty');
  if (!d.admins.every((a) => typeof a === 'string' && FPR_RE.test(a))) throw new G00passError('admins must be upper-case full fingerprints');
  const sorted = [...new Set(d.admins)].sort();
  if (sorted.join() !== d.admins.join()) throw new G00passError('admins must be sorted and unique');
  if (typeof d.serial !== 'number' || !Number.isSafeInteger(d.serial) || d.serial < 1) throw new G00passError('invalid serial');
  if (d.serial === 1 ? d.previous !== null : typeof d.previous !== 'string' || !DIGEST_RE.test(d.previous)) {
    throw new G00passError('previous must be null for serial 1 and a sha256 digest otherwise');
  }
  if (typeof d.updatedBy !== 'string' || !FPR_RE.test(d.updatedBy)) throw new G00passError('invalid updatedBy');
  if (typeof d.updatedAt !== 'string' || !RFC3339_RE.test(d.updatedAt)) throw new G00passError('invalid updatedAt');
  return d as FolderAdminsDocument;
}

interface CacheEntry {
  digest: string;
  serial: number;
  admins: string[];
}
const isCacheEntry = (v: unknown): v is CacheEntry =>
  !!v &&
  typeof (v as CacheEntry).digest === 'string' &&
  Number.isSafeInteger((v as CacheEntry).serial) &&
  Array.isArray((v as CacheEntry).admins) &&
  (v as CacheEntry).admins.every((a) => typeof a === 'string' && FPR_RE.test(a));

interface Ctx {
  snapshot: StoreSnapshot;
  storeId: string;
  anchors: ReadonlySet<string>;
  escrow: ReadonlySet<string>;
  now: Date;
  signal?: AbortSignal;
  memo: Map<string, Promise<AdminsFileStatus>>;
}

const memos = new WeakMap<StoreSnapshot, Map<string, Map<string, Promise<AdminsFileStatus>>>>();

async function makeCtx(snapshot: StoreSnapshot, signal?: AbortSignal): Promise<Ctx | { error: string }> {
  const env = trustEnvironment();
  const storeId = env.storeId(snapshot);
  if (!storeId) return { error: 'store identity unknown' };
  const root = await evaluateRootTrust(snapshot, signal);
  if (!root.ok) return { error: `root not trusted: ${root.reason}` };
  const memoKey = `${storeId}#${snapshot.commitSha}#${root.anchors.join(',')}#${root.escrow.join(',')}`;
  let bySnap = memos.get(snapshot);
  if (!bySnap) memos.set(snapshot, (bySnap = new Map()));
  let memo = bySnap.get(memoKey);
  if (!memo) bySnap.set(memoKey, (memo = new Map()));
  return { snapshot, storeId, anchors: new Set(root.anchors), escrow: new Set(root.escrow), now: env.now(), signal, memo };
}

interface Version {
  doc: FolderAdminsDocument;
  digest: string;
}

/** Signature + schema check of one version (no authorization). */
async function checkVersion(ctx: Ctx, folder: string, bytes: Uint8Array, sig: Uint8Array | null): Promise<Version | string> {
  let doc: FolderAdminsDocument;
  try {
    doc = parseAdminsDocument(bytes, folder);
  } catch (e) {
    return (e as Error).message;
  }
  if (!sig) return 'admins file signature missing';
  if (ctx.escrow.has(doc.updatedBy)) return 'escrow key may not sign admins files';
  const key = await loadKeyByFingerprint(ctx.snapshot, doc.updatedBy, ctx.signal);
  if (!key) return `no public key for updatedBy ${doc.updatedBy} in .public-keys`;
  let res;
  try {
    res = await verifyDetached(bytes, await parseDetachedSignature(sig), [key], ctx.now);
  } catch (e) {
    return (e as Error).message;
  }
  if (!res.ok) return `admins file signature by updatedBy does not verify (${res.reason})`;
  return { doc, digest: await sha256Digest(bytes) };
}

/** Verified admins of the STRICT ancestors of `folder` (excluding the root). */
async function ancestorAdmins(ctx: Ctx, folder: string): Promise<Set<string>> {
  const out = new Set<string>();
  for (const g of ancestorsInclusive(dirname(folder))) {
    if (g === '') break;
    const st = await verifyAt(ctx, g);
    if (st.status === 'valid') st.admins.forEach((a) => out.add(a));
  }
  return out;
}

function verifyAt(ctx: Ctx, folder: string): Promise<AdminsFileStatus> {
  let p = ctx.memo.get(folder);
  if (!p) {
    p = verifyAdminsFileUncached(ctx, folder);
    ctx.memo.set(folder, p);
  }
  return p;
}

async function verifyAdminsFileUncached(ctx: Ctx, folder: string): Promise<AdminsFileStatus> {
  const path = joinPath(folder, ADMINS_FILE);
  const bytes = await ctx.snapshot.readFile(path, ctx.signal);
  if (!bytes) return { status: 'absent', folder };
  const invalid = (reason: string): AdminsFileStatus => ({ status: 'invalid', folder, reason });
  if (!ctx.snapshot.hasFile(joinPath(folder, GPG_ID))) return invalid('admins file in a folder without its own .gpg-id');
  const cur = await checkVersion(ctx, folder, bytes, await ctx.snapshot.readFile(joinPath(folder, ADMINS_SIG), ctx.signal));
  if (typeof cur === 'string') return invalid(cur);

  const cacheKey = `${ctx.storeId}|${folder}`;
  const cached = readMap(ADMINS_CACHE_STORAGE_KEY, isCacheEntry)[cacheKey];
  if (cached && cached.serial > cur.doc.serial) {
    return invalid(`rolled back: this device already verified serial ${cached.serial}, file has serial ${cur.doc.serial}`);
  }
  if (cached && cached.serial === cur.doc.serial && cached.digest !== cur.digest) {
    return invalid(`conflicting version: serial ${cur.doc.serial} differs from the one this device verified (fork)`);
  }

  // Cache ONLY after full validation, and only ever forwards: a version that
  // conflicts with the cache never validates (above / in the walk below), so
  // it can never overwrite it.
  const ok = (via: 'anchor' | 'ancestor-admin' | 'chain' | 'cache'): AdminsFileStatus => {
    if (!cached || cached.serial < cur.doc.serial) {
      updateMap(ADMINS_CACHE_STORAGE_KEY, isCacheEntry, (m) => {
        m[cacheKey] = { digest: cur.digest, serial: cur.doc.serial, admins: [...cur.doc.admins] };
      });
    }
    return { status: 'valid', folder, admins: cur.doc.admins.filter((a) => !ctx.escrow.has(a)), serial: cur.doc.serial, digest: cur.digest, signer: cur.doc.updatedBy, via };
  };

  const up = await ancestorAdmins(ctx, folder);
  const selfAuthorized = (v: Version) => ctx.anchors.has(v.doc.updatedBy) || up.has(v.doc.updatedBy);
  const headVia = ctx.anchors.has(cur.doc.updatedBy) ? 'anchor' : up.has(cur.doc.updatedBy) ? 'ancestor-admin' : null;
  // Exactly this version was fully validated on this device before.
  if (cached && cached.serial === cur.doc.serial) return ok(headVia ?? 'cache');

  if (!headVia && cur.doc.serial === 1) {
    return invalid(`serial 1 signed by ${cur.doc.updatedBy}, who is neither a trust anchor nor an admin of a parent folder`);
  }
  const hist = trustEnvironment().history(ctx.snapshot);
  if (!hist) {
    // Without history neither the chain nor a rollback to an older,
    // self-authorized version can be checked (documented residual risk).
    return headVia ? ok(headVia) : invalid('chain of custody cannot be verified (no history available)');
  }

  // History reachable from the snapshot commit, newest first, consecutive
  // identical contents collapsed. null = the file was absent (deleted).
  type Hist = { digest: string; v: Version | string } | null;
  const window: Hist[] = [];
  let lastDigest: string | null | undefined;
  for await (const n of hist.versions(path, [joinPath(folder, ADMINS_SIG)], { limit: MAX_CHAIN_VERSIONS + 1, signal: ctx.signal })) {
    const [b, sg] = n.files;
    const digest = b ? await sha256Digest(b) : null;
    if (digest === lastDigest) continue;
    lastDigest = digest;
    window.push(b && digest ? { digest, v: await checkVersion(ctx, folder, b, sg ?? null) } : null);
  }
  if (!window[0] || window[0].digest !== cur.digest) return invalid('history does not match the snapshot (the newest version in history is not the current file)');

  // Fork / rollback scan: removal is final. No genuine (signature-valid)
  // version in reachable history may carry the current serial with other
  // bytes, or a higher serial.
  for (const h of window.slice(1)) {
    if (!h || typeof h.v === 'string' || h.digest === cur.digest) continue;
    if (h.v.doc.serial >= cur.doc.serial) {
      return invalid(
        h.v.doc.serial === cur.doc.serial
          ? `fork: history contains a different serial ${cur.doc.serial}; the chain must be linear`
          : `rolled back: history contains serial ${h.v.doc.serial}, newer than the current serial ${cur.doc.serial}`,
      );
    }
  }
  if (headVia) return ok(headVia);

  // Chain of custody: each link must be the ACTUAL history predecessor of the
  // version that cites it, one serial lower, list the signer as admin, and be
  // genuine; the walk ends at a self-authorized version or at the version
  // this device cached. Anything at or below the cached serial must BE the
  // cached version.
  let v = cur;
  for (let i = 0; ; i++) {
    if (cached && v.doc.serial <= cached.serial) {
      if (v.doc.serial === cached.serial && v.digest === cached.digest) return ok('chain');
      return invalid(`fork: serial ${v.doc.serial} in the chain differs from the version this device verified`);
    }
    if (v !== cur && selfAuthorized(v)) return ok('chain');
    if (v.doc.serial === 1) {
      return invalid(`serial 1 signed by ${v.doc.updatedBy}, who is neither a trust anchor nor an admin of a parent folder`);
    }
    const next = window[i + 1];
    if (next === undefined) {
      return i + 1 >= MAX_CHAIN_VERSIONS + 1
        ? invalid(`chain of custody longer than ${MAX_CHAIN_VERSIONS} versions; ask a global admin to re-sign`)
        : invalid(`chain of custody broken: serial ${v.doc.serial} has no predecessor in history`);
    }
    if (next === null) return invalid(`chain of custody broken: the admins file was deleted before serial ${v.doc.serial}`);
    if (next.digest !== v.doc.previous) {
      return invalid(`chain of custody broken: serial ${v.doc.serial} cites ${v.doc.previous}, but its predecessor in history is ${next.digest} (fork)`);
    }
    if (typeof next.v === 'string') return invalid(`previous version (serial ${v.doc.serial - 1}) is invalid: ${next.v}`);
    const prev = next.v;
    if (prev.doc.serial !== v.doc.serial - 1) return invalid(`serial jump: ${prev.doc.serial} -> ${v.doc.serial}`);
    if (!prev.doc.admins.includes(v.doc.updatedBy)) {
      return invalid(`serial ${v.doc.serial} signed by ${v.doc.updatedBy}, who is not an admin in serial ${prev.doc.serial}`);
    }
    v = prev;
  }
}

/** Verify `<folder>/.g00pass-admins.json` in `snapshot` (see module doc). */
export async function verifyAdminsFile(snapshot: StoreSnapshot, folder: string, signal?: AbortSignal): Promise<AdminsFileStatus> {
  const f = normalizePath(folder);
  if (f === '') return { status: 'invalid', folder: f, reason: 'there is no admins file at the root (anchors are root admins)' };
  const ctx = await makeCtx(snapshot, signal);
  if ('error' in ctx) return snapshot.hasFile(joinPath(f, ADMINS_FILE)) ? { status: 'invalid', folder: f, reason: ctx.error } : { status: 'absent', folder: f };
  return verifyAt(ctx, f);
}

/** Verified folder admins of `folder`: union over valid admins files of it and its ancestors. */
export async function verifiedFolderAdmins(
  snapshot: StoreSnapshot,
  folder: string,
  signal?: AbortSignal,
): Promise<{ admins: Set<string>; files: AdminsFileStatus[] }> {
  const f = normalizePath(folder);
  const ctx = await makeCtx(snapshot, signal);
  const admins = new Set<string>();
  const files: AdminsFileStatus[] = [];
  if ('error' in ctx) return { admins, files };
  for (const g of ancestorsInclusive(f)) {
    if (g === '') break;
    const st = await verifyAt(ctx, g);
    if (st.status === 'absent') continue;
    files.push(st);
    if (st.status === 'valid') st.admins.forEach((a) => admins.add(a));
  }
  return { admins, files };
}

export interface FolderAdminCheck {
  readonly admin: boolean;
  /** 'anchor': global admin; 'admins-file': listed in a verified admins file of the folder or an ancestor. */
  readonly via: 'anchor' | 'admins-file' | null;
  /** Folder whose admins file grants it (via 'admins-file'). */
  readonly grantedBy?: string;
  readonly reason: string;
}

/**
 * May `fingerprint` administer `folder` (sign its `.gpg-id`, approve, remove)?
 * Requires a trusted root. Escrow keys are never admins.
 */
export async function checkFolderAdmin(
  snapshot: StoreSnapshot,
  folder: string,
  fingerprint: string,
  signal?: AbortSignal,
): Promise<FolderAdminCheck> {
  const f = normalizePath(folder);
  if (keyIdKind(fingerprint) !== 'fingerprint') return { admin: false, via: null, reason: 'not a full fingerprint' };
  const fpr = normalizeKeyId(fingerprint);
  const root = await evaluateRootTrust(snapshot, signal);
  if (!root.ok) return { admin: false, via: null, reason: `root not trusted: ${root.reason}` };
  if (root.escrow.includes(fpr)) return { admin: false, via: null, reason: 'escrow key is never an admin' };
  if (root.anchors.includes(fpr)) return { admin: true, via: 'anchor', reason: 'global admin (trust anchor)' };
  if (f === '') return { admin: false, via: null, reason: 'only global admins administer the root' };
  const ctx = await makeCtx(snapshot, signal);
  if ('error' in ctx) return { admin: false, via: null, reason: ctx.error };
  const notes: string[] = [];
  for (const g of ancestorsInclusive(f)) {
    if (g === '') break;
    const st = await verifyAt(ctx, g);
    if (st.status === 'valid' && st.admins.includes(fpr)) {
      return { admin: true, via: 'admins-file', grantedBy: g, reason: `listed in verified ${joinPath(g, ADMINS_FILE)}` };
    }
    if (st.status === 'invalid') notes.push(`${joinPath(g, ADMINS_FILE)}: ${st.reason}`);
  }
  return { admin: false, via: null, reason: notes.length ? `not a verified admin (${notes.join('; ')})` : 'not a verified admin' };
}

/** Boolean form of checkFolderAdmin (replaces Agent B's `isFolderAdmin` placeholder). */
export async function isVerifiedFolderAdmin(snapshot: StoreSnapshot, folder: string, fingerprint: string): Promise<boolean> {
  return (await checkFolderAdmin(snapshot, folder, fingerprint)).admin;
}

export interface SignedAdminsFile {
  readonly document: FolderAdminsDocument;
  readonly path: string;
  readonly sigPath: string;
  /** Exact canonical bytes (as text) to commit. */
  readonly content: string;
  readonly signature: Uint8Array;
  /** `[{path, content}, {path: sigPath, content: signature}]`, e.g. for reencryptFolder `extraChanges`. */
  readonly changes: readonly FileChange[];
}

/**
 * Produce the next version of `<folder>/.g00pass-admins.json` and its
 * signature, exactly in the format verifyAdminsFile accepts: serial and
 * previous follow the CURRENT file in `snapshot` (serial 1 if none), and
 * updatedBy is the signer's primary fingerprint. Base the commit on the same
 * snapshot (ConflictError → recompute).
 */
export async function signAdminsFile(opts: {
  snapshot: StoreSnapshot;
  folder: string;
  admins: readonly string[];
  signingKey: PrivateKey;
  date?: Date;
  signal?: AbortSignal;
}): Promise<SignedAdminsFile> {
  const folder = normalizePath(opts.folder);
  if (folder === '') throw new G00passError('there is no admins file at the root');
  const admins = normalizeFingerprints(opts.admins);
  if (admins.length === 0) throw new G00passError('an admins file needs at least one admin');
  const path = joinPath(folder, ADMINS_FILE);
  const current = await opts.snapshot.readFile(path, opts.signal);
  let serial = 1;
  let previous: string | null = null;
  if (current) {
    let s: unknown;
    try {
      s = (JSON.parse(new TextDecoder().decode(current)) as { serial?: unknown }).serial;
    } catch {
      s = undefined;
    }
    if (typeof s === 'number' && Number.isSafeInteger(s) && s >= 1) {
      serial = s + 1;
      previous = await sha256Digest(current);
    }
  }
  const date = opts.date ?? trustEnvironment().now();
  const document: FolderAdminsDocument = {
    admins,
    folder,
    previous,
    serial,
    type: ADMINS_TYPE,
    updatedAt: rfc3339(date),
    updatedBy: fingerprintOf(opts.signingKey),
    version: 1,
  };
  const content = canonicalJson(document);
  const signature = await signDetached(new TextEncoder().encode(content), opts.signingKey, { date });
  const sigPath = joinPath(folder, ADMINS_SIG);
  return { document, path, sigPath, content, signature, changes: [{ path, content }, { path: sigPath, content: signature }] };
}
