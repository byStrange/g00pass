import type { PrivateKey } from 'openpgp';
import { RFC3339_RE, canonicalJson, rfc3339 } from './canonical';
import { decryptEntry, wipe } from './crypto/decrypt';
import { G00passError } from './errors';
import { GPG_ID, entryName, isWithin, joinPath, normalizePath } from './paths';
import { type StoreSnapshot, type StoreWriter, listGovernedEntries } from './store';
import { type WriteEntryResult, writeEntry } from './entries';
import { fingerprintOf } from './keys';
import { trustEnvironment } from './trust-env';

/**
 * ROTATION TRACKING (docs/specs/rotation.md).
 *
 * `<F>/.g00pass-rotation.gpg` is an encrypted (hidden) entry of F holding
 * canonical JSON: when each governed secret was created / last rotated, and
 * the append-only history of members added and removed through g00pass.
 * It is encrypted to F's recipients like any entry, so `reencryptFolder`
 * keeps it current, and writers update it in the same commit as the change
 * it records (`replaceEntries` / `writeEntry` companions).
 */

export const ROTATION_FILE = '.g00pass-rotation.gpg';
export const ROTATION_TYPE = 'g00pass.rotation';

export interface RotationEntry {
  createdAt: string | null;
  rotatedAt: string | null;
  rotatedBy: string | null;
}

export interface RotationMember {
  addedAt: string | null;
  addedBy: string | null;
  fingerprint: string;
  name: string | null;
  removedAt: string | null;
  removedBy: string | null;
  /** `requestsRepo#issue` for approvals, else null. */
  request: string | null;
}

export interface RotationDocument {
  entries: Record<string, RotationEntry>;
  folder: string;
  members: RotationMember[];
  type: typeof ROTATION_TYPE;
  version: 1;
}

export class RotationError extends G00passError {}

const FPR_RE = /^[0-9A-F]{40}$|^[0-9A-F]{64}$/;
const isTime = (v: unknown): v is string | null => v === null || (typeof v === 'string' && RFC3339_RE.test(v));
const isFprOrNull = (v: unknown): v is string | null => v === null || (typeof v === 'string' && FPR_RE.test(v));
const isStrOrNull = (v: unknown, max: number): v is string | null => v === null || (typeof v === 'string' && v.length <= max);

export function rotationPath(folder: string): string {
  return joinPath(normalizePath(folder), ROTATION_FILE);
}

export function emptyRotation(folder: string): RotationDocument {
  return { entries: {}, folder: normalizePath(folder), members: [], type: ROTATION_TYPE, version: 1 };
}

/** Parse + validate rotation JSON for `folder`. Throws RotationError. */
export function parseRotation(bytes: Uint8Array, folder: string): RotationDocument {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new RotationError('rotation file is not JSON');
  }
  const d = v as Partial<RotationDocument>;
  if (!d || typeof d !== 'object' || d.type !== ROTATION_TYPE || d.version !== 1) throw new RotationError('unknown rotation file type/version');
  if (d.folder !== normalizePath(folder)) throw new RotationError(`rotation file is for "${String(d.folder)}", not "${folder}"`);
  if (!d.entries || typeof d.entries !== 'object' || Array.isArray(d.entries)) throw new RotationError('rotation entries must be an object');
  const entries: Record<string, RotationEntry> = {};
  for (const [k, e] of Object.entries(d.entries)) {
    if (!e || !isTime(e.createdAt) || !isTime(e.rotatedAt) || !isFprOrNull(e.rotatedBy)) throw new RotationError(`invalid rotation entry "${k}"`);
    entries[normalizePath(k)] = { createdAt: e.createdAt, rotatedAt: e.rotatedAt, rotatedBy: e.rotatedBy };
  }
  if (!Array.isArray(d.members)) throw new RotationError('rotation members must be an array');
  const members: RotationMember[] = d.members.map((m, i) => {
    if (
      !m ||
      typeof m.fingerprint !== 'string' ||
      !FPR_RE.test(m.fingerprint) ||
      !isTime(m.addedAt) ||
      !isTime(m.removedAt) ||
      !isFprOrNull(m.addedBy) ||
      !isFprOrNull(m.removedBy) ||
      !isStrOrNull(m.name, 200) ||
      !isStrOrNull(m.request, 200)
    ) {
      throw new RotationError(`invalid rotation member #${i}`);
    }
    return { addedAt: m.addedAt, addedBy: m.addedBy, fingerprint: m.fingerprint, name: m.name, removedAt: m.removedAt, removedBy: m.removedBy, request: m.request };
  });
  return { entries, folder: d.folder, members, type: ROTATION_TYPE, version: 1 };
}

export function serializeRotation(doc: RotationDocument): Uint8Array {
  return new TextEncoder().encode(canonicalJson(doc));
}

/**
 * Decrypt `F/.g00pass-rotation.gpg`, or the empty default when it does not
 * exist. A file that exists but cannot be decrypted / parsed throws (callers
 * must not silently replace history they could not read).
 */
export async function readRotation(snapshot: StoreSnapshot, folder: string, keys: readonly PrivateKey[], signal?: AbortSignal): Promise<RotationDocument> {
  const f = normalizePath(folder);
  const ct = await snapshot.readFile(rotationPath(f), signal);
  if (!ct) return emptyRotation(f);
  let plain: Uint8Array | null = null;
  try {
    plain = await decryptEntry(ct, keys, rotationPath(f));
    return parseRotation(plain, f);
  } finally {
    wipe(plain);
  }
}

const clone = (d: RotationDocument): RotationDocument => JSON.parse(JSON.stringify(d)) as RotationDocument;

/** Entry key relative to `folder` ("infra/db/primary.gpg" in "infra" -> "db/primary"). */
export function rotationKey(folder: string, entryPath: string): string {
  const f = normalizePath(folder);
  const n = entryName(entryPath);
  if (!isWithin(n, f) || n === f) throw new RotationError(`"${entryPath}" is not inside "${f}"`);
  return f ? n.slice(f.length + 1) : n;
}

function firstLine(b: Uint8Array | null): string | null {
  if (!b) return null;
  const t = new TextDecoder().decode(b);
  const i = t.indexOf('\n');
  return (i === -1 ? t : t.slice(0, i)).replace(/\r$/, '');
}

/**
 * Record an entry write: new entries get createdAt = rotatedAt = now; an
 * edit counts as a rotation only when the FIRST LINE (the password, by pass
 * convention) changed. Compare in memory, before encrypting.
 */
export function recordEntryWrite(
  doc: RotationDocument,
  entryPath: string,
  oldPlain: Uint8Array | null,
  newPlain: Uint8Array,
  operator: string,
  now: Date,
): RotationDocument {
  const out = clone(doc);
  const k = rotationKey(doc.folder, entryPath);
  const t = rfc3339(now);
  if (!oldPlain) {
    out.entries[k] = { createdAt: t, rotatedAt: t, rotatedBy: operator };
    return out;
  }
  const cur = out.entries[k] ?? { createdAt: null, rotatedAt: null, rotatedBy: null };
  out.entries[k] = firstLine(oldPlain) !== firstLine(newPlain) ? { ...cur, rotatedAt: t, rotatedBy: operator } : cur;
  return out;
}

/** "Mark as rotated": the secret was rotated at its source, the stored value is unchanged. */
export function markRotated(doc: RotationDocument, entryPath: string, operator: string, now: Date): RotationDocument {
  const out = clone(doc);
  const k = rotationKey(doc.folder, entryPath);
  out.entries[k] = { createdAt: out.entries[k]?.createdAt ?? null, rotatedAt: rfc3339(now), rotatedBy: operator };
  return out;
}

export function recordEntryDeleted(doc: RotationDocument, entryPath: string): RotationDocument {
  const out = clone(doc);
  delete out.entries[rotationKey(doc.folder, entryPath)];
  return out;
}

/** Move within the folder: metadata follows the entry. */
export function recordEntryMoved(doc: RotationDocument, from: string, to: string): RotationDocument {
  const out = clone(doc);
  const a = rotationKey(doc.folder, from);
  const b = rotationKey(doc.folder, to);
  if (out.entries[a]) out.entries[b] = out.entries[a]!;
  delete out.entries[a];
  return out;
}

export function recordMemberAdded(
  doc: RotationDocument,
  m: { fingerprint: string; name: string | null; addedBy: string; request: string | null },
  now: Date,
): RotationDocument {
  const out = clone(doc);
  out.members.push({ addedAt: rfc3339(now), addedBy: m.addedBy, fingerprint: m.fingerprint.toUpperCase(), name: m.name, removedAt: null, removedBy: null, request: m.request });
  return out;
}

/** Close X's open member record, or append one with addedAt: null (CLI-era member). */
export function recordMemberRemoved(doc: RotationDocument, fingerprint: string, removedBy: string, now: Date): RotationDocument {
  const out = clone(doc);
  const fpr = fingerprint.toUpperCase();
  const t = rfc3339(now);
  const open = [...out.members].reverse().find((m) => m.fingerprint === fpr && m.removedAt === null);
  if (open) {
    open.removedAt = t;
    open.removedBy = removedBy;
  } else {
    out.members.push({ addedAt: null, addedBy: null, fingerprint: fpr, name: null, removedAt: t, removedBy, request: null });
  }
  return out;
}

// ---- checklist (computed, never stored) ----

export interface ChecklistItem {
  /** Store-relative entry path (with `.gpg`). */
  readonly path: string;
  readonly createdAt: string | null;
  readonly rotatedAt: string | null;
  readonly rotatedBy: string | null;
}

export interface MemberChecklist {
  readonly fingerprint: string;
  readonly name: string | null;
  readonly addedAt: string | null;
  readonly removedAt: string;
  /** Exposed and not rotated since removal: rotate these at the source. */
  readonly open: readonly ChecklistItem[];
  /** Exposed, already rotated after removal. */
  readonly done: readonly ChecklistItem[];
  readonly notes: readonly string[];
}

const ms = (t: string | null) => (t === null ? null : Date.parse(t));

/**
 * For every removed member with a closed record (latest removal per
 * fingerprint): exposed(e) = e governed by F and (createdAt null or < R);
 * open(e) = exposed(e) and (rotatedAt null or <= R). Entries without
 * metadata count as created at an unknown time (exposed) and never rotated.
 * Escrow keys and members that were re-added (open record after removal)
 * are skipped. Only members with open items are returned unless `all`.
 */
export function rotationChecklist(doc: RotationDocument, snapshot: StoreSnapshot, opts: { all?: boolean; escrow?: readonly string[] } = {}): MemberChecklist[] {
  const f = doc.folder;
  const rot = rotationPath(f);
  const governed = listGovernedEntries(snapshot, f).filter((p) => p !== rot);
  const escrow = new Set((opts.escrow ?? []).map((e) => e.toUpperCase()));
  const latest = new Map<string, RotationMember>();
  for (const m of doc.members) latest.set(m.fingerprint, m);
  const out: MemberChecklist[] = [];
  for (const m of latest.values()) {
    if (m.removedAt === null || escrow.has(m.fingerprint)) continue;
    const R = ms(m.removedAt)!;
    const open: ChecklistItem[] = [];
    const done: ChecklistItem[] = [];
    for (const p of governed) {
      const e = doc.entries[rotationKey(f, p)] ?? { createdAt: null, rotatedAt: null, rotatedBy: null };
      const c = ms(e.createdAt);
      if (c !== null && c >= R) continue;
      const r = ms(e.rotatedAt);
      const item = { path: p, createdAt: e.createdAt, rotatedAt: e.rotatedAt, rotatedBy: e.rotatedBy };
      (r === null || r <= R ? open : done).push(item);
    }
    const notes = [
      'Nested folders with their own .gpg-id are not covered: if this member was a recipient there, remove them there separately.',
      'Git history keeps the old ciphertext: re-encryption only protects future values. Rotate each secret at its source.',
    ];
    if (m.addedAt === null) notes.unshift('Added before tracking: assume they could read everything that existed before the removal.');
    if (open.length || opts.all) out.push({ fingerprint: m.fingerprint, name: m.name, addedAt: m.addedAt, removedAt: m.removedAt, open: open.sort((a, b) => a.path.localeCompare(b.path)), done, notes });
  }
  return out;
}

/**
 * "Mark rotated" for `entries` of `folder` and commit the rotation file
 * (encrypted to the folder's verified recipients via writeEntry).
 */
export async function commitMarkRotated(opts: {
  snapshot: StoreSnapshot;
  writer: StoreWriter;
  folder: string;
  entries: readonly string[];
  operatorKey: PrivateKey;
  now?: Date;
  signal?: AbortSignal;
}): Promise<WriteEntryResult> {
  const f = normalizePath(opts.folder);
  if (!opts.snapshot.hasFile(joinPath(f, GPG_ID))) throw new RotationError(`"${f}" has no .gpg-id of its own`);
  const now = opts.now ?? trustEnvironment().now();
  const op = fingerprintOf(opts.operatorKey);
  let doc = await readRotation(opts.snapshot, f, [opts.operatorKey], opts.signal);
  for (const e of opts.entries) doc = markRotated(doc, e, op, now);
  return writeEntry({
    snapshot: opts.snapshot,
    writer: opts.writer,
    entry: rotationPath(f),
    plaintext: serializeRotation(doc),
    message: `g00pass: mark ${opts.entries.length} entr${opts.entries.length === 1 ? 'y' : 'ies'} rotated in ${f || '/'}`,
    signal: opts.signal,
  });
}
