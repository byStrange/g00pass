import { NoRecipientsError } from './errors';
import { GPG_ID, ancestorsInclusive, dirname, entryFile, joinPath, normalizePath } from './paths';

/**
 * `.gpg-id` parsing, compatible with pass and gopass:
 *  - one recipient per line (fingerprint, key id, or e-mail/user id)
 *  - surrounding whitespace trimmed, blank lines ignored
 *  - `#` starts a comment, whole-line or trailing (pass: `${id%%#*}`,
 *    gopass: strings.Cut(line, "#"))
 *
 * g00pass extension (invisible to pass/gopass because it lives in a comment):
 * trailing-comment tokens of the form `g00pass:<flag>` annotate a recipient,
 * e.g. `0123...CDEF # g00pass:escrow` marks the org recovery key.
 */

export interface GpgIdRecipient {
  /** Recipient id exactly as written (trimmed). */
  id: string;
  /** g00pass annotation flags from the trailing comment, e.g. ["escrow"]. */
  flags: string[];
  /** 1-based source line. */
  line: number;
}

export const ESCROW_FLAG = 'escrow';

export function parseGpgId(text: string): GpgIdRecipient[] {
  const out: GpgIdRecipient[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, i) => {
    const hash = raw.indexOf('#');
    const idPart = (hash === -1 ? raw : raw.slice(0, hash)).trim();
    if (idPart === '') return;
    const comment = hash === -1 ? '' : raw.slice(hash + 1);
    const flags = [...comment.matchAll(/\bg00pass:([a-z][a-z0-9-]*)/g)].map((m) => m[1] as string);
    out.push({ id: idPart, flags, line: i + 1 });
  });
  return out;
}

/** Plain recipient ids, deduplicated by normalized form, order preserved. */
export function recipientIds(recipients: readonly GpgIdRecipient[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of recipients) {
    const k = normalizeKeyId(r.id);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(r.id);
  }
  return out;
}

export interface GpgIdLine {
  id: string;
  flags?: readonly string[];
}

/**
 * Deterministic serialization: one id per line, `\n` line endings, trailing
 * newline, duplicates (by normalized id) dropped keeping the first occurrence,
 * flags merged. Order is preserved as given.
 */
export function serializeGpgId(lines: readonly (GpgIdLine | string)[]): string {
  const merged = new Map<string, { id: string; flags: Set<string> }>();
  for (const l of lines) {
    const line = typeof l === 'string' ? { id: l } : l;
    const id = line.id.trim();
    if (id === '' || /[#\r\n]/.test(id)) throw new Error(`Invalid recipient id for .gpg-id: "${line.id}"`);
    const k = normalizeKeyId(id);
    const cur = merged.get(k) ?? { id, flags: new Set<string>() };
    for (const f of line.flags ?? []) {
      if (!/^[a-z][a-z0-9-]*$/.test(f)) throw new Error(`Invalid g00pass flag "${f}"`);
      cur.flags.add(f);
    }
    merged.set(k, cur);
  }
  if (merged.size === 0) throw new Error('Refusing to serialize an empty .gpg-id');
  return (
    [...merged.values()]
      .map(({ id, flags }) => (flags.size ? `${id} # ${[...flags].map((f) => `g00pass:${f}`).join(' ')}` : id))
      .join('\n') + '\n'
  );
}

const HEX_ID = /^(?:0x)?([0-9a-fA-F]{8}|[0-9a-fA-F]{16}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/;

/**
 * Canonical comparison form of a recipient id: hex ids/fingerprints are
 * upper-cased with `0x` and inner spaces removed; anything else (e-mail/user
 * id) is lower-cased and trimmed.
 */
export function normalizeKeyId(id: string): string {
  const compact = id.trim().replace(/\s+/g, '');
  const m = HEX_ID.exec(compact);
  if (m) return (m[1] as string).toUpperCase();
  return id.trim().toLowerCase();
}

export type KeyIdKind = 'fingerprint' | 'long-id' | 'short-id' | 'user-id';

export function keyIdKind(id: string): KeyIdKind {
  const n = normalizeKeyId(id);
  if (/^[0-9A-F]{40}$|^[0-9A-F]{64}$/.test(n)) return 'fingerprint';
  if (/^[0-9A-F]{16}$/.test(n)) return 'long-id';
  if (/^[0-9A-F]{8}$/.test(n)) return 'short-id';
  return 'user-id';
}

/**
 * Nearest `.gpg-id` for an ENTRY (read and write path), following pass:
 * start in the entry's directory and walk up to the root.
 *
 * Note: gopass starts one level deeper (it also checks `<entry-name>/.gpg-id`).
 * The two only differ when a folder and an entry share a name (`a/b/` and
 * `a/b.gpg`); g00pass follows pass and documents the difference.
 *
 * @param hasFile predicate over normalized store-relative file paths
 * @returns path of the governing `.gpg-id`
 */
export function findGpgIdForEntry(hasFile: (path: string) => boolean, entry: string): string {
  const file = entryFile(entry);
  const found = findGpgIdFrom(hasFile, dirname(file));
  if (found === null) throw new NoRecipientsError(file);
  return found;
}

/** Nearest `.gpg-id` for a FOLDER: the folder itself first, then upwards. */
export function findGpgIdForFolder(hasFile: (path: string) => boolean, folder: string): string {
  const f = normalizePath(folder);
  const found = findGpgIdFrom(hasFile, f);
  if (found === null) throw new NoRecipientsError(f || '/');
  return found;
}

function findGpgIdFrom(hasFile: (path: string) => boolean, startFolder: string): string | null {
  for (const dir of ancestorsInclusive(startFolder)) {
    const candidate = joinPath(dir, GPG_ID);
    if (hasFile(candidate)) return candidate;
  }
  return null;
}

/** Folder that owns a `.gpg-id` path ("a/b/.gpg-id" -> "a/b", ".gpg-id" -> ""). */
export function gpgIdFolder(gpgIdPath: string): string {
  return dirname(normalizePath(gpgIdPath));
}
