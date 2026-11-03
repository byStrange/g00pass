import { StorePathError } from './errors';

/**
 * Store-relative paths: no leading/trailing slash, `/` separated, root is "".
 * Entries are files ending in `.gpg`; an entry *name* is the path without it.
 */

export const GPG_ID = '.gpg-id';
export const GPG_ID_SIG = '.gpg-id.sig';
export const ENTRY_EXT = '.gpg';
export const PUBLIC_KEYS_DIR = '.public-keys';
export const LEGACY_PUBLIC_KEYS_DIR = '.gpg-keys';

export function normalizePath(p: string): string {
  if (p.includes('\0')) throw new StorePathError('Path contains NUL');
  if (p.includes('\\')) throw new StorePathError(`Backslash not allowed in store path: "${p}"`);
  const parts: string[] = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') throw new StorePathError(`".." not allowed in store path: "${p}"`);
    parts.push(seg);
  }
  return parts.join('/');
}

export function joinPath(...parts: string[]): string {
  return normalizePath(parts.filter((p) => p !== '').join('/'));
}

/** Parent directory of a normalized path; parent of a top-level item is "". */
export function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? '' : p.slice(0, i);
}

export function basename(p: string): string {
  return p.slice(p.lastIndexOf('/') + 1);
}

/** True if `p` is `folder` itself or inside it. Root folder "" contains everything. */
export function isWithin(p: string, folder: string): boolean {
  return folder === '' || p === folder || p.startsWith(folder + '/');
}

/** Top-level directories that hold g00pass/gopass metadata, never entries. */
export const NON_ENTRY_DIRS = [PUBLIC_KEYS_DIR, LEGACY_PUBLIC_KEYS_DIR, '.g00pass', '.git'];

export function isEntryFile(p: string): boolean {
  if (NON_ENTRY_DIRS.some((d) => p.startsWith(d + '/'))) return false;
  return p.endsWith(ENTRY_EXT) && basename(p).length > ENTRY_EXT.length;
}

/** "a/b.gpg" -> "a/b". Accepts names without the extension unchanged. */
export function entryName(p: string): string {
  const n = normalizePath(p);
  return isEntryFile(n) ? n.slice(0, -ENTRY_EXT.length) : n;
}

/** "a/b" or "a/b.gpg" -> "a/b.gpg" */
export function entryFile(nameOrPath: string): string {
  const n = normalizePath(nameOrPath);
  if (n === '') throw new StorePathError('Empty entry name');
  return isEntryFile(n) ? n : n + ENTRY_EXT;
}

/** The chain of folders from `folder` up to the root, inclusive: "a/b" -> ["a/b","a",""] */
export function ancestorsInclusive(folder: string): string[] {
  const out: string[] = [];
  let cur = normalizePath(folder);
  for (;;) {
    out.push(cur);
    if (cur === '') return out;
    cur = dirname(cur);
  }
}

/**
 * Entries whose file name starts with "." (e.g. `.g00pass-rotation.gpg`) are
 * g00pass metadata: encrypted and re-encrypted like entries, but hidden from
 * entry lists in the UI.
 */
export function isHiddenEntry(p: string): boolean {
  return normalizePath(p).split('/').some((seg) => seg.startsWith('.'));
}
