import { ConflictError } from './errors';
import { GPG_ID, dirname, isEntryFile, isWithin, normalizePath } from './paths';

/**
 * A consistent, read-only view of the store at one commit. All reads used to
 * compute a change MUST come from the same snapshot whose `commitSha` is then
 * used as the optimistic-concurrency base for the write.
 */
export interface StoreSnapshot {
  /** Commit the snapshot was taken at; the base sha for writes. */
  readonly commitSha: string;
  /** All blob paths, store-relative and normalized. */
  listFiles(): readonly string[];
  hasFile(path: string): boolean;
  /** File bytes or null if absent. Implementations may cache ciphertext only. */
  readFile(path: string, signal?: AbortSignal): Promise<Uint8Array | null>;
}

export type FileChange =
  | { path: string; content: Uint8Array | string; delete?: never }
  | { path: string; delete: true; content?: never };

export interface CommitResult {
  commitSha: string;
  treeSha: string;
}

/**
 * Applies changes as ONE atomic commit on top of `baseSha`. Must throw
 * ConflictError if the branch is no longer at `baseSha`.
 */
export interface StoreWriter {
  commit(
    changes: readonly FileChange[],
    opts: { baseSha: string; message: string; signal?: AbortSignal },
  ): Promise<CommitResult>;
}

/** Every entry (`*.gpg`) under `folder` (recursively, ignoring `.gpg-id` boundaries). */
export function listEntries(snapshot: StoreSnapshot, folder = ''): string[] {
  const f = normalizePath(folder);
  return snapshot
    .listFiles()
    .filter((p) => isEntryFile(p) && isWithin(p, f))
    .sort();
}

/**
 * Entries GOVERNED by `folder`'s recipients: everything under it, but not
 * descending into nested sub-folders that carry their own `.gpg-id`.
 */
export function listGovernedEntries(snapshot: StoreSnapshot, folder: string): string[] {
  const f = normalizePath(folder);
  const boundaries = nestedGpgIdFolders(snapshot, f);
  return listEntries(snapshot, f).filter((p) => !boundaries.some((b) => isWithin(p, b)));
}

/** Sub-folders strictly below `folder` that have their own `.gpg-id`. */
export function nestedGpgIdFolders(snapshot: StoreSnapshot, folder: string): string[] {
  const f = normalizePath(folder);
  return snapshot
    .listFiles()
    .filter((p) => (p === GPG_ID || p.endsWith('/' + GPG_ID)) && isWithin(p, f))
    .map(dirname)
    .filter((d) => d !== f)
    .sort();
}

/**
 * DIRECT nested boundaries of `folder` by file presence: sub-folders with
 * their own `.gpg-id` that are not inside another nested one. Whether these
 * are the AUTHORIZED boundaries is decided by the trust policy (signed
 * `child@g00pass` declarations, docs/specs/gpg-id-signatures.md).
 */
export function directNestedGpgIdFolders(snapshot: StoreSnapshot, folder: string): string[] {
  const nested = nestedGpgIdFolders(snapshot, folder);
  return nested.filter((n) => !nested.some((m) => m !== n && isWithin(n, m)));
}

/** In-memory snapshot, used in tests and for offline previews. */
export class MemoryStore implements StoreSnapshot {
  private readonly files = new Map<string, Uint8Array>();
  constructor(
    files: Record<string, Uint8Array | string> = {},
    public commitSha = 'mem-0',
  ) {
    for (const [p, c] of Object.entries(files)) this.set(p, c);
  }
  set(path: string, content: Uint8Array | string): void {
    this.files.set(normalizePath(path), typeof content === 'string' ? new TextEncoder().encode(content) : content);
  }
  delete(path: string): void {
    this.files.delete(normalizePath(path));
  }
  listFiles(): string[] {
    return [...this.files.keys()].sort();
  }
  hasFile(path: string): boolean {
    return this.files.has(normalizePath(path));
  }
  async readFile(path: string): Promise<Uint8Array | null> {
    const v = this.files.get(normalizePath(path));
    return v ? v.slice() : null;
  }
}

/** A StoreWriter over a MemoryStore with the same CAS semantics as GitHub. */
export class MemoryWriter implements StoreWriter {
  private n = 0;
  readonly commits: { message: string; changes: FileChange[] }[] = [];
  constructor(private readonly store: MemoryStore) {}
  async commit(changes: readonly FileChange[], opts: { baseSha: string; message: string }): Promise<CommitResult> {
    if (opts.baseSha !== this.store.commitSha) throw new ConflictError(opts.baseSha, this.store.commitSha);
    for (const c of changes) {
      if (c.delete) this.store.delete(c.path);
      else this.store.set(c.path, c.content);
    }
    this.store.commitSha = `mem-${++this.n}`;
    this.commits.push({ message: opts.message, changes: [...changes] });
    return { commitSha: this.store.commitSha, treeSha: `tree-${this.n}` };
  }
}
