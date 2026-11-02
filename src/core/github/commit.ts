import { ConflictError, GitHubApiError, throwIfAborted } from '../errors';
import { joinPath, normalizePath } from '../paths';
import type { CommitResult, FileChange, StoreWriter } from '../store';
import { type GitHubClient, type GitHubRepo, refPath, repoPath, validateRepo } from './client';
import { bytesToBase64, getBranchHead } from './snapshot';

/**
 * Atomic multi-file commit via the Git Data API:
 *   1. GET ref           -> must equal baseSha, else ConflictError (fast fail)
 *   2. GET commit        -> base tree
 *   3. POST blobs        -> one per binary file (text files go inline in the tree)
 *   4. POST tree         -> base_tree + changes (deletions: sha null)
 *   5. POST commit       -> parents [baseSha]
 *   6. PATCH ref         -> force:false. GitHub rejects non-fast-forward
 *                           updates (422), which is the real compare-and-swap:
 *                           if anyone pushed after step 1, we get ConflictError.
 * Nothing is visible on the branch until step 6 succeeds.
 */

interface CreatedSha {
  sha: string;
}
interface CommitObj {
  sha: string;
  tree: { sha: string };
}

type TreeEntry =
  | { path: string; mode: '100644'; type: 'blob'; sha: string | null }
  | { path: string; mode: '100644'; type: 'blob'; content: string };

export interface CommitOptions {
  baseSha: string;
  message: string;
  signal?: AbortSignal;
  /** Parallel blob uploads (default 2; GitHub throttles content creation). */
  concurrency?: number;
}

export async function commitChanges(
  client: GitHubClient,
  repo: GitHubRepo,
  changes: readonly FileChange[],
  opts: CommitOptions,
): Promise<CommitResult> {
  validateRepo(repo);
  if (changes.length === 0) throw new Error('No changes to commit');
  if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(opts.baseSha)) throw new Error('baseSha must be a full commit sha');
  const seen = new Set<string>();
  for (const c of changes) {
    const p = normalizePath(c.path);
    if (p === '' || seen.has(p)) throw new Error(`Invalid or duplicate path in commit: "${c.path}"`);
    seen.add(p);
  }

  const head = await getBranchHead(client, repo, opts.signal);
  if (head !== opts.baseSha) throw new ConflictError(opts.baseSha, head);
  const base = await client.request<CommitObj>('GET', repoPath(repo, `/git/commits/${opts.baseSha}`), undefined, opts.signal);

  const root = repo.storeRoot ?? '';
  const entries: TreeEntry[] = new Array(changes.length);
  const queue = changes.map((c, i) => ({ c, i }));
  const worker = async () => {
    for (let item = queue.shift(); item; item = queue.shift()) {
      throwIfAborted(opts.signal);
      const { c, i } = item;
      const path = joinPath(root, c.path);
      if (c.delete) {
        entries[i] = { path, mode: '100644', type: 'blob', sha: null };
      } else if (typeof c.content === 'string') {
        entries[i] = { path, mode: '100644', type: 'blob', content: c.content };
      } else {
        const blob = await client.request<CreatedSha>(
          'POST',
          repoPath(repo, '/git/blobs'),
          { content: bytesToBase64(c.content), encoding: 'base64' },
          opts.signal,
        );
        entries[i] = { path, mode: '100644', type: 'blob', sha: blob.sha };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, opts.concurrency ?? 2) }, worker));
  throwIfAborted(opts.signal);

  const tree = await client.request<CreatedSha>(
    'POST',
    repoPath(repo, '/git/trees'),
    { base_tree: base.tree.sha, tree: entries },
    opts.signal,
  );
  const commit = await client.request<CreatedSha>(
    'POST',
    repoPath(repo, '/git/commits'),
    { message: opts.message, tree: tree.sha, parents: [opts.baseSha] },
    opts.signal,
  );
  throwIfAborted(opts.signal);
  try {
    await client.request('PATCH', repoPath(repo, `/git/refs/heads/${refPath(repo.branch)}`), { sha: commit.sha, force: false });
  } catch (e) {
    if (e instanceof GitHubApiError && (e.status === 422 || e.status === 409)) {
      let actual: string | null = null;
      try {
        actual = await getBranchHead(client, repo);
      } catch {
        /* ignore */
      }
      // Only a moved branch is a (retryable) conflict. If the head is still
      // our base, the update was refused for another reason (e.g. branch
      // protection) and retrying would not help.
      if (actual === opts.baseSha) throw e;
      throw new ConflictError(opts.baseSha, actual);
    }
    throw e;
  }
  return { commitSha: commit.sha, treeSha: tree.sha };
}

/** StoreWriter bound to one repo/branch. */
export class GitHubWriter implements StoreWriter {
  constructor(
    private readonly client: GitHubClient,
    private readonly repo: GitHubRepo,
  ) {}
  commit(changes: readonly FileChange[], opts: { baseSha: string; message: string; signal?: AbortSignal }) {
    return commitChanges(this.client, this.repo, changes, opts);
  }
}

/**
 * Re-run `attempt` (which must reload its snapshot and recompute everything)
 * when it throws ConflictError, up to `attempts` times in total.
 */
export async function withConflictRetry<T>(
  attempt: (n: number) => Promise<T>,
  opts: { attempts?: number; signal?: AbortSignal; onConflict?: (e: ConflictError, n: number) => void } = {},
): Promise<T> {
  const max = opts.attempts ?? 3;
  for (let n = 1; ; n++) {
    throwIfAborted(opts.signal);
    try {
      return await attempt(n);
    } catch (e) {
      if (!(e instanceof ConflictError) || n >= max) throw e;
      opts.onConflict?.(e, n);
    }
  }
}
