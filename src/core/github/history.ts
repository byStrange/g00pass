import { GitHubApiError } from '../errors';
import { joinPath, normalizePath } from '../paths';
import { type GitHubClient, type GitHubRepo, repoPath } from './client';


/** One historic version of a file plus companion files, at one commit. */
export interface FileVersion {
  readonly commitSha: string;
  /** `[path, ...companions]` contents at that commit (null: absent). */
  readonly files: readonly (Uint8Array | null)[];
}

/**
 * Read access to older versions of store files, used to walk the folder-admins
 * chain of custody (folder-admins.md §Chain). Versions are those of commits
 * REACHABLE FROM THE SNAPSHOT COMMIT that touched `path`, newest first, so the
 * walk is bound to the same history the snapshot was taken from.
 */
export interface MergeCommit {
  readonly sha: string;
  readonly parents: readonly string[];
}

export interface FileHistory {
  versions(
    path: string,
    companions: readonly string[],
    opts: { limit: number; signal?: AbortSignal },
  ): AsyncIterable<FileVersion>;
  /**
   * Merge commits reachable from the snapshot commit but not from `base`
   * (i.e. in base..head). Null when the range is too large to check.
   *
   * Needed because `commits?path=` uses git's default history
   * simplification: at a merge that is TREESAME to one parent for `path`,
   * the other parents are pruned, so a writer can hide versions (e.g. the
   * admins version that removed them) behind a merge without force-pushing.
   */
  merges(base: string, opts: { signal?: AbortSignal }): Promise<readonly MergeCommit[] | null>;
  /** Content of store path `path` at `commit` (null: absent). */
  readAt(commit: string, path: string, signal?: AbortSignal): Promise<Uint8Array | null>;
}

/** Commits in base..head examined for merges (beyond this: unverifiable, fail closed). */
export const MAX_RANGE_COMMITS = 1000;

function b64(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const SHA_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/;

export class GitHubFileHistory implements FileHistory {
  constructor(
    private readonly client: GitHubClient,
    private readonly repo: GitHubRepo,
    private readonly commitSha: string,
  ) {}

  private repoRel(path: string): string {
    return joinPath(this.repo.storeRoot ?? '', normalizePath(path));
  }

  async *versions(path: string, companions: readonly string[], opts: { limit: number; signal?: AbortSignal }) {
    const limit = Math.max(1, Math.min(100, opts.limit));
    const q = new URLSearchParams({ sha: this.commitSha, path: this.repoRel(path), per_page: String(limit) });
    const commits = await this.client.request<{ sha?: unknown }[]>(
      'GET',
      repoPath(this.repo, `/commits?${q.toString()}`),
      undefined,
      opts.signal,
    );
    if (!Array.isArray(commits)) return;
    for (const c of commits.slice(0, limit)) {
      if (typeof c?.sha !== 'string' || !SHA_RE.test(c.sha)) continue;
      const sha = c.sha;
      const files = await Promise.all([path, ...companions].map((p) => this.readAt(sha, p, opts.signal)));
      yield { commitSha: sha, files };
    }
  }

  async merges(base: string, opts: { signal?: AbortSignal }): Promise<readonly MergeCommit[] | null> {
    if (!SHA_RE.test(base)) return null;
    if (base === this.commitSha) return [];
    const out: MergeCommit[] = [];
    const perPage = 100;
    for (let page = 1; page <= MAX_RANGE_COMMITS / perPage; page++) {
      const q = new URLSearchParams({ per_page: String(perPage), page: String(page) });
      const r = await this.client.request<{ status?: unknown; total_commits?: unknown; commits?: { sha?: unknown; parents?: { sha?: unknown }[] }[] }>(
        'GET',
        repoPath(this.repo, `/compare/${base}...${this.commitSha}?${q.toString()}`),
        undefined,
        opts.signal,
      );
      // base must be an ancestor of head ("ahead"); anything else is not a linear range.
      if (r?.status !== 'ahead' && r?.status !== 'identical') return null;
      if (typeof r.total_commits !== 'number' || r.total_commits > MAX_RANGE_COMMITS) return null;
      const commits = Array.isArray(r.commits) ? r.commits : [];
      for (const c of commits) {
        const parents = (Array.isArray(c?.parents) ? c.parents : []).map((p) => p?.sha);
        if (typeof c?.sha !== 'string' || !SHA_RE.test(c.sha) || !parents.every((p): p is string => typeof p === 'string' && SHA_RE.test(p))) return null;
        if (parents.length > 1) out.push({ sha: c.sha, parents });
      }
      if (page * perPage >= r.total_commits || commits.length < perPage) return out;
    }
    return null;
  }

  async readAt(ref: string, path: string, signal?: AbortSignal): Promise<Uint8Array | null> {
    if (!SHA_RE.test(ref)) throw new GitHubApiError(0, 'invalid commit sha');
    const enc = this.repoRel(path).split('/').map(encodeURIComponent).join('/');
    try {
      const r = await this.client.request<{ type?: string; encoding?: string; content?: string }>(
        'GET',
        repoPath(this.repo, `/contents/${enc}?ref=${ref}`),
        undefined,
        signal,
      );
      if (r?.type !== 'file' || r.encoding !== 'base64' || typeof r.content !== 'string') return null;
      return b64(r.content);
    } catch (e) {
      if (e instanceof GitHubApiError && e.status === 404) return null;
      throw e;
    }
  }
}
