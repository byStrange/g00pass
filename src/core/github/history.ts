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
export interface FileHistory {
  versions(
    path: string,
    companions: readonly string[],
    opts: { limit: number; signal?: AbortSignal },
  ): AsyncIterable<FileVersion>;
}

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

  private async readAt(ref: string, path: string, signal?: AbortSignal): Promise<Uint8Array | null> {
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
