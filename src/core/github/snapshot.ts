import { G00passError } from '../errors';
import { isWithin, joinPath, normalizePath } from '../paths';
import type { StoreSnapshot } from '../store';
import { type GitHubClient, type GitHubRepo, refPath, repoPath, validateRepo } from './client';

interface RefResponse {
  object: { sha: string; type: string };
}
interface CommitResponse {
  sha: string;
  tree: { sha: string };
}
interface TreeResponse {
  sha: string;
  truncated: boolean;
  tree: { path: string; type: 'blob' | 'tree' | 'commit'; sha: string; mode: string }[];
}
interface BlobResponse {
  content: string;
  encoding: 'base64' | 'utf-8';
}

export async function getBranchHead(client: GitHubClient, repo: GitHubRepo, signal?: AbortSignal): Promise<string> {
  const ref = await client.request<RefResponse>('GET', repoPath(repo, `/git/ref/heads/${refPath(repo.branch)}`), undefined, signal);
  return ref.object.sha;
}

/**
 * Read-only snapshot of the store at one commit, via the Git Data API.
 * Paths are store-relative (storeRoot stripped). Blob contents (ciphertext)
 * are cached in memory for the lifetime of the snapshot.
 */
export class GitHubSnapshot implements StoreSnapshot {
  private readonly cache = new Map<string, Uint8Array>();
  private constructor(
    private readonly client: GitHubClient,
    readonly repo: GitHubRepo,
    readonly commitSha: string,
    readonly treeSha: string,
    private readonly blobs: ReadonlyMap<string, string>,
  ) {}

  static async load(client: GitHubClient, repo: GitHubRepo, opts: { commitSha?: string; signal?: AbortSignal } = {}) {
    validateRepo(repo);
    if (opts.commitSha !== undefined && !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(opts.commitSha)) {
      throw new G00passError('commitSha must be a full hex commit sha');
    }
    const commitSha = opts.commitSha ?? (await getBranchHead(client, repo, opts.signal));
    const commit = await client.request<CommitResponse>('GET', repoPath(repo, `/git/commits/${commitSha}`), undefined, opts.signal);
    const tree = await client.request<TreeResponse>(
      'GET',
      repoPath(repo, `/git/trees/${commit.tree.sha}?recursive=1`),
      undefined,
      opts.signal,
    );
    if (tree.truncated) {
      throw new G00passError('Repository tree too large for a single recursive listing (truncated); not supported yet');
    }
    const root = normalizePath(repo.storeRoot ?? '');
    const blobs = new Map<string, string>();
    for (const e of tree.tree) {
      if (e.type !== 'blob' || !isWithin(e.path, root)) continue;
      if (e.mode === '120000') continue; // symlinks: never follow
      blobs.set(root ? e.path.slice(root.length + 1) : e.path, e.sha);
    }
    return new GitHubSnapshot(client, repo, commitSha, commit.tree.sha, blobs);
  }

  listFiles(): string[] {
    return [...this.blobs.keys()].sort();
  }
  hasFile(path: string): boolean {
    return this.blobs.has(normalizePath(path));
  }
  blobSha(path: string): string | undefined {
    return this.blobs.get(normalizePath(path));
  }
  async readFile(path: string, signal?: AbortSignal): Promise<Uint8Array | null> {
    const p = normalizePath(path);
    const sha = this.blobs.get(p);
    if (!sha) return null;
    let data = this.cache.get(sha);
    if (!data) {
      const b = await this.client.request<BlobResponse>('GET', repoPath(this.repo, `/git/blobs/${sha}`), undefined, signal);
      data = b.encoding === 'base64' ? base64ToBytes(b.content) : new TextEncoder().encode(b.content);
      this.cache.set(sha, data);
    }
    return data.slice();
  }
  /** Repo-relative path for a store-relative path. */
  repoPathOf(path: string): string {
    return joinPath(this.repo.storeRoot ?? '', path);
  }
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
