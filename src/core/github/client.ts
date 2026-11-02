import { GitHubApiError, redactSecrets } from '../errors';

/**
 * Minimal GitHub REST client. Tokens:
 *  - are read through a TokenProvider on every request (never copied into
 *    long-lived objects, never put in URLs, never included in errors)
 *  - only ever sent to `baseUrl` (default https://api.github.com, the only
 *    third-party origin the CSP allows)
 */

export type TokenProvider = () => string | null;

export interface GitHubRepo {
  owner: string;
  repo: string;
  branch: string;
  /** Sub-directory of the repo that is the store root ("" = repo root). */
  storeRoot?: string;
}

export interface GitHubClientOptions {
  token: TokenProvider;
  fetch?: typeof fetch;
  baseUrl?: string;
}

const NAME_RE = /^[A-Za-z0-9_.-]+$/;

export function validateRepo(r: GitHubRepo): void {
  if (!NAME_RE.test(r.owner) || !NAME_RE.test(r.repo)) throw new Error('Invalid owner/repo name');
  if (!r.branch || r.branch.includes('..') || /[\s~^:?*[\\]/.test(r.branch)) throw new Error('Invalid branch name');
}

export function repoPath(r: GitHubRepo, rest: string): string {
  return `/repos/${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}${rest}`;
}

export function refPath(branch: string): string {
  return branch.split('/').map(encodeURIComponent).join('/');
}

export class GitHubClient {
  private readonly fetchImpl: typeof fetch;
  private readonly baseUrl: string;
  private readonly token: TokenProvider;

  constructor(opts: GitHubClientOptions) {
    this.token = opts.token;
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.baseUrl = (opts.baseUrl ?? 'https://api.github.com').replace(/\/$/, '');
  }

  async request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    if (!path.startsWith('/')) throw new Error('path must be absolute');
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    const tok = this.token();
    if (tok) headers.Authorization = `Bearer ${tok}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res: Response;
    try {
      res = await this.fetchImpl(this.baseUrl + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
    } catch (e) {
      if ((e as Error)?.name === 'AbortError') throw e;
      throw new GitHubApiError(0, 'network error');
    }
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    if (!res.ok) {
      let msg = res.statusText || 'request failed';
      try {
        const j = JSON.parse(text) as { message?: string };
        if (typeof j.message === 'string') msg = j.message;
      } catch {
        /* non-JSON error body */
      }
      if (tok) msg = msg.split(tok).join('[REDACTED]');
      const ra = res.headers.get('retry-after');
      throw new GitHubApiError(res.status, redactSecrets(msg).slice(0, 300), ra ? Number(ra) : undefined);
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }
}
