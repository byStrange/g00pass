import { G00passError } from '../errors';
import { type GitHubClient, type GitHubRepo, repoPath, validateRepo } from './client';
import { REQUEST_LABEL } from '../requests/build';

/**
 * Issue API used for access requests (docs/specs/access-requests.md).
 * Issue content is UNTRUSTED: callers must treat title/body/user as text only.
 */

export type IssueRepo = Pick<GitHubRepo, 'owner' | 'repo'>;

export const LABEL_REQUEST = REQUEST_LABEL;
export const LABEL_APPROVED = 'g00pass:approved';
export const LABEL_REJECTED = 'g00pass:rejected';

export interface IssueSummary {
  number: number;
  title: string;
  /** Raw markdown body; may be null/empty. Untrusted. */
  body: string | null;
  state: 'open' | 'closed';
  labels: string[];
  /** Login of the author. Untrusted metadata (never an identity). */
  author: string | null;
  htmlUrl: string | null;
  createdAt: string | null;
}

interface RawIssue {
  number: number;
  title?: string;
  body?: string | null;
  state?: string;
  labels?: (string | { name?: string })[];
  user?: { login?: string } | null;
  html_url?: string;
  created_at?: string;
  pull_request?: unknown;
}

function issuesBase(r: IssueRepo): string {
  validateRepo({ ...r, branch: 'main' });
  return repoPath({ ...r, branch: 'main' }, '/issues');
}

function checkNumber(n: number): void {
  if (!Number.isSafeInteger(n) || n <= 0) throw new G00passError('Invalid issue number');
}

/**
 * State + labels of one issue (the requester polls their own request).
 * UX only: issue metadata is untrusted; real access shows when entries decrypt.
 */
export async function getIssueStatus(
  client: GitHubClient,
  repo: IssueRepo,
  issueNumber: number,
  signal?: AbortSignal,
): Promise<{ state: 'open' | 'closed'; labels: string[] }> {
  checkNumber(issueNumber);
  const i = await client.request<RawIssue>('GET', `${issuesBase(repo)}/${issueNumber}`, undefined, signal);
  return {
    state: i.state === 'closed' ? 'closed' : 'open',
    labels: (i.labels ?? []).map((l) => (typeof l === 'string' ? l : (l.name ?? ''))).filter(Boolean),
  };
}

/**
 * List OPEN issues (pull requests are skipped), newest first. Discovery does
 * not depend on labels: callers filter on the body marker. Capped at `maxPages`
 * pages of 100 to respect rate limits.
 */
export async function listIssues(
  client: GitHubClient,
  repo: IssueRepo,
  opts: { maxPages?: number; signal?: AbortSignal } = {},
): Promise<IssueSummary[]> {
  const base = issuesBase(repo);
  const out: IssueSummary[] = [];
  for (let page = 1; page <= (opts.maxPages ?? 3); page++) {
    const raw = await client.request<RawIssue[]>(
      'GET',
      `${base}?state=open&sort=created&direction=desc&per_page=100&page=${page}`,
      undefined,
      opts.signal,
    );
    for (const i of raw) {
      if (i.pull_request || !Number.isSafeInteger(i.number)) continue;
      out.push({
        number: i.number,
        title: typeof i.title === 'string' ? i.title : '',
        body: typeof i.body === 'string' ? i.body : null,
        state: i.state === 'closed' ? 'closed' : 'open',
        labels: (i.labels ?? []).map((l) => (typeof l === 'string' ? l : (l.name ?? ''))).filter(Boolean),
        author: i.user?.login ?? null,
        htmlUrl: typeof i.html_url === 'string' ? i.html_url : null,
        createdAt: typeof i.created_at === 'string' ? i.created_at : null,
      });
    }
    if (raw.length < 100) break;
  }
  return out;
}

export async function commentOnIssue(
  client: GitHubClient,
  repo: IssueRepo,
  number: number,
  body: string,
  signal?: AbortSignal,
): Promise<void> {
  checkNumber(number);
  await client.request('POST', `${issuesBase(repo)}/${number}/comments`, { body }, signal);
}

export async function addIssueLabels(
  client: GitHubClient,
  repo: IssueRepo,
  number: number,
  labels: readonly string[],
  signal?: AbortSignal,
): Promise<void> {
  checkNumber(number);
  await client.request('POST', `${issuesBase(repo)}/${number}/labels`, { labels }, signal);
}

export async function closeIssue(
  client: GitHubClient,
  repo: IssueRepo,
  number: number,
  reason: 'completed' | 'not_planned',
  signal?: AbortSignal,
): Promise<void> {
  checkNumber(number);
  await client.request('PATCH', `${issuesBase(repo)}/${number}`, { state: 'closed', state_reason: reason }, signal);
}
