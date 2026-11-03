import { GitHubClient, validateRepo } from '../github/client';
import { REQUEST_LABEL, type AccessRequestInput } from './build';
import { G00passError } from '../errors';

/** Result of creating the request issue. Contains no secrets. */
export interface SubmittedRequest {
  requestsRepo: string;
  issueNumber: number;
  url: string;
  labelled: boolean;
}

export class SubmitError extends G00passError {}

export function parseOwnerRepo(s: string): { owner: string; repo: string } {
  const m = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(s.trim());
  if (!m) throw new SubmitError('Repository must look like owner/name.');
  const r = { owner: m[1] as string, repo: m[2] as string };
  validateRepo({ ...r, branch: 'main' });
  return r;
}

/**
 * Optional prefill from an invite (Phase 2). The invite flow supplies the
 * same fields; the token is handed to a memory-only TokenStore by the caller.
 */
export interface RequestPrefill {
  folder?: string;
  role?: AccessRequestInput['role'];
  inviteId?: string;
  requestsRepo?: string;
}

/** Where requests go: explicit requestsRepo, else the store repo (with a warning). */
export function resolveRequestsRepo(storeRepo: string, requestsRepo?: string | null): { repo: string; fallback: boolean } {
  const r = requestsRepo?.trim();
  return r ? { repo: r, fallback: false } : { repo: storeRepo, fallback: true };
}

export function requestsRepoWarning(fallback: boolean): string | null {
  return fallback
    ? 'No separate requests repo is configured, so requests go to the store repo. A separate private requests repo is recommended: an invite token with issues access can read every issue in its repo.'
    : null;
}

/**
 * POST /repos/{requestsRepo}/issues with the access-request label.
 * Errors never include the token (the client redacts it).
 */
export async function createAccessRequestIssue(
  client: GitHubClient,
  requestsRepo: string,
  built: { title: string; body: string },
  signal?: AbortSignal,
): Promise<SubmittedRequest> {
  const { owner, repo } = parseOwnerRepo(requestsRepo);
  const issue = await client.createIssue({ owner, repo }, { title: built.title, body: built.body, labels: [REQUEST_LABEL] }, signal);
  const labelled = issue.labels.some((l) => l === REQUEST_LABEL);
  // Never trust the response for a link target: pin it to github.com.
  const url = issue.html_url.startsWith('https://github.com/') ? issue.html_url : `https://github.com/${owner}/${repo}/issues/${issue.number}`;
  return { requestsRepo: `${owner}/${repo}`, issueNumber: issue.number, url, labelled };
}

/** User-facing explanation for a failed submission. Never includes the token. */
export function describeSubmitError(e: unknown): string {
  const status = (e as { status?: unknown })?.status;
  if (status === 401) return 'GitHub rejected the token (invalid or expired).';
  if (status === 403 || status === 404)
    return 'This token cannot create issues in the requests repo. It needs "Issues: Read and write" on that repository (or the repo name is wrong).';
  if (status === 410) return 'Issues are disabled on the requests repo.';
  if (status === 422) return 'GitHub refused the request (validation failed).';
  if (e instanceof G00passError) return e.message;
  return 'Could not submit the request.';
}
