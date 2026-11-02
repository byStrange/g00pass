import { describe, expect, it } from 'vitest';
import {
  GitHubApiError,
  GitHubClient,
  addIssueLabels,
  closeIssue,
  commentOnIssue,
  denyAccessRequest,
  finalizeApprovedIssue,
  listIssues,
} from '../src/core';

const TOKEN = 'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH';
type Call = { method: string; url: string; body: unknown; auth: string | undefined };

function mock(handler: (c: Call) => { status?: number; json?: unknown }) {
  const calls: Call[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    const call: Call = {
      method: init.method ?? 'GET',
      url,
      body: init.body ? JSON.parse(init.body as string) : undefined,
      auth: (init.headers as Record<string, string>).Authorization,
    };
    calls.push(call);
    const r = handler(call);
    const status = r.status ?? 200;
    return new Response(r.json === undefined ? null : JSON.stringify(r.json), { status });
  }) as unknown as typeof fetch;
  return { calls, client: new GitHubClient({ token: () => TOKEN, fetch: fetchFn }) };
}
const repo = { owner: 'acme', repo: 'requests' };

describe('issue API', () => {
  it('listIssues: open issues, skips PRs, normalises fields, paginates', async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({ number: i + 1, title: 'a', body: i === 0 ? null : 'b', state: 'open', labels: ['x', { name: 'y' }], user: { login: 'u' } }));
    const { calls, client } = mock((c) =>
      c.url.endsWith('&page=1') ? { json: [{ number: 500, pull_request: {} }, ...page1.slice(1)] } : { json: [{ number: 9, title: 7 }] },
    );
    const out = await listIssues(client, repo);
    expect(calls.map((c) => c.url)).toEqual([
      'https://api.github.com/repos/acme/requests/issues?state=open&sort=created&direction=desc&per_page=100&page=1',
      'https://api.github.com/repos/acme/requests/issues?state=open&sort=created&direction=desc&per_page=100&page=2',
    ]);
    expect(out.find((i) => i.number === 500)).toBeUndefined();
    expect(out.at(-1)).toMatchObject({ number: 9, title: '', body: null });
    expect(out[0]!.labels).toEqual(['x', 'y']);
    expect(calls[0]!.auth).toBe(`Bearer ${TOKEN}`);
    expect(calls.every((c) => !c.url.includes(TOKEN))).toBe(true);
  });

  it('stops at maxPages and on a short page', async () => {
    const { calls, client } = mock(() => ({ json: Array.from({ length: 100 }, (_, i) => ({ number: i + 1 })) }));
    await listIssues(client, repo, { maxPages: 2 });
    expect(calls).toHaveLength(2);
  });

  it('comment / label / close use the right endpoints and payloads', async () => {
    const { calls, client } = mock(() => ({ json: {} }));
    await commentOnIssue(client, repo, 12, 'hello');
    await addIssueLabels(client, repo, 12, ['g00pass:approved']);
    await closeIssue(client, repo, 12, 'completed');
    expect(calls.map((c) => [c.method, c.url.replace('https://api.github.com', ''), c.body])).toEqual([
      ['POST', '/repos/acme/requests/issues/12/comments', { body: 'hello' }],
      ['POST', '/repos/acme/requests/issues/12/labels', { labels: ['g00pass:approved'] }],
      ['PATCH', '/repos/acme/requests/issues/12', { state: 'closed', state_reason: 'completed' }],
    ]);
  });

  it('rejects bad issue numbers and repo names before any request', async () => {
    const { calls, client } = mock(() => ({ json: {} }));
    await expect(commentOnIssue(client, repo, 0, 'x')).rejects.toThrow();
    await expect(closeIssue(client, repo, 1.5, 'completed')).rejects.toThrow();
    await expect(listIssues(client, { owner: '../x', repo: 'y' })).rejects.toThrow();
    expect(calls).toHaveLength(0);
  });

  it('surfaces API errors without the token', async () => {
    const { client } = mock(() => ({ status: 403, json: { message: `bad ${TOKEN}` } }));
    const e = await listIssues(client, repo).catch((x) => x);
    expect(e).toBeInstanceOf(GitHubApiError);
    expect(e.message).not.toContain(TOKEN);
  });

  it('finalizeApprovedIssue: comment with sha, label, close as completed; reports failed best-effort steps', async () => {
    const { calls, client } = mock((c) => (c.url.endsWith('/labels') ? { status: 403, json: { message: 'no' } } : { json: {} }));
    const failed = await finalizeApprovedIssue(client, repo, 3, { commitSha: 'abc123', operatorFingerprint: 'F'.repeat(40) });
    expect(failed).toEqual(['label']);
    expect((calls[0]!.body as { body: string }).body).toContain('abc123');
    expect(calls[2]!.body).toEqual({ state: 'closed', state_reason: 'completed' });
  });

  it('denyAccessRequest: optional sanitised reason, closes as not_planned', async () => {
    const { calls, client } = mock(() => ({ json: {} }));
    await denyAccessRequest(client, repo, 4, 'not on the team\u0000\u0007');
    expect((calls[0]!.body as { body: string }).body).toBe('Access request denied.\n\nReason: not on the team');
    expect(calls[1]!.body).toEqual({ labels: ['g00pass:rejected'] });
    expect(calls[2]!.body).toEqual({ state: 'closed', state_reason: 'not_planned' });
    calls.length = 0;
    await denyAccessRequest(client, repo, 4);
    expect((calls[0]!.body as { body: string }).body).toBe('Access request denied.');
  });
});
