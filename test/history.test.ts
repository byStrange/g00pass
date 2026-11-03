import { describe, expect, it } from 'vitest';
import { GitHubClient, GitHubFileHistory, bytesToBase64 } from '../src/core';

describe('GitHubFileHistory', () => {
  it('lists commits reachable from the snapshot commit and reads files at each commit', async () => {
    const calls: string[] = [];
    const head = 'a'.repeat(40);
    const older = 'b'.repeat(40);
    const fetch = (async (url: string) => {
      calls.push(url);
      const u = new URL(url);
      const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status });
      if (u.pathname === '/repos/acme/secrets/commits') return json([{ sha: head }, { sha: 'not-a-sha' }, { sha: older }]);
      if (u.pathname === '/repos/acme/secrets/contents/store/infra/.g00pass-admins.json') {
        return json({ type: 'file', encoding: 'base64', content: bytesToBase64(new TextEncoder().encode(u.searchParams.get('ref')!)) });
      }
      return json({ message: 'Not Found' }, 404);
    }) as typeof globalThis.fetch;
    const client = new GitHubClient({ token: () => 'github_pat_x', fetch });
    const h = new GitHubFileHistory(client, { owner: 'acme', repo: 'secrets', branch: 'main', storeRoot: 'store' }, head);
    const out = [];
    for await (const v of h.versions('infra/.g00pass-admins.json', ['infra/.g00pass-admins.json.sig'], { limit: 5 })) out.push(v);
    expect(out.map((v) => v.commitSha)).toEqual([head, older]);
    expect(new TextDecoder().decode(out[1]!.files[0]!)).toBe(older);
    expect(out[1]!.files[1]).toBeNull();
    const list = new URL(calls[0]!);
    expect(list.searchParams.get('sha')).toBe(head); // bound to the snapshot commit, not the branch
    expect(list.searchParams.get('path')).toBe('store/infra/.g00pass-admins.json');
  });

  it('merges(): pages the compare API, returns merge commits, fails closed on non-linear or huge ranges', async () => {
    const head = 'a'.repeat(40);
    const base = 'b'.repeat(40);
    const c = (n: number, parents: number) => ({ sha: n.toString(16).padStart(40, '0'), parents: Array.from({ length: parents }, (_, i) => ({ sha: (n * 10 + i + 1).toString(16).padStart(40, '0') })) });
    let reply: (page: number) => unknown = () => ({});
    const fetch = (async (url: string) => {
      const u = new URL(url);
      expect(u.pathname).toBe(`/repos/acme/secrets/compare/${base}...${head}`);
      return new Response(JSON.stringify(reply(Number(u.searchParams.get('page')))), { status: 200 });
    }) as typeof globalThis.fetch;
    const h = new GitHubFileHistory(new GitHubClient({ token: () => null, fetch }), { owner: 'acme', repo: 'secrets', branch: 'main' }, head);
    reply = (page) => ({ status: 'ahead', total_commits: 150, commits: page === 1 ? Array.from({ length: 100 }, (_, i) => c(i + 1, i === 5 ? 2 : 1)) : Array.from({ length: 50 }, (_, i) => c(i + 200, 1)) });
    expect((await h.merges(base, {}))?.map((m) => m.sha)).toEqual([c(6, 2).sha]);
    reply = () => ({ status: 'diverged', total_commits: 1, commits: [c(1, 1)] });
    expect(await h.merges(base, {})).toBeNull();
    reply = () => ({ status: 'ahead', total_commits: 5000, commits: [] });
    expect(await h.merges(base, {})).toBeNull();
    expect(await h.merges(head, {})).toEqual([]);
    expect(await h.merges('nope', {})).toBeNull();
  });
});
