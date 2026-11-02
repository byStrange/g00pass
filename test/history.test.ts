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
});
