import { createHash } from 'node:crypto';

/**
 * In-memory GitHub for the browser e2e run (Playwright routes
 * https://api.github.com/** here). Covers what g00pass uses: Git Data API,
 * commits?path history, contents?ref, compare, issues. Tokens are scoped
 * like fine-grained PATs: per repo, `contents` (read|write) and `issues`.
 */
interface Commit {
  tree: Map<string, string>;
  parents: string[];
  message: string;
}
interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  state_reason: string | null;
  labels: string[];
  comments: string[];
}
interface Repo {
  blobs: Map<string, Uint8Array>;
  trees: Map<string, Map<string, string>>;
  commits: Map<string, Commit>;
  refs: Map<string, string>;
  issues: Issue[];
}
export interface TokenScope {
  [repo: string]: { contents?: 'read' | 'write'; issues?: boolean };
}

let n = 0;
const sha = (s: string) => createHash('sha1').update(`${n++}:${s}`).digest('hex');

export class FakeGitHubServer {
  readonly repos = new Map<string, Repo>();
  readonly tokens = new Map<string, TokenScope>();
  readonly log: string[] = [];

  repo(full: string): Repo {
    let r = this.repos.get(full);
    if (!r) this.repos.set(full, (r = { blobs: new Map(), trees: new Map(), commits: new Map(), refs: new Map(), issues: [] }));
    return r;
  }

  seed(full: string, branch: string, files: ReadonlyMap<string, Uint8Array>): string {
    const r = this.repo(full);
    const tree = new Map<string, string>();
    for (const [p, b] of files) tree.set(p, this.putBlob(r, b));
    const t = sha('tree');
    r.trees.set(t, tree);
    const c = sha('commit');
    r.commits.set(c, { tree, parents: [], message: 'seed' });
    r.refs.set(branch, c);
    return c;
  }

  head(full: string, branch = 'main'): Map<string, Uint8Array> {
    const r = this.repo(full);
    const c = r.commits.get(r.refs.get(branch)!)!;
    return new Map([...c.tree].map(([p, s]) => [p, r.blobs.get(s)!]));
  }

  private putBlob(r: Repo, b: Uint8Array): string {
    const s = createHash('sha1').update(b).digest('hex');
    r.blobs.set(s, b);
    return s;
  }

  private allowed(token: string | null, repo: string, need: 'contents-read' | 'contents-write' | 'issues' | 'meta'): boolean {
    const scope = token ? this.tokens.get(token)?.[repo] : undefined;
    if (!scope) return false;
    if (need === 'meta') return true;
    if (need === 'issues') return !!scope.issues;
    if (need === 'contents-read') return !!scope.contents;
    return scope.contents === 'write';
  }

  private history(r: Repo, from: string): string[] {
    const out: string[] = [];
    for (let c: string | undefined = from; c; c = r.commits.get(c)?.parents[0]) out.push(c);
    return out;
  }

  handle(method: string, url: string, headers: Record<string, string>, bodyText: string | null): { status: number; body: unknown } {
    const u = new URL(url);
    const token = (headers.authorization ?? headers.Authorization ?? '').replace(/^Bearer /, '') || null;
    const body = bodyText ? (JSON.parse(bodyText) as Record<string, unknown>) : undefined;
    this.log.push(`${method} ${u.pathname}${u.search}`);
    const m0 = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(u.pathname);
    if (!m0) return { status: 404, body: { message: 'Not Found' } };
    const full = `${m0[1]}/${m0[2]}`;
    const rest = decodeURIComponent(m0[3] ?? '');
    if (!this.repos.has(full)) return { status: 404, body: { message: 'Not Found' } };
    const r = this.repo(full);
    const deny = { status: 404, body: { message: 'Not Found' } };
    const ok = (b: unknown, status = 200) => ({ status, body: b });
    let m: RegExpExecArray | null;

    if (rest === '' && method === 'GET') return this.allowed(token, full, 'meta') ? ok({ full_name: full, private: true }) : deny;

    // ---- issues ----
    if (rest.startsWith('/issues')) {
      if (!this.allowed(token, full, 'issues')) return { status: 403, body: { message: 'Resource not accessible by personal access token' } };
      const view = (i: Issue) => ({ number: i.number, title: i.title, body: i.body, state: i.state, labels: i.labels.map((name) => ({ name })), html_url: `https://github.com/${full}/issues/${i.number}`, user: { login: 'someone' }, created_at: '2026-11-03T00:00:00Z' });
      if (rest === '/issues' && method === 'GET') return ok(u.searchParams.get('page') === '1' || !u.searchParams.get('page') ? r.issues.filter((i) => i.state === 'open').reverse().map(view) : []);
      if (rest === '/issues' && method === 'POST') {
        const i: Issue = { number: r.issues.length + 1, title: String(body!.title), body: String(body!.body), state: 'open', state_reason: null, labels: (body!.labels as string[]) ?? [], comments: [] };
        r.issues.push(i);
        return ok(view(i), 201);
      }
      if ((m = /^\/issues\/(\d+)(\/comments|\/labels)?$/.exec(rest))) {
        const i = r.issues.find((x) => x.number === Number(m![1]));
        if (!i) return deny;
        if (!m[2] && method === 'GET') return ok(view(i));
        if (!m[2] && method === 'PATCH') {
          if (body!.state) i.state = body!.state as 'closed';
          i.state_reason = (body!.state_reason as string) ?? null;
          return ok(view(i));
        }
        if (m[2] === '/comments' && method === 'POST') {
          i.comments.push(String(body!.body));
          return ok({ id: i.comments.length }, 201);
        }
        if (m[2] === '/labels' && method === 'POST') {
          i.labels.push(...(body!.labels as string[]));
          return ok(i.labels.map((name) => ({ name })));
        }
      }
      return deny;
    }

    // ---- contents ----
    const read = this.allowed(token, full, 'contents-read');
    if (!read) return deny;
    if (method === 'GET' && rest === '/commits') {
      const from = u.searchParams.get('sha')!;
      const path = u.searchParams.get('path')!;
      const per = Number(u.searchParams.get('per_page') ?? 30);
      const out: { sha: string }[] = [];
      for (const c of this.history(r, from)) {
        const cur = r.commits.get(c)!;
        const parent = cur.parents[0] ? r.commits.get(cur.parents[0])! : null;
        if (cur.tree.get(path) !== parent?.tree.get(path)) out.push({ sha: c });
        if (out.length >= per) break;
      }
      return ok(out);
    }
    if (method === 'GET' && (m = /^\/compare\/([0-9a-f]{40})\.\.\.([0-9a-f]{40})$/.exec(rest))) {
      const h = this.history(r, m[2]!);
      const idx = h.indexOf(m[1]!);
      if (idx === -1) return ok({ status: 'diverged', total_commits: 0, commits: [] });
      const range = h.slice(0, idx).reverse();
      return ok({ status: range.length ? 'ahead' : 'identical', total_commits: range.length, commits: range.map((c) => ({ sha: c, parents: r.commits.get(c)!.parents.map((p) => ({ sha: p })) })) });
    }
    if (method === 'GET' && (m = /^\/contents\/(.+)$/.exec(rest))) {
      const c = r.commits.get(u.searchParams.get('ref')!);
      const s = c?.tree.get(m[1]!);
      return s ? ok({ type: 'file', encoding: 'base64', content: Buffer.from(r.blobs.get(s)!).toString('base64') }) : deny;
    }
    if (method === 'GET' && (m = /^\/git\/ref\/heads\/(.+)$/.exec(rest))) {
      const s = r.refs.get(m[1]!);
      return s ? ok({ object: { sha: s, type: 'commit' } }) : deny;
    }
    if (method === 'GET' && (m = /^\/git\/commits\/([0-9a-f]+)$/.exec(rest))) {
      const c = r.commits.get(m[1]!);
      return c ? ok({ sha: m[1], tree: { sha: `t${m[1]}` } }) : deny;
    }
    if (method === 'GET' && (m = /^\/git\/trees\/t([0-9a-f]+)$/.exec(rest))) {
      const c = r.commits.get(m[1]!);
      return c ? ok({ sha: `t${m[1]}`, truncated: false, tree: [...c.tree].map(([path, s]) => ({ path, type: 'blob', mode: '100644', sha: s })) }) : deny;
    }
    if (method === 'GET' && (m = /^\/git\/blobs\/([0-9a-f]+)$/.exec(rest))) {
      const b = r.blobs.get(m[1]!);
      return b ? ok({ encoding: 'base64', content: Buffer.from(b).toString('base64') }) : deny;
    }
    if (!this.allowed(token, full, 'contents-write')) return { status: 403, body: { message: 'Resource not accessible by personal access token' } };
    if (method === 'POST' && rest === '/git/blobs') return ok({ sha: this.putBlob(r, Buffer.from(String(body!.content), 'base64')) }, 201);
    if (method === 'POST' && rest === '/git/trees') {
      const base = r.commits.get(String(body!.base_tree).slice(1));
      if (!base) return { status: 422, body: { message: 'bad base tree' } };
      const t = new Map(base.tree);
      for (const e of body!.tree as { path: string; sha?: string | null; content?: string }[]) {
        if (e.content !== undefined) t.set(e.path, this.putBlob(r, new TextEncoder().encode(e.content)));
        else if (e.sha === null) t.delete(e.path);
        else t.set(e.path, e.sha!);
      }
      const id = sha('tree');
      r.trees.set(id, t);
      return ok({ sha: id }, 201);
    }
    if (method === 'POST' && rest === '/git/commits') {
      const tree = r.trees.get(String(body!.tree));
      if (!tree) return { status: 422, body: { message: 'bad tree' } };
      const c = sha('commit');
      r.commits.set(c, { tree, parents: body!.parents as string[], message: String(body!.message) });
      return ok({ sha: c }, 201);
    }
    if (method === 'PATCH' && (m = /^\/git\/refs\/heads\/(.+)$/.exec(rest))) {
      const cur = r.refs.get(m[1]!);
      const next = String(body!.sha);
      if (!cur || !this.history(r, next).includes(cur)) return { status: 422, body: { message: 'Update is not a fast forward' } };
      r.refs.set(m[1]!, next);
      return ok({ object: { sha: next } });
    }
    return { status: 404, body: { message: `unhandled ${method} ${rest}` } };
  }
}
