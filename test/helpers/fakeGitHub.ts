import { createHash } from 'node:crypto';

/**
 * In-memory fake of the GitHub Git Data API subset used by g00pass.
 * Trees are stored flat (path -> blob sha) which is all the client needs.
 */
interface Commit {
  tree: string;
  parents: string[];
  message: string;
}

export interface RecordedRequest {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

let counter = 0;
const sha = (kind: string, data: string) =>
  createHash('sha1').update(`${kind}:${counter++}:${data}`).digest('hex');

export class FakeGitHub {
  blobs = new Map<string, Uint8Array>();
  trees = new Map<string, Map<string, string>>();
  commits = new Map<string, Commit>();
  refs = new Map<string, string>();
  requests: RecordedRequest[] = [];
  /** Called right before the ref PATCH is applied (simulate a concurrent push). */
  beforePatch: (() => void) | null = null;
  /** Force an error status for matching requests. */
  failWith: { match: RegExp; status: number; message: string } | null = null;

  constructor(
    readonly owner = 'acme',
    readonly repo = 'secrets',
  ) {}

  /** Create an initial commit on `branch` with the given files. */
  seed(branch: string, files: Record<string, Uint8Array | string>): string {
    const tree = new Map<string, string>();
    for (const [p, c] of Object.entries(files)) tree.set(p, this.putBlob(typeof c === 'string' ? new TextEncoder().encode(c) : c));
    const treeSha = sha('tree', JSON.stringify([...tree]));
    this.trees.set(treeSha, tree);
    const parent = this.refs.get(branch);
    const c = sha('commit', treeSha);
    this.commits.set(c, { tree: treeSha, parents: parent ? [parent] : [], message: 'seed' });
    this.refs.set(branch, c);
    return c;
  }

  putBlob(b: Uint8Array): string {
    const s = sha('blob', Buffer.from(b).toString('base64'));
    this.blobs.set(s, b);
    return s;
  }

  filesAt(branch: string): Map<string, Uint8Array> {
    const c = this.commits.get(this.refs.get(branch)!)!;
    const out = new Map<string, Uint8Array>();
    for (const [p, s] of this.trees.get(c.tree)!) out.set(p, this.blobs.get(s)!);
    return out;
  }

  private isAncestor(anc: string, desc: string): boolean {
    if (anc === desc) return true;
    const c = this.commits.get(desc);
    return !!c && c.parents.some((p) => this.isAncestor(anc, p));
  }

  fetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = String(input);
    const u = new URL(url);
    const method = (init.method ?? 'GET').toUpperCase();
    const headers = { ...(init.headers as Record<string, string>) };
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    this.requests.push({ method, url, path: u.pathname + u.search, headers, body });
    const json = (status: number, data: unknown) =>
      new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

    if (this.failWith && this.failWith.match.test(`${method} ${u.pathname}`)) {
      return json(this.failWith.status, { message: this.failWith.message });
    }
    const prefix = `/repos/${this.owner}/${this.repo}/git/`;
    if (!u.pathname.startsWith(prefix)) return json(404, { message: 'Not Found' });
    const rest = decodeURIComponent(u.pathname.slice(prefix.length));

    let m: RegExpExecArray | null;
    if (method === 'GET' && (m = /^ref\/heads\/(.+)$/.exec(rest))) {
      const s = this.refs.get(m[1]!);
      return s ? json(200, { ref: `refs/heads/${m[1]}`, object: { sha: s, type: 'commit' } }) : json(404, { message: 'Not Found' });
    }
    if (method === 'GET' && (m = /^commits\/([0-9a-f]+)$/.exec(rest))) {
      const c = this.commits.get(m[1]!);
      return c ? json(200, { sha: m[1], tree: { sha: c.tree }, parents: c.parents.map((p) => ({ sha: p })) }) : json(404, { message: 'Not Found' });
    }
    if (method === 'GET' && (m = /^trees\/([0-9a-f]+)$/.exec(rest))) {
      const t = this.trees.get(m[1]!);
      if (!t) return json(404, { message: 'Not Found' });
      return json(200, {
        sha: m[1],
        truncated: false,
        tree: [...t].map(([path, s]) => ({ path, type: 'blob', mode: '100644', sha: s })),
      });
    }
    if (method === 'GET' && (m = /^blobs\/([0-9a-f]+)$/.exec(rest))) {
      const b = this.blobs.get(m[1]!);
      return b ? json(200, { sha: m[1], encoding: 'base64', content: Buffer.from(b).toString('base64') }) : json(404, { message: 'Not Found' });
    }
    if (method === 'POST' && rest === 'blobs') {
      const b = body as { content: string; encoding: string };
      if (b.encoding !== 'base64') return json(422, { message: 'bad encoding' });
      return json(201, { sha: this.putBlob(new Uint8Array(Buffer.from(b.content, 'base64'))) });
    }
    if (method === 'POST' && rest === 'trees') {
      const b = body as { base_tree: string; tree: { path: string; sha?: string | null; content?: string }[] };
      const base = this.trees.get(b.base_tree);
      if (!base) return json(422, { message: 'bad base tree' });
      const t = new Map(base);
      for (const e of b.tree) {
        if (e.content !== undefined) t.set(e.path, this.putBlob(new TextEncoder().encode(e.content)));
        else if (e.sha === null) t.delete(e.path);
        else if (e.sha && this.blobs.has(e.sha)) t.set(e.path, e.sha);
        else return json(422, { message: 'bad tree entry' });
      }
      const s = sha('tree', JSON.stringify([...t]));
      this.trees.set(s, t);
      return json(201, { sha: s });
    }
    if (method === 'POST' && rest === 'commits') {
      const b = body as { message: string; tree: string; parents: string[] };
      if (!this.trees.has(b.tree)) return json(422, { message: 'bad tree' });
      const s = sha('commit', b.tree + b.parents.join());
      this.commits.set(s, { tree: b.tree, parents: b.parents, message: b.message });
      return json(201, { sha: s });
    }
    if (method === 'PATCH' && (m = /^refs\/heads\/(.+)$/.exec(rest))) {
      this.beforePatch?.();
      const b = body as { sha: string; force?: boolean };
      const cur = this.refs.get(m[1]!);
      if (!cur) return json(422, { message: 'Reference does not exist' });
      if (!b.force && !this.isAncestor(cur, b.sha)) return json(422, { message: 'Update is not a fast forward' });
      this.refs.set(m[1]!, b.sha);
      return json(200, { object: { sha: b.sha } });
    }
    return json(404, { message: `unhandled ${method} ${rest}` });
  };
}
