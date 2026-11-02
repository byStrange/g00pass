import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ConflictError,
  GitHubApiError,
  GitHubClient,
  GitHubSnapshot,
  GitHubWriter,
  TokenStore,
  commitChanges,
  passThroughTrustHook,
  readEntry,
  setTrustHook,
  withConflictRetry,
  writeEntry,
  type GitHubRepo,
} from '../src/core';
import { FakeGitHub } from './helpers/fakeGitHub';
import { type TestIdentity, dec, decryptText, enc, encryptForTest, makeIdentity } from './helpers/keys';

const TOKEN = 'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH';
let gh: FakeGitHub;
let client: GitHubClient;
let alice: TestIdentity;
const repo: GitHubRepo = { owner: 'acme', repo: 'secrets', branch: 'main' };

beforeAll(async () => {
  alice = await makeIdentity('Alice');
});
beforeEach(() => {
  setTrustHook(passThroughTrustHook);
  gh = new FakeGitHub();
  client = new GitHubClient({ token: () => TOKEN, fetch: gh.fetch as typeof fetch });
});

describe('GitHubSnapshot', () => {
  it('lists blobs relative to storeRoot and reads base64 blobs', async () => {
    gh.seed('main', { 'README.md': 'hi', 'store/.gpg-id': 'X\n', 'store/a/b.gpg': new Uint8Array([0, 255, 1]) });
    const s = await GitHubSnapshot.load(client, { ...repo, storeRoot: 'store' });
    expect(s.listFiles()).toEqual(['.gpg-id', 'a/b.gpg']);
    expect([...(await s.readFile('a/b.gpg'))!]).toEqual([0, 255, 1]);
    expect(await s.readFile('nope')).toBeNull();
    expect(s.commitSha).toBe(gh.refs.get('main'));
  });

  it('sends the token only as a Bearer header to the API origin', async () => {
    gh.seed('main', { x: 'y' });
    await GitHubSnapshot.load(client, repo);
    for (const r of gh.requests) {
      expect(r.url.startsWith('https://api.github.com/')).toBe(true);
      expect(r.url).not.toContain(TOKEN);
      expect(r.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    }
  });
});

describe('commitChanges (Git Data API)', () => {
  it('creates blobs -> tree -> commit -> fast-forward ref, atomically', async () => {
    const base = gh.seed('main', { 'store/keep.txt': 'k', 'store/old.gpg': 'o', 'outside.txt': 'z' });
    const res = await commitChanges(
      client,
      { ...repo, storeRoot: 'store' },
      [
        { path: 'a.gpg', content: new Uint8Array([1, 2, 3]) },
        { path: '.gpg-id', content: 'ABC\n' },
        { path: 'old.gpg', delete: true },
      ],
      { baseSha: base, message: 'msg' },
    );
    const files = gh.filesAt('main');
    expect([...files.keys()].sort()).toEqual(['outside.txt', 'store/.gpg-id', 'store/a.gpg', 'store/keep.txt']);
    expect([...files.get('store/a.gpg')!]).toEqual([1, 2, 3]);
    expect(dec(files.get('store/.gpg-id')!)).toBe('ABC\n');
    expect(gh.refs.get('main')).toBe(res.commitSha);
    expect(gh.commits.get(res.commitSha)!.parents).toEqual([base]);
    const seq = gh.requests.map((r) => `${r.method} ${r.path.split('/git/')[1]}`);
    expect(seq).toEqual([
      'GET ref/heads/main',
      `GET commits/${base}`,
      'POST blobs',
      'POST trees',
      'POST commits',
      'PATCH refs/heads/main',
    ]);
    expect(gh.requests.at(-1)!.body).toEqual({ sha: res.commitSha, force: false });
  });

  it('fails fast with ConflictError if the branch moved before we start', async () => {
    const base = gh.seed('main', { a: '1' });
    const head = gh.seed('main', { a: '2' });
    const err = await commitChanges(client, repo, [{ path: 'b', content: 'x' }], { baseSha: base, message: 'm' }).catch((e) => e);
    expect(err).toBeInstanceOf(ConflictError);
    expect(err.actualSha).toBe(head);
    expect(gh.requests.filter((r) => r.method !== 'GET')).toHaveLength(0);
  });

  it('turns a concurrent push during the commit into ConflictError (no force push)', async () => {
    const base = gh.seed('main', { a: '1' });
    let concurrent = '';
    gh.beforePatch = () => {
      gh.beforePatch = null;
      concurrent = gh.seed('main', { a: 'someone else' });
    };
    const err = await commitChanges(client, repo, [{ path: 'b', content: 'x' }], { baseSha: base, message: 'm' }).catch((e) => e);
    expect(err).toBeInstanceOf(ConflictError);
    expect(err.retryable).toBe(true);
    expect(gh.refs.get('main')).toBe(concurrent);
    expect(dec(gh.filesAt('main').get('a')!)).toBe('someone else');
  });

  it('withConflictRetry recomputes from a fresh snapshot and succeeds', async () => {
    gh.seed('main', { 'n.txt': '0' });
    let raced = false;
    gh.beforePatch = () => {
      if (!raced) {
        raced = true;
        gh.seed('main', { 'n.txt': '5' });
      }
    };
    const attempts: number[] = [];
    await withConflictRetry(async (n) => {
      attempts.push(n);
      const snap = await GitHubSnapshot.load(client, repo);
      const cur = Number(dec((await snap.readFile('n.txt'))!));
      return commitChanges(client, repo, [{ path: 'n.txt', content: String(cur + 1) }], { baseSha: snap.commitSha, message: 'inc' });
    });
    expect(attempts).toEqual([1, 2]);
    expect(dec(gh.filesAt('main').get('n.txt')!)).toBe('6');
  });

  it('withConflictRetry gives up after max attempts', async () => {
    const e = new ConflictError('a'.repeat(40), 'b'.repeat(40));
    let n = 0;
    await expect(withConflictRetry(async () => { n++; throw e; }, { attempts: 2 })).rejects.toBe(e);
    expect(n).toBe(2);
  });

  it('validates inputs: duplicate paths, bad base sha, empty change set', async () => {
    const base = gh.seed('main', { a: '1' });
    await expect(commitChanges(client, repo, [], { baseSha: base, message: 'm' })).rejects.toThrow();
    await expect(commitChanges(client, repo, [{ path: 'x', content: 'a' }, { path: '/x', content: 'b' }], { baseSha: base, message: 'm' })).rejects.toThrow(/duplicate/);
    await expect(commitChanges(client, repo, [{ path: 'x', content: 'a' }], { baseSha: 'main', message: 'm' })).rejects.toThrow(/full commit sha/);
    await expect(commitChanges(client, { ...repo, owner: '../evil' }, [{ path: 'x', content: 'a' }], { baseSha: base, message: 'm' })).rejects.toThrow();
  });

  it('API errors never contain the token', async () => {
    gh.seed('main', { a: '1' });
    gh.failWith = { match: /GET .*\/ref\//, status: 401, message: `Bad credentials for ${TOKEN} Authorization: Bearer ${TOKEN}` };
    const err = await GitHubSnapshot.load(client, repo).catch((e) => e);
    expect(err).toBeInstanceOf(GitHubApiError);
    expect(err.status).toBe(401);
    expect(String(err.message)).not.toContain(TOKEN);
    expect(JSON.stringify(err)).not.toContain(TOKEN);
    expect(String(err.stack)).not.toContain(TOKEN);
  });
});

describe('entry write path through GitHub', () => {
  it('writeEntry encrypts to the nearest .gpg-id and commits; readEntry decrypts', async () => {
    gh.seed('main', {
      '.gpg-id': 'nobody@example.test\n',
      'team/.gpg-id': `${alice.fpr}\n`,
      [`.public-keys/${alice.fpr}`]: alice.armoredPublic,
      'team/old.gpg': await encryptForTest('old', [alice]),
    });
    const writer = new GitHubWriter(client, repo);
    await withConflictRetry(async () => {
      const snapshot = await GitHubSnapshot.load(client, repo);
      return writeEntry({ snapshot, writer, entry: 'team/new/thing', plaintext: enc('hunter2') });
    });
    const ct = gh.filesAt('main').get('team/new/thing.gpg')!;
    expect(await decryptText(ct, alice)).toBe('hunter2');
    const snap = await GitHubSnapshot.load(client, repo);
    expect(dec(await readEntry(snap, 'team/new/thing', [alice.priv]))).toBe('hunter2');
    expect(dec(await readEntry(snap, 'team/old.gpg', [alice.priv]))).toBe('old');
    // root .gpg-id recipient has no public key -> cannot write at root
    await expect(writeEntry({ snapshot: snap, writer, entry: 'rootlevel', plaintext: enc('x') })).rejects.toThrow(/no public key/);
  });
});

describe('TokenStore', () => {
  class FakeStorage {
    m = new Map<string, string>();
    getItem = (k: string) => this.m.get(k) ?? null;
    setItem = (k: string, v: string) => void this.m.set(k, v);
    removeItem = (k: string) => void this.m.delete(k);
  }
  it('memory by default; session only when chosen; never serializes', () => {
    const ss = new FakeStorage();
    const t = new TokenStore('memory', ss as unknown as Storage);
    t.set(' tok ');
    expect(t.get()).toBe('tok');
    expect(ss.m.size).toBe(0);
    t.set('tok2', 'session');
    expect([...ss.m.values()]).toEqual(['tok2']);
    expect(JSON.stringify({ t })).not.toContain('tok2');
    t.clear();
    expect(t.get()).toBeNull();
    expect(ss.m.size).toBe(0);
    ss.setItem('g00pass.gh-session', 'restored');
    expect(new TokenStore('session', ss as unknown as Storage).get()).toBe('restored');
  });
});
