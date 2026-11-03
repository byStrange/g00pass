import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  GitHubClient,
  INVITE_FRAGMENT,
  MemoryStore,
  MemoryWriter,
  approveAccessRequest,
  buildInbox,
  canonicalJson,
  inviteRecordPath,
  issueInvite,
  parseAccessRequest,
  passThroughTrustHook,
  pinAnchors,
  previewApproval,
  probeInviteToken,
  resetTrustEnvironment,
  setTrustHook,
  signDetached,
  signatureTrustHook,
  takeInviteFromLocation,
  validateInvite,
  verifyInviteRecord,
  type InvitePayload,
} from '../src/core';
import { type TestIdentity, encryptForTest, makeIdentity } from './helpers/keys';
import { buildBody } from './helpers/requests';
import { STORE_ID, adminsFiles, freshEnv, signedGpgId } from './helpers/trust';

let A: TestIdentity, C: TestIdentity, M: TestIdentity, N: TestIdentity, E: TestIdentity;
const TOKEN = 'github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef';
const repo = { owner: 'acme', repo: 'secrets', branch: 'main', storeRoot: '', requestsRepo: 'acme/requests' };
const keys = (...ids: TestIdentity[]) => Object.fromEntries(ids.map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic]));
const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: unknown) => (e as { code?: string }).code ?? `other:${(e as Error).message}`);

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, C, M, N, E] = (await Promise.all(['A', 'C', 'M', 'N', 'E'].map((n) => makeIdentity(n, born)))) as [TestIdentity, TestIdentity, TestIdentity, TestIdentity, TestIdentity];
  setTrustHook(signatureTrustHook);
});
afterAll(() => {
  setTrustHook(passThroughTrustHook);
  resetTrustEnvironment();
});
beforeEach(() => {
  freshEnv();
  pinAnchors(STORE_ID, [A.fpr], 'first-use');
});

async function store(sha: string) {
  const s = new MemoryStore({
    ...keys(A, C, M, N, E),
    ...(await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv, { children: ['team'] })),
    ...(await signedGpgId('team', `${A.fpr}\n${C.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv)),
    'team/db.gpg': await encryptForTest('db', [A, C, E]),
  }, sha);
  for (const [p, c] of Object.entries(await adminsFiles(s, 'team', [C.fpr], A.priv))) s.set(p, c);
  return s;
}

const fakeLocation = (link: string) => {
  const u = new URL(link);
  return { hash: u.hash, pathname: u.pathname, search: u.search };
};

async function request(id: TestIdentity, over: Record<string, unknown>) {
  const r = await parseAccessRequest(await buildBody(id, { folder: 'team', ...over }), { repo: 'acme/secrets', storeRoot: '' });
  if (!r.ok) throw new Error(r.message);
  return r.request;
}

describe('invites: link, registry, approval', () => {
  it('a folder admin issues an invite; the newcomer link is stripped from history at once and parsed', async () => {
    const s = await store('i0');
    const inv = await issueInvite({ snapshot: s, writer: new MemoryWriter(s), repo, folder: 'team', role: 'reader', days: 7, token: TOKEN, appUrl: 'https://vault.example/', operatorKey: C.priv });
    expect(s.hasFile(inviteRecordPath(inv.id))).toBe(true);
    expect(new TextDecoder().decode((await s.readFile(inviteRecordPath(inv.id)))!)).not.toContain('github_pat_');
    expect(inv.link.startsWith('https://vault.example/' + INVITE_FRAGMENT)).toBe(true);

    const calls: string[] = [];
    const taken = takeInviteFromLocation(fakeLocation(inv.link), { replaceState: (_d: unknown, _t: string, url?: string | URL | null) => void calls.push(String(url)) });
    expect(calls).toEqual(['/']);
    if (taken.kind !== 'invite') throw new Error(JSON.stringify(taken));
    expect(taken.invite).toMatchObject({ folder: 'team', role: 'reader', anchors: [A.fpr], requestsRepo: 'acme/requests', issuedBy: C.fpr, id: inv.id });
    expect(taken.invite.token).toBe(TOKEN);
    expect(JSON.stringify(taken.invite)).not.toContain('github_pat_'); // token is non-enumerable
    expect(await verifyInviteRecord(s, inv.id, { folder: 'team', role: 'reader' })).toMatchObject({ valid: true });
  });

  it('approval with a valid invite needs no uninvited acknowledgement and consumes the record in the same commit', async () => {
    const s = await store('i1');
    const inv = await issueInvite({ snapshot: s, writer: new MemoryWriter(s), repo, folder: 'team', role: 'reader', days: 3, token: TOKEN, appUrl: 'https://vault.example/', operatorKey: A.priv });
    const req = await request(N, { inviteId: inv.id });
    const inbox = await buildInbox({ issues: [{ number: 1, title: 't', body: await buildBody(N, { folder: 'team', inviteId: inv.id }), state: 'open', labels: [], author: null, htmlUrl: null, createdAt: null }], snapshot: s, store: { repo: 'acme/secrets', storeRoot: '' }, operatorFingerprint: C.fpr });
    expect(inbox.actionable[0]!.invite).toMatchObject({ valid: true });
    const plan = await previewApproval(s, req, C.fpr);
    const w = new MemoryWriter(s);
    const res = await approveAccessRequest(req, {
      loadSnapshot: async () => s, writer: w, operatorKey: C.priv, requestRef: 'acme/requests#1',
      confirmation: { fingerprintSuffix: N.fpr.slice(-16), approvedPlan: plan.digest },
    });
    expect(res.inviteConsumed).toBe(true);
    expect(w.commits).toHaveLength(1);
    expect(s.hasFile(inviteRecordPath(inv.id))).toBe(false);

    // Single use: another request naming the same invite now needs the acknowledgement.
    const again = await request(M, { inviteId: inv.id });
    const plan2 = await previewApproval(s, again, C.fpr);
    expect(await code(approveAccessRequest(again, {
      loadSnapshot: async () => s, writer: new MemoryWriter(s), operatorKey: C.priv, requestRef: 'r#2',
      confirmation: { fingerprintSuffix: M.fpr.slice(-16), approvedPlan: plan2.digest },
    }))).toBe('invite-not-acknowledged');
  });

  it('records that do not match, are expired, or were signed by a non-admin are not valid', async () => {
    const s = await store('i2');
    const inv = await issueInvite({ snapshot: s, writer: new MemoryWriter(s), repo, folder: 'team', role: 'reader', days: 1, token: TOKEN, appUrl: 'https://vault.example/', operatorKey: C.priv });
    expect(await verifyInviteRecord(s, inv.id, { folder: 'team', role: 'folder-admin' })).toMatchObject({ valid: false, reason: expect.stringContaining('role') });
    expect(await verifyInviteRecord(s, inv.id, { folder: 'other', role: 'reader' })).toMatchObject({ valid: false });
    expect(await verifyInviteRecord(s, inv.id, { folder: 'team', role: 'reader', now: new Date(Date.now() + 2 * 86400_000) })).toMatchObject({ valid: false, reason: expect.stringContaining('expired') });
    // A writer who is not an admin forges a record signed with their own key.
    const forged = { createdAt: '2026-01-01T00:00:00Z', expiresAt: new Date(Date.now() + 86400_000).toISOString().replace(/\.\d{3}Z$/, 'Z'), folder: 'team', id: 'AAAAAAAAAAAAAAAAAAAAAA', issuedBy: M.fpr, note: null, role: 'folder-admin', type: 'g00pass.invite-record', version: 1 };
    const content = canonicalJson(forged);
    s.set(inviteRecordPath(forged.id), content);
    s.set(inviteRecordPath(forged.id) + '.sig', await signDetached(new TextEncoder().encode(content), M.priv));
    expect(await verifyInviteRecord(s, forged.id, { folder: 'team', role: 'reader' })).toMatchObject({ valid: false, reason: expect.stringContaining('not an admin') });
    // A non-admin cannot issue one either.
    expect(await code(issueInvite({ snapshot: s, writer: new MemoryWriter(s), repo, folder: 'team', role: 'reader', days: 1, token: TOKEN, appUrl: 'https://vault.example/', operatorKey: M.priv }))).toMatch(/not an admin/);
  });

  it('link validation: expired, classic token, too long, unexpected fields, damaged', () => {
    const now = new Date();
    const base: InvitePayload = {
      anchors: [A.fpr], branch: 'main', expiresAt: new Date(now.getTime() + 86400_000).toISOString().replace(/\.\d{3}Z$/, 'Z'), folder: 'team',
      id: 'q3V1x0bN0m5Qm6cU2f5r9A', issuedBy: A.fpr, repo: 'acme/secrets', requestsRepo: 'acme/requests', role: 'reader', storeRoot: '', token: TOKEN, type: 'g00pass.invite', version: 1,
    };
    expect(() => validateInvite(base, now)).not.toThrow();
    expect(() => validateInvite({ ...base, expiresAt: '2020-01-01T00:00:00Z' }, now)).toThrow(/expired/);
    expect(() => validateInvite({ ...base, token: 'ghp_' + 'a'.repeat(36) }, now)).toThrow(/fine-grained/);
    expect(() => validateInvite({ ...base, expiresAt: new Date(now.getTime() + 30 * 86400_000).toISOString().replace(/\.\d{3}Z$/, 'Z') }, now)).toThrow(/at most/);
    expect(() => validateInvite({ ...base, extra: 1 }, now)).toThrow(/unexpected/);
    expect(() => validateInvite({ ...base, anchors: ['ABCD'] }, now)).toThrow();
    for (const e of [() => validateInvite({ ...base, token: 'github_pat_x' }, now)]) {
      try {
        e();
      } catch (err) {
        expect(String((err as Error).message)).not.toContain('github_pat_x'); // never echoes the token
      }
    }
    const replace = vi.fn();
    expect(takeInviteFromLocation({ hash: INVITE_FRAGMENT + '%%%', pathname: '/', search: '' }, { replaceState: replace })).toMatchObject({ kind: 'invalid' });
    expect(replace).toHaveBeenCalledOnce();
    expect(takeInviteFromLocation({ hash: '#other', pathname: '/', search: '' }, { replaceState: replace })).toEqual({ kind: 'none' });
    expect(replace).toHaveBeenCalledOnce();
  });

  it('token probe: must see the requests repo and must not read the store', async () => {
    let storeStatus = 404;
    const fetch = (async (url: string) => {
      const p = new URL(url).pathname;
      if (p === '/repos/acme/requests') return new Response('{}', { status: 200 });
      if (p === '/repos/acme/secrets/git/ref/heads/main') return new Response(JSON.stringify({ message: 'x' }), { status: storeStatus });
      return new Response('{}', { status: 404 });
    }) as typeof globalThis.fetch;
    const client = new GitHubClient({ token: () => TOKEN, fetch });
    expect(await probeInviteToken(client, repo)).toEqual({ ok: true });
    storeStatus = 200;
    expect(await probeInviteToken(client, repo)).toMatchObject({ ok: false, reason: expect.stringContaining('over-scoped') });
    expect(await probeInviteToken(client, { ...repo, requestsRepo: 'acme/nope' })).toMatchObject({ ok: false });
  });
});
