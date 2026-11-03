// Regression tests for the Phase 1 security re-review (docs/reviews/phase1-rereview.md).
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  MemoryStore,
  isVerifiedFolderAdmin,
  passThroughTrustHook,
  pinAnchors,
  resetTrustEnvironment,
  setTrustHook,
  signAdminsFile,
  signatureTrustHook,
  verifyAdminsFile,
} from '../src/core';
import { type TestIdentity, makeIdentity } from './helpers/keys';
import { FakeHistory, STORE_ID, derive, freshEnv, signedGpgId, type EnvHandle } from './helpers/trust';

let A: TestIdentity, C: TestIdentity, M: TestIdentity, E: TestIdentity;
let env: EnvHandle;
const keys = (...ids: TestIdentity[]) => Object.fromEntries(ids.map((i) => [`.public-keys/${i.fpr}`, i.armoredPublic]));

beforeAll(async () => {
  const born = new Date(Date.now() - 2 * 86400_000);
  [A, C, M, E] = (await Promise.all(['A', 'C', 'M', 'E'].map((n) => makeIdentity(n, born)))) as [TestIdentity, TestIdentity, TestIdentity, TestIdentity];
  setTrustHook(signatureTrustHook);
});
afterAll(() => {
  setTrustHook(passThroughTrustHook);
  resetTrustEnvironment();
});
beforeEach(() => {
  env = freshEnv();
  pinAnchors(STORE_ID, [A.fpr], 'first-use');
});

const ADM = 'infra/.g00pass-admins.json';
const SIG = 'infra/.g00pass-admins.json.sig';

async function setup(tag: string) {
  const s0 = new MemoryStore({
    ...keys(A, C, M, E),
    ...(await signedGpgId('', `${A.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv, { children: ['infra'] })),
    ...(await signedGpgId('infra', `${A.fpr}\n${C.fpr}\n${E.fpr} # g00pass:escrow\n`, A.priv)),
  }, `${tag}-0`);
  const sign = async (base: MemoryStore, admins: string[], k: TestIdentity) => {
    const f = await signAdminsFile({ snapshot: base, folder: 'infra', admins, signingKey: k.priv });
    return derive(base, { [f.path]: f.content, [f.sigPath]: f.signature });
  };
  const v1 = await sign(s0, [C.fpr, M.fpr], A); // anchor: C and M are admins
  const v2 = await sign(v1, [C.fpr], C); // C removes M
  const copyAdmins = async (from: MemoryStore, onto: MemoryStore) =>
    derive(onto, { [ADM]: (await from.readFile(ADM))!, [SIG]: (await from.readFile(SIG))! });
  return { s0, sign, v1, v2, copyAdmins };
}

describe('R-H1: a merge commit must not hide admins-file history (git log path simplification)', () => {
  it("fresh device: M forks V2' on a side branch from V1 and merges it (TREESAME to the side): refused", async () => {
    const { sign, v1, v2, copyAdmins } = await setup('m1');
    const side = await sign(v1, [C.fpr, M.fpr], M); // serial 2, previous = digest(V1), M was admin in V1
    const head = await copyAdmins(side, v2); // merge commit resolved to the side's version
    // commits?path= follows only the TREESAME parent: it lists side + V1 and hides V2.
    const h = new FakeHistory([side, v1]);
    h.hidden = [v2];
    h.mergeList = [{ sha: head.commitSha, parents: [v2.commitSha, side.commitSha] }];
    env.history = h;
    expect(await verifyAdminsFile(head, 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('merge') });
    expect(await isVerifiedFolderAdmin(head, 'infra', M.fpr)).toBe(false);
  });

  it('fresh device: rollback to the anchor-signed V1 hidden behind a merge is refused', async () => {
    const { v1, v2, copyAdmins } = await setup('m2');
    const side = await derive(v1, { 'unrelated.txt': 'x' }); // side branch from V1, file untouched
    const head = await copyAdmins(v1, v2);
    const h = new FakeHistory([v1]);
    h.hidden = [v2, side];
    h.mergeList = [{ sha: head.commitSha, parents: [v2.commitSha, side.commitSha] }];
    env.history = h;
    expect(await verifyAdminsFile(head, 'infra')).toMatchObject({ status: 'invalid', reason: expect.stringContaining('merge') });
  });

  it('a benign merge (the side branch did not touch the file) still verifies', async () => {
    const { v1, v2 } = await setup('m3');
    const side = await derive(v1, { 'unrelated.txt': 'x' });
    const head = await derive(v2, { 'unrelated.txt': 'x' });
    const h = new FakeHistory([v2, v1]);
    h.hidden = [side];
    h.mergeList = [{ sha: head.commitSha, parents: [v2.commitSha, side.commitSha] }];
    env.history = h;
    expect(await verifyAdminsFile(head, 'infra')).toMatchObject({ status: 'valid', serial: 2 });
  });

  it('a side branch from before the file existed is fine when the listing reaches its creation', async () => {
    const { s0, v1, v2 } = await setup('m4');
    const side = await derive(s0, { 'unrelated.txt': 'x' });
    const head = await derive(v2, { 'unrelated.txt': 'x' });
    const h = new FakeHistory([v2, v1]);
    h.hidden = [side];
    h.mergeList = [{ sha: head.commitSha, parents: [v2.commitSha, side.commitSha] }];
    env.history = h;
    expect(await verifyAdminsFile(head, 'infra')).toMatchObject({ status: 'valid' });
  });

  it('an unverifiable range (too much history) fails closed', async () => {
    const { v1, v2 } = await setup('m5');
    const h = new FakeHistory([v2, v1]);
    h.mergesResult = null;
    env.history = h;
    expect(await verifyAdminsFile(v2, 'infra')).toMatchObject({ status: 'invalid' });
  });
});
