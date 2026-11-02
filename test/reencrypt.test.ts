import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  AbortError,
  ConflictError,
  MemoryStore,
  MemoryWriter,
  ReencryptError,
  TrustError,
  passThroughTrustHook,
  reencryptFolder,
  setTrustHook,
  type ReencryptProgress,
} from '../src/core';
import { type TestIdentity, dec, decryptText, encryptForTest, makeIdentity } from './helpers/keys';

let alice: TestIdentity, bob: TestIdentity, carol: TestIdentity, escrow: TestIdentity;
let store: MemoryStore;
let writer: MemoryWriter;
const secrets: Record<string, string> = {
  'team/db.gpg': 'db-password\nuser: admin',
  'team/api/token.gpg': 'tok-123',
  'team/web.gpg': 'web-pass',
};

beforeAll(async () => {
  [alice, bob, carol, escrow] = await Promise.all([
    makeIdentity('Alice'),
    makeIdentity('Bob'),
    makeIdentity('Carol'),
    makeIdentity('Escrow'),
  ]);
});

beforeEach(async () => {
  setTrustHook(passThroughTrustHook);
  store = new MemoryStore({
    '.gpg-id': `${alice.fpr}\n${escrow.fpr} # g00pass:escrow\n`,
    'team/.gpg-id': `${alice.fpr}\n${escrow.fpr}\n`,
    'team/.gpg-id.sig': new Uint8Array([9, 9]),
    'team/private/.gpg-id': `${alice.fpr}\n`,
    [`.public-keys/${alice.fpr}`]: alice.armoredPublic,
    [`.public-keys/${escrow.fpr}`]: escrow.armoredPublic,
    [`.public-keys/${carol.fpr}`]: carol.armoredPublic,
  });
  for (const [p, t] of Object.entries(secrets)) store.set(p, await encryptForTest(t, [alice, escrow]));
  store.set('team/private/only-alice.gpg', await encryptForTest('alice-only', [alice]));
  writer = new MemoryWriter(store);
});

describe('reencryptFolder', () => {
  it('round-trips: new recipient can decrypt, nested .gpg-id folder untouched, one commit', async () => {
    const nestedBefore = await store.readFile('team/private/only-alice.gpg');
    const progress: ReencryptProgress[] = [];
    const res = await reencryptFolder('team', [alice.fpr, bob.fpr], {
      snapshot: store,
      writer,
      decryptionKeys: [alice.priv],
      pendingKeys: new Map([[bob.fpr, bob.armoredPublic]]),
      chunkSize: 2,
      onProgress: (p) => progress.push(p),
    });

    expect(writer.commits).toHaveLength(1);
    expect(res.entries).toEqual(['team/api/token.gpg', 'team/db.gpg', 'team/web.gpg']);
    expect(res.fingerprints).toEqual([alice.fpr, bob.fpr, escrow.fpr]);

    for (const [p, t] of Object.entries(secrets)) {
      const ct = (await store.readFile(p))!;
      expect(await decryptText(ct, bob)).toBe(t);
      expect(await decryptText(ct, alice)).toBe(t);
      expect(await decryptText(ct, escrow)).toBe(t); // escrow kept
      await expect(decryptText(ct, carol)).rejects.toThrow();
    }
    expect(await store.readFile('team/private/only-alice.gpg')).toEqual(nestedBefore);
    await expect(decryptText(nestedBefore!, bob)).rejects.toThrow();

    expect(dec((await store.readFile('team/.gpg-id'))!)).toBe(`${alice.fpr}\n${bob.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    expect(store.hasFile('team/.gpg-id.sig')).toBe(false); // stale signature removed
    expect(dec((await store.readFile(`.public-keys/${bob.fpr}`))!)).toBe(bob.armoredPublic);

    const changed = writer.commits[0]!.changes.map((c) => c.path).sort();
    expect(changed).toEqual(
      [`.public-keys/${bob.fpr}`, 'team/.gpg-id', 'team/.gpg-id.sig', ...Object.keys(secrets)].sort(),
    );
    // never any plaintext in what gets written
    for (const c of writer.commits[0]!.changes) {
      if (!c.content) continue;
      const s = typeof c.content === 'string' ? c.content : Buffer.from(c.content).toString('latin1');
      for (const t of Object.values(secrets)) expect(s).not.toContain(t.split('\n')[0]);
    }
    expect(progress[0]).toEqual({ phase: 'verifying', done: 0, total: 3 });
    expect(progress.filter((p) => p.phase === 'reencrypting').map((p) => p.done)).toEqual([2, 3]);
    expect(progress.at(-1)).toEqual({ phase: 'done', done: 3, total: 3 });
  });

  it('removing a member: removed key can no longer decrypt the new ciphertext', async () => {
    await reencryptFolder('team', [alice.fpr, carol.fpr], { snapshot: store, writer, decryptionKeys: [alice.priv] });
    const store2 = store;
    await reencryptFolder('team', [carol.fpr], { snapshot: store2, writer: new MemoryWriter(store2), decryptionKeys: [carol.priv] });
    const ct = (await store.readFile('team/db.gpg'))!;
    await expect(decryptText(ct, alice)).rejects.toThrow();
    expect(await decryptText(ct, carol)).toBe(secrets['team/db.gpg']);
  });

  it('writes the provided .gpg-id signature (signer gets the final text)', async () => {
    let signedText = '';
    await reencryptFolder('team', [alice.fpr], {
      snapshot: store,
      writer,
      decryptionKeys: [alice.priv],
      gpgIdSignature: async (t) => ((signedText = t), new Uint8Array([7])),
    });
    expect(dec((await store.readFile('team/.gpg-id'))!)).toBe(signedText);
    expect([...(await store.readFile('team/.gpg-id.sig'))!]).toEqual([7]);
  });

  it('refuses to commit if any entry fails to decrypt, listing failed paths', async () => {
    store.set('team/foreign.gpg', await encryptForTest('not for alice', [carol]));
    const before = store.commitSha;
    const err = await reencryptFolder('team', [alice.fpr, bob.fpr], {
      snapshot: store,
      writer,
      decryptionKeys: [alice.priv],
      pendingKeys: new Map([[bob.fpr, bob.armoredPublic]]),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(ReencryptError);
    expect(err.failedPaths).toEqual(['team/foreign.gpg']);
    expect(writer.commits).toHaveLength(0);
    expect(store.commitSha).toBe(before);
  });

  it('is cancellable and commits nothing when aborted', async () => {
    const ac = new AbortController();
    const err = await reencryptFolder('team', [alice.fpr], {
      snapshot: store,
      writer,
      decryptionKeys: [alice.priv],
      chunkSize: 1,
      signal: ac.signal,
      onProgress: (p) => p.phase === 'reencrypting' && p.done === 1 && ac.abort(),
    }).catch((e) => e);
    expect(err).toBeInstanceOf(AbortError);
    expect(writer.commits).toHaveLength(0);
  });

  it('surfaces ConflictError when the base moved', async () => {
    store.commitSha = 'mem-other'; // simulate stale snapshot vs. writer
    const stale = new MemoryWriter(new MemoryStore({}, 'mem-head'));
    await expect(
      reencryptFolder('team', [alice.fpr], { snapshot: store, writer: stale, decryptionKeys: [alice.priv] }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('goes through the trust hook (proposed) and stops if it rejects', async () => {
    let proposed: boolean | undefined;
    setTrustHook({
      name: 'deny',
      verify: async (r) => ((proposed = r.proposed), { ok: false, code: 'unknown-signer', reason: 'nope' }),
    });
    await expect(
      reencryptFolder('team', [alice.fpr], { snapshot: store, writer, decryptionKeys: [alice.priv] }),
    ).rejects.toBeInstanceOf(TrustError);
    expect(proposed).toBe(true);
    expect(writer.commits).toHaveLength(0);
  });

  it('rejects extraChanges touching entries or .gpg-id', async () => {
    await expect(
      reencryptFolder('team', [alice.fpr], {
        snapshot: store,
        writer,
        decryptionKeys: [alice.priv],
        extraChanges: [{ path: 'team/db.gpg', content: 'x' }],
      }),
    ).rejects.toThrow(/may not touch/);
  });

  it('rejects pending keys whose fingerprint does not match', async () => {
    await expect(
      reencryptFolder('team', [alice.fpr], {
        snapshot: store,
        writer,
        decryptionKeys: [alice.priv],
        pendingKeys: new Map([[carol.fpr, bob.armoredPublic]]),
      }),
    ).rejects.toThrow(ReencryptError);
  });

  it('creates a new boundary when re-encrypting a folder without its own .gpg-id', async () => {
    store.set('loose/x.gpg', await encryptForTest('loose', [alice, escrow]));
    await reencryptFolder('loose', [carol.fpr], { snapshot: store, writer, decryptionKeys: [alice.priv] });
    expect(dec((await store.readFile('loose/.gpg-id'))!)).toBe(`${carol.fpr}\n${escrow.fpr} # g00pass:escrow\n`);
    expect(await decryptText((await store.readFile('loose/x.gpg'))!, carol)).toBe('loose');
  });
});
