import { beforeAll, describe, expect, it } from 'vitest';
import type { PrivateKey } from 'openpgp';
import {
  REQUEST_LABEL,
  buildAccessRequest,
  generateEnrollmentKey,
  parseAccessRequest,
  unlockPrivateKey,
  type AccessRequestInput,
} from '../src/core';

const PASS = 'correct horse battery staple';
let gen: Awaited<ReturnType<typeof generateEnrollmentKey>>;
let key: PrivateKey;

beforeAll(async () => {
  gen = await generateEnrollmentKey({ name: 'Carol Example', email: 'carol@example.test', passphrase: PASS });
  key = await unlockPrivateKey(gen.privateKeyArmored, PASS);
});

describe('A (build) <-> B (parse) round trip', () => {
  const input = (over: Partial<AccessRequestInput> = {}): AccessRequestInput => ({
    repo: 'acme/secrets',
    storeRoot: 'store',
    folder: 'team/api',
    role: 'reader',
    name: 'Carol Example',
    note: 'Joining the API team',
    inviteId: null,
    fingerprint: gen.fingerprint,
    publicKey: gen.publicKeyArmored,
    ...over,
  });

  it.each([{ role: 'reader' as const }, { role: 'folder-admin' as const, note: null, inviteId: 'AAAAAAAAAAAAAAAAAAAAAA' }])(
    'parses what the builder produced and yields the same fields (%o)',
    async (over) => {
      const now = new Date();
      const built = await buildAccessRequest(input(over), key, { now });
      const res = await parseAccessRequest(built.body, { repo: 'acme/secrets', storeRoot: 'store', now: new Date(now.getTime() + 1000) });
      if (!res.ok) throw new Error(`${res.code}: ${res.message}`);
      const r = res.request;
      const p = built.payload;
      expect(r).toMatchObject({
        repo: p.repo,
        storeRoot: p.storeRoot,
        folder: p.folder,
        role: p.role,
        fingerprint: p.fingerprint,
        name: p.name,
        note: p.note,
        inviteId: p.inviteId,
        createdAt: p.createdAt,
        nonce: p.nonce,
        signatureValid: true,
      });
      expect(r.fingerprint).toBe(gen.fingerprint);
      expect(r.publicKey).toContain('BEGIN PGP PUBLIC KEY BLOCK');
      expect(r.publicKey).not.toContain('PRIVATE');
    },
  );

  it('the parser rejects the request for a different store', async () => {
    const built = await buildAccessRequest(input(), key);
    const res = await parseAccessRequest(built.body, { repo: 'evil/other', storeRoot: 'store', now: new Date(Date.now() + 1000) });
    expect(res.ok).toBe(false);
  });

  it('uses the one spec label', () => {
    expect(REQUEST_LABEL).toBe('g00pass:access-request');
  });
});
