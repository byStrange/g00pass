import { beforeAll, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import { formatFingerprint, isParsedAccessRequest, parseAccessRequest, MAX_BODY_BYTES } from '../src/core';
import { type TestIdentity, makeIdentity } from './helpers/keys';
import { bodyFromBlock, buildBody, canon, payloadFor, signedBlock } from './helpers/requests';

const ctx = { repo: 'Acme/Secrets', storeRoot: '' };
let carol: TestIdentity, mallory: TestIdentity;
beforeAll(async () => {
  [carol, mallory] = await Promise.all([makeIdentity('Carol'), makeIdentity('Mallory')]);
});

const code = async (body: unknown, c = ctx) => {
  const r = await parseAccessRequest(body, c);
  return r.ok ? 'ok' : r.code;
};

describe('parseAccessRequest', () => {
  it('accepts a valid request and exposes only signed / parsed data', async () => {
    const r = await parseAccessRequest(await buildBody(carol, { note: 'hi\nthere' }), ctx);
    if (!r.ok) throw new Error(r.message);
    expect(r.request).toMatchObject({
      fingerprint: carol.fpr,
      folder: 'team',
      role: 'reader',
      name: 'Carol',
      email: 'carol@example.test',
      note: 'hi\nthere',
      inviteId: null,
      repo: 'acme/secrets',
      signatureValid: true,
    });
    expect(r.request.publicKey).toContain('BEGIN PGP PUBLIC KEY BLOCK');
    expect(isParsedAccessRequest(r.request)).toBe(true);
    expect(isParsedAccessRequest({ ...r.request })).toBe(false);
  });

  it('ignores markdown outside the signed block (lying summary)', async () => {
    const block = (await buildBody(carol)).split('```g00pass-request\n')[1]!.split('\n```')[0]!;
    const body = `<!-- g00pass:access-request v1 -->\n- Folder: \`root\`\n- Fingerprint: \`${mallory.fpr}\`\n\n\`\`\`g00pass-request\n${block}\n\`\`\`\n`;
    const r = await parseAccessRequest(body, ctx);
    expect(r.ok && r.request.fingerprint).toBe(carol.fpr);
    expect(r.ok && r.request.folder).toBe('team');
  });

  it('rejects a tampered signed text', async () => {
    const body = (await buildBody(carol)).replace('"folder": "team"', '"folder": "prod"');
    expect(await code(body)).toBe('bad-signature');
  });

  it('rejects a signature by a different key than the embedded one', async () => {
    expect(await code(await buildBody(carol, {}, { signer: mallory }))).toBe('bad-signature');
  });

  it('rejects fingerprint that does not match the embedded key', async () => {
    expect(await code(await buildBody(carol, { fingerprint: mallory.fpr }))).toBe('fingerprint-mismatch');
    expect(await code(await buildBody(carol, { fingerprint: carol.fpr.toLowerCase() }))).toBe('bad-field');
  });

  it.each(['', '..', '../x', '/abs', 'a//b', 'a/', 'a/../b', '.public-keys', 'team/.g00pass', 'a\\b', 'a\u0000b', 7])(
    'rejects bad folder %j',
    async (folder) => {
      expect(await code(await buildBody(carol, { folder }))).toBe('bad-field');
    },
  );

  it('rejects unknown roles, types, versions and unknown/missing fields', async () => {
    expect(await code(await buildBody(carol, { role: 'owner' }))).toBe('bad-field');
    expect(await code(await buildBody(carol, { type: 'x' }))).toBe('unsupported-type');
    expect(await code(await buildBody(carol, { version: 2 }))).toBe('unsupported-type');
    expect(await code(await buildBody(carol, { extra: 1 }))).toBe('bad-field');
    expect(await code(await buildBody(carol, { note: undefined }))).toBe('bad-field');
  });

  it('rejects another store (case-insensitive repo match is accepted)', async () => {
    expect(await code(await buildBody(carol, { repo: 'ACME/SECRETS' }))).toBe('ok');
    expect(await code(await buildBody(carol, { repo: 'acme/other' }))).toBe('wrong-store');
    expect(await code(await buildBody(carol, { storeRoot: 'sub' }))).toBe('wrong-store');
  });

  it('rejects unsafe display strings', async () => {
    expect(await code(await buildBody(carol, { name: 'Bob‮evil' }))).toBe('bad-field');
    expect(await code(await buildBody(carol, { name: 'x'.repeat(101) }))).toBe('bad-field');
    expect(await code(await buildBody(carol, { note: 'x'.repeat(501) }))).toBe('bad-field');
    expect(await code(await buildBody(carol, { name: 'a\nb' }))).toBe('bad-field');
  });

  it('keeps HTML as inert data (it is rendered as text by the UI)', async () => {
    const r = await parseAccessRequest(await buildBody(carol, { name: '<img src=x onerror=alert(1)>', note: '<script>1</script>' }), ctx);
    expect(r.ok && r.request.name).toBe('<img src=x onerror=alert(1)>');
  });

  it('checks time windows', async () => {
    const iso = (d: number) => new Date(Date.now() + d).toISOString().replace(/\.\d{3}Z$/, 'Z');
    expect(await code(await buildBody(carol, { createdAt: iso(-31 * 864e5) }))).toBe('bad-time');
    expect(await code(await buildBody(carol, { createdAt: iso(20 * 60_000) }))).toBe('bad-time');
    expect(await code(await buildBody(carol, { createdAt: 'yesterday' }))).toBe('bad-field');
    // createdAt an hour before the signature was made
    expect(await code(await buildBody(carol, { createdAt: iso(-3600_000) }))).toBe('bad-time');
  });

  it('rejects non-canonical JSON', async () => {
    const text = JSON.stringify(payloadFor(carol)); // compact, unsorted order is fine but not 2-space indented
    expect(await code(bodyFromBlock(await signedBlock(carol, text)))).toBe('not-canonical');
  });

  it('rejects embedded private key material', async () => {
    const priv = carol.priv.armor();
    expect(await code(await buildBody(carol, { publicKey: priv }))).toBe('bad-key');
  });

  it('rejects two keys, expiring and expired keys', async () => {
    expect(await code(await buildBody(carol, { publicKey: carol.armoredPublic + '\n' + mallory.armoredPublic }))).toBe('bad-key');
    const { privateKey } = await openpgp.generateKey({
      type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Soon' }], keyExpirationTime: 7 * 86400, format: 'armored',
    });
    const priv = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const soon: TestIdentity = { name: 'Soon', email: '', priv, armoredPublic: priv.toPublic().armor(), fpr: priv.getFingerprint().toUpperCase() };
    expect(await code(await buildBody(soon))).toBe('bad-key');
  });

  it('rejects garbage, HTML, empty, huge and duplicated blocks', async () => {
    for (const b of ['', '<script>alert(1)</script>', 'hello', '```g00pass-request\nnot pgp\n```', '```g00pass-request\n```']) {
      const r = await parseAccessRequest(b, ctx);
      expect(r.ok).toBe(false);
    }
    expect(await code(null)).toBe('no-request-block');
    expect(await code(undefined)).toBe('no-request-block');
    expect(await code('x'.repeat(MAX_BODY_BYTES + 1))).toBe('too-large');
    const good = await buildBody(carol);
    expect(await code(good + '\n' + good)).toBe('multiple-request-blocks');
    expect(await code(good.replace(/\n```\n$/, '\n'))).toBe('bad-signature-block');
    const block = good.split('```g00pass-request\n')[1]!.split('\n```')[0]!;
    const notJson = bodyFromBlock(await signedBlock(carol, 'not json'));
    expect(await code(notJson)).toBe('bad-payload');
    expect(await code(bodyFromBlock(await signedBlock(carol, '[1,2]')))).toBe('bad-payload');
    expect(block).toContain('BEGIN PGP SIGNED MESSAGE');
  });

  it('error messages never echo attacker-controlled text', async () => {
    const r = await parseAccessRequest(await buildBody(carol, { folder: '<b>evil</b>/../x' }), ctx);
    expect(!r.ok && r.message).not.toContain('evil');
  });
});

describe('formatFingerprint', () => {
  it('groups by 4 with a wider gap in the middle', () => {
    expect(formatFingerprint('AAAABBBBCCCCDDDDEEEEFFFF0000111122223333')).toBe('AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333');
  });
});

void canon;
