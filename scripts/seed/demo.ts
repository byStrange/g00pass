/**
 * Demo store builder (scripts/seed-demo-store.mjs runs it; e2e/ uses it too).
 *
 * Generates demo keys (global admin, team member, escrow), and builds a
 * signed store exactly as g00pass verifies it:
 *
 *   /               admin + escrow      declares team, infra
 *   team/           admin, member       admins file [member] (signed by admin)
 *   infra/          admin               declares infra/prod
 *   infra/prod/     admin
 *
 * Every entry is written through the real write path (writeEntry ->
 * verifyRecipients -> signatureTrustHook -> encryptToVerified) against an
 * in-memory copy, so the seed fails if the store would not verify.
 * DEMO ONLY: the keys and passphrases are printed in clear.
 */
import * as openpgp from 'openpgp';
import {
  MemoryStore,
  MemoryTrustStorage,
  MemoryWriter,
  fingerprintOf,
  pinAnchors,
  readEntry,
  setTrustEnvironment,
  setTrustHook,
  signAdminsFile,
  signGpgId,
  signatureTrustHook,
  writeEntry,
  allFolderTrustStatus,
} from '../../src/core';

export interface DemoIdentity {
  readonly role: 'admin' | 'member' | 'escrow';
  readonly name: string;
  readonly email: string;
  readonly fingerprint: string;
  readonly passphrase: string;
  /** Passphrase-protected (iterated S2K) armored private key. */
  readonly privateKey: string;
  readonly publicKey: string;
}

export interface DemoStore {
  /** Store files (store-relative path -> bytes). */
  readonly files: ReadonlyMap<string, Uint8Array>;
  readonly identities: readonly DemoIdentity[];
  readonly entries: Readonly<Record<string, string>>;
}

const PASSPHRASES = { admin: 'demo admin passphrase 1', member: 'demo member passphrase 2', escrow: 'demo escrow passphrase 3' } as const;

async function identity(role: DemoIdentity['role'], name: string, date: Date): Promise<DemoIdentity & { priv: openpgp.PrivateKey }> {
  const email = `${role}@demo.g00pass.invalid`;
  const passphrase = PASSPHRASES[role];
  const { privateKey, publicKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name, email }], passphrase, date, format: 'armored' });
  const priv = await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }), passphrase });
  return { role, name, email, fingerprint: fingerprintOf(priv), passphrase, privateKey, publicKey, priv };
}

export const DEMO_ENTRIES: Record<string, string> = {
  'team/wiki.gpg': 'correct-horse-battery\nurl: https://wiki.demo.invalid\nuser: team',
  'team/email/smtp.gpg': 'smtp-demo-password\nhost: smtp.demo.invalid',
  'infra/db.gpg': 'db-root-demo\nhost: db.demo.invalid',
  'infra/prod/api-key.gpg': 'prod-api-key-demo',
};

export async function buildDemoStore(opts: { storeId: string; now?: Date }): Promise<DemoStore> {
  const born = new Date((opts.now ?? new Date()).getTime() - 60_000);
  const admin = await identity('admin', 'Demo Admin', born);
  const member = await identity('member', 'Demo Member', born);
  const escrow = await identity('escrow', 'Demo Escrow', born);
  const esc = `${escrow.fingerprint} # g00pass:escrow`;
  const s = new MemoryStore({}, 'seed-0');
  for (const i of [admin, member, escrow]) s.set(`.public-keys/${i.fingerprint}`, i.publicKey);

  const gpgId = async (folder: string, ids: string[], children: string[]) => {
    const text = [...ids, esc].join('\n') + '\n';
    const prefix = folder ? `${folder}/` : '';
    s.set(`${prefix}.gpg-id`, text);
    s.set(`${prefix}.gpg-id.sig`, await signGpgId(text, folder, admin.priv, { children }));
  };
  await gpgId('', [admin.fingerprint], ['infra', 'team']);
  await gpgId('team', [admin.fingerprint, member.fingerprint], []);
  await gpgId('infra', [admin.fingerprint], ['infra/prod']);
  await gpgId('infra/prod', [admin.fingerprint], []);
  const af = await signAdminsFile({ snapshot: s, folder: 'team', admins: [member.fingerprint], signingKey: admin.priv });
  for (const c of af.changes) s.set(c.path, c.content as Uint8Array | string);

  // Write every entry through the real trust policy on a throwaway device.
  setTrustHook(signatureTrustHook);
  setTrustEnvironment({ storage: new MemoryTrustStorage(), storeId: () => opts.storeId, history: () => null, now: () => new Date() });
  pinAnchors(opts.storeId, [admin.fingerprint], 'manual');
  const w = new MemoryWriter(s);
  for (const [path, text] of Object.entries(DEMO_ENTRIES)) {
    await writeEntry({ snapshot: s, writer: w, entry: path, plaintext: new TextEncoder().encode(text) });
  }
  const statuses = await allFolderTrustStatus(s);
  const bad = statuses.filter((x) => !x.verified);
  if (bad.length) throw new Error(`seeded store does not verify: ${bad.map((b) => `${b.folder || '/'}: ${b.reason}`).join('; ')}`);
  if (new TextDecoder().decode(await readEntry(s, 'team/wiki.gpg', [member.priv])) !== DEMO_ENTRIES['team/wiki.gpg']) throw new Error('round trip failed');

  const files = new Map<string, Uint8Array>();
  for (const p of s.listFiles()) files.set(p, (await s.readFile(p))!);
  const strip = ({ priv: _p, ...rest }: DemoIdentity & { priv: openpgp.PrivateKey }): DemoIdentity => rest;
  return { files, identities: [strip(admin), strip(member), strip(escrow)], entries: DEMO_ENTRIES };
}
