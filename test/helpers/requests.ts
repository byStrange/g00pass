import * as openpgp from 'openpgp';
import { REQUEST_MARKER } from '../../src/core';
import type { TestIdentity } from './keys';

/** Test-only request builder following docs/specs/access-requests.md (Agent A owns the real builder). */
export function sortKeysDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sortKeysDeep((v as Record<string, unknown>)[k])]));
  }
  return v;
}
export const canon = (v: unknown) => JSON.stringify(sortKeysDeep(v), null, 2) + '\n';

export function payloadFor(id: TestIdentity, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    createdAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    fingerprint: id.fpr,
    folder: 'team',
    inviteId: null,
    name: id.name,
    nonce: 'Zk9a1c1m3bS0dXl2b0x0eA',
    note: null,
    publicKey: id.armoredPublic,
    repo: 'acme/secrets',
    role: 'reader',
    storeRoot: '',
    type: 'g00pass.access-request',
    version: 1,
    ...over,
  };
}

export async function signedBlock(signer: TestIdentity, text: string, date?: Date): Promise<string> {
  return (await openpgp.sign({
    message: await openpgp.createCleartextMessage({ text }),
    signingKeys: signer.priv,
    date,
  })) as string;
}

export function bodyFromBlock(block: string, extra = ''): string {
  return `${REQUEST_MARKER}\n**g00pass access request.**\n\n- Folder: \`x\`\n\n\`\`\`g00pass-request\n${block}\n\`\`\`\n${extra}`;
}

export async function buildBody(
  id: TestIdentity,
  over: Record<string, unknown> = {},
  opts: { signer?: TestIdentity; sigDate?: Date } = {},
): Promise<string> {
  const text = canon(payloadFor(id, over));
  return bodyFromBlock(await signedBlock(opts.signer ?? id, text.replace(/\n$/, ''), opts.sigDate));
}
