import { createCleartextMessage, sign, type PrivateKey } from 'openpgp';
import { canonicalJson, rfc3339 } from '../canonical';
import { G00passError } from '../errors';
import { normalizePath } from '../paths';

/**
 * Access request builder (docs/specs/access-requests.md §Issue format).
 * Pure apart from the signature: no network, no storage. Parsing/verifying
 * is a separate module.
 */

export const REQUEST_MARKER = '<!-- g00pass:access-request v1 -->';
export const REQUEST_FENCE = 'g00pass-request';
export const REQUEST_LABEL = 'g00pass:access-request';
export const MAX_BODY_BYTES = 32 * 1024;
export const MAX_NAME = 100;
export const MAX_NOTE = 500;

export type RequestRole = 'reader' | 'folder-admin';
export const REQUEST_ROLES: readonly RequestRole[] = ['reader', 'folder-admin'];

export class RequestBuildError extends G00passError {}

export interface AccessRequestInput {
  /** The STORE repo, "owner/name" (not the requests repo). */
  repo: string;
  storeRoot?: string;
  folder: string;
  role: RequestRole;
  /** Display name (the key's user-id name). */
  name: string;
  note?: string | null;
  inviteId?: string | null;
  /** Armored PUBLIC key, exactly the key that signs. */
  publicKey: string;
  /** 40-hex v4 fingerprint of that key. */
  fingerprint: string;
}

export interface BuildEnv {
  now?: Date;
  /** 16 random bytes; injectable for tests. */
  randomBytes?: (n: number) => Uint8Array;
}

export interface BuiltAccessRequest {
  title: string;
  body: string;
  canonicalJson: string;
  payload: Record<string, unknown>;
}

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const FPR_RE = /^[0-9A-F]{40}$/;
const B64URL16_RE = /^[A-Za-z0-9_-]{22}$/;

export function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function groupFingerprint(fpr: string): string {
  const g = fpr.match(/.{1,4}/g) ?? [];
  return g.slice(0, 5).join(' ') + '  ' + g.slice(5).join(' ');
}

/**
 * Build and cleartext-sign an access request. `signingKey` must be the
 * UNLOCKED private key whose public half is `input.publicKey`.
 */
export async function buildAccessRequest(
  input: AccessRequestInput,
  signingKey: PrivateKey,
  env: BuildEnv = {},
): Promise<BuiltAccessRequest> {
  const fingerprint = input.fingerprint.toUpperCase();
  if (!REPO_RE.test(input.repo)) throw new RequestBuildError('Store repo must look like owner/name.');
  if (!FPR_RE.test(fingerprint)) throw new RequestBuildError('Fingerprint must be 40 hex characters.');
  if (signingKey.getFingerprint().toUpperCase() !== fingerprint) throw new RequestBuildError('Signing key does not match the fingerprint.');
  if (!signingKey.isDecrypted()) throw new RequestBuildError('Signing key is locked.');
  if (!REQUEST_ROLES.includes(input.role)) throw new RequestBuildError('Unknown role.');
  if (input.publicKey.includes('PRIVATE KEY')) throw new RequestBuildError('Refusing to include private key material.');
  if (!input.publicKey.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) throw new RequestBuildError('Public key must be armored.');
  const folder = normalizePath(input.folder);
  if (!folder) throw new RequestBuildError('A folder is required.');
  const storeRoot = normalizePath(input.storeRoot ?? '');
  const name = input.name.trim();
  if (!name || name.length > MAX_NAME) throw new RequestBuildError(`Name is required (max ${MAX_NAME} characters).`);
  const note = input.note?.trim() ? input.note.trim() : null;
  if (note !== null && note.length > MAX_NOTE) throw new RequestBuildError(`Note is too long (max ${MAX_NOTE} characters).`);
  const inviteId = input.inviteId ?? null;
  if (inviteId !== null && !B64URL16_RE.test(inviteId)) throw new RequestBuildError('Invalid invite id.');

  const now = env.now ?? new Date();
  const rnd = env.randomBytes ?? ((n: number) => crypto.getRandomValues(new Uint8Array(n)));
  const payload = {
    createdAt: rfc3339(now),
    fingerprint,
    folder,
    inviteId,
    name,
    nonce: b64url(rnd(16)),
    note,
    publicKey: input.publicKey.replace(/\r\n/g, '\n'),
    repo: input.repo,
    role: input.role,
    storeRoot,
    type: 'g00pass.access-request',
    version: 1,
  };
  const json = canonicalJson(payload);
  const signed = (await sign({
    message: await createCleartextMessage({ text: json }),
    signingKeys: signingKey,
    date: now,
    format: 'armored',
  })) as string;

  const body = [
    REQUEST_MARKER,
    '**g00pass access request.** Open g00pass to review. Do not approve without',
    'confirming the fingerprint with the requester out of band.',
    '',
    `- Folder: \`${folder}\``,
    `- Role: ${input.role}`,
    `- Fingerprint: \`${groupFingerprint(fingerprint)}\``,
    '',
    '```' + REQUEST_FENCE,
    signed.trimEnd(),
    '```',
    '',
  ].join('\n');
  if (new TextEncoder().encode(body).length > MAX_BODY_BYTES) throw new RequestBuildError('Request is too large.');
  const title = `[g00pass] Access request: ${folder} (${input.role}) ${fingerprint.slice(-16)}`;
  return { title, body, canonicalJson: json, payload };
}
