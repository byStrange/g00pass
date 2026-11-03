import { readCleartextMessage, verify, type PublicKey } from 'openpgp';
import { canonicalJson } from '../canonical';
import { fingerprintOf, parsePublicKey } from '../keys';
import { StorePathError } from '../errors';
import { normalizePath } from '../paths';

/**
 * Access-request parser (docs/specs/access-requests.md §Approver client).
 *
 * The issue body is UNTRUSTED input. Only the cleartext-signed block counts;
 * the markdown around it is ignored. Everything shown to the operator comes
 * from the signed payload or the parsed key, and must be rendered as text.
 * Error messages are static strings: they never echo attacker-controlled text.
 *
 * Pure: no network, no store access. Checks that need the store (folder exists,
 * requester not yet a recipient, operator authority) live in access/inbox.ts.
 */

export const REQUEST_MARKER = '<!-- g00pass:access-request v1 -->';
export const REQUEST_FENCE = 'g00pass-request';
export const MAX_BODY_BYTES = 32 * 1024;
export type RequestRole = 'reader' | 'folder-admin';

export interface ParsedAccessRequest {
  readonly repo: string;
  readonly storeRoot: string;
  readonly folder: string;
  readonly role: RequestRole;
  /** Upper-case 40-hex v4 fingerprint; equals the key and the signer. */
  readonly fingerprint: string;
  /** Re-armored from the parsed key (never the raw string): exactly one public key. */
  readonly publicKey: string;
  /** Display only; never trusted. */
  readonly name: string;
  readonly note: string | null;
  readonly inviteId: string | null;
  readonly createdAt: string;
  readonly nonce: string;
  /** User ids on the key (display only). */
  readonly userIds: readonly string[];
  /** First e-mail found on the key's user ids, if any (display only). */
  readonly email: string | null;
  /** Always true for a successfully parsed request (proof of possession). */
  readonly signatureValid: true;
}

export type ParseErrorCode =
  | 'too-large'
  | 'no-request-block'
  | 'multiple-request-blocks'
  | 'bad-signature-block'
  | 'bad-payload'
  | 'not-canonical'
  | 'unsupported-type'
  | 'wrong-store'
  | 'bad-field'
  | 'bad-key'
  | 'fingerprint-mismatch'
  | 'bad-signature'
  | 'bad-time';

export type ParseResult = { ok: true; request: ParsedAccessRequest } | { ok: false; code: ParseErrorCode; message: string };

export interface ParseContext {
  /** The approver's configured store, `owner/name` (compared case-insensitively). */
  repo: string;
  storeRoot?: string;
  now?: Date;
}

const parsed = new WeakSet<object>();
/** True only for objects produced by `parseAccessRequest` (guards the approve path). */
export function isParsedAccessRequest(x: unknown): x is ParsedAccessRequest {
  return typeof x === 'object' && x !== null && parsed.has(x);
}

const fail = (code: ParseErrorCode, message: string): ParseResult => ({ ok: false, code, message });

const FIELDS = [
  'createdAt', 'fingerprint', 'folder', 'inviteId', 'name', 'nonce', 'note',
  'publicKey', 'repo', 'role', 'storeRoot', 'type', 'version',
] as const;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const FPR_RE = /^[0-9A-F]{40}$/;
const B64URL16_RE = /^[A-Za-z0-9_-]{22}$/;
const TS_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
// C0/C1 controls, bidi overrides/isolates, zero-width and line/paragraph separators.
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/;
const MIN = 60_000;
const DAY = 24 * 60 * MIN;

export function formatFingerprint(fpr: string): string {
  const groups = fpr.toUpperCase().replace(/\s+/g, '').match(/.{1,4}/g) ?? [];
  return groups.map((g, i) => (i === 5 ? ` ${g}` : g)).join(' ');
}

function extractBlock(body: string): { ok: true; armored: string } | { ok: false; res: ParseResult } {
  const lines = body.split(/\r?\n/);
  const opens = lines.flatMap((l, i) => (l.trim() === '```' + REQUEST_FENCE ? [i] : []));
  if (opens.length === 0) return { ok: false, res: fail('no-request-block', `Body has no ${REQUEST_FENCE} block`) };
  if (opens.length > 1) return { ok: false, res: fail('multiple-request-blocks', `Body has more than one ${REQUEST_FENCE} block`) };
  const start = opens[0]! + 1;
  const end = lines.findIndex((l, i) => i >= start && l.trim() === '```');
  if (end === -1) return { ok: false, res: fail('bad-signature-block', 'Request block is not closed') };
  const armored = lines.slice(start, end).join('\n').trim();
  if (!armored.startsWith('-----BEGIN PGP SIGNED MESSAGE-----') || !armored.endsWith('-----END PGP SIGNATURE-----')) {
    return { ok: false, res: fail('bad-signature-block', 'Request block is not a cleartext-signed message') };
  }
  return { ok: true, armored };
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const safeText = (v: unknown, max: number, allowNewlines = false): v is string =>
  typeof v === 'string' && v.length <= max && !UNSAFE_CHARS.test(v) && (allowNewlines || !/[\n\t]/.test(v));

function validFolder(folder: unknown): folder is string {
  if (typeof folder !== 'string' || folder === '') return false;
  try {
    if (normalizePath(folder) !== folder) return false;
  } catch (e) {
    if (e instanceof StorePathError) return false;
    throw e;
  }
  // No hidden/metadata segments: blocks .public-keys, .g00pass, .git, ...
  return !folder.split('/').some((s) => s.startsWith('.')) && !UNSAFE_CHARS.test(folder);
}

function validTime(s: unknown): s is string {
  return typeof s === 'string' && TS_RE.test(s) && !Number.isNaN(Date.parse(s));
}

export async function parseAccessRequest(body: unknown, ctx: ParseContext): Promise<ParseResult> {
  const now = ctx.now ?? new Date();
  if (typeof body !== 'string') return fail('no-request-block', 'Issue has no body');
  if (new TextEncoder().encode(body).length > MAX_BODY_BYTES) return fail('too-large', 'Issue body exceeds 32 KiB');
  const block = extractBlock(body);
  if (!block.ok) return block.res;

  // --- cleartext message + JSON ---
  let text: string;
  let message: Awaited<ReturnType<typeof readCleartextMessage>>;
  try {
    message = await readCleartextMessage({ cleartextMessage: block.armored });
    text = message.getText();
  } catch {
    return fail('bad-signature-block', 'Request block is not a valid cleartext-signed message');
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    return fail('bad-payload', 'Signed text is not JSON');
  }
  if (!isObj(payload)) return fail('bad-payload', 'Signed payload is not an object');
  if (canonicalJson(payload).replace(/\n$/, '') !== text.replace(/\n+$/, '')) {
    return fail('not-canonical', 'Signed payload is not canonical JSON');
  }
  if (payload.type !== 'g00pass.access-request' || payload.version !== 1) {
    return fail('unsupported-type', 'Unknown request type or version');
  }
  const keys = Object.keys(payload).sort();
  if (keys.length !== FIELDS.length || keys.some((k, i) => k !== FIELDS[i])) {
    return fail('bad-field', 'Payload has missing or unexpected fields');
  }

  // --- field validation ---
  const { repo, storeRoot, folder, role, fingerprint, publicKey, name, note, inviteId, createdAt, nonce } = payload;
  if (typeof repo !== 'string' || !REPO_RE.test(repo)) return fail('bad-field', 'Invalid repo');
  if (typeof storeRoot !== 'string') return fail('bad-field', 'Invalid storeRoot');
  let root: string;
  try {
    root = normalizePath(storeRoot);
  } catch {
    return fail('bad-field', 'Invalid storeRoot');
  }
  if (root !== storeRoot) return fail('bad-field', 'storeRoot is not normalized');
  if (repo.toLowerCase() !== ctx.repo.toLowerCase() || root !== normalizePath(ctx.storeRoot ?? '')) {
    return fail('wrong-store', 'Request is for a different store');
  }
  if (!validFolder(folder)) return fail('bad-field', 'Invalid folder');
  if (role !== 'reader' && role !== 'folder-admin') return fail('bad-field', 'Unknown role');
  if (typeof fingerprint !== 'string' || !FPR_RE.test(fingerprint)) return fail('bad-field', 'Invalid fingerprint');
  if (typeof publicKey !== 'string') return fail('bad-field', 'Invalid publicKey');
  if (!safeText(name, 100) || name.trim() === '') return fail('bad-field', 'Invalid name');
  if (note !== null && !safeText(note, 500, true)) return fail('bad-field', 'Invalid note');
  if (inviteId !== null && (typeof inviteId !== 'string' || !B64URL16_RE.test(inviteId))) return fail('bad-field', 'Invalid inviteId');
  if (typeof nonce !== 'string' || !B64URL16_RE.test(nonce)) return fail('bad-field', 'Invalid nonce');
  if (!validTime(createdAt)) return fail('bad-field', 'Invalid createdAt');
  const created = Date.parse(createdAt);
  if (created > now.getTime() + 5 * MIN) return fail('bad-time', 'Request is dated in the future');
  if (created < now.getTime() - 30 * DAY) return fail('bad-time', 'Request is older than 30 days');

  // --- key checks ---
  if ((publicKey.match(/-----BEGIN PGP/g) ?? []).length !== 1) return fail('bad-key', 'publicKey must contain exactly one armored block');
  let key: PublicKey;
  try {
    const ks = await parsePublicKey(publicKey, fingerprint);
    if (ks.length !== 1) return fail('bad-key', 'publicKey must contain exactly one key');
    key = ks[0]!;
  } catch {
    return fail('bad-key', 'publicKey is unreadable or contains private key material');
  }
  if (key.keyPacket.version !== 4) return fail('bad-key', 'Only v4 keys are accepted');
  if (fingerprintOf(key) !== fingerprint) return fail('fingerprint-mismatch', 'Fingerprint does not match the embedded key');
  const keyErr = await checkKey(key, now);
  if (keyErr) return fail('bad-key', keyErr);

  // --- proof of possession ---
  let sigTime: number;
  try {
    const res = await verify({ message, verificationKeys: key, date: new Date(now.getTime() + 5 * MIN) });
    if (res.signatures.length !== 1) return fail('bad-signature', 'Expected exactly one signature');
    const s = res.signatures[0]!;
    await s.verified; // rejects if invalid
    sigTime = (await s.signature).packets[0]!.created!.getTime();
  } catch {
    return fail('bad-signature', 'Signature does not verify against the embedded key');
  }
  if (Math.abs(sigTime - created) > 10 * MIN) return fail('bad-time', 'Signature time does not match createdAt');

  const userIds = key.getUserIDs();
  const request: ParsedAccessRequest = Object.freeze({
    repo,
    storeRoot: root,
    folder,
    role,
    fingerprint,
    publicKey: key.armor(),
    name,
    note,
    inviteId,
    createdAt,
    nonce,
    userIds: Object.freeze(userIds),
    email: userIds.map((u) => /<([^<>\s]{1,254})>/.exec(u)?.[1]).find((e) => e !== undefined) ?? null,
    signatureValid: true,
  });
  parsed.add(request);
  return { ok: true, request };
}

/** Step 4 of the spec: algorithm, encryption subkey, expiry. Returns an error message or null. */
async function checkKey(key: PublicKey, now: Date): Promise<string | null> {
  const okAlgo = (i: { algorithm: string; bits?: number }) =>
    i.algorithm === 'eddsaLegacy' || i.algorithm === 'ecdh' || (i.algorithm.startsWith('rsa') && (i.bits ?? 0) >= 3072);
  try {
    await key.verifyPrimaryKey(now);
    if (!okAlgo(key.getAlgorithmInfo())) return 'Key algorithm not accepted (need Ed25519/Cv25519 or RSA >= 3072)';
    const enc = await key.getEncryptionKey(undefined, now);
    if (!okAlgo(enc.getAlgorithmInfo())) return 'Encryption subkey algorithm not accepted';
    const exp = await key.getExpirationTime();
    if (exp === null) return 'Key has no valid self-signature';
    if (exp instanceof Date && exp.getTime() < now.getTime() + 30 * DAY) return 'Key expires within 30 days';
  } catch {
    return 'Key is expired, revoked or has no usable encryption subkey';
  }
  return null;
}
