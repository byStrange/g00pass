import type { PrivateKey } from 'openpgp';
import { checkFolderAdmin } from './admins';
import { evaluateRootTrust, normalizeFingerprints } from './anchors';
import { RFC3339_RE, canonicalJson, parseCanonicalJson, rfc3339 } from './canonical';
import { G00passError, GitHubApiError } from './errors';
import { type GitHubClient, type GitHubRepo, refPath, repoPath, validateRepo } from './github/client';
import { fingerprintOf } from './keys';
import { joinPath, normalizePath } from './paths';
import { INVITE_RECORD_RE } from './reencrypt';
import { REQUEST_ROLES, type RequestRole } from './requests/build';
import { loadKeyByFingerprint, parseDetachedSignature, signDetached, verifyDetached } from './signatures';
import type { CommitResult, FileChange, StoreSnapshot, StoreWriter } from './store';
import { trustEnvironment } from './trust-env';

/**
 * INVITES (docs/specs/access-requests.md §Invites).
 *
 * A link carries, in the URL FRAGMENT (never sent to any server), an unsigned
 * payload: the store, folder, role, the trust anchors to pin, the requests
 * repo, and an issues-only requester token. The delivery channel is the
 * trust root for it; the newcomer confirms the anchors, the approver confirms
 * the requester's fingerprint.
 *
 * The admin also commits a signed invite RECORD (never containing the
 * token) at `.g00pass/invites/<id>.json` + `.sig`. An approval of a request
 * that names a valid record needs no "uninvited" acknowledgement and deletes
 * the record in the same commit (single use).
 */

export const INVITE_FRAGMENT = '#g00pass-invite=';
export const INVITE_TYPE = 'g00pass.invite';
export const INVITE_RECORD_TYPE = 'g00pass.invite-record';
export const INVITES_DIR = '.g00pass/invites';
/** Longest an invite (and its token) may live. */
export const MAX_INVITE_DAYS = 7;

export class InviteError extends G00passError {}

export interface InvitePayload {
  anchors: string[];
  branch: string;
  expiresAt: string;
  folder: string;
  id: string;
  issuedBy: string;
  repo: string;
  requestsRepo: string;
  role: RequestRole;
  storeRoot: string;
  token: string;
  type: typeof INVITE_TYPE;
  version: 1;
}

/** A parsed invite. `token` is non-enumerable: it never ends up in JSON / logs. */
export type Invite = Omit<InvitePayload, 'token'> & { readonly token: string };

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const FPR_RE = /^[0-9A-F]{40}$|^[0-9A-F]{64}$/;
const PAYLOAD_FIELDS = 'anchors,branch,expiresAt,folder,id,issuedBy,repo,requestsRepo,role,storeRoot,token,type,version';

function b64urlEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new InviteError('invite is not base64url');
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function newInviteId(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

/** Validate a payload (any source). Throws InviteError with a static message (never echoes the token). */
export function validateInvite(v: unknown, now: Date): Invite {
  const d = v as Partial<InvitePayload>;
  if (!d || typeof d !== 'object' || Object.keys(d).sort().join(',') !== PAYLOAD_FIELDS) throw new InviteError('invite has unexpected fields');
  if (d.type !== INVITE_TYPE || d.version !== 1) throw new InviteError('unknown invite type/version');
  if (typeof d.repo !== 'string' || !REPO_RE.test(d.repo)) throw new InviteError('invalid store repo');
  if (typeof d.requestsRepo !== 'string' || !REPO_RE.test(d.requestsRepo)) throw new InviteError('invalid requests repo');
  const [owner, repo] = d.repo.split('/') as [string, string];
  if (typeof d.branch !== 'string') throw new InviteError('invalid branch');
  try {
    validateRepo({ owner, repo, branch: d.branch });
  } catch {
    throw new InviteError('invalid store repo or branch');
  }
  let storeRoot: string, folder: string;
  try {
    storeRoot = normalizePath(String(d.storeRoot));
    folder = normalizePath(String(d.folder));
  } catch {
    throw new InviteError('invalid folder');
  }
  if (storeRoot !== d.storeRoot || folder !== d.folder || folder === '') throw new InviteError('invalid folder');
  if (!REQUEST_ROLES.includes(d.role as RequestRole)) throw new InviteError('invalid role');
  if (typeof d.id !== 'string' || !ID_RE.test(d.id)) throw new InviteError('invalid invite id');
  if (typeof d.issuedBy !== 'string' || !FPR_RE.test(d.issuedBy)) throw new InviteError('invalid issuer');
  if (!Array.isArray(d.anchors) || !d.anchors.length || !d.anchors.every((a) => typeof a === 'string' && FPR_RE.test(a))) throw new InviteError('anchors must be full fingerprints');
  const anchors = normalizeFingerprints(d.anchors);
  if (typeof d.expiresAt !== 'string' || !RFC3339_RE.test(d.expiresAt)) throw new InviteError('invalid expiry');
  const exp = Date.parse(d.expiresAt);
  if (exp <= now.getTime()) throw new InviteError('this invite has expired; ask your admin for a new one');
  if (exp > now.getTime() + (MAX_INVITE_DAYS + 1) * 86400_000) throw new InviteError(`invites may be valid for at most ${MAX_INVITE_DAYS} days`);
  // Classic tokens (ghp_) cannot be limited to one repository.
  if (typeof d.token !== 'string' || !/^github_pat_[A-Za-z0-9_]{20,255}$/.test(d.token)) throw new InviteError('the invite token must be a fine-grained token (github_pat_…)');
  const inv = { anchors, branch: d.branch, expiresAt: d.expiresAt, folder, id: d.id, issuedBy: d.issuedBy, repo: d.repo, requestsRepo: d.requestsRepo, role: d.role as RequestRole, storeRoot, type: INVITE_TYPE, version: 1 } as Invite;
  Object.defineProperty(inv, 'token', { value: d.token, enumerable: false });
  return Object.freeze(inv);
}

/** `<base>#g00pass-invite=<base64url(canonical JSON)>`. The result contains a credential. */
export function buildInviteLink(base: string, payload: InvitePayload): string {
  const url = new URL(base);
  url.hash = '';
  return url.toString().replace(/#$/, '') + INVITE_FRAGMENT + b64urlEncode(new TextEncoder().encode(canonicalJson(payload)));
}

export type TakenInvite = { kind: 'none' } | { kind: 'invite'; invite: Invite } | { kind: 'invalid'; reason: string };

/**
 * Call FIRST on page load: if the fragment holds an invite, remove it from
 * the address bar and session history immediately (replaceState), then
 * decode and validate it. The raw string is not kept.
 */
export function takeInviteFromLocation(
  loc: Pick<Location, 'hash' | 'pathname' | 'search'>,
  hist: Pick<History, 'replaceState'>,
  now: Date = new Date(),
): TakenInvite {
  if (!loc.hash.startsWith(INVITE_FRAGMENT)) return { kind: 'none' };
  const raw = loc.hash.slice(INVITE_FRAGMENT.length);
  hist.replaceState(null, '', loc.pathname + loc.search);
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b64urlDecode(raw))) as unknown;
    return { kind: 'invite', invite: validateInvite(value, now) };
  } catch (e) {
    return { kind: 'invalid', reason: e instanceof InviteError ? e.message : 'the invite link is damaged' };
  }
}

// ---- registry ----

export interface InviteRecord {
  createdAt: string;
  expiresAt: string;
  folder: string;
  id: string;
  issuedBy: string;
  note: string | null;
  role: RequestRole;
  type: typeof INVITE_RECORD_TYPE;
  version: 1;
}

export const inviteRecordPath = (id: string) => joinPath(INVITES_DIR, `${id}.json`);
export const inviteRecordSigPath = (id: string) => joinPath(INVITES_DIR, `${id}.json.sig`);

export function parseInviteRecord(bytes: Uint8Array, id: string): InviteRecord {
  let v: unknown;
  try {
    v = parseCanonicalJson(bytes);
  } catch {
    throw new InviteError('invite record is not canonical JSON');
  }
  const d = v as Partial<InviteRecord>;
  if (!d || Object.keys(d).sort().join(',') !== 'createdAt,expiresAt,folder,id,issuedBy,note,role,type,version') throw new InviteError('invite record has unexpected fields');
  if (d.type !== INVITE_RECORD_TYPE || d.version !== 1) throw new InviteError('unknown invite record type');
  if (d.id !== id) throw new InviteError('invite record id does not match its file name');
  if (typeof d.folder !== 'string' || normalizePath(d.folder) !== d.folder || d.folder === '') throw new InviteError('invalid invite record folder');
  if (!REQUEST_ROLES.includes(d.role as RequestRole)) throw new InviteError('invalid invite record role');
  if (typeof d.issuedBy !== 'string' || !FPR_RE.test(d.issuedBy)) throw new InviteError('invalid invite record issuer');
  if (typeof d.createdAt !== 'string' || !RFC3339_RE.test(d.createdAt) || typeof d.expiresAt !== 'string' || !RFC3339_RE.test(d.expiresAt)) throw new InviteError('invalid invite record times');
  if (d.note !== null && (typeof d.note !== 'string' || d.note.length > 500)) throw new InviteError('invalid invite record note');
  return d as InviteRecord;
}

export type InviteRecordStatus =
  | { valid: true; record: InviteRecord }
  | { valid: false; reason: string; exists: boolean };

const ROLE_RANK: Record<RequestRole, number> = { reader: 0, 'folder-admin': 1 };

/**
 * Is there a VALID invite record `id` for a request of `role` on `folder`?
 * Valid = canonical, signed by `issuedBy` (key in `.public-keys`, valid now),
 * `issuedBy` is a trust anchor or a verified admin of the folder in THIS
 * snapshot (never escrow), unexpired, same folder, role <= the record's role.
 */
export async function verifyInviteRecord(
  snapshot: StoreSnapshot,
  id: string,
  want: { folder: string; role: RequestRole; now?: Date },
  signal?: AbortSignal,
): Promise<InviteRecordStatus> {
  if (!ID_RE.test(id)) return { valid: false, reason: 'invalid invite id', exists: false };
  const bytes = await snapshot.readFile(inviteRecordPath(id), signal);
  if (!bytes) return { valid: false, reason: 'no invite record with this id (never issued, or already used)', exists: false };
  const no = (reason: string): InviteRecordStatus => ({ valid: false, reason, exists: true });
  let rec: InviteRecord;
  try {
    rec = parseInviteRecord(bytes, id);
  } catch (e) {
    return no((e as Error).message);
  }
  const now = want.now ?? trustEnvironment().now();
  if (Date.parse(rec.expiresAt) <= now.getTime()) return no('the invite has expired');
  if (rec.folder !== normalizePath(want.folder)) return no(`the invite is for "${rec.folder}", not "${want.folder}"`);
  if (ROLE_RANK[want.role] > ROLE_RANK[rec.role]) return no(`the invite allows the role "${rec.role}" only`);
  const sig = await snapshot.readFile(inviteRecordSigPath(id), signal);
  if (!sig) return no('the invite record is not signed');
  const key = await loadKeyByFingerprint(snapshot, rec.issuedBy, signal);
  if (!key) return no('no public key for the invite issuer');
  try {
    const res = await verifyDetached(bytes, await parseDetachedSignature(sig), [key], now);
    if (!res.ok) return no(`invite record signature: ${res.reason}`);
  } catch (e) {
    return no((e as Error).message);
  }
  const root = await evaluateRootTrust(snapshot, signal);
  if (!root.ok) return no(`root not trusted: ${root.reason}`);
  const admin = await checkFolderAdmin(snapshot, rec.folder, rec.issuedBy, signal);
  if (!admin.admin) return no(`the issuer is not an admin of "${rec.folder}" (${admin.reason})`);
  return { valid: true, record: rec };
}

/** Deletion of a record, for the approval commit (reencryptFolder allows exactly this). */
export function consumeInviteChanges(snapshot: StoreSnapshot, id: string): FileChange[] {
  return [inviteRecordPath(id), inviteRecordSigPath(id)]
    .filter((p) => snapshot.hasFile(p) && INVITE_RECORD_RE.test(p))
    .map((path) => ({ path, delete: true as const }));
}

export interface IssueInviteInput {
  snapshot: StoreSnapshot;
  writer: StoreWriter;
  repo: GitHubRepo;
  folder: string;
  role: RequestRole;
  /** Days until expiry (1..7). */
  days: number;
  note?: string | null;
  /** Requester token (fine-grained, Issues on requestsRepo only). Goes into the LINK only. */
  token: string;
  /** App URL the link opens (origin + path of this deployment). */
  appUrl: string;
  operatorKey: PrivateKey;
  now?: Date;
  signal?: AbortSignal;
}

export interface IssuedInvite extends CommitResult {
  readonly id: string;
  readonly record: InviteRecord;
  /** Contains the token: show once, never store. */
  readonly link: string;
}

/**
 * Commit a signed invite record and return the link. The operator must be an
 * anchor or a verified admin of `folder`; the anchors in the link are the
 * device's verified effective anchors.
 */
export async function issueInvite(i: IssueInviteInput): Promise<IssuedInvite> {
  const folder = normalizePath(i.folder);
  const now = i.now ?? trustEnvironment().now();
  const op = fingerprintOf(i.operatorKey);
  if (!Number.isInteger(i.days) || i.days < 1 || i.days > MAX_INVITE_DAYS) throw new InviteError(`expiry must be 1 to ${MAX_INVITE_DAYS} days`);
  if (!i.snapshot.hasFile(joinPath(folder, '.gpg-id'))) throw new InviteError(`"${folder}" has no .gpg-id of its own`);
  const root = await evaluateRootTrust(i.snapshot, i.signal);
  if (!root.ok) throw new InviteError(`root not trusted: ${root.reason}`);
  const admin = await checkFolderAdmin(i.snapshot, folder, op, i.signal);
  if (!admin.admin) throw new InviteError(`you are not an admin of "${folder}" (${admin.reason})`);
  const requestsRepo = i.repo.requestsRepo?.trim() || `${i.repo.owner}/${i.repo.repo}`;
  const id = newInviteId();
  const expiresAt = rfc3339(new Date(now.getTime() + i.days * 86400_000));
  const record: InviteRecord = {
    createdAt: rfc3339(now),
    expiresAt,
    folder,
    id,
    issuedBy: op,
    note: i.note?.trim() ? i.note.trim().slice(0, 500) : null,
    role: i.role,
    type: INVITE_RECORD_TYPE,
    version: 1,
  };
  const content = canonicalJson(record);
  const payload: InvitePayload = {
    anchors: [...root.anchors],
    branch: i.repo.branch,
    expiresAt,
    folder,
    id,
    issuedBy: op,
    repo: `${i.repo.owner}/${i.repo.repo}`,
    requestsRepo,
    role: i.role,
    storeRoot: normalizePath(i.repo.storeRoot ?? ''),
    token: i.token.trim(),
    type: INVITE_TYPE,
    version: 1,
  };
  validateInvite(JSON.parse(canonicalJson(payload)), now); // same checks the newcomer runs
  const signature = await signDetached(new TextEncoder().encode(content), i.operatorKey, { date: now });
  const res = await i.writer.commit(
    [
      { path: inviteRecordPath(id), content },
      { path: inviteRecordSigPath(id), content: signature },
    ],
    { baseSha: i.snapshot.commitSha, message: `g00pass: invite ${id} (${i.role} on ${folder}, expires ${expiresAt})`, signal: i.signal },
  );
  return { ...res, id, record, link: buildInviteLink(i.appUrl, payload) };
}

export type TokenProbe = { ok: true } | { ok: false; reason: string };

/**
 * Best-effort scope check of a pasted requester token: it must see the
 * requests repo, and must NOT read the store's contents (else over-scoped).
 */
export async function probeInviteToken(client: GitHubClient, repo: GitHubRepo, signal?: AbortSignal): Promise<TokenProbe> {
  const requestsRepo = repo.requestsRepo?.trim() || `${repo.owner}/${repo.repo}`;
  const [owner, name] = requestsRepo.split('/') as [string, string];
  try {
    await client.request('GET', repoPath({ owner, repo: name, branch: 'main' }, ''), undefined, signal);
  } catch (e) {
    return { ok: false, reason: e instanceof GitHubApiError && e.status === 401 ? 'GitHub rejected the token' : `the token cannot see ${requestsRepo}` };
  }
  try {
    await client.request('GET', repoPath(repo, `/git/ref/heads/${refPath(repo.branch)}`), undefined, signal);
    return { ok: false, reason: 'the token is over-scoped: it can read the store contents. Create one with only "Issues: Read and write" on the requests repo.' };
  } catch (e) {
    if (e instanceof GitHubApiError && (e.status === 403 || e.status === 404)) return { ok: true };
    return { ok: false, reason: 'could not check the token scope' };
  }
}
