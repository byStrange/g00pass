import type { PrivateKey } from 'openpgp';
import { signDetached } from '../crypto/sign';
import { G00passError } from '../errors';
import { joinPath, normalizePath } from '../paths';
import type { FileChange, StoreSnapshot } from '../store';
import { canonicalJson } from './canonical';
import { ADMINS_FILE, ADMINS_SIG_FILE } from './folders';

const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const FPR_RE = /^[0-9A-F]{40}$/;

/**
 * New `.g00pass-admins.json` (+ `.sig`) for `folder` with `add` merged in
 * (docs/specs/folder-admins.md §Operations). Returns the file changes for
 * `reencryptFolder({ extraChanges })`. The caller recomputes this on every
 * conflict retry, so `serial`/`previous` always match the fresh snapshot.
 */
export async function buildAdminsFileUpdate(
  snapshot: StoreSnapshot,
  folder: string,
  add: readonly string[],
  signer: PrivateKey,
  now: Date = new Date(),
): Promise<FileChange[]> {
  const f = normalizePath(folder);
  if (f === '') throw new G00passError('There is no admins file at the store root');
  for (const a of add) if (!FPR_RE.test(a)) throw new G00passError('Invalid admin fingerprint');
  const path = joinPath(f, ADMINS_FILE);
  const prev = await snapshot.readFile(path);
  let admins = [...add];
  let serial = 1;
  let previous: string | null = null;
  if (prev) {
    let old: { admins?: unknown; serial?: unknown };
    try {
      old = JSON.parse(new TextDecoder().decode(prev));
    } catch {
      throw new G00passError(`${path} is unreadable; refusing to overwrite it`);
    }
    if (!Array.isArray(old.admins) || !Number.isSafeInteger(old.serial)) {
      throw new G00passError(`${path} is malformed; refusing to overwrite it`);
    }
    admins = [...(old.admins as string[]), ...add];
    serial = (old.serial as number) + 1;
    previous = 'sha256:' + hex(await crypto.subtle.digest('SHA-256', new Uint8Array(prev)));
  }
  const text = canonicalJson({
    admins: [...new Set(admins.map((a) => a.toUpperCase()))].sort(),
    folder: f,
    previous,
    serial,
    type: 'g00pass.folder-admins',
    updatedAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    updatedBy: signer.getFingerprint().toUpperCase(),
    version: 1,
  });
  const sig = await signDetached(text, signer);
  return [
    { path, content: text },
    { path: joinPath(f, ADMINS_SIG_FILE), content: sig },
  ];
}
