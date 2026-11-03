import type { PrivateKey } from 'openpgp';
import { G00passError } from '../errors';
import { type GpgIdLine, normalizeKeyId } from '../gpgid';
import { fingerprintOf, parsePublicKey } from '../keys';
import { PUBLIC_KEYS_DIR, joinPath, normalizePath } from '../paths';
import { type ReencryptOptions, type ReencryptProgress, type ReencryptResult, reencryptFolder } from '../reencrypt';
import { type StoreSnapshot, type StoreWriter, listGovernedEntries } from '../store';
import { signGpgId } from '../signatures';
import { escrowRecipientIds } from '../trust';
import { idMatchesFingerprint, readRecipientLines } from './folders';

export interface RecipientChange {
  /** Recipients to add; `publicKey` is committed to `.public-keys/<FPR>`. */
  add?: readonly { fingerprint: string; publicKey: string }[];
  /** Fingerprints (40 hex) to remove. The escrow recipient can never be removed. */
  remove?: readonly string[];
}

export interface ChangeRecipientsOptions {
  snapshot: StoreSnapshot;
  writer: StoreWriter;
  /** Unlocked operator key: decrypts every entry and signs the new `.gpg-id`. */
  operatorKey: PrivateKey;
  message?: string;
  /** Default: armored (single tree request) when the folder has more than 50 entries. */
  armor?: boolean;
  extraChanges?: ReencryptOptions['extraChanges'];
  replaceEntries?: ReencryptOptions['replaceEntries'];
  chunkSize?: number;
  onProgress?: (p: ReencryptProgress) => void;
  signal?: AbortSignal;
}

/** GitHub throttles content creation (~80/min); above this, armored inline content is used. */
export const ARMOR_THRESHOLD = 50;

const FPR_RE = /^[0-9A-F]{40}$/;

/**
 * recipient-change + sign + re-encrypt + commit pipeline, shared by
 * "approve request" (add) and, in Phase 2, "remove member" (remove).
 *
 * One commit contains: all governed entries re-encrypted, the new `.gpg-id`,
 * its detached `.gpg-id.sig` (signed by `operatorKey`, bound to the folder via the `folder@g00pass` notation), new `.public-keys/*`,
 * plus `extraChanges`. Callers wrap this in `withConflictRetry` with a fresh
 * snapshot per attempt. Encryption goes through reencryptFolder, i.e. the
 * trust choke-point; escrow recipients are merged back in by the core.
 */
export async function changeFolderRecipients(
  folder: string,
  change: RecipientChange,
  opts: ChangeRecipientsOptions,
): Promise<ReencryptResult> {
  const f = normalizePath(folder);
  const { snapshot, operatorKey } = opts;
  if (f === '') throw new G00passError('Changing the root recipient list is not supported here');
  const current = await readRecipientLines(snapshot, f, opts.signal);
  if (!current) throw new G00passError(`"${f}" has no .gpg-id of its own`);
  const operatorFpr = fingerprintOf(operatorKey);
  if (!current.some((l) => idMatchesFingerprint(l.id, operatorFpr))) {
    throw new G00passError(`Your key is not a recipient of "${f}", so you cannot decrypt it to change access`);
  }

  const escrow = await escrowRecipientIds(snapshot, opts.signal);
  let lines: GpgIdLine[] = current.map((l) => ({ id: l.id, flags: l.flags }));

  const remove = (change.remove ?? []).map((r) => r.toUpperCase());
  for (const r of remove) {
    if (!FPR_RE.test(r)) throw new G00passError('Invalid fingerprint to remove');
    if (escrow.some((e) => idMatchesFingerprint(e, r))) throw new G00passError('The escrow recipient cannot be removed');
    if (!lines.some((l) => idMatchesFingerprint(l.id, r))) throw new G00passError('Fingerprint to remove is not a recipient');
    lines = lines.filter((l) => !idMatchesFingerprint(l.id, r));
  }

  const pending = new Map<string, string>();
  for (const a of change.add ?? []) {
    const fpr = a.fingerprint.toUpperCase();
    if (!FPR_RE.test(fpr)) throw new G00passError('Invalid fingerprint to add');
    if (lines.some((l) => idMatchesFingerprint(l.id, fpr))) throw new G00passError('Already a recipient');
    const keys = await parsePublicKey(a.publicKey, fpr);
    if (keys.length !== 1 || fingerprintOf(keys[0]!) !== fpr) throw new G00passError('Public key does not match fingerprint');
    pending.set(fpr, a.publicKey);
    lines.push({ id: fpr, flags: [] });
  }
  const escrowIds = new Set(escrow.map(normalizeKeyId));
  if (!lines.some((l) => !escrowIds.has(normalizeKeyId(l.id)))) {
    throw new G00passError('Refusing to leave the folder with only the escrow recipient');
  }
  // The signer's public key must be in the store for signature verification.
  const opKeyPath = joinPath(PUBLIC_KEYS_DIR, operatorFpr);
  if (!snapshot.hasFile(opKeyPath) && !pending.has(operatorFpr)) pending.set(operatorFpr, operatorKey.toPublic().armor());

  const total = listGovernedEntries(snapshot, f).length;
  return reencryptFolder(f, lines, {
    snapshot,
    writer: opts.writer,
    decryptionKeys: [operatorKey],
    pendingKeys: pending,
    gpgIdSignature: (text) => signGpgId(text, f, operatorKey),
    replaceEntries: opts.replaceEntries,
    extraChanges: opts.extraChanges,
    message: opts.message,
    chunkSize: opts.chunkSize,
    armor: opts.armor ?? total > ARMOR_THRESHOLD,
    onProgress: opts.onProgress,
    signal: opts.signal,
  });
}
