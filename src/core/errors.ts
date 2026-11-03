/**
 * Error types shared by the core. Rule: error messages may contain store
 * paths, key ids/fingerprints and HTTP status codes; they must NEVER contain
 * plaintext, passphrases, private key material or tokens.
 */

export class G00passError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(redactSecrets(message), options);
    this.name = new.target.name;
  }
}

/** Invalid store path (absolute, `..`, NUL, ...). */
export class StorePathError extends G00passError {}

/** No `.gpg-id` found between an entry and the store root. */
export class NoRecipientsError extends G00passError {
  constructor(public readonly path: string) {
    super(`No .gpg-id found for "${path}" (walked up to the store root)`);
  }
}

/** A recipient id could not be resolved to exactly one usable public key. */
export class RecipientKeyError extends G00passError {
  constructor(
    public readonly recipientId: string,
    reason: string,
  ) {
    super(`Recipient "${recipientId}": ${reason}`);
  }
}

/** The trust choke-point refused a recipient set. Callers must NOT encrypt. */
export class TrustError extends G00passError {
  constructor(
    public readonly folder: string,
    public readonly reason: string,
    public readonly code: TrustErrorCode = 'untrusted',
  ) {
    super(`Refusing to encrypt to recipients of "${folder || '/'}": ${reason}`);
  }
}
export type TrustErrorCode =
  | 'untrusted'
  | 'signature-missing'
  | 'signature-invalid'
  | 'unknown-signer'
  | 'escrow-missing'
  | 'not-verified'
  /** Root `.gpg-id` is not signed by a pinned trust anchor (store-layout.md §Trust anchors). */
  | 'anchor-mismatch'
  /** `.gpg-id` + `.sig` older than a version this device already accepted (rollback). */
  | 'replayed'
  /** Recipient id is not a full primary fingerprint, or its key file does not match it. */
  | 'weak-recipient'
  /** A signed-declared (or device-known) child boundary's `.gpg-id` was deleted (gpg-id-signatures.md §Child boundaries). */
  | 'boundary-vanished'
  /** A nested `.gpg-id` is not declared by its parent boundary's signature, or a new signature declares the wrong children. */
  | 'boundary-undeclared';

/** Decryption of an entry failed (wrong key, corrupt data, not a recipient). */
export class DecryptError extends G00passError {
  constructor(
    public readonly path: string,
    options?: { cause?: unknown },
  ) {
    super(`Could not decrypt "${path}"`, options);
  }
}

/** GitHub API returned a non-success status. */
export class GitHubApiError extends G00passError {
  constructor(
    public readonly status: number,
    message: string,
    public readonly retryAfterSeconds?: number,
  ) {
    super(`GitHub API error ${status}: ${message}`);
  }
}

/**
 * The branch moved since the snapshot the change was computed from. Safe to
 * retry: reload a fresh snapshot, recompute, commit again (see withConflictRetry).
 */
export class ConflictError extends G00passError {
  readonly retryable = true;
  constructor(
    public readonly expectedSha: string,
    public readonly actualSha: string | null,
  ) {
    super(
      `Branch was updated concurrently (expected base ${expectedSha.slice(0, 12)}, ` +
        `found ${actualSha ? actualSha.slice(0, 12) : 'unknown'}). Reload and retry.`,
    );
  }
}

/** Re-encrypt refused or failed; nothing was committed. */
export class ReencryptError extends G00passError {
  constructor(
    message: string,
    public readonly failedPaths: readonly string[] = [],
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }
}

export class AbortError extends G00passError {
  constructor() {
    super('Operation cancelled');
  }
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new AbortError();
}

const TOKEN_PATTERNS: RegExp[] = [
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /(authorization\s*[:=]\s*)(bearer|token)?\s*\S+/gi,
];

/** Best-effort scrubbing of GitHub tokens from any string. */
export function redactSecrets(s: string): string {
  let out = s;
  for (const re of TOKEN_PATTERNS) {
    out = out.replace(re, (m, prefix?: string) =>
      typeof prefix === 'string' && /authorization/i.test(prefix) ? `${prefix}[REDACTED]` : '[REDACTED]',
    );
  }
  return out;
}
