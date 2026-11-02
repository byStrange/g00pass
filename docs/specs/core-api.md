# Core API (Phase 0)

All modules live in `src/core/` and are re-exported from `src/core/index.ts`.
They are pure TypeScript with no DOM dependencies (except `sessionStorage` in
`TokenStore`, which is injectable), and they are unit-tested in `test/`.

Paths are **store-relative** and normalized: no leading or trailing `/`, `/`
separated, and the root is `""`. `..`, `\` and NUL are rejected (`StorePathError`).
An *entry* is a file ending in `.gpg`, and its *name* is the path without `.gpg`.

## Errors — `src/core/errors.ts`

Every error extends `G00passError`, whose message passes through
`redactSecrets()`. Messages may contain paths, fingerprints and HTTP status
codes. They must never contain plaintext, passphrases, keys or tokens.

| Class | When | Fields |
| --- | --- | --- |
| `StorePathError` | bad path | |
| `NoRecipientsError` | no `.gpg-id` up to the root | `path` |
| `RecipientKeyError` | id doesn't resolve to exactly one usable public key | `recipientId` |
| `TrustError` | choke-point refused | `folder`, `reason`, `code: 'untrusted' \| 'signature-missing' \| 'signature-invalid' \| 'unknown-signer' \| 'escrow-missing' \| 'not-verified'` |
| `DecryptError` | entry can't be decrypted | `path` |
| `GitHubApiError` | non-2xx from GitHub | `status`, `retryAfterSeconds?` |
| `ConflictError` | branch moved since the snapshot | `expectedSha`, `actualSha`, `retryable = true` |
| `ReencryptError` | re-encrypt refused; nothing committed | `failedPaths` |
| `AbortError` | `signal` aborted | |

## Paths — `src/core/paths.ts`

```ts
GPG_ID = '.gpg-id'; GPG_ID_SIG = '.gpg-id.sig'; ENTRY_EXT = '.gpg'
PUBLIC_KEYS_DIR = '.public-keys'; LEGACY_PUBLIC_KEYS_DIR = '.gpg-keys'
normalizePath(p): string            joinPath(...parts): string
dirname(p) / basename(p)            isWithin(p, folder): boolean
isEntryFile(p) / entryName(p) / entryFile(nameOrPath)
ancestorsInclusive(folder): string[] // "a/b" -> ["a/b","a",""]
isHiddenEntry(p): boolean            // any dot-segment; hide from UI lists
```

## Recipients — `src/core/gpgid.ts`

```ts
interface GpgIdRecipient { id: string; flags: string[]; line: number }
parseGpgId(text): GpgIdRecipient[]
recipientIds(recipients): string[]            // dedup by normalized id, order kept
serializeGpgId(lines: (string | {id, flags?})[]): string   // deterministic, '\n', trailing newline
normalizeKeyId(id): string                    // hex: upper, no 0x/spaces; else lower-case
keyIdKind(id): 'fingerprint' | 'long-id' | 'short-id' | 'user-id'
findGpgIdForEntry(hasFile, entry): string     // throws NoRecipientsError
findGpgIdForFolder(hasFile, folder): string   // folder itself first
gpgIdFolder(gpgIdPath): string
ESCROW_FLAG = 'escrow'
```

**Parsing** matches pass (`${id%%#*}`) and gopass (`strings.Cut(line, "#")`):
one id per line, trimmed, blank lines ignored, and `#` starting a comment at any
position. The g00pass extension is that tokens `g00pass:<flag>` inside the
trailing comment become `flags`. pass and gopass ignore them. See store-layout.md.

**Nearest `.gpg-id`**: for an entry, start in the entry's directory and walk up
to the root, as pass does. gopass starts one level deeper: for entry `a/b` it
first checks `a/b/.gpg-id`. The two only differ when a folder and an entry share
a name (`a/b/` and `a/b.gpg`). Avoid creating that layout. For a folder, start
at the folder itself.

## Store — `src/core/store.ts`

```ts
interface StoreSnapshot {
  readonly commitSha: string;                 // optimistic-concurrency base
  listFiles(): readonly string[]; hasFile(path): boolean;
  readFile(path, signal?): Promise<Uint8Array | null>;
}
type FileChange = { path; content: Uint8Array | string } | { path; delete: true };
interface StoreWriter {
  commit(changes, { baseSha, message, signal? }): Promise<{ commitSha; treeSha }>; // ConflictError if moved
}
listEntries(snapshot, folder = ''): string[]          // all *.gpg below, recursive
listGovernedEntries(snapshot, folder): string[]       // stops at nested .gpg-id folders
nestedGpgIdFolders(snapshot, folder): string[]
class MemoryStore / MemoryWriter                      // tests; same CAS semantics
```

**Invariant:** every read used to compute a change comes from one snapshot, and
that snapshot's `commitSha` is the `baseSha` of the write.

## Public keys — `src/core/keys.ts`

```ts
interface ResolvedRecipient { id; fingerprint /* upper hex */; key: PublicKey; source }
resolveRecipient(snapshot, id, { pending?, date?, signal? }): Promise<ResolvedRecipient>
resolveRecipients(snapshot, ids, opts): Promise<ResolvedRecipient[]>   // dedup by fingerprint
parsePublicKey(data, id?): Promise<PublicKey[]>   // rejects private key material
keyMatchesId(key, id): boolean; fingerprintOf(key): string
```

The lookup order is deterministic, and the first existing file wins:
1. `.public-keys/<id as written>` (gopass writes the canonical fingerprint here)
2. `.public-keys/<normalizeKeyId(id)>`
3. `.gpg-keys/<id>` (gopass legacy)
4. `pending` (keys added in the same commit), keyed by fingerprint

The chosen file must contain exactly one key matching the id. That key must be
public and have a valid encryption subkey (not expired or revoked). There are
no keyserver or keyring lookups.

## Trust choke-point — `src/core/trust.ts`

```ts
interface RecipientVerificationRequest {
  folder; gpgIdPath; gpgIdContent: Uint8Array; gpgIdSignature: Uint8Array | null;
  proposed: boolean; recipients: readonly ResolvedRecipient[]; snapshot: StoreSnapshot;
}
type TrustDecision = { ok: true; warnings?: string[] } | { ok: false; code: TrustErrorCode; reason: string };
interface TrustHook { name: string; verify(req): Promise<TrustDecision> }

passThroughTrustHook           // Phase 0 default: ok + warning 'recipient-signatures-not-verified'
setTrustHook(hook): TrustHook  // install once at startup (src/main.ts); returns previous
getTrustHook(): TrustHook

interface VerifiedRecipientSet {   // frozen; only mintable inside trust.ts
  folder; gpgIdPath; fingerprints; keys; snapshotSha; proposed; warnings; hook
}
isVerifiedRecipientSet(x): boolean
verifyRecipients(snapshot, { entry } | { folder }, { signal? }): Promise<VerifiedRecipientSet>
verifyProposedRecipients(snapshot, folder, lines, { pending?, signature?, signal? })
  : Promise<{ verified; gpgIdText; gpgIdPath; gpgIdSignature }>
escrowRecipientIds(snapshot): Promise<string[]>
```

The core enforces these rules regardless of which hook is installed:

- **Fail closed.** A hook that throws or returns anything other than `{ok:true}`
  raises `TrustError`.
- **Escrow (proposed sets).** Every root `.gpg-id` line flagged `g00pass:escrow`
  is merged into `gpgIdText`. If the merged set still lacks an escrow
  fingerprint, the result is `TrustError('escrow-missing')`.
- **Escrow (existing sets).** If the folder lacks the escrow recipient, the set
  is still allowed but gets a `warnings: ['escrow-missing']` entry.
- **Signature binding.** `signature` may be a callback `(gpgIdText) => Promise<Uint8Array>`.
  It receives the exact final bytes and runs before the hook, so the hook can
  verify it.

**To implement signature checks**, write a `TrustHook` that follows
[gpg-id-signatures.md](gpg-id-signatures.md) and install it in `src/main.ts`.
Do not add new entry points that produce `VerifiedRecipientSet`.

## Crypto — `src/core/crypto/`

```ts
encryptToVerified(plaintext: Uint8Array, set: VerifiedRecipientSet, { armor? }): Promise<Uint8Array | string>
decryptEntry(ciphertext: Uint8Array, keys: PrivateKey[], path?): Promise<Uint8Array>  // binary or armored
readProtectedPrivateKey(armored): Promise<PrivateKey>   // refuses unprotected keys
unlockPrivateKey(armored, passphrase): Promise<PrivateKey>
wipe(buf)                                               // best-effort zeroing
```

`encrypt.ts` is the **only** file allowed to call `openpgp.encrypt`. ESLint
`no-restricted-imports`/`no-restricted-properties` and the static scan in
`test/guards.test.ts` enforce this, and every other file must use named
imports from `openpgp`. Output is a binary OpenPGP message, which is what
pass/gopass write. Armor is optional, and gpg/pass/gopass read both.

Key generation for enrollment MUST use v4 keys (`type: 'ecc', curve:
'curve25519Legacy'`, or RSA ≥ 3072) so that gpg and gopass can use them. It
MUST also use openpgp.js's default iterated-and-salted S2K for the passphrase.

**Argon2:** openpgp.js decrypts Argon2-S2K-protected keys with WebAssembly,
which the CSP blocks (there is no `'wasm-unsafe-eval'`). Such keys fail to
unlock with a `KeyUnlockError`. Do not loosen the CSP to fix this. Re-export
the key with iterated S2K instead.

## Entries — `src/core/entries.ts`

```ts
readEntry(snapshot, entry, keys, signal?): Promise<Uint8Array>
writeEntry({ snapshot, writer, entry, plaintext, companions?, message?, armor?, signal })
  : Promise<{ commitSha; treeSha; path; gpgIdPath; fingerprints; warnings }>
```

`writeEntry` uses the nearest `.gpg-id` (`verifyRecipients({entry})`).
`companions` are additional encrypted files committed in the same commit, and
each must be governed by the same `.gpg-id`. The rotation metadata is an
example (rotation.md).

## Folder re-encrypt — `src/core/reencrypt.ts`

```ts
reencryptFolder(path, newRecipients: (string | {id, flags?})[], {
  snapshot, writer, decryptionKeys,
  pendingKeys?: Map<FPR, armoredPublicKey>,     // also written to .public-keys/<FPR>
  gpgIdSignature?: Uint8Array | ((gpgIdText) => Promise<Uint8Array>),
  replaceEntries?: { path, plaintext }[],       // new content for governed entries (e.g. rotation metadata)
  extraChanges?: FileChange[],                  // e.g. admins file; may not touch *.gpg / .gpg-id
  message?, chunkSize? = 20, armor?, onProgress?, signal?,
}): Promise<{ commitSha; treeSha; folder; entries; fingerprints; gpgIdText; warnings }>
type ReencryptProgress = { phase: 'verifying' | 'reencrypting' | 'committing' | 'done'; done; total }
```

Semantics:
- **Scope** is `listGovernedEntries(folder)`, which includes hidden metadata
  entries such as `.g00pass-rotation.gpg` and stops at nested folders that have
  their own `.gpg-id`. Running it on a folder without its own `.gpg-id` creates
  a new boundary there.
- **Recipients** pass through `verifyProposedRecipients`, so escrow is always
  kept.
- **All or nothing.** Every entry is decrypted in memory. If any entry fails,
  the call throws `ReencryptError(failedPaths)` and nothing is committed.
- **Plaintext** buffers are wiped after re-encryption.
- **One commit** contains the entries, the new `.gpg-id`, and the new
  `.gpg-id.sig`. If no new signature is given, any stale `.gpg-id.sig` is
  deleted. The same commit adds new `.public-keys/<FPR>` files and any
  `extraChanges`.
- **Cancellation** checks `signal` between entries and before the commit.
- **Conflicts** surface as `ConflictError`. Reload the snapshot and call again.

Large folders: blobs are uploaded at concurrency 2. GitHub limits
content-creating requests (roughly 80 per minute), so for folders with more
than about 50 entries, pass `armor: true`. Armored ciphertext goes inline in a
single tree request instead of one blob per entry.

## GitHub — `src/core/github/`

```ts
type TokenProvider = () => string | null
interface GitHubRepo { owner; repo; branch; storeRoot? }
class GitHubClient({ token: TokenProvider, fetch?, baseUrl? }).request<T>(method, path, body?, signal?)
class GitHubSnapshot  // .load(client, repo, { commitSha?, signal? }) — Git Data API, recursive tree
getBranchHead(client, repo): Promise<sha>
commitChanges(client, repo, changes, { baseSha, message, signal?, concurrency? }): Promise<CommitResult>
class GitHubWriter(client, repo) implements StoreWriter
withConflictRetry(attempt: (n) => Promise<T>, { attempts = 3, signal?, onConflict? })
```

A commit runs these steps: `GET ref` (must equal `baseSha`, otherwise
`ConflictError`) → `GET commit` → `POST blobs` (binary) or inline tree content
(strings) → `POST tree` (`base_tree`, deletions as `sha: null`) → `POST commit`
(`parents: [baseSha]`) → `PATCH ref {force:false}`.

If GitHub rejects the ref update (422 or 409), the outcome depends on the
branch head. If the head moved, the error becomes `ConflictError`. If the head
did not move (for example, branch protection refused the update), the original
`GitHubApiError` is rethrown.

Truncated recursive trees (very large repos) are rejected with a clear error
for now.

Tokens are only read through the provider. They are sent only as an
`Authorization: Bearer` header to `baseUrl`, never placed in URLs, and are
scrubbed from error messages.

## Tokens — `src/core/token.ts`

`new TokenStore('memory' | 'session')`: `get` (bound, usable as a `TokenProvider`),
`set(token, persistence?)`, `clear()`, `hasToken`. `toJSON()` returns a
placeholder. Tokens are never stored in `localStorage` (enforced by a lint rule
and a guard test).
