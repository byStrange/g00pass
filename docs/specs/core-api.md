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
| `TrustError` | choke-point refused | `folder`, `reason`, `code: 'untrusted' \| 'signature-missing' \| 'signature-invalid' \| 'unknown-signer' \| 'escrow-missing' \| 'not-verified' \| 'anchor-mismatch' \| 'replayed' \| 'weak-recipient' \| 'boundary-vanished' \| 'boundary-undeclared'` |
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
NON_ENTRY_DIRS = ['.public-keys', '.gpg-keys', '.g00pass', '.git']   // *.gpg under these are never entries
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
directNestedGpgIdFolders(snapshot, folder): string[]  // nested, not inside another nested one
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
  folder; gpgIdPath; target /* folder the write lands in */; childBoundaries: string[] | null /* proposed */;
  gpgIdContent: Uint8Array; gpgIdSignature: Uint8Array | null;
  proposed: boolean; recipients: readonly ResolvedRecipient[]; snapshot: StoreSnapshot;
}
type TrustDecision = { ok: true; warnings?: string[] } | { ok: false; code: TrustErrorCode; reason: string };
interface TrustHook {
  name: string; verify(req): Promise<TrustDecision>;
  childBoundaries?(snapshot, folder, signal?): Promise<{ ok: true; children } | { ok: false; code; reason }>; // asked before signing
}
type GpgIdSigner = (gpgIdText, { folder, children }) => Promise<Uint8Array>

unconfiguredTrustHook          // default until main.ts installs a policy: refuses everything
passThroughTrustHook           // tests only (test/setup.ts): ok + warning 'recipient-signatures-not-verified'
setTrustHook(hook): TrustHook  // install once at startup (src/main.ts); returns previous
lockTrustHook(): void          // main.ts locks after install; later setTrustHook throws
getTrustHook(): TrustHook

interface VerifiedRecipientSet {   // frozen; only mintable inside trust.ts
  folder; gpgIdPath; fingerprints; keys; snapshotSha; proposed; childBoundaries; warnings; hook
}
isVerifiedRecipientSet(x): boolean
verifyRecipients(snapshot, { entry } | { folder }, { signal? }): Promise<VerifiedRecipientSet>
verifyProposedRecipients(snapshot, folder, lines, { pending?, signature?: Uint8Array | GpgIdSigner, signal? })
  : Promise<{ verified; gpgIdText; gpgIdPath; gpgIdSignature }>
escrowRecipientIds(snapshot): Promise<string[]>
```

The core enforces these rules regardless of which hook is installed:

- **Fail closed.** A hook that throws or returns anything other than `{ok:true}`
  raises `TrustError`.
- **Escrow (proposed sets).** Every root `.gpg-id` line flagged `g00pass:escrow`
  is merged into `gpgIdText`. If the merged set still lacks an escrow
  fingerprint, the result is `TrustError('escrow-missing')`.
- **Escrow (existing sets).** If the folder lacks the escrow recipient, the core
  adds `warnings: ['escrow-missing']`; the production hook then refuses
  (`escrow-missing`).
- **Signature binding.** `signature` may be a callback `(gpgIdText, { folder, children }) => Promise<Uint8Array>`.
  It receives the exact final bytes and the child boundaries to declare
  (from `hook.childBoundaries`, else the nested `.gpg-id` folders present),
  and runs before the hook, so the hook can verify it.

**Signature checks (Phase 1)** are implemented by `signatureTrustHook`
(`src/core/trust-policy.ts`, [gpg-id-signatures.md](gpg-id-signatures.md)),
installed in `src/main.ts`.
Do not add new entry points that produce `VerifiedRecipientSet`. Tests may
call `setTrustHook` freely, but production code may not call it outside
`src/main.ts` (which calls `lockTrustHook()` right after installing the hook).

## Trust policy (Phase 1)

```ts
// src/core/trust-env.ts: device-local inputs; frozen by lockTrustHook()
interface TrustEnvironment { storage; storeId(snapshot): string | null; history(snapshot): FileHistory | null; now(): Date }
trustEnvironment(); setTrustEnvironment(partial) /* tests */; resetTrustEnvironment(); MemoryTrustStorage
storeIdOf(repo): string                      // "owner/repo|storeRoot", lower-cased owner/repo
isTrustHookLocked(): boolean                 // src/core/trust.ts

// src/core/anchors.ts
pinAnchors(store: GitHubRepo | storeId, fingerprints, source: 'first-use' | 'invite' | 'manual'): PinnedAnchors
getPinnedAnchors(store): PinnedAnchors | null; resetAnchors(store): void
evaluateRootTrust(snapshot): Promise<RootTrust>   // { ok, anchors, escrow, signer, rolledOver } | { ok:false, code, reason, added, removed }
normalizeFingerprints(fprs): string[]

// src/core/signatures.ts
signGpgId(text | bytes, folder, privateKey, { date?, children? }): Promise<Uint8Array>   // folder-bound .gpg-id.sig + child@g00pass
childBoundariesFromNotations(values, folder): string[] | errorMessage
signDetached(bytes, privateKey, { notations?, date? }); parseDetachedSignature(bytes); verifyDetached(bytes, parsed, keys, now)
loadKeyByFingerprint(snapshot, FPR): Promise<PublicKey | null>                // primary FPR must match

// src/core/admins.ts
verifyAdminsFile(snapshot, folder): Promise<AdminsFileStatus>                  // absent | valid | invalid(reason)
verifiedFolderAdmins(snapshot, folder): Promise<{ admins: Set<FPR>; files }>
checkFolderAdmin(snapshot, folder, fpr): Promise<{ admin; via: 'anchor' | 'admins-file' | null; grantedBy?; reason }>
isVerifiedFolderAdmin(snapshot, folder, fpr): Promise<boolean>
signAdminsFile({ snapshot, folder, admins, signingKey, date? }): Promise<{ document, path, sigPath, content, signature, changes }>

// src/core/boundaries.ts (gpg-id-signatures.md §Child boundaries)
declaredChildren(snapshot, folder); boundaryChain(snapshot, folder); expectedChildBoundaries(snapshot, folder)
vanishedBoundaryFor(...); knownBoundaries(storeId); recordBoundaries(storeId, folders); allowedSigners(snapshot, folder, root)

// src/core/trust-policy.ts
signatureTrustHook: TrustHook                 // name 'gpg-id signatures v1'; implements childBoundaries
folderTrustStatus(snapshot, folder); allFolderTrustStatus(snapshot)   // UI status = real write-path decision

// src/core/canonical.ts
canonicalJson(v); parseCanonicalJson(bytes); sortKeysDeep(v); sha256Digest(bytes) /* "sha256:hex" */; rfc3339(date)

// src/core/github/history.ts
GitHubFileHistory; GitHubSnapshot.fileHistory()  // history reachable from the snapshot commit
```

## Crypto — `src/core/crypto/`

```ts
encryptToVerified(plaintext: Uint8Array, set: VerifiedRecipientSet, { armor? }): Promise<Uint8Array | string>
decryptEntry(ciphertext: Uint8Array, keys: PrivateKey[], path?): Promise<Uint8Array>  // binary or armored
readProtectedPrivateKey(armored): Promise<PrivateKey>   // refuses unprotected keys
unlockPrivateKey(armored, passphrase): Promise<PrivateKey>
wipe(buf)                                               // best-effort zeroing
```

`encrypt.ts` is the **only** file allowed to call `openpgp.encrypt`. ESLint
`no-restricted-imports`/`no-restricted-properties`/`no-restricted-syntax`
(any `.encrypt(` / `.encryptSessionKey(` call, e.g. `Message#encrypt`) and the
static scan in `test/guards.test.ts` enforce this, and every other file must
use named imports from `openpgp`. At runtime, `installEncryptGuard()`
(called by `src/main.ts`) makes openpgp's `Message#encrypt` and
`Message.encryptSessionKey` refuse any key array that encryptToVerified did
not pass in, and any password. Output is a binary OpenPGP message, which is what
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

## Recipient changes — `src/core/access/recipients.ts`, `approve.ts`

```ts
planFolderRecipientChange(snapshot, folder, { add?, remove? }, { operatorFingerprint })
  : Promise<RecipientChangePlan>   // { folder, before, after, added, removed, droppedEscrow, childBoundaries, digest, warnings }
changeFolderRecipients(folder, change, { snapshot, writer, operatorKey, approvedPlanDigest, ... }): Promise<ReencryptResult>
previewApproval(snapshot, request, operatorFpr): Promise<RecipientChangePlan>
approveAccessRequest(request, { ..., confirmation: { fingerprintSuffix, acknowledgeUninvited?, approvedPlan } })
RecipientChangeError.code: 'invalid-change' | 'not-recipient' | 'folder-not-verified' | 'plan-changed'
```

The plan requires the folder's CURRENT `.gpg-id` to verify (tolerating only
`escrow-missing`), drops retired escrow lines, and is bound to a digest over
`{folder, before, after, childBoundaries}`; `changeFolderRecipients`
recomputes it on its snapshot and refuses a different digest.

## Folder re-encrypt — `src/core/reencrypt.ts`

```ts
reencryptFolder(path, newRecipients: (string | {id, flags?})[], {
  snapshot, writer, decryptionKeys,
  pendingKeys?: Map<FPR, armoredPublicKey>,     // also written to .public-keys/<FPR>
  gpgIdSignature?: Uint8Array | GpgIdSigner,    // (text, { folder, children }) => signGpgId(text, folder, key, { children })
  replaceEntries?: { path, plaintext }[],       // new content for governed entries (e.g. rotation metadata)
  extraChanges?: FileChange[],                  // ONLY <folder>/.g00pass-admins.json(.sig)
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
- **No absorption.** The declared child boundaries of the verified proposal
  must be exactly the nested `.gpg-id`s that are skipped, and every governed
  entry must already be encrypted (by PKESK key id) to every current
  non-escrow recipient of the governing `.gpg-id`; otherwise
  `ReencryptError` (the entry may belong to a deleted boundary). Note: a
  `.gpg-id` that gained a member without re-encrypting (hand-edited and
  signed with gpg) is refused too; re-encrypt with `pass init -p` / gopass.
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
