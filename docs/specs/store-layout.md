# Store layout and shared formats

A g00pass store is a normal pass/gopass store. Its root is the repository root
or `GitHubRepo.storeRoot`. Every g00pass addition is either a dot-file, which
pass/gopass ignore, or a comment inside `.gpg-id`, which they also ignore.
**The plain gopass/pass CLI must keep working on the same repo.**

## Files

| Path | Format | Written by | Notes |
| --- | --- | --- | --- |
| `<F>/<name>.gpg` | OpenPGP message, binary (armored accepted) | anyone with write | Entry. Encrypted to the nearest `.gpg-id`. |
| `.gpg-id` (root) | text, one id per line | global admin | Recipients of root entries **and** the list of global admins (see below). Escrow line flagged `g00pass:escrow`. |
| `<F>/.gpg-id` | text | folder admin / global admin | Recipients of folder F (nearest-wins). MUST contain the escrow fingerprint. |
| `<F>/.gpg-id.sig` | detached OpenPGP signature over `.gpg-id` bytes | signer of that `.gpg-id` | [gpg-id-signatures.md](gpg-id-signatures.md). pass-compatible. |
| `.public-keys/<FPR>` | armored OpenPGP public key, exactly one key | approver | gopass convention: file name = id as written in `.gpg-id`. g00pass always writes the upper-case 40-hex (v4) fingerprint as both. |
| `.gpg-keys/<id>` | same | (legacy gopass) | Read-only fallback. |
| `<F>/.g00pass-admins.json` | canonical JSON | global admin / folder admin | [folder-admins.md](folder-admins.md) |
| `<F>/.g00pass-admins.json.sig` | detached signature | same | |
| `<F>/.g00pass-rotation.gpg` | OpenPGP message containing canonical JSON | any recipient of F | [rotation.md](rotation.md). Lives in the folder that owns the `.gpg-id`; re-encrypted together with entries. |
| `.g00pass/invites/<inviteId>.json` + `.sig` | canonical JSON + detached sig | global/folder admin | [access-requests.md](access-requests.md) §Invite registry |
| `.g00pass/config.json` + `.sig` | canonical JSON + detached sig | global admin | Optional store-wide settings (requests repo, label names). See access-requests.md. |

`<F>` denotes a store-relative folder (`""` = root). File names starting with
`.` are hidden from entry listings (`isHiddenEntry`).

## Recipient ids in `.gpg-id`

- g00pass **writes** upper-case 40-hex v4 fingerprints, one per line. If the
  line carries a g00pass flag, it is followed by ` # g00pass:<flag>`. The output
  of `serializeGpgId` is the canonical form.
- g00pass **reads** whatever pass and gopass accept: fingerprints, long or short
  key ids, `0x` prefixes, and e-mail addresses. Short ids and e-mail ids resolve
  only through `.public-keys/<id>` and are weak. The UI SHOULD show a warning for
  them.
- Known flags:
  - `escrow`: org recovery key (recovery.md). Meaningful in the root `.gpg-id`;
    copied into every folder `.gpg-id`.

Example root `.gpg-id`:

```
# global admins
3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B
9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A2F1E0D
# org recovery key, offline
0123456789ABCDEF0123456789ABCDEF01234567 # g00pass:escrow
```

Example `infra/.gpg-id` as written by `reencryptFolder`:

```
3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B
AAAABBBBCCCCDDDDEEEEFFFF0000111122223333
0123456789ABCDEF0123456789ABCDEF01234567 # g00pass:escrow
```

## Global admins and trust anchors

- **Global admins** are the non-escrow recipients of the root `.gpg-id`.
- The root `.gpg-id` cannot vouch for itself, because anyone with write access
  could replace it and self-sign. Each device therefore keeps **trust anchors**,
  a locally pinned set of global-admin fingerprints. They are stored in
  `localStorage` under `g00pass.trust-anchors.v1` as
  `{"repo":"owner/repo","storeRoot":"","anchors":["FPR",...],"pinnedAt":"ISO"}`.
  They are not secret, but they MUST NOT be writable from the store.
- Anchors are set in one of three ways:
  1. From an invite link (`anchors` field, access-requests.md). The user
     confirms the fingerprints in the UI.
  2. On first use: the client shows the root `.gpg-id` fingerprints and asks
     the user to confirm them out of band.
  3. Manually in settings.
- Anchors are updated automatically **only** when a new root `.gpg-id` carries
  a valid `.gpg-id.sig` from a currently pinned anchor. In that case the new
  anchor set is the new root `.gpg-id`'s non-escrow fingerprints. Any other
  change to the root `.gpg-id` is treated as untrusted (gpg-id-signatures.md).

## Shared formats

**Fingerprint (`FPR`)**: upper-case hex of the primary key fingerprint, 40
chars for v4 keys and 64 for v6. v6 keys MUST NOT be enrolled while gopass/gpg
interop is required. Comparisons always use `normalizeKeyId`.

**Timestamps**: RFC 3339 UTC with `Z` and no fractional seconds, e.g.
`2026-11-02T10:15:00Z`.

**Canonical JSON** (for every signed g00pass JSON file):

- UTF-8 with no BOM.
- Object keys sorted lexicographically by UTF-16 code unit at every level.
- 2-space indentation, `\n` line endings, and one trailing `\n`.
- Produced by: `JSON.stringify(sortKeysDeep(value), null, 2) + '\n'`.
- No `undefined`, no NaN or Infinity, and optional fields are written as
  `null`.

Verifiers check signatures over the **raw bytes** of the file. They never
re-serialize first. After verifying, they parse the bytes and SHOULD reject a
file that does not round-trip to identical bytes, which rejects non-canonical
files.

**Detached signatures** (`*.sig`):

- A binary OpenPGP detached signature of type 0x00 (binary document) over the
  exact file bytes. This is what `gpg --detach-sign` produces, and pass
  uses the same format for `.gpg-id.sig`.
- Verifiers also accept an armored signature.
- openpgp.js: `sign({ message: await createMessage({ binary: bytes }), signingKeys, detached: true, format: 'binary' })`.
- The signer's public key MUST be available at `.public-keys/<FPR>` in the same
  snapshot.
- The signature counts for a fingerprint `S` if the issuer key's primary
  fingerprint **or** the signing subkey's fingerprint equals `S`. This is
  pass's `VALIDSIG` rule.

**Signed JSON envelope type tags**: every g00pass JSON document has
`"type": "g00pass.<kind>"` and `"version": <int>`. Verifiers MUST reject unknown
types and versions newer than they support.
