# `.gpg-id` signatures

Status: **implemented** (Phase 1) as `signatureTrustHook` in
`src/core/trust-policy.ts`. `src/main.ts` installs it and then calls
`lockTrustHook()`. Tests: `test/trust-policy.test.ts`.

## Threat

Anyone with write access to the repository could edit a `.gpg-id` and add
their own key. Future secrets would then be encrypted to them. Write access is
not the same as authority, so the client must verify who authored each
recipient list before it encrypts.

## Format and compatibility with pass and gopass

- **pass** with `PASSWORD_STORE_SIGNING_KEY="FPR1 FPR2"` writes
  `<folder>/.gpg-id.sig` using `gpg --detach-sign` (binary) on every
  `pass init`, and accepts it when `VALIDSIG` reports a listed fingerprint
  (signing subkey or primary key).
- g00pass uses **the same file name and packet format**: one binary-document
  (type 0x00) signature packet over the exact `.gpg-id` bytes, binary or
  armored. pass and `gpg --verify` accept every signature g00pass writes.
- **Folder binding (g00pass addition).** The signature MUST carry a signed
  (hashed-area), non-critical notation

  ```
  folder@g00pass=/<folder>        e.g. "/" for the root, "/infra", "/clients/x"
  ```

  Without it, a `.gpg-id` + `.gpg-id.sig` pair signed for folder A can be
  copied over folder B and still verify (the bytes are identical). That
  cross-folder replay works against plain pass too. gpg and pass ignore the
  notation, so the format stays byte-compatible. **A plain pass signature without
  the notation is rejected for writing** (`signature-invalid`, "not bound to a
  folder"). To produce a valid one with pass:

  ```sh
  PASSWORD_STORE_SIGNING_KEY=<FPR> \
  PASSWORD_STORE_GPG_OPTS="--sig-notation folder@g00pass=/infra" \
  pass init -p infra <FPR…>
  # or directly: gpg -u <FPR> --sig-notation folder@g00pass=/infra --detach-sign -o infra/.gpg-id.sig infra/.gpg-id
  ```

  Only hashed notations count. openpgp.js ignores notations in the unhashed
  area, so they cannot be injected without breaking the signature (tested).
- **Child boundaries (g00pass addition, see below).** The signature also
  carries one hashed, non-critical notation `child@g00pass=/<child>` per
  DIRECT nested folder that has its own `.gpg-id`. gpg and pass ignore it.
- **gopass** neither creates nor checks `.gpg-id.sig`. After
  `gopass recipients add/remove`, the old `.sig` no longer matches, and
  g00pass refuses to encrypt in that folder until an admin re-signs it.
- `reencryptFolder` writes a fresh signature in the same commit. Without
  one, the proposal is refused (`signature-missing`).

Producer: `signGpgId(text, folder, privateKey, { date?, children? })` in
`src/core/signatures.ts`.

## Child boundaries

**Threat.** pass and gopass pick the governing `.gpg-id` by file presence
(nearest wins). Anyone with repo write who deletes `infra/prod/.gpg-id` (and
its `.sig`) silently moves `infra/prod/**` under `infra`: new writes are
encrypted to the `infra` members, and the next re-encrypt of `infra`
re-encrypts the existing `infra/prod` entries to them as well.

**Rule: the boundary set is signed state.** Every `.gpg-id.sig` declares the
folder's direct child boundaries:

```
child@g00pass=/infra/prod        one notation per direct child; repeatable
```

Values are normalized absolute folders strictly below the signed folder; no
value may lie inside another (only direct children); duplicates and anything
else make the signature `signature-invalid`. A folder with no nested
boundaries carries no `child@g00pass` notation.

The policy (`src/core/boundaries.ts`) enforces, on top of the per-folder checks:

1. **Declared chain.** A folder F ≠ root with its own `.gpg-id` is a trusted
   boundary only if the verified (authorized, folder-bound, not replayed)
   signature of its nearest parent boundary P declares F, and P is itself
   declared by its parent, up to the root. Otherwise writes in F are refused
   (`boundary-undeclared`), or `boundary-vanished` when P declares a boundary
   between P and F that no longer exists. Verified parents raise their replay
   high-water marks.
2. **Vanished boundary.** A write whose target folder lies inside a child
   that the governing folder's signature declares, or inside any boundary this
   device has verified before (`g00pass.boundaries-seen.v1`), but whose
   `.gpg-id` is gone, is refused (`boundary-vanished`). Writes elsewhere in
   the governing folder still work; the status shows the warning
   `boundary-vanished:<child>`.
3. **Re-signing F (approve / remove / re-encrypt).** The new signature must
   declare exactly the expected children (`TrustHook.childBoundaries`, which
   the core passes to the signer callback `(text, { folder, children })`):
   - every child declared by F's current verified signature, and every
     device-known boundary below F, must still exist (else refused:
     re-encrypting would absorb their entries);
   - a declared child must still be a direct child;
   - an undeclared nested `.gpg-id` is adopted only if its own signature
     verifies for its folder ("catch-up" after a gpg bootstrap); otherwise
     the re-sign is refused until it is deleted or signed;
   - a new boundary (F without `.gpg-id`) must already be declared by its
     parent (declare, then create), and may not be created above existing
     nested boundaries.
4. **No absorption (core).** `reencryptFolder` refuses if the declared
   children do not match the nested `.gpg-id`s it skips, and refuses any
   governed entry whose PKESK recipient key ids do not include every current
   non-escrow recipient of the governing `.gpg-id` (`ReencryptError` listing
   paths and missing fingerprints). Such an entry was encrypted for a
   narrower set, e.g. a deleted boundary. Entries with an anonymous recipient
   (`gpg --throw-keyids`) cannot be checked and are let through.

Boundary removal (merging a child back into its parent) is not supported in
Phase 1: devices that verified the child keep refusing until their derived
trust state is reset (re-pin or reset the anchors).

## Recipient ids

Every recipient line of a `.gpg-id` that g00pass encrypts to MUST be the
**full primary fingerprint** of its key, and the key file MUST contain that
exact primary key. Short ids, long ids, e-mail addresses and subkey
fingerprints are refused (`weak-recipient`), because they bind the signed list
to a key file the attacker can swap. A key file whose primary fingerprint
differs from the id never resolves (`RecipientKeyError`). Reading is
unaffected.

## Valid signers

```
allowed("")  = anchors
allowed(F)   = anchors ∪ admins(F)                    (F ≠ root)
admins(F)    = ⋃ { admins of the VALID .g00pass-admins.json at G | G ∈ {F, parent(F), …}, G ≠ root }
anchors      = non-escrow fingerprints of the root .gpg-id, IF the root verifies (below)
```

- Escrow fingerprints are never signers, even if pinned or listed.
- Admin authority is **hierarchical**: an admin of `infra` may sign
  `infra/prod/.gpg-id`. Invalid admins files contribute nothing and block
  nothing (folder-admins.md).
- The signer's key is read only from `.public-keys/<FPR>`. The file MUST hold
  exactly one key whose primary fingerprint is `FPR`.

## Root `.gpg-id` and pinned anchors

The root cannot vouch for itself (store-layout.md §Trust anchors). The root is
**trusted** iff:

1. this device has pinned anchors for the store;
2. every id in it is a full fingerprint;
3. `.gpg-id.sig` verifies, is bound to `/`, and its signer is a pinned anchor
   (or, for exactly the root version that caused the last rollover, its
   signer: an anchor may sign themselves out);
4. its signature is not older than the newest root signature this device
   accepted (rollback).

If the trusted root's admin set differs from the pinned set, the pinned set is
**replaced** by it (rollover, `source: "rollover"`).

**If the root is not trusted, nothing in the store is writable.** The escrow
recipient comes from the root, and so do the anchors. The UI shows a red banner
with the added and removed fingerprints.

## Verification algorithm (`signatureTrustHook.verify`)

Input: `RecipientVerificationRequest` (`folder`, `gpgIdContent`,
`gpgIdSignature`, `proposed`, `recipients`, `snapshot`). Everything is read
from `snapshot`, the same snapshot the caller encrypts from and uses as the
commit base. Device state comes from the locked trust environment.

1. Unknown store identity → `untrusted`.
2. Root not trusted → its code (`untrusted` when no anchors are pinned,
   `anchor-mismatch`, `signature-*`, `weak-recipient`, `replayed`).
3. `gpgIdSignature` null → `signature-missing`.
4. Parse: exactly one packet, type 0x00, v4/v6, creation time present; else
   `signature-invalid`.
5. Verify over the exact bytes against each key in `allowed(folder)` (only
   key files named after the signature's issuer are tried to name an
   unauthorized signer, at most 4: bounded cost). A
   signature counts for key K when:
   - the issuer key id names K's primary key or a subkey, and the issuer
     fingerprint subpacket matches it if present;
   - it verifies cryptographically. openpgp.js also checks that the signing
     (sub)key was valid at signature creation time, including the subkey
     binding and the primary-key back-signature;
   - the signing (sub)key is **also valid now**: not revoked, not expired.
     Creation times are chosen by the signer, so "valid at signing time"
     alone would let the holder of an expired or retired key back-date
     signatures. Remedy for an expired admin key: extend it and re-upload
     `.public-keys/<FPR>`;
   - the creation time is at most 5 minutes in the future.

   If the signature verifies against some other store key → `unknown-signer`
   (with that fingerprint). Otherwise → `signature-invalid`.
6. Folder notation missing or ≠ `/<folder>`, or malformed `child@g00pass`
   declarations → `signature-invalid`.
7. Committed sets only: signature older than the newest one this device
   accepted for this folder → `replayed`.
8. Every recipient is a full primary fingerprint (§Recipient ids) → else
   `weak-recipient`.
8a. Boundaries (§Child boundaries): declared chain up to the root, then for
    committed sets the vanished-boundary check for the write target, for
    proposed sets the exact expected children → `boundary-undeclared` /
    `boundary-vanished` (or the parent's code, e.g. `signature-invalid`).
9. Every root escrow fingerprint is a recipient → else `escrow-missing`. This
   now applies to committed sets too (recovery.md). It is checked LAST, so
   `escrow-missing` implies every other check passed; approvals rely on this
   to repair escrow (access-requests.md §Approving).
10. `ok`. A warning `admins-file-unverified:<G>` is added for every invalid
    admins file on the path, and `boundary-vanished:<child>` for vanished
    declared children. Only now are the replay high-water marks raised and
    the boundary recorded in the device-local set.

### Proposed recipient lists (approve / remove / re-encrypt)

`verifyProposedRecipients(snapshot, folder, lines, { signature })` runs
the same hook with `proposed: true`:

- Authorization is computed from the **current** snapshot: who is an anchor
  or verified admin *now*. Files that the same commit would add (a new admins
  file in `extraChanges`, new `.public-keys`) can never authorize their own
  signer (tested).
- The signature must be produced over the exact final text, after the
  escrow merge, declaring the expected child boundaries. With
  `reencryptFolder`, pass
  `gpgIdSignature: (text, { children }) => signGpgId(text, folder, operatorKey, { children })`.
  The core calls it with the exact bytes it will commit, and the result goes
  into the same commit.
- The approver must therefore be an anchor (any folder) or a verified admin of
  the folder or an ancestor (non-root). Root proposals need an anchor.
- No replay check, since the signature is fresh. The high-water mark is
  raised when the committed result is next verified.

## Replay: what is and isn't prevented

| Attack | Result |
| --- | --- |
| Copy `.gpg-id` + `.sig` from folder A to folder B | **Prevented** (folder notation) |
| Restore an older `.gpg-id` + `.sig` of the same folder (e.g. re-add a removed member) on a device that has verified a newer version | **Prevented** (`replayed`; per-device high-water mark of signature creation time in `g00pass.gpgid-seen.v1`) |
| Same, on a device that never saw the newer version (new device, cleared storage) | **NOT prevented.** The old signature is genuine. Mitigation: branch protection / CODEOWNERS on `.gpg-id*`, and review of the commit history. |
| Replay an older root after an anchor rollover | Prevented on devices that saw the newer root; otherwise the old root must still be signed by a *currently pinned* anchor |
| Strip revocation or expiry self-signatures from a signer's key file (attacker holds the compromised private key) | **NOT prevented.** Key state comes from the store. Remove compromised keys from the anchors (rollover) or the admins file instead of relying on revocation alone. |
| Old admins file version | Prevented on devices with a cached newer serial, and on fresh devices when reachable history shows a newer serial (folder-admins.md) |
| Delete a nested `.gpg-id` (+ `.sig`) to move its entries under the parent | **Prevented** on every device when the parent's signature declares the child (`boundary-vanished`), and on devices that verified the child before even if not declared. Re-encrypting the parent refuses entries not encrypted to all current parent members (PKESK check) |
| Create a nested `.gpg-id` to keep entries out of the parent's re-encrypt | **Prevented**: undeclared boundaries are not writable, and a parent re-sign refuses (or, if validly signed, adopts) them |
| Replay an older parent `.gpg-id` + `.sig` that did not declare the child, and delete the child | Existing devices: `replayed` / known-boundary set. **Fresh device: NEW writes into the child's folder are encrypted to the old parent set.** Existing child entries are still protected on the parent's re-encrypt by the PKESK check. Same residual class as the same-folder replay above |
| Delete the child and re-sign the parent without the declaration | Needs an authorized signer of the parent (`unknown-signer` otherwise); g00pass itself never drops a declaration |

## Client behaviour

| Situation | Reads/decrypt | Encrypt/write in F | UI |
| --- | --- | --- | --- |
| valid signature | allowed | allowed | ✓ verified (per folder, Recipient trust card) |
| missing `.sig` | allowed | **refused** (`signature-missing`) | ⚠ "Recipients of F are not signed by an admin. Writing is disabled." |
| invalid / unknown signer / wrong folder | allowed | **refused** | ⚠ "changed by an unauthorized key or the signature is invalid" + reason (signer FPR if known) |
| root not trusted | allowed | **refused everywhere** | red banner + added/removed fingerprints |
| no anchors pinned | allowed | **refused** | pin prompt (full fingerprints, explicit out-of-band confirmation) |

- Decryption never depends on `.gpg-id` and is always allowed.
- The client MUST NOT offer an "encrypt anyway" button.
- The only remedy is for an authorized signer to re-sign. The approve and
  remove flows do this automatically.

## Producing signatures

- **Approve or remove (`reencryptFolder`):** `gpgIdSignature: (text) => signGpgId(text, folder, operatorKey)`.
- **Bootstrap or migration:** sign with gpg or pass as above, adding one
  `--sig-notation child@g00pass=/<child>` per direct child boundary. An
  in-app "Sign all recipient lists" action for global admins is still a
  later feature.

### Migrating an existing store (breaking change)

Signatures made before child boundaries existed declare no children, so
every nested boundary becomes `boundary-undeclared` (not writable) until its
parent is re-signed with the declarations. Work top-down:

```sh
# root (a pinned global admin), declaring every top-level boundary:
gpg -u <ANCHOR FPR> --sig-notation folder@g00pass=/ \
    --sig-notation child@g00pass=/infra --sig-notation child@g00pass=/clients \
    --detach-sign -o .gpg-id.sig .gpg-id
# each folder with nested boundaries (an admin of that folder or an ancestor):
gpg -u <ADMIN FPR> --sig-notation folder@g00pass=/infra --sig-notation child@g00pass=/infra/prod \
    --detach-sign -o infra/.gpg-id.sig infra/.gpg-id
# or with pass:
PASSWORD_STORE_SIGNING_KEY=<FPR> \
PASSWORD_STORE_GPG_OPTS="--sig-notation folder@g00pass=/infra --sig-notation child@g00pass=/infra/prod" \
pass init -p infra <FPR…>
```

`gpg --list-packets infra/.gpg-id.sig` shows the notations. Once the root
declares a folder, any g00pass approval in that folder re-signs it with its
validly signed children declared automatically.

## Test cases (all in `test/trust-policy.test.ts`)

1. Valid signature by an anchor.
2. Valid signature by a folder admin, both direct and inherited from an
   ancestor's admins file.
3. Signature by a non-admin recipient → `unknown-signer`.
4. `.gpg-id` modified after signing → `signature-invalid`.
5. Missing `.sig`.
6. `.gpg-id` + `.sig` copied from another folder → `signature-invalid` (folder
   binding).
7. Revoked or expired signer key.
8. A signing subkey that matches by primary fingerprint.
9. `gpg --detach-sign` fixture (`test/fixtures/gpg/`), both folder-bound
   (accepted) and plain pass style (rejected for writing).
10. Root `.gpg-id` signed by a non-anchor.
11. Anchor rollover, an anchor signing themselves out, and a replayed old
    root.

Also covered: the attacker's own signature, an escrow-line swap, escrow as
signer, weak ids, swapped recipient or signer key files, escrow removed,
future-dated, text-mode, multi-packet and garbage signatures, unhashed notation
injection, same-folder replay, and proposed changes by a non-admin, without a
signature, for the wrong folder, or self-authorized via `extraChanges`.

Child boundaries (`test/boundaries.test.ts`, `test/security-probes.test.ts` "H2"):
deleted child on a fresh device (writes and parent approval refused, engine
refuses directly), device-known boundary with a parent that never declared it
or a newer parent signature that "forgot" it, worst case on a fresh device
(PKESK check), forging the parent declaration away, re-sign carries the
declarations, undeclared child not writable / adopted when validly signed /
blocking when not, wrong declared children, malformed and nested
declarations, declare-then-create of a new boundary, companion inside a
vanished boundary, deleted intermediate boundary, replayed parent on an
existing device. Bounded signer identification: `test/hardening.test.ts` (L7).
