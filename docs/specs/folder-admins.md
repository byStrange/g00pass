# Folder admins

A **folder admin** of F may approve access requests for F, remove members from
F, and sign `F/.gpg-id`. Approving requires decrypting every entry in F, so in
practice a folder admin must also be a **recipient** of F. An admin who is not a
recipient can sign metadata, but `reencryptFolder` fails for them with
`ReencryptError`. The UI MUST hide Approve for such users and explain why.

Global admins (store-layout.md) have admin authority on every folder. To
approve in a folder, they too must be one of its recipients.

## Files

```
<F>/.g00pass-admins.json       canonical JSON (store-layout.md)
<F>/.g00pass-admins.json.sig   detached signature over the exact bytes
```

F MUST be a folder that has its own `.gpg-id`. There is no admins file at the
root, because root authority comes from the trust anchors.

```json
{
  "admins": [
    "3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B",
    "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
  ],
  "folder": "infra",
  "previous": "sha256:9b1f…64 hex…",
  "serial": 3,
  "type": "g00pass.folder-admins",
  "updatedAt": "2026-11-02T10:15:00Z",
  "updatedBy": "3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B",
  "version": 1
}
```

| Field | Rule |
| --- | --- |
| `type`, `version` | Exactly `"g00pass.folder-admins"` and `1`. |
| `folder` | MUST equal the folder the file sits in. A file copied from another folder is invalid. |
| `admins` | Sorted, unique, upper-case FPRs, at least 1. Each SHOULD be a recipient of `F/.gpg-id`; if not, show a UI warning. |
| `serial` | 1 for the first version, and previous + 1 for each update. |
| `previous` | `null` when `serial == 1`. Otherwise `"sha256:" + hex(sha256(previous file bytes))`. |
| `updatedBy` | FPR of the signer. MUST match the signature issuer. |
| `updatedAt` | RFC 3339 UTC. |

## Validity

Implemented in `src/core/admins.ts` (`verifyAdminsFile`, `checkFolderAdmin`,
`isVerifiedFolderAdmin`, producer `signAdminsFile`).

Let `V(n)` be version *n* (its bytes, signature, and parsed JSON). `V(n)` is
**valid** if all of the following hold:

1. The root is trusted (gpg-id-signatures.md §Root). Without a trusted
   root, no admins file is valid.
2. `F/.gpg-id` exists. An admins file in a folder without its own `.gpg-id`
   is invalid.
3. The bytes are canonical JSON with exactly the fields above, the type and
   version are known, `folder` equals F, `admins` is sorted, unique, full upper-case
   fingerprints and non-empty, and `previous` is null iff `serial == 1`.
4. The signature verifies over the exact bytes against
   `.public-keys/<updatedBy>`, with the same rules as `.gpg-id`
   signatures: signer valid at signing time *and now*, at most 5 min in the
   future. `updatedBy` is therefore the signer's primary fingerprint. Escrow
   keys may not sign. (No folder notation is needed: `folder` is inside the
   signed bytes.)
5. **Rollback**: if this device's cache holds a higher serial for F, or the
   same serial with a different digest, the file is invalid ("rolled back" /
   "conflicting version").
6. The signer is authorized:
   - **self-authorizing** signers: a trust anchor, or a verified admin of a
     *strict ancestor* folder (hierarchical authority, at any serial). For
     example, admins of `infra` may create or rewrite
     `infra/prod/.g00pass-admins.json`;
   - otherwise (`serial > 1`): the signer is listed in `V(n-1).admins`,
     where `V(n-1)` satisfies 3–4, has `serial == n-1`, a bytes digest equal
     to `previous`, **is the actual predecessor of V(n) in the git history**
     reachable from the snapshot, and is itself valid by this rule
     (recursively, until a self-authorizing or cached version is reached);
   - `serial == 1` signed by anyone else is invalid.
7. **Removal is final (fork / rollback detection).** With history available:
   - the newest version in history must be the snapshot's file;
   - no genuine (signature-valid) version in the history window may have the
     current serial with other bytes (fork) or a higher serial (rollback);
     this applies to self-authorized versions too;
   - in the chain walk, any version at or below the cached serial must be
     exactly the cached version.
   Because each link must be the real history predecessor, the walked
   segment is linear, so it cannot contain two versions with one serial.
   Versions older than the trusted cut point (the self-authorized or cached
   version where the walk stops) are not examined.

Admin authority is **hierarchical**:
`admins(F) = ⋃ admins of valid files at F, parent(F), …` (not the root).
Global admins (anchors) administer every folder. An invalid file grants
nothing and does not hide ancestors' admins. The worst an attacker can do by
tampering is make it invalid.

Historic versions are authorized against the *current* anchors and
ancestors. If a chain bottoms out at a version signed by a since-removed
global admin, it becomes unverifiable until a current admin re-signs.

## Chain of custody (finding `V(n-1)`)

1. **Local cache.** `localStorage['g00pass.admins-cache.v1']` holds
   `{ "<owner>/<repo>|<storeRoot>|<F>": { "digest": "sha256:…", "serial": n, "admins": [...] } }`
   (owner/repo lower-cased). An entry is written only after full verification,
   and only ever moves to a higher serial; a version that conflicts with it
   never validates, so a fork can never overwrite it. If the cache matches
   `V(n)` itself, verification stops without history; while walking, the walk
   stops successfully at the cached version. The cache is cleared for a store
   when its anchors are re-pinned, reset, or rolled over.
2. **Git history**, bound to the snapshot:
   `GET /repos/{o}/{r}/commits?sha=<snapshot commit>&path=<repoPath>&per_page=21`.
   For each commit, read the file and its `.sig` at that commit with
   `GET /contents/<path>?ref=<sha>`, newest first (consecutive identical
   contents collapsed). The version right after V(n) is its predecessor and
   MUST be the one whose digest equals `previous`, otherwise the chain is
   broken (fork). At most **20 versions** are walked (`MAX_CHAIN_VERSIONS`).
   On a cache miss the whole window (21 commits) is read once for the
   fork/rollback scan, also for self-authorized versions.
3. **Truncation.** If the chain cannot be walked (depth limit, history
   rewritten, or no history available), the file is valid only if its
   signer is self-authorizing. Otherwise it is *invalid/unverifiable*: it
   grants no admin rights and adds a UI warning
   (`admins-file-unverified:<F>`), but it does not block reads.

A device with no cache walks the history once and then caches the result.

### Residual risk

- **History rewrite.** A writer who can force-push (no branch protection) can
  remove the legitimate newer version from history. A fresh device then
  accepts a sibling or an older version signed by the removed admin's
  predecessor list. Devices that cached the newer version still refuse.
  Mitigation: protect the branch against force pushes.
- **Window flooding.** A writer who pushes 20+ commits touching the admins
  file pushes older versions out of the window. Chain versions then become
  unverifiable (fail closed), but a restored, self-authorized (anchor- or
  ancestor-signed) older version is accepted on a fresh device if no newer
  genuine version is left in the window.
- **No history** (non-GitHub snapshot): only self-authorized versions are
  valid, and rollback to one of them is detected only by the local cache.
- **Denial of service.** Anyone with write can make a file invalid (e.g. a
  genuine-looking higher serial signed by any key in `.public-keys`).
  Invalid files grant nothing; a global admin recovers by writing a serial
  higher than any in the window.

## Operations

- **Make someone an admin.** The current admin, an ancestor admin or a global
  admin writes `serial+1` with the new list and signs it, using
  `signAdminsFile({ snapshot, folder, admins, signingKey })`, which returns
  `changes` ready for `extraChanges`.
  - When it happens as part of an approval with `role: "folder-admin"`, the
    file goes into the approval commit through `reencryptFolder({extraChanges})`.
  - Otherwise it is a separate commit made with `commitChanges`.
- **Remove an admin.** Same flow. An admin may remove themselves. The last
  admin cannot be removed unless the signer is a trust anchor, so folders never
  silently become admin-less.
- **Remove a member who is an admin.** The removal commit MUST also update the
  admins file.
- **Concurrency.** Base everything on a single snapshot. Two admins editing at
  once produce a `ConflictError`. The retry recomputes `serial` and `previous`.

## Tests (`test/trust-policy.test.ts`, "folder admins file")

1. A chain of three valid versions.
2. A forged `serial` jump.
3. A `previous` mismatch.
4. A file copied from another folder.
5. A self-signed first version by a non-anchor non-delegate, which is invalid.
6. Delegation from a parent folder (and that it does not flow upwards).
7. Cache hit and cache miss.
8. A history walk limited by depth (21 versions valid, 22 not).
9. A tampered file (attacker adds self, keeps the signature).
10. Rollback to an older, validly signed version on a device that saw the newer one.
11. `signAdminsFile` round trip (serial and previous follow the current file).

Fork / rollback (`test/security-probes.test.ts`, "H1"): a removed admin's
sibling V2' + V3' on a device that cached V2 (refused; the cache stays V2), a
lone V2' on a fresh device, restoring the anchor-signed V1 bytes on a fresh
device, and a sibling committed between legitimate versions.
