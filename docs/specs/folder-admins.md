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

Let `V(n)` be version *n* (its bytes, signature, and parsed JSON). `V(n)` is
**valid** if all of the following hold:

1. The signature over the bytes verifies (store-layout.md §Detached
   signatures), and the issuer equals `updatedBy`.
2. The JSON is canonical, the type and version are known, `folder` matches,
   and the admin list is non-empty.
3. The signer is authorized:
   - `serial == 1`: the signer is a **trust anchor**, or an admin of the nearest
     *valid* admins file of an ancestor folder (delegation). For example,
     admins of `infra` may create `infra/prod/.g00pass-admins.json`.
   - `serial > 1`: the signer is a trust anchor, or is listed in `V(n-1).admins`.
     `V(n-1)` must itself be valid, have a bytes digest equal to `previous`,
     and have `serial == n-1`.

## Chain of custody (finding `V(n-1)`)

1. **Local cache.** `localStorage['g00pass.admins-cache.v1']` holds
   `{ "<repo>|<storeRoot>|<F>": { "digest": "sha256:…", "serial": n, "admins": [...] } }`.
   An entry is written only after full verification. If the cache digest
   equals `previous`, `V(n-1)` is known valid and verification can stop.
2. **Git history.** Call
   `GET /repos/{o}/{r}/commits?sha=<branch>&path=<repoPath>&per_page=30`, and
   for each commit read the file at that commit (tree, then blob). Stop at the
   first version whose digest equals `previous`, then verify it recursively.
   Walk at most **20 versions**.
3. **Truncation.** If the chain cannot be walked (the depth limit is hit, or
   history was rewritten), the file is **valid only if signed by a trust
   anchor**. Otherwise it is *unverifiable*. An unverifiable file grants no
   admin rights and triggers a UI warning, but it does not block reads.

A device with no cache walks the history once and then caches the result.

## Operations

- **Make someone an admin.** The current admin or a global admin writes
  `serial+1` with the new list and signs it.
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

## Tests the implementation MUST cover

1. A chain of three valid versions.
2. A forged `serial` jump.
3. A `previous` mismatch.
4. A file copied from another folder.
5. A self-signed first version by a non-anchor non-delegate, which is invalid.
6. Delegation from a parent folder.
7. Cache hit and cache miss.
8. A history walk limited by depth.
