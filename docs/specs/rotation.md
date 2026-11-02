# Rotation tracking and the "remove member" checklist

Removing a key from `.gpg-id` and re-encrypting does **not** revoke access. The
removed person may still have git history and any values they decrypted. Every
secret they could read must be rotated, which means changing the actual
credential at its source. g00pass tracks enough data to list those secrets and
to show which ones have already been rotated.

## Storage

The metadata lives in one file per governing folder (a folder with its own
`.gpg-id`):

```
<F>/.g00pass-rotation.gpg
```

- It is an OpenPGP message (like any entry) whose plaintext is canonical JSON.
- It is **encrypted to F's recipients**. Rotation dates and member history are
  no more visible than the secrets themselves, while entry paths are already
  visible to repo readers.
- It is a hidden entry (`isHiddenEntry`). `listGovernedEntries` includes it, so
  `reencryptFolder` keeps it encrypted to the current set automatically.
- Writers update it in the **same commit** as the change it records:
  - entry edits use `writeEntry({ companions: [{ path: '<F>/.g00pass-rotation.gpg', plaintext }] })`;
  - approve and remove use `reencryptFolder({ replaceEntries: [...] })`.
- If the file is missing, treat it as `{entries:{}, members:[]}`. Stores
  created by the CLI start that way.
- If it exists but can't be decrypted, `reencryptFolder` refuses; this is the
  same rule as for any other entry.

```json
{
  "entries": {
    "db/primary": {
      "createdAt": "2026-03-01T09:00:00Z",
      "rotatedAt": "2026-10-20T14:02:11Z",
      "rotatedBy": "3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B"
    },
    "web/admin": {
      "createdAt": null,
      "rotatedAt": null,
      "rotatedBy": null
    }
  },
  "folder": "infra",
  "members": [
    {
      "addedAt": "2026-01-10T08:00:00Z",
      "addedBy": "3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B",
      "fingerprint": "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333",
      "name": "Carol Example",
      "removedAt": "2026-11-02T10:15:00Z",
      "removedBy": "3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B",
      "request": "acme/secrets#12"
    }
  ],
  "type": "g00pass.rotation",
  "version": 1
}
```

| Field | Meaning |
| --- | --- |
| `folder` | Governing folder. MUST match the file's location. |
| `entries` | Key: entry name **relative to `folder`**, without `.gpg`. Only entries governed by `folder` appear here; nested `.gpg-id` folders have their own file. |
| `entries[].createdAt` | When g00pass first wrote the entry. `null` = unknown (created by the CLI or before tracking). |
| `entries[].rotatedAt` / `rotatedBy` | Last time the **secret value** changed (see below). `null` = never or unknown. |
| `members` | Append-only history of recipients added or removed through g00pass. A member who is added again gets a new element. |
| `members[].request` | `requestsRepo#issue` for approvals, or `null`. |

Escrow fingerprints never appear in `members`.

### What counts as "rotated"

When an entry is written with a **different first line** (the password, by
pass convention), the writer sets `rotatedAt` to now and `rotatedBy` to the
operator. The writer compares the old and new plaintext in memory before
encrypting. Edits that leave the first line unchanged do not count. The UI also
offers "Mark as rotated", for secrets rotated at the source when the stored
value stays the same.

Other cases:

- **New entries** set `createdAt = rotatedAt = now`.
- **Deleted entries** have their key removed from `entries`. The deletion
  commit should be listed in the checklist history (see below).
- **Moved or renamed entries** keep their metadata under the new key, and the
  move is recorded in the same commit. A move into a different governing folder
  carries the metadata over **and** counts as exposure to the new folder's
  recipients.

## "Remove member" flow (feature agent 4)

Input: folder F and the fingerprint X being removed. X must not be an escrow
fingerprint, and the operator must be an admin-recipient of F.

1. Use a fresh snapshot. Decrypt `F/.g00pass-rotation.gpg`, or start from the
   empty default.
2. Set `removedAt` and `removedBy` on X's open `members` record. If X has no
   record (a CLI-era member), append one with `addedAt: null`.
3. Commit:

   ```ts
   reencryptFolder(F, currentLinesWithout(X), {
     replaceEntries: [rotationFile],
     extraChanges: [adminsFileWithout(X)?],
     gpgIdSignature: signer,
   })
   ```

   Run it inside `withConflictRetry`.
4. Show the **checklist** (below). It is computed, never stored.

### Checklist computation

For a removed member M (with `removedAt = R`) and the current snapshot:

```
exposed(e) = e is governed by F
             and (e.createdAt is null or e.createdAt < R)
open(e)    = exposed(e) and (e.rotatedAt is null or e.rotatedAt <= R)
```

The checklist is shown on the folder until every exposed entry is rotated, for
every removed member that has open items. The list for M contains:

- every `open(e)`, sorted by path, showing `rotatedAt` ("never" or "unknown")
  and a "Mark rotated" action;
- entries already rotated after R, shown as done;
- a note that **nested folders** with their own `.gpg-id` are not covered. If M
  was also a recipient there, it must be removed there separately; the UI
  checks for this and offers it;
- **deleted entries**, best-effort. These are `.gpg` paths under F that
  appear in git history between `addedAt` and R but no longer exist. They come
  from `GET /repos/{o}/{r}/commits?path=<F>` (paginated, capped at 300 commits)
  and are listed as "deleted, but X may have a copy".

Limits shown to the user:

- If `addedAt` is null, assume M could read everything that existed before R.
- If M was a recipient of an ancestor folder before F got its own `.gpg-id`,
  that ancestor's entries are not listed.
- Git history means M keeps the old ciphertext forever. Re-encryption protects
  only future values.

## Tests the implementation MUST cover

1. Exposure logic with null, before-R, and after-R timestamps.
2. A member re-added after removal.
3. A rename that keeps the metadata.
4. The rotation file is re-encrypted by `reencryptFolder`. Phase 0 core already
   covers that it is re-encrypted like any governed entry.
5. A missing file is treated as empty.
6. A changed first line sets `rotatedAt`; other edits do not.
