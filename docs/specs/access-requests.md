# Access requests, invites, and token scopes

The transport is **GitHub issues**, so no backend is needed. The requester's
identity is their new OpenPGP key. Issue metadata (author, labels, state) is
**never trusted**: only the signed block in the body counts, and the approver
always confirms the fingerprint out of band.

## Where requests live

**Requests go to a separate private "requests repo" by default.** The store
repo is only a fallback.

Resolution order in the client:

1. `requestsRepo` from an invite (§Invites), if the user arrived through one.
2. The app's repo config field `requestsRepo` (`"owner/name"`, set in the
   Repository settings; stored with the other non-secret repo settings).
3. A signed `.g00pass/config.json` in the store (below), once trust
   verification can read it.
4. Fallback: the **store repo**. The UI MUST show a warning that a separate
   private requests repo is recommended.

The signed config shape:

```json
{
  "requestsRepo": "acme/secrets-requests",
  "type": "g00pass.config",
  "version": 1
}
```

The file is canonical JSON with a detached `.sig` from a trust anchor. A
missing, unsigned, or invalid config means no value from this source.

**Why a separate repo is recommended:** an invite token has
`Issues: Read and write`. With it, the holder can read, edit, and close *every*
issue in that repo. That exposes other requests (folder names and public keys)
and any unrelated issues.

**Labels:**

| Label | Meaning |
| --- | --- |
| `g00pass:access-request` | Open request |
| `g00pass:approved` | Approved |
| `g00pass:rejected` | Rejected |

Labels are a convenience for filtering only. Discovery MUST also work without
labels: list open issues and match the body marker.

## Issue format

- **Title:** `[g00pass] Access request: <folder> (<role>) <FPR last 16>`
  (informational only).
- **Body:** markdown, at most 32 KiB, in the format below:

````markdown
<!-- g00pass:access-request v1 -->
**g00pass access request.** Open g00pass to review. Do not approve without
confirming the fingerprint with the requester out of band.

- Folder: `infra`
- Role: reader
- Fingerprint: `AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333`

```g00pass-request
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

{
  "createdAt": "2026-11-02T10:15:00Z",
  "fingerprint": "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333",
  "folder": "infra",
  "inviteId": "q3V1x0bN0m5Qm6cU2f5r9A",
  "name": "Carol Example",
  "nonce": "Zk9a1c1m3bS0dXl2b0x0eA",
  "note": null,
  "publicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEZ…\n-----END PGP PUBLIC KEY BLOCK-----\n",
  "repo": "acme/secrets",
  "role": "reader",
  "storeRoot": "",
  "type": "g00pass.access-request",
  "version": 1
}
-----BEGIN PGP SIGNATURE-----

wnUEARYKACcFgm…
-----END PGP SIGNATURE-----
```
````

- The body is an OpenPGP **cleartext-signed message** (RFC 4880 §7). The
  signed text is the canonical JSON (store-layout.md), *signed with the
  requester's new key*.
- This proves possession of the private key. It does **not** prove who the
  requester is.
- Build it with openpgp.js:

  ```ts
  sign({ message: await createCleartextMessage({ text: canonicalJson }), signingKeys: newKey })
  ```

- Dash-escaping: no canonical-JSON line starts with `-`, because the armored
  key is a JSON string containing `\n` escapes.

### Payload fields

| Field | Type | Rule |
| --- | --- | --- |
| `type` / `version` | `"g00pass.access-request"` / `1` | exact |
| `repo` | `"owner/name"` | the **store** repo (not the requests repo) |
| `storeRoot` | string | normalized, `""` = repo root |
| `folder` | string | normalized folder that has its own `.gpg-id` |
| `role` | `"reader"` \| `"folder-admin"` | `folder-admin` also adds the key to `.g00pass-admins.json` |
| `fingerprint` | FPR (40 hex, v4) | MUST equal the key in `publicKey` and the signer |
| `publicKey` | armored public key | exactly one key, no secret material |
| `name` | string ≤ 100 chars | display only; never trusted |
| `note` | string ≤ 500 chars \| null | display only |
| `inviteId` | base64url(16 bytes) \| null | see §Invites |
| `createdAt` | RFC 3339 UTC | |
| `nonce` | base64url(16 random bytes) | uniqueness |

### Requester client: submitting

1. Generate the key:
   - v4, `type: 'ecc', curve: 'curve25519Legacy'`;
   - the user id is the name and e-mail the user enters;
   - the passphrase is chosen by the user (at least 12 characters, confirmed
     twice), never leaves the browser, and the key is stored protected with
     the default **iterated-and-salted S2K**, never Argon2 (core-api.md
     §Crypto). An existing armored private key can be imported instead (v4,
     Ed25519 or RSA ≥ 3072, protected);
   - the UI shows the fingerprint prominently, in groups of 4, with the hint
     to share it out of band with the admin.
2. Also generate the revocation certificate, and offer the recovery kit
   (recovery.md) **before** submitting.
3. Build the canonical JSON and the cleartext signature, then build the body.
4. Check for duplicates: list open issues in `requestsRepo` and skip creation if
   one already contains a request with the same `fingerprint` and `folder`.
5. Submit with
   `POST /repos/{requestsRepo}/issues {title, body, labels:["g00pass:access-request"]}`
   (`GitHubClient.createIssue`). The token is the invite token or one the user
   pastes; it is held in memory only (`TokenStore('memory')`), never persisted
   and never in an error message. A 401/403/404 is reported as "this token
   cannot create issues in the requests repo". Labels may be dropped silently,
   which is fine.
6. Remember `{issueNumber, requestsRepo}` locally; this is not secret. Poll
   `GET /repos/{requestsRepo}/issues/{n}` at most once a minute while the tab
   is open.
7. When the issue closes with the label `g00pass:approved`, the UI tells the
   user to get a **reader token** (§Token scopes). Tokens are never posted in
   issues.

### Approver client: verifying (MUST, in this order; any failure means "invalid request", shown with the reason and no Approve button)

1. The body contains exactly one fenced ```` ```g00pass-request ```` block, and
   the issue body is at most 32 KiB.
2. `readCleartextMessage` succeeds. The signed text parses as JSON, is
   canonical, and has a known `type`/`version`.
3. `repo` and `storeRoot` equal the approver's configured store. The `repo`
   comparison is case-insensitive.
4. `publicKey` passes these checks:
   - It contains exactly one key; `parsePublicKey` rejects any private
     material.
   - It is a v4 key.
   - Its fingerprint equals `fingerprint`.
   - Its algorithm is Ed25519/Cv25519, or RSA with at least 3072 bits.
   - It has a valid encryption subkey.
   - It has no expiry, or one more than 30 days away.
5. The cleartext signature verifies with that key. The signature's creation
   time is within ±10 minutes of `createdAt`. `createdAt` is no more than 5
   minutes in the future and no more than 30 days in the past.
6. `folder` exists with its own `.gpg-id`, and `fingerprint` is not already
   one of its recipients.
7. Invite check:
   - If `inviteId` is set, a **valid** invite record (§Invite registry) exists.
     It must be unexpired, its `folder` must equal the requested folder, and
     the requested role must be ≤ the invite's role (`reader` < `folder-admin`).
   - If `inviteId` is null, the request shows an **Uninvited** badge, and
     approving needs an extra confirmation.
8. The operator must be a folder admin of `folder` (folder-admins.md) or a
   trust anchor, **and** a recipient of it. Otherwise Approve is hidden.
9. The UI shows the fingerprint in groups of 4 and requires the approver to
   tick "I confirmed this fingerprint with <name> through another channel".
   This step is the only identity check. Anyone holding an invite link, or
   anyone who can edit issues, can submit a validly self-signed request.

### Approving

All of the following happens in one `withConflictRetry` attempt (fresh snapshot
each time):

```ts
reencryptFolder(folder, [...currentNonEscrowLines, fingerprint], {
  snapshot, writer, decryptionKeys: [operatorKey],
  pendingKeys: new Map([[fingerprint, publicKey]]),        // -> .public-keys/<FPR>
  gpgIdSignature: (text) => signDetached(text, operatorKey),
  replaceEntries: [rotationFileWithMemberAdded],         // rotation.md
  extraChanges: [
    ...(role === 'folder-admin' ? adminsFileUpdate : []),  // folder-admins.md, signed
    ...(inviteId ? [{ path: `.g00pass/invites/${inviteId}.json`, delete: true },
                    { path: `.g00pass/invites/${inviteId}.json.sig`, delete: true }] : []),
  ],
  message: `g00pass: grant ${fingerprint.slice(-16)} ${role} on ${folder} (${requestsRepo}#${n})`,
});
```

After the commit succeeds, update the issue. These steps are best-effort, and
the commit remains the source of truth:

1. Comment: "Approved in `<commitSha>` by `<operator FPR>`."
2. Add the label `g00pass:approved`.
3. Close with `state_reason: "completed"`.

The UI then reminds the admin to **revoke the invite token** on GitHub.

**Rejecting:**

1. Comment with the reason.
2. Add the label `g00pass:rejected`.
3. Close with `state_reason: "not_planned"`.
4. Optionally delete the invite record. No commit to the store is needed
   otherwise.

## Invites

An invite is a link the admin sends to the new user through a channel they
trust (chat, e-mail, in person). It carries a **requester token** and the
**trust anchors**.

```
https://<app-origin>/<app-path>/#g00pass-invite=<base64url(utf8(canonical JSON))>
```

```json
{
  "anchors": ["3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B"],
  "branch": "main",
  "expiresAt": "2026-11-09T10:15:00Z",
  "folder": "infra",
  "id": "q3V1x0bN0m5Qm6cU2f5r9A",
  "issuedBy": "3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B",
  "repo": "acme/secrets",
  "requestsRepo": "acme/secrets",
  "role": "reader",
  "storeRoot": "",
  "token": "github_pat_11ABC…",
  "type": "g00pass.invite",
  "version": 1
}
```

**Why the URL fragment:** browsers never send the fragment to the server, so
the static host, CDN logs, and proxies never see the token. Our CSP and
`Referrer-Policy: no-referrer` also keep it out of Referer headers.

The invite payload is **unsigned on purpose**. The newcomer has no trusted key
yet, so the delivery channel is the trust root. The newcomer confirms
`anchors`, and the approver confirms the requester's fingerprint.

### Client handling (MUST)

1. On load, if `location.hash` starts with `#g00pass-invite=`:
   - decode it;
   - **immediately** call
     `history.replaceState(null, '', location.pathname + location.search)`,
     which removes it from the address bar and history;
   - discard the raw string.
2. Validate the payload:
   - `type` and `version` are known;
   - `repo` and `requestsRepo` match `owner/name` syntax;
   - `role` is in the enum;
   - `expiresAt` is in the future;
   - `token` starts with `github_pat_`. Classic `ghp_` tokens cannot be scoped
     to one repo and are refused.
3. Keep the token in memory only (`new TokenStore('memory')`). Never write it to
   sessionStorage, localStorage, or IndexedDB, and never write it into an
   issue. Drop it once the request is approved or rejected, or when the tab
   closes.
4. Show the invite summary and the `anchors` fingerprints. Ask the user to
   confirm the anchors (ideally against what the admin told them). On
   confirmation, pin them (store-layout.md §Trust anchors).
5. Continue with key generation and submission.

### Admin client: issuing an invite

1. Create the fine-grained PAT manually on GitHub. The API cannot create PATs.
   The UI gives step-by-step instructions:
   - Settings → Developer settings → Fine-grained tokens.
   - Resource owner: the owner of `requestsRepo`.
   - Repository access: *Only select repositories* → `requestsRepo`.
   - Permissions: *Issues: Read and write*. *Metadata: Read-only* is mandatory.
     Nothing else.
   - Expiration: custom, at most 7 days.
2. Paste the token into the app. The app tests it, best-effort:
   - `GET /repos/{requestsRepo}` must return 200.
   - `GET /repos/{storeRepo}/git/ref/heads/{branch}` **must fail with 403 or
     404**. If the token can read store contents, refuse with "token is
     over-scoped".
3. Commit the **invite record** with the signed metadata (below).
4. Show the link once, with a copy button, and say that it contains a
   credential.

### Invite registry

`.g00pass/invites/<id>.json` + `.sig`, canonical JSON. The registry **never**
contains the token.

```json
{
  "createdAt": "2026-11-02T10:15:00Z",
  "expiresAt": "2026-11-09T10:15:00Z",
  "folder": "infra",
  "id": "q3V1x0bN0m5Qm6cU2f5r9A",
  "issuedBy": "3F2A9C0D1B7E4F6A8C5D2E1F0A9B8C7D6E5F4A3B",
  "note": null,
  "role": "reader",
  "type": "g00pass.invite-record",
  "version": 1
}
```

- A record is valid if it is signed by `issuedBy`, and `issuedBy` is a trust
  anchor or a folder admin of `folder`.
- The record is single-use: approval deletes it in the same commit.
- Any admin may delete expired records.

## Token scopes per role

Use fine-grained PATs, always restricted to *Only select repositories*.
*Metadata: Read-only* is mandatory for all roles and omitted below.

| Role | Repo(s) | Permissions | Created by | Max lifetime | Client storage |
| --- | --- | --- | --- | --- | --- |
| **Requester** (invite) | `requestsRepo` only | Issues: **Read and write** | issuing admin | 7 days; revoke after approval | URL fragment, then memory |
| **Reader** | store repo | Contents: **Read-only** | the user (if a collaborator), or an admin on their behalf, handed over out of band | 90 days | memory or sessionStorage (opt-in) |
| **Folder admin** | store repo + `requestsRepo` | Contents: **Read and write**; Issues: **Read and write** | the admin | 90 days | memory or sessionStorage |
| **Global admin** | same as folder admin | same | the admin | 90 days | memory or sessionStorage |

Notes:
- Organization-owned repos may require org approval for fine-grained PATs.
- **Branch protection:** admins commit directly to `branch` through the Git
  Data API. If the branch requires PRs, the ref update fails. The commit layer
  reports this as a `GitHubApiError` (not as `ConflictError`). Either add the
  admins to the ruleset bypass list, or keep `.gpg-id` integrity enforced
  client-side (gpg-id-signatures.md) plus CODEOWNERS on a review branch. That
  second option is out of scope for Phase 0.
- No role ever needs `Administration`, `Workflows`, `Secrets`, or
  `Pull requests`. The UI should warn if a pasted token appears over-scoped,
  using the 403/404 probes above.

## Security notes for implementers

- Render issue bodies, names, and notes **as text only**, never as HTML or
  markdown.
- An attacker with issues write access can edit another person's request and
  swap in their own key. The swapped key produces a different fingerprint, and
  the out-of-band fingerprint confirmation catches that.
- Rate limits: poll at most once a minute, and stop polling on 401 or 403.
