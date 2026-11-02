# gopass-web: Team Access Design

Context handoff for a coding agent. Extends the existing gopass-web PWA (browser-side OpenPGP decrypt, per-device keys, reads encrypted entries from GitHub, static hosting, strict CSP) with automated team enrollment and per-folder access control. Everything stays in one git repo; no server holds secrets.

## Goals
- One GitHub repo holds all org secrets; different people can decrypt only specific folders.
- Automate enrollment: user generates a key in the browser, requests access, a folder admin approves in the browser. No manual `gpg --import` / `gopass recipients add`.
- Easy removal of access, with a clear list of secrets that must be rotated.
- Personally operated (owner controls the repo and the web client), not company-owned infrastructure. No backend that holds keys or secrets.

## Non-goals
- No custom crypto primitives. Use openpgp.js for all operations.
- No server-side decryption, no always-online key.
- No forking gopass itself (name obfuscation is handled in the client, see below).

## Core model: cryptographic access, not repo access
Branches or GitHub permissions are NOT an access boundary: anyone with repo read can read all branches. Access control is per-folder recipients.

```
.gpg-id             -> global admins
infra/.gpg-id       -> alice, bob
clients/x/.gpg-id   -> carol, dave
```

- Anyone with repo read can clone everything, but only decrypts folders encrypted to their key.
- Client resolves the NEAREST `.gpg-id` walking up from an entry's path, and encrypts to that folder's recipients. (Verify gopass honors nested `.gpg-id` in the targeted version; `pass` does.)
- Prefer a PRIVATE repo with a read-only fine-grained token, since ciphertext and paths are otherwise public forever.

## Enrollment flow
1. New user opens the app (optionally via a one-time invite link carrying a token that names the requested store/folder and role).
2. Browser generates an OpenPGP key. Passphrase set by the user, never leaves the browser. Private key stays in browser storage, passphrase-encrypted. Users generate their own keys; admins never see private keys.
3. Browser submits an access request containing the PUBLIC key + requested folder. Transport is GitHub itself (a PR or issue against the repo, or a requests branch) so no backend is needed. No separate signup/login system: the key is the identity.
4. A recipient of that folder who is marked folder admin sees the request in the app and taps Approve.
5. The admin's BROWSER does the work: decrypts each entry in the folder, re-encrypts to the new recipient list (openpgp.js), updates that folder's `.gpg-id`, and commits through the GitHub API.

Important consequence: only a recipient of a folder can add people to it (needs decrypt). Folder ownership is therefore delegated naturally; a global admin who is not a recipient cannot approve. Mark certain recipients as folder admins (store the flag in a signed metadata file).

## Revocation
"Remove member" is a single action:
1. Remove key from the folder's `.gpg-id`, re-encrypt all entries in that folder.
2. Show a rotation checklist: every secret that person could read, with last-rotated info if tracked. Removal alone is not revocation, since they may hold old git history and decrypted values.

## Integrity of `.gpg-id`
Anyone with write access could replace a `.gpg-id` to add their own key for future secrets.
- GitHub branch protection / required reviews / CODEOWNERS on `.gpg-id` files.
- Signed commits; client verifies a signature on `.gpg-id` by a known admin key before encrypting to its recipients (as `pass` can do).

## Name / metadata privacy
Paths are visible to anyone with repo read. Options, in order of preference:
1. Private repo (mostly sufficient).
2. Optional: hashed filenames plus a per-folder encrypted index mapping names to hashes, handled in the client. This breaks plain gopass CLI compatibility for those stores, so make it opt-in per folder.

## Security of the web app itself (highest risk)
A tampered build can steal passphrases.
- Keep strict CSP; pin dependencies and review lockfile changes; SRI for any external asset.
- Signed or reproducible builds; show the version/commit in the UI.
- Auto-lock, clipboard auto-clear (already present).

## Suggested build order
1. Nested `.gpg-id` resolution in the client (read + write paths).
2. Access request submission via GitHub (PR/issue) from the new-user flow.
3. Admin approval UI with in-browser re-encrypt and commit via GitHub API.
4. Remove member + rotation checklist.
5. `.gpg-id` signature verification.
6. Invite links with scoped tokens.
7. Optional hashed names + encrypted index.

## Open questions
- How are folder admins recorded and trusted (signed metadata file vs. first recipient)?
- Re-encryption performance for large folders in the browser; may need chunking and progress UI.
- Exact request transport on GitHub (issues vs. PRs vs. branch) and the token scopes each role needs.
- Add recovery path (admin escrow key or documented recovery kit) so a lost device key is not a lost folder.
