# g00pass specs (Phase 0)

These specs are **normative** for the feature agents building on the Phase 0
core. Design rationale lives in [`/DESIGN.md`](../../DESIGN.md). Where a spec
says MUST, the core or the feature implementation is expected to enforce it
and to have a test for it.

| Spec | What it fixes |
| --- | --- |
| [core-api.md](core-api.md) | The Phase 0 TypeScript API (`src/core`), invariants, how to extend it |
| [store-layout.md](store-layout.md) | Every file g00pass reads/writes in the store, shared formats (fingerprints, canonical JSON, signatures), trust anchors |
| [gpg-id-signatures.md](gpg-id-signatures.md) | `.gpg-id.sig`, valid signers, verification algorithm, client behaviour on failure |
| [folder-admins.md](folder-admins.md) | `.g00pass-admins.json` + signature, chain of custody |
| [access-requests.md](access-requests.md) | Access request issues, signed request block, invite links, token scopes per role |
| [recovery.md](recovery.md) | Org escrow recipient, offline recovery kit |
| [rotation.md](rotation.md) | Rotation metadata, member history, "remove member" checklist |

## Build order for feature agents

Matches DESIGN.md. Every item below codes against the specs listed:

1. Nested `.gpg-id` resolution: **done in Phase 0** (`findGpgIdForEntry`, `writeEntry`).
2. Access request submission → access-requests.md, store-layout.md.
3. Admin approval UI → access-requests.md, folder-admins.md, `reencryptFolder`.
4. Remove member + rotation checklist → rotation.md, `reencryptFolder`.
5. `.gpg-id` signature verification → gpg-id-signatures.md (implement as a `TrustHook`).
6. Invite links with scoped tokens → access-requests.md §Invites.
7. Optional hashed names (not specified yet).

## Ground rules (all features)

- **Encrypt only via the choke-point**: `verifyRecipients` / `verifyProposedRecipients`
  → `encryptToVerified`. ESLint and `test/guards.test.ts` fail the build otherwise.
- **No plaintext, passphrase, private key or token** in logs, errors, URLs,
  `localStorage`, IndexedDB, git, issue bodies, or commit messages. `console.*` is
  banned in `src/`.
- **Writes are single atomic commits** with optimistic concurrency
  (`ConflictError` → reload snapshot, recompute, retry via `withConflictRetry`).
- **CSP stays strict**: no new origins besides `https://api.github.com`, no
  `'unsafe-*'`, no `'wasm-unsafe-eval'` (see core-api.md §Argon2).
- **Pinned deps**: `npm install --save-exact`; lockfile changes get reviewed.
