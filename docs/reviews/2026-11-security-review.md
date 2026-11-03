# Security review: Phase 1 fixes (re-review) and Phase 2

Scope:

1. **Re-review** of the Phase 1 security fixes
   (`bmp/team-access-integrate-09db83..bmp/team-access-security-fixes-f98b16`):
   C1 (plan digest), H1 (admins fork/rollback, fresh vs cached device, cache
   poisoning), H2 (child notations, boundary-vanished, no-absorption,
   replayed parents, deleting a child together with its declaration), M1,
   the encrypt guard and `check-dist`.
2. **Phase 2** as built on this branch: remove member and rotation, invites,
   create and remove sub-folder.

Each finding below has been fixed, and each fix has a regression test that
fails without it.

## Re-review findings

| ID | Severity | Finding | Fix | Test |
| --- | --- | --- | --- | --- |
| R-H1 | **High** | **H1 bypass via merge commits.** `GET /commits?path=` uses git's history simplification. At a merge that is TREESAME to one parent for the path, the other parents are pruned. A removed admin M can branch from V1 (where M was an admin), commit a fork V2′ there, and merge it into `main` with the result resolved to V2′. The listing then shows only `V2′, V1`; the legitimate V2 that removed M is hidden. On a fresh device the fork scan never sees V2, so M is an admin again. No force push is needed, so "block force pushes" does not help. Rollback works the same way (restoring the anchor-signed V1 behind a merge). Reproduced with real git: `git log -- path` lists `V2p, V1`. | Every merge in oldest-listed..head is examined with the compare API. Each merge parent's file content must be a version the listing shows ("absent" too, if the listing reaches the file's creation). Unverifiable ranges (over 1000 commits or 50 merges, or a non-linear base) fail closed. | `test/rereview.test.ts` (fork and rollback via merge refused; benign merges accepted), `test/history.test.ts` |
| R-M1 | Medium | **8-hex fingerprint confirmation is grindable.** The typed suffix (32 bits) can be matched by a vanity-key search in hours on a GPU (cf. evil32). Anyone with issue write access, which includes every invite-token holder, can edit a pending request and swap in a key with the same last 8 hex. | The approver now types the last **16** hex characters (64 bits). | `test/access-approve.test.ts` |
| R-M2 | Medium | **Runtime encrypt guard bypass.** openpgp.js exports `PublicKeyEncryptedSessionKeyPacket` and `SymEncryptedSessionKeyPacket`. A message can be assembled by hand without `Message#encrypt` (the only guarded path). | Both packets' `encrypt` are now guarded (non-writable, non-configurable). A PKESK is allowed only for a key packet of the set that `encryptToVerified` is encrypting right now (ref-counted), and a password SKESK never. | `test/encrypt-guard.test.ts` |
| R-L1 | Low | **The plan digest did not cover the admin grant.** For `role: folder-admin`, the approval also wrote the admins file, but the reviewed plan neither showed it nor covered it with the digest. | The admins change (before → after) is part of `RecipientChangePlan` and its digest, and is shown in the UI. The same `approvalChange()` is used by the inbox, preview and commit. | `test/remove-rotation.test.ts` |
| R-L2 | Low | **Removing a folder admin left the folders they signed broken.** Nested `.gpg-id` / admins files signed by a removed admin stop verifying. Re-signing an unverified folder is refused, so in-app this was a deadlock. | The removal re-signs them in the same commit (`plan.resign`), as the operator, keeping their declarations. | `test/remove-rotation.test.ts` |

Checked and found holding: the C1 digest recomputation on the commit snapshot;
the H1 cache (written only after full validation; a fork never overwrites
it); H2 vanished/undeclared/no-absorption checks, including deleting an
intermediate boundary and replaying an older parent on a device that saw a
newer one; M1 retired-escrow drop; `check-dist` markers; the ESLint `.encrypt(`
rule.

Accepted residual risks (unchanged, documented in the specs):

- Replay on fresh devices.
- Force-push history rewrite and window flooding (H1).
- Blind approval.
- Anonymous-recipient (`--throw-keyids`) entries skip the PKESK no-absorption check during a folder re-encrypt.

## Phase 2 findings

| ID | Severity | Finding | Fix | Test |
| --- | --- | --- | --- | --- |
| P2-H1 | **High** | **`removeSubfolder` could widen a deleted grandchild's secrets.** A committed verification of C only *warns* about a vanished boundary below it. Merging C into P would have re-encrypted a deleted grandchild D's entries (narrower recipients) to P, without showing it in the plan. | Removal requires C's declarations to verify, no declared children, and no vanished declared or device-known boundary below C. Every entry under C must also be encrypted to all of C's current recipients (PKESK check; anonymous recipients fail closed). | `test/subfolders.test.ts` ("phase-2 review") |
| P2-M1 | Medium | **A forged invite could replace a device's anchors.** The newcomer flow pinned the invite's anchors after one checkbox, even when a different set was already pinned. A phishing link plus repo write would then redirect an existing user's trust. | `pinAnchors(…, 'invite')` throws when a different set is pinned. The UI explains how to reset anchors (in person) first. | `test/invites.test.ts` |
| P2-M2 | Medium (UX → security) | **The invite link was hidden right after it was created.** The link (shown once) was wiped by an immediate reload, and approval/removal results ("revoke the invite token", "still has access in …") were overwritten by the reload status. Found by the browser e2e run. | Reloads keep the action's result, the folder card re-opens, and invite creation no longer reloads. | `e2e/flow.e2e.ts` |
| P2-M3 | Medium | **Folder-admin approvals always failed.** The inbox planned folder-admin requests without the admin grant, so the reviewed digest never matched the commit (`plan-changed`). | `approvalChange()` is shared by the inbox, preview and commit. | `test/remove-rotation.test.ts`, `test/invites.test.ts` |

Reviewed and holding:

- **Removal completeness.** The member leaves F's `.gpg-id` and F's admins file in one commit, with every governed entry re-encrypted. Invite records they issued become invalid (the issuer must be an admin now). Other folders where they are still a recipient or listed admin are reported (`memberAccessElsewhere`) and shown in the UI. The rotation checklist lists every exposed, un-rotated entry. The removal of a global anchor from a folder does not remove anchor status; the root shows in "still has access in".
- **Invite token scope and leakage.**
  - The token lives only in the URL fragment, which is stripped by `replaceState` before the origin gate even renders. It is then kept in memory and is non-enumerable on the parsed invite.
  - It is never in the signed record, the access-request issue (asserted in e2e) or error messages.
  - Only fine-grained tokens are accepted, the lifetime is capped at 7 days, and the admin side checks for over-scope (the token must not read the store).
  - Residual: browser global history may keep the original URL (documented). Approvals remind the admin to revoke the token.
- **Invite records.**
  - Records are signed by `issuedBy`, who must be an anchor or folder admin in the *current* snapshot.
  - The folder must match exactly, the role must be ≤ the record's role, and the record must be unexpired at commit time.
  - Each record is single use: it is deleted in the approval commit, and `reencryptFolder` allows only that exact deletion.
- **Subfolder create vs H2.** It is one commit. The parent's same-commit declaration must declare exactly `expected(P) ∪ {C}`, be made by an authorized signer of P, cover P's unchanged bytes, and P's own chain must verify. Forged, wrong and wrong-parent declarations are refused. Moved entries go through the no-absorption check.
- **Subfolder remove vs H2.**
  - A device that knew C accepts the removal only through a verified, non-replayed `removed@g00pass` on P.
  - The declaration is carried forward on every re-sign, and the policy enforces that.
  - A forged removal by a non-admin and a replay of the pre-removal parent signature are both refused.

Accepted residual risks (Phase 2):

- **The rotation file is encrypted but not signed.** A writer can forge "rotated" marks. It is a reminder list, not an authority.
- **The "deleted entries from history" part of the checklist is not implemented yet.**
- **The app has no entry editor yet.** Rotation tracking on entry edits is implemented in the core but not wired to the UI.

## Owner decisions (still pending)

- Accept that a member added with gpg but not re-encrypted blocks g00pass re-encryption. Recommendation: yes.
- Enable "block force pushes" on the store branch. Recommendation: yes. This mitigates the remaining H1 rewrite risk; it does not stop merges, which R-H1 now covers.
- Create/remove subfolder actions: implemented in this round.
