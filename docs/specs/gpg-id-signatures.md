# `.gpg-id` signatures

Status: specified; implement it as the `TrustHook` installed in `src/main.ts`
(core-api.md §Trust choke-point). Phase 0 ships `passThroughTrustHook`, which is
marked `TODO(trust)`.

## Threat

Anyone with write access to the repository could edit a `.gpg-id` and add
their own key. Future secrets would then be encrypted to them. Write access is
not the same as authority, so the client must verify who authored each
recipient list before it encrypts.

## Compatibility with pass and gopass

- **pass** with `PASSWORD_STORE_SIGNING_KEY="FPR1 FPR2"` writes
  `<folder>/.gpg-id.sig` using `gpg --detach-sign` (binary) on every
  `pass init`. It then verifies the signature on every operation and accepts it
  when `VALIDSIG` reports a listed fingerprint, either the signing subkey's or
  the primary key's.
- g00pass uses **the same file name and format**, so a store maintained with
  pass and `PASSWORD_STORE_SIGNING_KEY` set to the global admins' fingerprints
  is valid for g00pass, and the reverse also holds.
- **gopass** neither creates nor checks `.gpg-id.sig` as far as we could
  determine, and it leaves the file alone. After `gopass recipients add/remove`,
  the old `.sig` no longer matches. g00pass will then refuse to encrypt in that
  folder until an admin re-signs it.
- `reencryptFolder` either writes a fresh signature or deletes the stale one, in
  the same commit.

## Valid signers

For `<F>/.gpg-id`, with F ≠ root:

```
allowed(F) = trustAnchors ∪ admins(nearestAdminsFile(F))
```

- `trustAnchors` is the device's pinned global admin fingerprints
  (store-layout.md).
- `nearestAdminsFile(F)` is the first `.g00pass-admins.json` found at
  `F`, `parent(F)`, …, stopping before the root. It must verify according to
  folder-admins.md. An unverifiable admins file contributes **no** signers. It
  does not cause the operation to fail.

For the root `.gpg-id`:

```
allowed("") = trustAnchors
```

## Verification algorithm (`TrustHook.verify`)

Input: a `RecipientVerificationRequest` (`folder`, `gpgIdContent`,
`gpgIdSignature`, `proposed`, `recipients`, `snapshot`).

1. If `gpgIdSignature` is null, return
   `{ok:false, code:'signature-missing'}`.
2. Parse the signature. Accept binary or armored input, and require exactly one
   signature packet of type 0x00. If it does not parse, return
   `{ok:false, code:'signature-invalid'}`.
3. Compute `allowed(folder)`. For each allowed fingerprint, resolve the key from
   `.public-keys/<FPR>` in `snapshot`.
4. Verify the detached signature over the **exact** `gpgIdContent` bytes. A
   signature is accepted when all of these hold:
   - it verifies cryptographically;
   - the issuer matches an allowed key, by primary or signing-subkey
     fingerprint;
   - the key was not revoked and not expired at signature creation time;
   - the creation time is no more than 5 minutes in the future.

   If it verifies but the signer is not allowed, return
   `{ok:false, code:'unknown-signer'}`. If it does not verify, return
   `{ok:false, code:'signature-invalid'}`.
5. If `proposed`, the signature was just produced by the operator. The same
   rules apply, so an operator who is neither a trust anchor nor a folder admin
   cannot change recipients.
6. Otherwise return `{ok:true}`. Add a warning when the signer is valid only
   through an admins file whose chain could not be fully walked (folder-admins.md
   §Chain).
7. If trust anchors are not configured on this device, return
   `{ok:false, code:'untrusted', reason:'no trust anchors pinned'}`.

**Root `.gpg-id` change detection**: when the root `.gpg-id` verifies, the hook
updates the pinned anchors as described in store-layout.md. It does this only
after a successful verification against the *currently pinned* anchors.

## Client behaviour

| Situation | Reads/decrypt | Encrypt/write in F | UI |
| --- | --- | --- | --- |
| valid signature | allowed | allowed | none |
| missing `.sig` | allowed | **refused** (`TrustError signature-missing`) | Warning banner on F: "Recipients of F are not signed by an admin. Writing is disabled." |
| invalid / unknown signer | allowed | **refused** | Red banner with the signer's fingerprint, if known: "Recipient list of F was changed by an unauthorized key." |
| no anchors pinned | allowed | **refused** | Setup prompt to pin anchors |

- Decryption never depends on `.gpg-id` and is always allowed.
- The client MUST NOT offer an "encrypt anyway" button.
- The only remedy is for an authorized signer to re-sign. The approve and
  remove flows do this automatically.

## Producing signatures

- **Approve or remove (`reencryptFolder`):** pass
  `gpgIdSignature: (text) => signDetached(text, operatorKey)`. The callback
  receives the exact bytes that will be committed.
- **Bootstrap or migration:** a global admin runs "Sign all recipient lists".
  This is a later feature. It lists every `.gpg-id`, shows each recipient list
  with names from `.public-keys`, asks for explicit confirmation, and commits
  all the `.sig` files in one commit. The pass equivalent is
  `PASSWORD_STORE_SIGNING_KEY=… pass init -p <F> <ids…>`.

## Test cases the implementation MUST cover

1. Valid signature by an anchor.
2. Valid signature by a folder admin, both directly and inherited from an
   ancestor's admins file.
3. Signature by a non-admin, which yields `unknown-signer`.
4. `.gpg-id` modified after signing, which yields `signature-invalid`.
5. Missing `.sig`.
6. `.sig` copied from another folder, which is invalid because the bytes
   differ.
7. Revoked or expired signer key.
8. A signing subkey that matches by primary fingerprint.
9. A signature produced by `gpg --detach-sign`, from a fixture generated
   offline and committed in `test/fixtures/`.
10. Root `.gpg-id` signed by a non-anchor.
11. Anchor rollover.
