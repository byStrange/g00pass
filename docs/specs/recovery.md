# Recovery: org escrow key and offline recovery kit

Goal: losing a device key, or every key of a folder's members, must not mean
losing the folder. There are two independent mechanisms.

## 1. Org recovery (escrow) recipient (optional, recommended)

### Setup (global admin, offline)

1. On an air-gapped machine with GnuPG ≥ 2.2, generate the key:

   ```
   gpg --quick-generate-key "g00pass org recovery <recovery@org.example>" cv25519 encr never
   ```

   This is a dedicated, **encryption-only** key with no expiry, or with a long
   expiry and a calendar reminder. Escrow does not need a signing capability:
   it must never be able to sign `.gpg-id` or admins files. RSA 4096 is also
   acceptable.
2. Store the secret key **offline only**:
   - a `paperkey` printout plus 2 hardware tokens or encrypted USB sticks;
   - kept in separate physical locations.
   - Optionally use a k-of-n Shamir split (for example `gfsplit`) among
     trustees.
   - Write down the passphrase custody procedure.
3. Export the public key to `.public-keys/<FPR>` (armored).
4. Add `<FPR> # g00pass:escrow` to the root `.gpg-id`, then re-sign it
   (gpg-id-signatures.md).
5. Re-encrypt every folder so that each `.gpg-id` contains the escrow FPR. The
   core does this automatically on the next `reencryptFolder` of each folder. A
   later "Add escrow to all folders" admin action can batch it, folder by
   folder, with one commit each.

### Rules (enforced by core; see core-api.md)

- The escrow recipient is the line(s) in the **root** `.gpg-id` flagged
  `g00pass:escrow`. Escrow is never inferred from anywhere else.
- `verifyProposedRecipients` (and therefore `reencryptFolder`, approve, and
  remove) **always merges** the current escrow line(s) into the new `.gpg-id`.
  A proposed set without escrow fails with `TrustError('escrow-missing')`.
- When an existing folder lacks escrow, the core adds the warning
  `escrow-missing`, and the production trust hook (Phase 1) **refuses writes**
  there with `TrustError('escrow-missing')`. Otherwise an admin could
  silently drop the recovery key. Reads stay allowed. The remedy is a
  re-encrypt (`reencryptFolder`), which merges escrow back in.
- Escrow fingerprints are **never** global admins, folder admins, or trust
  anchors, even though they appear in the root `.gpg-id`.
- The UI MUST NOT offer "remove member" for an escrow fingerprint.

### Rotating or removing the escrow key

1. A global admin changes the escrow line in the root `.gpg-id` and re-signs
   it.
2. Each folder then gets re-encrypted. The feature code MUST drop the previous
   escrow lines: any `.gpg-id` line flagged `g00pass:escrow` whose FPR is no
   longer flagged in the root. The core merges in only the *current* escrow.
3. Removal of escrow is a deliberate root `.gpg-id` change by a global admin.
   There is no per-folder opt-out.

### Using escrow (lost keys)

This runs offline, outside g00pass. Because the store stays pass/gopass
compatible, the CLI can be used directly:

```sh
git clone git@github.com:acme/secrets.git && cd secrets
gpg --import escrow-secret.asc        # on the air-gapped machine only
# Option A: add the member's NEW key (from their new access request) to the folder.
#   pass:   PASSWORD_STORE_DIR=. PASSWORD_STORE_SIGNING_KEY=<global-admin FPR> \
#           pass init -p infra <existing FPRs…> <new FPR> <escrow FPR>
#   gopass: gopass recipients add --store <mount> <new FPR>   (then re-sign .gpg-id)
# Option B: decrypt and hand over via a sanctioned channel (discouraged).
git push   # from the air-gapped machine via sneakernet, or export the commit
```

- `pass init -p` re-encrypts the folder and, with `PASSWORD_STORE_SIGNING_KEY`,
  writes `.gpg-id.sig` in g00pass-compatible form.
- Afterwards, re-add the `# g00pass:escrow` comment on the escrow line if the
  tool dropped it.
- After any escrow use, record it in the incident log and consider rotating
  the escrow key.

## 2. Personal offline recovery kit (every user)

The app offers this right after key generation, before the access request is
sent, and again in settings. The kit is a single text file the user saves
offline: printed, or on a USB stick. It contains no unprotected secrets.

File name: `g00pass-recovery-<FPR last 16>.txt`

```
g00pass recovery kit
====================
Created:      2026-11-02T10:15:00Z
Store:        acme/secrets (branch main, root /)
Fingerprint:  AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333
User ID:      Carol Example <carol@example.org>

How to restore
--------------
1. Open g00pass → Settings → Device key → Import, paste the PRIVATE KEY block.
2. Enter your passphrase (it is NOT in this file).
Or with GnuPG:  gpg --import this-file.txt

If this key is compromised, publish the REVOCATION CERTIFICATE below to the
store admins and ask to be removed (they will re-encrypt and rotate secrets).

-----BEGIN PGP PRIVATE KEY BLOCK-----
(passphrase-protected, iterated+salted S2K, as stored on the device)
-----END PGP PRIVATE KEY BLOCK-----

-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: This is a revocation certificate
…
-----END PGP PUBLIC KEY BLOCK-----
```

Rules:
- Generate the kit locally. The download is a `Blob` with `URL.createObjectURL`
  (CSP `default-src 'none'` still allows downloads via `<a download>`). The kit
  is never uploaded, never put in an issue, and never placed in the store.
- The private key is included **only in its passphrase-protected form**. The
  passphrase is never included.
- The revocation certificate is the `revocationCertificate` returned by
  openpgp.js `generateKey`.

## 3. Lost device without a kit

The user enrolls a **new** key through a normal access request. Any remaining
recipient who is a folder admin approves it. Then the folder admin removes the
old key with "remove member"; the rotation checklist applies only if the old
device may be compromised rather than just lost. Escrow is needed only when
**no** admin-recipient of the folder remains.
