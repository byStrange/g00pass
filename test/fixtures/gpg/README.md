# gpg-produced `.gpg-id.sig` fixtures

Generated offline with GnuPG 2.4.9 in a throw-away `GNUPGHOME` (the secret key
was discarded). Used by `test/trust-policy.test.ts` (gpg-id-signatures.md test 9).

```sh
export GNUPGHOME=$(mktemp -d)
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "Gpg Admin <gpgadmin@example.test>" ed25519 sign never
FPR=$(gpg --batch --with-colons --list-keys | awk -F: '/^fpr/{print $10; exit}')
gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key $FPR cv25519 encr never
printf '%s\n' $FPR > ops.gpg-id
gpg --batch --armor --export $FPR > public-key.asc
# g00pass format: folder-bound (what pass writes with
#   PASSWORD_STORE_GPG_OPTS="--sig-notation folder@g00pass=/ops")
gpg --batch -u $FPR --sig-notation 'folder@g00pass=/ops' --detach-sign -o ops.gpg-id.sig ops.gpg-id
# plain pass format (no folder binding): g00pass rejects it for writing
gpg --batch -u $FPR --detach-sign -o ops.gpg-id.pass-style.sig ops.gpg-id
```

Fingerprint: `1C7F172FAFB0F0461DC02D26075D719D60EADF3D`.
