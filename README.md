# g00pass (gopass-web)

A PWA that reads a gopass/pass password store from a GitHub repo and decrypts
entries **in the browser** with openpgp.js. It uses per-device keys and static
hosting with a strict CSP. No server ever holds keys or secrets.

- Design: [DESIGN.md](DESIGN.md)
- Specs for team access (normative): [docs/specs/](docs/specs/README.md)
- Core API: [docs/specs/core-api.md](docs/specs/core-api.md)

```sh
npm ci
npm run dev        # dev server (CSP is only injected in production builds)
npm test           # vitest, single worker
npm run typecheck
npm run lint
npm run build      # typecheck + vite build + dist CSP/inline-script check
```

The build version and commit appear in the app header. Set `G00PASS_COMMIT`
to override the commit (e.g. for reproducible CI builds). Deploy `dist/` at
the **root of a dedicated origin** (own domain or subdomain): the device key
and the pinned trust anchors live in `localStorage`, which every page on the
same origin can read and change. Prefer a host that serves `dist/_headers`
(CSP incl. `frame-ancestors`), e.g. Cloudflare Pages or Netlify. On
`*.github.io` or below the origin root the app shows a blocking warning that
must be explicitly accepted.

**Tokens:** use a fine-grained PAT restricted to the store repo with
*Contents: Read-only*. It stays in memory, or in sessionStorage if you opt in.
See [access-requests.md](docs/specs/access-requests.md#token-scopes-per-role)
for other roles.

**Access requests:** new users generate a key in the browser (v4 curve25519,
iterated-S2K passphrase protection, stored passphrase-encrypted on the device)
and post a signed request as an issue. Set **Requests repo** (`owner/name`) in
the settings to a *separate private repo*: a token with Issues access can read
every issue in its repo, so do not share the store repo with requesters. If it
is unset the app falls back to the store repo and shows a warning. Requesters
need only a fine-grained PAT with *Issues: Read and write* on the requests
repo; the request token is kept in memory only. Before approving, ask the
requester for their fingerprint out of band and type its last 8 characters,
and review the exact before → after recipient list. Folders whose current
recipient list does not verify cannot be approved.

**Existing stores (breaking change):** `.gpg-id.sig` must now declare nested
boundaries with `child@g00pass` notations; re-sign the root and every parent
of a nested `.gpg-id` once, see
[gpg-id-signatures.md §Migrating](docs/specs/gpg-id-signatures.md#migrating-an-existing-store-breaking-change).
