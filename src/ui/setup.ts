import { G00passError, GitHubApiError, parsePublicKey, pinAnchors, sanitizeDisplayText, unlockPrivateKey, type RootTrust, type StoreSnapshot } from '../core';
import { actionButton, field, fingerprint, form, help, input, notice, screen, tokenSteps } from './components';
import { type AppCtx, storeLabel } from './context';
import { h } from './dom';
import { type StoredKeyInfo, forgetDeviceKey, loadDeviceKeyArmored } from './keystore';
import { keyChooser } from './keyforms';

/** First-run setup: Connect → Verify admins → Your key, then Unlock. */

export const SETUP_STEPS = ['Connect', 'Verify admins', 'Your key'] as const;

const REPO_RE = /^\s*(?:https:\/\/github\.com\/)?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?\s*$/;

export function describeLoadError(e: unknown): string {
  if (e instanceof GitHubApiError) {
    if (e.status === 401) return 'GitHub rejected the token (wrong or expired).';
    if (e.status === 403 || e.status === 404) return 'This token cannot read that repository (or the repository/branch does not exist). It needs Contents: Read-only on the store repo.';
    if (e.status === 0) return 'Could not reach GitHub (network).';
  }
  return e instanceof Error ? e.message : 'Could not load the store.';
}

export function connectScreen(ctx: AppCtx, opts: { error?: string; embedded?: boolean } = {}): HTMLElement {
  const c = ctx.config();
  const repo = input({ required: true, placeholder: 'owner/repository', value: c.owner ? `${c.owner}/${c.repo}` : '' });
  const token = input({ type: 'password', placeholder: ctx.tokens.hasToken ? '•••••• (saved for this tab; paste to replace)' : 'github_pat_…', 'aria-label': 'GitHub token' });
  const remember = h('input', { type: 'checkbox', checked: true });
  const branch = input({ value: c.branch || 'main' });
  const storeRoot = input({ value: c.storeRoot ?? '', placeholder: '(repository root)' });
  const requestsRepo = input({ value: c.requestsRepo ?? '', placeholder: 'owner/requests-repo (recommended)' });
  const body = form(
    async () => {
      const m = REPO_RE.exec(repo.value);
      if (!m) throw new G00passError('Repository must look like owner/name.');
      const req = requestsRepo.value.trim();
      if (req && !REPO_RE.test(req)) throw new G00passError('Requests repo must look like owner/name.');
      ctx.saveConfig({ owner: m[1]!, repo: m[2]!, branch: branch.value.trim() || 'main', storeRoot: storeRoot.value.trim(), requestsRepo: req.replace(REPO_RE, '$1/$2') });
      if (token.value.trim()) ctx.tokens.set(token.value.trim(), remember.checked ? 'session' : 'memory');
      token.value = '';
      if (!ctx.tokens.hasToken) throw new G00passError('Paste a GitHub token.');
      await ctx.reload();
    },
    (m) => ctx.toast(m, true),
    opts.embedded ? 'Save & reload' : 'Connect',
    'Connecting…',
    opts.error ? notice('danger', opts.error) : null,
    field('Store repository', repo, 'The GitHub repository that holds the password store, e.g. acme/secrets.'),
    field('GitHub token', token),
    h('label', { class: 'check' }, remember, 'Keep the token until this tab closes'),
    help('How do I get a token?', tokenSteps('the store repository', 'Contents: Read-only (admins: Read and write, plus Issues: Read and write on the requests repo)', 'up to 90 days'), h('p', { class: 'hint' }, 'The token is only sent to api.github.com and is never written to disk.')),
    help('More settings', field('Branch', branch), field('Store folder inside the repo', storeRoot), field('Requests repository', requestsRepo, 'A separate private repo where access requests are filed as issues. Leave empty to use the store repo (not recommended).')),
  );
  if (opts.embedded) return body;
  return screen({ steps: SETUP_STEPS, step: 0, title: 'Connect your password store', lead: 'g00pass reads your gopass/pass store straight from GitHub and decrypts it in this browser. Nothing else ever sees your secrets.' }, body);
}

async function claimedName(snapshot: StoreSnapshot, fpr: string): Promise<string> {
  try {
    const data = await snapshot.readFile(`.public-keys/${fpr}`);
    const keys = data ? await parsePublicKey(data, fpr) : [];
    return keys.length === 1 ? keys[0]!.getUserIDs().map((u) => sanitizeDisplayText(u, 200)).join(', ') : '(no key file)';
  } catch {
    return '(unreadable key file)';
  }
}

export function verifyAdminsScreen(ctx: AppCtx, root: Extract<RootTrust, { ok: false }>): HTMLElement {
  const snapshot = ctx.snapshot()!;
  const fprs = root.root?.admins ?? [];
  if (!fprs.length) {
    return screen({ steps: SETUP_STEPS, step: 1, title: 'This store is not set up for g00pass yet' }, notice('danger', root.reason), h('p', {}, 'The root .gpg-id must list the admins and be signed by one of them. See docs/specs/gpg-id-signatures.md §Migrating.'));
  }
  const ok = h('input', { type: 'checkbox' });
  const list = h('ul', { class: 'admin-list' });
  for (const f of fprs) {
    const li = h('li', {}, fingerprint(f, true), h('span', { class: 'hint uid' }, '…'));
    list.append(li);
    void claimedName(snapshot, f).then((n) => (li.lastChild!.textContent = `claims to be: ${n}`));
  }
  const go = actionButton('These are my admins — continue', async () => {
    if (!ok.checked) throw new G00passError('Tick the box once you have compared every fingerprint.');
    pinAnchors(ctx.config(), fprs, 'first-use');
    await ctx.reload('Admins verified.');
  }, { variant: 'primary', onError: (m) => ctx.toast(m, true) });
  return screen(
    { steps: SETUP_STEPS, step: 1, title: 'Check who the admins are', lead: `${storeLabel(ctx.config())} names these admins. This browser will only trust member lists they (or folder admins they appoint) signed.` },
    list,
    notice('warn', h('b', {}, 'Compare every fingerprint with your admin'), ' — in person, on a call, or in a chat you already trust. The names come from the repository and prove nothing; the fingerprint is what counts.'),
    h('label', { class: 'check' }, ok, 'I compared the fingerprints and they match.'),
    h('div', { class: 'actions' }, go),
  );
}

export function keyScreen(ctx: AppCtx): HTMLElement {
  return screen(
    { steps: SETUP_STEPS, step: 2, title: 'Your personal key', lead: 'Secrets are encrypted to people’s keys. Your key stays in this browser, protected by your passphrase.' },
    keyChooser(async () => ctx.reload('Key saved on this device.'), (m) => ctx.toast(m, true)),
  );
}

export function unlockScreen(ctx: AppCtx, info: StoredKeyInfo): HTMLElement {
  const pass = input({ type: 'password', autocomplete: 'current-password', required: true, 'aria-label': 'Passphrase' });
  const name = info.userIds[0] ? sanitizeDisplayText(info.userIds[0], 200) : 'your key';
  const f = form(
    async () => {
      const armored = loadDeviceKeyArmored();
      if (!armored) return ctx.rerender();
      try {
        ctx.session.unlock(await unlockPrivateKey(armored, pass.value));
      } finally {
        pass.value = '';
      }
      ctx.toast('Unlocked. Locks itself after 5 minutes without activity.');
      ctx.rerender();
    },
    (m) => {
      ctx.toast(m, true);
      pass.focus();
    },
    'Unlock',
    'Unlocking…',
    field('Passphrase', pass),
  );
  queueMicrotask(() => pass.focus());
  return screen(
    { title: 'Unlock', lead: `Enter the passphrase for ${name}.` },
    f,
    h('p', { class: 'hint' }, `Key …${(info.fingerprint.slice(-16).match(/.{4}/g) ?? []).join(' ')}`),
    h('button', {
      type: 'button',
      class: 'ghost small',
      onclick: () => {
        if (!confirm('Remove this key from this browser? You will need the key file (or create a new key and request access again).')) return;
        forgetDeviceKey();
        ctx.rerender();
      },
    }, 'Use a different key'),
  );
}

/** Shown instead of everything when the root recipient list does not match the pinned admins. */
export function trustBanner(root: Extract<RootTrust, { ok: false }>): HTMLElement {
  return notice(
    'danger',
    h('b', {}, 'Admin list not trusted. '),
    `${root.reason}. You can still read, but nothing can be changed until this is resolved. Do not ignore this: someone may be trying to add their key. `,
    root.added.length ? h('div', {}, 'Not trusted but listed: ', ...root.added.map((a) => fingerprint(a))) : null,
  );
}
