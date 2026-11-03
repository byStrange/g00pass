import {
  G00passError,
  GitHubClient,
  GitHubSnapshot,
  TokenStore,
  getTrustHook,
  getPinnedAnchors,
  formatFingerprint,
  pinAnchors,
  takeInviteFromLocation,
  type Invite,
  type TakenInvite,
  inspectImportedKey,
  isHiddenEntry,
  listEntries,
  readEntry,
  unlockPrivateKey,
  wipe,
  type GitHubRepo,
} from '../core';
import { h, clear } from './dom';
import { deviceKeyInfo, forgetDeviceKey, loadDeviceKeyArmored, saveDeviceKey } from './keystore';
import { createEnrollment } from './enroll';
import { mountInbox } from './inbox';
import { mountFolders } from './folders';
import { acknowledgeOriginRisk, assessOrigin, isOriginRiskAcknowledged } from './origin';
import { Session, copyWithAutoClear } from './session';
import { createTrustPanel } from './trust';

const CONFIG_KEY = 'g00pass.repo-config.v1';
const IDLE_LOCK_MS = 5 * 60_000;
const CLIPBOARD_CLEAR_MS = 30_000;

function loadConfig(): GitHubRepo {
  try {
    const c = JSON.parse(localStorage.getItem(CONFIG_KEY) ?? '{}') as Partial<GitHubRepo>;
    return { owner: c.owner ?? '', repo: c.repo ?? '', branch: c.branch ?? 'main', storeRoot: c.storeRoot ?? '', requestsRepo: c.requestsRepo ?? '' };
  } catch {
    return { owner: '', repo: '', branch: 'main', storeRoot: '', requestsRepo: '' };
  }
}

function errMsg(e: unknown): string {
  return e instanceof G00passError ? e.message : 'Unexpected error';
}

/**
 * Blocking warning when the app does not own its origin (M2): shared
 * localStorage exposes the device key and the trust anchors to other pages.
 * Resolves once the user explicitly accepts the risk for this origin + path.
 */
function originGate(root: HTMLElement): Promise<void> {
  const risk = assessOrigin(location);
  if (!risk.risky || isOriginRiskAcknowledged(localStorage, risk)) return Promise.resolve();
  return new Promise((resolve) => {
    const ok = h('input', { type: 'checkbox' });
    const btn = h('button', { type: 'button', class: 'danger', disabled: true }, 'I understand the risk, continue');
    ok.addEventListener('change', () => (btn.disabled = !ok.checked));
    const screen = h(
      'section',
      { class: 'card origin-gate', role: 'alertdialog', 'aria-labelledby': 'origin-gate-title' },
      h('h2', { id: 'origin-gate-title' }, 'Unsafe hosting: this origin is shared'),
      h('p', { class: 'banner danger' }, `g00pass keeps your passphrase-protected device key and the pinned global admins (trust anchors) in this browser's storage for ${location.origin}. Every page on that origin can read and change them.`),
      h('ul', {}, ...risk.reasons.map((r) => h('li', {}, r))),
      h('p', {}, 'A page on the same origin could steal the encrypted key (and try passphrases offline) or replace the pinned anchors so that you trust an attacker. Deploy g00pass at the root of a dedicated origin (its own domain or subdomain) on a host that serves dist/_headers, e.g. Cloudflare Pages or Netlify.'),
      h('label', { class: 'inline' }, ok, `I understand that other pages on ${risk.scope} can read and modify g00pass data.`),
      btn,
    );
    btn.addEventListener('click', () => {
      if (!ok.checked) return;
      acknowledgeOriginRisk(localStorage, risk);
      screen.remove();
      resolve();
    });
    root.append(screen);
  });
}

export function mountApp(root: HTMLElement): void {
  // FIRST: an invite link carries a token in the fragment; strip it from the
  // address bar and history before anything else (even the origin warning).
  const invite = takeInviteFromLocation(location, history);
  void originGate(root).then(() => mountAppUnguarded(root, invite));
}

function mountAppUnguarded(root: HTMLElement, invite: TakenInvite): void {
  const tokens = new TokenStore('session');
  let config = loadConfig();
  let snapshot: GitHubSnapshot | null = null;
  const client = new GitHubClient({ token: tokens.get });

  const status = h('p', { class: 'status', role: 'status', 'aria-live': 'polite' });
  const setStatus = (t: string, isError = false) => {
    status.textContent = t;
    status.classList.toggle('error', isError);
  };

  const trust = createTrustPanel({ setStatus });
  const entryView = h('section', { class: 'card entry', hidden: true });
  const clearEntryView = () => {
    clear(entryView);
    entryView.hidden = true;
  };

  const session = new Session(IDLE_LOCK_MS, () => {
    clearEntryView();
    render();
    setStatus('Locked.');
  });
  for (const ev of ['pointerdown', 'keydown']) document.addEventListener(ev, () => session.touch(), { passive: true });
  window.addEventListener('pagehide', () => session.lock());

  // ----- repo config -----
  const f = {
    owner: h('input', { name: 'owner', required: true, autocomplete: 'off', spellcheck: 'false' }),
    repo: h('input', { name: 'repo', required: true, autocomplete: 'off', spellcheck: 'false' }),
    branch: h('input', { name: 'branch', required: true, autocomplete: 'off' }),
    storeRoot: h('input', { name: 'storeRoot', autocomplete: 'off', placeholder: '(repo root)' }),
    requestsRepo: h('input', { name: 'requestsRepo', autocomplete: 'off', spellcheck: 'false', placeholder: 'owner/name (recommended)' }),
    token: h('input', { name: 'token', type: 'password', autocomplete: 'off', placeholder: 'fine-grained, read-only' }),
    remember: h('input', { type: 'checkbox', name: 'remember' }),
  };
  f.owner.value = config.owner;
  f.repo.value = config.repo;
  f.branch.value = config.branch;
  f.storeRoot.value = config.storeRoot ?? '';
  f.requestsRepo.value = config.requestsRepo ?? '';
  f.remember.checked = tokens.hasToken;

  const configForm = h(
    'form',
    {
      class: 'card',
      onsubmit: (e: Event) => {
        e.preventDefault();
        config = {
          owner: f.owner.value.trim(),
          repo: f.repo.value.trim(),
          branch: f.branch.value.trim() || 'main',
          storeRoot: f.storeRoot.value.trim(),
          requestsRepo: f.requestsRepo.value.trim(),
        };
        localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
        if (f.token.value) tokens.set(f.token.value, f.remember.checked ? 'session' : 'memory');
        f.token.value = '';
        void refresh();
        void enroll.render();
      },
    },
    h('h2', {}, 'Repository'),
    h('label', {}, 'Owner', f.owner),
    h('label', {}, 'Repository', f.repo),
    h('label', {}, 'Branch', f.branch),
    h('label', {}, 'Store folder', f.storeRoot),
    h('label', {}, 'Requests repo (private, for access requests)', f.requestsRepo),
    h('p', { class: 'hint' }, 'Leave empty to use the store repo. A separate private requests repo is recommended.'),
    h('label', {}, 'GitHub token', f.token),
    h('label', { class: 'inline' }, f.remember, 'Keep token for this tab (sessionStorage)'),
    h('div', { class: 'row' }, h('button', { type: 'submit' }, 'Save & load'), h('button', { type: 'button', onclick: () => { tokens.clear(); setStatus('Token forgotten.'); } }, 'Forget token')),
  );

  const enroll = createEnrollment({
    getConfig: () => config,
    getUnlockedKey: () => session.unlockedKey,
    mainToken: tokens.get,
    setStatus,
    onKeyChanged: () => void renderKeyCard(),
  });

  // ----- device key -----
  const keyCard = h('section', { class: 'card' });
  const passphrase = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Passphrase' });

  async function renderKeyCard() {
    void enroll.render();
    clear(keyCard);
    keyCard.append(h('h2', {}, 'Device key'));
    const info = await deviceKeyInfo().catch(() => null);
    if (!info) {
      const ta = h('textarea', { rows: '6', spellcheck: 'false', placeholder: '-----BEGIN PGP PRIVATE KEY BLOCK-----' });
      keyCard.append(
        h('p', { class: 'hint' }, 'Paste a passphrase-protected private key. It is stored encrypted in this browser only.'),
        ta,
        h('button', {
          onclick: async () => {
            try {
              // Same checks as enrollment import (protected, v4, accepted algorithm).
              await inspectImportedKey(ta.value);
              await saveDeviceKey(ta.value);
              ta.value = '';
              setStatus('Key stored.');
              await renderKeyCard();
            } catch (e) {
              setStatus(errMsg(e), true);
            }
          },
        }, 'Store key'),
      );
      return;
    }
    keyCard.append(h('p', { class: 'mono' }, info.fingerprint), h('p', { class: 'hint' }, info.userIds.join(', ')));
    if (session.unlockedKey) {
      keyCard.append(h('div', { class: 'row' }, h('button', { onclick: () => session.lock() }, 'Lock now')));
    } else {
      keyCard.append(
        h('form', {
          class: 'row',
          onsubmit: async (e: Event) => {
            e.preventDefault();
            const armored = loadDeviceKeyArmored();
            if (!armored) return;
            try {
              session.unlock(await unlockPrivateKey(armored, passphrase.value));
              setStatus('Unlocked. Auto-locks after 5 minutes of inactivity.');
            } catch (err) {
              setStatus(errMsg(err), true);
            } finally {
              passphrase.value = '';
              render();
            }
          },
        }, passphrase, h('button', { type: 'submit' }, 'Unlock')),
        h('button', {
          class: 'danger',
          onclick: async () => {
            if (!confirm('Remove the device key from this browser?')) return;
            forgetDeviceKey();
            await renderKeyCard();
          },
        }, 'Remove key from this device'),
      );
    }
  }

  // ----- entries -----
  const filter = h('input', { type: 'search', placeholder: 'Filter entries', autocomplete: 'off' });
  const list = h('ul', { class: 'entries' });
  const entriesCard = h('section', { class: 'card' }, h('h2', {}, 'Entries'), filter, list);
  filter.addEventListener('input', () => renderList());

  function renderList() {
    clear(list);
    if (!snapshot) return;
    const q = filter.value.trim().toLowerCase();
    for (const p of listEntries(snapshot).filter((e) => !isHiddenEntry(e))) {
      const name = p.slice(0, -4);
      if (q && !name.toLowerCase().includes(q)) continue;
      list.append(h('li', {}, h('button', { class: 'link', onclick: () => void openEntry(p) }, name)));
    }
  }

  /** Reload the store. `note` (the result of the action that caused the reload) stays visible. */
  async function refresh(note?: string, noteIsError = false) {
    if (!config.owner || !config.repo) return;
    setStatus(note ? `${note} Reloading…` : 'Loading…', noteIsError);
    try {
      snapshot = await GitHubSnapshot.load(client, config);
      const loaded = `Loaded ${listEntries(snapshot).filter((e) => !isHiddenEntry(e)).length} entries at ${snapshot.commitSha.slice(0, 7)}.`;
      setStatus(note ? `${note} (${loaded})` : loaded, noteIsError);
      renderList();
      folders.refresh();
      await trust.refresh(snapshot, config).catch(() => setStatus('Could not evaluate recipient trust; treat this store as unverified.', true));
    } catch (e) {
      snapshot = null;
      void trust.refresh(null, config);
      setStatus(errMsg(e), true);
    }
  }

  async function openEntry(path: string) {
    const key = session.unlockedKey;
    if (!snapshot) return;
    if (!key) {
      setStatus('Unlock your device key first.', true);
      return;
    }
    clearEntryView();
    let plain: Uint8Array | null = null;
    try {
      plain = await readEntry(snapshot, path, [key]);
      const text = new TextDecoder().decode(plain);
      const nl = text.indexOf('\n');
      const password = nl === -1 ? text : text.slice(0, nl).replace(/\r$/, '');
      const rest = nl === -1 ? '' : text.slice(nl + 1);
      const pw = h('code', { class: 'secret' }, '••••••••');
      const details = h('pre', { class: 'details', hidden: true }, rest);
      let shown = false;
      entryView.append(
        h('h2', {}, path.slice(0, -4)),
        pw,
        h('div', { class: 'row' },
          h('button', {
            onclick: () => {
              shown = !shown;
              pw.textContent = shown ? password : '••••••••';
              details.hidden = !shown;
            },
          }, 'Reveal / hide'),
          h('button', {
            onclick: () =>
              copyWithAutoClear(password, CLIPBOARD_CLEAR_MS, () => setStatus('Clipboard cleared.')).then(
                () => setStatus('Copied. Clipboard clears in 30 s.'),
                () => setStatus('Clipboard not available.', true),
              ),
          }, 'Copy password'),
          h('button', { onclick: clearEntryView }, 'Close'),
        ),
      );
      if (rest) entryView.append(details);
      const st = await trust.entryStatus(snapshot, path).catch(() => null);
      if (st) entryView.append(st);
      entryView.hidden = false;
    } catch (e) {
      setStatus(errMsg(e), true);
    } finally {
      wipe(plain);
    }
  }

  // ----- admin inbox (access requests) -----
  const inbox = mountInbox({
    client,
    getConfig: () => config,
    deviceFingerprint: async () => (await deviceKeyInfo().catch(() => null))?.fingerprint ?? null,
    session,
    setStatus,
    onApproved: (note, isError) => void refresh(note, isError),
  });

  // ----- folder administration (remove member, rotation, sub-folders) -----
  const folders = mountFolders({
    client,
    getConfig: () => config,
    getSnapshot: () => snapshot,
    session,
    setStatus,
    onChanged: (note) => void refresh(note),
  });

  // ----- invite link (newcomer) -----
  function inviteCard(inv: Invite): HTMLElement {
    const [owner, repo] = inv.repo.split('/') as [string, string];
    const store = { owner, repo, storeRoot: inv.storeRoot };
    const pinned = getPinnedAnchors(store);
    const differs = !!pinned && (pinned.anchors.length !== inv.anchors.length || pinned.anchors.some((a) => !inv.anchors.includes(a)));
    const ok = h('input', { type: 'checkbox' });
    const btn = h('button', { type: 'button', class: 'primary', disabled: true }, 'Accept invite');
    ok.addEventListener('change', () => (btn.disabled = differs || !ok.checked));
    const card = h(
      'section',
      { class: 'card invite' },
      h('h2', {}, 'You were invited'),
      h('p', {}, `Store ${inv.repo}${inv.storeRoot ? ` (folder ${inv.storeRoot})` : ''}, branch ${inv.branch}. Access requested for ${inv.folder}/ as ${inv.role}. Requests go to ${inv.requestsRepo}. Expires ${inv.expiresAt}.`),
      h('p', {}, 'The invite names these global admins (trust anchors). Compare EVERY fingerprint with what your admin told you through another channel before accepting: they decide whom this device trusts.'),
      h('ul', { class: 'fprs' }, ...inv.anchors.map((a) => h('li', { class: 'mono' }, formatFingerprint(a)))),
      differs
        ? h('p', { class: 'banner danger', role: 'alert' }, 'This device already pinned DIFFERENT global admins for this store. An invite cannot replace them: a forged invite could make this device trust an attacker. If your admin confirms the change in person, reset the pinned global admins (settings below) and open the invite link again.')
        : '',
      h('label', { class: 'inline' }, ok, 'I compared these fingerprints with my admin and they match.'),
      h('p', { class: 'hint' }, 'The invite token is kept in memory only (this tab) and can only file your access request.'),
      btn,
    );
    btn.addEventListener('click', () => {
      if (!ok.checked || differs) return;
      pinAnchors(store, inv.anchors, 'invite');
      config = { owner, repo, branch: inv.branch, storeRoot: inv.storeRoot, requestsRepo: inv.requestsRepo };
      localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
      f.owner.value = owner;
      f.repo.value = repo;
      f.branch.value = inv.branch;
      f.storeRoot.value = inv.storeRoot;
      f.requestsRepo.value = inv.requestsRepo;
      enroll.applyPrefill({ folder: inv.folder, role: inv.role, inviteId: inv.id, requestsRepo: inv.requestsRepo, token: inv.token });
      card.remove();
      setStatus('Invite accepted: global admins pinned. Create your key below and submit the access request.');
    });
    return card;
  }

  // ----- layout -----
  const header = h(
    'header',
    {},
    h('h1', {}, 'g00pass'),
    h('span', { class: 'version', title: 'Build version and commit' }, `v${__APP_VERSION__} · ${__APP_COMMIT__}`),
  );
  const footer = h('footer', {}, `Trust policy: ${getTrustHook().name} (recipient lists verified per folder, see Recipient trust). Nothing leaves this browser except GitHub API calls.`);

  function render() {
    void renderKeyCard();
  }

  const inviteEl = invite.kind === 'invite' ? inviteCard(invite.invite) : null;
  if (invite.kind === 'invalid') setStatus(`Invite link not usable: ${invite.reason}`, true);
  root.append(header, status, ...(inviteEl ? [inviteEl] : []), configForm, trust.card, keyCard, enroll.el, entriesCard, entryView, inbox.el, folders.el, trust.settings, footer);
  render();
  if (tokens.hasToken) void refresh();
}
