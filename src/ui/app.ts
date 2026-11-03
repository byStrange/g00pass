import {
  G00passError,
  GitHubClient,
  GitHubSnapshot,
  TokenStore,
  getTrustHook,
  isHiddenEntry,
  listEntries,
  readEntry,
  unlockPrivateKey,
  wipe,
  type GitHubRepo,
} from '../core';
import { h, clear } from './dom';
import { deviceKeyInfo, forgetDeviceKey, loadDeviceKeyArmored, saveDeviceKey } from './keystore';
import { Session, copyWithAutoClear } from './session';
import { createTrustPanel } from './trust';

const CONFIG_KEY = 'g00pass.repo-config.v1';
const IDLE_LOCK_MS = 5 * 60_000;
const CLIPBOARD_CLEAR_MS = 30_000;

function loadConfig(): GitHubRepo {
  try {
    const c = JSON.parse(localStorage.getItem(CONFIG_KEY) ?? '{}') as Partial<GitHubRepo>;
    return { owner: c.owner ?? '', repo: c.repo ?? '', branch: c.branch ?? 'main', storeRoot: c.storeRoot ?? '' };
  } catch {
    return { owner: '', repo: '', branch: 'main', storeRoot: '' };
  }
}

function errMsg(e: unknown): string {
  return e instanceof G00passError ? e.message : 'Unexpected error';
}

export function mountApp(root: HTMLElement): void {
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
    token: h('input', { name: 'token', type: 'password', autocomplete: 'off', placeholder: 'fine-grained, read-only' }),
    remember: h('input', { type: 'checkbox', name: 'remember' }),
  };
  f.owner.value = config.owner;
  f.repo.value = config.repo;
  f.branch.value = config.branch;
  f.storeRoot.value = config.storeRoot ?? '';
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
        };
        localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
        if (f.token.value) tokens.set(f.token.value, f.remember.checked ? 'session' : 'memory');
        f.token.value = '';
        void refresh();
      },
    },
    h('h2', {}, 'Repository'),
    h('label', {}, 'Owner', f.owner),
    h('label', {}, 'Repository', f.repo),
    h('label', {}, 'Branch', f.branch),
    h('label', {}, 'Store folder', f.storeRoot),
    h('label', {}, 'GitHub token', f.token),
    h('label', { class: 'inline' }, f.remember, 'Keep token for this tab (sessionStorage)'),
    h('div', { class: 'row' }, h('button', { type: 'submit' }, 'Save & load'), h('button', { type: 'button', onclick: () => { tokens.clear(); setStatus('Token forgotten.'); } }, 'Forget token')),
  );

  // ----- device key -----
  const keyCard = h('section', { class: 'card' });
  const passphrase = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Passphrase' });

  async function renderKeyCard() {
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

  async function refresh() {
    if (!config.owner || !config.repo) return;
    setStatus('Loading…');
    try {
      snapshot = await GitHubSnapshot.load(client, config);
      setStatus(`Loaded ${listEntries(snapshot).filter((e) => !isHiddenEntry(e)).length} entries at ${snapshot.commitSha.slice(0, 7)}.`);
      renderList();
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

  // ----- layout -----
  const header = h(
    'header',
    {},
    h('h1', {}, 'g00pass'),
    h('span', { class: 'version', title: 'Build version and commit' }, `v${__APP_VERSION__} · ${__APP_COMMIT__}`),
  );
  const footer = h('footer', {}, `Trust policy: ${getTrustHook().name} (recipient lists verified per folder, see Recipient trust). Read-only client; nothing leaves this browser except GitHub API calls.`);

  function render() {
    void renderKeyCard();
  }

  root.append(header, status, configForm, trust.card, keyCard, entriesCard, entryView, trust.settings, footer);
  render();
  if (tokens.hasToken) void refresh();
}
