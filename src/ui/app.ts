import {
  GitHubClient,
  GitHubSnapshot,
  TokenStore,
  checkFolderAdmin,
  dirname,
  evaluateRootTrust,
  takeInviteFromLocation,
  type GitHubRepo,
  type Invite,
  type RootTrust,
  type TakenInvite,
} from '../core';
import { notice } from './components';
import { type IconName, icon } from './icons';
import { avatar, splitUserId } from './people';
import { type AppCtx, CONFIG_KEY, loadConfig, storeLabel } from './context';
import { h } from './dom';
import { mountFolders } from './folders';
import { mountInbox } from './inbox';
import { joinFlow, pendingFlow } from './join';
import { deviceKeyInfo } from './keystore';
import { acknowledgeOriginRisk, assessOrigin, isOriginRiskAcknowledged } from './origin';
import { loadPending } from './request';
import { howSharingWorks, secretsView } from './secrets';
import { Session } from './session';
import { settingsView } from './settings';
import { connectScreen, describeLoadError, keyScreen, trustBanner, unlockScreen, verifyAdminsScreen } from './setup';

const IDLE_LOCK_MS = 5 * 60_000;

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
    const gate = h(
      'section',
      { class: 'screen origin-gate', role: 'alertdialog', 'aria-labelledby': 'origin-gate-title' },
      h('h2', { id: 'origin-gate-title', class: 'screen-title' }, 'Unsafe hosting: this address is shared'),
      notice('danger', `g00pass keeps your passphrase-protected key and the trusted admins in this browser's storage for ${location.origin}. Every page on that address can read and change them.`),
      h('ul', {}, ...risk.reasons.map((r) => h('li', {}, r))),
      h('p', {}, 'Host g00pass at the root of its own domain or subdomain, on a host that serves dist/_headers (e.g. Cloudflare Pages or Netlify).'),
      h('label', { class: 'check' }, ok, `I understand that other pages on ${risk.scope} can read and modify g00pass data.`),
      btn,
    );
    btn.addEventListener('click', () => {
      if (!ok.checked) return;
      acknowledgeOriginRisk(localStorage, risk);
      gate.remove();
      resolve();
    });
    root.append(gate);
  });
}

export function mountApp(root: HTMLElement): void {
  // FIRST: an invite link carries a token in the fragment; strip it from the
  // address bar and history before anything else (even the origin warning).
  const invite = takeInviteFromLocation(location, history);
  void originGate(root).then(() => start(root, invite));
}

type Tab = 'secrets' | 'access' | 'settings';

function start(root: HTMLElement, invite: TakenInvite): void {
  const tokens = new TokenStore('session');
  const client = new GitHubClient({ token: tokens.get });
  let config: GitHubRepo = loadConfig();
  let snapshot: GitHubSnapshot | null = null;
  let rootTrust: RootTrust | null = null;
  let loadError: string | null = null;
  let loading = false;
  let tab: Tab = 'secrets';
  let adminOf: string[] = [];
  let requestCount = 0;
  const folderMemory: { folder: string | null } = { folder: null };
  const secretsMemory: { selected: string | null } = { selected: null };
  let joining: Invite | null = invite.kind === 'invite' ? invite.invite : null;
  let joinEl: HTMLElement | null = null;
  let generation = 0;

  // Floating toast (aria-live). Errors stay until replaced or dismissed; other messages fade.
  const status = h('p', { class: 'status', role: 'status', 'aria-live': 'polite' });
  const toastIcon = h('span', { class: 'toast-icon' });
  const toastClose = h('button', { type: 'button', class: 'toast-close', 'aria-label': 'Dismiss' }, icon('x', { size: 16 }));
  const toastEl = h('div', { class: 'toast', hidden: true }, toastIcon, status, toastClose);
  let toastTimer: ReturnType<typeof setTimeout> | null = null;
  const hideToast = () => {
    toastEl.classList.add('leaving');
    setTimeout(() => {
      toastEl.hidden = true;
      toastEl.classList.remove('leaving');
    }, 180);
  };
  toastClose.addEventListener('click', hideToast);
  const toast = (text: string, isError = false) => {
    if (toastTimer) clearTimeout(toastTimer);
    status.textContent = text;
    toastEl.classList.toggle('error', isError);
    toastEl.classList.remove('leaving');
    toastIcon.replaceChildren(icon(isError ? 'alert' : text.endsWith('…') ? 'clock' : 'check', { size: 18 }));
    toastEl.hidden = !text;
    if (text && !isError && !text.endsWith('…')) toastTimer = setTimeout(hideToast, Math.max(5000, text.length * 80));
  };
  const main = h('main', { class: 'main' });
  let me: { fingerprint: string; name: string; email: string | null } | null = null;

  const session = new Session(IDLE_LOCK_MS, () => {
    toast('Locked.');
    void rerender();
  });
  for (const ev of ['pointerdown', 'keydown']) document.addEventListener(ev, () => session.touch(), { passive: true });
  window.addEventListener('pagehide', () => session.lock());

  const ctx: AppCtx = {
    client,
    tokens,
    session,
    config: () => config,
    saveConfig: (c) => {
      config = c;
      localStorage.setItem(CONFIG_KEY, JSON.stringify(c));
    },
    snapshot: () => snapshot,
    root: () => rootTrust,
    toast,
    reload,
    rerender: () => void rerender(),
  };

  async function computeAdmin(s: GitHubSnapshot): Promise<string[]> {
    const info = await deviceKeyInfo().catch(() => null);
    if (!info) return [];
    const folders = s.listFiles().filter((p) => p === '.gpg-id' || p.endsWith('/.gpg-id')).map(dirname).sort();
    const out: string[] = [];
    for (const f of folders) if ((await checkFolderAdmin(s, f, info.fingerprint).catch(() => null))?.admin) out.push(f);
    return out;
  }

  async function reload(note?: string, isError = false): Promise<void> {
    if (!config.owner || !tokens.hasToken) {
      snapshot = null;
      if (note) toast(note, isError);
      return rerender();
    }
    loading = true;
    toast(note ? `${note} Loading…` : 'Loading…', isError);
    try {
      snapshot = await GitHubSnapshot.load(client, config);
      rootTrust = await evaluateRootTrust(snapshot);
      adminOf = await computeAdmin(snapshot);
      loadError = null;
      const n = snapshot.listFiles().filter((p) => p.endsWith('.gpg') && !p.split('/').some((x) => x.startsWith('.'))).length;
      toast(note ? note : `Loaded ${n} secrets from ${storeLabel(config)}.`, isError);
    } catch (e) {
      snapshot = null;
      rootTrust = null;
      loadError = describeLoadError(e);
      toast(loadError, true);
    } finally {
      loading = false;
    }
    await rerender();
  }

  const brand = () => h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, icon('shield', { size: 18 })), h('span', { class: 'brand-name' }, 'g00pass'));

  /** Setup, unlock and join screens: centered, with the brand above. */
  function authFrame(view: HTMLElement): HTMLElement {
    return h('div', { class: 'auth' }, h('header', { class: 'auth-head' }, brand()), view, h('p', { class: 'auth-foot' }, icon('lock', { size: 14 }), 'End-to-end encrypted. Secrets are only ever decrypted in this browser.'));
  }

  const PAGES: Record<Tab, { title: string; lead: string }> = {
    secrets: { title: 'Secrets', lead: 'Passwords and notes your team shares.' },
    access: { title: 'People', lead: 'Invite people, approve requests, and manage who can open which folder.' },
    settings: { title: 'Settings', lead: 'Your connection, your key, and the admins this browser trusts.' },
  };

  function shell(): HTMLElement {
    const tabs: [Tab, string, IconName][] = [['secrets', 'Secrets', 'key'], ...(adminOf.length ? ([['access', 'People', 'users']] as [Tab, string, IconName][]) : []), ['settings', 'Settings', 'settings']];
    if (!tabs.some(([t]) => t === tab)) tab = 'secrets';
    const badge = h('span', { class: 'badge count', hidden: requestCount === 0 }, String(requestCount));
    const nav = h('nav', { class: 'nav', role: 'tablist', 'aria-label': 'Sections' }, ...tabs.map(([t, label, ic]) =>
      h('button', { type: 'button', role: 'tab', 'aria-selected': String(t === tab), class: 'nav-item', onclick: () => { if (tab === t) return; tab = t; void rerender(); } }, icon(ic, { size: 20 }), h('span', { class: 'nav-label' }, label), t === 'access' ? badge : '')));
    const meP = me ? { fingerprint: me.fingerprint, name: me.name, escrow: false } : null;
    const sidebar = h(
      'aside',
      { class: 'sidebar' },
      brand(),
      h('div', { class: 'store-card', title: `Branch ${config.branch}` }, icon('github', { size: 16 }), h('span', {}, storeLabel(config))),
      nav,
      h('div', { class: 'sidebar-spacer' }),
      meP
        ? h('div', { class: 'me-card' }, avatar(meP, 'md'), h('div', { class: 'me-text' }, h('b', { class: 'uid', dir: 'auto' }, meP.name), h('span', { class: 'hint' }, adminOf.length ? 'Admin' : 'Member')),
            h('button', { type: 'button', class: 'icon-btn', title: 'Lock', 'aria-label': 'Lock', onclick: () => session.lock() }, icon('lock')))
        : '',
    );
    let content: HTMLElement;
    if (tab === 'access') {
      const inbox = mountInbox({
        client,
        getConfig: () => config,
        deviceFingerprint: async () => (await deviceKeyInfo().catch(() => null))?.fingerprint ?? null,
        session,
        setStatus: toast,
        onApproved: (note, isErr) => void reload(note, isErr),
        onCount: (n) => {
          requestCount = n;
          badge.textContent = String(n);
          badge.hidden = n === 0;
        },
      });
      const folders = mountFolders({ client, getConfig: () => config, getSnapshot: () => snapshot, session, setStatus: toast, onChanged: (note) => void reload(note), memory: folderMemory });
      folders.refresh();
      void inbox.refresh();
      content = h('div', { class: 'access' }, inbox.el, folders.el, h('section', { class: 'panel intro' }, howSharingWorks()));
    } else if (tab === 'settings') {
      content = settingsView(ctx);
    } else {
      content = secretsView(ctx, secretsMemory);
    }
    const page = PAGES[tab];
    return h(
      'div',
      { class: 'app-shell' },
      sidebar,
      h('div', { class: 'content' },
        h('header', { class: 'page-head' },
          h('div', {}, h('h1', { class: 'page-title' }, page.title), h('p', { class: 'page-lead' }, page.lead)),
          h('button', { type: 'button', class: 'icon-btn mobile-only', title: 'Lock', 'aria-label': 'Lock now', onclick: () => session.lock() }, icon('lock'))),
        rootTrust && !rootTrust.ok ? trustBanner(rootTrust) : '',
        h('div', { class: 'tab-body', role: 'tabpanel' }, content)),
    );
  }

  async function rerender(): Promise<void> {
    const gen = ++generation;
    let view: HTMLElement;
    if (joining) {
      joinEl ??= joinFlow(ctx, joining, () => {
        joining = null;
        joinEl = null;
      });
      view = joinEl;
    } else if (!config.owner || !tokens.hasToken) {
      const p = loadPending();
      view = p ? pendingFlow(ctx, p, () => void rerender()) : connectScreen(ctx);
    } else if (!snapshot) {
      view = loading ? h('div', { class: 'loading' }, h('span', { class: 'spinner' }), 'Opening your vault…') : connectScreen(ctx, { error: loadError ?? undefined });
    } else if (rootTrust && !rootTrust.ok && !rootTrust.pinned) {
      view = verifyAdminsScreen(ctx, rootTrust);
    } else {
      const info = await deviceKeyInfo().catch(() => null);
      if (info) {
        const { name, email } = splitUserId(info.userIds[0] ?? '');
        me = { fingerprint: info.fingerprint, name: name || 'You', email };
      }
      if (!info) view = keyScreen(ctx);
      else if (!session.unlockedKey) view = unlockScreen(ctx, info);
      else {
        if (!adminOf.length && snapshot) adminOf = await computeAdmin(snapshot);
        view = shell();
      }
    }
    if (gen !== generation) return;
    const inShell = view.classList.contains('app-shell');
    main.classList.toggle('in-shell', inShell);
    main.replaceChildren(inShell ? view : authFrame(view));
  }

  if (invite.kind === 'invalid') toast(`This invite link cannot be used: ${invite.reason}`, true);
  root.append(main, toastEl);
  if (!joining && config.owner && tokens.hasToken) void reload();
  else void rerender();
}
