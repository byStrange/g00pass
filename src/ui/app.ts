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
import { type AppCtx, CONFIG_KEY, loadConfig, storeLabel } from './context';
import { h } from './dom';
import { mountFolders } from './folders';
import { mountInbox } from './inbox';
import { joinFlow, pendingFlow } from './join';
import { deviceKeyInfo } from './keystore';
import { acknowledgeOriginRisk, assessOrigin, isOriginRiskAcknowledged } from './origin';
import { loadPending } from './request';
import { secretsView } from './secrets';
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
  let joining: Invite | null = invite.kind === 'invite' ? invite.invite : null;
  let joinEl: HTMLElement | null = null;
  let generation = 0;

  const status = h('p', { class: 'status', role: 'status', 'aria-live': 'polite' });
  let toastTimer: ReturnType<typeof setTimeout> | null = null;
  /** Errors stay until replaced; other messages fade after a while (longer ones stay longer). */
  const toast = (text: string, isError = false) => {
    if (toastTimer) clearTimeout(toastTimer);
    status.textContent = text;
    status.classList.toggle('error', isError);
    status.hidden = !text;
    if (text && !isError && !text.endsWith('…')) toastTimer = setTimeout(() => (status.hidden = true), Math.max(6000, text.length * 90));
  };
  const headerRight = h('div', { class: 'header-right' });
  const header = h('header', { class: 'topbar' }, h('div', { class: 'brand' }, h('span', { class: 'logo', 'aria-hidden': 'true' }, '🔐'), h('span', {}, 'g00pass')), headerRight);
  const main = h('main', { class: 'main' });

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

  function renderHeader(unlocked: boolean) {
    headerRight.replaceChildren(
      snapshot ? h('span', { class: 'store-chip', title: `Branch ${config.branch}` }, storeLabel(config)) : '',
      unlocked ? h('button', { type: 'button', class: 'ghost small', onclick: () => session.lock() }, 'Lock') : '',
    );
  }

  function shell(): HTMLElement {
    const tabs: [Tab, string][] = [['secrets', 'Secrets'], ...(adminOf.length ? ([['access', 'Access']] as [Tab, string][]) : []), ['settings', 'Settings']];
    if (!tabs.some(([t]) => t === tab)) tab = 'secrets';
    const badge = h('span', { class: 'badge count', hidden: requestCount === 0 }, String(requestCount));
    const nav = h('nav', { class: 'tabs', role: 'tablist' }, ...tabs.map(([t, label]) =>
      h('button', { type: 'button', role: 'tab', 'aria-selected': String(t === tab), class: 'tab', onclick: () => { if (tab === t) return; tab = t; void rerender(); } }, label, t === 'access' ? badge : '')));
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
      content = h('div', { class: 'access' }, inbox.el, folders.el);
    } else if (tab === 'settings') {
      content = settingsView(ctx);
    } else {
      content = secretsView(ctx);
    }
    return h('div', { class: 'shell' }, rootTrust && !rootTrust.ok ? trustBanner(rootTrust) : '', nav, h('div', { class: 'tab-body', role: 'tabpanel' }, content));
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
      view = loading ? h('p', { class: 'hint center' }, 'Loading…') : connectScreen(ctx, { error: loadError ?? undefined });
    } else if (rootTrust && !rootTrust.ok && !rootTrust.pinned) {
      view = verifyAdminsScreen(ctx, rootTrust);
    } else {
      const info = await deviceKeyInfo().catch(() => null);
      if (!info) view = keyScreen(ctx);
      else if (!session.unlockedKey) view = unlockScreen(ctx, info);
      else {
        if (!adminOf.length && snapshot) adminOf = await computeAdmin(snapshot);
        view = shell();
      }
    }
    if (gen !== generation) return;
    renderHeader(!!session.unlockedKey);
    main.replaceChildren(view);
  }

  if (invite.kind === 'invalid') toast(`This invite link cannot be used: ${invite.reason}`, true);
  root.append(header, status, main);
  status.hidden = true;
  if (!joining && config.owner && tokens.hasToken) void reload();
  else void rerender();
}
